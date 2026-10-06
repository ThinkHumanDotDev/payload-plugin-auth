/**
 * Extracts what a SAML connection needs from an identity provider's metadata document
 * (`EntityDescriptor` → `IDPSSODescriptor`). Only the DOM parser that ships with
 * `@node-saml/node-saml` is used, so the optional peer dependency covers it.
 */
export interface IdpMetadata {
  entityId: string
  /** `SingleSignOnService` location: HTTP-Redirect preferred, HTTP-POST as fallback. */
  entryPoint: string
  /** Binding of `entryPoint`. */
  binding: 'redirect' | 'post'
  /** Signing certificates (bare base64, as node-saml accepts them). */
  certificates: string[]
  logoutUrl?: string
  nameIdFormats: string[]
}

const REDIRECT = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
const POST = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'

type Elem = {
  localName: string
  getAttribute(name: string): string | null
  getElementsByTagNameNS(ns: string, local: string): ArrayLike<Elem>
  textContent: string | null
}

const all = (
  node: { getElementsByTagNameNS(ns: string, local: string): ArrayLike<Elem> },
  local: string,
): Elem[] => Array.from(node.getElementsByTagNameNS('*', local))

export async function parseIdpMetadata(xml: string): Promise<IdpMetadata> {
  const { DOMParser } = await import('@xmldom/xmldom')
  const errors: string[] = []
  const doc = new DOMParser({
    errorHandler: (_level: string, message: unknown) => {
      errors.push(String(message))
    },
  }).parseFromString(xml, 'text/xml') as unknown as {
    documentElement: Elem | null
    getElementsByTagNameNS(ns: string, local: string): ArrayLike<Elem>
  }
  if (errors.length > 0 || !doc.documentElement) {
    throw new Error(`Invalid IdP metadata XML: ${errors[0] ?? 'no root element'}`)
  }

  const descriptor = all(doc, 'EntityDescriptor')[0]
  if (!descriptor) throw new Error('IdP metadata has no EntityDescriptor')
  const entityId = descriptor.getAttribute('entityID')?.trim()
  if (!entityId) throw new Error('IdP metadata EntityDescriptor has no entityID')

  const idp = all(descriptor, 'IDPSSODescriptor')[0]
  if (!idp) throw new Error('IdP metadata has no IDPSSODescriptor')

  const services = all(idp, 'SingleSignOnService')
  const byBinding = (binding: string) =>
    services
      .find((s) => s.getAttribute('Binding') === binding)
      ?.getAttribute('Location')
      ?.trim()
  const redirect = byBinding(REDIRECT)
  const post = byBinding(POST)
  const entryPoint = redirect ?? post
  if (!entryPoint) throw new Error('IdP metadata has no SingleSignOnService with a known binding')

  const certificates: string[] = []
  for (const key of all(idp, 'KeyDescriptor')) {
    const use = key.getAttribute('use')
    if (use && use !== 'signing') continue
    for (const cert of all(key, 'X509Certificate')) {
      const value = cert.textContent?.replace(/\s+/g, '')
      if (value && !certificates.includes(value)) certificates.push(value)
    }
  }
  if (certificates.length === 0) throw new Error('IdP metadata has no signing certificate')

  const logout = all(idp, 'SingleLogoutService')
  const logoutUrl =
    logout
      .find((s) => s.getAttribute('Binding') === REDIRECT)
      ?.getAttribute('Location')
      ?.trim() ??
    logout[0]?.getAttribute('Location')?.trim() ??
    undefined

  return {
    entityId,
    entryPoint,
    binding: redirect ? 'redirect' : 'post',
    certificates,
    logoutUrl,
    nameIdFormats: all(idp, 'NameIDFormat')
      .map((n) => n.textContent?.trim() ?? '')
      .filter(Boolean),
  }
}
