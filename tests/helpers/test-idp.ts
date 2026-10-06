import crypto from 'node:crypto'
import { readFileSync } from 'node:fs'
import path from 'node:path'
import { inflateRawSync } from 'node:zlib'

import { SignedXml } from 'xml-crypto'

/**
 * A SAML 2.0 identity provider for tests: it produces signed `Response` documents the way Okta or
 * Keycloak would (enveloped signature on the Assertion, exclusive canonicalisation, SHA-256), with
 * knobs to produce every kind of bad response the service provider must reject.
 */
const fixtures = path.resolve('tests/fixtures')
export const IDP_KEY = readFileSync(path.join(fixtures, 'idp-key.pem'), 'utf8')
export const IDP_CERT = readFileSync(path.join(fixtures, 'idp-cert.pem'), 'utf8')
/** A second key pair nobody trusts, for wrong-signer responses. */
export const ROGUE_KEY = readFileSync(path.join(fixtures, 'sp-key.pem'), 'utf8')
export const ROGUE_CERT = readFileSync(path.join(fixtures, 'sp-cert.pem'), 'utf8')

export const IDP_ENTITY_ID = 'https://idp.example.test/saml'
export const IDP_SSO_URL = 'https://idp.example.test/saml/sso'

const escape = (value: string) =>
  value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/"/g, '&quot;')

export interface ResponseOptions {
  /** ACS URL the response is destined for. */
  destination: string
  /** SP entity id (Audience). */
  audience: string
  /** `InResponseTo`; omit for an unsolicited (IdP-initiated) response. */
  inResponseTo?: string
  nameId: string
  nameIdFormat?: string
  attributes?: Record<string, string | string[]>
  issuer?: string
  /** Sign with a key the SP does not trust. */
  signWith?: 'idp' | 'rogue' | 'none'
  /** Shift validity: negative `expiresInMs` makes an expired assertion. */
  notBeforeMs?: number
  expiresInMs?: number
  /** Sign the whole Response instead of the Assertion. */
  signResponse?: boolean
  /** Tamper with the signed assertion after signing. */
  tamper?: (signedXml: string) => string
  assertionId?: string
}

export function buildSamlResponse(options: ResponseOptions): { xml: string; assertionId: string } {
  const now = Date.now()
  const issuer = options.issuer ?? IDP_ENTITY_ID
  const responseId = `_${crypto.randomBytes(16).toString('hex')}`
  const assertionId = options.assertionId ?? `_${crypto.randomBytes(16).toString('hex')}`
  const issueInstant = new Date(now).toISOString()
  const notBefore = new Date(now + (options.notBeforeMs ?? -60_000)).toISOString()
  const notOnOrAfter = new Date(now + (options.expiresInMs ?? 5 * 60_000)).toISOString()
  const format = options.nameIdFormat ?? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
  const inResponseTo = options.inResponseTo ? ` InResponseTo="${escape(options.inResponseTo)}"` : ''

  const attributes = Object.entries(options.attributes ?? {})
    .map(([name, value]) => {
      const values = (Array.isArray(value) ? value : [value])
        .map((v) => `<saml:AttributeValue xsi:type="xs:string">${escape(v)}</saml:AttributeValue>`)
        .join('')
      return `<saml:Attribute Name="${escape(name)}" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">${values}</saml:Attribute>`
    })
    .join('')

  const assertion =
    `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="${assertionId}" Version="2.0" IssueInstant="${issueInstant}">` +
    `<saml:Issuer>${escape(issuer)}</saml:Issuer>` +
    `<saml:Subject><saml:NameID Format="${format}">${escape(options.nameId)}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:SubjectConfirmationData NotOnOrAfter="${notOnOrAfter}" Recipient="${escape(options.destination)}"${inResponseTo}/></saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${notBefore}" NotOnOrAfter="${notOnOrAfter}"><saml:AudienceRestriction><saml:Audience>${escape(options.audience)}</saml:Audience></saml:AudienceRestriction></saml:Conditions>` +
    `<saml:AuthnStatement AuthnInstant="${issueInstant}" SessionIndex="${responseId}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>` +
    (attributes ? `<saml:AttributeStatement>${attributes}</saml:AttributeStatement>` : '') +
    `</saml:Assertion>`

  const sign = (xml: string, referenceXPath: string, key: string, cert: string) => {
    const signer = new SignedXml({
      privateKey: key,
      publicCert: cert,
      signatureAlgorithm: 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
      canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
    })
    signer.addReference({
      xpath: referenceXPath,
      digestAlgorithm: 'http://www.w3.org/2001/04/xmlenc#sha256',
      transforms: [
        'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
        'http://www.w3.org/2001/10/xml-exc-c14n#',
      ],
    })
    signer.computeSignature(xml, {
      location: { reference: `${referenceXPath}/*[local-name()='Issuer']`, action: 'after' },
    })
    return signer.getSignedXml()
  }

  const signWith = options.signWith ?? 'idp'
  const key = signWith === 'rogue' ? ROGUE_KEY : IDP_KEY
  const cert = signWith === 'rogue' ? ROGUE_CERT : IDP_CERT

  let signedAssertion = assertion
  if (signWith !== 'none' && !options.signResponse) {
    signedAssertion = sign(assertion, "/*[local-name()='Assertion']", key, cert)
    if (options.tamper) signedAssertion = options.tamper(signedAssertion)
  }

  let response =
    `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="${responseId}" Version="2.0" IssueInstant="${issueInstant}" Destination="${escape(options.destination)}"${inResponseTo}>` +
    `<saml:Issuer>${escape(issuer)}</saml:Issuer>` +
    `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
    signedAssertion +
    `</samlp:Response>`

  if (signWith !== 'none' && options.signResponse) {
    response = sign(response, "/*[local-name()='Response']", key, cert)
  }
  return { xml: response, assertionId }
}

export const encodeResponse = (xml: string): string => Buffer.from(xml, 'utf8').toString('base64')

/** Decodes the `SAMLRequest` of a redirect-binding URL (deflate + base64) into XML. */
export function decodeAuthnRequest(location: string): {
  xml: string
  id: string
  relayState: string | null
} {
  const url = new URL(location)
  const encoded = url.searchParams.get('SAMLRequest')
  if (!encoded) throw new Error('no SAMLRequest in URL')
  const xml = inflateRawSync(Buffer.from(encoded, 'base64')).toString('utf8')
  const id = /\sID="([^"]+)"/.exec(xml)?.[1]
  if (!id) throw new Error('AuthnRequest has no ID')
  return { xml, id, relayState: url.searchParams.get('RelayState') }
}

export const IDP_METADATA = `<?xml version="1.0"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="${IDP_ENTITY_ID}">
  <md:IDPSSODescriptor WantAuthnRequestsSigned="false" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <md:KeyDescriptor use="signing">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>${IDP_CERT.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '')}</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:KeyDescriptor use="encryption">
      <ds:KeyInfo><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></ds:KeyInfo>
    </md:KeyDescriptor>
    <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.test/saml/slo"/>
    <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.example.test/saml/sso-post"/>
    <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="${IDP_SSO_URL}"/>
  </md:IDPSSODescriptor>
</md:EntityDescriptor>`
