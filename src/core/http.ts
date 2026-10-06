/** Response helpers shared by the OAuth and SAML handlers. */

export function redirect(location: string, cookies: string[] = [], status = 302): Response {
  const headers = new Headers({ Location: location, 'Cache-Control': 'no-store' })
  for (const cookie of cookies) headers.append('Set-Cookie', cookie)
  return new Response(null, { status, headers })
}

export function json(body: unknown, { status = 200, cookies = [] as string[] } = {}): Response {
  const headers = new Headers({ 'Cache-Control': 'no-store' })
  for (const cookie of cookies) headers.append('Set-Cookie', cookie)
  return Response.json(body, { status, headers })
}

export const wantsJson = (request: Request): boolean =>
  (request.headers.get('accept') ?? '').includes('application/json')

/**
 * Only same-origin absolute paths may be used as a post-login destination: no protocol-relative
 * `//evil`, no backslash tricks, no schemes. Anything else falls back.
 */
export function safeRedirectPath(value: unknown, fallback = '/'): string {
  if (typeof value !== 'string') return fallback
  const path = value.trim()
  if (!path.startsWith('/') || path.startsWith('//') || path.startsWith('/\\')) return fallback
  // eslint-disable-next-line no-control-regex -- control characters must never reach a Location header
  if (/[\u0000-\u001f\u007f]/.test(path)) return fallback
  return path
}

/** `${base}?error=code` while keeping any query the base already carries. */
export function errorRedirectUrl(
  base: string,
  code: string,
  extra?: Record<string, string>,
): string {
  const [path, query = ''] = base.split('?', 2)
  const params = new URLSearchParams(query)
  params.set('error', code)
  for (const [key, value] of Object.entries(extra ?? {})) params.set(key, value)
  return `${path}?${params}`
}

/** Strips a trailing slash so URLs can be concatenated predictably. */
export const trimSlash = (url: string): string => url.replace(/\/+$/, '')

export async function readJsonBody(request: Request): Promise<Record<string, unknown>> {
  try {
    const body = (await request.clone().json()) as unknown
    return body && typeof body === 'object' ? (body as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

export async function readFormBody(request: Request): Promise<Record<string, string>> {
  const text = await request.clone().text()
  const result: Record<string, string> = {}
  for (const [key, value] of new URLSearchParams(text)) result[key] = value
  return result
}
