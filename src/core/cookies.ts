/**
 * Minimal cookie helpers on top of the Fetch API. No dependency so the package works wherever
 * `Request`/`Response` do (Next.js route handlers, Payload endpoints, tests).
 */

export interface CookieAttributes {
  path?: string
  maxAge?: number
  httpOnly?: boolean
  secure?: boolean
  sameSite?: 'Lax' | 'Strict' | 'None'
  domain?: string
}

/** Builds a `Set-Cookie` header value. */
export function serializeCookie(name: string, value: string, attributes: CookieAttributes): string {
  const parts = [`${name}=${encodeURIComponent(value)}`]
  if (attributes.maxAge !== undefined) parts.push(`Max-Age=${Math.floor(attributes.maxAge)}`)
  if (attributes.domain) parts.push(`Domain=${attributes.domain}`)
  parts.push(`Path=${attributes.path ?? '/'}`)
  if (attributes.httpOnly !== false) parts.push('HttpOnly')
  if (attributes.secure) parts.push('Secure')
  parts.push(`SameSite=${attributes.sameSite ?? 'Lax'}`)
  return parts.join('; ')
}

/** `Set-Cookie` value that removes a cookie (same attributes as when it was set). */
export function expireCookie(name: string, attributes: CookieAttributes): string {
  return `${serializeCookie(name, '', { ...attributes, maxAge: 0 })}; Expires=Thu, 01 Jan 1970 00:00:00 GMT`
}

/** Reads one cookie from a request's `Cookie` header. */
export function readCookie(headers: Headers, name: string): string | undefined {
  const header = headers.get('cookie')
  if (!header) return undefined
  for (const pair of header.split(/; */)) {
    const index = pair.indexOf('=')
    if (index === -1) continue
    if (pair.slice(0, index).trim() !== name) continue
    const raw = pair.slice(index + 1)
    try {
      return decodeURIComponent(raw)
    } catch {
      return raw
    }
  }
  return undefined
}
