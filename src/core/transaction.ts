import { expireCookie, readCookie, serializeCookie, type CookieAttributes } from './cookies.js'
import { open, seal } from './sealed.js'

/**
 * The per-login transaction (state, nonce, PKCE verifier or SAML request id, post-login path, link
 * target) travels in a sealed cookie between the login and the callback endpoint.
 */
export interface TransactionCookieOptions {
  /** Cookie name. Default `payload-auth-tx`. */
  name?: string
  /** Cookie path. Default `/`; narrow it to the auth endpoints when they share a prefix. */
  path?: string
  /** `Secure` attribute. Default: `true` when the server URL is https. */
  secure?: boolean
  sameSite?: CookieAttributes['sameSite']
  domain?: string
  /** Lifetime in seconds. Default 600 (ten minutes to finish at the provider). */
  ttlSeconds?: number
}

export interface Transaction {
  /** Provider or connection id the flow was started for. */
  provider: string
  /** Same-origin path to land on after login (already validated). */
  next: string
  /** When set, the callback links the identity to this user instead of signing in. */
  linkUserId?: string
  /** Protocol-specific values (state, nonce, code verifier, SAML request id). */
  [key: string]: unknown
}

export const DEFAULT_TRANSACTION_COOKIE = 'payload-auth-tx'
export const DEFAULT_TRANSACTION_TTL_SECONDS = 10 * 60

export interface TransactionStore {
  cookieName: string
  /** Seals the transaction and returns the `Set-Cookie` value. */
  issue(transaction: Transaction, now?: number): Promise<string>
  /** Reads and opens the transaction cookie of a request; `null` when absent or invalid. */
  read(request: Request, now?: number): Promise<Transaction | null>
  /** `Set-Cookie` value that clears the cookie. */
  clear(): string
}

const PURPOSE = 'payload-auth:transaction'

export function createTransactionStore(
  secret: string,
  purpose: string,
  options: TransactionCookieOptions = {},
): TransactionStore {
  const name = options.name ?? DEFAULT_TRANSACTION_COOKIE
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TRANSACTION_TTL_SECONDS
  const attributes: CookieAttributes = {
    path: options.path ?? '/',
    httpOnly: true,
    secure: options.secure ?? false,
    // Lax, not Strict: the callback is a top-level navigation (or form POST) coming from the provider.
    sameSite: options.sameSite ?? 'Lax',
    domain: options.domain,
  }
  const fullPurpose = `${PURPOSE}:${purpose}`

  return {
    cookieName: name,
    async issue(transaction, now) {
      const sealed = await seal(transaction, secret, fullPurpose, { ttlSeconds, now })
      return serializeCookie(name, sealed, { ...attributes, maxAge: ttlSeconds })
    },
    async read(request, now) {
      const payload = await open(readCookie(request.headers, name), secret, fullPurpose, { now })
      if (!payload) return null
      // Drop the registered JWT claims the sealing added; what is left is the transaction.
      const { iat: _iat, exp: _exp, sub: _sub, ...transaction } = payload
      const { provider, next } = transaction
      if (typeof provider !== 'string' || !provider || typeof next !== 'string' || !next)
        return null
      return transaction as Transaction
    },
    clear() {
      return expireCookie(name, attributes)
    },
  }
}
