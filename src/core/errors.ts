/**
 * Error codes every flow in this package can end with. A flow that fails redirects the browser to
 * `${errorRedirect}?error=<code>`, so codes are short, lower-case identifiers the host application
 * can map to user-facing text. Host hooks may throw `AuthError` with their own codes (for example
 * `signup_disabled` or `invitation_required`); they are forwarded untouched.
 */
export const AUTH_ERROR_CODES = {
  /** No provider or connection with that id, or it is disabled. */
  provider_unknown: 'This sign-in method is not available.',
  /** The transaction cookie is missing, expired, forged or does not match the response. */
  state_mismatch: 'Your sign-in session expired or was tampered with. Please try again.',
  /** The identity provider answered with an authorization error (the user declined, policy, ...). */
  access_denied: 'The identity provider refused the sign-in request.',
  /** Token exchange, assertion validation or profile retrieval failed. */
  exchange_failed: 'Single sign-on failed. Please try again or contact your administrator.',
  /** The provider released no email address but the application needs one. */
  email_missing: 'Your identity provider did not share an email address, which is required.',
  /** An account with the same email exists but the provider did not assert the email as verified. */
  email_unverified:
    'An account with your email already exists but your identity provider has not verified it.',
  /** No matching account and provisioning is off. */
  provisioning_disabled: 'No account exists for your identity and automatic signup is disabled.',
  /** Linking: the identity is already attached to a different account. */
  account_in_use: 'This identity is already linked to another account.',
  /** Linking was requested without a signed-in session. */
  not_signed_in: 'Sign in first to link another account.',
} as const

export type KnownAuthErrorCode = keyof typeof AUTH_ERROR_CODES

/** Codes travel in a query string: keep them to a safe alphabet. */
const CODE_PATTERN = /^[a-z][a-z0-9_]{0,63}$/

export const isAuthErrorCode = (value: unknown): value is string =>
  typeof value === 'string' && CODE_PATTERN.test(value)

/** Message for a known code, `undefined` for unknown input (never reflect it). */
export const authErrorMessage = (code: unknown): string | undefined =>
  isAuthErrorCode(code) && Object.prototype.hasOwnProperty.call(AUTH_ERROR_CODES, code)
    ? AUTH_ERROR_CODES[code as KnownAuthErrorCode]
    : undefined

export interface AuthErrorOptions {
  /** HTTP status for JSON responses; redirects ignore it. Defaults to 403. */
  status?: number
  message?: string
  cause?: unknown
}

/**
 * Thrown anywhere in a flow (including host hooks) to end it with a specific code. The handlers turn
 * it into the error redirect; everything else that is thrown becomes `exchange_failed`.
 */
export class AuthError extends Error {
  readonly code: string
  readonly status: number

  constructor(code: string, options: AuthErrorOptions = {}) {
    if (!isAuthErrorCode(code)) {
      throw new TypeError(`Invalid auth error code "${code}": use lower-case letters, digits and _`)
    }
    super(options.message ?? authErrorMessage(code) ?? code, { cause: options.cause })
    this.name = 'AuthError'
    this.code = code
    this.status = options.status ?? 403
  }
}

export const isAuthError = (error: unknown): error is AuthError =>
  error instanceof AuthError ||
  (error instanceof Error && error.name === 'AuthError' && 'code' in error)
