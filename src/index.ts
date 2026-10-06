/**
 * `@thinkhuman/payload-auth` core: what the OAuth/OIDC and SAML plugins share and what a host
 * application needs to build its own login page, account settings and custom routes.
 *
 * - `linkedAccountsCollection` — the `(provider, providerAccountId) → user` collection
 * - `createSessionCookie` / `revokeSession` — Payload sessions for externally authenticated users
 * - `resolveUser` / `linkIdentity` — identity → user mapping with host hooks
 * - `AuthError` — typed failures that end a flow with an error code
 * - sealed transaction cookies and small HTTP/cookie helpers
 */
export {
  DEFAULT_ACCOUNTS_SLUG,
  defaultUsersSlug,
  ensureLinkedAccountsCollection,
  linkedAccountsCollection,
  type LinkedAccountsOptions,
} from './core/accounts.js'
export { expireCookie, readCookie, serializeCookie, type CookieAttributes } from './core/cookies.js'
export {
  AUTH_ERROR_CODES,
  AuthError,
  authErrorMessage,
  isAuthError,
  isAuthErrorCode,
  type AuthErrorOptions,
  type KnownAuthErrorCode,
} from './core/errors.js'
export {
  errorRedirectUrl,
  json,
  readFormBody,
  readJsonBody,
  redirect,
  safeRedirectPath,
  trimSlash,
  wantsJson,
} from './core/http.js'
export {
  createAccount,
  findAccount,
  findUserByEmail,
  findUserById,
  linkIdentity,
  listAccounts,
  looksLikeEmail,
  normalizeEmail,
  randomPassword,
  resolveUser,
  touchAccount,
  unlinkAccount,
  type AccountsClient,
  type LinkIdentityArgs,
  type ResolveUserArgs,
} from './core/resolve-user.js'
export { deriveKey, open as openSealed, seal, type SealOptions } from './core/sealed.js'
export {
  createSessionCookie,
  expiredSessionCookie,
  revokeSession,
  sessionIdOf,
  type CreateSessionArgs,
  type RevokeSessionArgs,
  type SessionCookie,
} from './core/session.js'
export {
  createTransactionStore,
  DEFAULT_TRANSACTION_COOKIE,
  DEFAULT_TRANSACTION_TTL_SECONDS,
  type Transaction,
  type TransactionCookieOptions,
  type TransactionStore,
} from './core/transaction.js'
export type {
  AuthUser,
  ExternalIdentity,
  IdentityContext,
  LinkedAccount,
  ProviderInfo,
  ProviderKind,
  ResolvedUser,
  UserContext,
  UserId,
  UserResolutionOptions,
} from './core/types.js'
