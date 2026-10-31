/**
 * `@thinkhuman/payload-plugin-auth` core: what the OAuth/OIDC and SAML plugins share and what a host
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
  type LinkedAccountsOptions,
  linkedAccountsCollection,
} from './core/accounts.js'
export { type CookieAttributes, expireCookie, readCookie, serializeCookie } from './core/cookies.js'
export {
  AUTH_ERROR_CODES,
  AuthError,
  type AuthErrorOptions,
  authErrorMessage,
  isAuthError,
  isAuthErrorCode,
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
  type AccountsClient,
  createAccount,
  findAccount,
  findUserByEmail,
  findUserById,
  type LinkIdentityArgs,
  linkIdentity,
  listAccounts,
  looksLikeEmail,
  normalizeEmail,
  type ResolveUserArgs,
  randomPassword,
  resolveUser,
  touchAccount,
  unlinkAccount,
} from './core/resolve-user.js'
export { deriveKey, open as openSealed, type SealOptions, seal } from './core/sealed.js'
export {
  type CreateSessionArgs,
  createSessionCookie,
  expiredSessionCookie,
  type RevokeSessionArgs,
  revokeSession,
  type SessionCookie,
  sessionIdOf,
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
