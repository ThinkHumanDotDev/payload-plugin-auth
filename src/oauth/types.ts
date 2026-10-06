import type * as oidc from 'openid-client'
import type { Payload, PayloadRequest } from 'payload'

import type { ExternalIdentity, ProviderInfo, UserResolutionOptions } from '../core/types.js'
import type { TransactionCookieOptions } from '../core/transaction.js'

export type OAuthTokens = oidc.TokenEndpointResponse & oidc.TokenEndpointResponseHelpers

/** What a provider's `profile` function returns; `provider` and `raw` are filled in by the plugin. */
export type ProfileResult = Omit<ExternalIdentity, 'provider' | 'raw'> & {
  raw?: Record<string, unknown>
}

export interface ProfileContext {
  provider: OAuthProvider
  tokens: OAuthTokens
  /** ID token claims (OIDC providers). */
  claims?: Record<string, unknown>
  /** UserInfo response when the provider has a `userinfo_endpoint` (OIDC providers). */
  userinfo?: Record<string, unknown>
  /** `GET url` with the access token as bearer; throws on non-2xx. */
  fetchJson<T = Record<string, unknown>>(url: string): Promise<T>
}

export type ClientAuthMethod = 'client_secret_basic' | 'client_secret_post' | 'none'

/**
 * One OAuth 2.0 / OpenID Connect client registration. Build one with a preset (`github()`,
 * `google()`, `oidc()`, ...) or by hand for anything else.
 */
export interface OAuthProvider {
  /** Used in URLs (`/oauth/<id>/login`) and stored on linked accounts. `[a-z0-9_-]`. */
  id: string
  /** Button label. */
  name: string
  type: 'oidc' | 'oauth2'
  clientId: string
  /** Confidential clients. Omit for public clients (`clientAuth: 'none'`). */
  clientSecret?: string
  /** Default `['openid', 'email', 'profile']` for OIDC. */
  scopes?: string[]
  /** OIDC issuer; endpoints and keys come from `/.well-known/openid-configuration`. */
  issuer?: string
  /** Explicit endpoints for providers without discovery (plain OAuth 2.0). */
  authorizationEndpoint?: string
  tokenEndpoint?: string
  userinfoEndpoint?: string
  jwksUri?: string
  endSessionEndpoint?: string
  /** Proof Key for Code Exchange (S256). Default `true`; only turn off for servers that reject it. */
  pkce?: boolean
  /** Extra authorization request parameters (`prompt`, `access_type`, `hd`, ...). */
  authorizationParams?: Record<string, string>
  /** Default `client_secret_basic` when a secret is set, `none` otherwise. */
  clientAuth?: ClientAuthMethod
  /**
   * Maps tokens, claims and/or API responses to an identity. OIDC providers have a default (standard
   * claims); plain OAuth providers must provide one.
   */
  profile?: (ctx: ProfileContext) => ProfileResult | Promise<ProfileResult>
  /** Accept `http://` endpoints (local test issuers). Default: `NODE_ENV !== 'production'`. */
  allowInsecureRequests?: boolean
  /** Fail discovery/token requests after this many seconds. Default 15. */
  timeoutSeconds?: number
  icon?: string
  /** Host-defined data returned with `listProviders()` and in hooks (for example a tenant id). */
  meta?: Record<string, unknown>
}

export interface ProviderContext {
  payload: Payload
  req?: PayloadRequest
  request: Request
}

/**
 * Providers that live outside the config (a database of per-tenant connections). `get` resolves one
 * by id for the login/callback endpoints; `list` feeds the login page.
 */
export interface OAuthProviderResolver {
  get(id: string, ctx: ProviderContext): Promise<OAuthProvider | null | undefined>
  list?(ctx: ProviderContext): Promise<OAuthProvider[]>
}

export type OAuthProviders = OAuthProvider[] | OAuthProviderResolver

export interface AuthenticatedContext {
  payload: Payload
  req?: PayloadRequest
  request: Request
  provider: OAuthProvider
  identity: ExternalIdentity
  tokens: OAuthTokens
  user: { id: string | number } & Record<string, unknown>
  /** The user was created by this login. */
  created: boolean
  /** The identity was attached to an existing user by this login (verified email or explicit link). */
  linked: boolean
  /** `true` when the flow was started to link an identity to the signed-in user. */
  linking: boolean
  /** Validated post-login path. */
  next: string
  /** `Set-Cookie` values the response must carry (clears the transaction cookie). */
  cookies: string[]
}

export interface OAuthErrorContext {
  payload: Payload
  req?: PayloadRequest
  request: Request
  code: string
  error: unknown
  providerId?: string
  /** `Set-Cookie` values the response should carry. */
  cookies: string[]
}

export interface OAuthOptions {
  /** Slug of the auth-enabled collection. Default: `config.admin.user` or `users`. */
  usersSlug?: string
  /** Linked-accounts collection: slug (default `auth-accounts`) and overrides, or `false` to manage it yourself. */
  accounts?: { slug?: string } | false
  providers: OAuthProviders
  /**
   * Mount endpoints on the users collection: `GET <basePath>/providers`, `GET <basePath>/:provider/login`,
   * `GET <basePath>/:provider/callback`, `POST <basePath>/logout`. Default `/oauth`; `false` to mount the
   * handlers yourself (`createOAuth(...).handlers`).
   */
  basePath?: string | false
  /**
   * Redirect URI registered at the provider. Default:
   * `${serverURL}${routes.api}/${usersSlug}${basePath}/${provider.id}/callback`.
   */
  redirectUri?: string | ((provider: OAuthProvider, ctx: ProviderContext) => string)
  /** Where to send the browser after a login without `?next=`. Default `/`. */
  successRedirect?: string
  /** Where to send the browser after a failure, with `?error=<code>` added. Default `/login`. */
  errorRedirect?: string
  /** Where the provider sends the browser after RP-initiated logout. Default `${serverURL}/`. */
  postLogoutRedirectUri?: string
  /** Transaction cookie. */
  cookie?: TransactionCookieOptions
  /** Secret for the transaction cookie. Default: the Payload secret. */
  secret?: string
  /** Let a signed-in user link another identity with `?link=1`. Default `true`. */
  allowLinking?: boolean
  /** How identities become users. */
  users?: UserResolutionOptions
  /**
   * Runs once the identity is mapped to a user and before the session is issued. Return a `Response`
   * to take over (a second factor, a consent page); return nothing for the default redirect + cookie.
   */
  onAuthenticated?: (ctx: AuthenticatedContext) => Promise<Response | void> | Response | void
  /** Runs on every failure. Return a `Response` to take over; otherwise the error redirect is sent. */
  onError?: (ctx: OAuthErrorContext) => Promise<Response | void> | Response | void
}

export type { ProviderInfo, UserResolutionOptions }
