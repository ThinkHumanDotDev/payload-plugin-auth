import type { Payload, PayloadRequest, TypeWithID } from 'payload'

export type UserId = string | number

/** What every provider (OAuth, OIDC, SAML) boils down to once the protocol work is done. */
export interface ExternalIdentity {
  /** Id of the provider or connection that authenticated the user (`github`, `okta`, `conn_42`). */
  provider: string
  /** Stable identifier at the provider: OIDC `sub`, OAuth user id, SAML `NameID`. */
  providerAccountId: string
  email?: string
  /** `true` only when the provider asserted the email as verified. Drives account linking. */
  emailVerified: boolean
  name?: string
  picture?: string
  /** Claims, profile or assertion attributes as the provider returned them (no tokens). */
  raw: Record<string, unknown>
}

export type ProviderKind = 'oidc' | 'oauth2' | 'saml'

/** Public description of a provider, safe to send to a login page. */
export interface ProviderInfo {
  id: string
  name: string
  type: ProviderKind
  /** Icon hint for the button (`github`, `google`, `key`), interpreted by the host UI. */
  icon?: string
  /** Host-defined data carried along (for example the organization a connection belongs to). */
  meta?: Record<string, unknown>
}

/**
 * A user document of the auth-enabled collection. Deliberately loose (`id` + `email`) so generated
 * Payload types (interfaces without an index signature) are assignable; cast to your `User` type.
 */
export type AuthUser = TypeWithID & { email?: string | null }

/** A document of the linked-accounts collection. */
export interface LinkedAccount extends TypeWithID {
  user: UserId | AuthUser
  provider: string
  providerAccountId: string
  email?: string | null
  name?: string | null
  lastLoginAt?: string | null
}

export interface IdentityContext {
  payload: Payload
  /** The incoming request as a Payload request when available (endpoints), for transactions. */
  req?: PayloadRequest
  request: Request
  identity: ExternalIdentity
  provider: ProviderInfo
}

export interface UserContext extends IdentityContext {
  user: AuthUser
}

/**
 * How an authenticated identity becomes a user. Every hook is optional; the defaults implement
 * "match linked account → link by verified email → provision a new user".
 */
export interface UserResolutionOptions {
  /**
   * Create a user when neither a linked account nor a verified email matches. Default `true`. A
   * function can decide per login (for example from the connection's settings).
   */
  autoProvision?: boolean | ((ctx: IdentityContext) => boolean | Promise<boolean>)
  /**
   * Attach the identity to an existing user with the same email when the provider asserts the
   * email as verified. Default `true`; `false` never links by email. A function decides per login
   * (it receives the matched user) and replaces the verified-email rule, for example to also trust
   * a domain the tenant has proven to own. Unverified emails never take over an account otherwise.
   */
  linkByVerifiedEmail?: boolean | ((ctx: UserContext) => boolean | Promise<boolean>)
  /** Refuse identities without an email. Default `true` (users collections normally require one). */
  requireEmail?: boolean
  /**
   * Custom lookup that runs after the linked-accounts match and before the email match: return the
   * user the identity belongs to (an employee id, a legacy `oidcSubject` column, ...) and it is linked
   * to that user regardless of email verification. Return nothing to continue with the defaults.
   */
  findUser?: (
    ctx: IdentityContext,
  ) => AuthUser | null | undefined | Promise<AuthUser | null | undefined>
  /**
   * Data for a new user. Merged over the defaults (`email`, `name`, and a random password unless the
   * collection disables the local strategy). Return extra fields such as roles or a tenant.
   */
  mapNewUser?: (ctx: IdentityContext) => Record<string, unknown> | Promise<Record<string, unknown>>
  /** Runs before a user is created; throw `AuthError` to refuse (for example `signup_disabled`). */
  beforeProvision?: (ctx: IdentityContext) => void | Promise<void>
  /** Runs after a user was created and the account linked (accept an invitation, send a mail, ...). */
  afterProvision?: (ctx: UserContext) => void | Promise<void>
  /** Runs before an identity is attached to an existing user (verified-email match or explicit link). */
  beforeLink?: (ctx: UserContext) => void | Promise<void>
  /** Runs after an identity was attached to an existing user. */
  afterLink?: (ctx: UserContext) => void | Promise<void>
  /** Runs on every successful login, including the first one, before the session is issued. */
  afterLogin?: (ctx: UserContext & { created: boolean; linked: boolean }) => void | Promise<void>
}

export interface ResolvedUser {
  user: AuthUser
  account: LinkedAccount
  /** The user was created during this login. */
  created: boolean
  /** The identity was attached to an existing user during this login. */
  linked: boolean
}
