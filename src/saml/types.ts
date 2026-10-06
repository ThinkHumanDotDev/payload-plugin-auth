import type { Payload, PayloadRequest } from 'payload'

import type { ExternalIdentity, ProviderInfo, UserResolutionOptions } from '../core/types.js'
import type { Transaction, TransactionCookieOptions } from '../core/transaction.js'

/** The SAML subject and attributes as `@node-saml/node-saml` returns them. */
export type SamlProfile = {
  issuer: string
  nameID: string
  nameIDFormat: string
  sessionIndex?: string
  inResponseTo?: string
} & Record<string, unknown>

export type SamlProfileResult = Omit<ExternalIdentity, 'provider' | 'raw'> & {
  raw?: Record<string, unknown>
}

/** Attribute names to read an identity field from, in order of preference. */
export interface SamlAttributeMap {
  email?: string[]
  name?: string[]
  firstName?: string[]
  lastName?: string[]
  picture?: string[]
}

/**
 * One SAML 2.0 identity provider the application (the service provider) trusts. The values come
 * from the IdP's metadata; `parseIdpMetadata()` extracts them from a metadata document.
 */
export interface SamlConnection {
  /** Used in URLs (`/saml/<id>/acs`) and stored on linked accounts. `[a-z0-9_-]`. */
  id: string
  /** Button label. */
  name: string
  /** IdP single sign-on URL (HTTP-Redirect binding). */
  entryPoint: string
  /** IdP signing certificate(s): PEM or bare base64. Responses must be signed by one of them. */
  idpCert: string | string[]
  /** IdP entity id. When set, the `Issuer` of responses must match. */
  idpIssuer?: string
  /** IdP single logout URL, advertised in the SP metadata only (SLO is not implemented). */
  logoutUrl?: string
  /**
   * Service-provider entity id (the `Issuer` of requests and the expected `Audience`). Default: the
   * connection's metadata URL.
   */
  entityId?: string
  /** SP signing key and certificate: signs AuthnRequests and metadata when set. */
  privateKey?: string
  publicCert?: string
  /** SP decryption key and certificate for encrypted assertions. */
  decryptionPvk?: string
  decryptionCert?: string
  /** Requested NameID format. Default `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`; `null` omits it. */
  identifierFormat?: string | null
  /** Default `true`. */
  wantAssertionsSigned?: boolean
  /** Default `false` (most IdPs sign the assertion; some sign the response as well). */
  wantAuthnResponseSigned?: boolean
  /** Tolerated clock difference for `NotBefore`/`NotOnOrAfter`. Default 5000 ms. */
  acceptedClockSkewMs?: number
  /** Reject assertions issued longer ago than this (`IssueInstant`). Default 0 = no limit beyond the conditions. */
  maxAssertionAgeMs?: number
  /** Accept unsolicited (IdP-initiated) responses. Default `false`. */
  allowIdpInitiated?: boolean
  forceAuthn?: boolean
  /** Requested authentication contexts; default: none requested (`disableRequestedAuthnContext`). */
  authnContext?: string[]
  signatureAlgorithm?: 'sha1' | 'sha256' | 'sha512'
  digestAlgorithm?: 'sha1' | 'sha256' | 'sha512'
  /** Attribute names to map. Merged over the built-in list (common URIs and friendly names). */
  attributes?: SamlAttributeMap
  /**
   * SAML has no `email_verified`. Default `true`: an enterprise IdP is authoritative for the emails it
   * asserts. Set `false` to never link existing users by email through this connection.
   */
  emailVerified?: boolean
  /** Replace the default attribute mapping entirely. */
  profile?: (profile: SamlProfile) => SamlProfileResult | Promise<SamlProfileResult>
  icon?: string
  meta?: Record<string, unknown>
}

export interface ConnectionContext {
  payload: Payload
  req?: PayloadRequest
  request: Request
}

export interface SamlConnectionResolver {
  get(id: string, ctx: ConnectionContext): Promise<SamlConnection | null | undefined>
  list?(ctx: ConnectionContext): Promise<SamlConnection[]>
}

export type SamlConnections = SamlConnection[] | SamlConnectionResolver

export interface SamlAuthenticatedContext {
  payload: Payload
  req?: PayloadRequest
  request: Request
  connection: SamlConnection
  identity: ExternalIdentity
  profile: SamlProfile
  user: { id: string | number } & Record<string, unknown>
  created: boolean
  linked: boolean
  linking: boolean
  next: string
  cookies: string[]
}

export interface SamlErrorContext {
  payload: Payload
  req?: PayloadRequest
  request: Request
  code: string
  error: unknown
  connectionId?: string
  /** The transaction the failing response belonged to, when its cookie could be read. */
  transaction?: Transaction
  cookies: string[]
}

/**
 * Guards against assertion replay beyond what `InResponseTo` gives: called with the assertion id
 * and its expiry; return `false` when the id was seen before. Back it with Redis or a database in
 * multi-process deployments.
 */
export type AssertionReplayCheck = (
  assertionId: string,
  expiresAt: Date,
  ctx: ConnectionContext,
) => Promise<boolean> | boolean

export interface SamlOptions {
  usersSlug?: string
  accounts?: { slug?: string } | false
  connections: SamlConnections
  /**
   * Mount endpoints on the users collection: `GET <basePath>/connections`,
   * `GET <basePath>/:connection/login`, `POST <basePath>/:connection/acs`,
   * `GET <basePath>/:connection/metadata`. Default `/saml`; `false` to mount the handlers yourself.
   */
  basePath?: string | false
  /** Assertion consumer service URL. Default `${serverURL}${routes.api}/${usersSlug}${basePath}/${id}/acs`. */
  callbackUrl?: string | ((connection: SamlConnection, ctx: ConnectionContext) => string)
  /** SP metadata URL, also the default entity id. Default `${serverURL}${routes.api}/${usersSlug}${basePath}/${id}/metadata`. */
  metadataUrl?: string | ((connection: SamlConnection, ctx: ConnectionContext) => string)
  successRedirect?: string
  errorRedirect?: string
  cookie?: TransactionCookieOptions
  secret?: string
  allowLinking?: boolean
  users?: UserResolutionOptions
  replayCheck?: AssertionReplayCheck
  onAuthenticated?: (ctx: SamlAuthenticatedContext) => Promise<Response | void> | Response | void
  onError?: (ctx: SamlErrorContext) => Promise<Response | void> | Response | void
}

export type { ProviderInfo, UserResolutionOptions }
