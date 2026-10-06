import crypto from 'node:crypto'

import type { Config, Endpoint, Payload, PayloadRequest, Plugin } from 'payload'

import {
  DEFAULT_ACCOUNTS_SLUG,
  defaultUsersSlug,
  ensureLinkedAccountsCollection,
} from '../core/accounts.js'
import { AuthError, isAuthError } from '../core/errors.js'
import {
  errorRedirectUrl,
  json,
  readFormBody,
  redirect,
  safeRedirectPath,
  trimSlash,
} from '../core/http.js'
import { linkIdentity, resolveUser } from '../core/resolve-user.js'
import { createSessionCookie } from '../core/session.js'
import { createTransactionStore, type TransactionStore } from '../core/transaction.js'
import type { AuthUser, ExternalIdentity, ProviderInfo, ResolvedUser } from '../core/types.js'

import { samlProfile } from './profile.js'
import type {
  ConnectionContext,
  SamlConnection,
  SamlConnectionResolver,
  SamlOptions,
  SamlProfile,
} from './types.js'

export interface SamlHandlerContext {
  payload: Payload
  req?: PayloadRequest
}

export interface SamlHandlers {
  /** `GET …/connections` → `{ connections: ProviderInfo[] }`. */
  connections(request: Request, ctx: SamlHandlerContext): Promise<Response>
  /** `GET …/:connection/login?next=/path&link=1` → redirect to the IdP with an AuthnRequest. */
  login(request: Request, ctx: SamlHandlerContext & { connectionId: string }): Promise<Response>
  /** `POST …/:connection/acs` (SAMLResponse form post) → session cookie + redirect, or error redirect. */
  acs(request: Request, ctx: SamlHandlerContext & { connectionId: string }): Promise<Response>
  /** `GET …/:connection/metadata` → service-provider metadata XML. */
  metadata(request: Request, ctx: SamlHandlerContext & { connectionId: string }): Promise<Response>
}

export interface Saml {
  plugin: Plugin
  handlers: SamlHandlers
  getConnection(id: string, ctx: ConnectionContext): Promise<SamlConnection | null>
  listConnections(ctx: ConnectionContext): Promise<ProviderInfo[]>
  /** Assertion consumer service URL to register at the IdP. */
  callbackUrl(connection: SamlConnection, ctx: ConnectionContext): string
  /** SP metadata URL (and default entity id). */
  metadataUrl(connection: SamlConnection, ctx: ConnectionContext): string
  /** SP entity id. */
  entityId(connection: SamlConnection, ctx: ConnectionContext): string
  readonly usersSlug: string
  readonly accountsSlug: string
}

export const CONNECTION_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/i

export const connectionInfo = (connection: SamlConnection): ProviderInfo => ({
  id: connection.id,
  name: connection.name,
  type: 'saml',
  icon: connection.icon,
  meta: connection.meta,
})

export function assertConnection(connection: SamlConnection): void {
  if (!CONNECTION_ID_PATTERN.test(connection.id)) {
    throw new Error(
      `payload-auth: connection id "${connection.id}" must match ${CONNECTION_ID_PATTERN}`,
    )
  }
  if (!connection.entryPoint)
    throw new Error(`payload-auth: connection "${connection.id}" needs an entryPoint`)
  const certs = Array.isArray(connection.idpCert) ? connection.idpCert : [connection.idpCert]
  if (certs.length === 0 || certs.some((c) => !c)) {
    throw new Error(`payload-auth: connection "${connection.id}" needs the IdP signing certificate`)
  }
}

const isResolver = (
  connections: SamlOptions['connections'],
): connections is SamlConnectionResolver => !Array.isArray(connections)

const serverUrlOf = (payload: Payload, request: Request): string =>
  trimSlash(payload.config.serverURL || new URL(request.url).origin)

/** A SAML request id must be an XML NCName: start with a letter or underscore. */
const newRequestId = () => `_${crypto.randomBytes(16).toString('hex')}`

// eslint-disable-next-line @typescript-eslint/consistent-type-imports -- the module is an optional peer loaded lazily
type NodeSaml = typeof import('@node-saml/node-saml')

let nodeSaml: Promise<NodeSaml> | undefined
async function loadNodeSaml(): Promise<NodeSaml> {
  nodeSaml ??= import('@node-saml/node-saml').catch((error: unknown) => {
    nodeSaml = undefined
    throw new Error(
      'payload-auth: install the optional peer dependency "@node-saml/node-saml" to use the SAML plugin',
      { cause: error },
    )
  })
  return nodeSaml
}

/**
 * Builds the SAML 2.0 service-provider integration: a Payload plugin plus framework-agnostic handlers.
 * SP-initiated login (HTTP-Redirect AuthnRequest, HTTP-POST response) and, per connection, IdP-initiated
 * login. Single logout is not implemented; the SP metadata advertises no SLO endpoint.
 */
export function createSaml(options: SamlOptions): Saml {
  const basePath = options.basePath === undefined ? '/saml' : options.basePath
  const successRedirect = options.successRedirect ?? '/'
  const errorRedirect = options.errorRedirect ?? '/login'
  const allowLinking = options.allowLinking !== false

  let usersSlug = options.usersSlug ?? 'users'
  let accountsSlug =
    options.accounts === false
      ? DEFAULT_ACCOUNTS_SLUG
      : (options.accounts?.slug ?? DEFAULT_ACCOUNTS_SLUG)

  if (Array.isArray(options.connections)) {
    const ids = new Set<string>()
    for (const connection of options.connections) {
      assertConnection(connection)
      if (ids.has(connection.id))
        throw new Error(`payload-auth: duplicate connection id "${connection.id}"`)
      ids.add(connection.id)
    }
  }

  const stores = new WeakMap<Payload, TransactionStore>()
  const transactions = (payload: Payload, request: Request): TransactionStore => {
    let store = stores.get(payload)
    if (!store) {
      store = createTransactionStore(options.secret ?? payload.secret, 'saml', {
        name: 'payload-auth-saml',
        secure: serverUrlOf(payload, request).startsWith('https://'),
        // The ACS is a cross-site POST from the IdP; `Lax` cookies are not sent on cross-site POSTs,
        // so the transaction cookie must be `None` (which requires `Secure` on https).
        sameSite: serverUrlOf(payload, request).startsWith('https://') ? 'None' : 'Lax',
        ...options.cookie,
      })
      stores.set(payload, store)
    }
    return store
  }

  async function getConnection(id: string, ctx: ConnectionContext): Promise<SamlConnection | null> {
    if (!id) return null
    let connection: SamlConnection | null | undefined
    if (isResolver(options.connections)) {
      connection = await options.connections.get(id, ctx)
      if (connection) assertConnection(connection)
    } else {
      connection = options.connections.find((c) => c.id === id)
    }
    return connection ?? null
  }

  async function listConnections(ctx: ConnectionContext): Promise<ProviderInfo[]> {
    const connections = isResolver(options.connections)
      ? ((await options.connections.list?.(ctx)) ?? [])
      : options.connections
    return connections.map(connectionInfo)
  }

  const endpointUrl = (
    option: SamlOptions['callbackUrl'],
    connection: SamlConnection,
    ctx: ConnectionContext,
    suffix: string,
  ): string => {
    if (typeof option === 'function') return option(connection, ctx)
    if (option) return option
    if (basePath === false) {
      throw new Error(
        'payload-auth: set `callbackUrl` and `metadataUrl` when the endpoints are not mounted (basePath: false)',
      )
    }
    const api = trimSlash(ctx.payload.config.routes.api)
    return `${serverUrlOf(ctx.payload, ctx.request)}${api}/${usersSlug}${basePath}/${connection.id}/${suffix}`
  }
  const callbackUrl = (connection: SamlConnection, ctx: ConnectionContext) =>
    endpointUrl(options.callbackUrl, connection, ctx, 'acs')
  const metadataUrl = (connection: SamlConnection, ctx: ConnectionContext) =>
    endpointUrl(options.metadataUrl, connection, ctx, 'metadata')
  const entityId = (connection: SamlConnection, ctx: ConnectionContext) =>
    connection.entityId ?? metadataUrl(connection, ctx)

  /** node-saml settings shared by request generation, response validation and metadata. */
  function samlConfig(connection: SamlConnection, ctx: ConnectionContext) {
    return {
      callbackUrl: callbackUrl(connection, ctx),
      entryPoint: connection.entryPoint,
      issuer: entityId(connection, ctx),
      idpCert: connection.idpCert,
      idpIssuer: connection.idpIssuer,
      audience: entityId(connection, ctx),
      privateKey: connection.privateKey,
      publicCert: connection.publicCert,
      decryptionPvk: connection.decryptionPvk,
      identifierFormat:
        connection.identifierFormat === undefined
          ? 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
          : connection.identifierFormat,
      wantAssertionsSigned: connection.wantAssertionsSigned ?? true,
      wantAuthnResponseSigned: connection.wantAuthnResponseSigned ?? false,
      acceptedClockSkewMs: connection.acceptedClockSkewMs ?? 5000,
      maxAssertionAgeMs: connection.maxAssertionAgeMs ?? 0,
      forceAuthn: connection.forceAuthn ?? false,
      disableRequestedAuthnContext: !connection.authnContext,
      authnContext: connection.authnContext,
      signatureAlgorithm: connection.signatureAlgorithm ?? 'sha256',
      digestAlgorithm: connection.digestAlgorithm ?? 'sha256',
      logoutUrl: connection.logoutUrl,
    }
  }

  async function fail(
    ctx: SamlHandlerContext & { request: Request; connectionId?: string },
    code: string,
    cookies: string[],
    error: unknown,
  ): Promise<Response> {
    const custom = await options.onError?.({
      payload: ctx.payload,
      req: ctx.req,
      request: ctx.request,
      code,
      error,
      connectionId: ctx.connectionId,
      cookies,
    })
    if (custom) return custom
    return redirect(errorRedirectUrl(errorRedirect, code), cookies, 303)
  }

  const handlers: SamlHandlers = {
    async connections(request, { payload, req }) {
      return json({ connections: await listConnections({ payload, req, request }) })
    },

    async login(request, { payload, req, connectionId }) {
      const ctx = { payload, req, request, connectionId }
      const connection = await getConnection(connectionId, ctx)
      if (!connection) return fail(ctx, 'provider_unknown', [], new AuthError('provider_unknown'))

      const url = new URL(request.url)
      const next = safeRedirectPath(url.searchParams.get('next'), successRedirect)

      let linkUserId: string | undefined
      if (url.searchParams.get('link') === '1') {
        if (!allowLinking)
          return fail(ctx, 'provider_unknown', [], new AuthError('provider_unknown'))
        const { user } = await payload.auth({ headers: request.headers })
        if (!user || user.collection !== usersSlug) {
          return fail(ctx, 'not_signed_in', [], new AuthError('not_signed_in', { status: 401 }))
        }
        linkUserId = String(user.id)
      }

      try {
        const { SAML } = await loadNodeSaml()
        const requestId = newRequestId()
        const saml = new SAML({ ...samlConfig(connection, ctx), generateUniqueId: () => requestId })
        const location = await saml.getAuthorizeUrlAsync(connection.id, undefined, {})
        const cookie = await transactions(payload, request).issue({
          provider: connection.id,
          next,
          linkUserId,
          requestId,
        })
        return redirect(location, [cookie])
      } catch (error) {
        payload.logger.error(
          {
            err: error instanceof Error ? error.message : String(error),
            connection: connection.id,
          },
          'payload-auth: could not build the SAML request',
        )
        return fail(ctx, 'exchange_failed', [], error)
      }
    },

    async acs(request, { payload, req, connectionId }) {
      const ctx = { payload, req, request, connectionId }
      const store = transactions(payload, request)
      const clear = store.clear()
      const connection = await getConnection(connectionId, ctx)
      if (!connection)
        return fail(ctx, 'provider_unknown', [clear], new AuthError('provider_unknown'))

      const transaction = await store.read(request)
      if (transaction && transaction.provider !== connectionId) {
        return fail(ctx, 'state_mismatch', [clear], new AuthError('state_mismatch'))
      }
      if (!transaction && !connection.allowIdpInitiated) {
        return fail(ctx, 'state_mismatch', [clear], new AuthError('state_mismatch'))
      }
      const requestId =
        typeof transaction?.requestId === 'string' ? transaction.requestId : undefined

      const body = await readFormBody(request)
      if (!body.SAMLResponse)
        return fail(ctx, 'state_mismatch', [clear], new AuthError('state_mismatch'))

      try {
        const { SAML, ValidateInResponseTo } = await loadNodeSaml()
        const saml = new SAML({
          ...samlConfig(connection, ctx),
          // Solicited responses must answer our request (the id travels in the sealed cookie);
          // unsolicited ones are accepted only when the connection allows IdP-initiated login, and
          // then only without an `InResponseTo` we never issued.
          validateInResponseTo: requestId
            ? ValidateInResponseTo.always
            : ValidateInResponseTo.ifPresent,
          cacheProvider: {
            saveAsync: async () => null,
            getAsync: async (key: string) =>
              requestId && key === requestId ? new Date().toISOString() : null,
            removeAsync: async () => null,
          },
        })
        const { profile, loggedOut } = await saml.validatePostResponseAsync(body)
        if (loggedOut || !profile) throw new AuthError('exchange_failed')
        const samlProfileValue = profile as unknown as SamlProfile
        // node-saml checks the issuer of logout messages only; a signed assertion from an unexpected
        // issuer (a shared IdP key across tenants, say) is still refused here.
        if (connection.idpIssuer && samlProfileValue.issuer !== connection.idpIssuer) {
          throw new Error(
            `Unexpected SAML issuer: expected ${connection.idpIssuer}, received ${String(samlProfileValue.issuer)}`,
          )
        }

        if (options.replayCheck) {
          const assertion = profile.getAssertion?.() as Record<string, unknown> | undefined
          const assertionNode = assertion?.Assertion as Record<string, unknown> | undefined
          const attrs = assertionNode?.$ as Record<string, string> | undefined
          const id = attrs?.ID
          const conditions = (
            assertionNode?.Conditions as Array<{ $?: Record<string, string> }> | undefined
          )?.[0]?.$
          const notOnOrAfter = conditions?.NotOnOrAfter
            ? new Date(conditions.NotOnOrAfter)
            : new Date(Date.now() + 10 * 60_000)
          if (id && !(await options.replayCheck(id, notOnOrAfter, ctx))) {
            throw new AuthError('state_mismatch')
          }
        }

        const result = connection.profile
          ? await connection.profile(samlProfileValue)
          : samlProfile(connection, samlProfileValue)
        if (!result.providerAccountId) throw new Error('profile() returned no providerAccountId')
        const identity: ExternalIdentity = {
          provider: connection.id,
          providerAccountId: String(result.providerAccountId),
          email: result.email || undefined,
          emailVerified: result.emailVerified === true,
          name: result.name || undefined,
          picture: result.picture || undefined,
          raw: result.raw ?? {},
        }

        const info = connectionInfo(connection)
        const common = {
          payload,
          req,
          request,
          identity,
          provider: info,
          usersSlug,
          accountsSlug,
          options: options.users,
        }
        const resolved: ResolvedUser = transaction?.linkUserId
          ? await linkIdentity({ ...common, userId: transaction.linkUserId })
          : await resolveUser(common)
        const next = safeRedirectPath(transaction?.next, successRedirect)

        const custom = await options.onAuthenticated?.({
          payload,
          req,
          request,
          connection,
          identity,
          profile: samlProfileValue,
          user: resolved.user as AuthUser,
          created: resolved.created,
          linked: resolved.linked,
          linking: Boolean(transaction?.linkUserId),
          next,
          cookies: [clear],
        })
        if (custom) return custom

        if (transaction?.linkUserId) return redirect(next, [clear], 303)
        const session = await createSessionCookie({
          payload,
          collectionSlug: usersSlug,
          userId: resolved.user.id,
        })
        payload.logger.info(
          { user: resolved.user.id, connection: connection.id },
          'payload-auth: SAML login succeeded',
        )
        return redirect(next, [session.cookie, clear], 303)
      } catch (error) {
        if (isAuthError(error)) {
          payload.logger.warn(
            { code: error.code, connection: connection.id },
            'payload-auth: SAML login refused',
          )
          return fail(ctx, error.code, [clear], error)
        }
        payload.logger.error(
          {
            err: error instanceof Error ? error.message : String(error),
            connection: connection.id,
          },
          'payload-auth: SAML response rejected',
        )
        return fail(ctx, 'exchange_failed', [clear], error)
      }
    },

    async metadata(request, { payload, req, connectionId }) {
      const ctx = { payload, req, request, connectionId }
      const connection = await getConnection(connectionId, ctx)
      if (!connection) return json({ error: 'Unknown connection' }, { status: 404 })
      const { generateServiceProviderMetadata } = await loadNodeSaml()
      const config = samlConfig(connection, ctx)
      const xml = generateServiceProviderMetadata({
        issuer: config.issuer,
        callbackUrl: config.callbackUrl,
        identifierFormat: config.identifierFormat,
        wantAssertionsSigned: config.wantAssertionsSigned,
        decryptionPvk: connection.decryptionPvk,
        decryptionCert: connection.decryptionCert ?? null,
        privateKey: connection.privateKey,
        publicCerts: connection.publicCert ?? null,
        signatureAlgorithm: config.signatureAlgorithm,
        digestAlgorithm: config.digestAlgorithm,
      })
      return new Response(xml, {
        headers: {
          'content-type': 'application/samlmetadata+xml; charset=utf-8',
          'cache-control': 'no-store',
        },
      })
    },
  }

  const plugin: Plugin = (config: Config) => {
    usersSlug = options.usersSlug ?? defaultUsersSlug(config)
    if (options.accounts !== false) {
      accountsSlug = ensureLinkedAccountsCollection(config, {
        slug: options.accounts?.slug,
        usersSlug,
      })
    }
    if (basePath !== false) {
      const users = config.collections?.find((collection) => collection.slug === usersSlug)
      if (!users) throw new Error(`payload-auth: users collection "${usersSlug}" not found`)
      if (!users.auth)
        throw new Error(`payload-auth: collection "${usersSlug}" is not auth-enabled`)
      const param = (req: PayloadRequest, name: string) => String(req.routeParams?.[name] ?? '')
      const asRequest = (req: PayloadRequest) => req as unknown as Request
      const endpoints: Endpoint[] = [
        {
          path: `${basePath}/connections`,
          method: 'get',
          handler: (req) => handlers.connections(asRequest(req), { payload: req.payload, req }),
        },
        {
          path: `${basePath}/:connection/login`,
          method: 'get',
          handler: (req) =>
            handlers.login(asRequest(req), {
              payload: req.payload,
              req,
              connectionId: param(req, 'connection'),
            }),
        },
        {
          path: `${basePath}/:connection/acs`,
          method: 'post',
          handler: (req) =>
            handlers.acs(asRequest(req), {
              payload: req.payload,
              req,
              connectionId: param(req, 'connection'),
            }),
        },
        {
          path: `${basePath}/:connection/metadata`,
          method: 'get',
          handler: (req) =>
            handlers.metadata(asRequest(req), {
              payload: req.payload,
              req,
              connectionId: param(req, 'connection'),
            }),
        },
      ]
      users.endpoints = [...(users.endpoints || []), ...endpoints]
    }
    return config
  }

  return {
    plugin,
    handlers,
    getConnection,
    listConnections,
    callbackUrl,
    metadataUrl,
    entityId,
    get usersSlug() {
      return usersSlug
    },
    get accountsSlug() {
      return accountsSlug
    },
  }
}

/** Shorthand for `createSaml(options).plugin`. */
export const samlPlugin = (options: SamlOptions): Plugin => createSaml(options).plugin
