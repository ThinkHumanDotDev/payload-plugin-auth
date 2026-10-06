import * as oidc from 'openid-client'
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
  readJsonBody,
  redirect,
  safeRedirectPath,
  trimSlash,
  wantsJson,
} from '../core/http.js'
import { linkIdentity, listAccounts, resolveUser } from '../core/resolve-user.js'
import {
  createSessionCookie,
  expiredSessionCookie,
  revokeSession,
  sessionIdOf,
} from '../core/session.js'
import { createTransactionStore, type TransactionStore } from '../core/transaction.js'
import type { AuthUser, ExternalIdentity, ProviderInfo, ResolvedUser } from '../core/types.js'

import { assertProvider, defaultScopes, getConfiguration, resetConfiguration } from './client.js'
import { oidcProfile } from './providers/presets.js'
import type {
  OAuthOptions,
  OAuthProvider,
  OAuthProviderResolver,
  OAuthTokens,
  ProviderContext,
} from './types.js'

export interface HandlerContext {
  payload: Payload
  /** Pass the Payload request when the handler runs inside a Payload endpoint. */
  req?: PayloadRequest
}

export interface OAuthHandlers {
  /** `GET …/providers` → `{ providers: ProviderInfo[] }`. */
  providers(request: Request, ctx: HandlerContext): Promise<Response>
  /** `GET …/:provider/login?next=/path&link=1` → redirect to the provider. */
  login(request: Request, ctx: HandlerContext & { providerId: string }): Promise<Response>
  /** `GET …/:provider/callback?code=…&state=…` → session cookie + redirect, or error redirect. */
  callback(request: Request, ctx: HandlerContext & { providerId: string }): Promise<Response>
  /**
   * `POST …/logout` → revokes the Payload session and answers with the provider's end-session URL
   * (RP-initiated logout) or the post-logout URL: JSON `{ redirectTo }` for `Accept: application/json`,
   * a 303 otherwise. The provider is taken from `providerId`, the `provider` body/query field or the
   * user's most recently used linked account.
   */
  logout(request: Request, ctx: HandlerContext & { providerId?: string }): Promise<Response>
}

export interface OAuth {
  /** Add to `buildConfig({ plugins })`. Registers the accounts collection and (unless `basePath: false`) the endpoints. */
  plugin: Plugin
  handlers: OAuthHandlers
  getProvider(id: string, ctx: ProviderContext): Promise<OAuthProvider | null>
  listProviders(ctx: ProviderContext): Promise<ProviderInfo[]>
  /** The redirect URI to register at the provider. */
  redirectUri(provider: OAuthProvider, ctx: ProviderContext): string
  /** Slugs in use (known once the plugin ran or from the options). */
  readonly usersSlug: string
  readonly accountsSlug: string
}

export const providerInfo = (provider: OAuthProvider): ProviderInfo => ({
  id: provider.id,
  name: provider.name,
  type: provider.type,
  icon: provider.icon,
  meta: provider.meta,
})

const isResolver = (providers: OAuthOptions['providers']): providers is OAuthProviderResolver =>
  !Array.isArray(providers)

const serverUrlOf = (payload: Payload, request: Request): string =>
  trimSlash(payload.config.serverURL || new URL(request.url).origin)

/**
 * Builds the OAuth 2.0 / OpenID Connect integration: a Payload plugin plus framework-agnostic
 * handlers (Fetch `Request` → `Response`) for hosts that mount the routes themselves.
 */
export function createOAuth(options: OAuthOptions): OAuth {
  const basePath = options.basePath === undefined ? '/oauth' : options.basePath
  const successRedirect = options.successRedirect ?? '/'
  const errorRedirect = options.errorRedirect ?? '/login'
  const allowLinking = options.allowLinking !== false

  let usersSlug = options.usersSlug ?? 'users'
  let accountsSlug =
    options.accounts === false
      ? DEFAULT_ACCOUNTS_SLUG
      : (options.accounts?.slug ?? DEFAULT_ACCOUNTS_SLUG)

  if (Array.isArray(options.providers)) {
    const ids = new Set<string>()
    for (const provider of options.providers) {
      assertProvider(provider)
      if (ids.has(provider.id))
        throw new Error(`payload-auth: duplicate provider id "${provider.id}"`)
      ids.add(provider.id)
    }
  }

  const stores = new WeakMap<Payload, TransactionStore>()
  const transactions = (payload: Payload, request: Request): TransactionStore => {
    let store = stores.get(payload)
    if (!store) {
      store = createTransactionStore(options.secret ?? payload.secret, 'oauth', {
        secure: serverUrlOf(payload, request).startsWith('https://'),
        ...options.cookie,
      })
      stores.set(payload, store)
    }
    return store
  }

  async function getProvider(id: string, ctx: ProviderContext): Promise<OAuthProvider | null> {
    if (!id) return null
    let provider: OAuthProvider | null | undefined
    if (isResolver(options.providers)) {
      provider = await options.providers.get(id, ctx)
      if (provider) assertProvider(provider)
    } else {
      provider = options.providers.find((p) => p.id === id)
    }
    return provider ?? null
  }

  async function listProviders(ctx: ProviderContext): Promise<ProviderInfo[]> {
    const providers = isResolver(options.providers)
      ? ((await options.providers.list?.(ctx)) ?? [])
      : options.providers
    return providers.map(providerInfo)
  }

  function redirectUri(provider: OAuthProvider, ctx: ProviderContext): string {
    if (typeof options.redirectUri === 'function') return options.redirectUri(provider, ctx)
    if (options.redirectUri) return options.redirectUri
    if (basePath === false) {
      throw new Error(
        'payload-auth: set `redirectUri` when the endpoints are not mounted (basePath: false)',
      )
    }
    const api = trimSlash(ctx.payload.config.routes.api)
    return `${serverUrlOf(ctx.payload, ctx.request)}${api}/${usersSlug}${basePath}/${provider.id}/callback`
  }

  async function fail(
    ctx: HandlerContext & { request: Request; providerId?: string },
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
      providerId: ctx.providerId,
      cookies,
    })
    if (custom) return custom
    return redirect(errorRedirectUrl(errorRedirect, code), cookies, 303)
  }

  const handlers: OAuthHandlers = {
    async providers(request, { payload, req }) {
      return json({ providers: await listProviders({ payload, req, request }) })
    },

    async login(request, { payload, req, providerId }) {
      const ctx = { payload, req, request, providerId }
      const provider = await getProvider(providerId, ctx)
      if (!provider) return fail(ctx, 'provider_unknown', [], new AuthError('provider_unknown'))

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

      let configuration: oidc.Configuration
      try {
        configuration = await getConfiguration(provider)
      } catch (error) {
        payload.logger.error(
          { err: error instanceof Error ? error.message : String(error), provider: provider.id },
          'payload-auth: provider discovery failed',
        )
        return fail(ctx, 'exchange_failed', [], error)
      }

      const state = oidc.randomState()
      const usePkce = provider.pkce !== false
      const codeVerifier = usePkce ? oidc.randomPKCECodeVerifier() : undefined
      const nonce = provider.type === 'oidc' ? oidc.randomNonce() : undefined

      const params: Record<string, string> = {
        redirect_uri: redirectUri(provider, ctx),
        scope: defaultScopes(provider).join(' '),
        state,
        ...(codeVerifier
          ? {
              code_challenge: await oidc.calculatePKCECodeChallenge(codeVerifier),
              code_challenge_method: 'S256',
            }
          : {}),
        ...(nonce ? { nonce } : {}),
        ...(provider.authorizationParams ?? {}),
      }
      const authorizationUrl = oidc.buildAuthorizationUrl(configuration, params)

      const cookie = await transactions(payload, request).issue({
        provider: provider.id,
        next,
        linkUserId,
        state,
        nonce,
        codeVerifier,
      })
      return redirect(authorizationUrl.href, [cookie])
    },

    async callback(request, { payload, req, providerId }) {
      const ctx = { payload, req, request, providerId }
      const store = transactions(payload, request)
      const clear = store.clear()
      const transaction = await store.read(request)
      if (!transaction || transaction.provider !== providerId) {
        return fail(ctx, 'state_mismatch', [clear], new AuthError('state_mismatch'))
      }

      const url = new URL(request.url)
      const providerError = url.searchParams.get('error')
      if (providerError) {
        payload.logger.warn(
          {
            provider: providerId,
            error: providerError,
            description: url.searchParams.get('error_description'),
          },
          'payload-auth: provider returned an authorization error',
        )
        return fail(ctx, 'access_denied', [clear], new AuthError('access_denied'))
      }
      if (url.searchParams.get('state') !== transaction.state) {
        return fail(ctx, 'state_mismatch', [clear], new AuthError('state_mismatch'))
      }

      const provider = await getProvider(providerId, ctx)
      if (!provider)
        return fail(ctx, 'provider_unknown', [clear], new AuthError('provider_unknown'))

      try {
        const configuration = await getConfiguration(provider)

        // Rebuild the callback URL from the registered redirect URI: behind a reverse proxy
        // `request.url` may carry an internal host, and the token request must repeat the exact URI.
        const currentUrl = new URL(redirectUri(provider, ctx))
        currentUrl.search = url.search

        const tokens: OAuthTokens = await oidc.authorizationCodeGrant(configuration, currentUrl, {
          pkceCodeVerifier:
            typeof transaction.codeVerifier === 'string' ? transaction.codeVerifier : undefined,
          expectedState: transaction.state as string,
          expectedNonce: typeof transaction.nonce === 'string' ? transaction.nonce : undefined,
          idTokenExpected: provider.type === 'oidc',
        })

        const claims = tokens.claims() as Record<string, unknown> | undefined
        let userinfo: Record<string, unknown> | undefined
        if (
          provider.type === 'oidc' &&
          configuration.serverMetadata().userinfo_endpoint &&
          typeof claims?.sub === 'string'
        ) {
          try {
            userinfo = (await oidc.fetchUserInfo(
              configuration,
              tokens.access_token,
              claims.sub,
            )) as Record<string, unknown>
          } catch (error) {
            payload.logger.warn(
              {
                err: error instanceof Error ? error.message : String(error),
                provider: provider.id,
              },
              'payload-auth: UserInfo request failed; using ID token claims only',
            )
          }
        }

        const fetchJson = async <T>(target: string): Promise<T> => {
          const response = await oidc.fetchProtectedResource(
            configuration,
            tokens.access_token,
            new URL(target),
            'GET',
            undefined,
            new Headers({ accept: 'application/json', 'user-agent': 'payload-auth' }),
          )
          if (!response.ok) throw new Error(`${target} responded with ${response.status}`)
          return (await response.json()) as T
        }

        const profile = await (provider.profile ?? oidcProfile)({
          provider,
          tokens,
          claims,
          userinfo,
          fetchJson,
        })
        if (!profile.providerAccountId) throw new Error('profile() returned no providerAccountId')
        const identity: ExternalIdentity = {
          provider: provider.id,
          providerAccountId: String(profile.providerAccountId),
          email: profile.email || undefined,
          emailVerified: profile.emailVerified === true,
          name: profile.name || undefined,
          picture: profile.picture || undefined,
          raw: profile.raw ?? { ...(claims ?? {}), ...(userinfo ?? {}) },
        }

        const info = providerInfo(provider)
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
        const resolved: ResolvedUser = transaction.linkUserId
          ? await linkIdentity({ ...common, userId: transaction.linkUserId })
          : await resolveUser(common)
        const next = safeRedirectPath(transaction.next, successRedirect)

        const custom = await options.onAuthenticated?.({
          payload,
          req,
          request,
          provider,
          identity,
          tokens,
          user: resolved.user as AuthUser,
          created: resolved.created,
          linked: resolved.linked,
          linking: Boolean(transaction.linkUserId),
          next,
          cookies: [clear],
        })
        if (custom) return custom

        if (transaction.linkUserId) {
          // Already signed in: nothing to issue, just go back.
          return redirect(next, [clear], 303)
        }
        const session = await createSessionCookie({
          payload,
          collectionSlug: usersSlug,
          userId: resolved.user.id,
        })
        payload.logger.info(
          { user: resolved.user.id, provider: provider.id },
          'payload-auth: login succeeded',
        )
        return redirect(next, [session.cookie, clear], 303)
      } catch (error) {
        if (isAuthError(error)) {
          payload.logger.warn(
            { code: error.code, provider: provider.id },
            'payload-auth: login refused',
          )
          return fail(ctx, error.code, [clear], error)
        }
        // Never log tokens or response bodies; the library's message is enough.
        payload.logger.error(
          { err: error instanceof Error ? error.message : String(error), provider: provider.id },
          'payload-auth: login failed',
        )
        // Provider metadata or keys may have rotated; rediscover on the next attempt.
        resetConfiguration(provider)
        return fail(ctx, 'exchange_failed', [clear], error)
      }
    },

    async logout(request, { payload, req, providerId }) {
      const ctx = { payload, req, request }
      const { user } = await payload.auth({ headers: request.headers })
      const cookies = [expiredSessionCookie(payload, usersSlug)]
      let redirectTo = options.postLogoutRedirectUri ?? `${serverUrlOf(payload, request)}/`

      if (user && user.collection === usersSlug) {
        await revokeSession({
          payload,
          collectionSlug: usersSlug,
          userId: user.id,
          sid: sessionIdOf(user),
        })

        const body = request.method === 'POST' ? await readJsonBody(request) : {}
        const hinted =
          providerId ??
          (typeof body.provider === 'string' ? body.provider : undefined) ??
          new URL(request.url).searchParams.get('provider') ??
          undefined
        let id = hinted
        if (!id) {
          const [latest] = await listAccounts({ payload, req, usersSlug, accountsSlug }, user.id)
          id = latest?.provider
        }
        const provider = id ? await getProvider(id, ctx) : null
        if (provider) {
          try {
            const configuration = await getConfiguration(provider)
            if (configuration.serverMetadata().end_session_endpoint) {
              redirectTo = oidc.buildEndSessionUrl(configuration, {
                post_logout_redirect_uri: redirectTo,
              }).href
            }
          } catch {
            // The provider is unreachable: a local logout is still a logout.
          }
        }
      }

      if (wantsJson(request)) return json({ redirectTo }, { cookies })
      return redirect(redirectTo, cookies, 303)
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
      // `PayloadRequest` is typed as a partial `Request`; at runtime it is the Fetch request itself.
      const asRequest = (req: PayloadRequest) => req as unknown as Request
      const endpoints: Endpoint[] = [
        {
          path: `${basePath}/providers`,
          method: 'get',
          handler: (req) => handlers.providers(asRequest(req), { payload: req.payload, req }),
        },
        {
          path: `${basePath}/:provider/login`,
          method: 'get',
          handler: (req) =>
            handlers.login(asRequest(req), {
              payload: req.payload,
              req,
              providerId: param(req, 'provider'),
            }),
        },
        {
          path: `${basePath}/:provider/callback`,
          method: 'get',
          handler: (req) =>
            handlers.callback(asRequest(req), {
              payload: req.payload,
              req,
              providerId: param(req, 'provider'),
            }),
        },
        {
          path: `${basePath}/logout`,
          method: 'post',
          handler: (req) => handlers.logout(asRequest(req), { payload: req.payload, req }),
        },
      ]
      users.endpoints = [...(users.endpoints || []), ...endpoints]
    }
    return config
  }

  return {
    plugin,
    handlers,
    getProvider,
    listProviders,
    redirectUri,
    get usersSlug() {
      return usersSlug
    },
    get accountsSlug() {
      return accountsSlug
    },
  }
}

/** Shorthand for `createOAuth(options).plugin`. */
export const oauthPlugin = (options: OAuthOptions): Plugin => createOAuth(options).plugin
