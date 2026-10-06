import * as oidc from 'openid-client'

import type { ClientAuthMethod, OAuthProvider } from './types.js'

const isProduction = () => process.env.NODE_ENV === 'production'

export const PROVIDER_ID_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/i

export function assertProvider(provider: OAuthProvider): void {
  if (!PROVIDER_ID_PATTERN.test(provider.id)) {
    throw new Error(`payload-auth: provider id "${provider.id}" must match ${PROVIDER_ID_PATTERN}`)
  }
  if (!provider.clientId)
    throw new Error(`payload-auth: provider "${provider.id}" needs a clientId`)
  if (provider.type === 'oidc') {
    if (!provider.issuer && !(provider.authorizationEndpoint && provider.tokenEndpoint)) {
      throw new Error(
        `payload-auth: OIDC provider "${provider.id}" needs an issuer or explicit endpoints`,
      )
    }
  } else {
    if (!provider.authorizationEndpoint || !provider.tokenEndpoint) {
      throw new Error(
        `payload-auth: OAuth provider "${provider.id}" needs authorizationEndpoint and tokenEndpoint`,
      )
    }
    if (!provider.profile) {
      throw new Error(`payload-auth: OAuth provider "${provider.id}" needs a profile() function`)
    }
  }
}

function clientAuth(provider: OAuthProvider): oidc.ClientAuth {
  const method: ClientAuthMethod =
    provider.clientAuth ?? (provider.clientSecret ? 'client_secret_basic' : 'none')
  switch (method) {
    case 'client_secret_post':
      return oidc.ClientSecretPost(provider.clientSecret)
    case 'none':
      return oidc.None()
    case 'client_secret_basic':
    default:
      return oidc.ClientSecretBasic(provider.clientSecret)
  }
}

const allowsInsecure = (provider: OAuthProvider): boolean =>
  provider.allowInsecureRequests ?? !isProduction()

/** Everything that identifies a client registration; a change invalidates the cached configuration. */
const cacheKey = (provider: OAuthProvider): string =>
  JSON.stringify([
    provider.id,
    provider.type,
    provider.issuer,
    provider.authorizationEndpoint,
    provider.tokenEndpoint,
    provider.userinfoEndpoint,
    provider.jwksUri,
    provider.endSessionEndpoint,
    provider.clientId,
    provider.clientSecret,
    provider.clientAuth,
  ])

const cache = new Map<string, Promise<oidc.Configuration>>()

/** Builds (or reuses) the openid-client configuration for a provider. Failed discoveries are not cached. */
export function getConfiguration(provider: OAuthProvider): Promise<oidc.Configuration> {
  const key = cacheKey(provider)
  const cached = cache.get(key)
  if (cached) return cached

  const timeout = provider.timeoutSeconds ?? 15
  let pending: Promise<oidc.Configuration>

  if (provider.issuer && !provider.authorizationEndpoint) {
    const issuer = new URL(provider.issuer)
    const execute =
      issuer.protocol === 'http:' && allowsInsecure(provider) ? [oidc.allowInsecureRequests] : []
    pending = oidc.discovery(
      issuer,
      provider.clientId,
      provider.clientSecret,
      clientAuth(provider),
      {
        execute,
        timeout,
      },
    )
  } else {
    const authorizationEndpoint = provider.authorizationEndpoint as string
    const metadata: oidc.ServerMetadata = {
      issuer: provider.issuer ?? new URL(authorizationEndpoint).origin,
      authorization_endpoint: authorizationEndpoint,
      token_endpoint: provider.tokenEndpoint,
      userinfo_endpoint: provider.userinfoEndpoint,
      jwks_uri: provider.jwksUri,
      end_session_endpoint: provider.endSessionEndpoint,
    }
    const configuration = new oidc.Configuration(
      metadata,
      provider.clientId,
      provider.clientSecret,
      clientAuth(provider),
    )
    if (allowsInsecure(provider) && /^http:/.test(authorizationEndpoint)) {
      oidc.allowInsecureRequests(configuration)
    }
    configuration[oidc.customFetch] = (url, options) =>
      fetch(url, { ...(options as RequestInit), signal: AbortSignal.timeout(timeout * 1000) })
    pending = Promise.resolve(configuration)
  }

  const tracked = pending.catch((error: unknown) => {
    cache.delete(key)
    throw error
  })
  cache.set(key, tracked)
  return tracked
}

/** Forgets a provider's configuration so the next request rediscovers it (rotated keys, new metadata). */
export function resetConfiguration(provider?: OAuthProvider): void {
  if (provider) cache.delete(cacheKey(provider))
  else cache.clear()
}

export const defaultScopes = (provider: OAuthProvider): string[] =>
  provider.scopes ?? (provider.type === 'oidc' ? ['openid', 'email', 'profile'] : [])
