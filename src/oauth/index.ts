/**
 * OAuth 2.0 / OpenID Connect sign-in for Payload.
 *
 * ```ts
 * import { oauthPlugin, github, google, oidc } from '@thinkhuman/payload-auth/oauth'
 *
 * plugins: [
 *   oauthPlugin({
 *     providers: [
 *       github({ clientId, clientSecret }),
 *       google({ clientId, clientSecret }),
 *       oidc({ id: 'okta', name: 'Okta', issuer: 'https://acme.okta.com', clientId, clientSecret }),
 *     ],
 *   }),
 * ]
 * ```
 */
export { getConfiguration, resetConfiguration } from './client.js'
export {
  createOAuth,
  oauthPlugin,
  providerInfo,
  type HandlerContext,
  type OAuth,
  type OAuthHandlers,
} from './oauth.js'
export {
  discord,
  github,
  gitlab,
  google,
  microsoft,
  oauth2,
  oidc,
  oidcProfile,
} from './providers/index.js'
export type {
  AuthenticatedContext,
  ClientAuthMethod,
  OAuthErrorContext,
  OAuthOptions,
  OAuthProvider,
  OAuthProviderResolver,
  OAuthProviders,
  OAuthTokens,
  ProfileContext,
  ProfileResult,
  ProviderContext,
} from './types.js'
