/**
 * SAML 2.0 sign-in for Payload (service provider). Requires the optional peer dependency
 * `@node-saml/node-saml`.
 *
 * ```ts
 * import { samlPlugin } from '@thinkhuman/payload-plugin-auth/saml'
 *
 * plugins: [
 *   samlPlugin({
 *     connections: [
 *       { id: 'okta', name: 'Okta', entryPoint: 'https://acme.okta.com/app/.../sso/saml', idpCert: '...' },
 *     ],
 *   }),
 * ]
 * ```
 */
export { parseIdpMetadata, type IdpMetadata } from './metadata.js'
export { DEFAULT_SAML_ATTRIBUTES, pickAttribute, samlProfile } from './profile.js'
export {
  assertConnection,
  CONNECTION_ID_PATTERN,
  connectionInfo,
  createSaml,
  samlPlugin,
  type Saml,
  type SamlHandlerContext,
  type SamlHandlers,
} from './saml.js'
export type {
  AssertionReplayCheck,
  ConnectionContext,
  SamlAttributeMap,
  SamlAuthenticatedContext,
  SamlConnection,
  SamlConnectionResolver,
  SamlConnections,
  SamlErrorContext,
  SamlOptions,
  SamlProfile,
  SamlProfileResult,
} from './types.js'
