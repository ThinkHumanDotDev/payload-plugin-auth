<h1 align="center">@thinkhuman/payload-plugin-auth</h1>

<p align="center">
  Single sign-on for <a href="https://payloadcms.com">Payload CMS 3</a>: OAuth 2.0 / OpenID Connect and SAML 2.0, with linked accounts, provider presets and database-backed connections for multi-tenant apps.
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/@thinkhuman/payload-plugin-auth"><img src="https://img.shields.io/npm/v/@thinkhuman/payload-plugin-auth.svg" alt="npm version"></a>
  <a href="https://github.com/ThinkHumanDotDev/payload-plugin-auth/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/ThinkHumanDotDev/payload-plugin-auth/ci.yml?branch=main" alt="CI status"></a>
  <a href="https://github.com/ThinkHumanDotDev/payload-plugin-auth/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="MIT license"></a>
</p>

## What you get

- **`@thinkhuman/payload-plugin-auth/oauth`** — OAuth 2.0 and OpenID Connect sign-in: authorization code flow
  with PKCE, discovery, ID-token verification, UserInfo, RP-initiated logout. Presets for GitHub, Google,
  Microsoft Entra ID, GitLab, Discord, any OIDC issuer and any plain OAuth 2.0 server.
- **`@thinkhuman/payload-plugin-auth/saml`** — SAML 2.0 service provider: SP-initiated login (HTTP-Redirect),
  optional IdP-initiated login, HTTP-POST assertion consumer, SP metadata, IdP metadata parsing.
- **`@thinkhuman/payload-plugin-auth`** (core) — a `linked accounts` collection (`provider + providerAccountId →
user`, many per user), Payload session issuance that is indistinguishable from a password login, identity →
  user resolution with hooks (match account → link by verified email → provision), sealed transaction cookies.

Providers and connections can be a static list **or an async resolver**, so a hosted product can keep one
SSO connection per customer organization in a collection and resolve it at request time.

The handlers are plain Fetch `Request → Response` functions. The plugins mount them as Payload endpoints;
you can also mount them yourself (Next.js route handlers, rate limiting, custom paths).

## Install

```sh
pnpm add @thinkhuman/payload-plugin-auth
# SAML only:
pnpm add @node-saml/node-saml
```

Requires Payload `^3.0.0` and Node `>=20.9`.

## Quick start

```ts
// payload.config.ts
import { buildConfig } from 'payload'
import { github, google, oauthPlugin, oidc } from '@thinkhuman/payload-plugin-auth/oauth'
import { samlPlugin } from '@thinkhuman/payload-plugin-auth/saml'

export default buildConfig({
  serverURL: 'https://app.example.com',
  collections: [Users],
  plugins: [
    oauthPlugin({
      providers: [
        github({
          clientId: process.env.GITHUB_CLIENT_ID!,
          clientSecret: process.env.GITHUB_CLIENT_SECRET!,
        }),
        google({
          clientId: process.env.GOOGLE_CLIENT_ID!,
          clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
        }),
        oidc({
          id: 'okta',
          name: 'Okta',
          issuer: 'https://acme.okta.com',
          clientId: process.env.OKTA_CLIENT_ID!,
          clientSecret: process.env.OKTA_CLIENT_SECRET!,
        }),
      ],
    }),
    samlPlugin({
      connections: [
        {
          id: 'corp',
          name: 'Corp SSO',
          entryPoint: 'https://idp.example.com/sso/saml',
          idpCert: process.env.CORP_IDP_CERT!,
          idpIssuer: 'https://idp.example.com/metadata',
        },
      ],
    }),
  ],
})
```

With the defaults, the plugins add these endpoints to the users collection (`/api/users/...`):

| Method | Path                              | What it does                                                            |
| ------ | --------------------------------- | ----------------------------------------------------------------------- |
| GET    | `/oauth/providers`                | `{ providers: [{ id, name, type, icon, meta }] }` for the login page    |
| GET    | `/oauth/:provider/login?next=/p`  | Redirects to the provider (add `&link=1` to link to the signed-in user) |
| GET    | `/oauth/:provider/callback`       | Redirect URI to register at the provider                                |
| POST   | `/oauth/logout`                   | Revokes the session; answers with the provider's end-session URL        |
| GET    | `/saml/connections`               | `{ connections: [...] }`                                                |
| GET    | `/saml/:connection/login?next=/p` | Redirects to the IdP with an AuthnRequest                               |
| POST   | `/saml/:connection/acs`           | Assertion consumer service (register at the IdP)                        |
| GET    | `/saml/:connection/metadata`      | Service-provider metadata (also the default entity id)                  |

A login page is as simple as:

```tsx
const { providers } = await fetch('/api/users/oauth/providers').then((r) => r.json())
providers.map((p) => (
  <a href={`/api/users/oauth/${p.id}/login?next=/dashboard`}>Continue with {p.name}</a>
))
```

Successful logins set the regular Payload auth cookie and redirect to `next` (same-origin paths only).
Failures redirect to `errorRedirect` (default `/login`) with `?error=<code>`; see
[Error codes](#error-codes).

## How identities become users

1. A linked account with the same `(provider, providerAccountId)` → that user.
2. Otherwise a user with the same email, **only if the provider asserted the email as verified**
   (`email_verified` for OIDC, the primary verified email for GitHub, `emailVerified` on a SAML
   connection). An unverified email never takes over an existing account (`email_unverified`), unless
   `linkByVerifiedEmail` is a function and it says so (for example because the tenant verified the domain).
3. Otherwise, when `autoProvision` allows it, a new user is created (`email`, `name`, a random password)
   plus whatever `mapNewUser` returns, and the account is linked.

Every step has a hook (`users` option, shared by both plugins):

```ts
oauthPlugin({
  providers,
  users: {
    autoProvision: ({ provider }) => provider.meta?.jit !== false,
    // or a function: ({ identity, user }) => identity.emailVerified || trustedDomain(identity.email)
    linkByVerifiedEmail: true,
    mapNewUser: ({ identity }) => ({ roles: ['member'], avatarUrl: identity.picture }),
    beforeProvision: async ({ payload, identity }) => {
      // Throw to refuse with your own code → /login?error=invitation_required
      if (!(await hasInvitation(payload, identity.email)))
        throw new AuthError('invitation_required')
    },
    afterProvision: async ({ payload, user, identity }) => acceptInvitation(payload, user),
    afterLogin: async ({ user }) => audit('login', user.id),
  },
  onAuthenticated: async ({ user, next, cookies }) => {
    // Return a Response to take over, e.g. a second factor before the session is issued.
    if (user.twoFactorEnabled) return Response.redirect(`/login?two_factor=1&next=${next}`, 303)
  },
})
```

Signed-in users can **link** another identity: send them to `/oauth/:provider/login?link=1&next=/settings`.
The callback attaches the identity to their account (refusing identities that belong to someone else with
`account_in_use`) and redirects without issuing a new session. Use `listAccounts` / `unlinkAccount` from the
core to build the settings UI; decide yourself whether the last sign-in method may be removed.

## OAuth / OIDC

### `oauthPlugin(options)` / `createOAuth(options)`

| Option                  | Default                                                   | Notes                                                                                                                                                                    |
| ----------------------- | --------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `providers`             | —                                                         | `OAuthProvider[]` or `{ get(id, ctx), list?(ctx) }` resolver                                                                                                             |
| `usersSlug`             | `config.admin.user` or `users`                            | Auth-enabled collection                                                                                                                                                  |
| `accounts`              | `{ slug: 'auth-accounts' }`                               | Linked-accounts collection; `false` to register it yourself with `linkedAccountsCollection()`                                                                            |
| `basePath`              | `/oauth`                                                  | Endpoint prefix on the users collection; `false` to mount `handlers` yourself                                                                                            |
| `redirectUri`           | `${serverURL}${api}/${users}${basePath}/${id}/callback`   | String or `(provider, ctx) => string`; must match what is registered at the provider                                                                                     |
| `successRedirect`       | `/`                                                       | Destination when no `next` was given                                                                                                                                     |
| `errorRedirect`         | `/login`                                                  | Gets `?error=<code>`                                                                                                                                                     |
| `postLogoutRedirectUri` | `${serverURL}/`                                           | Where RP-initiated logout returns to                                                                                                                                     |
| `cookie`                | `{ name: 'payload-auth-tx', path: '/', ttlSeconds: 600 }` | Transaction cookie; `secure` defaults to `true` on https                                                                                                                 |
| `secret`                | Payload secret                                            | Key for the transaction cookie                                                                                                                                           |
| `allowLinking`          | `true`                                                    | Whether `?link=1` is honoured                                                                                                                                            |
| `users`                 | `{}`                                                      | Resolution hooks, see above                                                                                                                                              |
| `onAuthenticated`       | —                                                         | `(ctx) => Response \| void` before the session is issued                                                                                                                 |
| `onError`               | —                                                         | `(ctx) => Response \| void` instead of the error redirect; `ctx.transaction` is set when the cookie was readable (linking: `transaction.linkUserId`, `transaction.next`) |

`createOAuth` returns `{ plugin, handlers, getProvider, listProviders, redirectUri }`. `handlers.login`,
`callback`, `providers` and `logout` take `(request, { payload, req?, providerId })` and return a `Response`,
so you can mount them under your own routes with your own rate limiting:

```ts
// app/api/auth/oauth/[provider]/callback/route.ts (Next.js)
export const GET = (request: Request, { params }) =>
  oauth.handlers.callback(request, {
    payload: await getPayload({ config }),
    providerId: params.provider,
  })
```

### `OAuthProvider`

| Field                                                                                            | Notes                                                                                |
| ------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------ |
| `id`, `name`, `type: 'oidc' \| 'oauth2'`                                                         | `id` is used in URLs and stored on accounts                                          |
| `clientId`, `clientSecret?`                                                                      | Public clients omit the secret (`clientAuth: 'none'`)                                |
| `issuer`                                                                                         | OIDC discovery (`/.well-known/openid-configuration`)                                 |
| `authorizationEndpoint`, `tokenEndpoint`, `userinfoEndpoint?`, `jwksUri?`, `endSessionEndpoint?` | Explicit endpoints for servers without discovery                                     |
| `scopes`                                                                                         | Default `openid email profile` for OIDC                                              |
| `pkce`                                                                                           | Default `true` (S256)                                                                |
| `clientAuth`                                                                                     | `client_secret_basic` (default with a secret), `client_secret_post`, `none`          |
| `authorizationParams`                                                                            | Extra parameters (`prompt`, `hd`, `access_type`, ...)                                |
| `profile(ctx)`                                                                                   | Maps `{ tokens, claims, userinfo, fetchJson }` to an identity. Required for `oauth2` |
| `allowInsecureRequests`                                                                          | Accept `http://` endpoints (default: outside `NODE_ENV=production`)                  |
| `icon`, `meta`                                                                                   | Passed through to `listProviders()` and hooks                                        |

### Presets

| Preset                                | Type   | Notes                                                                                  |
| ------------------------------------- | ------ | -------------------------------------------------------------------------------------- |
| `github({ clientId, clientSecret })`  | oauth2 | Primary verified email from `/user/emails` (`user:email` scope); works for GitHub Apps |
| `google({ clientId, clientSecret })`  | oidc   | `authorizationParams: { hd: 'example.com' }` to restrict the domain                    |
| `microsoft({ ..., tenant })`          | oidc   | Needs a tenant id (multi-tenant aliases have no stable issuer)                         |
| `gitlab({ ..., baseUrl? })`           | oidc   | gitlab.com or self-managed                                                             |
| `discord({ clientId, clientSecret })` | oauth2 | `identify email`                                                                       |
| `oidc({ id, name, issuer, ... })`     | oidc   | Keycloak, Authentik, Okta, Auth0, Zitadel, Dex, Entra ID, ...                          |
| `oauth2({ ..., profile })`            | oauth2 | Anything with authorization + token endpoints                                          |

Every preset accepts `id` and `name` overrides so the same provider can be registered twice.

### Database-backed providers (multi-tenant)

```ts
const oauth = createOAuth({
  providers: {
    async get(id, { payload }) {
      const conn = await findConnection(payload, id) // your collection
      return (
        conn &&
        oidc({
          id,
          name: conn.name,
          issuer: conn.issuer,
          clientId: conn.clientId,
          clientSecret: decrypt(conn.secret),
          meta: { organization: conn.organization },
        })
      )
    },
    async list({ payload }) {
      return instanceWideProviders // what the public login page shows
    },
  },
  users: {
    mapNewUser: ({ provider }) => ({
      organizations: [{ organization: provider.meta?.organization, role: 'member' }],
    }),
  },
})
```

Configurations are cached per client registration; a changed secret or issuer is picked up on the next
request, and a failed token exchange triggers rediscovery.

## SAML

### `samlPlugin(options)` / `createSaml(options)`

Same shape as the OAuth options (`connections` instead of `providers`, `callbackUrl` / `metadataUrl`
instead of `redirectUri`, `replayCheck`). `createSaml` returns `{ plugin, handlers, getConnection,
listConnections, callbackUrl, metadataUrl, entityId }`.

### `SamlConnection`

| Field                                              | Notes                                                                            |
| -------------------------------------------------- | -------------------------------------------------------------------------------- |
| `id`, `name`                                       |                                                                                  |
| `entryPoint`                                       | IdP SSO URL (HTTP-Redirect binding)                                              |
| `idpCert`                                          | IdP signing certificate(s), PEM or bare base64                                   |
| `idpIssuer?`                                       | Expected `Issuer` of responses                                                   |
| `entityId?`                                        | SP entity id; default: the metadata URL                                          |
| `privateKey?`, `publicCert?`                       | Sign AuthnRequests and metadata                                                  |
| `decryptionPvk?`, `decryptionCert?`                | Encrypted assertions                                                             |
| `identifierFormat?`                                | Default `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`; `null` to omit |
| `wantAssertionsSigned` / `wantAuthnResponseSigned` | Defaults `true` / `false`                                                        |
| `acceptedClockSkewMs`, `maxAssertionAgeMs`         | Defaults 5000 / 0                                                                |
| `allowIdpInitiated`                                | Default `false`                                                                  |
| `attributes`                                       | Attribute names per identity field, merged over the built-in list                |
| `emailVerified`                                    | Default `true` (the IdP is authoritative); `false` disables linking by email     |
| `profile(profile)`                                 | Replace the attribute mapping                                                    |

`parseIdpMetadata(xml)` turns an IdP metadata document into `{ entityId, entryPoint, certificates,
logoutUrl, nameIdFormats }` for an admin UI that accepts metadata by URL or paste.

### Security notes

- Solicited responses must carry the `InResponseTo` of the request this server issued; the request id
  travels in a sealed cookie (`payload-auth-saml`, `SameSite=None; Secure` on https because the ACS is a
  cross-site POST). IdP-initiated responses are accepted only when the connection allows them and only
  without an `InResponseTo`.
- Signatures (assertion and/or response), audience, `NotBefore`/`NotOnOrAfter`, subject confirmation and
  issuer are validated by `@node-saml/node-saml`; the plugin adds the issuer check for login responses.
- Provide `replayCheck(assertionId, expiresAt)` backed by Redis or a database to refuse a replayed
  assertion within its validity window across processes.
- Single logout is not implemented.

## Core API

```ts
import {
  AuthError, // throw in hooks: new AuthError('invitation_required')
  linkedAccountsCollection, // register the accounts collection yourself
  createSessionCookie,
  revokeSession,
  expiredSessionCookie, // Payload sessions
  resolveUser,
  linkIdentity,
  listAccounts,
  unlinkAccount, // identity ↔ user
  createTransactionStore,
  seal,
  openSealed, // sealed cookies
  safeRedirectPath,
  readCookie,
  serializeCookie,
} from '@thinkhuman/payload-plugin-auth'
```

The accounts collection (`auth-accounts`) has `user`, `provider`, `providerAccountId`, `email`, `name`,
`lastLoginAt` and a unique index on `(provider, providerAccountId)`. Default access: users read and delete
(unlink) their own rows; nothing is writable through the API.

## Error codes

| Code                    | Meaning                                                            |
| ----------------------- | ------------------------------------------------------------------ |
| `provider_unknown`      | No provider/connection with that id, or linking is disabled        |
| `state_mismatch`        | Transaction cookie missing, expired, forged or for another request |
| `access_denied`         | The provider returned an authorization error                       |
| `exchange_failed`       | Token exchange, assertion validation or profile retrieval failed   |
| `email_missing`         | No email released                                                  |
| `email_unverified`      | Existing user with that email, email not asserted verified         |
| `provisioning_disabled` | No matching user and `autoProvision` is off                        |
| `account_in_use`        | Linking: identity belongs to another user                          |
| `not_signed_in`         | Linking requested without a session                                |

`authErrorMessage(code)` gives a default message; hosts usually map codes to their own copy.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: [SECURITY.md](SECURITY.md). If this package is
useful to you, consider [sponsoring its development](https://github.com/sponsors/EggsLeggs).

## License

[MIT](LICENSE)
