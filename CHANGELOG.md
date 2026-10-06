# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [SemVer](https://semver.org).

## [0.1.0] - 2026-10-06

### Added

- `linkByVerifiedEmail` accepts a function that decides per login whether an existing user with the same
  email may be linked (tenants with verified domains).
- `onError` receives the transaction of a failed callback (`transaction.linkUserId`, `transaction.next`) so
  hosts can send a signed-in user who was linking an account back to where they started.

- Core: `linkedAccountsCollection`, `createSessionCookie` / `revokeSession`, `resolveUser` /
  `linkIdentity` with host hooks, `AuthError` codes, sealed transaction cookies.
- OAuth 2.0 / OpenID Connect plugin (`./oauth`): authorization code + PKCE, discovery, ID-token and
  UserInfo handling, RP-initiated logout, account linking for signed-in users, static providers or an
  async resolver, presets for GitHub, Google, Microsoft Entra ID, GitLab, Discord and generic OIDC/OAuth2.
- SAML 2.0 plugin (`./saml`): SP-initiated (HTTP-Redirect) and optional IdP-initiated login, HTTP-POST
  assertion consumer, SP metadata, IdP metadata parsing, `InResponseTo` bound to a sealed cookie,
  optional replay check, attribute mapping.
