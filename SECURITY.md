# Security policy

Please report vulnerabilities privately via GitHub's "Report a vulnerability" button on this repository
(Security → Advisories) or by email to security@thinkhuman.dev. Do not open public issues for security
reports. We aim to acknowledge reports within 72 hours.

Supported versions: the latest published release.

## Scope

This package implements the relying-party / service-provider side of OAuth 2.0, OpenID Connect and
SAML 2.0 for Payload CMS. Anything that lets an attacker sign in as, link to or take over an account
they do not own is in scope: state/nonce/PKCE handling, assertion and token validation, account
linking rules, the transaction cookie, session issuance. Bugs in `openid-client`, `@node-saml/node-saml`
or Payload itself belong to those projects, but tell us if this package uses them unsafely.

## Hardening notes for integrators

- Serve the application over HTTPS so the transaction cookie carries `Secure` and SAML responses can
  use `SameSite=None`.
- Keep `linkByVerifiedEmail` on only for providers that assert verified emails; for SAML set
  `emailVerified: false` on connections whose IdP you do not fully control, or verify domains yourself.
- Provide a `replayCheck` backed by shared storage for SAML in multi-process deployments.
- Rate-limit the login and callback endpoints; the package deliberately leaves that to the host.
