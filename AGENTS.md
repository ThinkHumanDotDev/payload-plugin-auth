# payload-auth — agent guide

`@thinkhuman/payload-auth` is a set of single sign-on plugins for Payload CMS 3: OAuth 2.0 / OpenID
Connect (`./oauth`), SAML 2.0 (`./saml`) and the core they share (`.`: linked accounts, sessions, user
resolution). Read `CONTRIBUTING.md` before changing anything; the README is the API reference.

## Commands

- `pnpm check` – format, lint, typecheck, tests and build (run before every push)
- `pnpm test` – Vitest; suites boot Payload on SQLite with in-process mock identity providers
- `pnpm build` – `tsc` to `dist/` (ESM + declarations)

## Hard rules

- Conventional Commits, **no trailers** (no Co-authored-by, no session links). Plain branch names
  (`feat/…`, `fix/…`, `chore/…`); never `claude/*`.
- No framework dependency: handlers are Fetch `Request` → `Response`; Payload endpoints are adapters.
- Follow the specs (RFC 6749, RFC 7636, OpenID Connect Core, SAML 2.0 Web SSO). Every rejection path
  (state, nonce, PKCE, signature, audience, expiry, replay, unverified email) keeps a test.
- Never log tokens, assertions or secrets. Browser-facing error codes come from `AUTH_ERROR_CODES` or
  host `AuthError`s, never from provider input.
- `@node-saml/node-saml` stays an optional peer dependency loaded lazily inside the SAML handlers.
- Never skip or disable tests to get green. Keep PRs focused; one issue per PR.
