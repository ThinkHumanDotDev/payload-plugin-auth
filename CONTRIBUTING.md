# Contributing to @thinkhumandotdev/payload-auth

Thanks for helping! Issues and pull requests are the unit of work. The [README](README.md) documents the
API; this page is the contributor workflow. By participating you agree to the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Workflow

1. **Open or pick an issue first.** Features without an approved issue may be closed; small fixes and docs
   corrections do not need one. Use the issue templates (bug report, feature request).
2. Branch from `main` using a plain name: `feat/<slug>`, `fix/<slug>`, `chore/<slug>`, `docs/<slug>`,
   `ci/<slug>`. No personal or tool prefixes.
3. Keep PRs focused: one issue per PR, referenced with `Closes #NN`.
4. Run `pnpm check` before pushing (format, lint, typecheck, tests, build). A red check is yours to fix;
   never skip or disable a test to get green.
5. Fill in the pull request template (summary, how it was tested, checklist).
6. PRs are squash-merged; the PR title becomes the commit subject and must follow Conventional Commits
   (a CI check enforces it).

## Local setup

```sh
pnpm install
pnpm check
```

Use pnpm (version in `package.json` → `packageManager`) and Node 22, the versions CI runs. Tests boot a
real Payload on SQLite (`tests/.data/`, ignored) and talk to in-process mock identity providers; no
external services are needed.

## Commit messages and PR titles

[Conventional Commits](https://www.conventionalcommits.org): `type(scope): subject`.

- Types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `ci`, `build`, `perf`.
- Scopes: `core`, `oauth`, `saml`, `deps`, `ci`, `docs`, `release`.
- Subject in the imperative, no trailing period. Keep the body for the _why_.
- Breaking changes to the public API (option names, exports, endpoint paths, the accounts collection
  shape) need a `!` after the type and a note in the PR body.
- **No trailers of any kind**: no `Co-authored-by`, no `Signed-off-by`, no tool or session links. Commits
  that carry them are rewritten before merge.

## Code conventions

- TypeScript strict, ESM only, Node ≥ 20.9. Prettier formats, ESLint lints.
- Three entry points, kept independent: `.` (core), `./oauth`, `./saml`. The SAML entry point must keep
  working when `@node-saml/node-saml` is not installed until a handler runs (lazy import).
- Follow the specifications, not a particular provider: RFC 6749/7636 (OAuth 2.0, PKCE), OpenID Connect
  Core 1.0, SAML 2.0 Web Browser SSO Profile. Provider presets only add endpoints, scopes and profile
  mapping.
- Handlers take and return Fetch `Request`/`Response` and never depend on Next.js or Express; the Payload
  endpoints are thin adapters.
- Never log tokens, assertions or secrets. Error codes sent to the browser come from a closed list
  (`AUTH_ERROR_CODES`) or from host-defined `AuthError`s.
- Tests: Vitest in `tests/` for behaviour that matters (every rejection path, linking rules, cookie
  attributes, provider presets' profile mapping). No snapshot tests, no tests of trivial getters.
- A new provider preset needs: the preset in `src/oauth/providers/presets.ts`, a row in the README table,
  and a test of its `profile()` against a mocked API response.

## Releases

Bump `version` in `package.json` in a `chore(release): vX.Y.Z` PR with the CHANGELOG entry. Once it lands
on `main`, [`publish.yml`](.github/workflows/publish.yml) publishes to npm (trusted publishing) and
creates the GitHub release.

## Branch protection (maintainers)

`main` is protected by the repository ruleset in [`.github/rulesets/main.json`](.github/rulesets/main.json):
changes land through squash-merged pull requests with linear history, the `check` and
`Conventional PR title` checks must pass, review threads must be resolved, force pushes and deletion are
blocked, and admins may bypass on a pull request only. Apply it under **Settings → Rules → Rulesets →
New ruleset → Import a ruleset**, or with the GitHub CLI:

```sh
gh api --method POST repos/ThinkHumanDotDev/payload-plugin-auth/rulesets --input .github/rulesets/main.json
```

Check names in the ruleset must match the job `name:` fields in `ci.yml` and `pr-title.yml`; rename them
together. Under **Settings → General → Pull Requests**, allow squash merging only, default the commit
message to the PR title, and enable automatic deletion of head branches.

## Licensing

By contributing you agree that your contributions are licensed under the [MIT license](LICENSE).
