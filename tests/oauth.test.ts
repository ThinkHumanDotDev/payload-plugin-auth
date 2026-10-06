import type { Payload } from 'payload'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'

import { AuthError, listAccounts } from '../src/index.js'
import { createOAuth, oauth2, oidc, type OAuthProvider } from '../src/oauth/index.js'
import { startMockIssuer, type MockIssuer } from './helpers/mock-issuer.js'
import {
  authenticate,
  authorizeAt,
  bootPayload,
  locationOf,
  SERVER_URL,
  sessionCookieOf,
} from './helpers/payload.js'

let issuer: MockIssuer
let payload: Payload
let autoProvision = true
let refuseProvisioning = false
const seen: string[] = []

const run = Date.now().toString(36)
const email = (name: string) => `${name}-${run}@example.test`

let oauth: ReturnType<typeof createOAuth>
/** Providers served through a resolver, like database-backed connections would be. */
const dynamic = new Map<string, OAuthProvider>()

const txCookieOf = (res: Response) =>
  res.headers
    .getSetCookie()
    .find((c) => c.startsWith('payload-auth-tx='))
    ?.split(';')[0]

async function startLogin(
  providerId: string,
  query: Record<string, string> = {},
  headers?: HeadersInit,
) {
  const url = new URL(`${SERVER_URL}/api/users/oauth/${providerId}/login`)
  for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v)
  const res = await oauth.handlers.login(new Request(url, { headers }), { payload, providerId })
  return { res, cookie: txCookieOf(res), location: locationOf(res) }
}

async function callback(providerId: string, url: URL, cookie?: string) {
  const headers = new Headers()
  if (cookie) headers.set('cookie', cookie)
  return oauth.handlers.callback(new Request(url, { headers }), { payload, providerId })
}

/** Login → provider → callback, for the issuer's current user. */
async function loginVia(providerId: string, query: Record<string, string> = {}) {
  const started = await startLogin(providerId, query)
  expect(started.res.status).toBe(302)
  const callbackUrl = await authorizeAt(started.location)
  const res = await callback(providerId, callbackUrl, started.cookie)
  return { res, started, callbackUrl }
}

beforeAll(async () => {
  issuer = await startMockIssuer()
  oauth = createOAuth({
    providers: {
      async get(id) {
        if (id === 'corp') {
          return oidc({
            id: 'corp',
            name: 'Corp SSO',
            issuer: issuer.issuer,
            clientId: issuer.clientId,
            clientSecret: issuer.clientSecret,
            meta: { tenant: 'acme' },
          })
        }
        if (id === 'plain') {
          return oauth2({
            id: 'plain',
            name: 'Plain OAuth',
            authorizationEndpoint: `${issuer.issuer}/authorize`,
            tokenEndpoint: `${issuer.issuer}/token`,
            clientId: issuer.clientId,
            clientSecret: issuer.clientSecret,
            scopes: ['profile'],
            clientAuth: 'client_secret_post',
            async profile(ctx) {
              const me = await ctx.fetchJson<Record<string, unknown>>(`${issuer.issuer}/me`)
              return {
                providerAccountId: String(me.sub),
                email: typeof me.email === 'string' ? me.email : undefined,
                emailVerified: me.email_verified === true,
                name: typeof me.name === 'string' ? me.name : undefined,
                raw: me,
              }
            },
          })
        }
        return dynamic.get(id) ?? null
      },
      async list() {
        return [
          oidc({
            id: 'corp',
            name: 'Corp SSO',
            issuer: issuer.issuer,
            clientId: 'x',
            meta: { tenant: 'acme' },
          }),
        ]
      },
    },
    cookie: { path: '/api/users/oauth' },
    users: {
      autoProvision: () => autoProvision,
      mapNewUser: () => ({ roles: ['member'] }),
      findUser: async ({ payload, identity }) => {
        // Legacy column match (what a host migrating from a single `subject` column would do).
        if (!identity.providerAccountId.startsWith('legacy-')) return null
        const { docs } = await payload.find({
          collection: 'users',
          where: { name: { equals: identity.providerAccountId } },
          limit: 1,
        })
        return docs[0] ?? null
      },
      beforeProvision: ({ identity }) => {
        if (refuseProvisioning) throw new AuthError('signup_disabled')
        seen.push(`provision:${identity.email}`)
      },
      afterLink: ({ identity }) => {
        seen.push(`link:${identity.email}`)
      },
    },
    onAuthenticated: ({ identity, next, cookies }) => {
      if (identity.email?.startsWith('twofactor')) {
        return new Response(null, {
          status: 303,
          headers: {
            location: `/login?two_factor=1&next=${encodeURIComponent(next)}`,
            'set-cookie': cookies[0] as string,
          },
        })
      }
    },
  })
  payload = await bootPayload('oauth', [oauth.plugin])
})

beforeEach(() => {
  autoProvision = true
  refuseProvisioning = false
})

afterAll(async () => {
  await issuer.close()
  await payload.destroy()
})

describe('plugin setup', () => {
  it('registers the accounts collection and the endpoints on the users collection', () => {
    expect(payload.collections['auth-accounts']).toBeDefined()
    const endpoints = payload.collections.users?.config.endpoints || []
    const paths = endpoints.map((e) => `${e.method} ${e.path}`)
    expect(paths).toEqual(
      expect.arrayContaining([
        'get /oauth/providers',
        'get /oauth/:provider/login',
        'get /oauth/:provider/callback',
        'post /oauth/logout',
      ]),
    )
  })

  it('lists providers without secrets', async () => {
    const res = await oauth.handlers.providers(
      new Request(`${SERVER_URL}/api/users/oauth/providers`),
      { payload },
    )
    expect(await res.json()).toEqual({
      providers: [{ id: 'corp', name: 'Corp SSO', type: 'oidc', meta: { tenant: 'acme' } }],
    })
  })

  it('refuses duplicate or malformed provider ids at build time', () => {
    const p = oidc({ id: 'a', name: 'A', issuer: 'https://x', clientId: 'c' })
    expect(() => createOAuth({ providers: [p, p] })).toThrow(/duplicate/)
    expect(() =>
      createOAuth({
        providers: [oidc({ id: 'bad id', name: 'A', issuer: 'https://x', clientId: 'c' })],
      }),
    ).toThrow(/provider id/)
  })
})

describe('OIDC login', () => {
  it('redirects to the provider with PKCE, state, nonce and a sealed cookie', async () => {
    const { res, cookie, location } = await startLogin('corp', { next: '/acme/monitors' })
    expect(res.status).toBe(302)
    const url = new URL(location)
    expect(url.origin).toBe(issuer.issuer)
    expect(url.pathname).toBe('/authorize')
    const q = url.searchParams
    expect(q.get('response_type')).toBe('code')
    expect(q.get('client_id')).toBe(issuer.clientId)
    expect(q.get('redirect_uri')).toBe(`${SERVER_URL}/api/users/oauth/corp/callback`)
    expect(q.get('scope')).toBe('openid email profile')
    expect(q.get('code_challenge_method')).toBe('S256')
    expect(q.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/)
    expect(q.get('state')).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(q.get('nonce')).toMatch(/^[A-Za-z0-9_-]+$/)
    expect(cookie).toBeDefined()
    expect(cookie).not.toContain(q.get('state') as string)
    expect(res.headers.get('set-cookie')).toContain('Path=/api/users/oauth')
  })

  it('provisions a user on first login with mapNewUser data and a working session cookie', async () => {
    const address = email('jane')
    issuer.setUser({
      sub: 'jane',
      email: address,
      email_verified: true,
      given_name: 'Jane',
      family_name: 'Doe',
    })
    const { res } = await loginVia('corp', { next: '/acme/monitors' })
    expect(res.status).toBe(303)
    expect(locationOf(res)).toBe('/acme/monitors')
    expect(res.headers.getSetCookie().some((c) => c.startsWith('payload-auth-tx=;'))).toBe(true)

    const user = await authenticate(payload, sessionCookieOf(payload, res))
    expect(user?.email).toBe(address)
    expect(user?.name).toBe('Jane Doe')
    expect(user?.roles).toEqual(['member'])
    expect(seen).toContain(`provision:${address}`)

    const accounts = await listAccounts(
      { payload, usersSlug: 'users', accountsSlug: 'auth-accounts' },
      user!.id,
    )
    expect(accounts).toHaveLength(1)
    expect(accounts[0]).toMatchObject({
      provider: 'corp',
      providerAccountId: 'jane',
      email: address,
    })
  })

  it('reuses the same user on the next login and updates lastLoginAt', async () => {
    const { res } = await loginVia('corp')
    const user = await authenticate(payload, sessionCookieOf(payload, res))
    const { docs } = await payload.find({
      collection: 'users',
      where: { email: { equals: email('jane') } },
    })
    expect(docs).toHaveLength(1)
    expect(String(user?.id)).toBe(String(docs[0]?.id))
  })

  it('links an existing user by verified email and refuses unverified emails', async () => {
    const address = email('larry')
    const local = await payload.create({
      collection: 'users',
      data: { email: address, password: 'pw-123456', name: 'Local Larry' },
    })
    issuer.setUser({ sub: 'larry-sso', email: address, email_verified: true, name: 'Larry' })
    const { res } = await loginVia('corp')
    const user = await authenticate(payload, sessionCookieOf(payload, res))
    expect(String(user?.id)).toBe(String(local.id))
    expect(user?.name).toBe('Local Larry')
    expect(seen).toContain(`link:${address}`)

    const victim = email('victim')
    await payload.create({ collection: 'users', data: { email: victim, password: 'pw-123456' } })
    issuer.setUser({ sub: 'impostor', email: victim, email_verified: false })
    const refused = await loginVia('corp')
    expect(locationOf(refused.res)).toBe('/login?error=email_unverified')
    expect(sessionCookieOf(payload, refused.res)).toBeUndefined()
  })

  it('rejects a tampered state, a missing cookie and a cookie of another transaction', async () => {
    issuer.setUser({ sub: 'jane', email: email('jane'), email_verified: true })
    const before = issuer.tokenRequests()
    const first = await startLogin('corp')
    const callbackUrl = await authorizeAt(first.location)
    callbackUrl.searchParams.set('state', 'not-the-state')
    expect(locationOf(await callback('corp', callbackUrl, first.cookie))).toBe(
      '/login?error=state_mismatch',
    )

    const second = await startLogin('corp')
    const secondCallback = await authorizeAt(second.location)
    expect(locationOf(await callback('corp', secondCallback))).toBe('/login?error=state_mismatch')
    expect(locationOf(await callback('corp', secondCallback, first.cookie))).toBe(
      '/login?error=state_mismatch',
    )
    // The cookie was issued for `corp`; replaying it against another provider id fails too.
    expect(locationOf(await callback('plain', secondCallback, second.cookie))).toBe(
      '/login?error=state_mismatch',
    )
    expect(issuer.tokenRequests()).toBe(before)
  })

  it('maps provider errors, unknown providers and host refusals to error codes', async () => {
    expect(locationOf((await startLogin('nope')).res)).toBe('/login?error=provider_unknown')

    const started = await startLogin('corp')
    const denied = new URL(`${SERVER_URL}/api/users/oauth/corp/callback`)
    denied.searchParams.set('error', 'access_denied')
    denied.searchParams.set('state', 'whatever')
    expect(locationOf(await callback('corp', denied, started.cookie))).toBe(
      '/login?error=access_denied',
    )

    autoProvision = false
    issuer.setUser({ sub: 'manual', email: email('manual'), email_verified: true })
    expect(locationOf((await loginVia('corp')).res)).toBe('/login?error=provisioning_disabled')

    autoProvision = true
    refuseProvisioning = true
    issuer.setUser({ sub: 'uninvited', email: email('uninvited'), email_verified: true })
    expect(locationOf((await loginVia('corp')).res)).toBe('/login?error=signup_disabled')

    issuer.setUser({ sub: 'noemail' })
    expect(locationOf((await loginVia('corp')).res)).toBe('/login?error=email_missing')
  })

  it('lets onAuthenticated take over the response (second factor)', async () => {
    issuer.setUser({ sub: 'tf', email: email('twofactor'), email_verified: true })
    const { res } = await loginVia('corp', { next: '/x' })
    expect(res.status).toBe(303)
    expect(locationOf(res)).toBe('/login?two_factor=1&next=%2Fx')
    expect(sessionCookieOf(payload, res)).toBeUndefined()
  })
})

describe('findUser hook', () => {
  it('links to the user it returns even when the email is unverified', async () => {
    const legacy = await payload.create({
      collection: 'users',
      data: { email: email('legacy'), password: 'pw-123456', name: 'legacy-7' },
    })
    issuer.setUser({
      sub: 'legacy-7',
      email: 'different-' + email('legacy'),
      email_verified: false,
    })
    const { res } = await loginVia('corp')
    const user = await authenticate(payload, sessionCookieOf(payload, res))
    expect(String(user?.id)).toBe(String(legacy.id))
    const accounts = await listAccounts(
      { payload, usersSlug: 'users', accountsSlug: 'auth-accounts' },
      legacy.id,
    )
    expect(accounts.map((a) => a.providerAccountId)).toEqual(['legacy-7'])
  })
})

describe('plain OAuth 2.0 provider', () => {
  it('skips the nonce, exchanges the code and builds the identity from profile()', async () => {
    const address = email('plain')
    issuer.setUser({ sub: 'plain-1', email: address, email_verified: true, name: 'Plain Pat' })
    const started = await startLogin('plain')
    const q = new URL(started.location).searchParams
    expect(q.get('scope')).toBe('profile')
    expect(q.get('nonce')).toBeNull()
    expect(q.get('code_challenge')).toBeTruthy()
    const callbackUrl = await authorizeAt(started.location)
    const res = await callback('plain', callbackUrl, started.cookie)
    expect(res.status).toBe(303)
    const user = await authenticate(payload, sessionCookieOf(payload, res))
    expect(user?.email).toBe(address)
    expect(user?.name).toBe('Plain Pat')
  })
})

describe('linking and logout', () => {
  it('links a second identity to the signed-in user and refuses identities owned by others', async () => {
    issuer.setUser({ sub: 'jane', email: email('jane'), email_verified: true })
    const { res } = await loginVia('corp')
    const session = sessionCookieOf(payload, res)?.split(';')[0] as string
    const headers = { cookie: session, origin: SERVER_URL }

    // Not signed in → refused.
    expect(locationOf((await startLogin('plain', { link: '1' })).res)).toBe(
      '/login?error=not_signed_in',
    )

    issuer.setUser({ sub: 'jane-plain', email: 'other-' + email('jane'), email_verified: false })
    const started = await startLogin('plain', { link: '1', next: '/settings' }, headers)
    expect(started.res.status).toBe(302)
    const callbackUrl = await authorizeAt(started.location)
    const linked = await callback('plain', callbackUrl, started.cookie)
    expect(locationOf(linked)).toBe('/settings')
    expect(sessionCookieOf(payload, linked)).toBeUndefined() // already signed in: no new session

    const user = await authenticate(payload, session)
    const accounts = await listAccounts(
      { payload, usersSlug: 'users', accountsSlug: 'auth-accounts' },
      user!.id,
    )
    expect(accounts.map((a) => a.provider).sort()).toEqual(['corp', 'plain'])

    // Larry tries to link Jane's plain identity to his account.
    issuer.setUser({ sub: 'larry-sso', email: email('larry'), email_verified: true })
    const larry = await loginVia('corp')
    const larrySession = sessionCookieOf(payload, larry.res)?.split(';')[0] as string
    issuer.setUser({ sub: 'jane-plain', email: 'other-' + email('jane') })
    const attempt = await startLogin(
      'plain',
      { link: '1' },
      { cookie: larrySession, origin: SERVER_URL },
    )
    const attemptCallback = await authorizeAt(attempt.location)
    expect(locationOf(await callback('plain', attemptCallback, attempt.cookie))).toBe(
      '/login?error=account_in_use',
    )
  })

  it('revokes the session and points at the end-session endpoint', async () => {
    issuer.setUser({ sub: 'jane', email: email('jane'), email_verified: true })
    const { res } = await loginVia('corp')
    const session = sessionCookieOf(payload, res)?.split(';')[0] as string
    expect(await authenticate(payload, session)).not.toBeNull()

    const logout = await oauth.handlers.logout(
      new Request(`${SERVER_URL}/api/users/oauth/logout`, {
        method: 'POST',
        headers: { cookie: session, origin: SERVER_URL, accept: 'application/json' },
      }),
      { payload },
    )
    expect(logout.status).toBe(200)
    const { redirectTo } = (await logout.json()) as { redirectTo: string }
    const url = new URL(redirectTo)
    expect(`${url.origin}${url.pathname}`).toBe(issuer.endSessionEndpoint)
    expect(url.searchParams.get('post_logout_redirect_uri')).toBe(`${SERVER_URL}/`)
    expect(logout.headers.getSetCookie().some((c) => c.includes('Expires='))).toBe(true)
    expect(await authenticate(payload, session)).toBeNull()
  })
})
