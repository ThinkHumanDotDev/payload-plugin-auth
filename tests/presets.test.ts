import { describe, expect, it } from 'vitest'

import {
  discord,
  github,
  gitlab,
  google,
  microsoft,
  oidc,
  oidcProfile,
  type OAuthProvider,
  type ProfileContext,
} from '../src/oauth/index.js'

/** A `ProfileContext` whose `fetchJson` answers from a table of URL → body. */
function context(
  provider: OAuthProvider,
  responses: Record<string, unknown>,
  claims?: Record<string, unknown>,
) {
  return {
    provider,
    tokens: {
      access_token: 't',
      token_type: 'bearer',
      claims: () => undefined,
    } as unknown as ProfileContext['tokens'],
    claims,
    async fetchJson<T>(url: string): Promise<T> {
      if (!(url in responses)) throw new Error(`unexpected ${url}`)
      const body = responses[url]
      if (body instanceof Error) throw body
      return body as T
    },
  } satisfies ProfileContext
}

describe('provider presets', () => {
  it('github: primary verified email from /user/emails, falls back to the public email', async () => {
    const provider = github({ clientId: 'id', clientSecret: 'secret' })
    expect(provider).toMatchObject({
      id: 'github',
      type: 'oauth2',
      pkce: false,
      scopes: ['read:user', 'user:email'],
    })
    expect(provider.authorizationEndpoint).toBe('https://github.com/login/oauth/authorize')

    const withEmails = await provider.profile!(
      context(provider, {
        'https://api.github.com/user': {
          id: 42,
          login: 'octo',
          name: 'Octo Cat',
          avatar_url: 'https://a/x.png',
          email: null,
        },
        'https://api.github.com/user/emails': [
          { email: 'old@example.com', primary: false, verified: true },
          { email: 'octo@example.com', primary: true, verified: true },
        ],
      }),
    )
    expect(withEmails).toMatchObject({
      providerAccountId: '42',
      email: 'octo@example.com',
      emailVerified: true,
      name: 'Octo Cat',
      picture: 'https://a/x.png',
    })

    const withoutScope = await provider.profile!(
      context(provider, {
        'https://api.github.com/user': { id: 7, login: 'solo', email: 'solo@example.com' },
        'https://api.github.com/user/emails': new Error('403'),
      }),
    )
    expect(withoutScope).toMatchObject({
      providerAccountId: '7',
      email: 'solo@example.com',
      emailVerified: false,
      name: 'solo',
    })
  })

  it('discord: verified flag and avatar URL', async () => {
    const provider = discord({ clientId: 'id', clientSecret: 'secret' })
    const identity = await provider.profile!(
      context(provider, {
        'https://discord.com/api/users/@me': {
          id: '123',
          username: 'disc',
          global_name: 'Disc O',
          email: 'd@example.com',
          verified: true,
          avatar: 'abc',
        },
      }),
    )
    expect(identity).toMatchObject({
      providerAccountId: '123',
      email: 'd@example.com',
      emailVerified: true,
      name: 'Disc O',
      picture: 'https://cdn.discordapp.com/avatars/123/abc.png',
    })
  })

  it('oidc presets carry issuers and default scopes; microsoft refuses multi-tenant aliases', () => {
    expect(google({ clientId: 'a' })).toMatchObject({
      id: 'google',
      type: 'oidc',
      issuer: 'https://accounts.google.com',
    })
    expect(gitlab({ clientId: 'a', baseUrl: 'https://git.example.com/' }).issuer).toBe(
      'https://git.example.com',
    )
    expect(microsoft({ clientId: 'a', tenant: 'tenant-id' }).issuer).toBe(
      'https://login.microsoftonline.com/tenant-id/v2.0',
    )
    expect(() => microsoft({ clientId: 'a', tenant: 'common' })).toThrow(/tenant id/)
    expect(oidc({ issuer: 'https://idp', clientId: 'a', id: 'corp', name: 'Corp' })).toMatchObject({
      id: 'corp',
      name: 'Corp',
      type: 'oidc',
    })
    expect(github({ clientId: 'a', id: 'github-enterprise', name: 'GHE' })).toMatchObject({
      id: 'github-enterprise',
      name: 'GHE',
    })
  })

  it('oidcProfile merges UserInfo over ID-token claims and composes names', () => {
    const provider = google({ clientId: 'a' })
    const identity = oidcProfile({
      ...context(
        provider,
        {},
        {
          sub: 's',
          email: 'token@example.com',
          email_verified: false,
          given_name: 'Ann',
          family_name: 'Lee',
        },
      ),
      userinfo: { email: 'info@example.com', email_verified: true },
    })
    expect(identity).toMatchObject({
      providerAccountId: 's',
      email: 'info@example.com',
      emailVerified: true,
      name: 'Ann Lee',
    })
    expect(() => oidcProfile(context(provider, {}, { email: 'x' }))).toThrow(/sub/)
  })
})
