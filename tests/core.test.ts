import { describe, expect, it } from 'vitest'

import {
  AuthError,
  authErrorMessage,
  createTransactionStore,
  errorRedirectUrl,
  expireCookie,
  isAuthErrorCode,
  openSealed,
  readCookie,
  safeRedirectPath,
  seal,
  serializeCookie,
} from '../src/index.js'

const secret = 'core-test-secret-core-test-secret'

describe('sealed tokens', () => {
  it('round-trip, reject tampering, wrong secret, wrong purpose and expiry', async () => {
    const now = Date.now()
    const token = await seal({ a: 1, b: 'x' }, secret, 'test', { ttlSeconds: 60, now })
    expect(token.split('.')).toHaveLength(5)
    expect(await openSealed(token, secret, 'test', { now })).toEqual(
      expect.objectContaining({ a: 1, b: 'x' }),
    )
    expect(await openSealed(token, `${secret}x`, 'test', { now })).toBeNull()
    expect(await openSealed(token, secret, 'other', { now })).toBeNull()
    expect(await openSealed(token, secret, 'test', { now: now + 61_000 })).toBeNull()
    const [h, k, iv, ct, tag] = token.split('.') as [string, string, string, string, string]
    const flipped = (ct[0] === 'A' ? 'B' : 'A') + ct.slice(1)
    expect(await openSealed([h, k, iv, flipped, tag].join('.'), secret, 'test', { now })).toBeNull()
    expect(await openSealed('garbage', secret, 'test')).toBeNull()
    expect(await openSealed(undefined, secret, 'test')).toBeNull()
  })
})

describe('transaction store', () => {
  it('issues, reads and clears a cookie and refuses incomplete payloads', async () => {
    const store = createTransactionStore(secret, 'oauth', {
      name: 'tx',
      path: '/api/auth',
      secure: true,
    })
    const cookie = await store.issue({ provider: 'github', next: '/home', state: 's1' })
    expect(cookie).toMatch(/^tx=/)
    expect(cookie).toContain('Path=/api/auth')
    expect(cookie).toContain('HttpOnly')
    expect(cookie).toContain('Secure')
    expect(cookie).toContain('SameSite=Lax')
    expect(cookie).toContain('Max-Age=600')

    const request = new Request('http://x/cb', {
      headers: { cookie: cookie.split(';')[0] as string },
    })
    expect(await store.read(request)).toEqual({ provider: 'github', next: '/home', state: 's1' })
    expect(await store.read(new Request('http://x/cb'))).toBeNull()

    const other = createTransactionStore(secret, 'saml', { name: 'tx' })
    expect(await other.read(request)).toBeNull() // another purpose never opens it

    const incomplete = await seal(
      { provider: 'github' },
      secret,
      'payload-auth:transaction:oauth',
      { ttlSeconds: 60 },
    )
    expect(
      await store.read(new Request('http://x/cb', { headers: { cookie: `tx=${incomplete}` } })),
    ).toBeNull()

    expect(store.clear()).toMatch(/^tx=; Max-Age=0; .*Expires=Thu, 01 Jan 1970/)
  })
})

describe('cookies', () => {
  it('serialises and reads cookies', () => {
    const value = serializeCookie('n', 'a=b c', { path: '/p', maxAge: 10, secure: false })
    expect(value).toBe('n=a%3Db%20c; Max-Age=10; Path=/p; HttpOnly; SameSite=Lax')
    expect(readCookie(new Headers({ cookie: 'x=1; n=a%3Db%20c; y=2' }), 'n')).toBe('a=b c')
    expect(readCookie(new Headers(), 'n')).toBeUndefined()
    expect(expireCookie('n', { path: '/p' })).toContain('Max-Age=0')
  })
})

describe('errors and redirects', () => {
  it('maps codes, validates custom codes and builds error URLs', () => {
    expect(authErrorMessage('state_mismatch')).toMatch(/expired/)
    expect(authErrorMessage('nope')).toBeUndefined()
    expect(authErrorMessage('constructor')).toBeUndefined()
    expect(isAuthErrorCode('signup_disabled')).toBe(true)
    expect(isAuthErrorCode('<script>')).toBe(false)
    const custom = new AuthError('signup_disabled', { status: 403 })
    expect(custom.code).toBe('signup_disabled')
    expect(custom.message).toBe('signup_disabled')
    expect(() => new AuthError('Bad Code')).toThrow(TypeError)
    expect(errorRedirectUrl('/login', 'state_mismatch')).toBe('/login?error=state_mismatch')
    expect(errorRedirectUrl('/login?next=%2Fx', 'access_denied', { provider: 'g' })).toBe(
      '/login?next=%2Fx&error=access_denied&provider=g',
    )
  })

  it('only accepts same-origin paths as redirect targets', () => {
    expect(safeRedirectPath('/acme/monitors')).toBe('/acme/monitors')
    expect(safeRedirectPath('//evil.com')).toBe('/')
    expect(safeRedirectPath('/\\evil.com')).toBe('/')
    expect(safeRedirectPath('https://evil.com')).toBe('/')
    expect(safeRedirectPath(undefined, '/home')).toBe('/home')
    expect(safeRedirectPath('/a\nb')).toBe('/')
  })
})
