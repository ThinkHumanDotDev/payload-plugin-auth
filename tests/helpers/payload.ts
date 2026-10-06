import { mkdirSync, rmSync } from 'node:fs'
import path from 'node:path'

import { sqliteAdapter } from '@payloadcms/db-sqlite'
import { buildConfig, getPayload, type CollectionConfig, type Payload, type Plugin } from 'payload'

/**
 * Boots a real Payload on a throwaway SQLite database with a minimal `users` collection and the
 * plugins under test. Every suite gets its own file so suites never share state.
 */
export const TEST_SECRET = 'payload-auth-test-secret-payload-auth-test-secret'
export const SERVER_URL = 'http://localhost:3000'

export const Users: CollectionConfig = {
  slug: 'users',
  auth: true,
  fields: [
    { name: 'name', type: 'text' },
    { name: 'roles', type: 'select', hasMany: true, options: ['admin', 'member'] },
  ],
}

export async function bootPayload(
  name: string,
  plugins: Plugin[],
  extraCollections: CollectionConfig[] = [],
): Promise<Payload> {
  const dir = path.resolve('tests/.data')
  mkdirSync(dir, { recursive: true })
  const file = path.join(dir, `${name}-${process.pid}.db`)
  rmSync(file, { force: true })

  const config = await buildConfig({
    secret: TEST_SECRET,
    serverURL: SERVER_URL,
    collections: [Users, ...extraCollections],
    plugins,
    db: sqliteAdapter({ client: { url: `file:${file}` }, push: true }),
    logger: { options: { level: 'silent' } },
    telemetry: false,
  })
  return getPayload({ config })
}

/** What `payload.auth` makes of a `Set-Cookie` value; mimics a browser (Origin header for CSRF). */
export async function authenticate(payload: Payload, setCookie: string | undefined) {
  const cookie = setCookie ? setCookie.split(';')[0] : ''
  const { user } = await payload.auth({
    headers: new Headers({ cookie: cookie ?? '', origin: SERVER_URL }),
  })
  return user
}

export const sessionCookieOf = (payload: Payload, res: Response): string | undefined =>
  res.headers.getSetCookie().find((c) => c.startsWith(`${payload.config.cookiePrefix}-token=`))

export const locationOf = (res: Response): string => res.headers.get('location') ?? ''

/** Follows the mock provider's redirect back to the callback URL. */
export async function authorizeAt(authorizationUrl: string): Promise<URL> {
  const res = await fetch(authorizationUrl, { redirect: 'manual' })
  if (res.status !== 302) throw new Error(`authorize responded ${res.status}: ${await res.text()}`)
  return new URL(res.headers.get('location') ?? '')
}
