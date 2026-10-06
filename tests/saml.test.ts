import type { Payload } from 'payload'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

import { listAccounts } from '../src/index.js'
import {
  createSaml,
  parseIdpMetadata,
  samlProfile,
  type SamlConnection,
} from '../src/saml/index.js'
import {
  authenticate,
  bootPayload,
  locationOf,
  SERVER_URL,
  sessionCookieOf,
} from './helpers/payload.js'
import {
  buildSamlResponse,
  decodeAuthnRequest,
  encodeResponse,
  IDP_CERT,
  IDP_ENTITY_ID,
  IDP_METADATA,
  IDP_SSO_URL,
  type ResponseOptions,
} from './helpers/test-idp.js'

let payload: Payload
let saml: ReturnType<typeof createSaml>
const seenAssertions = new Set<string>()

const run = Date.now().toString(36)
const email = (name: string) => `${name}-${run}@corp.test`

const ACS = `${SERVER_URL}/api/users/saml/corp/acs`
const METADATA = `${SERVER_URL}/api/users/saml/corp/metadata`

const connections: SamlConnection[] = [
  {
    id: 'corp',
    name: 'Corp SAML',
    entryPoint: IDP_SSO_URL,
    idpCert: IDP_CERT,
    idpIssuer: IDP_ENTITY_ID,
    meta: { tenant: 'acme' },
  },
  {
    id: 'unsolicited',
    name: 'IdP-initiated',
    entryPoint: IDP_SSO_URL,
    idpCert: IDP_CERT,
    allowIdpInitiated: true,
    emailVerified: false,
  },
]

const txCookieOf = (res: Response) =>
  res.headers
    .getSetCookie()
    .find((c) => c.startsWith('payload-auth-saml='))
    ?.split(';')[0]

async function startLogin(
  connectionId: string,
  query: Record<string, string> = {},
  headers?: HeadersInit,
) {
  const url = new URL(`${SERVER_URL}/api/users/saml/${connectionId}/login`)
  for (const [k, v] of Object.entries(query)) url.searchParams.set(k, v)
  const res = await saml.handlers.login(new Request(url, { headers }), { payload, connectionId })
  return { res, cookie: txCookieOf(res), location: locationOf(res) }
}

async function postAcs(
  connectionId: string,
  xml: string,
  cookie?: string,
  relayState = connectionId,
) {
  const headers = new Headers({ 'content-type': 'application/x-www-form-urlencoded' })
  if (cookie) headers.set('cookie', cookie)
  const body = new URLSearchParams({ SAMLResponse: encodeResponse(xml), RelayState: relayState })
  return saml.handlers.acs(
    new Request(`${SERVER_URL}/api/users/saml/${connectionId}/acs`, {
      method: 'POST',
      headers,
      body,
    }),
    {
      payload,
      connectionId,
    },
  )
}

/** SP-initiated login: AuthnRequest → IdP builds a response for the request → ACS. */
async function loginVia(
  nameId: string,
  overrides: Partial<ResponseOptions> = {},
  query: Record<string, string> = {},
  headers?: HeadersInit,
) {
  const started = await startLogin('corp', query, headers)
  expect(started.res.status).toBe(302)
  const { id } = decodeAuthnRequest(started.location)
  const { xml } = buildSamlResponse({
    destination: ACS,
    audience: METADATA,
    inResponseTo: id,
    nameId,
    ...overrides,
  })
  const res = await postAcs('corp', xml, started.cookie)
  return { res, started }
}

beforeAll(async () => {
  saml = createSaml({
    connections,
    users: { mapNewUser: () => ({ roles: ['member'] }) },
    replayCheck: (assertionId) => {
      if (seenAssertions.has(assertionId)) return false
      seenAssertions.add(assertionId)
      return true
    },
  })
  payload = await bootPayload('saml', [saml.plugin])
})

afterAll(async () => {
  await payload.destroy()
})

describe('metadata', () => {
  it('parses IdP metadata into connection settings', async () => {
    const meta = await parseIdpMetadata(IDP_METADATA)
    expect(meta.entityId).toBe(IDP_ENTITY_ID)
    expect(meta.entryPoint).toBe(IDP_SSO_URL)
    expect(meta.binding).toBe('redirect')
    expect(meta.certificates).toHaveLength(1) // the encryption key is ignored
    expect(meta.certificates[0]).not.toContain('BEGIN')
    expect(meta.logoutUrl).toBe('https://idp.example.test/saml/slo')
    expect(meta.nameIdFormats).toEqual(['urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'])
    await expect(parseIdpMetadata('<nope/>')).rejects.toThrow(/EntityDescriptor/)
    await expect(parseIdpMetadata('not xml <')).rejects.toThrow(/Invalid/)
  })

  it('serves SP metadata with the entity id and ACS URL', async () => {
    const res = await saml.handlers.metadata(new Request(METADATA), {
      payload,
      connectionId: 'corp',
    })
    expect(res.status).toBe(200)
    expect(res.headers.get('content-type')).toContain('samlmetadata+xml')
    const xml = await res.text()
    expect(xml).toContain(`entityID="${METADATA}"`)
    expect(xml).toContain(`Location="${ACS}"`)
    expect(xml).toContain('WantAssertionsSigned="true"')
    const missing = await saml.handlers.metadata(new Request(METADATA), {
      payload,
      connectionId: 'nope',
    })
    expect(missing.status).toBe(404)
  })

  it('registers endpoints on the users collection and shares the accounts collection', () => {
    expect(payload.collections['auth-accounts']).toBeDefined()
    const endpoints = payload.collections.users?.config.endpoints || []
    expect(endpoints.map((e) => `${e.method} ${e.path}`)).toEqual(
      expect.arrayContaining([
        'get /saml/connections',
        'get /saml/:connection/login',
        'post /saml/:connection/acs',
        'get /saml/:connection/metadata',
      ]),
    )
  })
})

describe('SP-initiated login', () => {
  it('redirects to the IdP with a deflated AuthnRequest and a sealed cookie carrying the request id', async () => {
    const { res, cookie, location } = await startLogin('corp', { next: '/acme' })
    expect(res.status).toBe(302)
    const url = new URL(location)
    expect(`${url.origin}${url.pathname}`).toBe(IDP_SSO_URL)
    const { xml, id, relayState } = decodeAuthnRequest(location)
    expect(xml).toContain('AuthnRequest')
    expect(xml).toContain(`AssertionConsumerServiceURL="${ACS}"`)
    expect(xml).toContain(`<saml:Issuer`)
    expect(xml).toContain(METADATA)
    expect(id).toMatch(/^_[0-9a-f]{32}$/)
    expect(relayState).toBe('corp')
    expect(cookie).toBeDefined()
    expect(cookie).not.toContain(id)
  })

  it('provisions a user from a signed assertion, mapping common attributes', async () => {
    const address = email('jane')
    const { res } = await loginVia(
      address,
      {
        attributes: {
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname': 'Jane',
          'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname': 'Doe',
        },
      },
      { next: '/acme/monitors' },
    )
    expect(res.status).toBe(303)
    expect(locationOf(res)).toBe('/acme/monitors')
    const user = await authenticate(payload, sessionCookieOf(payload, res))
    expect(user?.email).toBe(address)
    expect(user?.name).toBe('Jane Doe')
    expect(user?.roles).toEqual(['member'])
    const accounts = await listAccounts(
      { payload, usersSlug: 'users', accountsSlug: 'auth-accounts' },
      user!.id,
    )
    expect(accounts[0]).toMatchObject({ provider: 'corp', providerAccountId: address })
  })

  it('links an existing user by email (the IdP is authoritative) and reuses it afterwards', async () => {
    const address = email('larry')
    const local = await payload.create({
      collection: 'users',
      data: { email: address, password: 'pw-123456', name: 'Local Larry' },
    })
    const first = await loginVia(address)
    expect(String((await authenticate(payload, sessionCookieOf(payload, first.res)))?.id)).toBe(
      String(local.id),
    )
    const second = await loginVia(address)
    expect(String((await authenticate(payload, sessionCookieOf(payload, second.res)))?.id)).toBe(
      String(local.id),
    )
    const { docs } = await payload.find({
      collection: 'users',
      where: { email: { equals: address } },
    })
    expect(docs).toHaveLength(1)
  })

  it('rejects unsigned, wrongly signed, tampered, expired, wrong-audience and foreign-issuer assertions', async () => {
    const cases: Partial<ResponseOptions>[] = [
      { signWith: 'none' },
      { signWith: 'rogue' },
      { tamper: (xml) => xml.replace(email('x'), email('y')) },
      { expiresInMs: -60_000 },
      { notBeforeMs: 60_000 },
      { audience: 'https://other.example.test/metadata' },
      { issuer: 'https://evil.example.test' },
    ]
    for (const overrides of cases) {
      const { res } = await loginVia(email('x'), overrides)
      expect(locationOf(res), JSON.stringify(Object.keys(overrides))).toBe(
        '/login?error=exchange_failed',
      )
      expect(sessionCookieOf(payload, res)).toBeUndefined()
    }
  })

  it('rejects responses that do not answer our request, missing cookies and replays', async () => {
    const started = await startLogin('corp')
    const { xml: foreign } = buildSamlResponse({
      destination: ACS,
      audience: METADATA,
      inResponseTo: '_someone_elses',
      nameId: email('x'),
    })
    expect(locationOf(await postAcs('corp', foreign, started.cookie))).toBe(
      '/login?error=exchange_failed',
    )

    const { id } = decodeAuthnRequest(started.location)
    const { xml } = buildSamlResponse({
      destination: ACS,
      audience: METADATA,
      inResponseTo: id,
      nameId: email('replay'),
    })
    // No cookie at all: the connection does not allow unsolicited responses.
    expect(locationOf(await postAcs('corp', xml))).toBe('/login?error=state_mismatch')
    // Cookie issued for another connection.
    const other = await startLogin('unsolicited')
    expect(locationOf(await postAcs('corp', xml, other.cookie))).toBe('/login?error=state_mismatch')
    // Right cookie: works once …
    const ok = await postAcs('corp', xml, started.cookie)
    expect(ok.status).toBe(303)
    // … and the same assertion again is refused by the replay check.
    expect(locationOf(await postAcs('corp', xml, started.cookie))).toBe(
      '/login?error=state_mismatch',
    )
    // Garbage body.
    const headers = new Headers({
      'content-type': 'application/x-www-form-urlencoded',
      cookie: started.cookie as string,
    })
    const garbage = await saml.handlers.acs(
      new Request(ACS, { method: 'POST', headers, body: 'SAMLResponse=bm90LXhtbA' }),
      { payload, connectionId: 'corp' },
    )
    expect(locationOf(garbage)).toBe('/login?error=exchange_failed')
  })

  it('accepts a response signed at the Response level', async () => {
    const { res } = await loginVia(email('signed-response'), { signResponse: true })
    expect(res.status).toBe(303)
  })

  it('links a SAML identity to the signed-in user', async () => {
    const { res } = await loginVia(email('jane'))
    const session = sessionCookieOf(payload, res)?.split(';')[0] as string
    const started = await startLogin(
      'corp',
      { link: '1', next: '/settings' },
      { cookie: session, origin: SERVER_URL },
    )
    const { id } = decodeAuthnRequest(started.location)
    const { xml } = buildSamlResponse({
      destination: ACS,
      audience: METADATA,
      inResponseTo: id,
      nameId: 'jane-alt',
    })
    const linked = await postAcs('corp', xml, started.cookie)
    expect(locationOf(linked)).toBe('/settings')
    const user = await authenticate(payload, session)
    const accounts = await listAccounts(
      { payload, usersSlug: 'users', accountsSlug: 'auth-accounts' },
      user!.id,
    )
    expect(accounts.map((a) => a.providerAccountId).sort()).toEqual(
      [email('jane'), 'jane-alt'].sort(),
    )
  })
})

describe('IdP-initiated login', () => {
  it('is refused by default and accepted when the connection allows it', async () => {
    const address = email('unsolicited')
    const unsolicited = buildSamlResponse({
      destination: `${SERVER_URL}/api/users/saml/unsolicited/acs`,
      audience: `${SERVER_URL}/api/users/saml/unsolicited/metadata`,
      nameId: address,
    }).xml
    const res = await postAcs('unsolicited', unsolicited)
    expect(res.status).toBe(303)
    expect(locationOf(res)).toBe('/')
    const user = await authenticate(payload, sessionCookieOf(payload, res))
    expect(user?.email).toBe(address)

    // An unsolicited response that claims to answer a request we never made is still rejected.
    const fake = buildSamlResponse({
      destination: `${SERVER_URL}/api/users/saml/unsolicited/acs`,
      audience: `${SERVER_URL}/api/users/saml/unsolicited/metadata`,
      nameId: address,
      inResponseTo: '_made_up',
    }).xml
    expect(locationOf(await postAcs('unsolicited', fake))).toBe('/login?error=exchange_failed')

    // `emailVerified: false` connections never link existing users by email.
    const victim = email('victim')
    await payload.create({ collection: 'users', data: { email: victim, password: 'pw-123456' } })
    const takeover = buildSamlResponse({
      destination: `${SERVER_URL}/api/users/saml/unsolicited/acs`,
      audience: `${SERVER_URL}/api/users/saml/unsolicited/metadata`,
      nameId: victim,
    }).xml
    expect(locationOf(await postAcs('unsolicited', takeover))).toBe('/login?error=email_unverified')
  })
})

describe('attribute mapping', () => {
  it('prefers attributes over the NameID and composes names', () => {
    const connection = connections[0] as SamlConnection
    const base = {
      issuer: IDP_ENTITY_ID,
      nameID: 'u-1',
      nameIDFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
    }
    expect(samlProfile(connection, { ...base, mail: 'a@b.co', displayName: 'A B' })).toMatchObject({
      providerAccountId: 'u-1',
      email: 'a@b.co',
      emailVerified: true,
      name: 'A B',
    })
    expect(samlProfile(connection, { ...base, givenName: ['Ann'], sn: ['Lee'] }).name).toBe(
      'Ann Lee',
    )
    expect(samlProfile(connection, { ...base, nameID: 'ann@b.co' }).email).toBe('ann@b.co')
    expect(samlProfile(connection, { ...base }).email).toBeUndefined()
    expect(
      samlProfile(
        { ...connection, attributes: { email: ['workMail'] } },
        { ...base, workMail: 'w@b.co', mail: 'x@b.co' },
      ).email,
    ).toBe('w@b.co')
  })
})
