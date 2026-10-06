import crypto from 'node:crypto'
import http from 'node:http'
import type { AddressInfo } from 'node:net'

import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose'

/**
 * Minimal in-process OpenID Connect provider for tests: discovery document, JWKS, `/authorize`
 * (redirects straight back with a code), `/token` (PKCE S256 + client secret), `/userinfo` and a
 * plain `/me` resource. Just enough of the spec for openid-client to accept it; not a real IdP.
 */

export interface MockUser {
  sub: string
  email?: string
  email_verified?: boolean
  name?: string
  given_name?: string
  family_name?: string
  preferred_username?: string
  picture?: string
}

export interface MockIssuer {
  issuer: string
  clientId: string
  clientSecret: string
  endSessionEndpoint: string
  setUser(user: MockUser): void
  tokenRequests(): number
  /** Last `/authorize` request's query, for assertions on what the client sent. */
  lastAuthorizeQuery(): URLSearchParams | undefined
  close(): Promise<void>
}

interface PendingCode {
  user: MockUser
  nonce?: string
  codeChallenge?: string
  redirectUri: string
}

const json = (res: http.ServerResponse, status: number, body: unknown) => {
  res.writeHead(status, { 'content-type': 'application/json' })
  res.end(JSON.stringify(body))
}

const readBody = (req: http.IncomingMessage) =>
  new Promise<string>((resolve, reject) => {
    let data = ''
    req.on('data', (chunk) => (data += chunk))
    req.on('end', () => resolve(data))
    req.on('error', reject)
  })

const s256 = (verifier: string) => crypto.createHash('sha256').update(verifier).digest('base64url')

export async function startMockIssuer(): Promise<MockIssuer> {
  const clientId = 'test-client'
  const clientSecret = crypto.randomBytes(16).toString('hex')
  const { publicKey, privateKey } = await generateKeyPair('RS256')
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'test-key', alg: 'RS256', use: 'sig' }

  let currentUser: MockUser = { sub: 'nobody' }
  let tokenRequests = 0
  let lastAuthorize: URLSearchParams | undefined
  const codes = new Map<string, PendingCode>()
  const accessTokens = new Map<string, MockUser>()
  let issuer = ''

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? '/', issuer)
    try {
      switch (url.pathname) {
        case '/.well-known/openid-configuration':
          return json(res, 200, {
            issuer,
            authorization_endpoint: `${issuer}/authorize`,
            token_endpoint: `${issuer}/token`,
            userinfo_endpoint: `${issuer}/userinfo`,
            jwks_uri: `${issuer}/jwks`,
            end_session_endpoint: `${issuer}/logout`,
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
            scopes_supported: ['openid', 'email', 'profile'],
            token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
            code_challenge_methods_supported: ['S256'],
            authorization_response_iss_parameter_supported: true,
          })

        case '/jwks':
          return json(res, 200, { keys: [jwk] })

        case '/authorize': {
          const q = url.searchParams
          lastAuthorize = q
          const redirectUri = q.get('redirect_uri')
          const state = q.get('state')
          if (
            q.get('client_id') !== clientId ||
            !redirectUri ||
            q.get('response_type') !== 'code'
          ) {
            return json(res, 400, { error: 'invalid_request' })
          }
          const code = crypto.randomBytes(12).toString('hex')
          codes.set(code, {
            user: currentUser,
            nonce: q.get('nonce') ?? undefined,
            codeChallenge: q.get('code_challenge') ?? undefined,
            redirectUri,
          })
          const location = new URL(redirectUri)
          location.searchParams.set('code', code)
          if (state) location.searchParams.set('state', state)
          location.searchParams.set('iss', issuer)
          res.writeHead(302, { location: location.href })
          return res.end()
        }

        case '/token': {
          tokenRequests += 1
          const params = new URLSearchParams(await readBody(req))
          let id = params.get('client_id')
          let secret = params.get('client_secret')
          const auth = req.headers.authorization
          if (auth?.startsWith('Basic ')) {
            const [u, p] = Buffer.from(auth.slice(6), 'base64').toString().split(':')
            id = decodeURIComponent(u ?? '')
            secret = decodeURIComponent(p ?? '')
          }
          if (id !== clientId || secret !== clientSecret) {
            return json(res, 401, { error: 'invalid_client' })
          }
          if (params.get('grant_type') !== 'authorization_code') {
            return json(res, 400, { error: 'unsupported_grant_type' })
          }
          const pending = codes.get(params.get('code') ?? '')
          codes.delete(params.get('code') ?? '')
          if (!pending || pending.redirectUri !== params.get('redirect_uri')) {
            return json(res, 400, { error: 'invalid_grant' })
          }
          const verifier = params.get('code_verifier')
          if (pending.codeChallenge && (!verifier || s256(verifier) !== pending.codeChallenge)) {
            return json(res, 400, { error: 'invalid_grant', error_description: 'bad PKCE' })
          }
          const now = Math.floor(Date.now() / 1000)
          const accessToken = crypto.randomBytes(16).toString('hex')
          accessTokens.set(accessToken, pending.user)
          const scope = params.get('scope') ?? 'openid email profile'
          const body: Record<string, unknown> = {
            access_token: accessToken,
            token_type: 'Bearer',
            expires_in: 300,
            scope,
          }
          // Plain OAuth clients (no `openid` in the original request) get no ID token.
          if (pending.nonce !== undefined || lastAuthorize?.get('scope')?.includes('openid')) {
            body.id_token = await new SignJWT({
              ...pending.user,
              ...(pending.nonce ? { nonce: pending.nonce } : {}),
            })
              .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
              .setIssuer(issuer)
              .setAudience(clientId)
              .setSubject(pending.user.sub)
              .setIssuedAt(now)
              .setExpirationTime(now + 300)
              .sign(privateKey)
          }
          return json(res, 200, body)
        }

        case '/userinfo':
        case '/me': {
          const token = req.headers.authorization?.replace(/^Bearer\s+/i, '')
          const user = token ? accessTokens.get(token) : undefined
          if (!user) {
            res.writeHead(401, { 'www-authenticate': 'Bearer error="invalid_token"' })
            return res.end()
          }
          return json(res, 200, user)
        }

        default:
          return json(res, 404, { error: 'not_found' })
      }
    } catch (error) {
      return json(res, 500, { error: 'server_error', error_description: String(error) })
    }
  })

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve))
  issuer = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  return {
    issuer,
    clientId,
    clientSecret,
    endSessionEndpoint: `${issuer}/logout`,
    setUser: (user) => {
      currentUser = user
    },
    tokenRequests: () => tokenRequests,
    lastAuthorizeQuery: () => lastAuthorize,
    close: () =>
      new Promise<void>((resolve, reject) => server.close((e) => (e ? reject(e) : resolve()))),
  }
}
