import type { OAuthProvider, ProfileContext, ProfileResult } from '../types.js'

type Overrides = Partial<Omit<OAuthProvider, 'type'>>

interface PresetBase {
  clientId: string
  clientSecret?: string
  /** Override the default id (`github`) when the same provider is registered twice. */
  id?: string
  /** Override the button label. */
  name?: string
  scopes?: string[]
  authorizationParams?: Record<string, string>
  meta?: Record<string, unknown>
}

const str = (value: unknown): string | undefined => (typeof value === 'string' ? value : undefined)

/**
 * Standard OpenID Connect claims → identity. Used by every OIDC provider unless it overrides
 * `profile`. UserInfo (when fetched) wins over ID-token claims.
 */
export function oidcProfile(ctx: ProfileContext): ProfileResult {
  const claims = { ...(ctx.claims ?? {}), ...(ctx.userinfo ?? {}) } as Record<string, unknown>
  const sub = str(claims.sub)
  if (!sub) throw new Error('ID token has no sub claim')
  const given = str(claims.given_name)?.trim()
  const family = str(claims.family_name)?.trim()
  const composed = [given, family].filter(Boolean).join(' ')
  return {
    providerAccountId: sub,
    email: str(claims.email),
    emailVerified: claims.email_verified === true,
    name:
      str(claims.name)?.trim() ||
      composed ||
      str(claims.nickname)?.trim() ||
      str(claims.preferred_username)?.trim() ||
      undefined,
    picture: str(claims.picture),
    raw: claims,
  }
}

/** Any OpenID Connect provider with a discovery document (Keycloak, Okta, Authentik, Auth0, Zitadel, ...). */
export function oidc(
  options: PresetBase & { issuer: string; name?: string; id?: string } & Overrides,
): OAuthProvider {
  const { id = 'oidc', name = 'Single sign-on', issuer, ...rest } = options
  return { type: 'oidc', id, name, issuer, ...rest }
}

/**
 * A plain OAuth 2.0 server without discovery: give the endpoints and a `profile()` that turns the
 * tokens into an identity.
 */
export function oauth2(
  options: PresetBase &
    Overrides & {
      id: string
      name: string
      authorizationEndpoint: string
      tokenEndpoint: string
      profile: OAuthProvider['profile']
    },
): OAuthProvider {
  return { type: 'oauth2', ...options }
}

interface GithubEmail {
  email: string
  primary: boolean
  verified: boolean
}

/** GitHub OAuth app or GitHub App (user-to-server). Scopes default to `read:user user:email`. */
export function github(options: PresetBase & Overrides): OAuthProvider {
  const { id = 'github', name = 'GitHub', scopes = ['read:user', 'user:email'], ...rest } = options
  return {
    type: 'oauth2',
    id,
    name,
    icon: 'github',
    issuer: 'https://github.com',
    authorizationEndpoint: 'https://github.com/login/oauth/authorize',
    tokenEndpoint: 'https://github.com/login/oauth/access_token',
    scopes,
    // GitHub ignores PKCE parameters; sending them is harmless but pointless.
    pkce: false,
    clientAuth: 'client_secret_post',
    async profile(ctx) {
      const user = await ctx.fetchJson<Record<string, unknown>>('https://api.github.com/user')
      let email = str(user.email)
      let emailVerified = false
      try {
        const emails = await ctx.fetchJson<GithubEmail[]>('https://api.github.com/user/emails')
        const primary =
          emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified)
        if (primary) {
          email = primary.email
          emailVerified = true
        }
      } catch {
        // Without the `user:email` scope the endpoint is forbidden; fall back to the public email.
      }
      return {
        providerAccountId: String(user.id),
        email,
        emailVerified,
        name: str(user.name) ?? str(user.login),
        picture: str(user.avatar_url),
        raw: { ...user, email },
      }
    },
    ...rest,
  }
}

/** Google (Google Workspace or consumer accounts). `hd` in `authorizationParams` restricts the domain. */
export function google(options: PresetBase & Overrides): OAuthProvider {
  const { id = 'google', name = 'Google', ...rest } = options
  return {
    type: 'oidc',
    id,
    name,
    icon: 'google',
    issuer: 'https://accounts.google.com',
    scopes: ['openid', 'email', 'profile'],
    ...rest,
  }
}

/**
 * Microsoft Entra ID. `tenant` is the directory (tenant) id; the multi-tenant aliases (`common`,
 * `organizations`) cannot be used because their discovery document advertises a templated issuer
 * that ID tokens never match. Register one provider per tenant instead.
 */
export function microsoft(options: PresetBase & Overrides & { tenant: string }): OAuthProvider {
  const { id = 'microsoft', name = 'Microsoft', tenant, ...rest } = options
  if (['common', 'organizations', 'consumers'].includes(tenant)) {
    throw new Error('payload-auth: microsoft() needs a tenant id, not a multi-tenant alias')
  }
  return {
    type: 'oidc',
    id,
    name,
    icon: 'microsoft',
    issuer: `https://login.microsoftonline.com/${tenant}/v2.0`,
    scopes: ['openid', 'email', 'profile'],
    ...rest,
  }
}

/** GitLab.com or a self-managed instance (`baseUrl`). */
export function gitlab(options: PresetBase & Overrides & { baseUrl?: string }): OAuthProvider {
  const { id = 'gitlab', name = 'GitLab', baseUrl = 'https://gitlab.com', ...rest } = options
  return {
    type: 'oidc',
    id,
    name,
    icon: 'gitlab',
    issuer: baseUrl.replace(/\/$/, ''),
    scopes: ['openid', 'email', 'profile'],
    ...rest,
  }
}

/** Discord (`identify email` scopes). */
export function discord(options: PresetBase & Overrides): OAuthProvider {
  const { id = 'discord', name = 'Discord', scopes = ['identify', 'email'], ...rest } = options
  return {
    type: 'oauth2',
    id,
    name,
    icon: 'discord',
    issuer: 'https://discord.com',
    authorizationEndpoint: 'https://discord.com/oauth2/authorize',
    tokenEndpoint: 'https://discord.com/api/oauth2/token',
    scopes,
    clientAuth: 'client_secret_post',
    async profile(ctx) {
      const user = await ctx.fetchJson<Record<string, unknown>>('https://discord.com/api/users/@me')
      return {
        providerAccountId: String(user.id),
        email: str(user.email),
        emailVerified: user.verified === true,
        name: str(user.global_name) ?? str(user.username),
        picture:
          typeof user.avatar === 'string'
            ? `https://cdn.discordapp.com/avatars/${String(user.id)}/${user.avatar}.png`
            : undefined,
        raw: user,
      }
    },
    ...rest,
  }
}
