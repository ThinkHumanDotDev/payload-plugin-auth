import { createLocalReq, getFieldsToSign, jwtSign, type Payload, type TypedUser } from 'payload'
import {
  addSessionToUser,
  generateExpiredPayloadCookie,
  generatePayloadCookie,
} from 'payload/shared'

import type { UserId } from './types.js'

/**
 * Issues a Payload session for a user that an external provider has already authenticated, exactly
 * the way `POST /api/<users>/login` does: a session row on the user (`auth.useSessions`), a JWT
 * signed with the Payload secret carrying the collection's `saveToJWT` fields, and the
 * `${cookiePrefix}-token` cookie with the collection's `tokenExpiration`. The result is
 * indistinguishable from a password login for `payload.auth`, the admin panel and the REST API.
 *
 * Payload internals relied on (all public exports of payload 3.x): `jwtSign`, `getFieldsToSign`,
 * `createLocalReq` from `payload`; `addSessionToUser`, `generatePayloadCookie`,
 * `generateExpiredPayloadCookie` from `payload/shared`.
 */
export interface SessionCookie {
  /** Full `Set-Cookie` header value. */
  cookie: string
  token: string
  /** Expiry as a unix timestamp in seconds. */
  exp: number
}

type RawUser = TypedUser & {
  sessions?: { id: string; createdAt: Date | string; expiresAt: Date | string }[]
}

/** The user as the login operation sees it: raw row including `sessions`, no access control. */
async function findRawUser(
  payload: Payload,
  collectionSlug: string,
  id: UserId,
): Promise<RawUser | null> {
  const doc = await payload.db.findOne<RawUser>({
    collection: collectionSlug,
    where: { id: { equals: id } },
  })
  return doc ?? null
}

export interface CreateSessionArgs {
  payload: Payload
  /** Slug of the auth-enabled collection (`users`). */
  collectionSlug: string
  userId: UserId
}

export async function createSessionCookie({
  payload,
  collectionSlug,
  userId,
}: CreateSessionArgs): Promise<SessionCookie> {
  const collection = payload.collections[collectionSlug]
  if (!collection?.config.auth) {
    throw new Error(`Collection "${collectionSlug}" is not auth-enabled`)
  }
  const collectionConfig = collection.config

  const user = await findRawUser(payload, collectionSlug, userId)
  if (!user) throw new Error('User not found')
  user.collection = collectionSlug

  const req = await createLocalReq({}, payload)
  const { sid } = await addSessionToUser({ collectionConfig, payload, req, user })

  const fieldsToSign = getFieldsToSign({
    collectionConfig,
    email: typeof user.email === 'string' ? user.email : '',
    sid,
    user,
  })
  const { exp, token } = await jwtSign({
    fieldsToSign,
    secret: payload.secret,
    tokenExpiration: collectionConfig.auth.tokenExpiration,
  })

  const cookie = generatePayloadCookie({
    collectionAuthConfig: collectionConfig.auth,
    cookiePrefix: payload.config.cookiePrefix,
    token,
  })
  return { cookie, token, exp }
}

/** `Set-Cookie` value that removes the Payload auth cookie (same attributes as `logout`). */
export function expiredSessionCookie(payload: Payload, collectionSlug: string): string {
  const collection = payload.collections[collectionSlug]
  if (!collection?.config.auth) {
    throw new Error(`Collection "${collectionSlug}" is not auth-enabled`)
  }
  return generateExpiredPayloadCookie({
    collectionAuthConfig: collection.config.auth,
    cookiePrefix: payload.config.cookiePrefix,
  })
}

export interface RevokeSessionArgs {
  payload: Payload
  collectionSlug: string
  userId: UserId
  /** `sid` claim of the JWT (`_sid` on the user `payload.auth` returns). */
  sid: string | undefined
}

/** Removes one session from the user so that token stops authenticating. No-op without sessions. */
export async function revokeSession({
  payload,
  collectionSlug,
  userId,
  sid,
}: RevokeSessionArgs): Promise<void> {
  if (!sid) return
  const user = await findRawUser(payload, collectionSlug, userId)
  if (!user?.sessions?.length) return
  const remaining = user.sessions.filter((session) => session.id !== sid)
  if (remaining.length === user.sessions.length) return
  await payload.db.updateOne({
    id: user.id,
    collection: collectionSlug,
    data: { ...user, sessions: remaining, updatedAt: null },
    returning: false,
  })
}

/** `sid` of the session behind a `payload.auth` result, when the collection uses sessions. */
export const sessionIdOf = (user: unknown): string | undefined => {
  const sid = (user as { _sid?: unknown } | null)?._sid
  return typeof sid === 'string' ? sid : undefined
}
