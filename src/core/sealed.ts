import { createHash } from 'node:crypto'

import { EncryptJWT, jwtDecrypt } from 'jose'

/**
 * Short-lived encrypted tokens for state that must survive a round trip through the browser
 * (the OAuth PKCE verifier + state + nonce, a SAML request id, the post-login path). A JWE
 * (`dir` + `A256GCM`) keyed from the application secret: the browser can read or forge nothing,
 * and the server stays stateless.
 */

/** 256-bit key derived from `secret`, scoped to `purpose` so tokens of one kind never open another. */
export function deriveKey(secret: string, purpose: string): Uint8Array {
  return new Uint8Array(createHash('sha256').update(`${purpose}:${secret}`).digest())
}

export interface SealOptions {
  ttlSeconds: number
  /** Overridable clock for tests. */
  now?: number
}

export async function seal(
  payload: Record<string, unknown>,
  secret: string,
  purpose: string,
  { ttlSeconds, now = Date.now() }: SealOptions,
): Promise<string> {
  const issuedAt = Math.floor(now / 1000)
  return new EncryptJWT(payload)
    .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
    .setSubject(purpose)
    .setIssuedAt(issuedAt)
    .setExpirationTime(issuedAt + ttlSeconds)
    .encrypt(deriveKey(secret, purpose))
}

/** Decrypts a sealed token; `null` when it is missing, forged, expired, of another purpose or malformed. */
export async function open(
  token: string | null | undefined,
  secret: string,
  purpose: string,
  { now = Date.now() }: { now?: number } = {},
): Promise<Record<string, unknown> | null> {
  if (!token) return null
  try {
    const { payload } = await jwtDecrypt(token, deriveKey(secret, purpose), {
      subject: purpose,
      currentDate: new Date(now),
    })
    return payload as Record<string, unknown>
  } catch {
    return null
  }
}
