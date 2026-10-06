import crypto from 'node:crypto'

import type { Payload, PayloadRequest, Where } from 'payload'

import { AuthError } from './errors.js'
import type {
  AuthUser,
  ExternalIdentity,
  IdentityContext,
  LinkedAccount,
  ProviderInfo,
  ResolvedUser,
  UserId,
  UserResolutionOptions,
} from './types.js'

export const normalizeEmail = (email: string): string => email.trim().toLowerCase()

/** Loose shape check so a provider's junk never fails the accounts collection's `email` field. */
export const looksLikeEmail = (value: string | undefined): value is string =>
  typeof value === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim())

/** Accounts of auth collections need a password column; nobody ever learns this one. */
export const randomPassword = (): string => crypto.randomBytes(32).toString('base64url')

export interface AccountsClient {
  payload: Payload
  req?: PayloadRequest
  usersSlug: string
  accountsSlug: string
}

const asUser = (doc: unknown): AuthUser => doc as AuthUser
const asAccount = (doc: unknown): LinkedAccount => doc as LinkedAccount
const accountUserId = (account: LinkedAccount): UserId =>
  typeof account.user === 'object' && account.user !== null ? account.user.id : account.user

export async function findAccount(
  { payload, req, accountsSlug }: AccountsClient,
  provider: string,
  providerAccountId: string,
): Promise<LinkedAccount | null> {
  const where: Where = {
    and: [{ provider: { equals: provider } }, { providerAccountId: { equals: providerAccountId } }],
  }
  const { docs } = await payload.find({
    collection: accountsSlug,
    where,
    limit: 1,
    depth: 0,
    req,
    overrideAccess: true,
  })
  return docs[0] ? asAccount(docs[0]) : null
}

export async function findUserById(
  { payload, req, usersSlug }: AccountsClient,
  id: UserId,
): Promise<AuthUser | null> {
  try {
    const doc = await payload.findByID({
      collection: usersSlug,
      id,
      depth: 0,
      req,
      overrideAccess: true,
    })
    return doc ? asUser(doc) : null
  } catch {
    return null
  }
}

export async function findUserByEmail(
  { payload, req, usersSlug }: AccountsClient,
  email: string,
): Promise<AuthUser | null> {
  const { docs } = await payload.find({
    collection: usersSlug,
    where: { email: { equals: normalizeEmail(email) } },
    limit: 1,
    depth: 0,
    req,
    overrideAccess: true,
  })
  return docs[0] ? asUser(docs[0]) : null
}

export async function createAccount(
  { payload, req, accountsSlug }: AccountsClient,
  userId: UserId,
  identity: ExternalIdentity,
): Promise<LinkedAccount> {
  const doc = await payload.create({
    collection: accountsSlug,
    data: {
      user: userId,
      provider: identity.provider,
      providerAccountId: identity.providerAccountId,
      email: looksLikeEmail(identity.email) ? normalizeEmail(identity.email) : undefined,
      name: identity.name,
      lastLoginAt: new Date().toISOString(),
    },
    depth: 0,
    req,
    overrideAccess: true,
  })
  return asAccount(doc)
}

/** Records the login time and the latest email/name the provider released. Never fails a login. */
export async function touchAccount(
  { payload, req, accountsSlug }: AccountsClient,
  account: LinkedAccount,
  identity: ExternalIdentity,
): Promise<LinkedAccount> {
  try {
    const doc = await payload.update({
      collection: accountsSlug,
      id: account.id,
      data: {
        email: looksLikeEmail(identity.email) ? normalizeEmail(identity.email) : account.email,
        name: identity.name ?? account.name,
        lastLoginAt: new Date().toISOString(),
      },
      depth: 0,
      req,
      overrideAccess: true,
    })
    return asAccount(doc)
  } catch (error) {
    payload.logger.warn(
      { err: error, account: account.id },
      'payload-auth: could not update account',
    )
    return account
  }
}

/** Linked accounts of one user, newest login first. */
export async function listAccounts(
  { payload, req, accountsSlug }: AccountsClient,
  userId: UserId,
): Promise<LinkedAccount[]> {
  const { docs } = await payload.find({
    collection: accountsSlug,
    where: { user: { equals: userId } },
    sort: '-lastLoginAt',
    limit: 100,
    depth: 0,
    req,
    overrideAccess: true,
  })
  return docs.map(asAccount)
}

/** Removes one linked account of `userId`. Returns `false` when it does not exist or is not theirs. */
export async function unlinkAccount(
  client: AccountsClient,
  userId: UserId,
  accountId: UserId,
): Promise<boolean> {
  const { payload, req, accountsSlug } = client
  const { docs } = await payload.find({
    collection: accountsSlug,
    where: { and: [{ id: { equals: accountId } }, { user: { equals: userId } }] },
    limit: 1,
    depth: 0,
    req,
    overrideAccess: true,
  })
  if (!docs[0]) return false
  await payload.delete({ collection: accountsSlug, id: docs[0].id, req, overrideAccess: true })
  return true
}

export interface ResolveUserArgs extends AccountsClient {
  request: Request
  identity: ExternalIdentity
  provider: ProviderInfo
  options?: UserResolutionOptions
}

/** Whether the users collection stores passwords (the local strategy is on). */
function usesLocalStrategy(payload: Payload, usersSlug: string): boolean {
  const auth = payload.collections[usersSlug]?.config.auth
  return Boolean(auth) && !auth?.disableLocalStrategy
}

/**
 * Maps an authenticated identity to a user:
 *
 * 1. a linked account `(provider, providerAccountId)` → that user;
 * 2. otherwise a user with the same email, linked only when the provider asserted the email as
 *    verified (`linkByVerifiedEmail`); an unverified email never takes over an existing account;
 * 3. otherwise, when `autoProvision` allows it, a new user with a random password.
 *
 * Throws `AuthError` with a code the handlers redirect to the error page with. Host hooks may throw
 * their own `AuthError`s (for example when sign-up is disabled and no invitation exists).
 */
export async function resolveUser(args: ResolveUserArgs): Promise<ResolvedUser> {
  const { payload, req, request, identity, provider, options = {} } = args
  const ctx: IdentityContext = { payload, req, request, identity, provider }
  const client: AccountsClient = {
    payload,
    req,
    usersSlug: args.usersSlug,
    accountsSlug: args.accountsSlug,
  }

  const existingAccount = await findAccount(client, identity.provider, identity.providerAccountId)
  if (existingAccount) {
    const user = await findUserById(client, accountUserId(existingAccount))
    if (user) {
      const account = await touchAccount(client, existingAccount, identity)
      await options.afterLogin?.({ ...ctx, user, created: false, linked: false })
      return { user, account, created: false, linked: false }
    }
    // The user was deleted but the account row survived: forget it and treat this as a new identity.
    await payload.delete({
      collection: client.accountsSlug,
      id: existingAccount.id,
      req,
      overrideAccess: true,
    })
  }

  const found = await options.findUser?.(ctx)
  if (found) {
    await options.beforeLink?.({ ...ctx, user: found })
    const account = await createAccount(client, found.id, identity)
    payload.logger.info(
      { user: found.id, provider: identity.provider },
      'payload-auth: linked identity to user returned by findUser',
    )
    await options.afterLink?.({ ...ctx, user: found })
    await options.afterLogin?.({ ...ctx, user: found, created: false, linked: true })
    return { user: found, account, created: false, linked: true }
  }

  const email = identity.email ? normalizeEmail(identity.email) : undefined
  if (!email && options.requireEmail !== false) throw new AuthError('email_missing')

  if (email) {
    const existingUser = await findUserByEmail(client, email)
    if (existingUser) {
      const allowed =
        typeof options.linkByVerifiedEmail === 'function'
          ? await options.linkByVerifiedEmail({ ...ctx, user: existingUser })
          : options.linkByVerifiedEmail !== false && identity.emailVerified
      if (!allowed) throw new AuthError('email_unverified')
      await options.beforeLink?.({ ...ctx, user: existingUser })
      const account = await createAccount(client, existingUser.id, identity)
      payload.logger.info(
        { user: existingUser.id, provider: identity.provider },
        'payload-auth: linked identity to existing user by verified email',
      )
      await options.afterLink?.({ ...ctx, user: existingUser })
      await options.afterLogin?.({ ...ctx, user: existingUser, created: false, linked: true })
      return { user: existingUser, account, created: false, linked: true }
    }
  }

  const autoProvision =
    typeof options.autoProvision === 'function'
      ? await options.autoProvision(ctx)
      : options.autoProvision !== false
  if (!autoProvision) throw new AuthError('provisioning_disabled')

  await options.beforeProvision?.(ctx)

  const data: Record<string, unknown> = {
    email,
    name: identity.name,
    ...(usesLocalStrategy(payload, client.usersSlug) ? { password: randomPassword() } : {}),
    ...((await options.mapNewUser?.(ctx)) ?? {}),
  }
  const user = asUser(
    await payload.create({
      collection: client.usersSlug,
      data,
      depth: 0,
      req,
      overrideAccess: true,
    }),
  )
  const account = await createAccount(client, user.id, identity)
  payload.logger.info(
    { user: user.id, provider: identity.provider },
    'payload-auth: provisioned user from external identity',
  )
  await options.afterProvision?.({ ...ctx, user })
  await options.afterLogin?.({ ...ctx, user, created: true, linked: false })
  return { user, account, created: true, linked: false }
}

export interface LinkIdentityArgs extends AccountsClient {
  request: Request
  identity: ExternalIdentity
  provider: ProviderInfo
  /** The signed-in user the identity should be attached to. */
  userId: UserId
  options?: UserResolutionOptions
}

/**
 * Attaches an identity to an already signed-in user ("connect another account"). Refuses when the
 * identity is linked to somebody else (`account_in_use`); a repeat link of the same identity is a
 * no-op.
 */
export async function linkIdentity(args: LinkIdentityArgs): Promise<ResolvedUser> {
  const { payload, req, request, identity, provider, userId, options = {} } = args
  const client: AccountsClient = {
    payload,
    req,
    usersSlug: args.usersSlug,
    accountsSlug: args.accountsSlug,
  }
  const user = await findUserById(client, userId)
  if (!user) throw new AuthError('not_signed_in', { status: 401 })
  const ctx = { payload, req, request, identity, provider, user }

  const existing = await findAccount(client, identity.provider, identity.providerAccountId)
  if (existing) {
    if (String(accountUserId(existing)) !== String(user.id)) {
      throw new AuthError('account_in_use', { status: 409 })
    }
    const account = await touchAccount(client, existing, identity)
    return { user, account, created: false, linked: false }
  }

  await options.beforeLink?.(ctx)
  const account = await createAccount(client, user.id, identity)
  payload.logger.info(
    { user: user.id, provider: identity.provider },
    'payload-auth: linked identity to signed-in user',
  )
  await options.afterLink?.(ctx)
  return { user, account, created: false, linked: true }
}
