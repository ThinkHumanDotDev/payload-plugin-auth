import type { Access, CollectionConfig, Config, Field } from 'payload'

export const DEFAULT_ACCOUNTS_SLUG = 'auth-accounts'

export interface LinkedAccountsOptions {
  /** Collection slug. Default `auth-accounts`. */
  slug?: string
  /** Slug of the auth-enabled users collection the accounts belong to. */
  usersSlug: string
  /**
   * Access control. Defaults: users read and delete their own accounts (unlinking), nothing is
   * writable through the API (the flows write with `overrideAccess`). Override per operation.
   */
  access?: Partial<CollectionConfig['access']>
  admin?: CollectionConfig['admin']
  /** Extra fields (for example a tenant relationship). */
  fields?: Field[]
  hooks?: CollectionConfig['hooks']
}

/** `req.user` belongs to the users collection and the row is theirs. */
const ownAccounts =
  (usersSlug: string): Access =>
  ({ req }) => {
    const user = req.user
    if (!user || user.collection !== usersSlug) return false
    return { user: { equals: user.id } }
  }

/**
 * The collection that links `(provider, providerAccountId)` to a user. One user may hold many
 * identities (GitHub and Google and the company IdP); one identity belongs to exactly one user.
 */
export function linkedAccountsCollection(options: LinkedAccountsOptions): CollectionConfig {
  const slug = options.slug ?? DEFAULT_ACCOUNTS_SLUG
  const own = ownAccounts(options.usersSlug)
  return {
    slug,
    admin: {
      useAsTitle: 'providerAccountId',
      defaultColumns: ['provider', 'providerAccountId', 'user', 'email', 'lastLoginAt'],
      group: 'Access',
      description: 'External identities linked to users by the single sign-on plugins.',
      ...options.admin,
    },
    access: {
      read: own,
      create: () => false,
      update: () => false,
      delete: own,
      ...options.access,
    },
    hooks: options.hooks,
    indexes: [{ fields: ['provider', 'providerAccountId'], unique: true }],
    fields: [
      {
        name: 'user',
        type: 'relationship',
        relationTo: options.usersSlug,
        required: true,
        index: true,
        maxDepth: 0,
      },
      {
        name: 'provider',
        type: 'text',
        required: true,
        index: true,
        admin: { description: 'Provider or connection id the identity came from.' },
      },
      {
        name: 'providerAccountId',
        type: 'text',
        required: true,
        admin: {
          description: 'Stable identifier at the provider (OIDC sub, OAuth id, SAML NameID).',
        },
      },
      {
        name: 'email',
        type: 'email',
        admin: { description: 'Email the provider released, if any.' },
      },
      { name: 'name', type: 'text' },
      { name: 'lastLoginAt', type: 'date', admin: { readOnly: true } },
      ...(options.fields ?? []),
    ],
    timestamps: true,
  }
}

/**
 * Adds the linked-accounts collection to a Payload config unless a collection with that slug is
 * already registered (the host, or the other plugin, may have added it). Returns the slug.
 */
export function ensureLinkedAccountsCollection(
  config: Config,
  options: LinkedAccountsOptions,
): string {
  const slug = options.slug ?? DEFAULT_ACCOUNTS_SLUG
  config.collections ??= []
  if (!config.collections.some((collection) => collection.slug === slug)) {
    config.collections.push(linkedAccountsCollection({ ...options, slug }))
  }
  return slug
}

/** Slug of the collection the admin panel authenticates against, or `users`. */
export function defaultUsersSlug(config: Config): string {
  return config.admin?.user ?? 'users'
}
