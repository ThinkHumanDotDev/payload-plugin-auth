import type { SamlAttributeMap, SamlConnection, SamlProfile, SamlProfileResult } from './types.js'

/** Attribute names identity providers commonly use, by identity field. */
export const DEFAULT_SAML_ATTRIBUTES: Required<SamlAttributeMap> = {
  email: [
    'email',
    'mail',
    'emailAddress',
    'emailaddress',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
    'urn:oid:0.9.2342.19200300.100.1.3',
    'User.email',
  ],
  name: [
    'name',
    'displayName',
    'displayname',
    'cn',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
    'http://schemas.microsoft.com/identity/claims/displayname',
    'urn:oid:2.16.840.1.113730.3.1.241',
  ],
  firstName: [
    'firstName',
    'firstname',
    'givenName',
    'givenname',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname',
    'urn:oid:2.5.4.42',
    'User.FirstName',
  ],
  lastName: [
    'lastName',
    'lastname',
    'surname',
    'sn',
    'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname',
    'urn:oid:2.5.4.4',
    'User.LastName',
  ],
  picture: ['picture', 'avatar', 'thumbnailPhoto'],
}

const EMAIL_FORMAT = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'
const looksLikeEmail = (value: string) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)

/** First non-empty string among the attributes named in `names` (multi-valued attributes: first value). */
export function pickAttribute(profile: SamlProfile, names: string[]): string | undefined {
  for (const name of names) {
    const value = profile[name]
    const first = Array.isArray(value) ? value[0] : value
    if (typeof first === 'string' && first.trim()) return first.trim()
  }
  return undefined
}

/** Default mapping of a SAML profile to an identity: NameID as id, email and name from attributes. */
export function samlProfile(connection: SamlConnection, profile: SamlProfile): SamlProfileResult {
  const map: Required<SamlAttributeMap> = {
    email: [...(connection.attributes?.email ?? []), ...DEFAULT_SAML_ATTRIBUTES.email],
    name: [...(connection.attributes?.name ?? []), ...DEFAULT_SAML_ATTRIBUTES.name],
    firstName: [...(connection.attributes?.firstName ?? []), ...DEFAULT_SAML_ATTRIBUTES.firstName],
    lastName: [...(connection.attributes?.lastName ?? []), ...DEFAULT_SAML_ATTRIBUTES.lastName],
    picture: [...(connection.attributes?.picture ?? []), ...DEFAULT_SAML_ATTRIBUTES.picture],
  }

  // Attributes first; the NameID only when it is an email (the format says so and it looks like one).
  let email = pickAttribute(profile, map.email)
  if (!email && profile.nameIDFormat === EMAIL_FORMAT && looksLikeEmail(profile.nameID)) {
    email = profile.nameID
  } else if (!email && looksLikeEmail(profile.nameID)) {
    email = profile.nameID
  }
  if (email && !looksLikeEmail(email)) email = undefined
  const composed = [pickAttribute(profile, map.firstName), pickAttribute(profile, map.lastName)]
    .filter(Boolean)
    .join(' ')
  const name = pickAttribute(profile, map.name) || composed || undefined

  const raw: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(profile)) {
    if (typeof value === 'function') continue
    raw[key] = value
  }

  return {
    providerAccountId: profile.nameID,
    email,
    emailVerified: connection.emailVerified !== false && Boolean(email),
    name,
    picture: pickAttribute(profile, map.picture),
    raw,
  }
}
