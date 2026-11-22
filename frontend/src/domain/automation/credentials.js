/*
 * Stored credentials (Settings → Credentials), and how the form of an
 * instance uses them.
 *
 * A credential is a secret kept once under a name: a `secret` (one value) or
 * a `pair` (a user name, which is shown, and a password). An instance names
 * it where it would hold a value, as `{{ credentials.<name> }}` (a pair:
 * `.username` / `.password`): that text is what the form sends for the field
 * and what the server stores. The value itself never comes back.
 *
 * A field that holds a secret is given in one of two ways: typed here, or
 * from a credential. The functions below say which way a field is in, what a
 * field can be given, and what choosing a credential fills.
 */

export const CREDENTIAL_KINDS = [
  { id: 'secret', label: 'Secret', hint: 'One value: an API key, a token.' },
  { id: 'pair', label: 'User name and password', hint: 'Two values kept together; the user name is shown.' },
]

export const CREDENTIAL_NAME = /^[a-z][a-z0-9_-]{0,39}$/

const REFERENCE = /^\s*\{\{\s*credentials\.([a-z][a-z0-9_-]*)(?:\.(username|password))?\s*\}\}\s*$/
// The two secrets of a connector that a pair fills together.
const PAIRS = [
  ['username', 'password'],
  ['client_id', 'client_secret'],
]

/** `{{ credentials.vt_key }}`, `{{ credentials.proxy.password }}`: what a field holds to name a credential. */
export const referenceText = (name, part = '') => `{{ credentials.${name}${part ? `.${part}` : ''} }}`

/** The credential a text names, `{ name, part }`, or null when it is something that was typed. */
export function parseReference(text) {
  const found = REFERENCE.exec(String(text ?? ''))
  return found ? { name: found[1], part: found[2] ?? '' } : null
}

/** Whether a text tries to name a credential (rightly or not): it is then shown as typed, not hidden. */
export const mentionsCredential = (text) => /\{\{\s*credentials\b/.test(String(text ?? ''))

/** The two secret fields a pair fills together among these, `[user, password]`, or null. */
export function pairOf(fieldNames) {
  const names = fieldNames ?? []
  return PAIRS.find(([user, password]) => names.includes(user) && names.includes(password)) ?? null
}

/**
 * What a secret field can be given from the stored credentials:
 * `[{ value, label, fills }]`. `value` is the text the field holds; `fills`
 * is every field the choice sets (a pair sets the user name and the password
 * together where the connector has both). The field of a user name takes
 * pairs only; a field that is one value takes a secret, or the password of a
 * pair.
 */
export function credentialChoices(credentials, field, fieldNames) {
  const pair = pairOf(fieldNames)
  const inPair = pair !== null && pair.includes(field)
  const choices = []
  const sorted = [...(credentials ?? [])].sort((a, b) => a.name.localeCompare(b.name))
  for (const credential of sorted) {
    if (credential.kind === 'pair') {
      if (inPair) {
        const user = referenceText(credential.name, 'username')
        const password = referenceText(credential.name, 'password')
        choices.push({
          value: field === pair[0] ? user : password,
          label: `${credential.name} (${credential.username})`,
          fills: { [pair[0]]: user, [pair[1]]: password },
        })
      } else {
        const value = referenceText(credential.name, 'password')
        choices.push({ value, label: `${credential.name} (its password)`, fills: { [field]: value } })
      }
    } else if (!(inPair && field === pair[0])) {
      const value = referenceText(credential.name)
      choices.push({ value, label: credential.name, fills: { [field]: value } })
    }
  }
  return choices
}

/** The text of the credential a field is stored with (`held` is `credentials` of an instance or of a key). */
export function storedReference(held, field) {
  const found = held?.[field]
  return found ? referenceText(found.name, found.part) : ''
}

/**
 * The way a secret field is given: 'typed' or 'credential'. What the person
 * chose wins; then what the field holds; then what is stored. A field that
 * holds nothing starts from a credential when one fits: the short way to make
 * an instance again.
 */
export function secretMode({ chosen = '', typed = '', stored = false, reference = '', choices = [] }) {
  if (chosen === 'typed' || chosen === 'credential') return chosen
  if (parseReference(typed)) return 'credential'
  if (typed) return 'typed'
  if (reference) return 'credential'
  if (stored) return 'typed'
  return choices.length > 0 ? 'credential' : 'typed'
}

/** The credential the picker of a field shows: the one just chosen, or the one that is stored. */
export const pickedReference = (typed, reference) => (parseReference(typed) ? String(typed).trim() : reference || '')

/**
 * The options of the picker of a field: its choices, and before them the
 * credential it is stored with when that one is not among them (it was
 * deleted, or is of another kind).
 */
export function pickerOptions(choices, picked, held) {
  if (!picked || choices.some((choice) => choice.value === picked)) return choices
  const named = parseReference(picked)
  const label = `${named?.name ?? picked}${held?.missing ? ' (does not exist any more)' : ''}`
  return [{ value: picked, label, fills: {} }, ...choices]
}

/**
 * What changing the way of a field does to what it holds: a credential that
 * was chosen is dropped when the field is typed again, and what was typed is
 * dropped when a credential is to be chosen.
 */
export function valueForMode(typed, mode) {
  const isReference = parseReference(typed) !== null
  if (mode === 'typed') return isReference ? '' : (typed ?? '')
  return isReference ? typed : ''
}

/**
 * Whether "Keep as a credential…" is offered on a field: its secret is stored, and was typed. Not on
 * the user name of a pair, which is no secret by itself: it is kept with its password, from there.
 */
export function keepable(stored, held, field, fieldNames = []) {
  if (!stored || held?.[field]) return false
  return pairOf(fieldNames)?.[0] !== field
}

/** What "Keep as a credential…" would make of a field: 'pair' when both parts were typed, else 'secret'. */
export function keptKind(field, fieldNames, stored, held) {
  const pair = pairOf(fieldNames)
  const both = pair !== null && pair.includes(field) && pair.every((name) => Boolean(stored?.[name]) && !held?.[name])
  return both ? 'pair' : 'secret'
}

/** A name to start from for a credential kept from an instance: "Shodan production" → "shodan_production". */
export function suggestedName(text) {
  const slug = String(text ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^[^a-z]+|_+$/g, '')
    .slice(0, 40)
    .replace(/_+$/, '')
  return slug
}

/** Why a name cannot be the name of a credential, or null. */
export function nameProblem(name, taken = []) {
  const text = String(name ?? '').trim()
  if (!text) return 'A name is needed'
  if (!CREDENTIAL_NAME.test(text))
    return 'A name is a lower-case letter, then lower-case letters, digits, _ or - (40 at most)'
  if (taken.includes(text)) return `A credential called "${text}" exists already`
  return null
}

/**
 * Why the form of a credential cannot be sent, or null. `existing` is the
 * credential that is edited (its value may be left empty: it stays); `taken`
 * the names of the others.
 */
export function credentialProblem(form, { existing = null, taken = [] } = {}) {
  const wrong = nameProblem(form.name, taken)
  if (wrong) return wrong
  if (form.kind === 'pair' && !String(form.username ?? '').trim()) return 'The user name is needed'
  if (!existing && !form.value) return form.kind === 'pair' ? 'The password is needed' : 'The value is needed'
  if (mentionsCredential(form.value) || mentionsCredential(form.username))
    return 'A credential holds a value, not the name of another credential'
  return null
}

/** What POST /api/automation/credentials takes for a new credential. */
export function createBody(form) {
  return {
    name: form.name.trim(),
    title: String(form.title ?? '').trim(),
    kind: form.kind,
    ...(form.kind === 'pair' ? { username: form.username.trim() } : {}),
    value: form.value,
  }
}

/** What PUT /api/automation/credentials/{id} takes: only what changed; a value left empty stays. */
export function updateBody(form, existing) {
  const body = {}
  if (form.name.trim() !== existing.name) body.name = form.name.trim()
  if (String(form.title ?? '').trim() !== (existing.title ?? '')) body.title = String(form.title ?? '').trim()
  if (existing.kind === 'pair' && form.username.trim() !== existing.username) body.username = form.username.trim()
  if (form.value) body.value = form.value
  return body
}

/** The form of a credential: empty for a new one, what can be shown of one that exists. */
export const credentialForm = (existing = null) => ({
  name: existing?.name ?? '',
  title: existing?.title ?? '',
  kind: existing?.kind ?? 'secret',
  username: existing?.username ?? '',
  value: '',
})

/**
 * Where a credential is used, as the page lists it: one line for each
 * instance, with the keys of it that name the credential when they are not
 * its first: `[{ instance, name, connectorName, tab, keys }]`.
 */
export function usedIn(usedBy) {
  const byInstance = new Map()
  for (const use of usedBy ?? []) {
    if (!byInstance.has(use.instance)) {
      byInstance.set(use.instance, {
        instance: use.instance,
        name: use.name,
        connectorName: use.connectorName,
        tab: 'keys',
        keys: [],
      })
    }
    const entry = byInstance.get(use.instance)
    // The first key is on the Connection tab; the others are on Keys.
    if (use.key === 'main') entry.tab = 'connection'
    else entry.keys.push(use.keyName)
  }
  return [...byInstance.values()]
}

/** The credentials narrowed by what is typed: the name, the description, the user name, an instance that uses it. */
export function filterCredentials(credentials, query) {
  const words = String(query ?? '')
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
  if (words.length === 0) return credentials ?? []
  return (credentials ?? []).filter((credential) => {
    const text = [
      credential.name,
      credential.title,
      credential.username,
      ...(credential.usedBy ?? []).map((use) => use.name),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
    return words.every((word) => text.includes(word))
  })
}
