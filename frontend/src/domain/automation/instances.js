/*
 * A connection as its form needs it: the fields a connector asks for (plain
 * values, then the parts of its credentials), and what the form sends.
 *
 * Secrets are write-only: the server never returns one, only whether it is
 * set. A secret field left empty on a connection that has it keeps it; the
 * form sends a secret only when something was typed, or when the person
 * asked to remove it.
 */

const SECRET_LABELS = {
  username: 'User name',
  password: 'Password',
  token: 'Token',
  value: 'Key',
  client_id: 'Client ID',
  client_secret: 'Client secret',
  api_key: 'API key',
}

// The parts of a credential that are not secret to look at (shown as typed).
const VISIBLE = new Set(['username', 'client_id'])

const AUTH_NAMES = {
  basic: 'a user name and a password',
  bearer: 'a token',
  header: 'a key sent in a header',
  oauth2_client: 'OAuth2 client credentials',
  session: 'a session opened with a login',
  zscaler: 'the Zscaler sign-in',
}

const label = (name) => SECRET_LABELS[name] ?? name.replaceAll('_', ' ').replace(/^./, (letter) => letter.toUpperCase())

/** How a connector signs in, in words ("a token"); '' when it needs no credentials. */
export function authOf(connector) {
  const auth = (connector?.configuration ?? []).find((param) => Object.hasOwn(AUTH_NAMES, param.type))
  return auth ? AUTH_NAMES[auth.type] : ''
}

/**
 * The fields of a connection's form, in order:
 * `[{ name, label, kind: 'config' | 'secret', type, required, choices, help, masked }]`.
 */
export function fieldsOf(connector) {
  const fields = []
  for (const param of connector?.configuration ?? []) {
    if (Object.hasOwn(AUTH_NAMES, param.type) || param.type === 'secret') continue
    fields.push({
      name: param.name,
      label: param.label || label(param.name),
      kind: 'config',
      type: param.type,
      required: Boolean(param.required),
      choices: param.choices ?? [],
      help: param.help ?? '',
      placeholder: param.default === null || param.default === undefined ? '' : String(param.default),
      masked: false,
    })
  }
  for (const name of connector?.secrets ?? []) {
    const param = (connector.configuration ?? []).find((item) => item.name === name && item.type === 'secret')
    fields.push({
      name,
      label: param?.label || label(name),
      kind: 'secret',
      type: 'secret',
      required: false,
      choices: [],
      help: param?.help ?? '',
      placeholder: '',
      masked: !VISIBLE.has(name),
    })
  }
  return fields
}

/** What the form starts from: the plain values of the connection; every secret empty. */
export function startingValues(connector, connection = null) {
  const values = {}
  for (const field of fieldsOf(connector)) {
    if (field.kind === 'secret') values[field.name] = ''
    else values[field.name] = connection?.config?.[field.name] ?? (field.type === 'bool' ? false : '')
  }
  return values
}

/**
 * What is sent: `{ config, secrets }`. A plain value is sent as its type
 * says, empty ones left out. A secret is sent when typed; `removed` names
 * the stored secrets to take away.
 */
export function payloadOf(connector, values, removed = []) {
  const config = {}
  const secrets = {}
  for (const field of fieldsOf(connector)) {
    const raw = values?.[field.name]
    if (field.kind === 'secret') {
      if (removed.includes(field.name)) secrets[field.name] = ''
      else if (typeof raw === 'string' && raw !== '') secrets[field.name] = raw
      continue
    }
    if (field.type === 'bool') {
      config[field.name] = Boolean(raw)
      continue
    }
    const text = typeof raw === 'string' ? raw.trim() : raw
    if (text === '' || text === null || text === undefined) continue
    config[field.name] = field.type === 'number' && Number.isFinite(Number(text)) ? Number(text) : text
  }
  return { config, secrets }
}

/** Why the form cannot be sent yet, or null. */
export function formProblem(connector, name, values) {
  if (!String(name ?? '').trim()) return 'A name is needed'
  for (const field of fieldsOf(connector)) {
    if (field.kind !== 'config') continue
    const text = String(values?.[field.name] ?? '').trim()
    if (field.required && !text && !field.placeholder) return `${field.label} is needed`
    if (field.type === 'url' && text && !/^https?:\/\/[^\s/]+/i.test(text))
      return `${field.label} is an https:// address`
    if (field.type === 'number' && text && !Number.isFinite(Number(text))) return `${field.label} is a number`
  }
  return null
}

/** The problems of a connector file as lines to show: "line 12: …" (the file itself has no line). */
export function problemLines(problems) {
  return (problems ?? []).map((problem) => ({
    key: `${problem.line}:${problem.message}`,
    line: problem.line || null,
    text: problem.message,
    where: problem.where ?? '',
  }))
}

/* ---- Connectors with their instances (Settings → Connectors) ---- */

export const CONNECTOR_FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'enabled', label: 'Enabled' },
  { id: 'unused', label: 'Not configured' },
]

/** What a connector can do besides its commands, in a few words: "9 commands · fetch · mirror". */
export function capabilities(connector) {
  const count = connector.commands?.length
  const parts = [count === undefined ? null : `${count} ${count === 1 ? 'command' : 'commands'}`]
  if (connector.fetch) parts.push('fetch')
  if (connector.mirror) parts.push('mirror')
  return parts.filter(Boolean).join(' · ')
}

/** "2 instances · 1 on", "1 instance · on", "1 instance · off", "not configured". */
export function instancesText(instances) {
  const count = instances.length
  if (count === 0) return 'not configured'
  const on = instances.filter((instance) => instance.enabled).length
  if (count === 1) return `1 instance · ${on ? 'on' : 'off'}`
  return `${count} instances · ${on} on`
}

/**
 * The connectors as the page lists them: each with its instances (by name),
 * narrowed by what is typed (the name, the id, the description of a connector,
 * the name or the host of an instance) and by the filter. `counts` are those of
 * the filters before the text narrows them.
 */
export function connectorRows(connectors, instances, { query = '', filter = 'all' } = {}) {
  const byConnector = new Map()
  for (const instance of instances ?? []) {
    if (!byConnector.has(instance.connector)) byConnector.set(instance.connector, [])
    byConnector.get(instance.connector).push(instance)
  }
  const all = (connectors ?? []).map((connector) => {
    const own = (byConnector.get(connector.id) ?? []).sort((a, b) =>
      a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }),
    )
    return { ...connector, instances: own, enabled: own.some((instance) => instance.enabled) }
  })
  const counts = {
    all: all.length,
    enabled: all.filter((row) => row.enabled).length,
    unused: all.filter((row) => row.instances.length === 0).length,
  }
  const words = String(query).trim().toLowerCase().split(/\s+/).filter(Boolean)
  const rows = all.filter((row) => {
    if (filter === 'enabled' && !row.enabled) return false
    if (filter === 'unused' && row.instances.length > 0) return false
    const text = [
      row.name,
      row.id,
      row.description,
      ...row.instances.flatMap((instance) => [instance.name, instance.host]),
    ]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
    return words.every((word) => text.includes(word))
  })
  return { rows, counts }
}

// --------------------------------------------------------------------------- //
// Several keys for one instance (6.1)                                          //
// --------------------------------------------------------------------------- //

/** How the keys of an instance take turns, as the form offers it. */
export const KEY_MODES = [
  { id: 'each', label: 'One request each', hint: 'The keys take turns, request after request.' },
  {
    id: 'until_exhausted',
    label: 'The same key until it is used up',
    hint: 'In the order above; the next one starts when the vendor answers "quota exceeded" or the limit below is reached.',
  },
  {
    id: 'least_used',
    label: 'The one with most left',
    hint: 'Each request goes to the key that was used least today.',
  },
  {
    id: 'reserve',
    label: 'First key only, the others in reserve',
    hint: 'Another key is used only while the first one is used up.',
  },
]

export const KEY_POLICY_DEFAULTS = { mode: 'each', perMinute: 0, perDay: 0, whenExhausted: 'wait', cacheHours: 0 }

/** The fields a key is made of: the credentials the connector asks for. */
export const keyFields = (connector) => fieldsOf(connector).filter((field) => field.kind === 'secret')

/** Whether an instance of this connector can hold more keys than one: it must have credentials. */
export const takesKeys = (connector) => keyFields(connector).length > 0 && !connector?.native

/**
 * The keys as the form edits them, from what the API gives: the first is the credentials of the
 * instance (`main`), the others can be renamed, reordered and removed. `values` is what was typed.
 */
export const editableKeys = (instance) => (instance?.keys ?? []).map((key) => ({ ...key, isNew: false, values: {} }))

/** A key that was just added in the form. */
export const newKey = (connector, count) => ({
  id: '',
  name: `Key ${count + 1}`,
  isNew: true,
  secrets: {},
  values: Object.fromEntries(keyFields(connector).map((field) => [field.name, ''])),
  usedToday: 0,
  usedThisMinute: 0,
  total: 0,
  state: 'new',
})

/** Why the keys cannot be saved, or null. */
export function keysProblem(connector, keys, policy) {
  const names = new Set()
  for (const key of keys) {
    const name = String(key.name ?? '').trim()
    if (!name) return 'A key needs a name'
    if (names.has(name.toLowerCase())) return `Two keys are called "${name}"`
    names.add(name.toLowerCase())
    if (key.isNew && !Object.values(key.values ?? {}).some((value) => String(value ?? '') !== '')) {
      return `"${name}" has no credential yet`
    }
  }
  for (const [field, label] of [
    ['perMinute', 'Requests a minute'],
    ['perDay', 'Requests a day'],
    ['cacheHours', 'The hours an answer is kept'],
  ]) {
    const value = Number(policy?.[field] ?? 0)
    if (!Number.isInteger(value) || value < 0) return `${label} is a whole number, 0 for none`
  }
  return null
}

/** What PUT /api/automation/instances/{id} takes for the keys: `{ mainName, keys, keyPolicy }`. */
export function keysPayload(keys, policy) {
  const [first, ...others] = keys
  return {
    mainName: String(first?.name ?? '').trim(),
    keys: others.map((key) => {
      const secrets = Object.fromEntries(
        Object.entries(key.values ?? {}).filter(([, value]) => typeof value === 'string' && value !== ''),
      )
      return {
        ...(key.id ? { id: key.id } : {}),
        name: String(key.name ?? '').trim(),
        ...(Object.keys(secrets).length ? { secrets } : {}),
      }
    }),
    keyPolicy: {
      mode: policy.mode,
      perMinute: Number(policy.perMinute) || 0,
      perDay: Number(policy.perDay) || 0,
      whenExhausted: policy.whenExhausted,
      cacheHours: Number(policy.cacheHours) || 0,
    },
  }
}

/** "190 / 500" or "190": what a key was used for today, against its limit when there is one. */
export const keyUse = (key, policy) =>
  Number(policy?.perDay) > 0 ? `${key.usedToday ?? 0} / ${policy.perDay}` : String(key.usedToday ?? 0)

/** How full the day of a key is, 0 to 1 (0 when there is no limit a day). */
export const keyShare = (key, policy) =>
  Number(policy?.perDay) > 0 ? Math.min(1, (key.usedToday ?? 0) / Number(policy.perDay)) : 0

/* ---------------------------------------------------------------- the form */

/**
 * The parts of the form of an instance, as its tabs: the connection always;
 * the keys for a connector that signs in; fetching for one that can fetch;
 * the classifier and the mappers once the instance exists (a classifier
 * belongs to an instance, and both are tried on what it fetched). `wide` parts
 * are tables that need the width of the page.
 */
export function instanceTabs(connector, instance) {
  const fetches = Boolean(connector?.fetch)
  const exists = Boolean(instance)
  return [
    { id: 'connection', label: 'Connection', wide: false },
    takesKeys(connector) && { id: 'keys', label: 'Keys', wide: false },
    fetches && { id: 'fetch', label: 'Fetch', wide: false },
    fetches && exists && { id: 'classifier', label: 'Classifier', wide: true },
    (fetches || Boolean(connector?.mirror)) && exists && { id: 'mappers', label: 'Mappers', wide: true },
  ].filter(Boolean)
}
