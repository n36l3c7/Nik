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
