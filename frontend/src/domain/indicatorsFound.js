/*
 * Indicators found by themselves when an incident comes in: the form of the
 * setting (Settings, Indicators found) and the words of what a reading gave.
 * The reading itself is the server's (app/indicators_found.py).
 */

export const TYPE_LABELS = {
  ip: 'IP addresses',
  domain: 'Domains',
  url: 'URLs',
  email: 'E-mail addresses',
  md5: 'MD5',
  sha1: 'SHA-1',
  sha256: 'SHA-256',
}

/** The setting as the form edits it: the paths one a line, the limit as text while it is typed. */
export function formOf(settings) {
  return {
    enabled: Boolean(settings.enabled),
    types: [...(settings.types ?? [])],
    leaveOutPrivate: Boolean(settings.leaveOutPrivate),
    leaveOutBenign: Boolean(settings.leaveOutBenign),
    cap: String(settings.cap ?? ''),
    skip: (settings.skip ?? []).join('\n'),
    lookUps: Boolean(settings.lookUps),
  }
}

/** The paths of the form as a list: one a line, without the empty ones and the repeats. */
export function skipLines(text) {
  const seen = []
  for (const line of String(text ?? '').split('\n')) {
    const entry = line.trim()
    if (entry && !seen.includes(entry)) seen.push(entry)
  }
  return seen
}

/** What the form cannot be saved with: `{ cap?, skip?, types? }`, a sentence each. */
export function problemsOf(form, settings) {
  const problems = {}
  const max = settings.capMax ?? 500
  if (!/^\d+$/.test(form.cap.trim()) || Number(form.cap) < 1 || Number(form.cap) > max) {
    problems.cap = `A whole number from 1 to ${max}`
  }
  const lines = skipLines(form.skip)
  const wrong = lines.find((line) => /\s/.test(line) || line.length > 200)
  if (wrong)
    problems.skip = `"${wrong.slice(0, 40)}" is not a path: a key or a path with dots, * for anything, no spaces`
  else if (lines.length > 100) problems.skip = 'A hundred paths at most'
  if (form.enabled && form.types.length === 0)
    problems.types = 'With no type chosen nothing would be found: turn it off instead'
  return problems
}

const same = (a, b) => a.length === b.length && a.every((item, index) => item === b[index])

/** What the form changes of the setting, as the body of the request (empty when nothing). */
export function changesOf(form, settings) {
  const changes = {}
  for (const name of ['enabled', 'leaveOutPrivate', 'leaveOutBenign', 'lookUps']) {
    if (form[name] !== Boolean(settings[name])) changes[name] = form[name]
  }
  const types = (settings.allTypes ?? Object.keys(TYPE_LABELS)).filter((type) => form.types.includes(type))
  if (!same(types, settings.types ?? [])) changes.types = types
  if (/^\d+$/.test(form.cap.trim()) && Number(form.cap) !== settings.cap) changes.cap = Number(form.cap)
  const skip = skipLines(form.skip)
  if (!same(skip, settings.skip ?? [])) changes.skip = skip
  return changes
}

/** The path a found indicator was read at, from a source of the index (`found:<path>`), or null. */
export const foundPath = (source) => (String(source ?? '').startsWith('found:') ? String(source).slice(6) : null)

/** Whether an indicator of an incident is there because it was found by itself, and by nothing else. */
export const onlyFound = (sources) => (sources ?? []).length > 0 && (sources ?? []).every((source) => foundPath(source))

const DOORS = {
  fetch: 'when it was fetched',
  api: 'when it was made through the API',
  hand: 'when it was made',
  playbook: 'when a playbook made it',
  mirror: 'at an update from the other system',
  asked: 'when someone asked',
}

/** "when it was fetched", "at an update from the other system"… */
export const doorWords = (door) => DOORS[door] ?? ''

/** What the last reading of an incident came to, in a sentence; "" when it was never read. */
export function scanWords(scan, on) {
  if (!scan) {
    return on
      ? 'This incident was never read for indicators: it came in before incidents were read.'
      : 'Incidents from where this one came are not read for indicators.'
  }
  const left = Object.values(scan.leftOut ?? {}).reduce((sum, count) => sum + count, 0)
  const parts = [`${scan.kept} kept`]
  if (left) parts.push(`${left} left out as private or benign`)
  if (scan.over) parts.push(`${scan.over} over the limit of ${scan.cap} and not kept`)
  if (scan.removed) parts.push(`${scan.removed} removed by a person and not found again`)
  if (scan.unread) parts.push(`${scan.unread} values not read`)
  return `Last read ${doorWords(scan.door) || 'once'}: ${parts.join(', ')}.`
}

/** What an instance says of its own incidents: "on", "off" or "setting" (it follows the setting). */
export const instanceChoice = (enabled) => (enabled === true ? 'on' : enabled === false ? 'off' : 'setting')
export const choiceValue = (choice) => (choice === 'on' ? true : choice === 'off' ? false : null)

/**
 * The instances told apart from the setting, by name: `[{ id, name, read }]`. `said` is what the
 * setting holds (`{ id: true | false }`), `fetching` the instances that fetch as GET /api/fetch
 * lists them; one that is not listed there (it cannot be seen, or fetches no more) keeps its id.
 */
export function toldApart(said, fetching) {
  const names = new Map((fetching ?? []).map((instance) => [instance.instanceId, instance.connection]))
  return Object.entries(said ?? {})
    .map(([id, read]) => ({ id, name: names.get(id) || id, read: Boolean(read) }))
    .sort((a, b) => a.name.localeCompare(b.name))
}
