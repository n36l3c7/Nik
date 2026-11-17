/*
 * Lists (GET /api/lists) as Settings → Lists reads them: what a kind is
 * called, the items of a list as the text of a box and back, the rows of a
 * key → value list, and which lists a feature can be pointed at.
 */

export const LIST_KINDS = {
  values: { label: 'Values', hint: 'Items, one a line: domains, networks, names…' },
  key_value: { label: 'Keys and values', hint: 'Each item is a key with a value.' },
  json: { label: 'One document', hint: 'A single JSON document.' },
  indicators: { label: 'Indicators', hint: 'A list of the IoC library, changed where indicators are.' },
}

export const ITEM_TYPES = [
  { id: 'text', label: 'Text' },
  { id: 'domain', label: 'Domains' },
  { id: 'host', label: 'Hosts' },
  { id: 'cidr', label: 'Networks' },
  { id: 'ip', label: 'Addresses' },
  { id: 'email', label: 'E-mail addresses' },
  { id: 'user', label: 'Users' },
  { id: 'url', label: 'URLs' },
  { id: 'indicator', label: 'Indicators' },
  { id: 'keyword', label: 'Keywords' },
]

export const kindLabel = (kind) => LIST_KINDS[kind]?.label ?? kind

/** A name a list can have, from the label typed for it: "VIP users" gives "vip_users". */
export function nameFromLabel(label) {
  const out = String(label ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return (/^[a-z]/.test(out) ? out : out ? `list_${out}` : '').slice(0, 49)
}

/** Why a name cannot be the name of a new list (a sentence), or null. */
export function nameProblem(name, lists) {
  if (!/^[a-z][a-z0-9_]{1,48}$/.test(String(name ?? ''))) {
    return 'A lower-case letter, then letters, digits or _ (2 to 49 characters)'
  }
  return (lists ?? []).some((list) => list.name === name) ? 'There is a list with this name already' : null
}

/** How many items a list holds, in words. */
export function countText(list) {
  if (list?.kind === 'json') return 'a document'
  const count = list?.items ?? 0
  return `${count} item${count === 1 ? '' : 's'}`
}

/** The lists whose name, label or description hold what was typed. */
export function matching(lists, typed) {
  const wanted = String(typed ?? '')
    .trim()
    .toLowerCase()
  if (!wanted) return lists ?? []
  return (lists ?? []).filter((list) =>
    [list.name, list.label, list.description].some((text) =>
      String(text ?? '')
        .toLowerCase()
        .includes(wanted),
    ),
  )
}

/** The items of a list of values as the text of a box, one a line. */
export const entriesToText = (entries) => (entries ?? []).map((entry) => entry.key).join('\n')

/** What was typed in the box as the entries PUT …/items takes: one a line, in order, once each. */
export function textToEntries(text, before = []) {
  const notes = Object.fromEntries((before ?? []).map((entry) => [entry.key, entry.note]))
  const seen = new Set()
  const entries = []
  for (const line of String(text ?? '').split('\n')) {
    const key = line.trim()
    if (!key || seen.has(key)) continue
    seen.add(key)
    entries.push(notes[key] ? { key, note: notes[key] } : { key })
  }
  return entries
}

/** A value of a key → value list as the text of an input: a text as it is, anything else as JSON. */
export const valueToText = (value) =>
  value === null || value === undefined ? '' : typeof value === 'string' ? value : JSON.stringify(value)

/** What was typed for a value: JSON when it reads as JSON (an object, a list, a number…), else the text. */
export function textToValue(typed) {
  const text = String(typed ?? '').trim()
  if (!text) return ''
  if (/^[[{"]|^-?\d|^(true|false|null)$/.test(text)) {
    try {
      return JSON.parse(text)
    } catch {
      return text
    }
  }
  return text
}

/**
 * The rows of a key → value list as a form edits them:
 * `{ key, cells: { column: text }, value: text, note }`. A list with columns
 * edits each key of its value; one without edits the value whole.
 */
export function toRows(list) {
  const columns = list?.columns ?? []
  return (list?.entries ?? []).map((entry) => ({
    key: entry.key,
    note: entry.note ?? '',
    value: valueToText(entry.value),
    cells: Object.fromEntries(
      columns.map((column) => [
        column.name,
        valueToText(entry.value && typeof entry.value === 'object' ? entry.value[column.name] : ''),
      ]),
    ),
  }))
}

/** The entries PUT …/items takes, from the rows; rows with no key are left out. */
export function fromRows(list, rows) {
  const columns = list?.columns ?? []
  return (rows ?? [])
    .filter((row) => String(row.key ?? '').trim())
    .map((row) => ({
      key: String(row.key).trim(),
      note: row.note ?? '',
      value: columns.length
        ? Object.fromEntries(columns.map((column) => [column.name, row.cells?.[column.name] ?? '']))
        : textToValue(row.value),
    }))
}

/** Why the text of a document cannot be saved, or null. */
export function documentProblem(text) {
  try {
    JSON.parse(String(text ?? ''))
    return null
  } catch (failure) {
    return `Not valid JSON: ${failure.message}`
  }
}

/** The lists a feature can read: those of the kind it takes, Nik's own first. */
export function choosable(lists, pointer) {
  return (lists ?? [])
    .filter((list) => list.kind === pointer?.kind && !list.readOnly)
    .sort(
      (a, b) => Number(b.name === pointer.default) - Number(a.name === pointer.default) || a.name.localeCompare(b.name),
    )
}

/** The address of a list in Settings → Lists. */
export const listPath = (name) => `/settings/lists/all${name ? `?open=${encodeURIComponent(name)}` : ''}`

/** The list an address asks to open (`?open=`), or null. */
export function openFromSearch(search) {
  try {
    return new URLSearchParams(String(search ?? '')).get('open') || null
  } catch {
    return null
  }
}

/** What a file is, from its name: 'csv' | 'json' | null. */
export function fileFormat(name) {
  const lower = String(name ?? '').toLowerCase()
  if (lower.endsWith('.json')) return 'json'
  return lower.endsWith('.csv') || lower.endsWith('.txt') ? 'csv' : null
}
