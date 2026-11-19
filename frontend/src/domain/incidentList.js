/*
 * The list of incidents as a page (6.2): its address, its columns, the order
 * of its rows, and which row comes before and after another.
 *
 * A column is named by a key. The first ones are read from the light row of
 * the list (GET /api/incidents?view=summary); every other is a field of the
 * registry that applies to incidents, read from `row.fields`, which the list
 * asks for by name (`&fields=…`). What a person chooses is a list of keys in
 * order, remembered in this browser, and carried by a saved filter.
 */
import { formatValue } from './fields.js'
import { formatNumber, statusLabel } from './incidentName.js'

export const INCIDENTS_ROOT = '/incidents'

/** True for the address of the list of incidents. */
export const isIncidentsPath = (pathname) => /^\/incidents\/?$/.test(String(pathname ?? '').split('?')[0])

/** `kind` says how a column is ordered and drawn: 'number' | 'text' | 'severity' | 'status' | 'date'. */
export const LIST_COLUMNS = [
  { key: 'number', label: '#', name: 'Number', kind: 'number' },
  { key: 'name', label: 'Title', kind: 'text' },
  { key: 'type', label: 'Type', kind: 'text' },
  { key: 'severity', label: 'Severity', kind: 'severity' },
  { key: 'status', label: 'Status', kind: 'status' },
  { key: 'owner', label: 'Owner', kind: 'text' },
  { key: 'created', label: 'Opened', kind: 'date' },
  { key: 'modified', label: 'Updated', kind: 'date' },
  { key: 'host', label: 'Host', kind: 'text' },
  { key: 'username', label: 'User', kind: 'text' },
  { key: 'ticket', label: 'Ticket', kind: 'text' },
  { key: 'os', label: 'System', kind: 'text' },
  { key: 'source', label: 'Source', kind: 'text' },
]

export const DEFAULT_COLUMNS = ['number', 'name', 'type', 'severity', 'status', 'owner', 'created', 'modified']
export const DEFAULT_SORT = { key: 'modified', dir: 'desc' }
export const COLUMNS_MAX = 30
/** How many rows are drawn at first, and how many more each time more are asked for. */
export const PAGE_ROWS = 200

// Fields of the registry that are no column: what the list has no value for, and what a cell cannot hold.
const NOT_A_COLUMN = new Set(['id', 'source_instance', 'source_id', 'close_notes'])
const NOT_IN_A_CELL = new Set(['list', 'json', 'long_text'])
const SEVERITY_RANK = { low: 1, medium: 2, high: 3, critical: 4 }
const STATUS_RANK = { open: 1, in_progress: 2, closed: 3 }
const FIELD_KIND = { number: 'number', date: 'date' }

const list = (value) => (Array.isArray(value) ? value : [])

/**
 * Every column there is: those of the list, then the fields of the registry
 * that apply to incidents, by label. A field column carries its `field`.
 */
export function allColumns(fields) {
  const own = new Set(LIST_COLUMNS.map((column) => column.key))
  const extra = list(fields)
    .filter(
      (field) =>
        field?.name &&
        (field.appliesTo ?? 'incident') === 'incident' &&
        !own.has(field.name) &&
        !NOT_A_COLUMN.has(field.name) &&
        !NOT_IN_A_CELL.has(field.type),
    )
    .map((field) => ({
      key: field.name,
      label: field.label || field.name,
      kind: FIELD_KIND[field.type] ?? 'text',
      field,
    }))
    .sort((a, b) => a.label.localeCompare(b.label))
  return [...LIST_COLUMNS, ...extra]
}

/**
 * The keys a person chose as they can be shown: those that are columns, once
 * each, in their order; the default ones when that leaves nothing.
 */
export function cleanColumns(keys, columns) {
  const known = new Set(list(columns).map((column) => column.key))
  const kept = [...new Set(list(keys).filter((key) => typeof key === 'string' && known.has(key)))].slice(0, COLUMNS_MAX)
  return kept.length > 0 ? kept : DEFAULT_COLUMNS.filter((key) => known.has(key))
}

/** The chosen keys with one added at the end, or taken away. The last column stays: a table needs one. */
export function toggleColumn(keys, key) {
  const chosen = list(keys)
  if (!chosen.includes(key)) return chosen.length >= COLUMNS_MAX ? chosen : [...chosen, key]
  return chosen.length > 1 ? chosen.filter((item) => item !== key) : chosen
}

/** The chosen keys with one moved a place up (`by` -1) or down (+1). */
export function moveColumn(keys, key, by) {
  const chosen = [...list(keys)]
  const from = chosen.indexOf(key)
  const to = from + by
  if (from < 0 || to < 0 || to >= chosen.length) return chosen
  chosen.splice(from, 1)
  chosen.splice(to, 0, key)
  return chosen
}

/** The names of the registry fields among the chosen columns: what the list asks the server for. */
export function fieldNames(keys, columns) {
  const byKey = Object.fromEntries(list(columns).map((column) => [column.key, column]))
  return list(keys).filter((key) => byKey[key]?.field)
}

const sameList = (a, b) => a.length === b.length && a.every((item, index) => item === b[index])

/** Whether two choices of columns are the same columns in the same order. */
export const sameColumns = (a, b) => sameList(list(a), list(b))

/** A sort as it is kept: a key and a direction, or the order of the list itself. */
export function cleanSort(sort) {
  if (!sort || typeof sort.key !== 'string' || !sort.key) return DEFAULT_SORT
  return { key: sort.key, dir: sort.dir === 'asc' ? 'asc' : 'desc' }
}

export const sameSort = (a, b) => cleanSort(a).key === cleanSort(b).key && cleanSort(a).dir === cleanSort(b).dir

/**
 * The sort after a click on the heading of a column: the other direction on
 * the column that orders the list already; on another, the direction one
 * wants first (the latest, the most severe, the highest number; A to Z).
 */
export function nextSort(sort, column) {
  const current = cleanSort(sort)
  if (current.key === column.key) return { key: column.key, dir: current.dir === 'asc' ? 'desc' : 'asc' }
  return { key: column.key, dir: column.kind === 'text' ? 'asc' : 'desc' }
}

const typeName = (types, id) => list(types).find((type) => type.id === id)?.name ?? ''

/** The date and the time of a moment as a cell shows them (`2026-11-19 09:14`, local), '' for none. */
export function shortDateTime(iso) {
  const ms = Date.parse(iso)
  if (!Number.isFinite(ms)) return ''
  const at = new Date(ms)
  const two = (value) => String(value).padStart(2, '0')
  return `${at.getFullYear()}-${two(at.getMonth() + 1)}-${two(at.getDate())} ${two(at.getHours())}:${two(at.getMinutes())}`
}

/** What a cell says, as text ('' for nothing). The table draws some of them as tags. */
export function cellText(row, column, { types = [] } = {}) {
  switch (column?.key) {
    case 'number':
      return formatNumber(row.number)
    case 'name':
      return row.name ?? ''
    case 'type':
      return typeName(types, row.type)
    case 'severity':
      return row.severity ?? ''
    case 'status':
      return statusLabel(row.status)
    case 'owner':
      return row.assignee ?? ''
    case 'created':
      return shortDateTime(row.createdAt)
    case 'modified':
      return shortDateTime(row.updatedAt)
    case 'host':
      return row.host ?? ''
    case 'username':
      return row.username ?? ''
    case 'ticket':
      return row.ticketId ?? ''
    case 'os':
      return row.os ?? ''
    case 'source':
      return row.source?.connection ?? ''
    default:
      return column?.field ? formatValue(column.field, row.fields?.[column.key]) : ''
  }
}

/** What a column orders its rows by: a number where there is one, a text otherwise; null for nothing. */
function sortValue(row, column, context) {
  switch (column.key) {
    case 'number':
      return Number.isInteger(row.number) ? row.number : null
    case 'severity':
      return SEVERITY_RANK[row.severity] ?? null
    case 'status':
      return STATUS_RANK[row.status] ?? STATUS_RANK.open
    case 'created':
    case 'modified': {
      const ms = Date.parse(column.key === 'created' ? row.createdAt : row.updatedAt)
      return Number.isFinite(ms) ? ms : null
    }
    default:
      break
  }
  if (column.field) {
    const value = row.fields?.[column.key]
    if (column.kind === 'number')
      return Number.isFinite(Number(value)) && value !== null && value !== '' ? Number(value) : null
    if (column.kind === 'date') {
      const ms = Date.parse(value)
      return Number.isFinite(ms) ? ms : null
    }
    if (column.field.type === 'bool') return value === true ? 1 : value === false ? 0 : null
  }
  const text = cellText(row, column, context)
  return text === '' ? null : text
}

const collator = new Intl.Collator('en', { sensitivity: 'base', numeric: true })
const latestFirst = (a, b) => String(b.updatedAt ?? '').localeCompare(String(a.updatedAt ?? ''))

/**
 * The rows in the order a sort gives them. A row with nothing in the column
 * comes last whichever the direction; rows that are equal stay with the one
 * changed last first. A sort on a column that is not there orders by the
 * last change.
 */
export function sortIncidents(rows, sort, columns, context = {}) {
  const { key, dir } = cleanSort(sort)
  const column = list(columns).find((item) => item.key === key) ?? LIST_COLUMNS.find((item) => item.key === 'modified')
  const sign = dir === 'asc' ? 1 : -1
  return list(rows)
    .map((row) => ({ row, value: sortValue(row, column, context) }))
    .sort((a, b) => {
      if (a.value === null || b.value === null) {
        if (a.value === b.value) return latestFirst(a.row, b.row)
        return a.value === null ? 1 : -1
      }
      const order =
        typeof a.value === 'number' && typeof b.value === 'number'
          ? a.value - b.value
          : collator.compare(String(a.value), String(b.value))
      return order !== 0 ? sign * order : latestFirst(a.row, b.row)
    })
    .map((item) => item.row)
}

/**
 * The id of the row `step` rows after (or before) the one with `id`, staying
 * on the first and the last. With no row of that id: the first one.
 */
export function neighbour(ids, id, step) {
  const all = list(ids)
  if (all.length === 0) return null
  const at = all.indexOf(id)
  if (at < 0) return all[0]
  return all[Math.max(0, Math.min(all.length - 1, at + step))]
}

// --------------------------------------------------------------------------- //
// What a person chose, remembered in this browser                             //
// --------------------------------------------------------------------------- //
export const COLUMNS_KEY = 'nik.incidents.columns'

/** The columns remembered here, or null (nothing was chosen, or the browser refuses storage). */
export function readColumns(storage) {
  try {
    const kept = JSON.parse(storage.getItem(COLUMNS_KEY) ?? 'null')
    return Array.isArray(kept) && kept.every((key) => typeof key === 'string') && kept.length > 0 ? kept : null
  } catch {
    return null
  }
}

/** Remember the columns; `null` forgets them (the default ones are shown again). */
export function writeColumns(storage, keys) {
  try {
    if (keys === null) storage.removeItem(COLUMNS_KEY)
    else storage.setItem(COLUMNS_KEY, JSON.stringify(list(keys)))
  } catch {
    // The choice still applies to this visit.
  }
}
