/*
 * The rules of a table whose rows come from the server in pages (components/ui/ServerTable.jsx).
 * The server pages by cursor: a page knows only where the next one starts, so the table keeps the
 * cursors of the pages it left (a stack) to go back, and never asks for the last page.
 */

import { formatDateTime } from '../lib/time.js'

export const PAGE_SIZES = [25, 50, 100, 200]
export const DEFAULT_PAGE_SIZE = 50
// Where the server stops counting (browse.COUNT_CAP is 100001): a count that reached it is "100,000+".
export const COUNT_SHOWN_CAP = 100000

const number = (n) => n.toLocaleString('en-US')

/** "1–50 of 2,418", "51–100 of 100,000+", "1–50" when the count is not known, "No records" for none. */
export function rangeText({ offset, shown, total = null, capped = false }) {
  if (shown === 0) return 'No records'
  const from = offset + 1
  const to = offset + shown
  const range = `${number(from)}–${number(to)}`
  if (total === null || total === undefined) return range
  return `${range} of ${capped ? `${number(COUNT_SHOWN_CAP)}+` : number(total)}`
}

/** The cursor to ask for: the last one of the stack, '' for the first page. */
export const cursorOf = (stack) => (stack.length ? stack[stack.length - 1] : '')

/** The stack after going to the next page (`next` is the cursor the last page gave). */
export const forward = (stack, next) => (next ? [...stack, next] : stack)

/** The stack after going back one page. */
export const back = (stack) => stack.slice(0, -1)

/** Where the page starts in the whole list: the pages before it are full. */
export const offsetOf = (stack, pageSize) => stack.length * pageSize

/** Filters that say something: what is empty (null, '', false) is not a filter. */
export function activeFilters(filters = {}) {
  const kept = {}
  for (const [name, value] of Object.entries(filters ?? {})) {
    if (value !== undefined && value !== null && value !== '' && value !== false) kept[name] = value
  }
  return kept
}

/** A key that changes when what the list asks for changes: a new key means page one. */
export const queryKey = (filters, order, pageSize) => JSON.stringify([activeFilters(filters), order, pageSize])

/** The filters with one set (or cleared when the value is empty). */
export function withFilter(filters, name, value) {
  return activeFilters({ ...filters, [name]: value })
}

/** The filters without `name`. */
export function withoutFilter(filters, name) {
  const { [name]: _gone, ...rest } = filters ?? {}
  return activeFilters(rest)
}

/** The text of a filter's value in its chip: a time range end is a date and time, never raw milliseconds. */
function valueText(name, value) {
  if ((name === 'from' || name === 'to') && Number.isFinite(Number(value))) return formatDateTime(Number(value))
  return String(value)
}

/**
 * The chips of the filters in force, except the search (`q` has its own box): `{ name, names, label, text }`,
 * the label being the one of the column that can be filtered by that name. `names` are the filters the chip
 * removes: `dataKey` and `dataValue` are one chip, "key = value". The text of a value comes from, in order,
 * `chipLabel(name, value)` (the caller's), the `chipLabel(value)` of the column, then the default; a
 * formatter that answers nothing leaves the default.
 */
export function filterChips(filters, columns = [], chipLabel = null) {
  const byKey = new Map(columns.filter((column) => column.filterKey).map((column) => [column.filterKey, column]))
  const active = activeFilters(filters)
  return Object.entries(active)
    .filter(([name]) => name !== 'q' && name !== 'dataValue')
    .map(([name, value]) => {
      if (name === 'dataKey') {
        return {
          name,
          names: ['dataKey', 'dataValue'],
          label: String(value),
          text: `${value} = ${active.dataValue ?? ''}`,
        }
      }
      const column = byKey.get(name)
      const label = column?.label ?? name
      const shown = chipLabel?.(name, value) ?? column?.chipLabel?.(value) ?? valueText(name, value)
      const text = value === true ? label : `${label} = ${shown}`
      return { name, names: [name], label, text }
    })
}

/** The other way round of the order a column sorts by: `time` and `-time`. */
export const reverseOrder = (order) => (order.startsWith('-') ? order.slice(1) : `-${order}`)

/**
 * The order a click on the Sort of a column asks for: its own order, or the reverse of it when it is the
 * one in force (unless the column says it has no reverse: `reverse: false`).
 */
export function nextOrder(current, column) {
  if (!column?.order) return current
  if (current === column.order && column.reverse !== false) return reverseOrder(column.order)
  return column.order
}

/** The direction the header of a column shows: 'asc', 'desc' or null when the list is not sorted by it. */
export function directionOf(current, column) {
  if (!column?.order) return null
  if (current === column.order) return 'asc'
  if (column.reverse !== false && current === reverseOrder(column.order)) return 'desc'
  return null
}

/** The columns that are shown: those the person did not hide (only a `hideable` one can be). */
export function visibleColumns(columns, hidden) {
  const gone = new Set(hidden)
  return columns.filter((column) => !(column.hideable && gone.has(column.key)))
}

/** What was stored under a table's key, read defensively: `{ hidden, pageSize }`. */
export function readSettings(raw, columns = []) {
  const known = new Set(columns.filter((column) => column.hideable).map((column) => column.key))
  let parsed
  try {
    parsed = JSON.parse(raw)
  } catch {
    // Nothing stored, or something else wrote there: the defaults.
  }
  // Nothing stored yet: the columns that say `hiddenByDefault` start hidden (the Columns menu shows them).
  const hidden = Array.isArray(parsed?.hidden)
    ? parsed.hidden.filter((key) => known.has(key))
    : columns.filter((column) => column.hideable && column.hiddenByDefault).map((column) => column.key)
  const pageSize = PAGE_SIZES.includes(parsed?.pageSize) ? parsed.pageSize : DEFAULT_PAGE_SIZE
  return { hidden, pageSize }
}

/** The text a cell holds, for "Filter on a value": null when there is none worth filtering on. */
export function cellValue(column, row) {
  const value = column.value ? column.value(row) : row?.[column.key]
  if (value === undefined || value === null || value === '' || typeof value === 'object') return null
  return value
}
