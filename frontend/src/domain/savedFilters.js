/*
 * Saved filters of the incident list (GET /api/filters) as the screen reads
 * them: a filter is a name and what was on screen when it was saved (the
 * query, the order of the rows, the columns). A person has their own, sees
 * those an administrator shared with everyone, and chooses one as the filter
 * the list opens with.
 */
import { cleanSort, sameColumns, sameSort } from './incidentList.js'

export const NAME_MAX = 80

const list = (value) => (Array.isArray(value) ? value : [])
const byName = (a, b) => a.name.localeCompare(b.name, 'en', { sensitivity: 'base' })

/** The filters in the two groups of the menu: one's own, and those of others shared with everyone; by name. */
export function groupFilters(filters) {
  const all = list(filters)
  return {
    mine: all.filter((filter) => filter.mine).sort(byName),
    shared: all.filter((filter) => !filter.mine && filter.shared).sort(byName),
  }
}

/**
 * What choosing a filter puts on screen: its query, its sort, and its columns
 * when it keeps some (`null` leaves the person's own columns).
 */
export function filterView(filter) {
  return {
    query: String(filter?.query ?? ''),
    sort: cleanSort(filter?.sort),
    columns: list(filter?.columns).length > 0 ? [...filter.columns] : null,
  }
}

/**
 * Whether what is on screen is no longer what the chosen filter keeps: another
 * query, another order, or other columns than those it was saved with.
 */
export function isChanged(filter, { query, sort, columns }) {
  if (!filter) return false
  const kept = filterView(filter)
  if (kept.query.trim() !== String(query ?? '').trim()) return true
  if (!sameSort(kept.sort, sort)) return true
  return kept.columns !== null && !sameColumns(kept.columns, columns)
}

/** What is sent to save what is on screen (POST or PUT /api/filters). */
export function filterPayload({ name, query, sort, columns }) {
  return {
    ...(name === undefined ? {} : { name: String(name).trim() }),
    query: String(query ?? '').trim(),
    sort: cleanSort(sort),
    columns: list(columns),
  }
}

/** Why a name cannot be given to a filter of one's own (null when it can). `except` is the filter being renamed. */
export function nameProblem(name, filters, except = null) {
  const text = String(name ?? '').trim()
  if (!text) return 'A filter needs a name'
  if (text.length > NAME_MAX) return `A name is ${NAME_MAX} characters at most`
  const taken = list(filters).some(
    (filter) => filter.mine && filter.id !== except && filter.name.toLowerCase() === text.toLowerCase(),
  )
  return taken ? 'You have a filter with this name already' : null
}

/** What the button of the menu says: the name of the chosen filter, or that there is none. */
export const menuLabel = (filter) => (filter ? `Filter: ${filter.name}` : 'Filter: none')
