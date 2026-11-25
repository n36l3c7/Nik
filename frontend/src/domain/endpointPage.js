/*
 * What the Endpoint Artifacts page works out from the categories of config/artifacts.js and from the
 * server's answers (sources, stack of `source`): the selector with its counts, the expected sources of
 * the incident's system, the filter of a category, its columns and the filters of the stat cards. The
 * worker names a source `<os>.<category>.<id>` and gives each record the `id` as its `type`
 * (workers/forensics/.../endpoint.py); the fields of a record are in its `data`.
 */

import { activeFilters } from './serverTable.js'

export const ENDPOINT_KIND = 'endpoint'
/** The selector item of the files whose source names no category (imported before 7.0). */
export const OTHER = 'other'

const LANGUAGES = { powershell: 'PowerShell', bash: 'Bash' }

/*
 * The columns of a category: each is a key of the record's `data` as the worker writes it (asked for
 * with `fields`). `mono`: monospaced; `align`: the side of the text.
 */
export const ENDPOINT_COLUMNS = {
  execution: [
    { key: 'name', label: 'Executable', mono: true },
    { key: 'path', label: 'Path', mono: true },
    { key: 'runCount', label: 'Runs', align: 'right' },
    { key: 'source', label: 'Artifact' },
  ],
  persistence: [
    { key: 'name', label: 'Name' },
    { key: 'kind', label: 'Type' },
    { key: 'command', label: 'Command / Target', mono: true },
    { key: 'location', label: 'Location', mono: true },
  ],
  fileaccess: [
    { key: 'name', label: 'Item' },
    { key: 'target', label: 'Target path', mono: true },
    { key: 'kind', label: 'Evidence' },
  ],
  usb: [
    { key: 'device', label: 'Device' },
    { key: 'serial', label: 'Serial', mono: true },
    { key: 'vendor', label: 'Vendor / Product' },
    { key: 'connection', label: 'Event' },
  ],
}

/** The columns of a category (none for "Other": its table shows the worker's summary). */
export const columnsOf = (categoryId) => ENDPOINT_COLUMNS[categoryId] ?? []

/** The keys of `data` to ask the server for with `fields`. */
export const fieldsOf = (categoryId) => columnsOf(categoryId).map((column) => column.key)

/** What a record holds under a key of its `data` ('' when it has none). */
export function dataOf(row, key) {
  const value = row?.data?.[key]
  return value === undefined || value === null ? '' : String(value)
}

/** The first part of the `source` the worker gives the files of a category on a system. */
export const sourcePrefix = (os, categoryId) => `${os}.${categoryId}.`

/** The id of a source inside its category (`windows.persistence.runkeys` -> `runkeys`), or null for another category. */
export function sourceKeyOf(source, os, categoryId) {
  const text = source?.source ?? ''
  const prefix = sourcePrefix(os, categoryId)
  return text.startsWith(prefix) && text.length > prefix.length ? text.slice(prefix.length) : null
}

/** The category a source name belongs to on this system, or OTHER when it names none. */
export function categoryOfSource(name, os, categories = []) {
  const found = categories.find((category) => sourceKeyOf({ source: name }, os, category.id) !== null)
  return found ? found.id : OTHER
}

/** The sources of the section that no category of this system claims. */
export const otherSources = (sources = [], os, categories = []) =>
  sources.filter((source) => categoryOfSource(source.source, os, categories) === OTHER)

/** What SourceFiles needs as `expected`: a grey row per source of the system, with where to find the file. */
export function expectedSources(category, os) {
  return (category.sources?.[os] ?? []).map((source) => ({
    key: source.key,
    label: source.name,
    hint:
      source.mode === 'script'
        ? `collection script (${LANGUAGES[source.script?.lang] ?? 'script'})`
        : source.path || source.tool || '',
  }))
}

/** The selector items that have a source read in part that nobody looked at (category ids, OTHER too). */
export function partialCategories(sources = [], os, categories = []) {
  const partial = new Set()
  for (const source of sources) {
    if (source.read !== 'partial' || source.seen || source.state === 'absent') continue
    partial.add(categoryOfSource(source.source, os, categories))
  }
  return partial
}

/** `{ source name: count }` from the values of a stack of `source`. */
export function countsBySource(values = []) {
  return Object.fromEntries(values.map((item) => [item.value, item.count]))
}

/** The records of each category (and of OTHER), from the counts by source name. */
export function categoryTotals(categories, os, counts = {}) {
  const totals = { [OTHER]: 0 }
  for (const category of categories) totals[category.id] = 0
  for (const [name, n] of Object.entries(counts)) totals[categoryOfSource(name, os, categories)] += n
  return totals
}

/** The items of the category selector: label, count, the yellow dot, and "Other" only when a file is in it. */
export function categoryItems(categories, totals, partial, hasOther) {
  const items = categories.map((category) => ({
    id: category.id,
    label: category.label,
    count: totals[category.id] ?? 0,
    partial: partial.has(category.id),
  }))
  if (hasOther)
    items.push({
      id: OTHER,
      label: 'Other',
      count: totals[OTHER] ?? 0,
      partial: partial.has(OTHER),
    })
  return items
}

const number = (n) => n.toLocaleString('en-US')

/**
 * The options of the "Source" select of a category: all of it, then each source of the system (with the
 * records it has, none included) and any other source found under the category's prefix.
 */
export function sourceOptions(category, os, counts = {}) {
  const prefix = sourcePrefix(os, category.id)
  const names = new Map((category.sources?.[os] ?? []).map((source) => [`${prefix}${source.key}`, source.name]))
  let all = 0
  for (const [name, n] of Object.entries(counts)) {
    if (!name.startsWith(prefix) || name.length === prefix.length) continue
    all += n
    if (!names.has(name)) names.set(name, name.slice(prefix.length))
  }
  return [
    { value: '', label: `all (${number(all)})` },
    ...[...names].map(([name, label]) => ({
      value: name,
      label: `${label} (${number(counts[name] ?? 0)})`,
    })),
  ]
}

/** The options of the "Source" select of OTHER: the source names that hold no category. */
export const otherOptions = (names = [], counts = {}) =>
  names.map((name) => ({
    value: name,
    label: `${name} (${number(counts[name] ?? 0)})`,
  }))

/** The source filter of the table: one source when chosen, else every source under the category's prefix. */
export const sourceFilter = (prefix, chosen) => (chosen ? { source: chosen } : { sourcePrefix: prefix })

/** The three counts of the stat cards are asked with these filters: all, the ones with a time, the flagged. */
export function statFilters(base = {}) {
  return {
    entries: activeFilters(base),
    timed: activeFilters({ ...base, dated: true }),
    flagged: activeFilters({ ...base, flagged: true }),
  }
}

/** The filters with one key of `data` set to a value (the two names of the API go together). */
export const withData = (filters, key, value) => ({
  ...filters,
  dataKey: key,
  dataValue: String(value),
})

/** The filters without the key of `data` that was set. */
export function withoutData(filters) {
  const { dataKey: _key, dataValue: _value, ...rest } = filters ?? {}
  return rest
}

/** The text of the chip of a `data` filter: "<column label> = <value>" ('' when none is in force). */
export function dataChip(filters, columns = []) {
  if (!filters?.dataKey) return ''
  const label = columns.find((column) => column.key === filters.dataKey)?.label ?? filters.dataKey
  return `${label} = ${filters.dataValue}`
}

/** The incident's suspicious window as `{ from, to }` (null when it has none). */
export function incidentRange(incident) {
  const from = incident?.suspiciousStart ?? null
  const to = incident?.suspiciousEnd ?? null
  return from === null && to === null ? null : { from, to }
}
