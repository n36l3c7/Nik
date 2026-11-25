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
 * The columns of a category: each is a key of the record's `data` as the worker writes it (asked for with
 * `fields`, twelve at most). A category is fed by several sources whose records name the same thing differently
 * (a prefetch file's `executable`, an Amcache entry's `name`): `also` lists the other keys a column reads when the
 * first is empty, and `join` shows the keys together ("vendor product"). `mono`: monospaced; `align`: the side of
 * the text; `bytes`: a size, shown as "4.2 MB".
 */
export const ENDPOINT_COLUMNS = {
  execution: [
    { key: 'name', also: ['executable'], label: 'Executable', mono: true },
    { key: 'path', also: ['executable_path'], label: 'Path', mono: true },
    { key: 'runCount', also: ['run_count'], label: 'Runs', align: 'right' },
    { key: 'sha1', label: 'SHA-1', mono: true },
    { key: 'source', label: 'Artifact' },
    { key: 'ts_is', label: 'Time is' },
  ],
  persistence: [
    { key: 'name', label: 'Name' },
    { key: 'kind', also: ['type_label'], label: 'Type' },
    { key: 'command', also: ['image_path', 'service_dll'], label: 'Command / Target', mono: true },
    { key: 'location', also: ['start_label'], label: 'Location', mono: true },
    { key: 'ts_is', label: 'Time is' },
  ],
  fileaccess: [
    { key: 'name', also: ['app_name'], label: 'Item' },
    { key: 'target', also: ['path'], label: 'Target path', mono: true },
    { key: 'kind', also: ['jumplist', 'drive_type'], label: 'Evidence' },
    { key: 'ts_is', label: 'Time is' },
  ],
  usb: [
    { key: 'device', also: ['friendly_name', 'drive_letter'], label: 'Device' },
    { key: 'serial', label: 'Serial', mono: true },
    { key: 'vendor', join: ['product'], label: 'Vendor / Product' },
    { key: 'connection', label: 'Event' },
    { key: 'ts_is', label: 'Time is' },
  ],
  network: [
    { key: 'app', label: 'Application', mono: true },
    { key: 'user', label: 'User' },
    { key: 'interface_type', label: 'Interface', align: 'right' },
    { key: 'bytes_sent', label: 'Sent', align: 'right', bytes: true },
    { key: 'bytes_received', label: 'Received', align: 'right', bytes: true },
    { key: 'bytes_total', label: 'Total', align: 'right', bytes: true },
    { key: 'foreground_bytes_read', label: 'Read', align: 'right', bytes: true },
    { key: 'foreground_bytes_written', label: 'Written', align: 'right', bytes: true },
  ],
}

/** The columns of a category (none for "Other": its table shows the worker's summary). */
export const columnsOf = (categoryId) => ENDPOINT_COLUMNS[categoryId] ?? []

/** Every key a column reads. */
export const keysOf = (column) => [column.key, ...(column.also ?? []), ...(column.join ?? [])]

/** The keys of `data` to ask the server for with `fields` (distinct, in column order). */
export const fieldsOf = (categoryId) => [...new Set(columnsOf(categoryId).flatMap(keysOf))]

/** What a record holds under a key of its `data` ('' when it has none). */
export function dataOf(row, key) {
  const value = row?.data?.[key]
  return value === undefined || value === null ? '' : String(value)
}

/**
 * What a row shows under a column: the first of its keys that holds something (the others it `join`s after it,
 * with a space); a size as text for a `bytes` column. '' when the record has none.
 */
export function valueOf(row, column, sizeText = (n) => String(n)) {
  const first = [column.key, ...(column.also ?? [])].map((key) => dataOf(row, key)).find((text) => text !== '') ?? ''
  if (column.bytes) return first === '' || !Number.isFinite(Number(first)) ? first : sizeText(Number(first))
  if (!column.join) return first
  return [first, ...column.join.map((key) => dataOf(row, key))].filter(Boolean).join(' ')
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

/*
 * A registry hive and SRUDB.dat are ONE file that gives several sources: their row of the list has the source of
 * the file (`windows.registry.hive`, `windows.network.srum-*`) and each record says its own. `gave` is
 * `{ file id: [source names of its records] }` (the stack of `source` of each such file): it says in which
 * categories the file shows, and what it is called.
 */
const HIVE_FILE = 'windows.registry.hive'
const SRUM_PREFIX = 'windows.network.srum-'

/** Whether a file's source is one that fills several (a hive, SRUDB.dat). */
export const isMultiSource = (name) => name === HIVE_FILE || String(name ?? '').startsWith(SRUM_PREFIX)

/** The categories a file of the section is shown in: those of the sources it gave, else its own. */
export function categoriesOfFile(file, os, categories = [], gave = {}) {
  if (isMultiSource(file.source)) {
    const found = new Set((gave[file.id] ?? []).map((name) => categoryOfSource(name, os, categories)))
    found.delete(OTHER)
    return found.size > 0 ? [...found] : [OTHER]
  }
  return [categoryOfSource(file.source, os, categories)]
}

/** The sources of the section that no category of this system claims (a hive that gave records is in its categories). */
export const otherSources = (sources = [], os, categories = [], gave = {}) =>
  sources.filter((source) => categoriesOfFile(source, os, categories, gave).includes(OTHER))

/** The name of a source on a system (`windows.usb.usbstor-hive` -> "USBSTOR (hive)"), or the name itself. */
export function sourceLabelOf(name, os, categories = []) {
  for (const category of categories) {
    const prefix = sourcePrefix(os, category.id)
    if (!String(name).startsWith(prefix)) continue
    const found = (category.sources?.[os] ?? []).find((source) => `${prefix}${source.key}` === name)
    if (found) return found.name
  }
  return String(name)
}

/** What the Source column says of a file that gave several sources: "Run keys (hive), ShimCache"; '' for any other. */
export function labelOfFile(file, os, categories = [], gave = {}) {
  if (!isMultiSource(file.source)) return ''
  const names = gave[file.id] ?? []
  if (names.length === 0) return file.source === HIVE_FILE ? 'Registry hive' : 'SRUDB.dat'
  return names.map((name) => sourceLabelOf(name, os, categories)).join(', ')
}

/** The hint of a source on the grey row: where its file is, or how a hive or SRUDB.dat gives it. */
export function hintOf(source) {
  if (source.mode === 'script') return `collection script (${LANGUAGES[source.script?.lang] ?? 'script'})`
  if (source.via === 'hive') return `from a registry hive: ${source.path}`
  if (source.via === 'srudb') return `from SRUDB.dat: ${source.path}`
  return source.path || source.tool || ''
}

/** What SourceFiles needs as `expected`: a grey row per source of the system, with where to find the file. */
export function expectedSources(category, os) {
  return (category.sources?.[os] ?? []).map((source) => ({
    key: source.key,
    label: source.name,
    hint: hintOf(source),
  }))
}

/**
 * The keys of the sources that come out of a hive or SRUDB.dat and have records: their grey row is satisfied by
 * the records, not by a file of that name. `counts` is `{ source name: records }`.
 */
export function presentKeys(category, os, counts = {}) {
  const prefix = sourcePrefix(os, category.id)
  return (category.sources?.[os] ?? [])
    .filter((source) => source.via && (counts[`${prefix}${source.key}`] ?? 0) > 0)
    .map((source) => source.key)
}

/**
 * The choices of "Add files as": each source that has a file of its own, then the hive and SRUDB.dat the
 * category's other sources come from. `source` is the whole name the file is sent as (`hiveSource`/`srumSource`
 * are the file-level names of config/artifacts.js).
 */
export function addOptions(category, os, { hiveSource, hiveLabel, srumSource, srumLabel }) {
  const prefix = sourcePrefix(os, category.id)
  const own = category.sources?.[os] ?? []
  const options = own
    .filter((source) => !source.via)
    .map((source) => ({ key: source.key, label: source.name, source: `${prefix}${source.key}` }))
  if (own.some((source) => source.via === 'hive')) options.push({ key: 'hive', label: hiveLabel, source: hiveSource })
  if (own.some((source) => source.via === 'srudb')) options.push({ key: 'srudb', label: srumLabel, source: srumSource })
  return options
}

/** The title of the Time column: the source's own when only that source is shown ("File modified" for ShimCache). */
export function timeLabelOf(category, os, chosen) {
  const prefix = sourcePrefix(os, category.id)
  const found = (category.sources?.[os] ?? []).find((source) => `${prefix}${source.key}` === chosen)
  return found?.timeLabel ?? 'Time'
}

/** The notes of the sources of a category that have records ("ShimCache: the time is not an execution time"). */
export function notesOf(category, os, counts = {}) {
  const prefix = sourcePrefix(os, category.id)
  return (category.sources?.[os] ?? [])
    .filter((source) => source.note && (counts[`${prefix}${source.key}`] ?? 0) > 0)
    .map((source) => source.note)
}

/** The selector items that have a source read in part that nobody looked at (category ids, OTHER too). */
export function partialCategories(sources = [], os, categories = [], gave = {}) {
  const partial = new Set()
  for (const source of sources) {
    if (source.read !== 'partial' || source.seen || source.state === 'absent') continue
    for (const id of categoriesOfFile(source, os, categories, gave)) partial.add(id)
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
