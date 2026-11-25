/*
 * What the Browser Forensics page says about the files and records the server holds (7.0). A browser
 * file is a source of kind `browser` whose `source` is `<browser>.<part>` (`chrome.history`,
 * `firefox.places`, `safari.downloads`) and whose `profile` is the folder it came from. Records are
 * `visit`, `download`, `search`, `bookmark` and `shortcut` (workers/forensics/.../parsers/browser.py).
 */

import { BROWSERS, sourcePathFor } from '../config/browsers.js'
import { defang } from './iocs.js'

export const DEFAULT_PROFILE = 'Default'
export const PROFILE_NAME_MAX = 120

/** The record types of each section. */
export const SECTION_TYPES = {
  events: ['visit', 'download', 'search'],
  bookmarks: ['bookmark'],
  shortcuts: ['shortcut'],
}
export const SECTIONS = [
  { id: 'events', label: 'Events' },
  { id: 'bookmarks', label: 'Bookmarks' },
  { id: 'shortcuts', label: 'Shortcuts' },
]
export const TYPE_LABELS = {
  visit: 'visit',
  download: 'download',
  search: 'search',
  bookmark: 'bookmark',
  shortcut: 'shortcut',
}

const number = (n) => n.toLocaleString('en-US')

/** The browser a source belongs to (`chrome`), or '' when it does not say. */
export const browserOf = (source) => String(source?.source ?? '').split('.')[0]
/** What the file is of that browser (`history`), or ''. */
export const partOf = (source) => String(source?.source ?? '').split('.')[1] ?? ''
export const profileOf = (source) => source?.profile || DEFAULT_PROFILE

/** The sources of the browser section. */
export const browserSources = (sources = []) => sources.filter((source) => source.kind === 'browser')

/** Records kept by these sources, and whether one of them was read in part and nobody looked at it. */
export function countsOf(sources = []) {
  let count = 0
  let partial = false
  for (const source of sources) {
    count += source.kept ?? 0
    if (source.state === 'done' && source.read === 'partial' && !source.seen) partial = true
  }
  return { count, partial }
}

/** The tabs of the browser selector, with the records each holds and the yellow dot. */
export function browserItems(sources = []) {
  const held = browserSources(sources)
  return BROWSERS.map((browser) => {
    const { count, partial } = countsOf(held.filter((source) => browserOf(source) === browser.id))
    return { id: browser.id, label: browser.label, count, partial }
  })
}

/** Whether a file is one of a browser's and a profile's. */
export const inScope = (source, browserId, profile) =>
  source.kind === 'browser' && browserOf(source) === browserId && profileOf(source) === profile

/** The files of a browser and a profile. */
export const scopedSources = (sources = [], browserId, profile) =>
  sources.filter((source) => inScope(source, browserId, profile))

const byName = (a, b) => a.localeCompare(b, 'en', { sensitivity: 'base' })

/** The profile names a browser has: those of its files and the ones added and not filled yet, Default first. */
export function profileNames(sources = [], browserId, added = []) {
  const names = new Set(added)
  for (const source of browserSources(sources)) {
    if (browserOf(source) === browserId) names.add(profileOf(source))
  }
  if (names.size === 0) names.add(DEFAULT_PROFILE)
  return [...names].sort((a, b) => (a === DEFAULT_PROFILE ? -1 : b === DEFAULT_PROFILE ? 1 : byName(a, b)))
}

/** The tabs of the profile selector, with the records each holds and the yellow dot. */
export function profileItems(sources = [], browserId, added = []) {
  return profileNames(sources, browserId, added).map((name) => {
    const { count, partial } = countsOf(scopedSources(sources, browserId, name))
    return { id: name, label: name, count, partial }
  })
}

/** A sentence for a profile name that cannot be used, or null. A name already there is not an error: it is chosen. */
export function profileNameError(name) {
  const text = String(name ?? '').trim()
  if (!text) return 'Enter a profile name.'
  if (text.length > PROFILE_NAME_MAX) return `Use at most ${PROFILE_NAME_MAX} characters.`
  return null
}

/** The name an existing profile has when the typed one matches it in any case, or the typed one trimmed. */
export function resolveProfileName(names, typed) {
  const text = String(typed ?? '').trim()
  return names.find((name) => name.toLocaleLowerCase() === text.toLocaleLowerCase()) ?? text
}

/** Only the files that have records to show: read (or being read). */
export const hasRecords = (source) => source.state === 'done' || source.state === 'parsing'

/** Records per type from the answers of `evidence.stack` on `type` (one per file). */
export function typeTotals(answers = []) {
  const totals = {}
  for (const answer of answers) {
    for (const { value, count } of answer?.values ?? []) totals[value] = (totals[value] ?? 0) + count
  }
  return totals
}

/** The records of a section, from the totals per type. */
export const sectionCount = (totals, section) =>
  SECTION_TYPES[section].reduce((sum, type) => sum + (totals[type] ?? 0), 0)

/** The Unique domains stat from two stacks over the same records: `data.domain` (its `distinct` is the figure). */
export function domainStat(domains) {
  return { count: domains?.distinct ?? 0, capped: Boolean(domains?.distinctCapped) }
}

/** The first version of the browser parser that writes `domain` on a record. */
const DOMAIN_PARSER_VERSION = 2

/**
 * Whether a file must be read again to have its domains counted: it was read before 7.0 (legacy) or by a
 * browser parser older than the one that writes `domain`. Records of a newer parser with no address are not a reason.
 */
export const needsReread = (sources = []) =>
  sources.some(
    (source) => source.legacy || (source.parser === 'browser' && Number(source.parserVersion) < DOMAIN_PARSER_VERSION),
  )

/** The filters that scope the records, a stat or a stack to a browser and a profile. */
export const scopeFilters = (browserId, profile) => ({ kind: 'browser', sourcePrefix: `${browserId}.`, profile })

/** The keys of `data` the columns and the menu of the table ask for (the API takes 12 at most). */
export const ROW_FIELDS = ['url', 'title', 'name', 'text', 'domain', 'referrerDomain', 'totalBytes', 'fileName']

/** The filters of a pick in a stack panel: a `data.<key>` value is a filter on that key, not a text search. */
export function pickedFilters(field, value) {
  return field.startsWith('data.') ? { dataKey: field.slice(5), dataValue: String(value) } : { [field]: value }
}

/** The `data.<key>` filter in force: `{ key, value }` or null. */
export const dataFilterOf = (filters = {}) =>
  filters.dataKey ? { key: filters.dataKey, value: filters.dataValue ?? '' } : null

/** The sources of a browser a file the page cannot place may be: `{ value, label }` for a choice. */
export function sourceChoices(browser) {
  return browser.sources.map((source) => ({ value: `${browser.id}.${source.key}`, label: source.label }))
}

/** Where a download came from: the site that sent it, else the host of its address. */
export const fromOf = (data) => data?.referrerDomain || data?.domain || ''

/** "4" or "4+" when the figure is a floor. */
export const countText = (value, capped = false) => `${number(value)}${capped ? '+' : ''}`

/** What the page expects of a browser: its files with where they live on the host's system. */
export function expectedFor(browser, os) {
  return browser.sources.map((source) => ({
    key: source.key,
    label: source.label,
    hint: `${sourcePathFor(source, os)}: ${source.hint}`,
  }))
}

/** The expected file a source satisfies, for the browser on screen. */
export const matchFor = (browserId) => (source) =>
  source.kind === 'browser' && browserOf(source) === browserId ? partOf(source) || null : null

/**
 * The `source` the server wants for a file of a browser (`edge.history`). It is told from the name the
 * browser gives the file; '' lets the worker tell by the content (it then calls any Chromium file Chrome).
 */
export function sourceForFile(browserId, fileName) {
  const browser = BROWSERS.find((item) => item.id === browserId)
  if (!browser) return ''
  const name = String(fileName ?? '')
    .toLowerCase()
    .replace(/^.*[\\/]/, '')
  const keys = new Set(browser.sources.map((source) => source.key))
  const named = (key) => (keys.has(key) ? `${browserId}.${key}` : '')
  if (browser.engine === 'firefox') return named('places')
  if (browser.engine === 'safari') {
    if (name.startsWith('history')) return named('history')
    if (name.startsWith('downloads')) return named('downloads')
    if (name.startsWith('bookmarks')) return named('bookmarks')
    return ''
  }
  if (name.startsWith('bookmarks')) return named('bookmarks')
  if (name.startsWith('shortcuts')) return named('shortcuts')
  if (name === 'history' || name.startsWith('history-')) return named('history')
  if (name.endsWith('.json')) return `${browserId}.json`
  if (name.endsWith('.csv')) return `${browserId}.csv`
  return ''
}

const SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i
const DOWNLOAD_FROM = ' <- '

/**
 * The text of the Title / URL cell. A record that is an address (a visit with no title, a bookmark with
 * no name) is shown defanged, like the address the old page showed after asking: it is never a link. The
 * host of a download ("file <- host") is defanged; a title is left as it is.
 */
export function summaryText(row) {
  const text = String(row?.summary ?? '')
  if (row?.type === 'download') {
    const at = text.lastIndexOf(DOWNLOAD_FROM)
    return at < 0 ? text : `${text.slice(0, at)}${DOWNLOAD_FROM}${defang(text.slice(at + DOWNLOAD_FROM.length))}`
  }
  return SCHEME.test(text) ? defang(text) : text
}

/** The address a record points at, from its `data` (a visit, a bookmark, a shortcut, a download, a search). */
export function addressOf(data) {
  const url = data?.url
  return typeof url === 'string' && url ? url : ''
}

/** The text of a row for "Copy as text": its time, type and summary. */
export const rowText = (row, time) => [time, row.type, summaryText(row)].filter(Boolean).join('  ')
