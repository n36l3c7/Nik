/*
 * The IoC library (GET /api/iocs): addresses of its views, what an export can
 * hold, and how pasted or dropped text is told from a single indicator.
 */

/** A view of the library: everything (with filters), one list, or the alerts. */
export const LIBRARY_ROOT = '/iocs'

export function libraryPath(view) {
  if (!view) return '/'
  if (view.kind === 'list') return `${LIBRARY_ROOT}/lists/${encodeURIComponent(view.id)}`
  if (view.kind === 'alerts') return `${LIBRARY_ROOT}/alerts`
  return LIBRARY_ROOT
}

/** The view an address names, or null when it is not the library's. */
export function viewFromPath(pathname = '') {
  const path = String(pathname).replace(/\/+$/, '')
  if (path === LIBRARY_ROOT) return { kind: 'all' }
  if (path === `${LIBRARY_ROOT}/alerts`) return { kind: 'alerts' }
  const match = path.match(/^\/iocs\/lists\/([^/]+)$/)
  return match ? { kind: 'list', id: decodeURIComponent(match[1]) } : null
}

export const isLibraryPath = (pathname) => viewFromPath(pathname) !== null

/** The quick filters of the side panel. */
export const QUICK_FILTERS = [
  { id: 'all', label: 'All indicators', count: 'all', filters: {} },
  { id: 'added', label: 'Added by hand or imported', count: 'added', filters: { origin: 'added' } },
  { id: 'malicious', label: 'Malicious', count: 'malicious', filters: { verdict: 'malicious' } },
  { id: 'suspicious', label: 'Suspicious', count: 'suspicious', filters: { verdict: 'suspicious' } },
  { id: 'unchecked', label: 'Never checked', count: 'unchecked', filters: { verdict: 'none' } },
  { id: 'expired', label: 'Expired', count: 'expired', filters: { expired: true } },
  { id: 'toAnalyse', label: 'Addresses to analyse', count: 'toAnalyse', filters: { analysis: 'none' } },
]

export const EMPTY_FILTERS = { q: '', type: '', verdict: '', origin: '', expired: null, analysis: '' }

/** Query string of GET /api/iocs for the filters, the sort and the page. */
export function libraryQuery({ filters = {}, list = null, sort = null, offset = 0, limit = 100 } = {}) {
  const params = new URLSearchParams()
  if (filters.q?.trim()) params.set('q', filters.q.trim())
  if (filters.type) params.set('type', filters.type)
  if (filters.verdict) params.set('verdict', filters.verdict)
  if (filters.origin) params.set('origin', filters.origin)
  if (filters.analysis) params.set('analysis', filters.analysis)
  if (filters.expired === true || filters.expired === false) params.set('expired', String(filters.expired))
  if (list) params.set('list', list)
  if (sort?.key) {
    params.set('sort', sort.key)
    params.set('dir', sort.dir === 'desc' ? 'desc' : 'asc')
  }
  if (offset) params.set('offset', String(offset))
  params.set('limit', String(limit))
  return params.toString()
}

/** The filters as the API's scope takes them (no empty values). */
export function scopeFilters(filters = {}, list = null) {
  const out = {}
  if (filters.q?.trim()) out.q = filters.q.trim()
  for (const key of ['type', 'verdict', 'origin', 'analysis']) if (filters[key]) out[key] = filters[key]
  if (filters.expired === true || filters.expired === false) out.expired = filters.expired
  if (list) out.list = list
  return out
}

export const ORIGIN_LABELS = { incident: 'incident', artifact: 'artifact', manual: 'by hand', import: 'import' }

export const TLP_OPTIONS = [
  { value: 'clear', label: 'TLP:CLEAR' },
  { value: 'green', label: 'TLP:GREEN' },
  { value: 'amber', label: 'TLP:AMBER' },
  { value: 'red', label: 'TLP:RED (never sent out)' },
]

/** Row tint by verdict only: red for malicious, amber for suspicious, none otherwise. */
export function verdictRowClass(verdict) {
  if (verdict === 'malicious') return 'bg-high-soft/60 shadow-[inset_2px_0_0_var(--color-high-line)]'
  if (verdict === 'suspicious') return 'bg-med-soft/60 shadow-[inset_2px_0_0_var(--color-med-line)]'
  return ''
}

// ---- export ----------------------------------------------------------------

export const EXPORT_FORMATS = [
  { id: 'csv', label: 'CSV', hint: 'spreadsheet, SIEM lookup', fields: true },
  { id: 'json', label: 'JSON', hint: 'scripts, import in Nik', fields: true },
  { id: 'stix', label: 'STIX 2.1', hint: 'TIP, OpenCTI', fields: false },
  { id: 'misp', label: 'MISP', hint: 'event with attributes', fields: false },
  { id: 'txt', label: 'Text', hint: 'one value per line', fields: false },
]

export const EXPORT_FIELDS = [
  { id: 'type', label: 'Type', main: true },
  { id: 'value', label: 'Value', main: true },
  { id: 'verdict', label: 'Verdict', main: true },
  { id: 'score', label: 'Score', main: true },
  { id: 'tags', label: 'Tags', main: true },
  { id: 'first_seen', label: 'First seen', main: true },
  { id: 'last_checked', label: 'Last checked' },
  { id: 'sources_flagging', label: 'Sources that flag' },
  { id: 'per_source', label: 'One column per source' },
  { id: 'incidents', label: 'Incidents' },
  { id: 'lists', label: 'Lists' },
  { id: 'note', label: 'Note' },
  { id: 'tlp', label: 'TLP' },
  { id: 'origin', label: 'Origin' },
  { id: 'added_by', label: 'Added by' },
  { id: 'expires', label: 'Expires' },
]

export const DEFAULT_EXPORT_FIELDS = EXPORT_FIELDS.filter((field) => field.main).map((field) => field.id)

/** A stored choice of fields, kept in the order of the list and without unknown names. */
export function cleanExportFields(stored) {
  if (!Array.isArray(stored)) return DEFAULT_EXPORT_FIELDS
  const kept = EXPORT_FIELDS.map((field) => field.id).filter((id) => stored.includes(id))
  return kept.length ? kept : DEFAULT_EXPORT_FIELDS
}

// ---- pasted or dropped text --------------------------------------------------

const INDICATOR_FILE = /\.(txt|csv|tsv|json|stix|ioc|iocs|list|lst)$/i
export const INDICATOR_FILE_MAX_BYTES = 5_000_000

/** A file small and textual enough to be read as a list of indicators. */
export function mayHoldIndicators({ name = '', size = 0, route = null } = {}) {
  if (size <= 0 || size > INDICATOR_FILE_MAX_BYTES) return false
  if (route && route.tab !== 'endpoint') return false // an executable, a capture, an e-mail…
  return INDICATOR_FILE.test(name) || !String(name).includes('.')
}

/**
 * Whether what the server read in a dropped file is a list of indicators.
 * A threat-intelligence document always is; a table or plain text only when
 * most of its lines held one (a log or a script mentions hosts too).
 */
export function isIndicatorList(parsed, text = '') {
  const found = parsed?.items?.length ?? 0
  if (!found) return false
  if (['nik', 'stix', 'misp'].includes(parsed.format)) return true
  const lines = String(text)
    .split('\n')
    .filter((line) => line.trim() && !line.trim().startsWith('#')).length
  // A table has a header line; a tool's export with a "value" column is not a list of indicators.
  return found >= (parsed.format === 'csv' ? lines - 1 : lines) * 0.6
}

/** Pasted text that is more than one indicator: several lines or values. */
export function isSeveralValues(text) {
  const parts = String(text ?? '')
    .trim()
    .split(/[\s,;]+/)
    .filter(Boolean)
  return parts.length > 1 && parts.length <= 20_000
}

/** "24 min", "< 1 min", "1.5 h": how long a bulk check takes today. */
export function durationLabel(seconds) {
  if (!seconds || seconds < 60) return '< 1 min'
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`
  return `${(seconds / 3600).toFixed(1)} h`
}

/** What a source will do in a bulk check, in a line. */
export function sourceLine(source) {
  if (source.leftToday === null || source.leftToday === undefined) return `${source.needed} · no daily limit`
  if (source.later > 0) return `${source.today} today, ${source.later} wait for the quota`
  return `${source.needed} of ${source.leftToday} left today`
}
