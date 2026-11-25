/*
 * What the Logons page says about the logons (components/tabs/eventlogs/LogonsSection.jsx): the names of
 * the Windows logon types, the outcomes, and the filters the table and the graph share. The shapes are the
 * ones of `GET .../logons` and `.../logons/graph` (backend/app/routers/evidence_processes.py).
 */

/** The logon types of Windows by their number, as their names are said. */
export const LOGON_TYPES = {
  2: 'interactive',
  3: 'network',
  4: 'batch',
  5: 'service',
  7: 'unlock',
  8: 'network cleartext',
  9: 'new credentials',
  10: 'remote interactive',
  11: 'cached',
}

/** The name of a logon type; the number when it has none here, '' for no type. */
export function logonTypeName(type) {
  if (type === null || type === undefined || type === '') return ''
  return LOGON_TYPES[Number(type)] ?? String(type)
}

/** "network (3)" for the filter and the detail; the name alone when the number is no one. */
export const logonTypeLabel = (type) =>
  LOGON_TYPES[Number(type)] ? `${LOGON_TYPES[Number(type)]} (${type})` : String(type)

export const TYPE_OPTIONS = [
  { value: '', label: 'Any type' },
  ...Object.keys(LOGON_TYPES).map((type) => ({ value: type, label: logonTypeLabel(type) })),
]

/** The outcomes by their API name, with the word and the Badge colour of each. */
export const OUTCOMES = {
  success: { label: 'success', color: 'emerald' },
  failure: { label: 'failure', color: 'red' },
  logoff: { label: 'logoff', color: 'slate' },
  explicit: { label: 'explicit credentials', color: 'violet' },
  privileged: { label: 'privileged', color: 'amber' },
}

export const OUTCOME_OPTIONS = [
  { value: '', label: 'Any outcome' },
  ...Object.entries(OUTCOMES).map(([value, item]) => ({ value, label: item.label })),
]

/** The outcome as a word and a colour; an outcome this version does not know is shown as it is, in grey. */
export const outcomeOf = (outcome) => OUTCOMES[outcome] ?? { label: String(outcome ?? '—'), color: 'slate' }

/** Where a logon came from: its source host and its address together, "ws-01 (10.0.0.5)"; '' when it is local. */
export function sourceText(logon) {
  const host = logon?.sourceHost ?? ''
  const ip = logon?.sourceIp ?? ''
  if (host && ip && host.toLowerCase() !== ip.toLowerCase()) return `${host} (${ip})`
  return host || ip
}

/** The user as the logon names it: "CORP\\j.alvarez"; the name alone with no domain. */
export function userText(logon) {
  if (!logon?.user) return ''
  return logon.domain ? `${logon.domain}\\${logon.user}` : logon.user
}

/**
 * The filters of the table of logons as the API takes them: the page keeps single choices for the outcome and
 * the type (a select each); the API takes lists.
 */
export function apiFilters(filters = {}) {
  const out = {}
  for (const [name, value] of Object.entries(filters)) {
    if (value === undefined || value === null || value === '' || value === false) continue
    out[name] = value
  }
  return out
}

/**
 * The filters of the graph: the ones of the table that make sense for it (time range, type, outcome, user) and
 * the minimum count. The host, source and text filters belong to a click in the graph, not to what it draws.
 */
export function graphFilters(filters = {}, minCount = 0) {
  const out = {}
  for (const name of ['from', 'to', 'logonType', 'outcome', 'user']) {
    const value = filters[name]
    if (value !== undefined && value !== null && value !== '') out[name] = value
  }
  if (minCount > 1) out.minCount = minCount
  return out
}

/** The filters of the table that a click on the graph set: the ones to clear before another click sets its own. */
export const CLICK_FILTERS = ['host', 'sourceHost', 'sourceIp']

/** The filters after a click in the graph: its own host and source filters replace the earlier ones. */
export function withClick(filters = {}, click = {}) {
  const kept = { ...filters }
  for (const name of CLICK_FILTERS) delete kept[name]
  return { ...kept, ...click }
}

/** What a click filtered, in words for the line above the table: "from ws-01 to srv-02". */
export function clickText(filters = {}) {
  const from = filters.sourceHost || filters.sourceIp
  const to = filters.host
  if (from && to) return `from ${from} to ${to}`
  if (from) return `from ${from}`
  if (to) return `to ${to}`
  return ''
}
