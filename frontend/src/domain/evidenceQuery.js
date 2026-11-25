/*
 * The query string of the host-evidence endpoints (routers/evidence.py, evidence_views.py).
 * The filters of the list of records, of the histogram and of the stack are the same names.
 */

/** The filters the API knows, by their names there (`from` and `to` are in ms). */
export const RECORD_FILTERS = [
  'kind',
  // Sections left out (comma-separated): the Timeline leaves the disk out until it is asked for.
  'kindNot',
  'type',
  'sourceId',
  'source',
  'sourcePrefix',
  'profile',
  'host',
  'username',
  'channel',
  'eventId',
  'level',
  'rule',
  'flagged',
  'dated',
  'matter',
  // `dataKey` and `dataValue` may be lists (up to 4, paired by position); `dataHas` is `key:value` (a list too):
  // the array `data.<key>` holds the value.
  'dataKey',
  'dataValue',
  'dataHas',
  'q',
  'from',
  'to',
]

const empty = (value) =>
  value === undefined || value === null || value === '' || value === false || (Array.isArray(value) && !value.length)

/** `?a=1&b=x` from an object; what is empty (null, '', false, []) is left out, true is `true`, a list repeats its name. */
export function queryString(params = {}) {
  const query = new URLSearchParams()
  for (const [name, value] of Object.entries(params)) {
    if (empty(value)) continue
    if (Array.isArray(value)) for (const one of value) query.append(name, String(one))
    else query.set(name, String(value))
  }
  const text = query.toString()
  return text ? `?${text}` : ''
}

/** Only the filters the API knows, and only the ones that say something. */
export function recordFilters(filters = {}) {
  const kept = {}
  for (const name of RECORD_FILTERS) {
    if (!empty(filters[name])) kept[name] = filters[name]
  }
  // The one filter whose `false` says something: only the records with no time.
  if (filters.dated === false) kept.dated = 'false'
  return kept
}
