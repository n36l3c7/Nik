/*
 * Incident identity: the display name, the severity tag, the status and the assignee.
 *
 * Name: `[TICKET] ` first when there is a ticket ID, then the short title when
 * set (it replaces host and user), else `host - user`, `host` or `user`:
 *   [INC-2041] Invoice phishing, finance
 *   [INC-2039] WKS-042 - m.rossi
 *   SRV-FILE-01
 * Severity is a tag the analysts set; it is never part of the name.
 * Status says where the work stands (an incident with none is open); the
 * assignee is the username of the analyst who has it, or ''.
 */

export const SEVERITIES = [
  { value: 'low', label: 'low' },
  { value: 'medium', label: 'medium' },
  { value: 'high', label: 'high' },
  { value: 'critical', label: 'critical' },
]

export const STATUSES = [
  { value: 'open', label: 'open' },
  { value: 'in_progress', label: 'in progress' },
  { value: 'closed', label: 'closed' },
]

const clean = (value) => (typeof value === 'string' ? value.trim() : '')

/** The incident's display name from its identity fields. */
export function deriveIncidentName({ ticketId, title, host, username } = {}) {
  const t = clean(ticketId)
  const h = clean(host)
  const u = clean(username)
  const base = clean(title) || (h && u ? `${h} - ${u}` : h || u)
  if (!base) return t ? `[${t}]` : 'Untitled incident'
  return t ? `[${t}] ${base}` : base
}

/** True when at least one field the name is built from is set. */
export function hasIdentity({ ticketId, title, host, username } = {}) {
  return [ticketId, title, host, username].some((value) => clean(value) !== '')
}

/** A known severity value, or null. */
export function normalizeSeverity(value) {
  return SEVERITIES.some((s) => s.value === value) ? value : null
}

/** A known status value; anything else is 'open'. */
export function normalizeStatus(value) {
  return STATUSES.some((s) => s.value === value) ? value : 'open'
}

/** The label of a status ('in progress' for 'in_progress'). */
export function statusLabel(value) {
  return STATUSES.find((s) => s.value === normalizeStatus(value)).label
}

/**
 * The number of an incident as it is written: `#00042`, five digits and more
 * when they are needed. '' for an incident that has none yet (one being created).
 */
export function formatNumber(number) {
  if (!Number.isInteger(number) || number <= 0) return ''
  return `#${String(number).padStart(5, '0')}`
}

/** The number a text names (`#42`, `42`, `#00042`), or null when it is not one. */
export function numberFromText(text) {
  const match = /^#?(\d{1,9})$/.exec(String(text ?? '').trim())
  const number = match ? Number(match[1]) : 0
  return number > 0 ? number : null
}

/** An incident as it is named in a sentence or a menu: `#00042 Invoice phishing, finance`. */
export function numberedName(incident) {
  const name = incident?.name || 'Untitled incident'
  const number = formatNumber(incident?.number)
  return number ? `${number} ${name}` : name
}

/**
 * The incidents to offer for what is typed, the most likely first, `limit` at
 * most. A number (`42`, `#42`, `00042`) finds the incident with it, then those
 * whose number starts with it; words find the incidents whose name (or host,
 * user, ticket) holds every one of them. With nothing typed: the latest changed.
 */
export function suggestIncidents(incidents, text, limit = 10) {
  const all = Array.isArray(incidents) ? incidents : []
  const typed = String(text ?? '').trim()
  const latest = (a, b) => String(b.updatedAt ?? '').localeCompare(String(a.updatedAt ?? ''))
  if (!typed) return [...all].sort(latest).slice(0, limit)
  const number = numberFromText(typed)
  const digits = typed.replace(/^#/, '').replace(/^0+(?=\d)/, '')
  const words = typed.toLowerCase().split(/\s+/).filter(Boolean)
  const scored = []
  for (const incident of all) {
    const own = Number.isInteger(incident.number) ? String(incident.number) : ''
    const haystack = [incident.name, incident.host, incident.username, incident.ticketId]
      .filter(Boolean)
      .join(' ')
      .toLowerCase()
    let score = 0
    if (number !== null && incident.number === number) score = 3
    else if (number !== null && own.startsWith(digits)) score = 2
    else if (words.every((word) => haystack.includes(word))) score = 1
    if (score) scored.push({ incident, score })
  }
  return scored
    .sort((a, b) => b.score - a.score || latest(a.incident, b.incident))
    .slice(0, limit)
    .map((entry) => entry.incident)
}
