/*
 * Incident identity: the display name and the severity tag.
 *
 * Name: `[TICKET] ` first when there is a ticket ID, then the short title when
 * set (it replaces host and user), else `host - user`, `host` or `user`:
 *   [INC-2041] Invoice phishing, finance
 *   [INC-2039] WKS-042 - m.rossi
 *   SRV-FILE-01
 * Severity is a tag the analysts set; it is never part of the name.
 */

export const SEVERITIES = [
  { value: 'low', label: 'low' },
  { value: 'medium', label: 'medium' },
  { value: 'high', label: 'high' },
  { value: 'critical', label: 'critical' },
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
