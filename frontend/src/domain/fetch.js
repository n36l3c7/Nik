/*
 * Fetching (GET /api/fetch) as its page reads it: the state of a connection
 * as a badge, what its last cycle found in a line, and what became of an
 * item.
 */

/** The state of a connection that can fetch, as a badge: `{ label, color }`. */
export function stateBadge(connection) {
  switch (connection?.state) {
    case 'ok':
      return { label: 'fetching', color: 'emerald' }
    case 'failing':
      return { label: 'failing', color: 'red' }
    case 'paused':
      return { label: 'paused', color: 'amber' }
    default:
      return { label: 'off', color: 'slate' }
  }
}

const plural = (count, one, many = `${one}s`) => `${count} ${count === 1 ? one : many}`

/** What the last cycle found, in a line; '' before the first cycle. */
export function lastText(connection) {
  const last = connection?.last
  if (!last || last.fetched === undefined) return ''
  if (last.fetched === 0) return 'nothing new'
  const parts = [`${plural(last.fetched, 'item')} read`, `${last.new} new`]
  const made = (last.created ?? 0) + (last.incomplete ?? 0)
  if (made) parts.push(plural(made, 'incident'))
  if (last.incomplete) parts.push(`${last.incomplete} incomplete`)
  if (last.dropped) parts.push(`${last.dropped} dropped`)
  if (last.linked) parts.push(`${last.linked} linked`)
  if (last.duplicate) parts.push(plural(last.duplicate, 'duplicate'))
  return parts.join(' · ')
}

/** When the next cycle is, in words, from seconds since 1970. */
export function nextText(connection, now = Date.now()) {
  if (connection?.state === 'off') return ''
  if (connection?.state === 'paused') return 'waits for someone to let it go on'
  const next = Number(connection?.nextAt)
  if (!Number.isFinite(next) || next <= 0) return 'at the next turn of the worker'
  const seconds = Math.round(next - now / 1000)
  if (seconds <= 0) return 'at the next turn of the worker'
  if (seconds < 90) return `in ${seconds} s`
  if (seconds < 5400) return `in ${Math.round(seconds / 60)} min`
  return `in ${Math.round(seconds / 3600)} h`
}

/** What became of an item, as a badge. */
export function outcomeBadge(outcome) {
  switch (outcome) {
    case 'created':
      return { label: 'incident', color: 'emerald' }
    case 'incomplete':
      return { label: 'incomplete', color: 'amber' }
    case 'dropped':
      return { label: 'dropped', color: 'slate' }
    case 'linked':
      return { label: 'linked', color: 'cyan' }
    case 'duplicate':
      return { label: 'duplicate', color: 'slate' }
    default:
      return { label: outcome ?? '', color: 'slate' }
  }
}

export const OUTCOMES = ['', 'created', 'incomplete', 'dropped', 'linked', 'duplicate']

/** How close a connection is to being paused: '' while it is far. */
export function limitText(connection) {
  const made = connection?.madeLastHour ?? 0
  const limit = connection?.limitPerHour ?? 0
  if (!limit || made < limit / 2) return ''
  return `${made} of ${limit} incidents this hour`
}

/** The connections that need someone: failing or paused. */
export const needingCare = (connections) =>
  (connections ?? []).filter((connection) => connection.state === 'failing' || connection.state === 'paused')
