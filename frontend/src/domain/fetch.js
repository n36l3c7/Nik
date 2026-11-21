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
  if (last.mirrored) parts.push(`${last.mirrored} added to incidents there were`)
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
    case 'mirrored':
      return { label: 'a line', color: 'cyan' }
    default:
      return { label: outcome ?? '', color: 'slate' }
  }
}

export const OUTCOMES = ['', 'created', 'incomplete', 'dropped', 'linked', 'duplicate', 'mirrored']

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

/* ------------------------------------------------- how an instance fetches */

const UNITS = { minute: 60, hour: 3600, day: 86400 }

/** "3 days" as seconds; null when it is not a length of time (a month at most), as the server reads it. */
export function firstFetchSeconds(text) {
  const found = /^\s*(\d{1,4})\s*(minute|hour|day)s?\s*$/.exec(String(text ?? '').toLowerCase())
  if (!found) return null
  const seconds = Number(found[1]) * UNITS[found[2]]
  return seconds > 0 && seconds <= 31 * 86400 ? seconds : null
}

/** Seconds in words: "30 s", "2 min", "1 h 30 min". */
export function intervalText(seconds) {
  const whole = Math.round(Number(seconds))
  if (!Number.isFinite(whole) || whole <= 0) return ''
  if (whole < 120 || whole % 60) return `${whole} s`
  const minutes = whole / 60
  if (minutes < 60) return `${minutes} min`
  return minutes % 60 ? `${Math.floor(minutes / 60)} h ${minutes % 60} min` : `${minutes / 60} h`
}

/**
 * What the Fetch part of the form of an instance starts with: what the
 * instance has (`instance.fetch`), or what its connector says for a new one.
 * The numbers are kept as they are typed.
 */
export function fetchForm(connector, instance) {
  const theirs = connector?.fetch ?? {}
  const held = instance?.fetch ?? {}
  return {
    enabled: Boolean(held.enabled),
    interval: String(held.intervalSeconds ?? theirs.intervalSeconds ?? 120),
    firstFetch: String(held.firstFetch ?? theirs.firstFetch ?? '3 days'),
    lookback: String(held.lookbackMinutes ?? theirs.lookbackMinutes ?? 0),
    // The direction the incidents it fetches are mirrored in, and the classes their mirrors may send.
    mirror: held.mirror?.direction ?? 'none',
    mirrorAllow: [...(held.mirror?.allow ?? [])].sort(),
  }
}

const wholeNumber = (typed) => (/^\s*\d+\s*$/.test(String(typed)) ? Number(typed) : null)

/** Why the Fetch part cannot be saved as it stands (a sentence), or null. */
export function fetchProblem(form, { minInterval = 30, maxLookback = 1440, byTime = true } = {}) {
  const interval = wholeNumber(form.interval)
  if (interval === null || interval < minInterval || interval > 86400) {
    return `Fetching: how often is a number of seconds, ${minInterval} at the least and 86400 at most`
  }
  if (firstFetchSeconds(form.firstFetch) === null) {
    return 'Fetching: the first fetch is a length of time, a month at most: 30 minutes, 12 hours, 3 days'
  }
  const lookback = wholeNumber(form.lookback)
  if (byTime && (lookback === null || lookback > maxLookback)) {
    return `Fetching: the look-back is a number of minutes, ${maxLookback} at most`
  }
  return null
}

/** What the form sends as `fetch` with the rest of the instance. */
export function fetchPayload(form, { byTime = true, mirrors = false } = {}) {
  const body = {
    enabled: Boolean(form.enabled),
    intervalSeconds: Number(form.interval),
    firstFetch: String(form.firstFetch).trim().toLowerCase().replace(/\s+/g, ' '),
  }
  if (byTime) body.lookbackMinutes = Number(form.lookback)
  if (mirrors) {
    // A connector that mirrors: the direction, and what may be sent when the direction sends.
    body.mirror = form.mirror ?? 'none'
    body.mirrorAllow = sends(body.mirror) ? [...(form.mirrorAllow ?? [])].sort() : []
  }
  return body
}

/** Whether the Fetch part differs from what the instance has: only then is it sent. */
export function fetchChanged(form, connector, instance) {
  const before = fetchForm(connector, instance)
  return ['enabled', 'interval', 'firstFetch', 'lookback', 'mirror', 'mirrorAllow'].some(
    (name) => String(form[name] ?? '').trim() !== String(before[name] ?? '').trim(),
  )
}

/** What resetting the last run will do, said before it is done. */
export function resetText(status) {
  const first = status?.firstFetch || 'the first fetch'
  return `The next cycle reads again from ${first} ago. What was already imported is skipped: no incident is made twice.`
}

/** What the look-back does, under its field. */
export function lookbackHint(form, { byTime = true } = {}) {
  if (!byTime)
    return 'This connector goes on from where it stopped, not from a time: the look-back does not apply to it.'
  const minutes = wholeNumber(form.lookback)
  if (!minutes) {
    return 'Each cycle asks from the newest time it has seen. An item that turns up later with an older time is missed: give it some minutes if the product shows its alerts late.'
  }
  return `Each cycle asks from ${minutes} min before the newest time it has seen. What it already has is skipped by its id.`
}

/* ------------------------------------------------------------------ mirroring */

export const DIRECTIONS = [
  { id: 'in', label: 'In', hint: 'What changes on the other side comes here. Nothing is sent.' },
  { id: 'out', label: 'Out', hint: 'What changes here is sent to the other side.' },
  { id: 'both', label: 'In-out', hint: 'Each side follows the other.' },
]

/** The direction of a mirror, in words. */
export function directionText(direction) {
  if (direction === 'in') return 'read from there'
  if (direction === 'out') return 'sent from here'
  return direction === 'both' ? 'both ways' : String(direction ?? '')
}

/** Why a mirror cannot be started as the form stands (a sentence), or null. */
export function mirrorProblem({ connection, mirrorId, direction, canSend }) {
  if (!connection) return 'Choose a connection'
  if (!String(mirrorId ?? '').trim()) return 'Say which object of the other side this incident is'
  if (direction !== 'in' && !connection.out) return `${connection.connector} is read, not written to: mirror in`
  if (direction !== 'in' && !canSend) return 'Sending to another system needs the permission to run playbooks'
  return null
}

/** What waits to be sent, or could not be, in a line. */
export function jobText(job, now = Date.now()) {
  const what = job.kind === 'comment' ? 'a comment' : 'the fields that changed'
  if (job.status === 'failed') return `${what}: given up after ${job.attempts} tries`
  if (!job.attempts) return `${what}: waits for the worker`
  const seconds = Math.round(Number(job.nextAt) - now / 1000)
  const again =
    seconds <= 0
      ? 'at the next turn of the worker'
      : seconds < 90
        ? `in ${seconds} s`
        : `in ${Math.round(seconds / 60)} min`
  return `${what}: tried ${job.attempts} time${job.attempts === 1 ? '' : 's'}, again ${again}`
}

/* ------------------------------------- the direction an instance gives its incidents */

/** Whether a direction sends anything to the other side. */
export const sends = (direction) => direction === 'out' || direction === 'both'

const CHOICE_LABELS = { none: 'None', in: 'In', out: 'Out', both: 'In-out' }

/** A direction as the product names it: None, In, Out, In-out. */
export const choiceLabel = (direction) => CHOICE_LABELS[direction] ?? String(direction ?? '')

/**
 * What a mirror with a connector can do, each way, from what the lists say of
 * the connector (`connector.mirror`): null for one that does not mirror.
 */
export function mirrorAbilities(connector) {
  const said = connector?.mirror
  if (!said) return null
  return {
    fieldsIn: said.fieldsIn !== false && !said.fed,
    commentsIn: Boolean(said.comments),
    fieldsOut: Boolean(said.fieldsOut),
    commentsOut: Boolean(said.commentsOut),
  }
}

const joined = (parts) => (parts.length === 2 ? `${parts[0]} and ${parts[1]}` : (parts[0] ?? ''))

/** What comes in with a connector, and what goes out, in words; '' for nothing. */
function comesIn(can, fed) {
  if (fed) return 'what goes on with the conversation (a reply) becomes a line of the War Room'
  const parts = []
  if (can.fieldsIn) parts.push('its fields follow the object on the other side')
  if (can.commentsIn) parts.push('new comments there become lines of the War Room')
  return joined(parts)
}

function goesOut(can) {
  const parts = []
  if (can.fieldsOut) parts.push('the fields the outgoing mapper reads are written to the other side when they change')
  if (can.commentsOut) parts.push('notes tagged mirror are added there as comments')
  return joined(parts)
}

const capital = (text) => text.charAt(0).toUpperCase() + text.slice(1)

/**
 * The directions an instance may give the incidents it fetches, each with
 * what it does for this connector in one sentence, and, for one the connector
 * cannot do, why it is not offered:
 * `[{ id, label, offered, text }]`. `connector` is what the lists say of it.
 */
export function mirrorChoices(connector) {
  const can = mirrorAbilities(connector)
  const name = connector?.name ?? 'This connector'
  if (!can) {
    const why = connector?.noMirror || `${name} does not say how to mirror.`
    return [
      { id: 'none', label: 'None', offered: true, text: 'Each item becomes an incident, and that is all.' },
      ...['in', 'out', 'both'].map((id) => ({ id, label: choiceLabel(id), offered: false, text: why })),
    ]
  }
  const fed = Boolean(connector.mirror.fed)
  const into = comesIn(can, fed)
  const out = goesOut(can)
  const cannotSend = fed
    ? `${name} is only read: Nik never sends a message by itself.`
    : `${name} has no command that writes to the other side.`
  return [
    {
      id: 'none',
      label: 'None',
      offered: true,
      text: 'Each item becomes an incident, and that is all, unless a mapper starts a mirror itself.',
    },
    { id: 'in', label: 'In', offered: Boolean(into), text: `${capital(into)}. Nothing is sent.` },
    { id: 'out', label: 'Out', offered: Boolean(out), text: out ? `${capital(out)}. Nothing is read.` : cannotSend },
    {
      id: 'both',
      label: 'In-out',
      offered: Boolean(out) && Boolean(into),
      text: out ? `${capital(into)}; ${out}.` : cannotSend,
    },
  ]
}

/** Why the Mirroring part cannot be saved as it stands (a sentence), or null. */
export function mirrorChoiceProblem(form, connector) {
  const chosen = mirrorChoices(connector).find((choice) => choice.id === (form.mirror ?? 'none'))
  if (!chosen) return 'Mirroring: choose None, In, Out or In-out'
  return chosen.offered ? null : `Mirroring: ${chosen.label} is not possible. ${chosen.text}`
}

/** Where the direction of the mirror of an incident came from, in words. */
export function originText(origin) {
  if (origin === 'instance') return 'from the instance'
  if (origin === 'mapper') return 'from the mapper'
  return 'set here'
}

/** What giving the choice of an instance to what it already fetched will do, said before it is done. */
export function applyText(count, direction) {
  const open = count?.open ?? 0
  if (!open) return 'No open incident was fetched from this instance: there is nothing to change.'
  const them = `${open} open incident${open === 1 ? '' : 's'} fetched from this instance`
  const more = open >= (count?.most ?? Infinity) ? ' (the first ones: run it again for the rest)' : ''
  if (direction === 'none') {
    return `${count.mirrored} of the ${them} ${count.mirrored === 1 ? 'is' : 'are'} mirrored with it: mirroring stops for ${count.mirrored === 1 ? 'it' : 'them'}, and what waited to be sent is dropped${more}.`
  }
  return `The ${them} will be mirrored ${choiceLabel(direction)}${more}. One mirrored with another instance is left as it is.`
}

/** What applying did, in a line. */
export function appliedText(done) {
  const parts = ['started', 'changed', 'stopped', 'unchanged', 'skipped']
    .filter((name) => done?.[name])
    .map((name) => `${done[name]} ${name === 'skipped' ? 'left alone' : name}`)
  return parts.length ? `${capital(parts.join(', '))}.` : 'Nothing to change.'
}

/** The last time a mirror read and wrote, as the panel of an incident says it. */
export function mirrorTimes(state, format) {
  const parts = []
  if (state?.lastPull) parts.push(`read ${format(state.lastPull)}`)
  if (state?.lastPush) parts.push(`sent ${format(state.lastPush)}`)
  if (!parts.length && state?.lastSync) parts.push(`in step ${format(state.lastSync)}`)
  if (!parts.length) parts.push(state?.fed ? 'no reply yet' : 'not read yet')
  if (state?.waiting) parts.push(`${state.waiting} to send`)
  return capital(parts.join(' · '))
}
