/*
 * The audit log as a chain, and its forwarding to syslog: what the screen says
 * of the state the server gives (GET /audit/chain, GET /audit/forwarding), and
 * the form of the forwarding.
 */

const HASH = /^[0-9a-f]{64}$/

/** An entry that came in a file of content from another server (`origin` of GET /audit). */
export const isImported = (entry) => entry?.origin === 'import'

/** What the mark on such an entry says. */
export const IMPORTED_NOTE =
  'It came in a file of content from another server: its time and its author are what that file said, not something this server saw.'

/**
 * The mark of an entry the server did not write itself, `{ text, note }`, or null:
 * `import` (a file of content), `outside` (found in the table: a restore leaves one, and so
 * would somebody who writes to the database by hand).
 */
export function originMark(entry) {
  if (isImported(entry)) return { text: 'imported', note: IMPORTED_NOTE }
  if (entry?.origin === 'outside') {
    return {
      text: 'written outside',
      note: 'It was put into the table by something other than the server (a restore leaves one such entry), and linked when the server found it.',
    }
  }
  return null
}

/** A hash as it is shown: its first twelve digits. */
export const shortHash = (hash) => (HASH.test(String(hash ?? '')) ? `${hash.slice(0, 12)}…` : '')

/**
 * The state of the chain in one line: `{ color, text, detail }`.
 * `ago` turns an ISO time into "3 minutes ago" (lib/time.js formatRelative).
 */
export function chainStatus(chain, ago = (iso) => iso) {
  if (!chain) return { color: 'slate', text: '', detail: '' }
  if (chain.problem) {
    return {
      color: 'red',
      text: `Broken at entry ${chain.problem.seq}`,
      detail: `${chain.problem.text}. Found ${ago(chain.problem.since)}.`,
    }
  }
  if (!chain.verified) {
    return {
      color: 'slate',
      text: 'Not verified yet',
      detail: 'The server walks the chain a few minutes after it starts, then every few minutes.',
    }
  }
  const count = chain.verified.seq ?? 0
  return {
    color: 'emerald',
    text: count ? `Holds up to entry ${count}` : 'Holds: no entry yet',
    detail:
      `Verified ${ago(chain.verified.at)}.` +
      (chain.fullWalk ? ` Every entry was read ${ago(chain.fullWalk.at)}.` : '') +
      uncheckedText(chain.unchecked) +
      (chain.unlinked
        ? ` ${chain.unlinked} ${chain.unlinked === 1 ? 'entry waits' : 'entries wait'} to be linked.`
        : ''),
  }
}

/** " 12 entries cannot be checked: …", for the entries whose key the server can no longer make. */
function uncheckedText(unchecked) {
  const count = Object.values(unchecked ?? {}).reduce((sum, some) => sum + some, 0)
  if (!count) return ''
  const keys = Object.keys(unchecked).filter(Boolean).join(', ')
  return ` The signature of ${count} ${count === 1 ? 'entry' : 'entries'} cannot be checked: this server no longer has the key${keys ? ` ${keys}` : ''}.`
}

/**
 * A head typed by hand, as a syslog receiver shows it in a checkpoint: `4182:9f2c…` (the number,
 * a colon or a space, the 64 digits of the hash). Returns `{ seq, hash }`, null for nothing typed,
 * or `{ error }`.
 */
export function parseHead(text) {
  const typed = String(text ?? '').trim()
  if (!typed) return null
  const found = /^(\d{1,15})\s*[:\s]\s*([0-9a-fA-F]{64})$/.exec(typed)
  if (!found || Number(found[1]) < 1) {
    return { error: 'A head is the number of an entry, a colon, and its hash (64 hexadecimal digits).' }
  }
  return { seq: Number(found[1]), hash: found[2].toLowerCase() }
}

export const PROTOCOLS = [
  { value: 'tls', label: 'TCP with TLS (RFC 5425)' },
  { value: 'tcp', label: 'TCP, not encrypted (RFC 6587)' },
  { value: 'udp', label: 'UDP' },
]

/** What the screen says under the protocol that is chosen. */
export const PROTOCOL_NOTES = {
  tls: 'The certificate of the receiver is always verified, against what is pasted below or against the authorities of the system.',
  tcp: 'Nothing is encrypted and the receiver is not authenticated: whoever is on the path reads the log, and can stand in for the receiver.',
  udp: 'Lossy and unauthenticated: a message that is lost is lost in silence, anybody can stand in for the receiver, and a message that does not fit a datagram is shortened. For receivers that take nothing else.',
}

const number = (value) => (/^\d+$/.test(String(value).trim()) ? Number(String(value).trim()) : NaN)

/** The form of the forwarding, from the settings the server gives. Numbers are kept as typed. */
export function forwardingForm(settings = {}) {
  return {
    enabled: Boolean(settings.enabled),
    host: settings.host ?? '',
    port: String(settings.port ?? 6514),
    protocol: settings.protocol ?? 'tls',
    ca: settings.ca ?? '',
    verifyName: settings.verifyName !== false,
    clientCert: settings.clientCert ?? '',
    // Never given back by the server: typed to set or replace it.
    clientKey: '',
    facility: String(settings.facility ?? 13),
    severity: String(settings.severity ?? 5),
    appName: settings.appName ?? 'nik',
    hostname: settings.hostname ?? 'nik',
    checkpointMinutes: String(settings.checkpointMinutes ?? 5),
    startFrom: settings.startFrom ?? 'beginning',
    maxDatagram: String(settings.maxDatagram ?? 2048),
  }
}

/** Why the form cannot be saved, or null. */
export function forwardingProblem(form, settings = {}) {
  const host = form.host.trim()
  if (form.enabled && !host) return 'Name the receiver before turning the forwarding on.'
  if (host && !/^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$/.test(host)) {
    return 'The receiver is a host name or an address.'
  }
  const port = number(form.port)
  if (!(port >= 1 && port <= 65535)) return 'The port is a number from 1 to 65535.'
  const minutes = number(form.checkpointMinutes)
  if (!(minutes >= 1 && minutes <= 1440)) return 'A checkpoint is sent every 1 to 1440 minutes.'
  for (const [value, what, limit] of [
    [form.appName, 'The application name', 48],
    [form.hostname, 'The host name', 255],
  ]) {
    if (!/^[\x21-\x7e]+$/.test(value.trim()) || value.trim().length > limit) {
      return `${what} is 1 to ${limit} printable ASCII characters without a space.`
    }
  }
  if (form.protocol === 'tls') {
    for (const [value, what] of [
      [form.ca, 'The CA or certificate of the receiver'],
      [form.clientCert, 'The client certificate'],
    ]) {
      if (value.trim() && !value.includes('-----BEGIN CERTIFICATE-----')) {
        return `${what} is pasted in PEM (-----BEGIN CERTIFICATE-----).`
      }
    }
    const keyKept = Boolean(settings.clientKeySet) && Boolean(settings.clientCert)
    if (form.clientCert.trim() && !form.clientKey.trim() && !keyKept) {
      return 'A client certificate needs its key: paste it, or name a stored credential.'
    }
  }
  if (form.protocol === 'udp') {
    const size = number(form.maxDatagram)
    if (!(size >= 480 && size <= 65000)) return 'The largest datagram is 480 to 65000 bytes.'
  }
  return null
}

/** What is sent to PUT /audit/forwarding. The key only when one was typed. */
export function forwardingBody(form) {
  const body = {
    enabled: form.enabled,
    host: form.host.trim(),
    port: number(form.port),
    protocol: form.protocol,
    facility: number(form.facility),
    severity: number(form.severity),
    appName: form.appName.trim(),
    hostname: form.hostname.trim(),
    checkpointMinutes: number(form.checkpointMinutes),
    startFrom: form.startFrom,
  }
  if (form.protocol === 'tls') {
    body.ca = form.ca.trim()
    body.verifyName = form.verifyName
    body.clientCert = form.clientCert.trim()
    if (form.clientKey.trim()) body.clientKey = form.clientKey
  }
  if (form.protocol === 'udp') body.maxDatagram = number(form.maxDatagram)
  return body
}

/** The facilities or severities the server names, as options sorted by their number. */
export const levelOptions = (levels = {}) =>
  Object.entries(levels)
    .sort((a, b) => a[1] - b[1])
    .map(([name, value]) => ({ value: String(value), label: `${value} · ${name}` }))

/**
 * How the forwarding stands, in one line: `{ color, text, detail }`.
 * `ago` as in chainStatus; `lasted` turns seconds into "12 minutes".
 */
export function forwardingStatus(found, ago = (iso) => iso, lasted = (seconds) => `${Math.round(seconds)} s`) {
  const state = found?.state
  const settings = found?.settings
  if (!state || !settings) return { color: 'slate', text: '', detail: '' }
  if (!state.destination && !settings.enabled) {
    return {
      color: 'slate',
      text: 'Not forwarded',
      detail:
        'The log exists on this server only. Whoever can change its database can remove the newest entries unseen: a receiver elsewhere is what shows it.',
    }
  }
  const waiting = state.backlog?.entries ?? 0
  const backlog =
    waiting === 0
      ? 'Nothing waits.'
      : `${waiting} ${waiting === 1 ? 'entry waits' : 'entries wait'}` +
        (state.backlog.seconds >= 1 ? `, the oldest for ${lasted(state.backlog.seconds)}.` : '.')
  const pending = state.pendingChange
    ? ' The change that was saved takes effect once the receiver set before it has heard of it.'
    : ''
  if (state.error) {
    return {
      color: 'red',
      text: `Not arriving${state.destination ? ` at ${state.destination}` : ''}`,
      detail: `${state.error}. Since ${ago(state.errorSince)}. ${backlog} They are sent in order when the receiver is back.${pending}`,
    }
  }
  if (!state.destination) {
    return {
      color: 'amber',
      text: 'Turned on, not taken up yet',
      detail:
        state.sends === 'off'
          ? 'The log is sent by the automation worker, which is off on this server.'
          : `The automation worker takes it up within seconds. ${backlog}`,
    }
  }
  return {
    color: waiting > 0 ? 'amber' : 'emerald',
    text: `Sent to ${state.destination}`,
    detail:
      `${backlog} ${state.sent} sent` +
      (state.sentAt ? `, the last ${ago(state.sentAt)}.` : '.') +
      (state.checkpointAt ? ` Last checkpoint ${ago(state.checkpointAt)}.` : '') +
      pending,
  }
}
