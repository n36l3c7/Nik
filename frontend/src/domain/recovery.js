/*
 * Settings → Backup, "Recovery to a moment": what the screen says, and the form of its settings.
 *
 * The server archives the log of its database and takes a base backup on a
 * schedule, so that it can be brought back to any moment between the oldest
 * base backup and the last segment archived; a second host can receive a copy
 * of all of it (GET /recovery). Nothing here talks to the server: these are
 * the sentences and the checks, so that they can be tested without a browser.
 *
 * The server gives its times in two ways, an ISO text or seconds since 1970:
 * `moment` reads both. Every function that writes a date takes `when`, which
 * turns milliseconds into the text the screen shows.
 */

import { formatBytes } from './events.js'

export const NO_ARCHIVE =
  'This server keeps no archive of its database log, so it cannot be brought back to a moment. ' +
  'The archive is part of the Compose stack.'
export const NO_SECOND_HOST =
  'No second host: set a backup passphrase and a destination above. Until then the archive is on this server only.'
export const COMMAND_ABOUT =
  'Run it on the server, as the user that runs the stack. It asks before it replaces the database, and keeps ' +
  'the one that is there aside.'
export const PROMOTION_ABOUT =
  'Promoting a standby is a command on its host (deploy/standby.sh promote): nothing on this screen does it.'

const text = (value) => String(value ?? '').trim()
const whole = (value) => (/^\d+$/.test(text(value)) ? Number(text(value)) : NaN)
const many = (count, one, several = `${one}s`) => `${count} ${count === 1 ? one : several}`

/** A time of the server (ISO text, or seconds since 1970) as milliseconds; null when there is none. */
export function moment(value) {
  if (value === null || value === undefined || value === '') return null
  if (typeof value === 'number') return Number.isFinite(value) && value > 0 ? Math.round(value * 1000) : null
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : null
}

/** A length of time in words, as the health page writes it: "40 seconds", "12 minutes", "3 hours". */
export function lasted(seconds) {
  const length = Math.max(0, Number(seconds) || 0)
  for (const [unit, size] of [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
  ]) {
    if (length >= size) return many(Math.round(length / size), unit)
  }
  return many(Math.round(length), 'second')
}

/** A size; "nothing" for zero, since a dash would read as "not known". */
export function sizeText(bytes) {
  const amount = Number(bytes)
  if (!Number.isFinite(amount) || amount < 0) return '—'
  return amount === 0 ? 'nothing' : formatBytes(amount)
}

/** Which server this is: { text, replaced }. A replaced server must stay off: the screen says it loudly. */
export function roleText(found, when) {
  const pair = found?.pair ?? {}
  if (found?.role === 'superseded') {
    const by = pair.superseded?.by || 'the other host'
    const at = moment(pair.superseded?.at)
    return { text: at ? `Replaced on ${when(at)} by ${by}` : `Replaced by ${by}`, replaced: true }
  }
  const promoted = moment(pair.promotedAt)
  return { text: promoted ? `The server, promoted from standby on ${when(promoted)}` : 'The server', replaced: false }
}

/** What the other host answered when this server last asked whether it was replaced, or '' when it never asked. */
export function askedText(asked, when) {
  const at = moment(asked?.at)
  if (!at) return ''
  if (asked.reachable === false) return `The other host could not be asked on ${when(at)} whether it replaced this one.`
  return `The other host was last asked on ${when(at)}: this server was not replaced.`
}

/** The archive of the log in one line: { text, color }. `now` in milliseconds. */
export function archiveState(archive, now) {
  if (!archive?.on) return { text: 'Off', color: 'red' }
  if (archive.stuck) return { text: 'Stuck', color: 'red' }
  const last = moment(archive.lastAt)
  if (!last) return { text: 'On, no segment yet', color: 'amber' }
  return { text: `Last segment ${lasted((now - last) / 1000)} ago`, color: 'emerald' }
}

/** The segments PostgreSQL has finished and not archived yet. */
export function waitingText(archive) {
  const waiting = archive?.waiting ?? 0
  if (waiting <= 0) return 'No segment waits to be archived.'
  return `${many(waiting, 'segment waits', 'segments wait')} to be archived (${sizeText(archive.waitingBytes)}).`
}

/** The archive timeout, said as what it means. */
export function timeoutText(seconds) {
  if (!(seconds > 0))
    return 'A segment is closed only when it is full: what this host loses if it dies has no limit in time.'
  const every = lasted(seconds).replace(/^1 /, '')
  return (
    `A segment is closed at least every ${every}: the most that is lost if this host dies before its last ` +
    'segment left it.'
  )
}

/** The moments one can go back to. */
export function windowText(window, when) {
  const oldest = moment(window?.oldest)
  const newest = moment(window?.newest)
  if (!oldest) return 'No moment yet: there is no base backup.'
  if (!newest) return `You can go back to any moment from ${when(oldest)}.`
  return `You can go back to any moment from ${when(oldest)} to ${when(newest)}.`
}

/**
 * How far behind the second host is: { text, color, most }. `most` is the upper bound in bytes of
 * log, as a sentence, or ''.
 */
export function copiesState(copies, when) {
  if (!copies?.on) return { text: 'No second host', color: 'amber', most: '' }
  if (copies.hold === 'own')
    return { text: 'Nothing is sent: the copies point at this server itself', color: 'red', most: '' }
  if (copies.link?.ok === false) {
    const since = moment(copies.link.since)
    return { text: since ? `Not reached since ${when(since)}` : 'Not reached', color: 'red', most: '' }
  }
  const behind = copies.behind ?? {}
  if (behind.seconds === null || behind.seconds === undefined)
    return { text: 'Nothing sent yet', color: 'amber', most: '' }
  const most = behind.bytes > 0 ? `at most ${sizeText(behind.bytes)} of log` : ''
  if (behind.seconds < 1) return { text: 'Up to date', color: 'emerald', most }
  return { text: `${lasted(behind.seconds)} behind`, color: 'emerald', most }
}

/** The last segment that left for the second host. */
export function shippedText(copies, when) {
  const at = moment(copies?.shipped?.at)
  if (!copies?.shipped?.wal) return 'No segment sent yet.'
  const sent = copies.sent > 0 ? ` ${many(copies.sent, 'segment')} sent in all (${sizeText(copies.sentBytes)}).` : ''
  return `${copies.shipped.wal}${at ? `, sent on ${when(at)}` : ''}.${sent}`
}

/** The files of the store that are not on the second host yet. */
export function storeText(store) {
  const files = store?.files ?? 0
  const copied = many(store?.copied ?? 0, 'file')
  if (files <= 0) return `No file of the store waits (${copied} copied).`
  return `${many(files, 'file of the store waits', 'files of the store wait')} to be copied (${sizeText(store.bytes)}); ${copied} copied.`
}

/** Whether the second host was reached at the last pass. */
export function linkText(link, when) {
  if (!link) return 'Not tried yet.'
  if (link.ok === false) {
    const since = moment(link.since)
    return `Not reached${since ? ` since ${when(since)}` : ''}${link.error ? `: ${link.error}` : '.'}`
  }
  const at = moment(link.okAt)
  return at ? `Reached on ${when(at)}.` : 'Reached.'
}

/** The recovery service, which takes the base backups and runs the tests. */
export function serviceText(service) {
  if (service?.running) return 'The recovery service answers.'
  if (service?.alive === null || service?.alive === undefined) return 'The recovery service has never answered.'
  return `The recovery service does not answer: it was last heard ${lasted(service.alive)} ago.`
}

/** The state of a base backup as a badge: { text, color, detail }. */
export function baseStatus(base) {
  if (base.state === 'requested')
    return { text: 'being taken', color: 'cyan', detail: 'The recovery service is writing it.' }
  if (base.state === 'failed') return { text: 'failed', color: 'red', detail: base.error || '' }
  const took = Number.isFinite(base.seconds) ? `Taken in ${lasted(base.seconds)}.` : ''
  return { text: 'done', color: 'emerald', detail: took }
}

/** Whether a base backup was read again and compared with its manifest. */
export function checkedText(base) {
  if (base.state !== 'done') return '—'
  return base.verified ? 'Yes' : 'Not checked'
}

/** Where the copy of a base backup stands. */
export function baseCopyText(base, when) {
  const copy = base.offsite ?? {}
  if (base.offsiteState === 'copied') {
    const at = moment(copy.at)
    return `On ${copy.where || 'the second host'}${at ? `, since ${when(at)}` : ''}`
  }
  if (base.offsiteState === 'pending') return 'Waits to be sent'
  if (base.offsiteState === 'failed') return `Not sent${copy.error ? `: ${copy.error}` : ''}`
  return base.local ? 'On this server only' : '—'
}

/** Whether something is being done, so that the screen is read again soon. */
export const isWorking = (found) =>
  Boolean(found?.test?.running) || (found?.bases ?? []).some((base) => base.state === 'requested')

/**
 * The recovery test: { proven, failed, color }. `proven` is the sentence of the last test that
 * passed; `failed` the sentence of the last one when it failed after that, or null.
 */
export function testState(test, when) {
  const proven = test?.proven
  const last = test?.last
  const failed =
    last?.state === 'failed'
      ? `The last test failed${moment(last.at) ? ` on ${when(moment(last.at))}` : ''}: ${last.error || 'no reason was given'}`
      : null
  if (!proven) return { proven: 'Not proven yet', failed, color: failed ? 'red' : 'amber' }
  const took = Number.isFinite(proven.seconds) ? ` (took ${lasted(proven.seconds)})` : ''
  return {
    proven: `Recovery to ${when(moment(proven.target))} proven on ${when(moment(proven.at))}${took}`,
    failed,
    color: failed ? 'red' : 'emerald',
  }
}

/** What the archive takes on its volume, as rows { label, value }. */
export function diskRows(disk) {
  const files = (count) => (count > 0 ? ` in ${many(count, 'file')}` : '')
  const rows = [
    { label: 'The log', value: `${sizeText(disk?.wal)}${files(disk?.walFiles)}` },
    { label: 'The base backups', value: sizeText(disk?.base) },
    { label: 'Deleted files, kept for recovery', value: `${sizeText(disk?.kept)}${files(disk?.keptFiles)}` },
  ]
  if (disk?.total > 0)
    rows.push({ label: 'Room left', value: `${sizeText(disk.free)} free of ${sizeText(disk.total)}` })
  return rows
}

/** What the archive will take once it has run for the days it keeps. */
export function estimateText(disk, keepDays) {
  if (!(disk?.steady > 0)) return 'How much the archive will take is known once a base backup has been taken.'
  const rate = disk.perDay > 0 ? `, at ${sizeText(disk.perDay)} of log a day` : ''
  return `About ${sizeText(disk.steady)} once it has run for the ${many(keepDays, 'day')} it keeps${rate}.`
}

/** The form of the settings, as strings a person edits, from what the server keeps. */
export function recoveryForm(settings) {
  const base = settings?.base ?? {}
  return {
    enabled: Boolean(base.enabled),
    every: base.every ?? 'day',
    hours: String(base.hours ?? 12),
    at: base.at ?? '03:30',
    weekday: String(base.weekday ?? 6),
    timezone: base.timezone ?? 'UTC',
    keepDays: String(settings?.keepDays ?? 2),
    lagMinutes: String(settings?.lagMinutes ?? 15),
    testEveryHours: String(settings?.testEveryHours ?? 24),
    name: settings?.name ?? '',
  }
}

/** Why the form cannot be saved, as a sentence, or null. */
export function recoveryProblem(form) {
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(text(form.at))) return 'The time is written HH:MM, from 00:00 to 23:59.'
  if (form.every === 'hours' && !(whole(form.hours) >= 1 && whole(form.hours) <= 23))
    return 'The number of hours between two base backups is from 1 to 23.'
  if (!text(form.timezone)) return 'Name a time zone: UTC, Europe/Rome…'
  if (!(whole(form.keepDays) >= 1 && whole(form.keepDays) <= 60))
    return 'The number of days one can go back is from 1 to 60.'
  if (!(whole(form.lagMinutes) >= 2 && whole(form.lagMinutes) <= 1440))
    return 'The delay of the second host that is warned about is from 2 to 1440 minutes.'
  if (!(whole(form.testEveryHours) >= 1 && whole(form.testEveryHours) <= 720))
    return 'The hours between two recovery tests are from 1 to 720.'
  if (text(form.name).length > 120) return 'The name of this server is at most 120 characters.'
  return null
}

/**
 * What PUT /recovery/settings is sent for a form: only what differs from what the server keeps.
 * The schedule goes whole when any part of it changed. An empty object: nothing to save.
 */
export function recoveryBody(form, settings) {
  const before = recoveryForm(settings)
  const body = {}
  if (['enabled', 'every', 'hours', 'at', 'weekday', 'timezone'].some((key) => form[key] !== before[key])) {
    body.base = {
      enabled: form.enabled,
      every: form.every,
      // A field that is not shown keeps what the server has.
      hours: whole(form.hours) >= 1 ? whole(form.hours) : (settings?.base?.hours ?? 12),
      at: text(form.at),
      weekday: whole(form.weekday) || 0,
      timezone: text(form.timezone),
    }
  }
  for (const key of ['keepDays', 'lagMinutes', 'testEveryHours']) {
    if (text(form[key]) !== before[key]) body[key] = whole(form[key])
  }
  if (text(form.name) !== text(before.name)) body.name = text(form.name)
  return body
}
