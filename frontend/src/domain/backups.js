/*
 * Settings → Backup: what the screen says of a backup, and the form of the settings.
 *
 * The server takes the backups, tests each one by restoring it, and sends a
 * copy off the server (GET /backups). Nothing here talks to it: these are the
 * sentences and the checks, so that they can be tested without a browser.
 */

import { formatBytes } from './events.js'

export const WEEKDAYS = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
export const EVERY = [
  { value: 'day', label: 'Every day' },
  { value: 'week', label: 'Every week' },
  { value: 'hours', label: 'Every few hours' },
]
export const PASSPHRASE_WARNING =
  'Write it down and keep it away from this server. A backup can only be read with the passphrase it was made ' +
  'with: if it is lost, every backup made under it is lost with it. Nobody can recover it, Nik included.'
export const INCLUDE_KEY_WARNING =
  'With the key inside, a backup and its passphrase are enough to read every stored secret (the keys of ' +
  'instances, the credentials). Without it, the key (in .env, or in the secrets directory) must be kept ' +
  'somewhere else, or those secrets have to be entered again after a restore. The store key is never put ' +
  'in a backup: a restore needs none but its own.'

const text = (value) => String(value ?? '').trim()
const whole = (value) => (/^\d+$/.test(text(value)) ? Number(text(value)) : NaN)

export function sizeText(bytes) {
  return Number.isFinite(bytes) && bytes > 0 ? formatBytes(bytes) : '—'
}

/** The form of the settings, as strings a person edits, from what the server keeps. */
export function settingsForm(settings) {
  const schedule = settings?.schedule ?? {}
  const retention = settings?.retention ?? {}
  const destination = settings?.destination ?? {}
  return {
    enabled: Boolean(schedule.enabled),
    every: schedule.every ?? 'hours',
    hours: String(schedule.hours ?? 6),
    at: schedule.at ?? '02:30',
    weekday: String(schedule.weekday ?? 6),
    timezone: schedule.timezone ?? 'UTC',
    last: String(retention.last ?? 8),
    weeks: String(retention.weeks ?? 4),
    upgrades: String(retention.upgrades ?? 3),
    warnAfterHours: String(settings?.warnAfterHours ?? 13),
    includeKey: Boolean(settings?.includeKey),
    copy: destination.kind === 'sftp',
    host: destination.host ?? '',
    port: String(destination.port ?? 22),
    user: destination.user ?? '',
    auth: destination.auth ?? 'key',
    path: destination.path ?? '',
    hostKey: destination.hostKey ?? '',
    // Never sent back by the server: typed to set it or to replace it.
    secret: '',
  }
}

/** Why the form cannot be saved, as a sentence, or null. */
export function settingsProblem(form, settings) {
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(text(form.at))) return 'The time is written HH:MM, from 00:00 to 23:59.'
  if (form.every === 'hours' && !(whole(form.hours) >= 1 && whole(form.hours) <= 23))
    return 'The number of hours between two backups is from 1 to 23.'
  if (!text(form.timezone)) return 'Name a time zone: UTC, Europe/Rome…'
  if (!(whole(form.last) >= 1 && whole(form.last) <= 365)) return 'The number of backups kept is from 1 to 365.'
  if (!(whole(form.weeks) >= 0 && whole(form.weeks) <= 520)) return 'The number of weeks is from 0 to 520.'
  if (!(whole(form.upgrades) >= 1 && whole(form.upgrades) <= 50))
    return 'The number of snapshots kept from before upgrades is from 1 to 50.'
  if (!(whole(form.warnAfterHours) >= 1)) return 'The age that is warned about is a number of hours.'
  if (form.copy) {
    if (!text(form.host)) return 'Name the host the copies go to.'
    if (!text(form.user)) return 'Name the account on that host.'
    if (!text(form.path)) return 'Name the directory on that host.'
    if (!(whole(form.port) >= 1 && whole(form.port) <= 65535)) return 'The port is from 1 to 65535.'
    const kept = settings?.destination?.kind === 'sftp' && settings.destination.auth === form.auth
    if (!form.secret && !(kept && settings.destination.secretSet))
      return form.auth === 'key' ? 'Paste the private key of the account.' : 'Type the password of the account.'
  }
  return null
}

/** What PUT /backups/settings is sent for a form. The secret goes only when it was typed. */
export function settingsBody(form) {
  const destination = form.copy
    ? {
        kind: 'sftp',
        host: text(form.host),
        port: whole(form.port),
        user: text(form.user),
        auth: form.auth,
        path: text(form.path),
        hostKey: text(form.hostKey),
        ...(form.secret ? { secret: form.secret } : {}),
      }
    : { kind: '' }
  return {
    schedule: {
      enabled: form.enabled,
      every: form.every,
      hours: whole(form.hours) || 6,
      at: text(form.at),
      weekday: whole(form.weekday) || 0,
      timezone: text(form.timezone),
    },
    retention: { last: whole(form.last), weeks: whole(form.weeks), upgrades: whole(form.upgrades) },
    warnAfterHours: whole(form.warnAfterHours),
    includeKey: form.includeKey,
    destination,
  }
}

/**
 * The room the backups take, in two sentences: what is kept now, and what the settings of the form
 * lead to. A backup copies the whole store each time, so the estimate is the number of backups the
 * retention keeps (the latest ones, and one for each week) times the size of the last good one.
 * `space` is { kept, count, lastGood } in bytes (GET /backups); returns { now, then }.
 */
export function spaceText(space, form) {
  const count = space?.count ?? 0
  const now =
    count === 0
      ? 'No backup is kept yet.'
      : `${count} ${count === 1 ? 'backup is' : 'backups are'} kept now: ${sizeText(space.kept)}.`
  const last = whole(form.last)
  const weeks = whole(form.weeks)
  if (!(space?.lastGood > 0)) {
    return { now, then: 'How much these settings will take is known once a backup has been taken.' }
  }
  if (!(last >= 1) || !(weeks >= 0)) return { now, then: '' }
  const most = last + weeks
  return {
    now,
    then:
      `With these settings up to ${most} are kept (${last} and one for each of ${weeks} ` +
      `${weeks === 1 ? 'week' : 'weeks'}): about ${sizeText(most * space.lastGood)} at the size of the last one ` +
      `(${sizeText(space.lastGood)}), and room for one more while it is written.`,
  }
}

/** The schedule, in words: "Every day at 02:30 (UTC)". */
export function scheduleText(schedule) {
  if (!schedule?.enabled) return 'The schedule is off: backups are taken only when asked for.'
  const zone = schedule.timezone || 'UTC'
  if (schedule.every === 'week') return `Every ${WEEKDAYS[schedule.weekday] ?? 'week'} at ${schedule.at} (${zone}).`
  if (schedule.every === 'hours')
    return `Every ${schedule.hours} ${schedule.hours === 1 ? 'hour' : 'hours'}, counted from ${schedule.at} (${zone}).`
  return `Every day at ${schedule.at} (${zone}).`
}

/** Whether something is being done for this backup, so that the list is read again soon. */
export const isBusy = (backup) =>
  ['queued', 'running'].includes(backup?.state) || ['queued', 'running'].includes(backup?.verifyState)

/** The state of a backup as a badge: { text, color, detail }. */
export function backupStatus(backup) {
  if (backup.state === 'queued') return { text: 'waiting', color: 'slate', detail: 'It starts within a few seconds.' }
  if (backup.state === 'running') return { text: 'being written', color: 'cyan', detail: '' }
  if (backup.state === 'failed') return { text: 'failed', color: 'red', detail: backup.error || '' }
  if (backup.verifyState === 'passed') {
    const checks = backup.verify?.checks ?? []
    return { text: 'verified', color: 'emerald', detail: checks.join('; ') }
  }
  if (backup.verifyState === 'failed')
    return { text: 'failed its restore test', color: 'red', detail: backup.verify?.error || '' }
  if (backup.verifyState === 'queued' || backup.verifyState === 'running')
    return { text: 'being tested', color: 'cyan', detail: 'It is restored into a scratch database and compared.' }
  return { text: 'not tested', color: 'amber', detail: 'Its restore test has not run.' }
}

/** Where a backup is: on the server, off it, both. */
export function whereText(backup) {
  const copied = backup.offsiteState === 'copied'
  const places = []
  if (backup.local) places.push('this server')
  if (copied) places.push(backup.offsite?.where || 'the other server')
  let said = places.length ? places.join(' and ') : '—'
  if (backup.offsiteState === 'pending') said += ' (its copy waits)'
  if (backup.offsiteState === 'failed') said += ' (its copy failed)'
  return said
}

/** What a backup is called in the list: its label, or what kind it is. */
export function backupTitle(backup) {
  if (backup.label) return backup.label
  return backup.kind === 'upgrade' ? 'Before an upgrade' : 'Database and files'
}

/** Whether what was typed is the name of the backup: what its deletion asks for. */
export const typedName = (typed, backup) => text(typed) === backup?.id

/**
 * How to put a backup back: the lines an operator types on the server, and what they do.
 * A snapshot taken before an upgrade is put back with the rollback, which also says which
 * version of the code goes with it.
 */
export function restoreSteps(backup) {
  if (backup.kind === 'upgrade') {
    return {
      command: `deploy/rollback.sh ${backup.id}`,
      about:
        'Run on the server, from the folder of Nik. It stops the stack, puts the database back as it was before ' +
        'the upgrade, tells which version of the code goes with it, starts the stack and checks that it answers. ' +
        'The files are not touched: an upgrade does not change them.',
    }
  }
  return {
    command: `deploy/restore.sh ${backup.id}`,
    about:
      'Run on the server, from the folder of Nik, with the stack stopped; on a new host, after copying the file ' +
      'there. It asks for the backup passphrase, reads the whole file before it changes anything, and refuses a ' +
      'database or a store that is not empty unless --replace is added.',
  }
}
