import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  backupStatus,
  backupTitle,
  isBusy,
  restoreSteps,
  scheduleText,
  settingsBody,
  settingsForm,
  settingsProblem,
  sizeText,
  typedName,
  whereText,
} from './backups.js'

const SETTINGS = {
  schedule: { enabled: true, every: 'day', hours: 6, at: '02:30', weekday: 6, timezone: 'UTC' },
  retention: { last: 7, weeks: 4, upgrades: 3 },
  warnAfterHours: 36,
  includeKey: false,
  destination: { kind: '' },
}

test('the form of the settings goes to the server as it came, and the secret only when typed', () => {
  const form = settingsForm(SETTINGS)
  assert.equal(form.secret, '')
  assert.equal(settingsProblem(form, SETTINGS), null)
  assert.deepEqual(settingsBody(form), { ...SETTINGS, destination: { kind: '' } })
  const copy = {
    ...form,
    copy: true,
    host: ' second.example ',
    user: 'nikbackup',
    path: '/srv/nik-backups',
    hostKey: 'ssh-ed25519 AAAA',
  }
  assert.equal(settingsProblem(copy, SETTINGS), 'Paste the private key of the account.')
  assert.equal(settingsProblem({ ...copy, auth: 'password' }, SETTINGS), 'Type the password of the account.')
  const sent = settingsBody({ ...copy, secret: 'PRIVATE' }).destination
  assert.deepEqual(sent, {
    kind: 'sftp',
    host: 'second.example',
    port: 22,
    user: 'nikbackup',
    auth: 'key',
    path: '/srv/nik-backups',
    hostKey: 'ssh-ed25519 AAAA',
    secret: 'PRIVATE',
  })
  // A secret the server already keeps is not asked for again, unless the way of signing in changes.
  const kept = { ...SETTINGS, destination: { kind: 'sftp', auth: 'key', secretSet: true } }
  assert.equal(settingsProblem(copy, kept), null)
  assert.equal('secret' in settingsBody(copy).destination, false)
  assert.equal(settingsProblem({ ...copy, auth: 'password' }, kept), 'Type the password of the account.')
})

test('what cannot be saved is said', () => {
  const form = settingsForm(SETTINGS)
  assert.match(settingsProblem({ ...form, at: '2:30' }, SETTINGS), /HH:MM/)
  assert.match(settingsProblem({ ...form, every: 'hours', hours: '0' }, SETTINGS), /from 1 to 23/)
  assert.equal(settingsProblem({ ...form, every: 'day', hours: '0' }, SETTINGS), null)
  assert.match(settingsProblem({ ...form, last: '' }, SETTINGS), /from 1 to 365/)
  assert.match(settingsProblem({ ...form, weeks: '-1' }, SETTINGS), /from 0 to 520/)
  assert.match(settingsProblem({ ...form, timezone: ' ' }, SETTINGS), /time zone/)
  assert.match(settingsProblem({ ...form, copy: true }, SETTINGS), /host/)
  assert.match(settingsProblem({ ...form, copy: true, host: 'h', user: 'u', path: 'p', port: '0' }, SETTINGS), /port/)
})

test('the schedule in words', () => {
  assert.equal(scheduleText(SETTINGS.schedule), 'Every day at 02:30 (UTC).')
  assert.equal(
    scheduleText({ ...SETTINGS.schedule, every: 'week', weekday: 6, timezone: 'Europe/Rome' }),
    'Every Sunday at 02:30 (Europe/Rome).',
  )
  assert.equal(
    scheduleText({ ...SETTINGS.schedule, every: 'hours', hours: 6 }),
    'Every 6 hours, counted from 02:30 (UTC).',
  )
  assert.match(scheduleText({ ...SETTINGS.schedule, enabled: false }), /schedule is off/)
})

test('the state of a backup', () => {
  const done = { state: 'done', verifyState: 'passed', verify: { checks: ['a', 'b'] } }
  assert.deepEqual(backupStatus(done), { text: 'verified', color: 'emerald', detail: 'a; b' })
  assert.equal(backupStatus({ state: 'queued' }).text, 'waiting')
  assert.equal(backupStatus({ state: 'running' }).text, 'being written')
  assert.deepEqual(backupStatus({ state: 'failed', error: 'no room' }), {
    text: 'failed',
    color: 'red',
    detail: 'no room',
  })
  const bad = { state: 'done', verifyState: 'failed', verify: { error: 'a row is missing' } }
  assert.deepEqual(backupStatus(bad), { text: 'failed its restore test', color: 'red', detail: 'a row is missing' })
  assert.equal(backupStatus({ state: 'done', verifyState: 'running' }).text, 'being tested')
  assert.equal(backupStatus({ state: 'done', verifyState: '' }).text, 'not tested')
  assert.equal(isBusy({ state: 'done', verifyState: 'queued' }), true)
  assert.equal(isBusy(done), false)
  assert.equal(isBusy({ state: 'running' }), true)
})

test('where a backup is', () => {
  assert.equal(whereText({ local: true, offsiteState: '' }), 'this server')
  const where = 'sftp://nik@second:22/b'
  assert.equal(
    whereText({ local: true, offsiteState: 'copied', offsite: { where } }),
    'this server and sftp://nik@second:22/b',
  )
  assert.equal(whereText({ local: false, offsiteState: 'copied', offsite: { where } }), where)
  assert.equal(whereText({ local: true, offsiteState: 'pending' }), 'this server (its copy waits)')
  assert.equal(whereText({ local: true, offsiteState: 'failed' }), 'this server (its copy failed)')
})

test('its title, its size, the name typed to delete it, and how to put it back', () => {
  assert.equal(backupTitle({ kind: 'full', label: '' }), 'Database and files')
  assert.equal(backupTitle({ kind: 'upgrade', label: '' }), 'Before an upgrade')
  assert.equal(backupTitle({ kind: 'upgrade', label: 'Before the upgrade from 6.6.0 to 6.7.0' }).slice(0, 6), 'Before')
  assert.equal(sizeText(0), '—')
  assert.match(sizeText(5 * 1024 * 1024), /5/)
  const backup = { id: 'nik-20261120-023000', kind: 'full' }
  assert.equal(typedName(' nik-20261120-023000 ', backup), true)
  assert.equal(typedName('nik-20261120', backup), false)
  assert.equal(typedName('', undefined), false)
  assert.equal(restoreSteps(backup).command, 'deploy/restore.sh nik-20261120-023000')
  assert.match(restoreSteps(backup).about, /asks for the backup passphrase/)
  const snapshot = { id: 'nik-upgrade-20261120-023000', kind: 'upgrade' }
  assert.equal(restoreSteps(snapshot).command, 'deploy/rollback.sh nik-upgrade-20261120-023000')
})
