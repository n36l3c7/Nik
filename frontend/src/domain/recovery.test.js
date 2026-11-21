import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  archiveState,
  askedText,
  baseCopyText,
  baseStatus,
  checkedText,
  copiesState,
  diskRows,
  estimateText,
  isWorking,
  lasted,
  linkText,
  moment,
  recoveryBody,
  recoveryForm,
  recoveryProblem,
  roleText,
  serviceText,
  shippedText,
  sizeText,
  storeText,
  testState,
  timeoutText,
  waitingText,
  windowText,
} from './recovery.js'

// Dates as the tests read them, whatever the time zone of the machine.
const when = (ms) => new Date(ms).toISOString().slice(0, 16).replace('T', ' ')
const NOW = Date.parse('2026-11-21T14:15:25Z')

// The server of a pair, as GET /recovery answers for it.
const FOUND = {
  available: true,
  name: 'host-b',
  role: 'primary',
  pair: {
    generation: 4,
    promotedAt: '2026-11-21T14:02:45.308733+00:00',
    promotedBy: 'host-b',
    superseded: null,
    asked: { at: 1795270513.731526, reachable: true, verdict: 'none' },
  },
  archive: {
    mode: 'on',
    on: true,
    stuck: false,
    lastWal: '0000000400000000000000B3',
    lastAt: '2026-11-21T14:15:09.594005+00:00',
    failedWal: '',
    failedAt: null,
    waiting: 0,
    waitingBytes: 0,
    logBytes: 352322085,
    timeline: 4,
    timeout: 20,
  },
  window: { oldest: '2026-11-21T13:47:52+00:00', newest: '2026-11-21T14:15:09.594005+00:00' },
  bases: [
    {
      id: 'base-20261121-140306',
      state: 'done',
      createdAt: '2026-11-21T14:03:06.947156+00:00',
      finishedAt: '2026-11-21T14:03:12.027794+00:00',
      size: 5650885,
      verified: true,
      seconds: 1,
      error: '',
      requestedBy: 'schedule',
      local: true,
      offsiteState: 'copied',
      offsite: {
        where: 'sftp://nik@second:22/copies/recovery',
        at: '2026-11-21T14:04:17.565762+00:00',
        bytes: 5360046,
      },
    },
  ],
  test: {
    running: true,
    last: {
      state: 'failed',
      at: '2026-11-21T14:07:58.475344+00:00',
      target: '2026-11-21T13:51:54.105421+00:00',
      base: 'base-20261121-131323',
      seconds: 0,
      auditSeq: null,
      error: 'The recovery service did not answer: is the `recovery` container running?',
    },
    proven: {
      state: 'passed',
      at: '2026-11-21T13:49:28.145132+00:00',
      target: '2026-11-21T13:48:13.471882+00:00',
      base: 'base-20261121-134752',
      seconds: 4,
      auditSeq: 127,
      error: '',
    },
  },
  disk: {
    wal: 3301258,
    walFiles: 52,
    base: 11288284,
    total: 1081101176832,
    free: 997091119104,
    kept: 0,
    keptFiles: 0,
    perDay: 79230192,
    steady: 254643231,
  },
  service: { alive: 413.48680663108826, running: false },
  copies: {
    on: true,
    where: 'sftp://nik@second:22/copies/recovery',
    shipped: { wal: '0000000400000000000000B3', closedAt: 1795270509.5639508, at: 1795270514.0915623, bytes: 6072 },
    link: { ok: true, okAt: 1795270513.731526, error: '', since: null },
    hold: null,
    sent: 287,
    sentBytes: 5765897,
    behind: { seconds: 16.922855854034424, bytes: 16008, safeUntil: 1795270509.5639508 },
    store: { files: 0, bytes: 0, copied: 3 },
  },
  settings: {
    base: { enabled: true, every: 'day', hours: 12, at: '03:30', weekday: 6, timezone: 'UTC' },
    keepDays: 2,
    lagMinutes: 15,
    testEveryHours: 24,
    name: '',
  },
}

test('a time of the server is read whether it is an ISO text or seconds', () => {
  assert.equal(moment('2026-11-21T14:15:09.594005+00:00'), Date.parse('2026-11-21T14:15:09.594Z'))
  assert.equal(moment(1795270513.731526), 1795270513732)
  assert.equal(when(moment(1795270513.731526)), '2026-11-21 14:15')
  for (const nothing of [null, undefined, '', 0, 'not a date']) assert.equal(moment(nothing), null)
})

test('a length of time and a size are said in words', () => {
  assert.equal(lasted(0.4), '0 seconds')
  assert.equal(lasted(1), '1 second')
  assert.equal(lasted(59), '59 seconds')
  assert.equal(lasted(60), '1 minute')
  assert.equal(lasted(720), '12 minutes')
  assert.equal(lasted(3 * 3600), '3 hours')
  assert.equal(lasted(5 * 86400), '5 days')
  assert.equal(sizeText(0), 'nothing')
  assert.equal(sizeText(16008), '15.6 KB')
  assert.equal(sizeText(undefined), '—')
})

test('the role line says which server this is', () => {
  assert.deepEqual(roleText(FOUND, when), {
    text: 'The server, promoted from standby on 2026-11-21 14:02',
    replaced: false,
  })
  assert.deepEqual(roleText({ role: 'primary', pair: { generation: 1, promotedAt: null } }, when), {
    text: 'The server',
    replaced: false,
  })
  const replaced = {
    role: 'superseded',
    pair: { generation: 4, superseded: { at: 1795270513.7, by: 'host-a', generation: 5 } },
  }
  assert.deepEqual(roleText(replaced, when), { text: 'Replaced on 2026-11-21 14:15 by host-a', replaced: true })
  assert.equal(roleText({ role: 'superseded', pair: {} }, when).text, 'Replaced by the other host')
})

test('what the other host answered when it was last asked', () => {
  assert.equal(
    askedText(FOUND.pair.asked, when),
    'The other host was last asked on 2026-11-21 14:15: this server was not replaced.',
  )
  assert.equal(
    askedText({ at: 1795270513.7, reachable: false, error: 'timed out' }, when),
    'The other host could not be asked on 2026-11-21 14:15 whether it replaced this one.',
  )
  assert.equal(askedText(null, when), '')
})

test('the archive is off, stuck, or says how old its last segment is', () => {
  assert.deepEqual(archiveState(FOUND.archive, NOW), { text: 'Last segment 15 seconds ago', color: 'emerald' })
  assert.deepEqual(archiveState(FOUND.archive, NOW + 12 * 60_000), {
    text: 'Last segment 12 minutes ago',
    color: 'emerald',
  })
  assert.deepEqual(archiveState({ ...FOUND.archive, stuck: true }, NOW), { text: 'Stuck', color: 'red' })
  assert.deepEqual(archiveState({ ...FOUND.archive, on: false, mode: 'off' }, NOW), { text: 'Off', color: 'red' })
  assert.deepEqual(archiveState({ on: true, stuck: false, lastAt: null }, NOW), {
    text: 'On, no segment yet',
    color: 'amber',
  })
})

test('the segments that wait and the archive timeout', () => {
  assert.equal(waitingText(FOUND.archive), 'No segment waits to be archived.')
  assert.equal(waitingText({ waiting: 1, waitingBytes: 16777216 }), '1 segment waits to be archived (16.0 MB).')
  assert.equal(waitingText({ waiting: 3, waitingBytes: 50331648 }), '3 segments wait to be archived (48.0 MB).')
  assert.match(timeoutText(20), /^A segment is closed at least every 20 seconds: the most that is lost/)
  assert.match(timeoutText(60), /^A segment is closed at least every minute: /)
  assert.match(timeoutText(300), /^A segment is closed at least every 5 minutes: /)
  assert.match(timeoutText(0), /^A segment is closed only when it is full/)
})

test('the moments one can go back to', () => {
  assert.equal(
    windowText(FOUND.window, when),
    'You can go back to any moment from 2026-11-21 13:47 to 2026-11-21 14:15.',
  )
  assert.equal(windowText({ oldest: null, newest: null }, when), 'No moment yet: there is no base backup.')
  assert.equal(windowText(undefined, when), 'No moment yet: there is no base backup.')
})

test('the delay of the second host', () => {
  assert.deepEqual(copiesState(FOUND.copies, when), {
    text: '17 seconds behind',
    color: 'emerald',
    most: 'at most 15.6 KB of log',
  })
  const quiet = { ...FOUND.copies, behind: { seconds: 0, bytes: 0, safeUntil: 1795270509 } }
  assert.deepEqual(copiesState(quiet, when), { text: 'Up to date', color: 'emerald', most: '' })
  const unreached = { ...FOUND.copies, link: { ok: false, okAt: 1795270000, error: 'refused', since: 1795270513.7 } }
  assert.equal(copiesState(unreached, when).text, 'Not reached since 2026-11-21 14:15')
  assert.equal(copiesState(unreached, when).color, 'red')
  assert.equal(
    copiesState({ ...FOUND.copies, hold: 'own' }, when).text,
    'Nothing is sent: the copies point at this server itself',
  )
  const fresh = { ...FOUND.copies, shipped: null, link: null, behind: { seconds: null, bytes: null, safeUntil: null } }
  assert.equal(copiesState(fresh, when).text, 'Nothing sent yet')
  assert.equal(copiesState({ on: false, where: '' }, when).text, 'No second host')
  // Across a change of timeline the bytes cannot be counted: the time alone is said.
  const across = { ...FOUND.copies, behind: { seconds: 90, bytes: null, safeUntil: 1 } }
  assert.deepEqual(copiesState(across, when), { text: '2 minutes behind', color: 'emerald', most: '' })
})

test('what was sent to the second host, the files of the store, the link', () => {
  assert.equal(
    shippedText(FOUND.copies, when),
    '0000000400000000000000B3, sent on 2026-11-21 14:15. 287 segments sent in all (5.5 MB).',
  )
  assert.equal(shippedText({ on: true, shipped: null }, when), 'No segment sent yet.')
  assert.equal(storeText(FOUND.copies.store), 'No file of the store waits (3 files copied).')
  assert.equal(
    storeText({ files: 2, bytes: 2048, copied: 1 }),
    '2 files of the store wait to be copied (2.0 KB); 1 file copied.',
  )
  assert.equal(linkText(FOUND.copies.link, when), 'Reached on 2026-11-21 14:15.')
  assert.equal(
    linkText({ ok: false, error: 'Connection refused', since: 1795270513.7 }, when),
    'Not reached since 2026-11-21 14:15: Connection refused',
  )
  assert.equal(linkText(null, when), 'Not tried yet.')
})

test('the recovery service answers or says since when it does not', () => {
  assert.equal(serviceText({ alive: 3, running: true }), 'The recovery service answers.')
  assert.equal(serviceText(FOUND.service), 'The recovery service does not answer: it was last heard 7 minutes ago.')
  assert.equal(serviceText({ alive: null, running: false }), 'The recovery service has never answered.')
})

test('a base backup: its state, whether it was checked, where its copy stands', () => {
  const [base] = FOUND.bases
  assert.deepEqual(baseStatus(base), { text: 'done', color: 'emerald', detail: 'Taken in 1 second.' })
  assert.equal(baseStatus({ ...base, seconds: null }).detail, '')
  assert.equal(checkedText(base), 'Yes')
  assert.equal(checkedText({ ...base, verified: false }), 'Not checked')
  assert.equal(baseCopyText(base, when), 'On sftp://nik@second:22/copies/recovery, since 2026-11-21 14:04')

  const asked = { id: 'base-1', state: 'requested', verified: false, local: false, offsiteState: '', offsite: {} }
  assert.equal(baseStatus(asked).text, 'being taken')
  assert.equal(checkedText(asked), '—')
  assert.equal(baseCopyText(asked, when), '—')

  const failed = { ...asked, state: 'failed', error: 'No room left on the archive volume' }
  assert.deepEqual(baseStatus(failed), { text: 'failed', color: 'red', detail: 'No room left on the archive volume' })

  assert.equal(baseCopyText({ ...base, offsiteState: 'pending', offsite: {} }, when), 'Waits to be sent')
  assert.equal(
    baseCopyText({ ...base, offsiteState: 'failed', offsite: { error: 'refused' } }, when),
    'Not sent: refused',
  )
  assert.equal(baseCopyText({ ...base, offsiteState: '', offsite: {} }, when), 'On this server only')
})

test('the page is read again while a base backup is taken or a test runs', () => {
  assert.equal(isWorking(FOUND), true)
  assert.equal(isWorking({ ...FOUND, test: { ...FOUND.test, running: false } }), false)
  assert.equal(isWorking({ test: { running: false }, bases: [{ state: 'requested' }] }), true)
  assert.equal(isWorking({ available: false }), false)
})

test('the recovery test: proven, failed since, or not proven yet', () => {
  assert.deepEqual(testState(FOUND.test, when), {
    proven: 'Recovery to 2026-11-21 13:48 proven on 2026-11-21 13:49 (took 4 seconds)',
    failed:
      'The last test failed on 2026-11-21 14:07: The recovery service did not answer: is the `recovery` container running?',
    color: 'red',
  })
  assert.deepEqual(testState({ running: false, last: FOUND.test.proven, proven: FOUND.test.proven }, when), {
    proven: 'Recovery to 2026-11-21 13:48 proven on 2026-11-21 13:49 (took 4 seconds)',
    failed: null,
    color: 'emerald',
  })
  assert.deepEqual(testState({ running: false, last: null, proven: null }, when), {
    proven: 'Not proven yet',
    failed: null,
    color: 'amber',
  })
  const never = testState({ running: false, last: { state: 'failed', at: null, error: '' }, proven: null }, when)
  assert.equal(never.proven, 'Not proven yet')
  assert.equal(never.failed, 'The last test failed: no reason was given')
})

test('what the archive takes, and what it will take', () => {
  assert.deepEqual(diskRows(FOUND.disk), [
    { label: 'The log', value: '3.1 MB in 52 files' },
    { label: 'The base backups', value: '10.8 MB' },
    { label: 'Deleted files, kept for recovery', value: 'nothing' },
    { label: 'Room left', value: '928.6 GB free of 1006.9 GB' },
  ])
  assert.equal(diskRows({ wal: 0, base: 0, kept: 2048, keptFiles: 1 })[2].value, '2.0 KB in 1 file')
  assert.equal(
    estimateText(FOUND.disk, 2),
    'About 242.8 MB once it has run for the 2 days it keeps, at 75.6 MB of log a day.',
  )
  assert.equal(estimateText({ ...FOUND.disk, perDay: 0 }, 1), 'About 242.8 MB once it has run for the 1 day it keeps.')
  assert.equal(
    estimateText({ perDay: null, steady: null }, 2),
    'How much the archive will take is known once a base backup has been taken.',
  )
})

test('the form of the settings sends only what changed', () => {
  const form = recoveryForm(FOUND.settings)
  assert.equal(recoveryProblem(form), null)
  assert.deepEqual(recoveryBody(form, FOUND.settings), {})
  assert.deepEqual(recoveryBody({ ...form, keepDays: ' 7 ' }, FOUND.settings), { keepDays: 7 })
  assert.deepEqual(recoveryBody({ ...form, lagMinutes: '30', name: ' host-b ' }, FOUND.settings), {
    lagMinutes: 30,
    name: 'host-b',
  })
  assert.deepEqual(recoveryBody({ ...form, testEveryHours: '12' }, FOUND.settings), { testEveryHours: 12 })
  // The schedule goes whole, and nothing else with it.
  assert.deepEqual(recoveryBody({ ...form, every: 'week', weekday: '0', at: '04:00' }, FOUND.settings), {
    base: { enabled: true, every: 'week', hours: 12, at: '04:00', weekday: 0, timezone: 'UTC' },
  })
  assert.deepEqual(recoveryBody({ ...form, enabled: false }, FOUND.settings).base.enabled, false)
  // Spaces around a name are not a change.
  assert.deepEqual(recoveryBody({ ...form, name: '  ' }, FOUND.settings), {})
})

test('the form of the settings says what cannot be saved', () => {
  const form = recoveryForm(FOUND.settings)
  assert.equal(recoveryProblem({ ...form, at: '24:00' }), 'The time is written HH:MM, from 00:00 to 23:59.')
  assert.equal(
    recoveryProblem({ ...form, every: 'hours', hours: '24' }),
    'The number of hours between two base backups is from 1 to 23.',
  )
  // The hours are not looked at while the schedule is not in hours.
  assert.equal(recoveryProblem({ ...form, hours: 'x' }), null)
  assert.equal(recoveryBody({ ...form, hours: 'x' }, FOUND.settings).base.hours, 12)
  assert.equal(recoveryProblem({ ...form, timezone: ' ' }), 'Name a time zone: UTC, Europe/Rome…')
  for (const days of ['0', '61', '', '2.5', 'two'])
    assert.equal(recoveryProblem({ ...form, keepDays: days }), 'The number of days one can go back is from 1 to 60.')
  for (const minutes of ['1', '1441'])
    assert.equal(
      recoveryProblem({ ...form, lagMinutes: minutes }),
      'The delay of the second host that is warned about is from 2 to 1440 minutes.',
    )
  for (const hours of ['0', '721'])
    assert.equal(
      recoveryProblem({ ...form, testEveryHours: hours }),
      'The hours between two recovery tests are from 1 to 720.',
    )
  assert.equal(
    recoveryProblem({ ...form, name: 'x'.repeat(121) }),
    'The name of this server is at most 120 characters.',
  )
  assert.equal(recoveryProblem({ ...form, keepDays: '60', lagMinutes: '1440', testEveryHours: '720' }), null)
})

test('a server that was never set starts from the defaults of the server', () => {
  assert.deepEqual(recoveryForm(undefined), {
    enabled: false,
    every: 'day',
    hours: '12',
    at: '03:30',
    weekday: '6',
    timezone: 'UTC',
    keepDays: '2',
    lagMinutes: '15',
    testEveryHours: '24',
    name: '',
  })
})
