import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  appliedText,
  applyText,
  choiceLabel,
  directionText,
  DIRECTIONS,
  mirrorAbilities,
  mirrorChoiceProblem,
  mirrorChoices,
  mirrorTimes,
  originText,
  fetchChanged,
  fetchForm,
  fetchPayload,
  fetchProblem,
  firstFetchSeconds,
  intervalText,
  jobText,
  lookbackHint,
  resetText,
  lastText,
  limitText,
  mirrorProblem,
  needingCare,
  nextText,
  outcomeBadge,
  stateBadge,
} from './fetch.js'

const NOW = Date.parse('2026-11-17T10:00:00Z')

test('the state of a connection that can fetch', () => {
  assert.deepEqual(stateBadge({ state: 'ok' }), { label: 'fetching', color: 'emerald' })
  assert.equal(stateBadge({ state: 'failing' }).color, 'red')
  assert.equal(stateBadge({ state: 'paused' }).label, 'paused')
  assert.equal(stateBadge({ state: 'off' }).label, 'off')
  assert.equal(stateBadge(null).label, 'off')
  assert.deepEqual(
    needingCare([{ state: 'ok' }, { state: 'failing', id: 1 }, { state: 'off' }, { state: 'paused', id: 2 }]).map(
      (connection) => connection.id,
    ),
    [1, 2],
  )
})

test('what the last cycle found, and when the next is', () => {
  assert.equal(lastText({}), '')
  assert.equal(lastText({ last: { fetched: 0, new: 0 } }), 'nothing new')
  assert.equal(
    lastText({ last: { fetched: 5, new: 4, created: 1, incomplete: 1, dropped: 1, linked: 1, duplicate: 0 } }),
    '5 items read · 4 new · 2 incidents · 1 incomplete · 1 dropped · 1 linked',
  )
  assert.equal(lastText({ last: { fetched: 1, new: 0, created: 0 } }), '1 item read · 0 new')
  assert.equal(
    lastText({ last: { fetched: 2, new: 2, created: 0, duplicate: 2 } }),
    '2 items read · 2 new · 2 duplicates',
  )

  const at = (seconds) => NOW / 1000 + seconds
  assert.equal(nextText({ state: 'ok', nextAt: at(45) }, NOW), 'in 45 s')
  assert.equal(nextText({ state: 'ok', nextAt: at(600) }, NOW), 'in 10 min')
  assert.equal(nextText({ state: 'failing', nextAt: at(3 * 3600) }, NOW), 'in 3 h')
  assert.equal(nextText({ state: 'ok', nextAt: at(-5) }, NOW), 'at the next turn of the worker')
  assert.equal(nextText({ state: 'paused', nextAt: at(60) }, NOW), 'waits for someone to let it go on')
  assert.equal(nextText({ state: 'off' }, NOW), '')

  assert.equal(limitText({ madeLastHour: 10, limitPerHour: 500 }), '')
  assert.equal(limitText({ madeLastHour: 300, limitPerHour: 500 }), '300 of 500 incidents this hour')
})

test('what became of an item', () => {
  assert.deepEqual(outcomeBadge('created'), { label: 'incident', color: 'emerald' })
  assert.equal(outcomeBadge('incomplete').color, 'amber')
  assert.equal(outcomeBadge('linked').label, 'linked')
  assert.equal(outcomeBadge('other').label, 'other')
})

test('mirroring: which way, why it cannot start, what waits to be sent', () => {
  assert.equal(directionText('in'), 'read from there')
  assert.equal(directionText('both'), 'both ways')
  const desk = { id: 'c1', name: 'Desk prod', connector: 'Desk', out: true }
  const readOnly = { ...desk, connector: 'Read only', out: false }
  assert.equal(
    mirrorProblem({ connection: null, mirrorId: 'T-9', direction: 'in', canSend: true }),
    'Choose a connection',
  )
  assert.equal(
    mirrorProblem({ connection: desk, mirrorId: ' ', direction: 'in', canSend: true }),
    'Say which object of the other side this incident is',
  )
  assert.equal(mirrorProblem({ connection: desk, mirrorId: 'T-9', direction: 'both', canSend: true }), null)
  assert.equal(
    mirrorProblem({ connection: readOnly, mirrorId: 'T-9', direction: 'out', canSend: true }),
    'Read only is read, not written to: mirror in',
  )
  assert.equal(mirrorProblem({ connection: readOnly, mirrorId: 'T-9', direction: 'in', canSend: false }), null)
  assert.equal(
    mirrorProblem({ connection: desk, mirrorId: 'T-9', direction: 'out', canSend: false }),
    'Sending to another system needs the permission to run playbooks',
  )

  const at = (seconds) => NOW / 1000 + seconds
  assert.equal(
    jobText({ kind: 'update', status: 'pending', attempts: 0 }, NOW),
    'the fields that changed: waits for the worker',
  )
  assert.equal(
    jobText({ kind: 'comment', status: 'pending', attempts: 2, nextAt: at(240) }, NOW),
    'a comment: tried 2 times, again in 4 min',
  )
  assert.equal(
    jobText({ kind: 'update', status: 'failed', attempts: 8 }, NOW),
    'the fields that changed: given up after 8 tries',
  )
})

test('how an instance fetches: what the form starts with, refuses and sends', () => {
  const connector = { fetch: { intervalSeconds: 120, firstFetch: '3 days', lookbackMinutes: 5, byTime: true } }
  // A new instance starts with what its connector says, and does not fetch.
  const unmirrored = { mirror: 'none', mirrorAllow: [] }
  assert.deepEqual(fetchForm(connector, null), {
    enabled: false,
    interval: '120',
    firstFetch: '3 days',
    lookback: '5',
    ...unmirrored,
  })
  const instance = { fetch: { enabled: true, intervalSeconds: 600, firstFetch: '12 hours', lookbackMinutes: 0 } }
  const form = fetchForm(connector, instance)
  assert.deepEqual(form, { enabled: true, interval: '600', firstFetch: '12 hours', lookback: '0', ...unmirrored })
  assert.deepEqual(fetchForm({}, null), {
    enabled: false,
    interval: '120',
    firstFetch: '3 days',
    lookback: '0',
    ...unmirrored,
  })

  assert.equal(fetchProblem(form), null)
  assert.match(fetchProblem({ ...form, interval: '5' }), /how often is a number of seconds, 30 at the least/)
  assert.match(fetchProblem({ ...form, interval: '' }), /how often/)
  assert.match(fetchProblem({ ...form, interval: '1.5' }), /how often/)
  assert.equal(fetchProblem({ ...form, interval: '60' }, { minInterval: 60 }), null)
  assert.match(fetchProblem({ ...form, firstFetch: 'soon' }), /the first fetch is a length of time/)
  assert.match(fetchProblem({ ...form, firstFetch: '40 days' }), /a month at most/)
  assert.match(fetchProblem({ ...form, lookback: '-1' }), /the look-back is a number of minutes, 1440 at most/)
  assert.match(fetchProblem({ ...form, lookback: '2000' }), /the look-back/)
  // A connector that goes on from a cursor has no look-back to get wrong.
  assert.equal(fetchProblem({ ...form, lookback: '' }, { byTime: false }), null)

  assert.deepEqual(fetchPayload({ enabled: true, interval: '90', firstFetch: ' 12  Hours ', lookback: '10' }), {
    enabled: true,
    intervalSeconds: 90,
    firstFetch: '12 hours',
    lookbackMinutes: 10,
  })
  assert.equal('lookbackMinutes' in fetchPayload(form, { byTime: false }), false)

  // Only what was changed is sent with the instance.
  assert.equal(fetchChanged(form, connector, instance), false)
  assert.equal(fetchChanged({ ...form, lookback: '10' }, connector, instance), true)
  assert.equal(fetchChanged({ ...form, enabled: false }, connector, instance), true)
  assert.equal(fetchChanged(fetchForm(connector, null), connector, null), false)
})

test('lengths of time, as they are typed and as they are said', () => {
  assert.equal(firstFetchSeconds('3 days'), 259200)
  assert.equal(firstFetchSeconds(' 30 Minutes '), 1800)
  assert.equal(firstFetchSeconds('1 hour'), 3600)
  assert.equal(firstFetchSeconds('0 days'), null)
  assert.equal(firstFetchSeconds('32 days'), null)
  assert.equal(firstFetchSeconds('a while'), null)
  assert.equal(intervalText(30), '30 s')
  assert.equal(intervalText(90), '90 s')
  assert.equal(intervalText(120), '2 min')
  assert.equal(intervalText('600'), '10 min')
  assert.equal(intervalText(3600), '1 h')
  assert.equal(intervalText(5400), '1 h 30 min')
  assert.equal(intervalText(''), '')
})

test('what the look-back and the reset do is said before they are used', () => {
  assert.match(lookbackHint({ lookback: '0' }), /asks from the newest time it has seen.*missed/)
  assert.match(lookbackHint({ lookback: '5' }), /asks from 5 min before the newest time it has seen.*skipped by its id/)
  assert.match(lookbackHint({ lookback: '5' }, { byTime: false }), /does not apply/)
  assert.equal(
    resetText({ firstFetch: '3 days' }),
    'The next cycle reads again from 3 days ago. What was already imported is skipped: no incident is made twice.',
  )
})

test('the direction an instance gives its incidents: what is offered, and what each does', () => {
  // A connector that reads and writes fields and comments: everything is offered.
  const desk = {
    name: 'Desk',
    mirror: { out: true, comments: true, commentsOut: true, fieldsIn: true, fieldsOut: true, fed: false },
  }
  assert.deepEqual(mirrorAbilities(desk), { fieldsIn: true, commentsIn: true, fieldsOut: true, commentsOut: true })
  const all = mirrorChoices(desk)
  assert.deepEqual(
    all.map((choice) => [choice.id, choice.label, choice.offered]),
    [
      ['none', 'None', true],
      ['in', 'In', true],
      ['out', 'Out', true],
      ['both', 'In-out', true],
    ],
  )
  assert.equal(
    all[1].text,
    'Its fields follow the object on the other side and new comments there become lines of the War Room. Nothing is sent.',
  )
  assert.match(
    all[2].text,
    /^The fields the outgoing mapper reads are written .* and notes tagged mirror .*\. Nothing is read\.$/,
  )
  assert.match(all[3].text, /^Its fields follow .*; the fields the outgoing mapper reads .*\.$/)
  assert.equal(mirrorChoiceProblem({ mirror: 'both' }, desk), null)

  // One that only reads: Out and In-out are shown with why they cannot be chosen.
  const reading = { name: 'Radar', mirror: { out: false, comments: false, fieldsIn: true, fieldsOut: false } }
  const some = mirrorChoices(reading)
  assert.deepEqual(
    some.map((choice) => choice.offered),
    [true, true, false, false],
  )
  assert.equal(some[1].text, 'Its fields follow the object on the other side. Nothing is sent.')
  assert.equal(some[2].text, 'Radar has no command that writes to the other side.')
  assert.equal(
    mirrorChoiceProblem({ mirror: 'out' }, reading),
    'Mirroring: Out is not possible. Radar has no command that writes to the other side.',
  )

  // A mailbox, fed by its fetch: In only, and it says that nothing is ever sent.
  const mail = { name: 'Mail', mirror: { out: false, comments: true, fieldsIn: false, fieldsOut: false, fed: true } }
  const fed = mirrorChoices(mail)
  assert.deepEqual(
    fed.map((choice) => choice.offered),
    [true, true, false, false],
  )
  assert.equal(
    fed[1].text,
    'What goes on with the conversation (a reply) becomes a line of the War Room. Nothing is sent.',
  )
  assert.equal(fed[3].text, 'Mail is only read: Nik never sends a message by itself.')

  // One that says why it does not mirror: None, and its reason beside the others.
  const silent = { name: 'SIEM', mirror: null, noMirror: 'The vendor documents no way to read an alert again.' }
  assert.equal(mirrorAbilities(silent), null)
  assert.deepEqual(
    mirrorChoices(silent).map((choice) => choice.offered),
    [true, false, false, false],
  )
  assert.equal(mirrorChoices(silent)[1].text, 'The vendor documents no way to read an alert again.')
  assert.equal(mirrorChoices({ name: 'Old' })[2].text, 'Old does not say how to mirror.')
  assert.equal(mirrorChoiceProblem({ mirror: 'none' }, silent), null)
  assert.equal(mirrorChoiceProblem({}, silent), null)

  // The names the product uses: the stored "both" is In-out wherever it is read.
  assert.deepEqual(['none', 'in', 'out', 'both', 'x'].map(choiceLabel), ['None', 'In', 'Out', 'In-out', 'x'])
  assert.deepEqual(
    DIRECTIONS.map((item) => item.label),
    ['In', 'Out', 'In-out'],
  )
})

test('the choice of an instance is part of its form, and is sent with it', () => {
  const connector = { fetch: {}, mirror: { out: true, fieldsOut: true } }
  const instance = { fetch: { enabled: true, mirror: { direction: 'both', allow: ['subject', 'email_address'] } } }
  const form = fetchForm(connector, instance)
  assert.equal(form.mirror, 'both')
  assert.deepEqual(form.mirrorAllow, ['email_address', 'subject'])
  assert.equal(fetchChanged(form, connector, instance), false)
  assert.equal(fetchChanged({ ...form, mirror: 'in' }, connector, instance), true)
  assert.equal(fetchChanged({ ...form, mirrorAllow: ['subject'] }, connector, instance), true)
  const sent = fetchPayload(form, { mirrors: true })
  assert.equal(sent.mirror, 'both')
  assert.deepEqual(sent.mirrorAllow, ['email_address', 'subject'])
  // A direction that sends nothing holds no class; a connector that does not mirror is sent nothing of it.
  assert.deepEqual(fetchPayload({ ...form, mirror: 'in' }, { mirrors: true }).mirrorAllow, [])
  assert.equal('mirror' in fetchPayload(form), false)
})

test('what the panel of an incident says of its mirror, and what applying a choice will do', () => {
  assert.deepEqual(['instance', 'mapper', 'here', undefined].map(originText), [
    'from the instance',
    'from the mapper',
    'set here',
    'set here',
  ])
  const at = (stamp) => `at ${stamp}`
  assert.equal(mirrorTimes({}, at), 'Not read yet')
  assert.equal(mirrorTimes({ fed: true }, at), 'No reply yet')
  assert.equal(mirrorTimes({ lastSync: 'T0' }, at), 'In step at T0')
  assert.equal(mirrorTimes({ lastPull: 'T1', lastPush: 'T2', waiting: 2 }, at), 'Read at T1 · sent at T2 · 2 to send')

  assert.equal(
    applyText({ open: 0, mirrored: 0 }, 'in'),
    'No open incident was fetched from this instance: there is nothing to change.',
  )
  assert.equal(
    applyText({ open: 3, mirrored: 1, most: 5000 }, 'both'),
    'The 3 open incidents fetched from this instance will be mirrored In-out. One mirrored with another instance is left as it is.',
  )
  assert.match(
    applyText({ open: 3, mirrored: 2, most: 5000 }, 'none'),
    /^2 of the 3 open incidents .* are mirrored with it: mirroring stops for them/,
  )
  assert.match(
    applyText({ open: 1, mirrored: 1 }, 'none'),
    /^1 of the 1 open incident fetched .* is mirrored with it: mirroring stops for it/,
  )
  assert.match(applyText({ open: 5000, mirrored: 0, most: 5000 }, 'in'), /the first ones: run it again for the rest/)
  assert.equal(
    appliedText({ started: 2, changed: 0, stopped: 0, unchanged: 1, skipped: 1 }),
    '2 started, 1 unchanged, 1 left alone.',
  )
  assert.equal(appliedText({}), 'Nothing to change.')
})
