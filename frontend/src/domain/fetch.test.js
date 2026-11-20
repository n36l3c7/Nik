import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  directionText,
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
  assert.deepEqual(fetchForm(connector, null), { enabled: false, interval: '120', firstFetch: '3 days', lookback: '5' })
  const instance = { fetch: { enabled: true, intervalSeconds: 600, firstFetch: '12 hours', lookbackMinutes: 0 } }
  const form = fetchForm(connector, instance)
  assert.deepEqual(form, { enabled: true, interval: '600', firstFetch: '12 hours', lookback: '0' })
  assert.deepEqual(fetchForm({}, null), { enabled: false, interval: '120', firstFetch: '3 days', lookback: '0' })

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
