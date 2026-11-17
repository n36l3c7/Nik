import assert from 'node:assert/strict'
import { test } from 'node:test'
import { lastText, limitText, needingCare, nextText, outcomeBadge, stateBadge } from './fetch.js'

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
