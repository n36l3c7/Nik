import assert from 'node:assert/strict'
import { test } from 'node:test'
import { HOST_KIND_META, KINDS_OFF_BY_DEFAULT, density, fromLocalInput, recordLabel, toLocalInput } from './timeline.js'

test('the density adds the events of the document to the buckets of the server', () => {
  assert.deepEqual(density(null, []), { from: null, width: 0, bars: [], peak: 0 })
  const histogram = {
    from: 1000,
    to: 1999,
    width: 500,
    buckets: [
      { t: 1000, count: 4 },
      { t: 1500, count: 1 },
    ],
  }
  const merged = density(histogram, [{ time: 1100 }, { time: 1700 }, { time: 1800 }, { time: null }])
  assert.equal(merged.width, 500)
  assert.deepEqual(merged.bars, [
    { t: 1000, host: 4, docs: 1 },
    { t: 1500, host: 1, docs: 2 },
  ])
  assert.equal(merged.peak, 5)
})

test('the density grows its range for an event outside the histogram and keeps the bars few', () => {
  const histogram = { from: 0, to: 99, width: 100, buckets: [{ t: 0, count: 2 }] }
  const wide = density(histogram, [{ time: 1_000_000 }], 10)
  assert.ok(wide.bars.length <= 2)
  assert.equal(wide.width, 100_001)
  assert.equal(
    wide.bars.reduce((sum, bar) => sum + bar.host + bar.docs, 0),
    3,
  )
  // Events only: no server buckets.
  assert.equal(density(null, [{ time: 5 }, { time: 5 }]).bars[0].docs, 2)
})

test('a record is said by its summary, else by what it is', () => {
  assert.equal(recordLabel({ summary: 'ran x' }), 'ran x')
  assert.equal(recordLabel({ kind: 'browser', type: 'visit' }), 'browser visit')
  assert.equal(recordLabel({}), '(no summary)')
})

test('the range inputs are local time and give back what they were given', () => {
  assert.equal(toLocalInput(null), '')
  assert.equal(fromLocalInput(''), null)
  assert.equal(fromLocalInput('not a date'), null)
  const ms = new Date(2026, 10, 25, 14, 30).getTime()
  assert.equal(toLocalInput(ms), '2026-11-25T14:30')
  assert.equal(fromLocalInput('2026-11-25T14:30'), ms)
})

test('the disk is a kind of the timeline that is off until the Kind filter asks for it', () => {
  assert.deepEqual(KINDS_OFF_BY_DEFAULT, ['disk'])
  for (const kind of ['syslog', 'disk']) assert.ok(HOST_KIND_META[kind].label && HOST_KIND_META[kind].tab, kind)
  assert.equal(HOST_KIND_META.syslog.tab, 'eventlogs')
  assert.equal(HOST_KIND_META.disk.tab, 'disk')
})
