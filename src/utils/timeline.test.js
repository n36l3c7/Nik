import assert from 'node:assert/strict'
import { test } from 'node:test'
import { tailLines } from './timeline.js'

const event = (id, time, severity = null) => ({
  id,
  time,
  sourceType: 'browser',
  sourceLabel: 'Chrome',
  label: `event ${id}`,
  soc: { severity },
})

test('tail shows the newest events, oldest first, with flags and severity', () => {
  // buildTimelineEvents returns newest first.
  const events = [event('c', 3000, 'high'), event('b', 2000), event('a', 1000, 'medium')]
  const lines = tailLines(events, { c: { key: 'c' } }, 2)
  assert.deepEqual(
    lines.map((l) => [l.id, l.severity, l.flagged]),
    [
      ['b', null, false],
      ['c', 'high', true],
    ],
  )
  assert.equal(lines[1].source, 'browser')
})

test('tail of an empty timeline is empty', () => {
  assert.deepEqual(tailLines([]), [])
})
