import test from 'node:test'
import assert from 'node:assert/strict'
import {
  LIMITS,
  ORDERS,
  countedText,
  hint,
  percentText,
  serverOrder,
  sortValues,
  tsvOf,
  withShares,
} from './stackValues.js'

const values = [
  { value: 'vssadmin.exe', count: 1, first: Date.UTC(2026, 10, 17, 14, 20), last: Date.UTC(2026, 10, 17, 14, 20) },
  { value: 'svchost.exe', count: 790, first: null, last: null },
  { value: 'conhost.exe', count: 9, first: 1, last: 2 },
]

test('there are three orders and the server knows two of them', () => {
  assert.deepEqual(
    ORDERS.map((item) => item.id),
    ['rare', 'common', 'az'],
  )
  assert.equal(serverOrder('az'), 'common')
  assert.equal(serverOrder('rare'), 'rare')
  assert.ok(LIMITS.az > LIMITS.rare)
})

test('A to Z sorts the values, the other orders keep the server order', () => {
  assert.deepEqual(
    sortValues(values, 'az').map((item) => item.value),
    ['conhost.exe', 'svchost.exe', 'vssadmin.exe'],
  )
  assert.equal(sortValues(values, 'rare'), values)
  // Numbers sort as numbers.
  assert.deepEqual(
    sortValues([{ value: '10' }, { value: '9' }, { value: '100' }], 'az').map((item) => item.value),
    ['9', '10', '100'],
  )
})

test('each value has its share of the listed records and a bar against the largest', () => {
  const { listed, rows } = withShares(values)
  assert.equal(listed, 800)
  assert.equal(rows[1].bar, 1)
  assert.equal(rows[0].bar, 1 / 790)
  assert.equal(rows[1].share, 790 / 800)
  assert.deepEqual(withShares([]), { listed: 0, rows: [] })
  assert.equal(withShares([{ value: 'a', count: 0 }]).rows[0].share, 0)
})

test('a share is written in the fewest digits that say it', () => {
  assert.equal(percentText(0), '0%')
  assert.equal(percentText(0.0004), '<0.1%')
  assert.equal(percentText(0.0123), '1.2%')
  assert.equal(percentText(0.987), '99%')
})

test('the copied text is tab-separated with a header, and a value cannot break a line', () => {
  const { rows } = withShares([
    { value: 'a\tb\nc', count: 3, first: Date.UTC(2026, 0, 2), last: null },
    { value: 'z', count: 1, first: null, last: null },
  ])
  const lines = tsvOf(rows, 'Process').split('\n')
  assert.equal(lines.length, 3)
  assert.equal(lines[0], 'Process\tcount\tshare\tfirst seen\tlast seen')
  assert.equal(lines[1], 'a b c\t3\t75.00%\t2026-01-02T00:00:00.000Z\t')
  assert.equal(lines[2], 'z\t1\t25.00%\t\t')
})

test('the words around the table', () => {
  assert.match(hint('rare'), /fewest/)
  assert.match(hint('common'), /most/)
  assert.match(hint('az'), /alphabetical/)
  assert.equal(countedText(null, 0), '')
  assert.equal(
    countedText({ distinct: 61, distinctCapped: false, missing: 0 }, 2418),
    '2,418 records listed, 61 distinct values',
  )
  assert.equal(
    countedText({ distinct: 1000, distinctCapped: true, missing: 4 }, 0),
    '1,000+ distinct values, 4 records without one',
  )
})
