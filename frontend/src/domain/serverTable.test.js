import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  activeFilters,
  back,
  cellValue,
  cursorOf,
  directionOf,
  filterChips,
  forward,
  nextOrder,
  offsetOf,
  queryKey,
  rangeText,
  readSettings,
  visibleColumns,
  withFilter,
  withoutFilter,
} from './serverTable.js'
import { formatDateTime } from '../lib/time.js'

test('the range says where the page is in the whole, and "100,000+" when the count was cut', () => {
  assert.equal(rangeText({ offset: 0, shown: 50, total: 2418 }), '1–50 of 2,418')
  assert.equal(rangeText({ offset: 50, shown: 50, total: 2418 }), '51–100 of 2,418')
  assert.equal(rangeText({ offset: 0, shown: 50, total: 100001, capped: true }), '1–50 of 100,000+')
  assert.equal(rangeText({ offset: 0, shown: 50, total: null }), '1–50')
  assert.equal(rangeText({ offset: 0, shown: 0, total: 0 }), 'No records')
})

test('the cursors of the pages left are a stack', () => {
  let stack = []
  assert.equal(cursorOf(stack), '')
  stack = forward(stack, 'c1')
  stack = forward(stack, 'c2')
  assert.equal(cursorOf(stack), 'c2')
  assert.equal(offsetOf(stack, 50), 100)
  stack = back(stack)
  assert.equal(cursorOf(stack), 'c1')
  assert.deepEqual(back([]), [])
  // The last page has no next: the stack stays.
  assert.deepEqual(forward(['c1'], null), ['c1'])
})

test('a filter that says nothing is not one', () => {
  assert.deepEqual(activeFilters({ host: 'H', q: '', flagged: false, level: 0, x: null }), { host: 'H', level: 0 })
  assert.deepEqual(withFilter({ host: 'H' }, 'eventId', 4688), { host: 'H', eventId: 4688 })
  assert.deepEqual(withFilter({ host: 'H' }, 'host', ''), {})
  assert.deepEqual(withoutFilter({ host: 'H', q: 'x' }, 'host'), { q: 'x' })
})

test('the chips name the filters but the search, by the label of their column', () => {
  const columns = [{ key: 'eventId', label: 'Event ID', filterKey: 'eventId' }]
  assert.deepEqual(filterChips({ eventId: 4688, q: 'ps', flagged: true, host: 'H1' }, columns), [
    { name: 'eventId', names: ['eventId'], label: 'Event ID', text: 'Event ID = 4688' },
    { name: 'flagged', names: ['flagged'], label: 'flagged', text: 'flagged' },
    { name: 'host', names: ['host'], label: 'host', text: 'host = H1' },
  ])
})

test('the chips of a time range show a date and time, not milliseconds', () => {
  const [from, to] = filterChips({ from: 1700000000000, to: '1700003600000' })
  assert.equal(from.text, `from = ${formatDateTime(1700000000000)}`)
  assert.equal(to.text, `to = ${formatDateTime(1700003600000)}`)
  assert.doesNotMatch(from.text, /1700000000000/)
})

test('a caller or a column can write the value of a chip', () => {
  const columns = [{ key: 'l', label: 'Level', filterKey: 'level', chipLabel: (value) => `L${value}` }]
  assert.equal(filterChips({ level: 2 }, columns)[0].text, 'Level = L2')
  assert.equal(
    filterChips({ level: 2 }, columns, (name) => (name === 'level' ? 'caller' : undefined))[0].text,
    'Level = caller',
  )
  assert.equal(filterChips({ host: 'H' }, columns, () => undefined)[0].text, 'host = H')
})

test('dataKey and dataValue are one chip that removes both', () => {
  const chips = filterChips({ dataKey: 'TargetUserName', dataValue: 'admin', host: 'H' })
  assert.deepEqual(chips, [
    { name: 'dataKey', names: ['dataKey', 'dataValue'], label: 'TargetUserName', text: 'TargetUserName = admin' },
    { name: 'host', names: ['host'], label: 'host', text: 'host = H' },
  ])
  assert.deepEqual(chips[0].names.reduce(withoutFilter, { dataKey: 'a', dataValue: 'b', host: 'H' }), { host: 'H' })
})

test('a new query is a new key, the same one is not', () => {
  assert.equal(queryKey({ host: 'H', q: '' }, 'time', 50), queryKey({ host: 'H' }, 'time', 50))
  assert.notEqual(queryKey({ host: 'H' }, 'time', 50), queryKey({ host: 'H' }, '-time', 50))
  assert.notEqual(queryKey({ host: 'H' }, 'time', 50), queryKey({ host: 'H' }, 'time', 100))
})

test('Sort asks for the order of the column, then for its reverse', () => {
  const time = { key: 'ts', order: 'time' }
  assert.equal(nextOrder('file', time), 'time')
  assert.equal(nextOrder('time', time), '-time')
  assert.equal(nextOrder('-time', time), 'time')
  // A column with no reverse (the order of the file) stays put; a column with no order changes nothing.
  assert.equal(nextOrder('file', { order: 'file', reverse: false }), 'file')
  assert.equal(nextOrder('time', { key: 'host' }), 'time')
  assert.equal(directionOf('time', time), 'asc')
  assert.equal(directionOf('-time', time), 'desc')
  assert.equal(directionOf('file', time), null)
  assert.equal(directionOf('-file', { order: 'file', reverse: false }), null)
})

test('only a hideable column can be hidden', () => {
  const columns = [{ key: 'a' }, { key: 'b', hideable: true }, { key: 'c', hideable: true }]
  assert.deepEqual(
    visibleColumns(columns, ['a', 'b']).map((column) => column.key),
    ['a', 'c'],
  )
})

test('what was stored is read defensively', () => {
  const columns = [{ key: 'b', hideable: true }]
  assert.deepEqual(readSettings('{"hidden":["b","zzz","a"],"pageSize":100}', columns), { hidden: ['b'], pageSize: 100 })
  assert.deepEqual(readSettings('{"pageSize":7}', columns), { hidden: [], pageSize: 50 })
  assert.deepEqual(readSettings('not json', columns), { hidden: [], pageSize: 50 })
  assert.deepEqual(readSettings(null, columns), { hidden: [], pageSize: 50 })
  // A column that starts hidden is hidden until a choice is stored (then the choice is the person's).
  const quiet = [
    { key: 'b', hideable: true, hiddenByDefault: true },
    { key: 'c', hiddenByDefault: true },
  ]
  assert.deepEqual(readSettings(null, quiet), { hidden: ['b'], pageSize: 50 })
  assert.deepEqual(readSettings('{"hidden":[]}', quiet), { hidden: [], pageSize: 50 })
})

test('a cell is filtered on when it holds a plain value', () => {
  assert.equal(cellValue({ key: 'host' }, { host: 'H1' }), 'H1')
  assert.equal(cellValue({ key: 'eventId' }, { eventId: 0 }), 0)
  assert.equal(cellValue({ key: 'host' }, { host: '' }), null)
  assert.equal(cellValue({ key: 'x' }, { x: { a: 1 } }), null)
  assert.equal(cellValue({ key: 'x', value: (row) => row.a.b }, { a: { b: 'v' } }), 'v')
})
