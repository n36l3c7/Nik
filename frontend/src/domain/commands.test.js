import assert from 'node:assert/strict'
import { test } from 'node:test'
import { defaultOrderFor, distinctOf, groupByShell, noTimeText, lineOf } from './commands.js'

test('groupByShell sums what was kept and marks unseen partial reads', () => {
  const groups = groupByShell([
    { id: '1', source: 'bash', kept: 3, state: 'done', read: 'complete' },
    { id: '2', source: 'bash', kept: 4, state: 'done', read: 'partial', seen: null },
    { id: '3', source: 'zsh', kept: 2, state: 'done', read: 'partial', seen: { by: 'a' } },
    { id: '4', source: 'fish', kept: null, state: 'queued', read: '' },
  ])
  assert.equal(groups.bash.count, 7)
  assert.equal(groups.bash.partial, true)
  assert.equal(groups.zsh.partial, false)
  assert.equal(groups.fish.count, 0)
})

test('distinctOf is sorted and leaves out the empty', () => {
  assert.deepEqual(distinctOf([{ host: 'b' }, { host: '' }, { host: 'a' }, { host: 'b' }], 'host'), ['a', 'b'])
})

test('defaultOrderFor is the newest first unless no file has a time', () => {
  assert.equal(defaultOrderFor([{ firstTs: null, lastTs: null }]), 'time')
  assert.equal(
    defaultOrderFor([
      { firstTs: null, lastTs: null },
      { firstTs: 1, lastTs: 2 },
    ]),
    '-time',
  )
  assert.equal(defaultOrderFor([]), '-time')
})

test('lineOf shows the line of the worker, else the place counted from one', () => {
  assert.equal(lineOf({ seq: 4, data: { line: 12 } }), 12)
  assert.equal(lineOf({ seq: 0 }), 1)
  assert.equal(lineOf({ seq: 4, data: {} }), 5)
  assert.equal(lineOf({}), null)
})

test('noTimeText speaks only when no command has a time', () => {
  assert.match(noTimeText('PowerShell', 0, 9), /keeps none/)
  assert.equal(noTimeText('Bash', 2, 9), undefined)
  assert.equal(noTimeText('Bash', 0, 0), undefined)
})
