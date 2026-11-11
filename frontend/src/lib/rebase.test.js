import assert from 'node:assert/strict'
import { test } from 'node:test'
import { isEqual, rebase } from './rebase.js'

test('isEqual compares JSON values deeply and ignores undefined members', () => {
  assert.equal(isEqual({ a: [1, { b: 2 }], c: undefined }, { a: [1, { b: 2 }] }), true)
  assert.equal(isEqual({ a: [1, 2] }, { a: [2, 1] }), false)
  assert.equal(isEqual([1], { 0: 1 }), false)
  assert.equal(isEqual(null, {}), false)
})

test('what only one side changed is kept from that side', () => {
  const base = { host: 'a', os: 'windows', severity: 'low' }
  const local = { ...base, host: 'mine' }
  const remote = { ...base, os: 'linux' }
  assert.deepEqual(rebase(base, local, remote), { host: 'mine', os: 'linux', severity: 'low' })
})

test('this side wins where both changed the same value', () => {
  assert.deepEqual(rebase({ host: 'a' }, { host: 'mine' }, { host: 'theirs' }), { host: 'mine' })
})

test('notes added by two analysts both survive', () => {
  const first = { id: '1', text: 'first' }
  const base = { notes: [first] }
  const local = { notes: [first, { id: 'b', text: 'from B' }] }
  const remote = { notes: [first, { id: 'a', text: 'from A' }] }
  assert.deepEqual(
    rebase(base, local, remote).notes.map((note) => note.id),
    ['1', 'a', 'b'],
  )
})

test('an item removed on one side stays removed, unless the other edited it', () => {
  const one = { id: '1', text: 'one' }
  const two = { id: '2', text: 'two' }
  const base = [one, two]
  // Removed here.
  assert.deepEqual(rebase(base, [two], [one, two, { id: '3', text: 'three' }]), [two, { id: '3', text: 'three' }])
  // Removed there, untouched here.
  assert.deepEqual(rebase(base, [one, two], [two]), [two])
  // Removed there, edited here: the edit is kept.
  const edited = { id: '1', text: 'edited' }
  assert.deepEqual(rebase(base, [edited, two], [two]), [two, edited])
})

test('the same item edited on both sides is merged member by member', () => {
  const base = [{ id: '1', text: 'a', comments: [] }]
  const local = [{ id: '1', text: 'a', comments: [{ id: 'c1', text: 'mine' }] }]
  const remote = [{ id: '1', text: 'theirs', comments: [{ id: 'c2', text: 'theirs' }] }]
  assert.deepEqual(rebase(base, local, remote), [
    {
      id: '1',
      text: 'theirs',
      comments: [
        { id: 'c2', text: 'theirs' },
        { id: 'c1', text: 'mine' },
      ],
    },
  ])
})

test('flags: one removed here, one added there, a comment added here', () => {
  const base = { flags: { x: { key: 'x', comments: [] }, y: { key: 'y', comments: [] } } }
  const local = { flags: { y: { key: 'y', comments: [{ id: 'c', text: 'note' }] } } }
  const remote = { flags: { ...base.flags, z: { key: 'z', comments: [] } } }
  assert.deepEqual(rebase(base, local, remote), {
    flags: { y: { key: 'y', comments: [{ id: 'c', text: 'note' }] }, z: { key: 'z', comments: [] } },
  })
})

test('a member removed there is removed, a member removed here stays removed', () => {
  assert.deepEqual(rebase({ a: 1, b: 2 }, { a: 1, b: 2 }, { a: 1 }), { a: 1 })
  assert.deepEqual(rebase({ a: 1, b: 2 }, { a: 1 }, { a: 1, b: 3 }), { a: 1 })
})

test('lists without identities are not merged: this side wins when both changed', () => {
  assert.deepEqual(rebase([1, 2], [1, 2, 3], [0, 1, 2]), [1, 2, 3])
  assert.deepEqual(rebase([1, 2], [1, 2], [0, 1, 2]), [0, 1, 2])
})

test('unchanged subtrees come back as the remote reference', () => {
  const rows = [{ id: 'r1' }, { id: 'r2' }]
  const base = { data: { history: rows }, host: 'a' }
  const local = { data: { history: rows }, host: 'mine' }
  const remote = { data: { history: [{ id: 'r1' }, { id: 'r2' }] }, host: 'a' }
  const merged = rebase(base, local, remote)
  assert.equal(merged.data, remote.data)
  assert.equal(merged.host, 'mine')
  // Nothing changed here at all: the remote document itself.
  assert.equal(rebase(base, base, remote), remote)
})
