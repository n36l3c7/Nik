import assert from 'node:assert/strict'
import { test } from 'node:test'
import { applyMergePatch, createMergePatch } from './mergePatch.js'

test('returns an empty patch when nothing changed', () => {
  const doc = { a: 1, b: { c: [1, 2] } }
  assert.deepEqual(createMergePatch(doc, doc), {})
  assert.deepEqual(createMergePatch(doc, { ...doc }), {})
})

test('sends only the changed subtree, skipping shared references', () => {
  const history = [{ id: 'h1' }]
  const prev = { updatedAt: 't0', data: { browser: { chrome: { history }, firefox: { history } } } }
  const next = {
    ...prev,
    updatedAt: 't1',
    data: { browser: { ...prev.data.browser, chrome: { history: [{ id: 'h2' }] } } },
  }
  assert.deepEqual(createMergePatch(prev, next), {
    updatedAt: 't1',
    data: { browser: { chrome: { history: [{ id: 'h2' }] } } },
  })
})

test('marks removed members as null', () => {
  const prev = { flags: { a: { key: 'a' }, b: { key: 'b' } } }
  const next = { flags: { b: prev.flags.b } }
  assert.deepEqual(createMergePatch(prev, next), { flags: { a: null } })
})

test('treats a member set to undefined as removed', () => {
  assert.deepEqual(createMergePatch({ a: 1 }, { a: undefined }), { a: null })
})

test('replaces arrays and type changes as a whole', () => {
  assert.deepEqual(createMergePatch({ a: [1, 2] }, { a: [1, 2, 3] }), { a: [1, 2, 3] })
  assert.deepEqual(createMergePatch({ a: { b: 1 } }, { a: 'x' }), { a: 'x' })
  assert.deepEqual(createMergePatch({ a: 'x' }, { a: { b: 1 } }), { a: { b: 1 } })
})

test('round-trips through an RFC 7396 apply', () => {
  const prev = { id: 'i1', a: { b: 1, c: { d: [1] } }, e: 'x', flags: { k: { key: 'k' } } }
  const next = { id: 'i1', a: { b: 2, c: { d: [1], f: true } }, flags: {}, g: { h: 'new' } }
  assert.deepEqual(applyMergePatch(prev, createMergePatch(prev, next)), next)
})
