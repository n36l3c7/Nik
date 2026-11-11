import assert from 'node:assert/strict'
import { test } from 'node:test'
import { nextInTrap } from './layers.js'

test('Tab goes round inside a dialog', () => {
  const [first, middle, last, outside] = ['first', 'middle', 'last', 'outside']
  const items = [first, middle, last]
  // In the middle the browser's own move is right.
  assert.equal(nextInTrap(items, middle, false), null)
  assert.equal(nextInTrap(items, middle, true), null)
  // At the ends it wraps instead of leaving the dialog.
  assert.equal(nextInTrap(items, last, false), first)
  assert.equal(nextInTrap(items, first, true), last)
  assert.equal(nextInTrap(items, first, false), null)
  // Focus that escaped (a click on the page behind) is brought back in.
  assert.equal(nextInTrap(items, outside, false), first)
  assert.equal(nextInTrap(items, outside, true), last)
  // Nothing to stop on: the caller keeps the focus on the dialog itself.
  assert.equal(nextInTrap([], outside, false), null)
})
