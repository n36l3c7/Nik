import test from 'node:test'
import assert from 'node:assert/strict'
import { appDropHeld, holdAppDrop } from './dropOwner.js'

test('the app drop stands down while a page holds it, and comes back when all gave it back', () => {
  assert.equal(appDropHeld(), false)
  const first = holdAppDrop()
  const second = holdAppDrop()
  assert.equal(appDropHeld(), true)
  first()
  first() // giving back twice counts once
  assert.equal(appDropHeld(), true)
  second()
  assert.equal(appDropHeld(), false)
})
