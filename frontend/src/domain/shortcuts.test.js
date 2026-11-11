import test from 'node:test'
import assert from 'node:assert/strict'
import { SHORTCUTS, shortcutFor, shortcutMessage } from './shortcuts.js'

test('plain F, C and ? are shortcuts; with a modifier or held down they are not', () => {
  assert.equal(shortcutFor({ key: 'f' }), 'flag')
  assert.equal(shortcutFor({ key: 'F' }), 'flag')
  assert.equal(shortcutFor({ key: 'c' }), 'comment')
  assert.equal(shortcutFor({ key: '?' }), 'help')
  assert.equal(shortcutFor({ key: 'c', ctrlKey: true }), null)
  assert.equal(shortcutFor({ key: 'f', metaKey: true }), null)
  assert.equal(shortcutFor({ key: 'f', altKey: true }), null)
  assert.equal(shortcutFor({ key: 'f', repeat: true }), null)
  assert.equal(shortcutFor({ key: 'x' }), null)
  assert.equal(shortcutFor({}), null)
})

test('the toast names what was flagged; the list covers every shortcut', () => {
  assert.equal(shortcutMessage('flag', 'Flag the sample', 'dropper.bin'), 'Flagged: dropper.bin')
  assert.equal(shortcutMessage('flag', 'Remove the flag', 'dropper.bin'), 'Flag removed: dropper.bin')
  assert.equal(shortcutMessage('flag', 'Flag as malicious'), 'Flagged.')
  assert.equal(shortcutMessage('comment', 'Add a comment…', 'x'), '')
  assert.ok(shortcutMessage('flag', 'Flag as malicious', 'a'.repeat(200)).length < 80)
  const keys = SHORTCUTS.flatMap((row) => row.keys)
  for (const key of ['F', 'C', '?']) assert.ok(keys.includes(key), key)
})
