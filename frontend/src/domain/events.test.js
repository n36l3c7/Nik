import test from 'node:test'
import assert from 'node:assert/strict'
import { formatBytes } from './events.js'

test('formatBytes writes a size in the largest unit that fits, and a dash for none', () => {
  assert.equal(formatBytes(512), '512 B')
  assert.equal(formatBytes(1536), '1.5 KB')
  assert.equal(formatBytes(5 * 1024 ** 3), '5.0 GB')
  assert.equal(formatBytes(0), '—')
  assert.equal(formatBytes('x'), '—')
})
