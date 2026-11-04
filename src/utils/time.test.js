import assert from 'node:assert/strict'
import { test } from 'node:test'
import { macToMs } from './time.js'

test('converts Mac absolute time (seconds since 2001) to Unix ms', () => {
  assert.equal(macToMs(0), Date.UTC(2001, 0, 1))
  const seconds = (Date.UTC(2026, 10, 4, 10, 30) - Date.UTC(2001, 0, 1)) / 1000
  assert.equal(macToMs(seconds + 0.5), Date.UTC(2026, 10, 4, 10, 30) + 500)
  assert.equal(macToMs('10'), Date.UTC(2001, 0, 1, 0, 0, 10))
  assert.equal(macToMs(null), null)
  assert.equal(macToMs(''), null)
  assert.equal(macToMs('abc'), null)
})
