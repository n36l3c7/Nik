import test from 'node:test'
import assert from 'node:assert/strict'
import { sha256Hex } from './hash.js'

test('sha256Hex digests a blob', async () => {
  assert.equal(await sha256Hex(new Blob(['abc'])), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad')
  assert.equal(await sha256Hex(null), '')
})
