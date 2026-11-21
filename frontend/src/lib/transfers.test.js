import assert from 'node:assert/strict'
import { test } from 'node:test'
import { dismissTransfer, retryTransfer, transfer, transfersNow } from './transfers.js'

const cut = () => Object.assign(new Error('cut'), { interrupted: true })
const settle = () => new Promise((resolve) => setTimeout(resolve, 0))

test('a transfer that ends leaves the tray, with what it gave or what went wrong', async () => {
  assert.equal(await transfer('Uploading a.bin', async () => 'kept'), 'kept')
  assert.deepEqual(transfersNow(), [])
  await assert.rejects(
    transfer('Uploading b.bin', async () => {
      throw new Error('Not a file Nik reads.')
    }),
    /Not a file Nik reads/,
  )
  assert.deepEqual(transfersNow(), [])
})

test('a transfer cut by a restart stays in the tray and is sent again from there', async () => {
  let calls = 0
  const going = transfer('Uploading case.pst', async (onProgress) => {
    calls += 1
    onProgress({ sent: 5, total: 10 })
    if (calls === 1) throw cut()
    return 'kept'
  })
  await settle()
  const [shown] = transfersNow()
  // Not a bar that hangs: a sentence, and nothing of the progress that was.
  assert.equal(shown.failed, 'Uploading case.pst: it was cut by a restart of the server. Try it again.')
  assert.equal(shown.total, 0)
  retryTransfer(shown.id)
  assert.equal(await going, 'kept')
  assert.equal(calls, 2)
  assert.deepEqual(transfersNow(), [])
})

test('a transfer that was cut and is let go gives its error to who started it', async () => {
  const going = transfer('Uploading case.pst', async () => {
    throw cut()
  })
  await settle()
  dismissTransfer(transfersNow()[0].id)
  await assert.rejects(going, /cut/)
  assert.deepEqual(transfersNow(), [])
  // Nothing waits for an answer any more: saying it again does nothing.
  retryTransfer(1)
  dismissTransfer(1)
})
