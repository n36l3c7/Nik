import assert from 'node:assert/strict'
import { test } from 'node:test'
import { CUT, amountText, cutText, percentOf, sizeText, wasCut, withTransfer, withoutTransfer } from './transfers.js'

test('how much of a transfer is done, when its size is known', () => {
  assert.equal(percentOf({ sent: 50, total: 200 }), 25)
  assert.equal(percentOf({ received: 200, total: 200 }), 100)
  assert.equal(percentOf({ sent: 300, total: 200 }), 100)
  assert.equal(percentOf({ sent: 0, total: 200 }), 0)
  // No size: there is no percentage to show, and the wait is the (o.o) one.
  assert.equal(percentOf({ received: 4096, total: null }), null)
  assert.equal(percentOf({ sent: 10, total: 0 }), null)
  assert.equal(percentOf(null), null)
})

test('a size as a person reads it', () => {
  assert.equal(sizeText(812), '812 B')
  assert.equal(sizeText(4300), '4.2 KB')
  assert.equal(sizeText(13 * 1024 ** 2), '13.0 MB')
  assert.equal(sizeText(1.25 * 1024 ** 3), '1.25 GB')
  assert.equal(sizeText(undefined), '0 B')
})

test('the amounts beside a bar', () => {
  assert.equal(amountText({ sent: 4300, total: 13 * 1024 ** 2 }), '4.2 KB of 13.0 MB')
  assert.equal(amountText({ received: 4300, total: null }), '4.2 KB')
  assert.equal(amountText({ sent: 0, total: 0 }), '')
  assert.equal(amountText(null), '')
})

test('the transfers in flight: one is added, follows its progress, and goes', () => {
  let list = withTransfer([], { id: 1, label: 'Uploading a.bin', sent: 0, total: 10 })
  list = withTransfer(list, { id: 2, label: 'Preparing the export' })
  list = withTransfer(list, { id: 1, sent: 5 })
  assert.deepEqual(list, [
    { id: 1, label: 'Uploading a.bin', sent: 5, total: 10 },
    { id: 2, label: 'Preparing the export' },
  ])
  assert.deepEqual(withoutTransfer(list, 1), [{ id: 2, label: 'Preparing the export' }])
  assert.deepEqual(withoutTransfer(list, 9), list)
})

test('a transfer the server went away under can be sent again, any other failure cannot', () => {
  // The connection broke (services/api.js marks it), or the proxy answered for a server that is starting.
  assert.equal(wasCut(Object.assign(new Error(CUT), { interrupted: true })), true)
  for (const status of [502, 503, 504]) assert.equal(wasCut(Object.assign(new Error('x'), { status })), true)
  // What the server said of the file itself is not a restart; nor is a transfer somebody cancelled.
  for (const status of [400, 413, 422, 500]) assert.equal(wasCut(Object.assign(new Error('x'), { status })), false)
  assert.equal(wasCut(Object.assign(new Error('Upload cancelled.'), { name: 'AbortError', interrupted: true })), false)
  assert.equal(wasCut(new Error('Not a mailbox.')), false)
  assert.equal(wasCut(null), false)
  assert.equal(
    cutText('Uploading case.pst'),
    'Uploading case.pst: it was cut by a restart of the server. Try it again.',
  )
  assert.match(CUT, /the server may be restarting/)
})
