import assert from 'node:assert/strict'
import { test } from 'node:test'
import { EXPIRY_CHOICES, expiryDate, expiryText, expiryUrgency, undatedText } from './artifactExpiry.js'

test('when an artifact expires, in words', () => {
  assert.equal(expiryText({ expiresAt: null }), 'kept: no expiry')
  assert.equal(expiryText({ expiresAt: '2026-11-25', expiresInDays: 6 }), 'expires in 6 days (2026-11-25)')
  assert.equal(expiryText({ expiresAt: '2026-11-20', expiresInDays: 1 }), 'expires tomorrow (2026-11-20)')
  assert.equal(expiryText({ expiresAt: '2026-11-19', expiresInDays: 0 }), 'expires today (2026-11-19)')
  assert.equal(expiryText({ expiresAt: '2026-11-25', expiresInDays: null }), 'expires on 2026-11-25')
  assert.equal(expiryUrgency({ expiresAt: null }), null)
  assert.equal(expiryUrgency({ expiresAt: '2026-11-25', expiresInDays: 6 }), 'soon')
  assert.equal(expiryUrgency({ expiresAt: '2027-11-25', expiresInDays: 371 }), 'later')
})

test('the days offered, and what has no date', () => {
  const now = Date.parse('2026-11-19T12:00:00Z')
  assert.equal(expiryDate(30, now), '2026-12-19')
  assert.equal(expiryDate(1, now), '2026-11-20')
  assert.deepEqual(
    EXPIRY_CHOICES.map((choice) => choice.days),
    [30, 90, 365, null],
  )
  const size = (bytes) => `${bytes} B`
  assert.equal(undatedText({ count: 0, bytes: 0 }, size), 'Every artifact has a date.')
  assert.equal(
    undatedText({ count: 1, bytes: 10 }, size),
    '1 artifact has no date (10 B) and is kept until someone deletes it.',
  )
  assert.equal(
    undatedText({ count: 12, bytes: 99 }, size),
    '12 artifacts have no date (99 B) and are kept until someone deletes them.',
  )
})

test('what the export dialog is asked for', async () => {
  const { exportRequest } = await import('./artifactExpiry.js')
  const rows = [
    { id: 'mailbox-1', name: 'finance.mbox', kind: 'mailbox', size: 1000 },
    { id: 'file-2', name: 'invoice.exe', kind: 'file', size: 24 },
  ]
  assert.deepEqual(exportRequest(rows), {
    mode: 'export',
    ids: ['mailbox-1', 'file-2'],
    label: 'finance.mbox',
    bytes: 1024,
    mailboxes: 1,
  })
  assert.deepEqual(exportRequest([]).ids, [])
})
