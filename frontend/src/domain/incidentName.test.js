import test from 'node:test'
import assert from 'node:assert/strict'
import {
  deriveIncidentName,
  filterIncidents,
  hasIdentity,
  normalizeSeverity,
  normalizeStatus,
  statusLabel,
} from './incidentName.js'
import { formatNumber, numberFromText, numberedName } from './incidentName.js'

test('the name puts the ticket first and lets the title replace host and user', () => {
  assert.equal(
    deriveIncidentName({ ticketId: 'INC-2041', title: 'Invoice phishing', host: 'WKS', username: 'u' }),
    '[INC-2041] Invoice phishing',
  )
  assert.equal(
    deriveIncidentName({ ticketId: 'INC-2039', host: 'WKS-042', username: 'm.rossi' }),
    '[INC-2039] WKS-042 - m.rossi',
  )
  assert.equal(deriveIncidentName({ host: ' SRV-FILE-01 ' }), 'SRV-FILE-01')
  assert.equal(deriveIncidentName({ username: 'l.bianchi' }), 'l.bianchi')
  assert.equal(deriveIncidentName({ ticketId: 'INC-1' }), '[INC-1]')
  assert.equal(deriveIncidentName({}), 'Untitled incident')
})

test('identity and severity helpers', () => {
  assert.equal(hasIdentity({ title: '  ' }), false)
  assert.equal(hasIdentity({ ticketId: 'X' }), true)
  assert.equal(normalizeSeverity('critical'), 'critical')
  assert.equal(normalizeSeverity('urgent'), null)
})

test('status: unknown values are open, and the panel filters by status and assignee', () => {
  assert.equal(normalizeStatus('closed'), 'closed')
  assert.equal(normalizeStatus(undefined), 'open')
  assert.equal(normalizeStatus('archived'), 'open')
  assert.equal(statusLabel('in_progress'), 'in progress')
  const list = [
    { id: 'a' },
    { id: 'b', status: 'in_progress', assignee: 'Anna' },
    { id: 'c', status: 'closed', assignee: 'anna' },
    { id: 'd', status: 'closed', assignee: 'luca' },
  ]
  const ids = (filters) => filterIncidents(list, filters).map((incident) => incident.id)
  assert.deepEqual(ids(), ['a', 'b', 'c', 'd'])
  assert.deepEqual(ids({ status: 'open' }), ['a'])
  assert.deepEqual(ids({ status: 'closed' }), ['c', 'd'])
  assert.deepEqual(ids({ assignee: 'ANNA' }), ['b', 'c'])
  assert.deepEqual(ids({ status: 'closed', assignee: 'anna' }), ['c'])
})

test('the number of an incident is written #00042 and read back from what is typed', () => {
  assert.equal(formatNumber(42), '#00042')
  assert.equal(formatNumber(1), '#00001')
  assert.equal(formatNumber(123456), '#123456')
  for (const none of [null, undefined, 0, -3, 1.5, '42']) assert.equal(formatNumber(none), '')

  assert.equal(numberFromText('#42'), 42)
  assert.equal(numberFromText(' 00042 '), 42)
  assert.equal(numberFromText('#00042'), 42)
  for (const none of ['', '#', 'abc', '4a', '#0', '-4', '1234567890', null]) assert.equal(numberFromText(none), null)

  assert.equal(numberedName({ number: 42, name: 'Invoice phishing' }), '#00042 Invoice phishing')
  assert.equal(numberedName({ name: 'Being created' }), 'Being created')
  assert.equal(numberedName({ number: 7 }), '#00007 Untitled incident')
})

test('an incident is found by typing its number or words of its name, ten at most', async () => {
  const { suggestIncidents } = await import('./incidentName.js')
  const incidents = [
    { id: 'a', number: 4, name: 'Invoice phishing, finance', host: 'WKS-01', updatedAt: '2026-11-19T10:00' },
    { id: 'b', number: 42, name: 'Beaconing from SRV-DB-02', updatedAt: '2026-11-19T09:00' },
    { id: 'c', number: 421, name: 'Phishing report 42', updatedAt: '2026-11-19T11:00' },
    { id: 'd', number: 7, name: 'Macro dropper', username: 'm.rossi', updatedAt: '2026-11-18T08:00' },
  ]
  const ids = (text, limit) => suggestIncidents(incidents, text, limit).map((incident) => incident.id)
  // Nothing typed: the latest changed first.
  assert.deepEqual(ids(''), ['c', 'a', 'b', 'd'])
  // A number: the incident with it, then those whose number starts with it, then a name that holds it.
  assert.deepEqual(ids('42'), ['b', 'c'])
  assert.deepEqual(ids('#42'), ['b', 'c'])
  assert.deepEqual(ids('00042'), ['b', 'c'])
  assert.deepEqual(ids('4'), ['a', 'c', 'b'])
  // Words: every one of them, in the name, the host, the user or the ticket.
  assert.deepEqual(ids('phishing'), ['c', 'a'])
  assert.deepEqual(ids('PHISHING finance'), ['a'])
  assert.deepEqual(ids('wks-01'), ['a'])
  assert.deepEqual(ids('m.rossi'), ['d'])
  assert.deepEqual(ids('zzz'), [])
  assert.deepEqual(ids('', 2), ['c', 'a'])
  const many = Array.from({ length: 30 }, (_, index) => ({ id: `i${index}`, number: index + 1, name: 'Same name' }))
  assert.equal(suggestIncidents(many, 'same').length, 10)
  assert.deepEqual(suggestIncidents(null, 'x'), [])
})
