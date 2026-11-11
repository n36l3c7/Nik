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
