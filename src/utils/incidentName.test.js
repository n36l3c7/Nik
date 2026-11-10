import test from 'node:test'
import assert from 'node:assert/strict'
import { deriveIncidentName, hasIdentity, normalizeSeverity } from './incidentName.js'

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
