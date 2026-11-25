import assert from 'node:assert/strict'
import { test } from 'node:test'
import { goneIncidentOf, ignoreGoneRejections, onIncidentGone, reportIncidentGone } from './incidentGone.js'

test('a 404 "Incident not found" to a request about an incident names it', () => {
  assert.equal(goneIncidentOf(404, 'Incident not found', '/incidents/abc/evidence/sources?kind=eventlog'), 'abc')
  assert.equal(goneIncidentOf(404, 'Incident not found', '/incidents/a%20b'), 'a b')
  assert.equal(goneIncidentOf(404, 'Incident not found', '/incidents/abc'), 'abc')
})

test('anything else is not an incident gone', () => {
  assert.equal(goneIncidentOf(404, 'Evidence file not found', '/incidents/abc/evidence/sources/x'), null)
  assert.equal(goneIncidentOf(403, 'Incident not found', '/incidents/abc'), null)
  assert.equal(goneIncidentOf(404, 'Incident not found', '/artifacts/abc'), null)
  assert.equal(goneIncidentOf(404, 'Incident not found', '/incidents'), null)
  assert.equal(goneIncidentOf(404, 'Incident not found', '/incidents/%E0%A4'), null)
  assert.equal(goneIncidentOf(404, 'Incident not found', undefined), null)
})

test('the handler is told once for each answer, and not when there is none', () => {
  const told = []
  assert.equal(reportIncidentGone(404, 'Incident not found', '/incidents/x/timers'), true)
  onIncidentGone((id) => told.push(id))
  assert.equal(reportIncidentGone(404, 'Incident not found', '/incidents/x/timers'), true)
  assert.equal(reportIncidentGone(500, 'Incident not found', '/incidents/x/timers'), false)
  onIncidentGone(null)
  assert.deepEqual(told, ['x'])
})

test('the page does not report as uncaught the rejection of a gone incident', () => {
  let prevented = 0
  const event = (reason) => ({ reason, preventDefault: () => prevented++ })
  ignoreGoneRejections(event(Object.assign(new Error('Incident not found'), { incidentGone: true })))
  ignoreGoneRejections(event(new Error('another failure')))
  ignoreGoneRejections(event(undefined))
  assert.equal(prevented, 1)
})
