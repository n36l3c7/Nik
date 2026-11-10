import test from 'node:test'
import assert from 'node:assert/strict'
import { isTypingTarget, matchActions, searchIncident, tabForSource } from './search.js'

const incident = {
  notes: [{ id: 'n1', text: 'Attacker pivoted via RDP', author: 'analyst' }],
  data: { malware: { samples: [{ sha256: 'ab'.repeat(32), fileName: 'invoice.exe', type: { label: 'PE32' } }] } },
}
const events = [
  { id: 'e1', label: '4624 Logon', detail: 'administrator — RDP from 185.220.101.47', sourceLabel: 'Security' },
  { id: 'e2', label: 'curl http://x.top', detail: '', sourceLabel: 'Bash' },
]

test('searchIncident matches every word in events, notes and samples', () => {
  const found = searchIncident({ incident, events, query: 'rdp 185.220' })
  assert.deepEqual(
    found.events.map((e) => e.id),
    ['e1'],
  )
  assert.equal(searchIncident({ incident, events, query: 'pivoted' }).notes.length, 1)
  assert.equal(searchIncident({ incident, events, query: 'INVOICE' }).samples.length, 1)
  assert.deepEqual(searchIncident({ incident, events, query: '   ' }), { events: [], notes: [], samples: [] })
  assert.equal(searchIncident({ incident, events, query: 'x', limit: 1 }).events.length, 1)
})

test('matchActions filters by the words after ">"', () => {
  const actions = [
    { id: 'tab:eventlogs', label: 'Go to Event Logs', keywords: 'evtx windows' },
    { id: 'new', label: 'New incident' },
  ]
  assert.deepEqual(
    matchActions(actions, '> evtx').map((a) => a.id),
    ['tab:eventlogs'],
  )
  assert.equal(matchActions(actions, '>').length, 2)
})

test('tabForSource and isTypingTarget', () => {
  assert.equal(tabForSource('eventlog'), 'eventlogs')
  assert.equal(tabForSource('command'), 'commands')
  assert.equal(tabForSource('unknown'), 'timeline')
  assert.equal(isTypingTarget({ tagName: 'INPUT' }), true)
  assert.equal(isTypingTarget({ tagName: 'DIV', isContentEditable: true }), true)
  assert.equal(isTypingTarget({ tagName: 'BUTTON' }), false)
  assert.equal(isTypingTarget(null), false)
})
