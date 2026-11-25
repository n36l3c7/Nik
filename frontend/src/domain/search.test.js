import test from 'node:test'
import assert from 'node:assert/strict'
import { evidenceTarget, isTypingTarget, markWords, matchActions, searchIncident, tabForSource } from './search.js'

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
  assert.equal(tabForSource('sample'), 'malware')
  assert.equal(tabForSource('mail'), 'mail')
  // Host records are not indexed here any more: whatever else goes to the timeline.
  assert.equal(tabForSource('eventlog'), 'timeline')
  assert.equal(tabForSource('unknown'), 'timeline')
  assert.equal(isTypingTarget({ tagName: 'INPUT' }), true)
  assert.equal(isTypingTarget({ tagName: 'DIV', isContentEditable: true }), true)
  assert.equal(isTypingTarget({ tagName: 'BUTTON' }), false)
  assert.equal(isTypingTarget(null), false)
})

test('the words typed are marked in the summary of a record, whatever the case', () => {
  assert.deepEqual(markWords('Process created: POWERSHELL -enc AAA', 'powershell'), [
    { text: 'Process created: ', hit: false },
    { text: 'POWERSHELL', hit: true },
    { text: ' -enc AAA', hit: false },
  ])
  // Every place, and the text typed as a whole first.
  assert.equal(markWords('a net b net c', 'net').filter((piece) => piece.hit).length, 2)
  // Words one by one when the whole is not there.
  assert.deepEqual(
    markWords('logon of admin from 10.0.0.5', 'admin logon')
      .filter((piece) => piece.hit)
      .map((piece) => piece.text),
    ['logon', 'admin'],
  )
  assert.deepEqual(markWords('', 'x'), [])
  assert.deepEqual(markWords('no hit here', 'zzz'), [{ text: 'no hit here', hit: false }])
})

test('a long summary is cut around the first hit', () => {
  const text = `${'x'.repeat(300)} NEEDLE ${'y'.repeat(300)}`
  const pieces = markWords(text, 'needle', 100)
  const joined = pieces.map((piece) => piece.text).join('')
  assert.ok(joined.length <= 102)
  assert.ok(joined.startsWith('…') && joined.endsWith('…'))
  assert.deepEqual(
    pieces.filter((piece) => piece.hit).map((piece) => piece.text),
    ['NEEDLE'],
  )
  // A hit at the start is not preceded by an ellipsis.
  assert.equal(markWords(`NEEDLE ${'y'.repeat(300)}`, 'needle', 100)[0].text, 'NEEDLE')
})

test('choosing a record asks for the page of its section, and the record to open', () => {
  const tabOf = (section) => ({ eventlog: 'eventlogs', syslog: 'eventlogs' })[section] ?? null
  const hit = { recordId: 7, incidentId: 'i1', section: 'syslog', sourceId: 's1', source: 'auth.log' }
  assert.deepEqual(evidenceTarget(hit, tabOf), {
    tab: 'eventlogs',
    request: { record: { id: 7, incidentId: 'i1', sourceId: 's1', fileName: 'auth.log' } },
  })
  assert.equal(evidenceTarget({ ...hit, section: 'odd' }, tabOf).tab, 'evidence')
})
