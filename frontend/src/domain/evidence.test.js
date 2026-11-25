import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  SYSTEM_KINDS,
  TAB_ALIASES,
  asksSystem,
  evidenceGroups,
  firstFile,
  firstPartialSource,
  hostCounts,
  openedAlone,
  partialPill,
  resolveTab,
  tabOfKind,
} from './evidence.js'

const TABS = [
  { id: 'summary', label: 'Summary' },
  { id: 'work_plan', label: 'Work plan' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'mail', label: 'Mail Analysis', dataKey: 'mail', evidence: true },
  { id: 'malware', label: 'Malware Analysis', dataKey: 'malware', evidence: true },
  { id: 'commands', label: 'Command History', dataKey: 'commands', evidence: true },
]
const KINDS = TABS.filter((tab) => tab.evidence)
const INCIDENT = {
  data: {
    mail: {
      messages: [{ sha256: 'm1', subject: 'Invoice overdue', from: 'billing@example.test', verdict: 'malicious' }],
    },
    malware: { samples: [{ sha256: 's1', fileName: 'invoice.exe', type: 'PE' }, { sha256: 's2' }] },
  },
}
// What the server says of the host kinds (evidence.summary): the records are not in the document.
const SUMMARY = {
  kinds: { commands: { sources: 2, records: 3, partial: 1, failed: 0, parsing: 0, absent: 0 } },
  partialUnseen: 1,
}

test('the address of a kind of evidence is the Evidence tab, on that kind', () => {
  const tab = (id) => TABS.find((item) => item.id === id)
  assert.deepEqual(resolveTab(TABS, 'summary'), { bar: tab('summary'), kind: null })
  assert.deepEqual(resolveTab(TABS, 'evidence'), { bar: tab('evidence'), kind: null })
  assert.deepEqual(resolveTab(TABS, 'mail'), { bar: tab('evidence'), kind: tab('mail') })
  // The Automation tab is gone: its runs are in the work plan.
  assert.equal(TAB_ALIASES.automation, 'work_plan')
  assert.deepEqual(resolveTab(TABS, 'automation'), { bar: tab('work_plan'), kind: null })
  // A tab that is not there falls back to the first; so does a kind when Evidence is hidden.
  assert.deepEqual(resolveTab(TABS, 'nope'), { bar: tab('summary'), kind: null })
  const hidden = TABS.filter((item) => item.id !== 'evidence')
  assert.deepEqual(resolveTab(hidden, 'mail'), { bar: tab('summary'), kind: null })
  assert.deepEqual(resolveTab([], 'mail'), { bar: null, kind: null })
  assert.deepEqual(resolveTab(null, 'mail'), { bar: null, kind: null })
})

test('the list of evidence: the files of each kind, the records of the others', () => {
  const groups = evidenceGroups(KINDS, INCIDENT, SUMMARY)
  assert.deepEqual(
    groups.map((group) => [group.id, group.files, group.count, group.items.map((item) => item.key)]),
    [
      ['mail', true, 1, ['m1']],
      ['malware', true, 2, ['s1', 's2']],
      ['commands', false, 3, []],
    ],
  )
  assert.deepEqual(groups[0].items[0], {
    key: 'm1',
    name: 'Invoice overdue',
    detail: 'billing@example.test',
    verdict: 'malicious',
  })
  // A file with no name is listed by what identifies it.
  assert.equal(groups[1].items[1].name, 's2')
  // Nothing at all: every kind is there, empty, so a file can be added to it.
  assert.deepEqual(
    evidenceGroups(KINDS, {}, null).map((group) => group.count),
    [0, 0, 0],
  )
  assert.deepEqual(evidenceGroups(null, INCIDENT, SUMMARY), [])
})

test('the list is searched by the name of a file, by its detail and by the kind', () => {
  const ids = (query) => evidenceGroups(KINDS, INCIDENT, SUMMARY, query).map((group) => [group.id, group.items.length])
  assert.deepEqual(ids('invoice'), [
    ['mail', 1],
    ['malware', 1],
  ])
  assert.deepEqual(ids('BILLING'), [['mail', 1]])
  // The name of a kind keeps all of it.
  assert.deepEqual(ids('malware'), [['malware', 2]])
  assert.deepEqual(ids('command'), [['commands', 0]])
  assert.deepEqual(ids('nothing like this'), [])
})

test('with nothing chosen the tab opens on the first file there is', () => {
  assert.deepEqual(firstFile(evidenceGroups(KINDS, INCIDENT, SUMMARY)), { kind: 'mail', key: 'm1' })
  assert.deepEqual(firstFile(evidenceGroups(KINDS, {}, SUMMARY)), { kind: 'commands', key: null })
  assert.equal(firstFile(evidenceGroups(KINDS, {}, null)), null)
})

test('what was collected on the machine asks for the system of the incident', () => {
  assert.deepEqual(SYSTEM_KINDS, ['endpoint', 'eventlogs', 'browser', 'commands'])
  for (const kind of SYSTEM_KINDS) {
    assert.equal(asksSystem(kind, ''), true, kind)
    assert.equal(asksSystem(kind, 'linux'), false, kind)
  }
  // A file is a file whatever the machine it came from.
  for (const kind of ['mail', 'malware', 'network', 'urls']) assert.equal(asksSystem(kind, ''), false, kind)
  // Without a system the tab opens by itself on a file, never on a kind that would ask.
  const groups = evidenceGroups(KINDS, INCIDENT, SUMMARY)
  assert.deepEqual(
    openedAlone(groups, '').map((group) => group.id),
    ['mail', 'malware'],
  )
  assert.equal(openedAlone(groups, 'windows').length, 3)
  const only = evidenceGroups(KINDS, {}, SUMMARY)
  assert.deepEqual(firstFile(only), { kind: 'commands', key: null })
  assert.equal(firstFile(openedAlone(only, '')), null)
  assert.deepEqual(openedAlone(null, ''), [])
})

test('the counts of host evidence come from the summary of the server', () => {
  assert.equal(hostCounts(SUMMARY, 'commands').records, 3)
  assert.equal(hostCounts(SUMMARY, 'browser').records, 0)
  assert.equal(hostCounts(null, 'eventlogs').partial, 0)
  assert.equal(hostCounts(SUMMARY, 'mail').records, 0)
  const group = evidenceGroups(KINDS, INCIDENT, SUMMARY).find((item) => item.id === 'commands')
  assert.equal(group.partial, 1)
  assert.equal(tabOfKind('eventlog'), 'eventlogs')
  assert.equal(tabOfKind('disk'), 'disk')
  assert.equal(tabOfKind('nothing'), null)
})

test('the event logs page counts the logs of Linux and macOS with those of Windows', () => {
  const summary = {
    kinds: {
      eventlog: { sources: 2, records: 10, partial: 1, failed: 0, parsing: 0, absent: 0 },
      syslog: { sources: 1, records: 5, partial: 0, failed: 1, parsing: 0, absent: 0 },
      disk: { sources: 1, records: 7 },
    },
  }
  assert.deepEqual(
    ['sources', 'records', 'partial', 'failed'].map((name) => hostCounts(summary, 'eventlogs')[name]),
    [3, 15, 1, 1],
  )
  assert.equal(hostCounts(summary, 'disk').records, 7)
  assert.equal(tabOfKind('syslog'), 'eventlogs')
})

test('the pill of the header and where it leads', () => {
  assert.equal(partialPill(null), '')
  assert.equal(partialPill({ partialUnseen: 0 }), '')
  assert.equal(partialPill({ partialUnseen: 1 }), '1 file read in part')
  assert.equal(partialPill({ partialUnseen: 2 }), '2 files read in part')
  const sources = [
    { id: 'a', read: 'complete', state: 'done', seen: null },
    { id: 'b', read: 'partial', state: 'done', seen: { at: 'x' } },
    { id: 'c', read: 'partial', state: 'done', seen: null },
  ]
  assert.equal(firstPartialSource(sources).id, 'c')
  assert.equal(firstPartialSource([]), null)
  assert.equal(firstPartialSource(null), null)
})
