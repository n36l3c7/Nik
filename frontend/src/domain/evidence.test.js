import assert from 'node:assert/strict'
import { test } from 'node:test'
import { TAB_ALIASES, evidenceGroups, firstFile, resolveTab } from './evidence.js'

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
    commands: { shells: { bash: { commands: [{}, {}, {}] }, zsh: { commands: [] } } },
  },
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
  const groups = evidenceGroups(KINDS, INCIDENT)
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
    evidenceGroups(KINDS, {}).map((group) => group.count),
    [0, 0, 0],
  )
  assert.deepEqual(evidenceGroups(null, INCIDENT), [])
})

test('the list is searched by the name of a file, by its detail and by the kind', () => {
  const ids = (query) => evidenceGroups(KINDS, INCIDENT, query).map((group) => [group.id, group.items.length])
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
  assert.deepEqual(firstFile(evidenceGroups(KINDS, INCIDENT)), { kind: 'mail', key: 'm1' })
  const hostOnly = { data: { commands: INCIDENT.data.commands } }
  assert.deepEqual(firstFile(evidenceGroups(KINDS, hostOnly)), { kind: 'commands', key: null })
  assert.equal(firstFile(evidenceGroups(KINDS, {})), null)
})
