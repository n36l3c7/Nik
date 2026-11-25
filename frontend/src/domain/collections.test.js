import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  collectionCounts,
  collectionState,
  fromCollection,
  importAction,
  importBody,
  importPercent,
  importText,
  isCollection,
  isWorking,
  kindOptions,
  leftOut,
  looksLikeCollection,
  memberState,
  memberTabs,
  placeOf,
  placedText,
  toggleKind,
  whatOf,
  whoOf,
} from './collections.js'

test('a collection is a zip row of kind collection, not the source a psort export becomes', () => {
  assert.equal(isCollection({ kind: 'collection', source: 'collection.zip' }), true)
  assert.equal(isCollection({ kind: 'collection', source: 'plaso.jsonl' }), false)
  assert.equal(isCollection(null), false)
})

test('the tabs of the list carry the counts of the server', () => {
  const tabs = memberTabs({ all: 9, importable: 5, imported: 1, skipped: 2, executables: 1, unrecognised: 0 })
  assert.deepEqual(
    tabs.map((tab) => [tab.label, tab.count]),
    [
      ['All', 9],
      ['Importable', 5],
      ['Already imported', 1],
      ['Skipped', 2],
      ['Programs', 1],
      ['Not recognised', 0],
    ],
  )
  assert.deepEqual(
    tabs.map((tab) => tab.id),
    ['all', 'importable', 'imported', 'skipped', 'executables', 'unrecognised'],
  )
  assert.equal(memberTabs()[0].count, 0)
})

test('the kinds the checkboxes offer come with their page names, by name', () => {
  assert.deepEqual(kindOptions({ eventlog: 3, disk: 2 }), [
    { kind: 'disk', label: 'Disk (NTFS)', count: 2 },
    { kind: 'eventlog', label: 'Event Logs', count: 3 },
  ])
  assert.deepEqual(toggleKind(['disk'], 'eventlog'), ['disk', 'eventlog'])
  assert.deepEqual(toggleKind(['disk'], 'disk'), [])
})

test('a member says what it is to the import', () => {
  assert.equal(memberState({ executable: true }).id, 'program')
  assert.equal(memberState({ skip: 'too large' }).title, 'too large')
  assert.equal(memberState({ importable: true, imported: true, alreadyImported: true }).id, 'already')
  assert.equal(memberState({ importable: true, imported: true }).id, 'imported')
  assert.equal(memberState({ importable: true }).id, 'importable')
  assert.equal(memberState({}).id, 'unrecognised')
  assert.equal(whoOf({ host: 'pc1', username: 'ann' }), 'pc1 · ann')
  assert.equal(whoOf({ username: 'ann' }), 'ann')
  assert.equal(whatOf({ kind: 'eventlog', source: 'windows.evtx' }), 'Event Logs · windows.evtx')
  assert.equal(whatOf({}), '')
})

test('the import goes on the numbers picked or on all, narrowed to the kinds ticked', () => {
  assert.deepEqual(importBody([5, 2]), { members: [2, 5] })
  assert.deepEqual(importBody([]), { all: true })
  assert.deepEqual(importBody([], ['disk']), { all: true, kinds: ['disk'] })
  assert.deepEqual(importAction(0, 12), { count: 12, label: 'Import 12 files', all: true })
  assert.deepEqual(importAction(1, 12), { count: 1, label: 'Import 1 file', all: false })
})

test('the progress of an import', () => {
  assert.equal(importPercent(null), null)
  assert.equal(importPercent({ total: 0 }), null)
  assert.equal(importPercent({ total: 4, done: 1, already: 1, failed: 0 }), 50)
  assert.equal(importPercent({ total: 3, done: 5 }), 100)
  assert.equal(importText({ total: 5, done: 3, already: 1, failed: 1 }), '3 of 5 imported · 1 already there · 1 failed')
  assert.equal(importText(null), '')
})

test('the row of a collection says its state and counts', () => {
  assert.equal(collectionState({ state: 'listing' }), 'listing the files')
  assert.equal(collectionState({ state: 'listed' }), 'listed')
  assert.equal(collectionState({ state: 'failed' }), 'could not be listed')
  assert.equal(isWorking({ state: 'importing' }), true)
  assert.equal(isWorking({ state: 'listed' }), false)
  assert.deepEqual(collectionCounts({ inFile: 20, kept: 3 }), { found: 20, imported: 3 })
  assert.deepEqual(collectionCounts({}), { found: null, imported: 0 })
})

test('a source that came out of a collection says from where', () => {
  assert.equal(
    fromCollection({ collectionId: 'c', collectionName: 'kape.zip', filePath: 'C/Windows/Security.evtx' }),
    'from kape.zip: C/Windows/Security.evtx',
  )
  assert.equal(fromCollection({ collectionId: 'c' }), 'from a collection')
  assert.equal(fromCollection({}), '')
})

test('a zip and a psort export are for a collection, by name', () => {
  for (const name of ['kape.zip', 'C:\\x\\plaso.jsonl', 'plaso.csv', 'case.plaso.jsonl']) {
    assert.equal(looksLikeCollection(name), true, name)
  }
  for (const name of ['Security.evtx', 'notes.txt', 'history.csv', 'zip'])
    assert.equal(looksLikeCollection(name), false, name)
})

test('where a file went is told with the page it is on', () => {
  assert.deepEqual(placeOf('eventlog'), { tab: 'eventlogs', label: 'Event Logs' })
  assert.equal(placeOf('syslog').tab, 'eventlogs')
  assert.equal(placeOf('disk').label, 'Disk (NTFS)')
  assert.equal(placeOf('nothing'), null)
  assert.equal(placedText('Security.evtx', 'eventlog'), 'Security.evtx → Event Logs')
  assert.equal(placedText('x', 'nothing'), 'x')
})

test('what a collection left out is told by reason, and adds up to the skipped members', () => {
  const report = {
    reasons: {
      'an archive inside the collection: it is not opened': {
        count: 2,
        lost: 0,
        examples: [{ detail: 'C/inner.zip' }, { detail: 'C/other.zip' }],
      },
      'it is encrypted and the password is not known': { count: 5, lost: 0, examples: [{ detail: 'C/a.evtx' }] },
    },
  }
  const { rows, total } = leftOut(report)
  assert.equal(total, 7)
  assert.deepEqual(
    rows.map((row) => [row.members, row.path, row.more]),
    [
      [5, 'C/a.evtx', 4],
      [2, 'C/inner.zip', 1],
    ],
  )
  assert.deepEqual(leftOut(undefined), { rows: [], total: 0 })
})
