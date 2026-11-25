import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  alreadyImported,
  canAcknowledge,
  canReadAgain,
  canView,
  expectedOf,
  hexOffset,
  keptText,
  missingExpected,
  needsPolling,
  noteRows,
  readPill,
  reasonRows,
  shortHash,
  uploadText,
  whereText,
} from './sourceFiles.js'

test('a file being uploaded says in what state it is', () => {
  assert.equal(uploadText({ state: 'queued' }), 'Waiting for its turn')
  assert.equal(uploadText({ state: 'sending', sent: 1048576, total: 2097152 }), 'Sending · 1.0 MB of 2.0 MB')
  assert.equal(uploadText({ state: 'keeping' }), 'The server is checking and keeping the file')
  assert.equal(uploadText({ state: 'done', already: true }), 'Already imported')
  assert.equal(uploadText({ state: 'done' }), 'Added: the worker is reading it')
  assert.equal(uploadText({ state: 'cancelled' }), 'Cancelled')
  assert.equal(uploadText({ state: 'sending', error: 'The file is larger' }), 'The file is larger')
})

const done = { id: 's1', state: 'done', read: 'complete', kept: 6402, inFile: 6402, sha256: 'a'.repeat(64) }

test('the pill says what became of the file', () => {
  assert.deepEqual(readPill(done).label, 'complete')
  assert.equal(readPill({ ...done, read: 'partial', skipped: 23 }).label, 'read in part · 23 skipped')
  assert.equal(readPill({ ...done, read: 'partial', skipped: 23 }).color, 'amber')
  const seen = readPill({ ...done, read: 'partial', skipped: 0, seen: { by: 'elena', at: 'x', note: '' } })
  assert.equal(seen.label, 'read in part · seen')
  assert.equal(seen.color, 'slate')
  assert.equal(readPill({ ...done, state: 'failed', read: 'failed', error: 'bad magic' }).title, 'bad magic')
  assert.equal(readPill({ ...done, state: 'queued' }).label, 'queued')
  assert.equal(
    readPill({ ...done, state: 'parsing', work: { progress: '1200 records read' } }).label,
    'reading · 1200 records read',
  )
  assert.equal(readPill({ ...done, legacy: true }).label, 'imported before 7.0')
  assert.equal(readPill({ ...done, state: 'absent' }).label, 'original absent')
})

test('kept and in the file read as the mockup does', () => {
  assert.equal(keptText({ ...done, kept: 48190, inFile: 48213 }), '48,190 / 48,213')
  assert.equal(keptText({ ...done, inFile: null }), '6,402')
  assert.equal(keptText({ ...done, legacy: true }), '—')
  assert.equal(keptText({ ...done, state: 'parsing' }), '—')
})

test('polling is needed only while a file is queued or being read', () => {
  assert.equal(needsPolling([done]), false)
  assert.equal(needsPolling([done, { ...done, state: 'queued' }]), true)
  assert.equal(needsPolling([{ ...done, state: 'parsing' }]), true)
  assert.equal(needsPolling([]), false)
})

test('an expected source is missing until a file satisfies it', () => {
  const expected = [
    { key: 'history', label: 'History', hint: 'path one' },
    { key: 'shortcuts', label: 'Shortcuts', hint: 'path two' },
  ]
  const match = (source) => (source.source === 'History' ? 'history' : null)
  assert.deepEqual(
    missingExpected(expected, [{ source: 'History' }, { source: 'Other' }], match).map((item) => item.key),
    ['shortcuts'],
  )
  assert.equal(missingExpected(expected, [], match).length, 2)
  assert.equal(expectedOf({ source: 'History' }, expected, match).label, 'History')
  assert.equal(expectedOf({ source: 'Other' }, expected, match), null)
})

test('a file may satisfy several expected sources at once', () => {
  const expected = [
    { key: 'security', label: 'Security' },
    { key: 'system', label: 'System' },
    { key: 'sysmon', label: 'Sysmon' },
  ]
  const match = (source) => source.keys
  const sources = [{ keys: ['security', 'system'] }, { keys: [] }, { keys: null }]
  assert.deepEqual(
    missingExpected(expected, sources, match).map((item) => item.key),
    ['sysmon'],
  )
  assert.equal(expectedOf(sources[0], expected, match).label, 'Security')
  assert.equal(expectedOf(sources[1], expected, match), null)
  assert.equal(expectedOf(sources[2], expected, match), null)
})

test('what can be done to a file depends on what became of it', () => {
  assert.equal(canReadAgain(done), true)
  assert.equal(canReadAgain({ ...done, state: 'parsing' }), false)
  assert.equal(canReadAgain({ ...done, legacy: true }), false)
  assert.equal(canView(done), true)
  assert.equal(canView({ ...done, state: 'absent' }), false)
  assert.equal(canAcknowledge({ ...done, read: 'partial' }), true)
  assert.equal(canAcknowledge({ ...done, read: 'partial', seen: { by: 'x' } }), false)
  assert.equal(canAcknowledge(done), false)
})

test('a file the incident held is told from a new one', () => {
  const started = Date.parse('2026-11-17T11:00:00Z')
  assert.equal(alreadyImported({ id: 's1', createdAt: '2026-11-17T11:00:05Z' }, new Set(['s1']), started), true)
  assert.equal(alreadyImported({ id: 's2', createdAt: '2026-11-17T10:00:00Z' }, new Set(), started), true)
  assert.equal(alreadyImported({ id: 's3', createdAt: '2026-11-17T11:00:05Z' }, new Set(), started), false)
  assert.equal(alreadyImported(null, new Set(), started), false)
})

test('offsets are written in hex, and where a skip was is said in bytes', () => {
  assert.equal(hexOffset(0xd6a200), '0x00D6A200')
  assert.equal(whereText({ offset: 4096, length: 512 }), '0x1000 (512 bytes)')
  assert.equal(whereText({ offset: 4096, length: null }), '0x1000')
  assert.equal(whereText({ offset: null, length: 3 }), '')
  assert.equal(shortHash('abcdef0123456789abcdef'), 'abcdef012345')
  assert.equal(shortHash(''), '')
})

test('the reasons of a report come largest loss first, with the first example', () => {
  const report = {
    reasons: {
      'no timestamp': { count: 2, lost: 0, examples: [{ offset: null, length: null, detail: 'TimeCreated empty' }] },
      'bad chunk checksum': {
        count: 3,
        lost: 21,
        examples: [{ offset: 4096, length: 65536, detail: 'chunk 214' }],
      },
    },
    notes: { 'recovered after clear': { count: 2, detail: 'slack of chunk 301' } },
    ended: true,
  }
  const rows = reasonRows(report)
  assert.deepEqual(
    rows.map((row) => [row.reason, row.records]),
    [
      ['bad chunk checksum', 21],
      ['no timestamp', 2],
    ],
  )
  assert.equal(rows[0].where, '0x1000 (65,536 bytes) + 2 more')
  assert.equal(rows[1].detail, 'TimeCreated empty')
  assert.deepEqual(noteRows(report), [{ reason: 'recovered after clear', count: 2, detail: 'slack of chunk 301' }])
  assert.deepEqual(reasonRows({}), [])
  assert.deepEqual(noteRows(undefined), [])
})
