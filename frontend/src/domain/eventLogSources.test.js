import test from 'node:test'
import assert from 'node:assert/strict'
import {
  EXPECTED_CHANNELS,
  channelOfFile,
  channelsLabel,
  channelsOf,
  coverageRows,
  flaggedOf,
  levelText,
  matchSource,
  neighbourRecords,
  sourceLabel,
  sourceOfRecord,
} from './eventLogSources.js'

test('the channel of an .evtx file comes from its name', () => {
  assert.equal(channelOfFile('Security.evtx').short, 'Security')
  assert.equal(channelOfFile('C:\\logs\\system.EVTX').short, 'System')
  assert.equal(channelOfFile('Microsoft-Windows-PowerShell%4Operational.evtx').short, 'PowerShell')
  assert.equal(channelOfFile('nik-eventlogs.json'), null)
  assert.equal(channelOfFile(undefined), null)
})

test('only the expected channels satisfy an expected row', () => {
  assert.deepEqual(matchSource({ fileName: 'Security.evtx' }), ['security'])
  assert.deepEqual(matchSource({ fileName: 'Microsoft-Windows-TaskScheduler%4Operational.evtx' }), [])
  assert.deepEqual(matchSource({ fileName: 'host-events.json' }), [])
  for (const item of EXPECTED_CHANNELS) assert.match(item.hint, /winevt\\Logs\\/)
})

test('the channels of a file come from the API, the file name only guesses for a file not read yet', () => {
  assert.deepEqual(channelsOf({ channels: ['System', 'Security'], fileName: 'Security.evtx' }), ['System', 'Security'])
  assert.deepEqual(channelsOf({ channels: [], fileName: 'Security.evtx' }), ['Security'])
  assert.deepEqual(channelsOf({ fileName: 'host-events.json' }), [])
  assert.equal(
    channelsLabel({ channels: ['Microsoft-Windows-PowerShell/Operational', 'Foo/Bar'] }),
    'PowerShell, Foo/Bar',
  )
  // The name is not asked when the file says what it holds.
  assert.equal(channelsLabel({ channels: ['System'], fileName: 'Security.evtx' }), 'System')
})

test('an expected row is satisfied by the channels, not the file name', () => {
  assert.deepEqual(matchSource({ fileName: 'copy-of-x.evtx', channels: ['Security'] }), ['security'])
  assert.deepEqual(
    matchSource({ fileName: 'Security.evtx', channels: ['Microsoft-Windows-TaskScheduler/Operational'] }),
    [],
  )
  assert.deepEqual(matchSource({ fileName: 'nik-eventlogs.json', channels: ['Foo', 'System'] }), ['system'])
  // An export holding two channels satisfies both rows.
  assert.deepEqual(matchSource({ fileName: 'my-export.json', channels: ['Security', 'System'] }), [
    'security',
    'system',
  ])
})

test('the level is the Windows name of the own level of the event', () => {
  assert.equal(levelText('4'), 'Information')
  assert.equal(levelText(2), 'Error')
  assert.equal(levelText(0), 'LogAlways')
  assert.equal(levelText('9'), '9')
  assert.equal(levelText(undefined), '')
  assert.equal(levelText(null), '')
})

test('a source goes by its channel, else by its file name', () => {
  assert.equal(sourceLabel({ fileName: 'Security.evtx' }), 'Security')
  assert.equal(sourceLabel({ fileName: 'x.json', source: 'nik-eventlogs.json' }), 'x.json')
  assert.equal(sourceLabel({ source: 'evtx' }), 'evtx')
})

test('coverage rows come from first and last time of the sources that have them', () => {
  const sources = [
    { id: 'b', fileName: 'System.evtx', firstTs: 50, lastTs: 990, kept: 5 },
    { id: 'a', fileName: 'Security.evtx', firstTs: 100, lastTs: 900, kept: 50 },
    { id: 'c', fileName: 'Windows PowerShell.evtx', firstTs: null, lastTs: null, kept: 0 },
  ]
  const { rows, min, max } = coverageRows(sources)
  assert.deepEqual(
    rows.map((row) => row.label),
    ['Security', 'System'],
  )
  assert.equal(min, 50)
  assert.equal(max, 990)
  assert.deepEqual(coverageRows([]), { rows: [], min: null, max: null })
})

test('the source and the neighbours of a record', () => {
  const sources = [{ id: 's1', fileName: 'Security.evtx', sha256: 'ab', size: 10, extra: 1 }]
  assert.deepEqual(sourceOfRecord({ sourceId: 's1' }, sources), {
    id: 's1',
    fileName: 'Security.evtx',
    sha256: 'ab',
    size: 10,
  })
  assert.equal(sourceOfRecord({ sourceId: 'nope' }, sources), null)
  const rows = [{ id: 1 }, { id: 2 }, { id: 3 }]
  assert.deepEqual(neighbourRecords(rows, 1), { previous: null, next: { id: 2 } })
  assert.deepEqual(neighbourRecords(rows, 3), { previous: { id: 2 }, next: null })
  assert.deepEqual(neighbourRecords(rows, 9), { previous: null, next: null })
})

test('a mark just made wins over the row', () => {
  assert.equal(flaggedOf({ key: 'k', flagged: false }, { k: true }), true)
  assert.equal(flaggedOf({ key: 'k', flagged: true }, {}), true)
  assert.equal(flaggedOf({ key: 'k', flagged: true }, { k: false }), false)
})
