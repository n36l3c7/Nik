import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  DISK_SOURCES,
  MFT_FIELDS,
  MFT_CHOICES,
  MFT_SOURCE,
  USN_REASONS,
  USN_SOURCE,
  deletedFilters,
  diskItems,
  diskSourceById,
  diskTabOf,
  expectedDiskFile,
  isDeleted,
  mftChoiceOf,
  pathOf,
  reasonOf,
  reasonOptions,
  reasonsOf,
  streamsText,
  withMftChoice,
  withReason,
} from './diskPage.js'

test('the two tabs are the two sources of the worker, with where to find each file', () => {
  assert.deepEqual(
    DISK_SOURCES.map((item) => [item.id, item.key, item.label]),
    [
      ['mft', 'ntfs.mft', '$MFT'],
      ['usn', 'ntfs.usnjrnl', '$J'],
    ],
  )
  assert.equal(diskSourceById('nope').id, 'mft')
  assert.match(expectedDiskFile('mft')[0].hint, /KAPE/)
  assert.match(expectedDiskFile('usn')[0].hint, /sparse/)
  assert.equal(diskTabOf(USN_SOURCE), 'usn')
  assert.equal(diskTabOf('windows.evtx'), '')
})

test('the selector counts the records of each source and dots a file read in part and not seen', () => {
  const sources = [
    { source: MFT_SOURCE, read: 'partial', seen: null, state: 'done' },
    { source: USN_SOURCE, read: 'partial', seen: { by: 'a' }, state: 'done' },
  ]
  assert.deepEqual(diskItems({ [MFT_SOURCE]: 12, [USN_SOURCE]: 3 }, sources), [
    { id: 'mft', label: '$MFT', count: 12, partial: true },
    { id: 'usn', label: '$J', count: 3, partial: false },
  ])
  assert.deepEqual(
    diskItems().map((item) => item.count),
    [0, 0],
  )
})

test('the entry filters are independent pairs of data filters, each replacing only its own', () => {
  assert.equal(mftChoiceOf({}, 'state'), '')
  const deleted = withMftChoice({ q: 'x' }, 'state', 'deleted')
  assert.deepEqual(deleted, { q: 'x', dataKey: ['inUse'], dataValue: ['false'] })
  const more = withMftChoice(withMftChoice(deleted, 'ads', 'has'), 'zone', 'internet')
  assert.deepEqual(more, { q: 'x', dataKey: ['inUse', 'ads', 'zoneId'], dataValue: ['false', 'true', '3'] })
  assert.deepEqual(
    MFT_CHOICES.map((choice) => mftChoiceOf(more, choice.name)),
    ['deleted', '', 'has', 'internet'],
  )
  const swapped = withMftChoice(more, 'state', 'in-use')
  assert.deepEqual(swapped.dataKey, ['ads', 'zoneId', 'inUse'])
  assert.deepEqual(swapped.dataValue, ['true', '3', 'true'])
  assert.deepEqual(withMftChoice(withMftChoice(deleted, 'type', 'directory'), 'state', ''), {
    q: 'x',
    dataKey: ['isDirectory'],
    dataValue: ['true'],
  })
  assert.deepEqual(withMftChoice(deleted, 'state', ''), { q: 'x' })
  assert.equal(mftChoiceOf({ dataKey: 'other', dataValue: '1' }, 'state'), '')
  assert.equal(mftChoiceOf({ dataKey: 'inUse', dataValue: 'true' }, 'state'), 'in-use')
  assert.ok(MFT_CHOICES.length <= 4, 'the API takes four pairs at most')
  assert.deepEqual(deletedFilters({ kind: 'disk' }), { kind: 'disk', dataKey: ['inUse'], dataValue: ['false'] })
})

test('the table asks for at most the twelve keys of data the server gives', () => {
  assert.ok(MFT_FIELDS.length <= 12)
  assert.ok(MFT_FIELDS.includes('siBeforeFn'))
})

test('the path and the deleted mark come from the summary the worker writes', () => {
  assert.equal(pathOf({ summary: 'C:\\a\\b.txt [deleted]' }), 'C:\\a\\b.txt')
  assert.equal(pathOf({ summary: 'C:\\a\\b.txt' }), 'C:\\a\\b.txt')
  assert.equal(isDeleted({ summary: 'x [deleted]' }), true)
  assert.equal(isDeleted({ summary: 'x [deleted] y' }), false)
  assert.equal(pathOf({}), '')
})

test('streams are named without the unnamed data stream', () => {
  assert.equal(
    streamsText({
      streams: [
        { name: '', size: 3 },
        { name: 'Zone.Identifier', size: 26 },
      ],
    }),
    'Zone.Identifier',
  )
  assert.equal(streamsText({}), '')
})

test('the reason filter asks whether the list of reasons holds one name', () => {
  assert.deepEqual(reasonsOf({ reasons: ['FILE_CREATE', 'CLOSE'] }), ['FILE_CREATE', 'CLOSE'])
  assert.deepEqual(reasonsOf({}), [])
  const options = reasonOptions()
  assert.deepEqual(options[0], { value: '', label: 'Any reason' })
  assert.deepEqual(
    options.slice(1).map((option) => option.value),
    USN_REASONS,
  )
  assert.equal(new Set(USN_REASONS).size, USN_REASONS.length)
  const filters = withReason({ q: 'a' }, 'CLOSE')
  assert.deepEqual(filters, { q: 'a', dataHas: ['reasons:CLOSE'] })
  assert.equal(reasonOf(filters), 'CLOSE')
  assert.deepEqual(withReason(filters, 'FILE_CREATE'), { q: 'a', dataHas: ['reasons:FILE_CREATE'] })
  assert.deepEqual(withReason(filters, ''), { q: 'a' })
  assert.equal(reasonOf({ dataKey: 'inUse', dataValue: 'false' }), '')
})
