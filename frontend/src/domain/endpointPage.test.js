import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ENDPOINT_COLUMNS,
  OTHER,
  addOptions,
  categoriesOfFile,
  categoryItems,
  categoryOfSource,
  categoryTotals,
  columnsOf,
  countsBySource,
  dataChip,
  dataOf,
  expectedSources,
  fieldsOf,
  incidentRange,
  isMultiSource,
  labelOfFile,
  notesOf,
  otherOptions,
  otherSources,
  partialCategories,
  presentKeys,
  sourceFilter,
  sourceKeyOf,
  sourceLabelOf,
  sourceOptions,
  statFilters,
  timeLabelOf,
  valueOf,
  withData,
  withoutData,
} from './endpointPage.js'

const persistence = {
  id: 'persistence',
  label: 'Persistence',
  sources: {
    windows: [
      { key: 'runkeys', name: 'Run keys', path: 'NTUSER.dat', mode: 'file' },
      {
        key: 'wmi',
        name: 'WMI',
        path: 'root\\Subscription',
        mode: 'script',
        script: { lang: 'powershell' },
      },
    ],
    linux: [{ key: 'cron', name: 'cron', path: '/etc/crontab', mode: 'file' }],
  },
}
const usb = {
  id: 'usb',
  label: 'USB',
  sources: { windows: [{ key: 'usbstor', name: 'USBSTOR', mode: 'file' }] },
}
const categories = [persistence, usb]

test('the columns of a category are keys the worker writes in the data of its records', () => {
  // workers/forensics/nik_forensics/parsers/endpoint.py, CATEGORIES.
  // The columns of a category read the keys of every source of it (a prefetch file has executable, an Amcache
  // entry name): the first key of each column, and the others it falls back on.
  const first = {
    execution: ['name', 'path', 'runCount', 'sha1', 'source', 'ts_is'],
    persistence: ['name', 'kind', 'command', 'location', 'ts_is'],
    fileaccess: ['name', 'target', 'kind', 'ts_is'],
    usb: ['device', 'serial', 'vendor', 'connection', 'ts_is'],
    network: [
      'app',
      'user',
      'interface_type',
      'bytes_sent',
      'bytes_received',
      'bytes_total',
      'foreground_bytes_read',
      'foreground_bytes_written',
    ],
  }
  assert.deepEqual(Object.keys(ENDPOINT_COLUMNS).sort(), Object.keys(first).sort())
  for (const [id, keys] of Object.entries(first)) {
    assert.deepEqual(
      columnsOf(id).map((column) => column.key),
      keys,
    )
  }
  // The server gives twelve keys of data at most.
  for (const id of Object.keys(first)) assert.ok(fieldsOf(id).length <= 12, id)
  assert.ok(fieldsOf('execution').includes('run_count'))
  assert.ok(fieldsOf('usb').includes('product'))
  assert.deepEqual(columnsOf(OTHER), [])
  assert.deepEqual(fieldsOf(OTHER), [])
})

test('a column shows the first of its keys that holds something, and sizes as sizes', () => {
  const [executable, , runs] = columnsOf('execution')
  assert.equal(valueOf({ data: { executable: 'CMD.EXE' } }, executable), 'CMD.EXE')
  assert.equal(valueOf({ data: { name: 'a.exe', executable: 'b.exe' } }, executable), 'a.exe')
  assert.equal(valueOf({ data: { run_count: 3 } }, runs), '3')
  const vendor = columnsOf('usb')[2]
  assert.equal(valueOf({ data: { vendor: 'SanDisk', product: 'Cruzer' } }, vendor), 'SanDisk Cruzer')
  assert.equal(valueOf({ data: { product: 'Cruzer' } }, vendor), 'Cruzer')
  const sent = columnsOf('network')[3]
  assert.equal(
    valueOf({ data: { bytes_sent: 2048 } }, sent, (n) => String(n / 1024) + ' KB'),
    '2 KB',
  )
  assert.equal(valueOf({ data: {} }, sent), '')
  assert.equal(sent.align, 'right')
})

test('dataOf reads a key of the data and is empty when there is none', () => {
  assert.equal(dataOf({ data: { runCount: 3 } }, 'runCount'), '3')
  assert.equal(dataOf({ data: {} }, 'path'), '')
  assert.equal(dataOf({}, 'path'), '')
})

test('sourceKeyOf reads the id of a source of the category and system', () => {
  assert.equal(sourceKeyOf({ source: 'windows.persistence.runkeys' }, 'windows', 'persistence'), 'runkeys')
  assert.equal(sourceKeyOf({ source: 'linux.persistence.cron' }, 'windows', 'persistence'), null)
  assert.equal(sourceKeyOf({ source: 'windows.usb.usbstor' }, 'windows', 'persistence'), null)
  assert.equal(sourceKeyOf({ source: 'windows.persistence.' }, 'windows', 'persistence'), null)
  assert.equal(sourceKeyOf({}, 'windows', 'persistence'), null)
})

test('a source name that names no category of the system is "other"', () => {
  assert.equal(categoryOfSource('windows.usb.usbstor', 'windows', categories), 'usb')
  assert.equal(categoryOfSource('linux.persistence.cron', 'windows', categories), OTHER)
  assert.equal(categoryOfSource('endpoint.csv', 'windows', categories), OTHER)
  const sources = [{ source: 'windows.usb.usbstor' }, { source: 'old-export.csv' }]
  assert.deepEqual(otherSources(sources, 'windows', categories), [{ source: 'old-export.csv' }])
})

test('expectedSources gives the path of a file and the script hint of a script', () => {
  assert.deepEqual(expectedSources(persistence, 'windows'), [
    { key: 'runkeys', label: 'Run keys', hint: 'NTUSER.dat' },
    { key: 'wmi', label: 'WMI', hint: 'collection script (PowerShell)' },
  ])
  assert.deepEqual(expectedSources(usb, 'macos'), [])
})

test('partialCategories counts only sources read in part and not seen', () => {
  const sources = [
    {
      source: 'windows.persistence.runkeys',
      read: 'partial',
      seen: null,
      state: 'done',
    },
    {
      source: 'windows.usb.usbstor',
      read: 'partial',
      seen: { by: 'a' },
      state: 'done',
    },
    {
      source: 'windows.usb.setupapi',
      read: 'partial',
      seen: null,
      state: 'absent',
    },
    { source: 'old.csv', read: 'partial', seen: null, state: 'done' },
  ]
  assert.deepEqual([...partialCategories(sources, 'windows', categories)].sort(), ['other', 'persistence'])
})

test('totals per category come from the counts by source, and Other only shows when a file is in it', () => {
  const counts = countsBySource([
    { value: 'windows.persistence.runkeys', count: 6 },
    { value: 'windows.persistence.wmi', count: 2 },
    { value: 'windows.usb.usbstor', count: 4 },
    { value: 'old.csv', count: 5 },
  ])
  const totals = categoryTotals(categories, 'windows', counts)
  assert.deepEqual(totals, { other: 5, persistence: 8, usb: 4 })
  assert.deepEqual(categoryItems(categories, totals, new Set(['usb']), false), [
    { id: 'persistence', label: 'Persistence', count: 8, partial: false },
    { id: 'usb', label: 'USB', count: 4, partial: true },
  ])
  const withOther = categoryItems(categories, totals, new Set(), true)
  assert.deepEqual(withOther.at(-1), {
    id: 'other',
    label: 'Other',
    count: 5,
    partial: false,
  })
})

test('sourceOptions lists all, then each source of the system with its records, and any other under the prefix', () => {
  const counts = {
    'windows.persistence.runkeys': 6,
    'windows.persistence.tasks': 1200,
    'linux.persistence.cron': 9,
  }
  assert.deepEqual(
    sourceOptions(persistence, 'windows', counts).map((o) => [o.value, o.label]),
    [
      ['', 'all (1,206)'],
      ['windows.persistence.runkeys', 'Run keys (6)'],
      ['windows.persistence.wmi', 'WMI (0)'],
      ['windows.persistence.tasks', 'tasks (1,200)'],
    ],
  )
  assert.deepEqual(sourceOptions(usb, 'macos', {}), [{ value: '', label: 'all (0)' }])
  assert.deepEqual(otherOptions(['old.csv'], { 'old.csv': 5 }), [{ value: 'old.csv', label: 'old.csv (5)' }])
})

test('the source filter is one source when chosen, else the prefix of the category', () => {
  assert.deepEqual(sourceFilter('windows.usb.', ''), {
    sourcePrefix: 'windows.usb.',
  })
  assert.deepEqual(sourceFilter('windows.usb.', 'windows.usb.usbstor'), {
    source: 'windows.usb.usbstor',
  })
})

test('statFilters asks for dated records and for flagged ones on top of the filters in force', () => {
  assert.deepEqual(statFilters({ sourcePrefix: 'windows.usb.', host: '', from: 50 }), {
    entries: { sourcePrefix: 'windows.usb.', from: 50 },
    timed: { sourcePrefix: 'windows.usb.', from: 50, dated: true },
    flagged: { sourcePrefix: 'windows.usb.', from: 50, flagged: true },
  })
})

test('a filter on a key of the data sets both names and has one chip', () => {
  const set = withData({ host: 'pc' }, 'path', 'C:\\x.exe')
  assert.deepEqual(set, {
    host: 'pc',
    dataKey: 'path',
    dataValue: 'C:\\x.exe',
  })
  assert.equal(dataChip(set, columnsOf('execution')), 'Path = C:\\x.exe')
  assert.equal(dataChip({ dataKey: 'zzz', dataValue: '1' }, []), 'zzz = 1')
  assert.equal(dataChip({}, []), '')
  assert.deepEqual(withoutData(set), { host: 'pc' })
})

test('incidentRange is null without a window', () => {
  assert.equal(incidentRange({}), null)
  assert.deepEqual(incidentRange({ suspiciousStart: 5, suspiciousEnd: null }), {
    from: 5,
    to: null,
  })
})

const hived = {
  id: 'execution',
  label: 'Program execution',
  sources: {
    windows: [
      { key: 'prefetch', name: 'Prefetch', path: 'C:\\Windows\\Prefetch', mode: 'file' },
      {
        key: 'shimcache',
        name: 'ShimCache',
        path: 'SYSTEM',
        mode: 'file',
        via: 'hive',
        timeLabel: 'File modified',
        note: 'not a run',
      },
      { key: 'amcache', name: 'Amcache', path: 'Amcache.hve', mode: 'file', via: 'hive' },
    ],
  },
}
const network = {
  id: 'network',
  label: 'Network usage',
  sources: { windows: [{ key: 'srum-network', name: 'SRUM network', path: 'SRUDB.dat', mode: 'file', via: 'srudb' }] },
}
const all = [hived, network]

test('the rows that come out of a hive say so, and records satisfy them', () => {
  assert.deepEqual(
    expectedSources(hived, 'windows').map((item) => item.hint),
    ['C:\\Windows\\Prefetch', 'from a registry hive: SYSTEM', 'from a registry hive: Amcache.hve'],
  )
  assert.equal(expectedSources(network, 'windows')[0].hint, 'from SRUDB.dat: SRUDB.dat')
  const counts = { 'windows.execution.shimcache': 4, 'windows.execution.prefetch': 9, 'windows.execution.amcache': 0 }
  // Prefetch has a file of its own: only the hive sources are satisfied by records.
  assert.deepEqual(presentKeys(hived, 'windows', counts), ['shimcache'])
  assert.deepEqual(presentKeys(hived, 'macos', counts), [])
})

test('"Add files as" offers the files with their own source, then the hive and SRUDB.dat', () => {
  const names = {
    hiveSource: 'windows.registry.hive',
    hiveLabel: 'Registry hive',
    srumSource: 'windows.network.srum-network',
    srumLabel: 'SRUDB',
  }
  assert.deepEqual(addOptions(hived, 'windows', names), [
    { key: 'prefetch', label: 'Prefetch', source: 'windows.execution.prefetch' },
    { key: 'hive', label: 'Registry hive', source: 'windows.registry.hive' },
  ])
  assert.deepEqual(addOptions(network, 'windows', names), [
    { key: 'srudb', label: 'SRUDB', source: 'windows.network.srum-network' },
  ])
  assert.deepEqual(addOptions(network, 'linux', names), [])
})

test('a hive is one file in the categories of the sources it gave, and is named by them', () => {
  const hive = { id: 'h1', source: 'windows.registry.hive' }
  const gave = { h1: ['windows.execution.shimcache', 'windows.execution.amcache'] }
  assert.equal(isMultiSource('windows.registry.hive'), true)
  assert.equal(isMultiSource('windows.network.srum-apps'), true)
  assert.equal(isMultiSource('windows.execution.prefetch'), false)
  assert.deepEqual(categoriesOfFile(hive, 'windows', all, gave), ['execution'])
  // Nothing gave yet, or nothing known: it waits in Other.
  assert.deepEqual(categoriesOfFile(hive, 'windows', all, {}), [OTHER])
  assert.deepEqual(categoriesOfFile({ id: 'p', source: 'windows.execution.prefetch' }, 'windows', all), ['execution'])
  assert.deepEqual(otherSources([hive], 'windows', all, gave), [])
  assert.deepEqual(otherSources([hive], 'windows', all, {}), [hive])
  assert.equal(labelOfFile(hive, 'windows', all, gave), 'ShimCache, Amcache')
  assert.equal(labelOfFile(hive, 'windows', all, {}), 'Registry hive')
  assert.equal(labelOfFile({ id: 's', source: 'windows.network.srum-network' }, 'windows', all, {}), 'SRUDB.dat')
  assert.equal(labelOfFile({ id: 'p', source: 'windows.execution.prefetch' }, 'windows', all, gave), '')
  assert.equal(sourceLabelOf('windows.execution.amcache', 'windows', all), 'Amcache')
  assert.equal(sourceLabelOf('unknown.name', 'windows', all), 'unknown.name')
  // A hive read in part dots the categories it gave.
  const partial = { ...hive, read: 'partial', seen: null, state: 'done' }
  assert.deepEqual([...partialCategories([partial], 'windows', all, gave)], ['execution'])
})

test('ShimCache has its own title for the time and a note on what it is not', () => {
  assert.equal(timeLabelOf(hived, 'windows', 'windows.execution.shimcache'), 'File modified')
  assert.equal(timeLabelOf(hived, 'windows', ''), 'Time')
  assert.equal(timeLabelOf(hived, 'windows', 'windows.execution.prefetch'), 'Time')
  assert.deepEqual(notesOf(hived, 'windows', { 'windows.execution.shimcache': 2 }), ['not a run'])
  assert.deepEqual(notesOf(hived, 'windows', { 'windows.execution.shimcache': 0 }), [])
})
