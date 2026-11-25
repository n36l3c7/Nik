import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  ENDPOINT_COLUMNS,
  OTHER,
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
  otherOptions,
  otherSources,
  partialCategories,
  sourceFilter,
  sourceKeyOf,
  sourceOptions,
  statFilters,
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
  const written = {
    execution: ['name', 'path', 'runCount', 'source'],
    persistence: ['name', 'kind', 'command', 'location'],
    fileaccess: ['name', 'target', 'kind'],
    usb: ['device', 'serial', 'vendor', 'connection'],
  }
  assert.deepEqual(Object.keys(ENDPOINT_COLUMNS).sort(), Object.keys(written).sort())
  for (const [id, keys] of Object.entries(written)) assert.deepEqual(fieldsOf(id), keys)
  assert.ok(Object.values(ENDPOINT_COLUMNS).every((columns) => columns.length <= 12))
  assert.deepEqual(columnsOf(OTHER), [])
  assert.deepEqual(fieldsOf(OTHER), [])
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
