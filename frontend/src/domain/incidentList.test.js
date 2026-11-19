import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  COLUMNS_KEY,
  DEFAULT_COLUMNS,
  DEFAULT_SORT,
  LIST_COLUMNS,
  allColumns,
  cellText,
  cleanColumns,
  cleanSort,
  fieldNames,
  isIncidentsPath,
  moveColumn,
  neighbour,
  nextSort,
  readColumns,
  sameColumns,
  sameSort,
  shortDateTime,
  sortIncidents,
  toggleColumn,
  writeColumns,
} from './incidentList.js'

const FIELDS = [
  { name: 'name', label: 'Name', type: 'text', appliesTo: 'incident', system: true },
  { name: 'id', label: 'Id', type: 'text', appliesTo: 'incident', system: true },
  { name: 'tlp', label: 'TLP', type: 'choice', appliesTo: 'incident', system: true },
  { name: 'business_unit', label: 'Business unit', type: 'text', appliesTo: 'incident' },
  { name: 'impact', label: 'Impact', type: 'number', appliesTo: 'incident' },
  { name: 'due', label: 'Due', type: 'date', appliesTo: 'incident' },
  { name: 'details', label: 'Details', type: 'long_text', appliesTo: 'incident' },
  { name: 'hosts', label: 'Hosts', type: 'list', appliesTo: 'incident' },
  { name: 'confidence', label: 'Confidence', type: 'number', appliesTo: 'indicator' },
]
const COLUMNS = allColumns(FIELDS)
const column = (key) => COLUMNS.find((item) => item.key === key)
const TYPES = [
  { id: 'unclassified', name: 'Unclassified' },
  { id: 'phishing', name: 'Phishing' },
]

const ROWS = [
  {
    id: 'a',
    number: 1,
    name: 'Beaconing from WS-0231',
    type: 'unclassified',
    severity: 'high',
    status: 'open',
    assignee: 'rita',
    createdAt: '2026-11-17T10:00:00.000Z',
    updatedAt: '2026-11-19T10:00:00.000Z',
    fields: { impact: 3, business_unit: 'Finance' },
  },
  {
    id: 'b',
    number: 2,
    name: 'invoice lure to finance',
    type: 'phishing',
    severity: null,
    status: 'closed',
    assignee: '',
    createdAt: '2026-11-18T10:00:00.000Z',
    updatedAt: '2026-11-18T12:00:00.000Z',
    fields: { impact: 12 },
  },
  {
    id: 'c',
    number: 10,
    name: 'Password spray on VPN',
    type: 'phishing',
    severity: 'critical',
    status: 'in_progress',
    assignee: 'admin',
    createdAt: '2026-11-19T08:00:00.000Z',
    updatedAt: '2026-11-19T09:00:00.000Z',
  },
]
const ids = (rows) => rows.map((row) => row.id).join('')

test('the list has an address of its own, and an incident has another', () => {
  assert.ok(isIncidentsPath('/incidents'))
  assert.ok(isIncidentsPath('/incidents/'))
  assert.ok(isIncidentsPath('/incidents?x=1'))
  assert.ok(!isIncidentsPath('/incident/abc'))
  assert.ok(!isIncidentsPath('/incidents/abc'))
  assert.ok(!isIncidentsPath('/'))
  assert.ok(!isIncidentsPath(null))
})

test('the columns are those of the list, then the fields of incidents a cell can hold', () => {
  assert.deepEqual(
    COLUMNS.slice(LIST_COLUMNS.length).map((item) => [item.key, item.label, item.kind]),
    [
      ['business_unit', 'Business unit', 'text'],
      ['due', 'Due', 'date'],
      ['impact', 'Impact', 'number'],
      ['tlp', 'TLP', 'text'],
    ],
  )
  assert.equal(allColumns(null).length, LIST_COLUMNS.length)
  assert.ok(DEFAULT_COLUMNS.every((key) => LIST_COLUMNS.some((item) => item.key === key)))
})

test('a choice of columns keeps what exists, once, in its order; nothing left is the default', () => {
  assert.deepEqual(cleanColumns(['impact', 'name', 'gone', 'impact', 7], COLUMNS), ['impact', 'name'])
  assert.deepEqual(cleanColumns([], COLUMNS), DEFAULT_COLUMNS)
  assert.deepEqual(cleanColumns(['gone'], COLUMNS), DEFAULT_COLUMNS)
  assert.deepEqual(cleanColumns(null, COLUMNS), DEFAULT_COLUMNS)
  assert.deepEqual(fieldNames(['number', 'impact', 'name', 'tlp'], COLUMNS), ['impact', 'tlp'])
  assert.ok(sameColumns(['a', 'b'], ['a', 'b']))
  assert.ok(!sameColumns(['a', 'b'], ['b', 'a']))
  assert.ok(!sameColumns(['a'], ['a', 'b']))
})

test('a column is added at the end, taken away, and moved; the last one stays', () => {
  assert.deepEqual(toggleColumn(['number', 'name'], 'impact'), ['number', 'name', 'impact'])
  assert.deepEqual(toggleColumn(['number', 'name'], 'number'), ['name'])
  assert.deepEqual(toggleColumn(['name'], 'name'), ['name'])
  assert.deepEqual(moveColumn(['a', 'b', 'c'], 'c', -1), ['a', 'c', 'b'])
  assert.deepEqual(moveColumn(['a', 'b', 'c'], 'a', 1), ['b', 'a', 'c'])
  assert.deepEqual(moveColumn(['a', 'b', 'c'], 'a', -1), ['a', 'b', 'c'])
  assert.deepEqual(moveColumn(['a', 'b', 'c'], 'c', 1), ['a', 'b', 'c'])
  assert.deepEqual(moveColumn(['a', 'b'], 'z', 1), ['a', 'b'])
})

test('a cell says what the row holds, by the names people read', () => {
  const [first, second] = ROWS
  assert.equal(cellText(first, column('number')), '#00001')
  assert.equal(cellText(second, column('type'), { types: TYPES }), 'Phishing')
  assert.equal(cellText(ROWS[2], column('status')), 'in progress')
  assert.equal(cellText(second, column('severity')), '')
  assert.equal(cellText(first, column('owner')), 'rita')
  assert.equal(cellText(first, column('impact')), '3')
  assert.equal(cellText(second, column('business_unit')), '')
  assert.equal(cellText({ source: { connection: 'Jira prod' } }, column('source')), 'Jira prod')
  assert.match(cellText(first, column('created')), /^2026-11-1[67] \d\d:\d\d$/)
  assert.equal(shortDateTime('nothing'), '')
})

test('the list is ordered by the last change until a column is chosen', () => {
  assert.equal(ids(sortIncidents(ROWS, null, COLUMNS)), 'acb')
  assert.equal(ids(sortIncidents(ROWS, DEFAULT_SORT, COLUMNS)), 'acb')
  assert.equal(ids(sortIncidents(ROWS, { key: 'gone', dir: 'asc' }, COLUMNS)), 'bca')
  assert.equal(ids(sortIncidents(null, null, COLUMNS)), '')
  assert.deepEqual(cleanSort({ key: 'name', dir: 'sideways' }), { key: 'name', dir: 'desc' })
  assert.ok(sameSort(null, DEFAULT_SORT))
  assert.ok(!sameSort({ key: 'name', dir: 'asc' }, { key: 'name', dir: 'desc' }))
})

test('a column orders by what it means: numbers, the rank of a severity, the name of a type', () => {
  const sorted = (key, dir) => ids(sortIncidents(ROWS, { key, dir }, COLUMNS, { types: TYPES }))
  assert.equal(sorted('number', 'desc'), 'cba') // 10 after 2, not before
  assert.equal(sorted('name', 'asc'), 'abc') // without minding the case
  assert.equal(sorted('severity', 'desc'), 'cab') // critical, high, then the one with none
  assert.equal(sorted('severity', 'asc'), 'acb') // the one with none is last both ways
  assert.equal(sorted('status', 'asc'), 'acb')
  assert.equal(sorted('created', 'asc'), 'abc')
  assert.equal(sorted('type', 'asc'), 'cba') // Phishing (the latest changed first), then Unclassified
  assert.equal(sorted('owner', 'asc'), 'cab')
  assert.equal(sorted('impact', 'desc'), 'bac') // a field of the registry, as a number
  assert.equal(sorted('business_unit', 'asc'), 'acb')
})

test('a click on a heading turns the order round, or starts with what one wants first', () => {
  assert.deepEqual(nextSort(DEFAULT_SORT, column('modified')), { key: 'modified', dir: 'asc' })
  assert.deepEqual(nextSort({ key: 'modified', dir: 'asc' }, column('modified')), { key: 'modified', dir: 'desc' })
  assert.deepEqual(nextSort(DEFAULT_SORT, column('name')), { key: 'name', dir: 'asc' })
  assert.deepEqual(nextSort(DEFAULT_SORT, column('severity')), { key: 'severity', dir: 'desc' })
  assert.deepEqual(nextSort(null, column('impact')), { key: 'impact', dir: 'desc' })
})

test('the arrows go to the row before and after, and stop at the ends', () => {
  const all = ['a', 'b', 'c']
  assert.equal(neighbour(all, 'a', 1), 'b')
  assert.equal(neighbour(all, 'b', -1), 'a')
  assert.equal(neighbour(all, 'a', -1), 'a')
  assert.equal(neighbour(all, 'c', 1), 'c')
  assert.equal(neighbour(all, 'gone', 1), 'a')
  assert.equal(neighbour([], 'a', 1), null)
})

test('the chosen columns are remembered in the browser, and forgotten on request', () => {
  const items = {}
  const storage = {
    getItem: (key) => items[key] ?? null,
    setItem: (key, value) => {
      items[key] = value
    },
    removeItem: (key) => {
      delete items[key]
    },
  }
  assert.equal(readColumns(storage), null)
  writeColumns(storage, ['number', 'impact'])
  assert.equal(items[COLUMNS_KEY], '["number","impact"]')
  assert.deepEqual(readColumns(storage), ['number', 'impact'])
  writeColumns(storage, null)
  assert.equal(readColumns(storage), null)
  items[COLUMNS_KEY] = 'not json'
  assert.equal(readColumns(storage), null)
  items[COLUMNS_KEY] = '[1, 2]'
  assert.equal(readColumns(storage), null)
  // A browser that refuses storage: no columns, no error.
  const refusing = {
    getItem: () => {
      throw new Error('denied')
    },
    setItem: () => {
      throw new Error('denied')
    },
  }
  assert.equal(readColumns(refusing), null)
  writeColumns(refusing, ['name'])
})
