import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  choosable,
  countText,
  documentProblem,
  entriesToText,
  fileFormat,
  fromRows,
  kindLabel,
  listPath,
  matching,
  nameFromLabel,
  nameProblem,
  openFromSearch,
  textToEntries,
  textToValue,
  toRows,
  valueToText,
} from './lists.js'

const LISTS = [
  { name: 'ioc_allowlist', label: 'IoC allowlist', kind: 'values', items: 40, builtin: true },
  { name: 'strict', label: 'Strict allowlist', kind: 'values', items: 1 },
  { name: 'business_hours', label: 'Business hours', kind: 'json', items: null },
  { name: 'campaign_q4', label: 'Campaign Q4', kind: 'indicators', items: 3, readOnly: true },
  { name: 'owners', label: 'Owners', kind: 'key_value', items: 2, description: 'Who has which server' },
]

test('what a list is called, and the name a new one can have', () => {
  assert.equal(kindLabel('key_value'), 'Keys and values')
  assert.equal(kindLabel('other'), 'other')
  assert.equal(countText(LISTS[0]), '40 items')
  assert.equal(countText(LISTS[1]), '1 item')
  assert.equal(countText(LISTS[2]), 'a document')
  assert.equal(nameFromLabel('  VIP users! '), 'vip_users')
  assert.equal(nameFromLabel('2024 hosts'), 'list_2024_hosts')
  assert.equal(nameFromLabel('???'), '')
  assert.equal(nameProblem('vip_users', LISTS), null)
  assert.equal(nameProblem('strict', LISTS), 'There is a list with this name already')
  assert.match(nameProblem('Bad Name', LISTS), /lower-case letter/)
  assert.deepEqual(
    matching(LISTS, 'ALLOW').map((list) => list.name),
    ['ioc_allowlist', 'strict'],
  )
  assert.deepEqual(
    matching(LISTS, 'server').map((list) => list.name),
    ['owners'],
  )
  assert.equal(matching(LISTS, ' ').length, 5)
})

test('the items of a list as the text of a box, and back', () => {
  const entries = [{ key: 'corp.example', note: 'ours' }, { key: '10.0.0.0/8' }]
  assert.equal(entriesToText(entries), 'corp.example\n10.0.0.0/8')
  // In order, once each, without the empty lines; what was noted of an item stays with it.
  assert.deepEqual(textToEntries(' new.example \n\ncorp.example\nnew.example\n', entries), [
    { key: 'new.example' },
    { key: 'corp.example', note: 'ours' },
  ])
  assert.deepEqual(textToEntries(''), [])
})

test('keys and values: a value is a text, or JSON when it reads as JSON', () => {
  assert.equal(valueToText('web'), 'web')
  assert.equal(valueToText({ team: 'infra' }), '{"team":"infra"}')
  assert.equal(valueToText(null), '')
  assert.deepEqual(textToValue('{"team": "infra"}'), { team: 'infra' })
  assert.equal(textToValue('42'), 42)
  assert.equal(textToValue('true'), true)
  assert.equal(textToValue('web team'), 'web team')
  assert.equal(textToValue('{not json'), '{not json')
  assert.equal(textToValue('  '), '')

  const plain = { entries: [{ key: 'srv-01', value: { team: 'infra' }, note: 'n' }], columns: [] }
  const rows = toRows(plain)
  assert.deepEqual(rows, [{ key: 'srv-01', note: 'n', value: '{"team":"infra"}', cells: {} }])
  assert.deepEqual(fromRows(plain, [...rows, { key: ' ', value: 'x' }, { key: 'srv-02', value: 'web' }]), [
    { key: 'srv-01', note: 'n', value: { team: 'infra' } },
    { key: 'srv-02', note: '', value: 'web' },
  ])
  // A list with columns edits each key of its value.
  const keywords = {
    columns: [{ name: 'pattern' }, { name: 'severity' }],
    entries: [{ key: 'tor', value: { pattern: 'tor', severity: 'medium' }, note: '' }],
  }
  assert.deepEqual(toRows(keywords)[0].cells, { pattern: 'tor', severity: 'medium' })
  assert.deepEqual(fromRows(keywords, [{ key: 'tor', cells: { pattern: 'torproject', severity: 'high' } }]), [
    { key: 'tor', note: '', value: { pattern: 'torproject', severity: 'high' } },
  ])
  assert.equal(documentProblem('{"a": 1}'), null)
  assert.match(documentProblem('{'), /^Not valid JSON/)
})

test('the lists a feature can read, the address of a list, what a file is', () => {
  const pointer = { list: 'strict', default: 'ioc_allowlist', kind: 'values' }
  // Of the kind it takes, Nik's own first; never a list of the IoC library.
  assert.deepEqual(
    choosable(LISTS, pointer).map((list) => list.name),
    ['ioc_allowlist', 'strict'],
  )
  assert.deepEqual(choosable(LISTS, { kind: 'json', default: 'business_hours' }).length, 1)
  assert.equal(listPath('vip users'), '/settings/lists/all?open=vip%20users')
  assert.equal(listPath(), '/settings/lists/all')
  assert.equal(openFromSearch('?open=vip_users'), 'vip_users')
  assert.equal(openFromSearch(''), null)
  assert.equal(fileFormat('Hosts.CSV'), 'csv')
  assert.equal(fileFormat('list.json'), 'json')
  assert.equal(fileFormat('values.txt'), 'csv')
  assert.equal(fileFormat('picture.png'), null)
})
