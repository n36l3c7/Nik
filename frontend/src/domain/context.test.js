import test from 'node:test'
import assert from 'node:assert/strict'
import {
  asExpression,
  asReference,
  copied,
  itemKey,
  openAtFirst,
  pathOf,
  provenanceOf,
  rows,
  runOf,
  shown,
  sourceLabel,
  treeKey,
  valueAt,
} from './context.js'
import { renderText } from './automation/expressions.js'

const ANSWER = {
  incident: { id: 'i1', name: 'CEO fraud', severity: 'high', labels: ['finance'] },
  context: {
    Ticket: [{ ID: 't-77', Number: 'T-77', System: 'Acme Desk' }],
    File: [{ Name: 'invoice.exe', SHA256: 'ab'.repeat(32) }, { Name: 'no hash' }],
    ext: { acme: { queue: 'SOC', 'odd key': 1 } },
  },
  provenance: {
    'Ticket:t-77': { source: 'connector:acme', at: '2026-11-17T10:00:00Z' },
    [`File:${'ab'.repeat(32)}`]: { source: 'nik', at: '2026-11-17T09:00:00Z' },
    'ext.acme.queue': { source: 'run:r1', at: '2026-11-17T10:00:01Z' },
  },
  schema: { Ticket: { keys: ['ID', 'Number'], key: ['ID'] }, File: { keys: ['Name', 'SHA256'], key: ['SHA256'] } },
}

test('a path is written as an expression reads it', () => {
  assert.equal(pathOf('context', ['Ticket', 0, 'Number']), 'context.Ticket[0].Number')
  assert.equal(pathOf('context', ['ext', 'acme', 'odd key']), 'context.ext.acme["odd key"]')
  assert.equal(pathOf('incident', []), 'incident')
  assert.equal(asExpression('incident.severity'), '{{ incident.severity }}')
  assert.equal(asReference('context.Ticket[0].ID'), '${context.Ticket[0].ID}')
})

test('who set a value: the item of an entity, a key under ext', () => {
  assert.equal(itemKey(ANSWER.schema, 'Ticket', ANSWER.context.Ticket[0]), 'Ticket:t-77')
  assert.equal(itemKey(ANSWER.schema, 'File', ANSWER.context.File[1]), null)
  assert.equal(itemKey(ANSWER.schema, 'Nope', {}), null)
  assert.equal(provenanceOf(ANSWER, ['Ticket', 0, 'Number']).source, 'connector:acme')
  assert.equal(provenanceOf(ANSWER, ['Ticket', 0]).source, 'connector:acme')
  assert.equal(provenanceOf(ANSWER, ['Ticket']), null)
  assert.equal(provenanceOf(ANSWER, ['File', 1, 'Name']), null)
  assert.equal(provenanceOf(ANSWER, ['ext', 'acme', 'queue']).source, 'run:r1')
  assert.equal(provenanceOf(ANSWER, ['ext', 'acme']), null)
  assert.equal(sourceLabel('nik'), "Nik's analysis")
  assert.equal(sourceLabel('connector:acme'), 'the connector acme')
  assert.equal(sourceLabel('user:anna'), 'anna')
  assert.equal(sourceLabel('run:r1'), 'a playbook run')
  assert.equal(runOf('run:r1'), 'r1')
  assert.equal(runOf('nik'), null)
})

test('the tree is rows in reading order, opened branch by branch', () => {
  const closed = rows(ANSWER, new Set())
  assert.deepEqual(
    closed.map((row) => [row.id, row.leaf, row.count]),
    [
      ['incident', false, 4],
      ['context', false, 3],
    ],
  )
  const first = rows(ANSWER, openAtFirst(ANSWER))
  assert.deepEqual(
    first.map((row) => row.id),
    [
      'incident',
      'incident.id',
      'incident.name',
      'incident.severity',
      'incident.labels',
      'context',
      'context.Ticket',
      'context.Ticket[0]',
      'context.File',
      'context.File[0]',
      'context.File[1]',
      'context.ext',
      'context.ext.acme',
    ],
  )
  const ticket = first.find((row) => row.id === 'context.Ticket')
  assert.deepEqual([ticket.depth, ticket.list, ticket.count, ticket.label], [1, true, 1, 'Ticket'])
  const name = first.find((row) => row.id === 'incident.name')
  assert.deepEqual([name.leaf, name.value, name.depth], [true, 'CEO fraud', 1])
})

test('a search keeps what matches, with what leads to it', () => {
  const found = rows(ANSWER, new Set(), 't-77')
  assert.deepEqual(
    found.map((row) => row.id),
    ['context', 'context.Ticket', 'context.Ticket[0]', 'context.Ticket[0].ID', 'context.Ticket[0].Number'],
  )
  // By the name of a key as well as by a value.
  assert.deepEqual(
    rows(ANSWER, new Set(), 'severity').map((row) => row.id),
    ['incident', 'incident.severity'],
  )
  assert.deepEqual(rows(ANSWER, new Set(), 'nothing like this'), [])
  assert.deepEqual(rows({}, new Set(), '').length, 2)
})

test('a value on one line', () => {
  assert.equal(shown('text'), 'text')
  assert.equal(shown(12), '12')
  assert.equal(shown(null), 'null')
  assert.equal(shown(false), 'false')
})

test('a path with odd keys is written so that an expression reads the same value back', () => {
  const data = {
    incident: { name: 'CEO fraud' },
    context: {
      ext: {
        'check-point': { 'a key': ['x'], 'say "hi"': 'y', 'back\\slash': 'z', 'two\nlines': 'n', 'tab\there': 't' },
        acme: { 0: 'zero', été: 'e', "it's": 'q', 'r\rreturn': 'r' },
      },
      File: [{ Name: 'a.exe' }, { Name: 'b.exe' }],
    },
  }
  assert.equal(pathOf('context', ['ext', 'check-point', 'a key', 0]), 'context.ext["check-point"]["a key"][0]')
  assert.equal(pathOf('context', ['ext', 'check-point', 'say "hi"']), 'context.ext["check-point"]["say \\"hi\\""]')
  assert.equal(pathOf('context', ['ext', 'check-point', 'back\\slash']), 'context.ext["check-point"]["back\\\\slash"]')
  assert.equal(pathOf('context', ['ext', 'check-point', 'two\nlines']), 'context.ext["check-point"]["two\\nlines"]')
  assert.equal(pathOf('context', ['ext', 'acme', '0']), 'context.ext.acme["0"]')
  assert.equal(pathOf('context', ['ext', 'acme', 'été']), 'context.ext.acme["été"]')
  // Every leaf of the tree, opened whole: its path as a playbook writes it gives its value.
  const open = new Set()
  for (let depth = 0; depth < 10; depth += 1) {
    for (const row of rows(data, open)) if (!row.leaf) open.add(row.id)
  }
  const everything = rows(data, open).filter((row) => row.leaf)
  assert.equal(everything.length, 12)
  for (const row of everything) {
    assert.equal(renderText(asExpression(row.id), data), String(row.value), row.id)
  }
})

test('a value is copied whole: a text as it is, a branch as JSON', () => {
  const long = 'x'.repeat(50_000)
  assert.equal(copied(long), long)
  assert.equal(copied('hxxp://evil[.]example'), 'hxxp://evil[.]example')
  assert.equal(copied(12), '12')
  assert.equal(copied(false), 'false')
  assert.equal(copied(null), 'null')
  assert.equal(copied(undefined), '')
  assert.equal(copied({ ID: 't-77', tags: ['a'] }), '{\n  "ID": "t-77",\n  "tags": [\n    "a"\n  ]\n}')
  assert.equal(copied([]), '[]')
  // What a row holds is found by its steps: a leaf, an item, a whole entity, a root.
  assert.equal(valueAt(ANSWER, 'context', ['Ticket', 0, 'Number']), 'T-77')
  assert.deepEqual(valueAt(ANSWER, 'context', ['Ticket', 0]), ANSWER.context.Ticket[0])
  assert.deepEqual(valueAt(ANSWER, 'context', ['File']), ANSWER.context.File)
  assert.deepEqual(valueAt(ANSWER, 'incident', []), ANSWER.incident)
  assert.equal(valueAt(ANSWER, 'context', ['Nope', 3, 'x']), undefined)
  assert.equal(valueAt(null, 'context', ['Ticket']), undefined)
})

test('the arrows walk the tree: down and up by a row, right opens and steps in, left closes and steps out', () => {
  const open = openAtFirst(ANSWER)
  const list = rows(ANSWER, open)
  assert.deepEqual(treeKey(list, open, 'incident', 'ArrowDown'), { focus: 'incident.id' })
  assert.deepEqual(treeKey(list, open, 'incident.id', 'ArrowUp'), { focus: 'incident' })
  assert.deepEqual(treeKey(list, open, 'incident', 'ArrowUp'), {})
  assert.deepEqual(treeKey(list, open, 'context.ext.acme', 'ArrowDown'), {})
  assert.deepEqual(treeKey(list, open, 'incident.name', 'Home'), { focus: 'incident' })
  assert.deepEqual(treeKey(list, open, 'incident.name', 'End'), { focus: 'context.ext.acme' })
  // Right: a closed branch opens; an open one steps to its first child; a leaf stays.
  assert.deepEqual(treeKey(list, open, 'context.Ticket[0]', 'ArrowRight'), { toggle: 'context.Ticket[0]' })
  assert.deepEqual(treeKey(list, open, 'context.Ticket', 'ArrowRight'), { focus: 'context.Ticket[0]' })
  assert.deepEqual(treeKey(list, open, 'incident.name', 'ArrowRight'), {})
  // Left: an open branch closes; a leaf or a closed branch goes to what holds it.
  assert.deepEqual(treeKey(list, open, 'context.Ticket', 'ArrowLeft'), { toggle: 'context.Ticket' })
  assert.deepEqual(treeKey(list, open, 'context.Ticket[0]', 'ArrowLeft'), { focus: 'context.Ticket' })
  assert.deepEqual(treeKey(list, open, 'incident.name', 'ArrowLeft'), { focus: 'incident' })
  assert.deepEqual(treeKey(list, open, 'incident.name', 'a'), {})
  assert.deepEqual(treeKey(list, open, 'not there', 'ArrowDown'), {})
})
