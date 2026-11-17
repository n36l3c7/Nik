import test from 'node:test'
import assert from 'node:assert/strict'
import {
  asExpression,
  asReference,
  itemKey,
  openAtFirst,
  pathOf,
  provenanceOf,
  rows,
  runOf,
  shown,
  sourceLabel,
} from './context.js'

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
