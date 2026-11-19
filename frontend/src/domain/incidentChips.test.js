import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  CHIPS,
  addCondition,
  applyChip,
  chipChoices,
  chipCondition,
  otherFields,
  rowCondition,
} from './incidentChips.js'

const SCHEMA = {
  entity: 'incidents',
  fields: [
    { name: 'name', aliases: [], kind: 'text', values: [] },
    { name: 'host', aliases: [], kind: 'text', values: [] },
    { name: 'severity', aliases: [], kind: 'ordered', values: ['low', 'medium', 'high', 'critical'] },
    { name: 'status', aliases: [], kind: 'keyword', values: ['open', 'in_progress', 'closed'] },
    { name: 'owner', aliases: ['assignee'], kind: 'keyword', values: [] },
    { name: 'created', aliases: ['createdAt'], kind: 'date', values: [] },
    { name: 'type', aliases: [], kind: 'keyword', values: [] },
  ],
}
const conditions = (choices) => choices.map((choice) => choice.condition)

test('each chip offers conditions the query language reads', () => {
  assert.deepEqual(
    CHIPS.map((chip) => chip.label),
    ['Type', 'Severity', 'Status', 'Owner', 'Opened'],
  )
  assert.deepEqual(conditions(chipChoices('type', { types: [{ name: 'Phishing' }, { name: 'Data leak' }] })), [
    'type:Phishing',
    'type:"Data leak"',
  ])
  assert.deepEqual(conditions(chipChoices('severity')), [
    'severity:critical',
    'severity:high',
    'severity:medium',
    'severity:low',
    'severity:>=high',
    'severity:>=medium',
    'severity:""',
  ])
  assert.deepEqual(conditions(chipChoices('status')), [
    'status:open',
    'status:in_progress',
    'status:closed',
    '!status:closed',
  ])
  assert.deepEqual(chipChoices('owner', { me: 'Rita', assignees: ['admin', 'rita', 'm rossi'] }), [
    { label: 'me (Rita)', condition: 'owner:Rita' },
    { label: 'nobody', condition: 'owner:""' },
    { label: 'admin', condition: 'owner:admin' },
    { label: 'm rossi', condition: 'owner:"m rossi"' },
  ])
  assert.deepEqual(conditions(chipChoices('owner')), ['owner:""'])
  assert.deepEqual(conditions(chipChoices('created')), [
    'created:today',
    'created:>=yesterday',
    'created:>=now-7d',
    'created:>=now-30d',
  ])
  assert.deepEqual(chipChoices('nothing'), [])
})

test('a chip writes its condition into the query, replaces the one it held, and takes it away', () => {
  assert.equal(applyChip('', 'status', 'status:open', SCHEMA), 'status:open')
  assert.equal(applyChip('host:WKS status:open', 'status', 'status:closed', SCHEMA), 'host:WKS status:closed')
  assert.equal(applyChip('host:WKS status:open', 'status', '!status:closed', SCHEMA), 'host:WKS !status:closed')
  // The one it holds already, or "any": the condition goes.
  assert.equal(applyChip('host:WKS status:open', 'status', 'status:open', SCHEMA), 'host:WKS')
  assert.equal(applyChip('host:WKS status:open', 'status', '', SCHEMA), 'host:WKS')
  // By the other name of the field too.
  assert.equal(applyChip('assignee:bob', 'owner', 'owner:""', SCHEMA), 'owner:""')
  // A query the builder does not rewrite is kept, and the condition added to the whole.
  assert.equal(applyChip('a or b', 'severity', 'severity:>=high', SCHEMA), '(a or b) severity:>=high')
  assert.equal(applyChip('x', 'nothing', 'y:z', SCHEMA), 'x')
})

test('a chip shows the condition the query holds on its field', () => {
  assert.equal(chipCondition('host:WKS severity:>=high', 'severity', SCHEMA), 'severity:>=high')
  assert.equal(chipCondition('host:WKS !status:closed', 'status', SCHEMA), '!status:closed')
  assert.equal(chipCondition('owner:""', 'owner', SCHEMA), 'owner:""')
  assert.equal(chipCondition('host:WKS', 'severity', SCHEMA), '')
  assert.equal(chipCondition('(broken', 'severity', SCHEMA), null)
  // Every choice of every chip is read back as it was written.
  const context = { types: [{ name: 'Data leak' }], assignees: ['m rossi'], me: 'rita' }
  for (const chip of CHIPS) {
    for (const choice of chipChoices(chip.id, context)) {
      const query = applyChip('host:WKS', chip.id, choice.condition, SCHEMA)
      assert.equal(chipCondition(query, chip.id, SCHEMA), choice.condition, choice.condition)
    }
  }
})

test('"Field…" offers the fields no chip writes first, and writes a row of the builder', () => {
  assert.deepEqual(
    otherFields(SCHEMA).map((field) => field.name),
    ['name', 'host', 'severity', 'status', 'owner', 'created', 'type'],
  )
  assert.deepEqual(otherFields(null), [])
  assert.equal(rowCondition({ field: 'host', op: '=', value: 'WKS 01', value2: '' }), 'host:"WKS 01"')
  assert.equal(rowCondition({ field: 'host', op: '=', value: '', value2: '' }), '')
  assert.equal(
    addCondition('status:open host:old', { field: 'host', op: '!', value: 'WKS', value2: '' }, SCHEMA),
    'status:open !host:WKS',
  )
  assert.equal(
    addCondition('status:open', { field: 'closed', op: 'filled', value: '', value2: '' }, SCHEMA),
    'status:open closed:*',
  )
  assert.equal(addCondition('status:open', { field: 'host', op: '=', value: '', value2: '' }, SCHEMA), 'status:open')
})
