import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  cellText,
  classifierBody,
  classifierRows,
  mapperBodies,
  mapperKey,
  unsavedText,
  classifierRules,
  conditionOf,
  conditionRow,
  moved,
  ruleBody,
  ruleForm,
  ruleProblem,
  ruleText,
  conditionText,
  extraRows,
  fieldsOfSample,
  incomingRows,
  incomingRules,
  outgoingRows,
  outgoingRules,
  parseSample,
  textToFrom,
  withField,
} from './mappers.js'

const TARGETS = {
  fields: [
    { name: 'agent_group', label: 'Agent group', type: 'text', required: true },
    { name: 'name', label: 'Name', type: 'text', required: false },
    { name: 'severity', label: 'Severity', type: 'choice', required: false },
    { name: 'host', label: 'Host', type: 'text', required: false },
  ],
}
const RULES = [
  { to: 'severity', from: '{{ item.score | severity }}', authoritative: true },
  { to: 'Alert(val.ID == obj.ID)', from: { ID: '{{ item.id }}' }, authoritative: false },
  { to: 'ext.acme.agent_uuid', from: '{{ item.agent.uuid }}', authoritative: false },
]

test('the rows of an incoming mapper: what the type needs, what is mapped, the rest', () => {
  const rows = incomingRows(TARGETS, RULES)
  assert.deepEqual(
    rows.map((row) => [row.name, row.group, row.from, row.authoritative]),
    [
      ['agent_group', 'required', '', false],
      ['severity', 'mapped', '{{ item.score | severity }}', true],
      ['name', 'rest', '', false],
      ['host', 'rest', '', false],
    ],
  )
  // What writes to the context is beside the table, as it was saved.
  const extras = extraRows(TARGETS, RULES)
  assert.deepEqual(extras, [
    { to: 'Alert(val.ID == obj.ID)', from: '{"ID":"{{ item.id }}"}' },
    { to: 'ext.acme.agent_uuid', from: '{{ item.agent.uuid }}' },
  ])
  // Back to rules: only the rows that read something, an object read as one.
  const typed = rows.map((row) => (row.name === 'host' ? { ...row, from: ' {{ item.agent.computerName }} ' } : row))
  assert.deepEqual(incomingRules(typed, [...extras, { to: ' ', from: 'x' }, { to: 'ext.acme.x', from: '' }]), [
    { to: 'severity', from: '{{ item.score | severity }}', authoritative: true },
    { to: 'host', from: '{{ item.agent.computerName }}', authoritative: false },
    { to: 'Alert(val.ID == obj.ID)', from: { ID: '{{ item.id }}' }, authoritative: false },
    { to: 'ext.acme.agent_uuid', from: '{{ item.agent.uuid }}', authoritative: false },
  ])
  assert.deepEqual(incomingRows(null, null), [])
  assert.equal(textToFrom('{not json'), '{not json')
})

test('the rows of an outgoing mapper: the names the product takes, and those written besides', () => {
  const schema = { outgoing: [{ name: 'short_description' }, { name: 'urgency' }] }
  const rules = [
    { to: 'urgency', from: "{{ incident.severity | map(high='1') }}" },
    { to: 'u_custom', from: 'security' },
  ]
  const rows = outgoingRows(schema, rules)
  assert.deepEqual(
    rows.map((row) => [row.to, row.from, row.known]),
    [
      ['short_description', '', true],
      ['urgency', "{{ incident.severity | map(high='1') }}", true],
      ['u_custom', 'security', false],
    ],
  )
  assert.deepEqual(outgoingRules(rows), rules)
  assert.deepEqual(outgoingRows(null, null), [])
})

test('a field of the product goes into an expression; a sample is read from what was pasted', () => {
  assert.equal(withField('', 'threatInfo.threatName'), '{{ item.threatInfo.threatName }}')
  assert.equal(withField('On', 'agent.computerName'), 'On {{ item.agent.computerName }}')
  assert.equal(withField('', 'fields.custom field'), '{{ item.fields["custom field"] }}')
  assert.equal(withField('', 'severity', 'incident'), '{{ incident.severity }}')

  assert.deepEqual(parseSample(''), { item: null, problem: null })
  assert.deepEqual(parseSample('{"id": 1}'), { item: { id: 1 }, problem: null })
  assert.deepEqual(parseSample('[{"id": 1}, {"id": 2}]').item, { id: 1 })
  assert.match(parseSample('{').problem, /^Not valid JSON/)
  assert.deepEqual(fieldsOfSample({ id: 'T-1', agent: { name: 'x', ports: [1] }, score: 5 }), [
    { name: 'id', type: 'text' },
    { name: 'agent.name', type: 'text' },
    { name: 'agent.ports', type: 'list' },
    { name: 'score', type: 'number' },
  ])
  assert.equal(cellText(['a', 'b']), '["a","b"]')
  assert.equal(cellText(true), 'yes')
  assert.equal(cellText(null), '')
  assert.equal(cellText(0), '0')
})

test('the rules of a classifier as rows, and back', () => {
  const rules = [
    { when: { all: [{ left: '{{ item.name }}', op: 'matches', right: '(?i)phish' }] }, type: 'phishing' },
    { when: { all: [{ left: '{{ item.score }}', op: 'gte', right: 80 }] }, type: 'malware' },
    {
      when: {
        any: [
          { left: '{{ item.a }}', op: 'eq', right: 1 },
          { left: '{{ item.b }}', op: 'exists' },
        ],
      },
      type: 'malware',
    },
  ]
  const rows = classifierRows(rules)
  assert.deepEqual(
    rows.map((row) => [row.left, row.op, row.right, row.type, Boolean(row.kept)]),
    [
      ['{{ item.name }}', 'matches', '(?i)phish', 'phishing', false],
      ['{{ item.score }}', 'gte', '80', 'malware', false],
      ['', 'eq', '', 'malware', true],
    ],
  )
  // A rule of several comparisons is kept as it was; a number typed is a number; an empty row is left out.
  assert.deepEqual(classifierRules([...rows, { left: ' ', op: 'eq', right: '', type: 'malware', kept: null }]), rules)
  assert.deepEqual(classifierRules([{ left: '{{ item.x }}', op: 'exists', right: 'ignored', type: 't', kept: null }]), [
    { when: { all: [{ left: '{{ item.x }}', op: 'exists' }] }, type: 't' },
  ])
  assert.equal(conditionText(rules[2].when), 'any of 2: {{ item.a }} eq 1; {{ item.b }} exists')
})

test('a pre-processing rule as its form, and back', () => {
  const rule = {
    id: 'r1',
    name: 'Same host, same case',
    enabled: true,
    when: { all: [{ left: '{{ incident.severity }}', op: 'ne', right: 'critical' }] },
    action: 'link_to_existing',
    params: { same: ['host'], within_hours: 48 },
  }
  const form = ruleForm(rule)
  assert.deepEqual(form.condition, { left: '{{ incident.severity }}', op: 'ne', right: 'critical', kept: null })
  assert.deepEqual([form.same, form.withinHours], [['host'], '48'])
  assert.equal(ruleProblem(form), null)
  assert.deepEqual(ruleBody(form), {
    name: 'Same host, same case',
    enabled: true,
    when: rule.when,
    action: 'link_to_existing',
    params: { same: ['host'], within_hours: 48 },
  })
  assert.equal(ruleText(rule), 'link it to the open incident with the same host made in the last 48 h')
  assert.equal(
    ruleText({ action: 'close_duplicate', params: { same: ['name', 'host'] } }),
    'close it as a duplicate of the open incident with the same name and host',
  )
  assert.equal(ruleText({ action: 'run_script', params: { script: 'LowScore' } }), 'ask the script LowScore')

  // A new rule: always, drop. What is missing is said.
  const fresh = ruleForm(null)
  assert.equal(ruleProblem(fresh), 'Give the rule a name')
  assert.deepEqual(ruleBody({ ...fresh, name: ' Noise ' }), {
    name: 'Noise',
    enabled: true,
    when: null,
    action: 'drop',
    params: {},
  })
  assert.equal(
    ruleProblem({ ...fresh, name: 'x', action: 'close_duplicate' }),
    'Say which fields are the same in the incident to look for',
  )
  assert.equal(ruleProblem({ ...fresh, name: 'x', action: 'run_script' }), 'Say which script decides')
  // A condition of several comparisons is kept as it was written.
  const several = {
    any: [
      { left: 'a', op: 'eq', right: 1 },
      { left: 'b', op: 'exists' },
    ],
  }
  assert.deepEqual(conditionOf(conditionRow(several)), several)
  assert.equal(conditionOf(conditionRow(null)), null)
  assert.deepEqual(conditionOf({ left: '{{ item.x }}', op: 'gte', right: '80' }), {
    all: [{ left: '{{ item.x }}', op: 'gte', right: 80 }],
  })

  assert.deepEqual(moved(['a', 'b', 'c'], 'c', -1), ['a', 'c', 'b'])
  assert.deepEqual(moved(['a', 'b', 'c'], 'a', -1), ['a', 'b', 'c'])
  assert.deepEqual(moved(['a', 'b', 'c'], 'a', 1), ['b', 'a', 'c'])
})

test('what was changed in the form of an instance is kept as drafts and sent by its one Save', () => {
  assert.equal(mapperKey('incoming', '*'), 'incoming:*')
  assert.equal(mapperKey('outgoing', ''), 'outgoing:*')
  const drafts = {
    [mapperKey('incoming', '*')]: {
      rows: [
        { name: 'name', from: '{{ item.title }}', authoritative: true },
        { name: 'severity', from: ' ', authoritative: false },
      ],
      extras: [{ to: 'Alert(val.ID == obj.ID)', from: '{"ID": "{{ item.id }}"}' }],
      outRows: [],
    },
    [mapperKey('outgoing', 'malware')]: {
      rows: [],
      extras: [],
      outRows: [
        { to: 'summary', from: '{{ incident.name }}', known: true },
        { to: '', from: 'x', known: false },
      ],
    },
  }
  assert.deepEqual(mapperBodies('acme', drafts), [
    {
      connectorId: 'acme',
      direction: 'incoming',
      incidentType: '*',
      rules: [
        { to: 'name', from: '{{ item.title }}', authoritative: true },
        { to: 'Alert(val.ID == obj.ID)', from: { ID: '{{ item.id }}' }, authoritative: false },
      ],
    },
    {
      connectorId: 'acme',
      direction: 'outgoing',
      incidentType: 'malware',
      rules: [{ to: 'summary', from: '{{ incident.name }}' }],
    },
  ])
  assert.deepEqual(mapperBodies('acme', {}), [])

  const classifier = { rows: [{ left: '{{ item.title }}', op: 'contains', right: 'Emotet', type: 'malware' }] }
  assert.deepEqual(classifierBody({ ...classifier, fallback: '' }), {
    rules: [{ when: { all: [{ left: '{{ item.title }}', op: 'contains', right: 'Emotet' }] }, type: 'malware' }],
    defaultType: null,
  })
  assert.equal(classifierBody({ rows: [], fallback: 'phishing' }).defaultType, 'phishing')

  assert.equal(unsavedText(null, {}), '')
  assert.equal(unsavedText(classifier, {}), 'the classifier')
  assert.equal(unsavedText(null, { 'incoming:*': {} }), 'a mapper')
  assert.equal(unsavedText(classifier, drafts), 'the classifier, 2 mappers')
})
