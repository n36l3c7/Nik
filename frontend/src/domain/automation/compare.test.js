import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  boundsOf,
  changesOf,
  compareFields,
  compareGraphs,
  countsOf,
  edgeKey,
  fieldLabel,
  fieldText,
  fieldsOf,
  lineText,
  marksOf,
} from './compare.js'

const at = (x, y) => ({ x, y })
const node = (id, kind, name, config = {}, position = at(0, 0)) => ({ id, kind, name, position, config })

// Main: a trigger, a look-up, a task for a person, a condition, the severity set.
const MAIN = {
  nodes: [
    node('start', 'trigger', 'Incident created', { event: 'incident.created' }, at(120, 20)),
    node(
      'lookup',
      'action',
      'URL report',
      { action: 'vt.url', instance: 'default', args: { url: '{{ item }}' }, on_error: { mode: 'stop' } },
      at(120, 100),
    ),
    node('check', 'task', 'Analyst checks the URLs', { title: 'Check them' }, at(120, 180)),
    node('bad', 'condition', 'Any malicious?', { all: [{ left: '{{ lookup.verdict }}', op: 'eq' }] }, at(120, 260)),
    node('severity', 'action', 'Set the severity', { action: 'nik.set', args: { severity: 'high' } }, at(120, 340)),
  ],
  edges: [
    { from: 'start', to: 'lookup' },
    { from: 'lookup', to: 'check' },
    { from: 'check', to: 'bad', port: 'done' },
    { from: 'bad', to: 'severity', port: 'yes' },
  ],
}

// The branch: the look-up uses another instance and goes on after a failure, two commands take the
// place of the task, and the severity node sits somewhere else.
const BRANCH = {
  nodes: [
    MAIN.nodes[0],
    node(
      'lookup',
      'action',
      'URL report',
      { action: 'vt.url', instance: 'lab', args: { url: '{{ item }}' }, on_error: { mode: 'continue' } },
      at(120, 100),
    ),
    node('submit', 'action', 'urlscan.io: submit', { action: 'urlscan.submit', args: { url: '{{ item }}' } }),
    node('result', 'action', 'urlscan.io: wait for result', { action: 'urlscan.result' }),
    MAIN.nodes[3],
    { ...MAIN.nodes[4], position: at(400, 600) },
  ],
  edges: [
    { from: 'start', to: 'lookup' },
    { from: 'lookup', to: 'submit' },
    { from: 'submit', to: 'result' },
    { from: 'result', to: 'bad' },
    { from: 'bad', to: 'severity', port: 'yes' },
  ],
}

test('nodes are added, removed or changed by their id, and one that only moved is not a change', () => {
  const diff = compareGraphs(MAIN, BRANCH)
  assert.deepEqual(
    diff.nodes.map((entry) => [entry.change, entry.id, entry.name]),
    [
      ['changed', 'lookup', 'URL report'],
      ['added', 'submit', 'urlscan.io: submit'],
      ['added', 'result', 'urlscan.io: wait for result'],
      ['removed', 'check', 'Analyst checks the URLs'],
    ],
  )
  assert.equal(diff.moved, 1)
  assert.equal(diff.same, false)
  assert.deepEqual(diff.counts, {
    added: 2,
    changed: 1,
    removed: 1,
    linesAdded: 0,
    linesRemoved: 0,
    linesMoved: 1,
    playbook: 0,
    moved: 1,
  })
  assert.deepEqual(
    countsOf(diff).map((count) => count.text),
    ['+2 added', '~1 changed', '-1 removed', '1 line moved', '1 node only moved'],
  )
})

test('a changed node says which fields differ, key by key, and which are the same', () => {
  const [lookup, submit, , check] = compareGraphs(MAIN, BRANCH).nodes
  assert.deepEqual(lookup.fields, [
    { path: 'kind', change: 'same', before: 'action', after: 'action' },
    { path: 'name', change: 'same', before: 'URL report', after: 'URL report' },
    { path: 'action', change: 'same', before: 'vt.url', after: 'vt.url' },
    { path: 'instance', change: 'changed', before: 'default', after: 'lab' },
    { path: 'args.url', change: 'same', before: '{{ item }}', after: '{{ item }}' },
    { path: 'on_error.mode', change: 'changed', before: 'stop', after: 'continue' },
  ])
  // An added node has every field on the side of the branch, a removed one on the side of main.
  assert.ok(submit.fields.every((field) => field.change === 'added' && !('before' in field)))
  assert.deepEqual(
    check.fields.map((field) => [field.path, field.change, field.before]),
    [
      ['kind', 'removed', 'task'],
      ['name', 'removed', 'Analyst checks the URLs'],
      ['title', 'removed', 'Check them'],
    ],
  )
})

test('the kind, the name, a key that comes or goes and a pinned script version are changes', () => {
  const before = { nodes: [node('a', 'script', 'Parse', { script: 'Parse', args: { text: 'x' } })], edges: [] }
  const change = (patch, config) => {
    const after = { nodes: [{ ...before.nodes[0], ...patch, config: config ?? before.nodes[0].config }], edges: [] }
    return compareGraphs(before, after)
      .nodes.flatMap((entry) => entry.fields)
      .filter((field) => field.change !== 'same')
  }
  assert.deepEqual(change({ name: 'Parse the mail' }), [
    { path: 'name', change: 'changed', before: 'Parse', after: 'Parse the mail' },
  ])
  assert.deepEqual(change({ kind: 'action' }), [{ path: 'kind', change: 'changed', before: 'script', after: 'action' }])
  assert.deepEqual(change({}, { script: 'Parse', args: { text: 'x' }, script_version: 3 }), [
    { path: 'script_version', change: 'added', after: 3 },
  ])
  assert.deepEqual(change({}, { script: 'Parse' }), [{ path: 'args.text', change: 'removed', before: 'x' }])
  // The order of the keys is not a change, nor is a configuration that is missing instead of empty.
  assert.deepEqual(change({}, { args: { text: 'x' }, script: 'Parse' }), [])
  const bare = { nodes: [{ id: 'e', kind: 'end', name: 'End' }], edges: [] }
  const empty = { nodes: [{ id: 'e', kind: 'end', name: 'End', config: {}, position: at(40, 40) }], edges: [] }
  assert.equal(compareGraphs(bare, empty).same, true)
})

test('a list of plain values is one field, a list of objects is gone into', () => {
  const fields = fieldsOf(
    node('ask', 'ask', 'Block it?', {
      choices: ['Yes', 'No'],
      all: [{ left: '{{ a }}', op: 'eq', right: 1 }],
      args: {},
    }),
  )
  assert.deepEqual(
    [...fields],
    [
      ['kind', 'ask'],
      ['name', 'Block it?'],
      ['choices', ['Yes', 'No']],
      ['all[0].left', '{{ a }}'],
      ['all[0].op', 'eq'],
      ['all[0].right', 1],
      ['args', {}],
    ],
  )
  // A key of the configuration called like the name of the node keeps a path of its own.
  assert.deepEqual(
    [...fieldsOf(node('a', 'action', 'Say', { name: 'x' }))],
    [
      ['kind', 'action'],
      ['name', 'Say'],
      ['config.name', 'x'],
    ],
  )
  assert.deepEqual(compareFields(new Map([['choices', ['Yes', 'No']]]), new Map([['choices', ['Yes', 'Maybe']]])), [
    { path: 'choices', change: 'changed', before: ['Yes', 'No'], after: ['Yes', 'Maybe'] },
  ])
})

test('lines are compared by where they leave, the port and where they go', () => {
  const diff = compareGraphs(MAIN, BRANCH)
  assert.deepEqual(diff.lines, [
    // The line out of the look-up goes somewhere else: moved. The others came or went with a node.
    { change: 'moved', from: 'lookup', port: 'out', to: 'submit', was: 'check', implied: false },
    { change: 'added', from: 'submit', port: 'out', to: 'result', implied: true },
    { change: 'added', from: 'result', port: 'out', to: 'bad', implied: true },
    { change: 'removed', from: 'check', port: 'done', to: 'bad', implied: true },
  ])

  const two = (edges) => ({
    nodes: [node('c', 'condition', 'Bad?'), node('x', 'action', 'Block'), node('y', 'action', 'Tell')],
    edges,
  })
  const drawn = compareGraphs(two([{ from: 'c', to: 'x', port: 'yes' }]), two([{ from: 'c', to: 'x', port: 'no' }]))
  // Another port is another line: one drawn, one taken away.
  assert.deepEqual(
    drawn.lines.map((line) => [line.change, line.port, line.implied]),
    [
      ['added', 'no', false],
      ['removed', 'yes', false],
    ],
  )
  assert.deepEqual(
    countsOf(drawn).map((count) => count.text),
    ['1 line added', '1 line removed'],
  )
  // A port that is not named is the first of the node, and the corners of a line are drawing.
  const named = two([{ from: 'x', to: 'y', port: 'out' }])
  const routed = two([{ from: 'x', to: 'y', points: [at(10, 10)] }])
  assert.equal(compareGraphs(named, routed).same, true)
})

test('identical graphs differ in nothing, and nothing is compared with something', () => {
  const diff = compareGraphs(MAIN, structuredClone(MAIN))
  assert.equal(diff.same, true)
  assert.deepEqual([diff.nodes, diff.lines, diff.playbook, diff.moved], [[], [], [], 0])
  assert.deepEqual(countsOf(diff), [{ change: 'same', text: 'nothing differs' }])
  assert.deepEqual(changesOf(diff, MAIN, MAIN), [])

  // Only positions: nothing differs, and it is said how many nodes sit elsewhere.
  const shifted = { ...MAIN, nodes: MAIN.nodes.map((item) => ({ ...item, position: at(item.position.x + 50, 0) })) }
  const only = compareGraphs(MAIN, shifted)
  assert.equal(only.same, true)
  assert.deepEqual(
    countsOf(only).map((count) => count.text),
    ['nothing differs', '5 nodes only moved'],
  )

  // A playbook with no version yet: everything in the branch is added.
  for (const nothing of [null, undefined, {}]) {
    const all = compareGraphs(nothing, MAIN)
    assert.deepEqual([all.counts.added, all.counts.changed, all.counts.removed], [5, 0, 0])
    assert.ok(all.lines.every((line) => line.change === 'added' && line.implied))
  }
})

test('the inputs and the outputs of the playbook are compared too', () => {
  const before = { ...MAIN, inputs: [{ name: 'word', type: 'text' }] }
  const after = { ...MAIN, inputs: [{ name: 'word', type: 'number' }], outputs: [{ name: 'said', from: '{{ a }}' }] }
  const diff = compareGraphs(before, after)
  assert.deepEqual(diff.playbook, [
    { path: 'inputs[0].type', change: 'changed', before: 'text', after: 'number' },
    { path: 'outputs[0].name', change: 'added', after: 'said' },
    { path: 'outputs[0].from', change: 'added', after: '{{ a }}' },
  ])
  assert.equal(diff.same, false)
  assert.deepEqual(
    countsOf(diff).map((count) => count.text),
    ['~inputs or outputs changed'],
  )
  assert.deepEqual(changesOf(diff, before, after), [
    { key: 'playbook', change: 'changed', sign: '~', text: 'Inputs and outputs of the playbook' },
  ])
})

test('the list of the changes: nodes by their sign, then the lines no node already tells', () => {
  const diff = compareGraphs(MAIN, BRANCH)
  assert.deepEqual(
    changesOf(diff, MAIN, BRANCH).map((item) => [item.sign, item.text, item.node]),
    [
      ['~', 'URL report', 'lookup'],
      ['+', 'urlscan.io: submit', 'submit'],
      ['+', 'urlscan.io: wait for result', 'result'],
      ['-', 'Analyst checks the URLs', 'check'],
      ['~', 'Line: URL report to urlscan.io: submit (was to Analyst checks the URLs) · moved', undefined],
    ],
  )
  const names = { c: { kind: 'condition', name: 'Bad?' }, x: { name: 'Block' } }
  assert.equal(
    lineText({ change: 'added', from: 'c', port: 'no', to: 'x' }, (id) => names[id] ?? null),
    'Line: Bad?, no, to Block',
  )
  assert.equal(lineText({ change: 'removed', from: 'a', port: 'out', to: 'b' }), 'Line: a to b')
})

test('each side marks what is its own: main what was removed, the branch what was added', () => {
  const diff = compareGraphs(MAIN, BRANCH)
  assert.deepEqual(marksOf(diff, 'main'), {
    nodes: { lookup: 'changed', check: 'removed' },
    edges: { [edgeKey('lookup', 'out', 'check')]: 'moved', [edgeKey('check', 'done', 'bad')]: 'removed' },
  })
  assert.deepEqual(marksOf(diff, 'branch'), {
    nodes: { lookup: 'changed', submit: 'added', result: 'added' },
    edges: {
      [edgeKey('lookup', 'out', 'submit')]: 'moved',
      [edgeKey('submit', 'out', 'result')]: 'added',
      [edgeKey('result', 'out', 'bad')]: 'added',
    },
  })
})

test('a field is shown as a line of text, and both graphs fit one rectangle', () => {
  assert.equal(fieldLabel('on_error.mode'), 'on error.mode')
  assert.deepEqual(['{{ item }}', '', 3, true, null, ['a', 'b'], {}, undefined].map(fieldText), [
    '{{ item }}',
    '(empty)',
    '3',
    'true',
    'null',
    '["a","b"]',
    '{}',
    '',
  ])
  assert.deepEqual(boundsOf([MAIN, BRANCH], 200, 60), { x: 0, y: 0, width: 600, height: 660 })
  assert.equal(boundsOf([{}, null], 200, 60), null)
})
