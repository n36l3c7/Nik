import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  connect,
  copyOf,
  disconnect,
  dominators,
  historyOf,
  idProblem,
  loopBodies,
  moveNodes,
  newId,
  normalise,
  portLabel,
  portName,
  portsOf,
  pruneEdges,
  slug,
  paste,
  readable,
  record,
  redo,
  removeNodes,
  renameNode,
  topological,
  undo,
  unreadable,
  updateNode,
} from './graph.js'
import {
  asksApproval,
  entryOf,
  freePosition,
  groupsOf,
  headingOf,
  nodeFrom,
  summaryOf,
  triggerFields,
  EVENTS,
  eventLabel,
  objectName,
  runsOn,
  sampleFilter,
  valueTree,
} from './catalog.js'
import { layered, tidy } from './layout.js'
import { automationFromPath, automationPath, visibleAreas } from '../automationNav.js'
import { hostOf } from './hosts.js'

const node = (id, kind, config = {}, position = { x: 0, y: 0 }) => ({ id, kind, name: id, position, config })

/*
 * start → check ─yes→ search → loop ─each→ note
 *              └no→ stop          └done→ report
 */
const GRAPH = {
  nodes: [
    node('start', 'trigger', { event: 'incident.created' }),
    node('check', 'condition', { all: [{ left: '{{ trigger.incident.severity }}', op: 'eq', right: 'high' }] }),
    node('stop', 'end'),
    node('search', 'action', { action: 'nik.get-incident', args: {} }),
    node('loop', 'for_each', { items: '{{ search.incident.tags }}' }),
    node('note', 'action', { action: 'nik.add-note', args: { text: '{{ item }} of {{ search.incident.name }}' } }),
    node('report', 'action', { action: 'nik.add-note', args: { text: '{{ loop.count }} done, {{ note.note }}' } }),
  ],
  edges: [
    { from: 'start', to: 'check' },
    { from: 'check', port: 'yes', to: 'search' },
    { from: 'check', port: 'no', to: 'stop' },
    { from: 'search', to: 'loop' },
    { from: 'loop', port: 'each', to: 'note' },
    { from: 'loop', to: 'report' },
  ],
}

test('the order, the bodies of loops and what is certain to have run', () => {
  const order = topological(GRAPH)
  assert.equal(order[0], 'start')
  assert.ok(order.indexOf('search') < order.indexOf('loop'))
  assert.deepEqual([...loopBodies(GRAPH).get('loop')], ['note'])
  assert.deepEqual([...dominators(GRAPH).get('report')].sort(), ['check', 'loop', 'search', 'start'])
  // A circle has no order.
  assert.equal(topological({ ...GRAPH, edges: [...GRAPH.edges, { from: 'report', to: 'check' }] }), null)
})

test('a node reads what ran before it; a loop body also reads its item', () => {
  assert.deepEqual(readable(GRAPH, 'report'), { nodes: ['start', 'check', 'search', 'loop'], loop: null, poll: false })
  assert.deepEqual(readable(GRAPH, 'note').loop, 'loop')
  assert.deepEqual(unreadable(GRAPH, 'note'), [])
  // "note" runs once per item: after the loop it cannot be read; "ghost" is no node at all.
  assert.deepEqual(unreadable(GRAPH, 'report'), [
    { name: 'note', reason: 'is not certain to have run before this node' },
  ])
  const odd = updateNode(GRAPH, 'stop', { config: { message: '{{ ghost.x }} {{ item }} {{ search.x }}' } })
  assert.deepEqual(
    unreadable(odd, 'stop').map((found) => found.name),
    ['ghost', 'item', 'search'],
  )
})

test('edges: drawn once, never to the trigger, never in a circle', () => {
  assert.equal(connect(GRAPH, 'report', 'out', 'start').problem, 'Nothing leads to the trigger')
  assert.equal(connect(GRAPH, 'check', 'yes', 'search').problem, 'This edge is drawn already')
  assert.match(connect(GRAPH, 'report', 'out', 'check').problem, /circle/)
  assert.match(connect(GRAPH, 'stop', 'out', 'report').problem, /no "out" port/)
  assert.equal(connect(GRAPH, 'note', 'out', 'note').problem, 'A node cannot lead to itself')
  const { graph, problem } = connect(GRAPH, 'search', 'error', 'stop')
  assert.equal(problem, null)
  assert.equal(graph.edges.length, GRAPH.edges.length + 1)
  assert.equal(disconnect(graph, 'search', 'error', 'stop').edges.length, GRAPH.edges.length)
  // The default port of an edge that names none.
  assert.equal(disconnect(GRAPH, 'loop', 'done', 'report').edges.length, GRAPH.edges.length - 1)
  assert.equal(disconnect(GRAPH, 'loop', 'error', 'report'), GRAPH)
})

test('nodes: ids, removal, moves, renames that expressions follow', () => {
  assert.equal(newId(GRAPH, 'Add a note'), 'add_a_note')
  assert.equal(newId(GRAPH, 'note'), 'note_2')
  assert.equal(newId(GRAPH, 'Run'), 'run_2')
  assert.equal(newId(GRAPH, '42 !!'), 'node')
  assert.equal(idProblem(GRAPH, 'Note'), 'A lower-case letter, then letters, digits or _ (32 at most)')
  assert.match(idProblem(GRAPH, 'item'), /name of the expressions/)
  assert.equal(idProblem(GRAPH, 'note'), 'Another node has this id')
  assert.equal(idProblem(GRAPH, 'note', 'note'), null)

  const removed = removeNodes(GRAPH, ['search', 'start'])
  assert.ok(
    removed.nodes.some((item) => item.id === 'start'),
    'the trigger stays',
  )
  assert.ok(!removed.edges.some((edge) => edge.from === 'search' || edge.to === 'search'))
  assert.equal(removeNodes(GRAPH, ['start']), GRAPH)

  assert.equal(moveNodes(GRAPH, { note: { x: 0, y: 0 } }), GRAPH)
  assert.deepEqual(moveNodes(GRAPH, { note: { x: 10.4, y: 5 } }).nodes.find((item) => item.id === 'note').position, {
    x: 10,
    y: 5,
  })

  const renamed = renameNode(GRAPH, 'search', 'lookup').graph
  assert.ok(renamed.edges.some((edge) => edge.from === 'check' && edge.to === 'lookup'))
  assert.equal(renamed.nodes.find((item) => item.id === 'loop').config.items, '{{ lookup.incident.tags }}')
  assert.equal(
    renamed.nodes.find((item) => item.id === 'note').config.args.text,
    '{{ item }} of {{ lookup.incident.name }}',
  )
  assert.equal(renameNode(GRAPH, 'search', 'note').problem, 'Another node has this id')
})

test('copy and paste: new ids, inner edges and expressions follow, the trigger is never copied', () => {
  const copied = copyOf(GRAPH, ['start', 'loop', 'note'])
  assert.deepEqual(
    copied.nodes.map((item) => item.id),
    ['loop', 'note'],
  )
  assert.deepEqual(copied.edges, [{ from: 'loop', port: 'each', to: 'note' }])
  const { graph, ids } = paste(GRAPH, copied)
  assert.deepEqual(ids, ['loop_2', 'note_2'])
  assert.ok(graph.edges.some((edge) => edge.from === 'loop_2' && edge.to === 'note_2' && edge.port === 'each'))
  assert.deepEqual(graph.nodes.find((item) => item.id === 'loop_2').position, { x: 40, y: 40 })
  // What reads a node outside the copy still reads it.
  assert.equal(graph.nodes.find((item) => item.id === 'loop_2').config.items, '{{ search.incident.tags }}')
  const twice = paste(graph, copyOf(graph, ['report', 'loop'])).graph
  assert.equal(
    twice.nodes.find((item) => item.id === 'report_2').config.args.text,
    '{{ loop_3.count }} done, {{ note.note }}',
  )
})

test('undo and redo; an edit that changed nothing is not a step', () => {
  let history = historyOf(GRAPH)
  const moved = moveNodes(GRAPH, { note: { x: 5, y: 5 } })
  history = record(history, moved)
  assert.equal(record(history, moved), history)
  history = undo(history)
  assert.equal(history.present, GRAPH)
  assert.equal(undo(history), history)
  history = redo(history)
  assert.equal(history.present, moved)
  assert.equal(redo(history), history)
})

test('a graph from the server is made safe to draw', () => {
  const graph = normalise({
    nodes: [{ id: 'a', kind: 'trigger' }, null, { kind: 'end' }],
    edges: [{ from: 'a' }, null],
  })
  assert.deepEqual(graph, { nodes: [{ id: 'a', kind: 'trigger', config: {}, position: { x: 40, y: 40 } }], edges: [] })
  assert.deepEqual(normalise(null), { nodes: [], edges: [] })
})

const entry = (id, kind, group, name, extra = {}) => ({ id, kind, group, name, arguments: [], outputs: [], ...extra })
const CATALOG = [
  entry('flow.condition', 'condition', 'Flow', 'Condition', { outputs: [{ name: 'result', type: 'bool' }] }),
  entry('flow.for_each', 'for_each', 'Flow', 'For each', { outputs: [{ name: 'count', type: 'number' }] }),
  entry('flow.end', 'end', 'Flow', 'End'),
  entry('script.GroupByField', 'script', 'Scripts', 'GroupByField', {
    script: 'GroupByField',
    version: 4,
    arguments: [{ name: 'field', type: 'text', default: 'office' }],
  }),
  entry('nik.get-incident', 'action', 'Nik', 'Get an incident', {
    description: 'Read it',
    outputs: [{ name: 'incident', type: 'object' }],
    changesOutside: false,
  }),
  entry('nik.add-note', 'action', 'Nik', 'Add a note', {
    arguments: [{ name: 'text', type: 'text', required: true }],
    outputs: [{ name: 'note', type: 'text' }],
    changesOutside: false,
  }),
  entry('http.request', 'action', 'HTTP', 'HTTP request', {
    arguments: [{ name: 'method', type: 'choice', default: 'GET' }],
    changesOutside: true,
  }),
]

test('the library: groups, search, the node an entry becomes', () => {
  assert.deepEqual(
    groupsOf(CATALOG).map((group) => group.name),
    ['Flow', 'Nik', 'HTTP', 'Scripts'],
  )
  assert.deepEqual(
    groupsOf(CATALOG, 'note').map((group) => group.entries.map((found) => found.id)),
    [['nik.add-note']],
  )
  assert.deepEqual(groupsOf(CATALOG, 'nik read'), [{ name: 'Nik', entries: [CATALOG[4]] }])

  const made = nodeFrom(CATALOG[5], GRAPH, { x: 10.6, y: 20 })
  assert.deepEqual(made, {
    id: 'add_note',
    kind: 'action',
    name: 'Add a note',
    position: { x: 11, y: 20 },
    config: { action: 'nik.add-note', args: {} },
  })
  assert.deepEqual(nodeFrom(CATALOG[6], GRAPH, { x: 0, y: 0 }).config, {
    action: 'http.request',
    args: { method: 'GET' },
  })
  assert.deepEqual(nodeFrom(CATALOG[3], GRAPH, { x: 0, y: 0 }).config, {
    script: 'GroupByField',
    script_version: 4,
    args: { field: 'office' },
  })
  assert.equal(entryOf(made, CATALOG), CATALOG[5])
  assert.equal(entryOf(node('x', 'action', { action: 'gone.away' }), CATALOG), null)
  assert.equal(entryOf(GRAPH.nodes[0], CATALOG).kind, 'trigger')
  assert.equal(headingOf(made, CATALOG[5]), 'Action · Nik')
  assert.equal(summaryOf(GRAPH.nodes[0]), 'incident.created')
  assert.equal(summaryOf(made, CATALOG[5]), 'Add a note')
  assert.equal(summaryOf({ ...made, config: { args: { text: 'hello' } } }, CATALOG[5]), 'text: hello')
  assert.equal(summaryOf({ ...made, name: 'Tell the team' }, CATALOG[5]), 'Add a note')
  assert.equal(
    summaryOf({ ...node('g', 'action', { action: 'nik.get-incident' }), name: 'Get an incident' }, CATALOG[4]),
    'Read it',
  )
  assert.equal(summaryOf(node('w', 'wait', { seconds: 7200 })), '2 h')
  assert.equal(summaryOf(node('a', 'approval', { question: 'Open a ticket?' })), 'Open a ticket? · waits without limit')
  assert.equal(summaryOf(node('x', 'action', { action: 'gone.away' }), null), 'this action does not exist any more')
})

test('approval before a node: its own setting, else what it does and the default of the playbook', () => {
  const http = node('call', 'action', { action: 'http.request', args: {} })
  assert.equal(asksApproval(http, CATALOG[6], true), true)
  assert.equal(asksApproval(http, CATALOG[6], false), false)
  assert.equal(asksApproval({ ...http, config: { ...http.config, approval: { ask: false } } }, CATALOG[6], true), false)
  assert.equal(asksApproval(GRAPH.nodes[5], CATALOG[5], true), false)
  assert.equal(asksApproval({ ...GRAPH.nodes[5], config: { approval: { ask: true } } }, CATALOG[5], true), true)
})

test('the values a node can pick', () => {
  const tree = valueTree({ ...GRAPH, inputs: [{ name: 'reason', type: 'text' }] }, 'note', CATALOG)
  assert.deepEqual(
    tree.map((root) => root.name),
    ['trigger', 'check', 'search', 'loop', 'item', 'index', 'inputs', 'run', 'incident', 'context'],
  )
  // The incident as it is when the step runs, and what is known of it.
  assert.equal(tree[8].fields.find((field) => field.name === 'owner').path, 'incident.owner')
  assert.equal(tree[9].fields.find((field) => field.name === 'Ticket').path, 'context.Ticket')
  assert.equal(tree[0].fields[0].path, 'trigger.incident.id')
  assert.deepEqual(tree[2].fields, [{ name: 'incident', type: 'object', path: 'search.incident' }])
  assert.equal(tree[4].fields[0].path, 'item')
  assert.equal(tree[6].fields[0].path, 'inputs.reason')
  assert.ok(!valueTree(GRAPH, 'report', CATALOG).some((root) => root.name === 'item'))
  assert.deepEqual(
    triggerFields({ cron: '0 * * * *' }).map((field) => field.name),
    ['at', 'cron'],
  )
  assert.ok(triggerFields({ event: 'incident.updated' }).some((field) => field.name === 'changed'))
  assert.equal(triggerFields({ manual: true })[0].name, 'actor')
})

test('each event says what its trigger holds, what it is about and a filter to start from', () => {
  const names = (config) => triggerFields(config).map((field) => field.name)
  assert.ok(names({ event: 'mail.analysed' }).includes('mail.sender_sha256'))
  assert.ok(names({ event: 'mail.analysed' }).includes('from_mailbox'))
  // An e-mail may have been analysed in an incident, or not.
  assert.equal(triggerFields({ event: 'mail.analysed' }).find((field) => field.name === 'incident.id').optional, true)
  assert.ok(names({ event: 'file.analysed' }).includes('file.yara'))
  assert.ok(names({ event: 'url.analysed' }).includes('scan.final_url'))
  assert.ok(!names({ event: 'url.analysed' }).includes('incident.id'))
  assert.ok(names({ event: 'ioc.verdict_changed' }).includes('ioc.old'))
  assert.ok(names({ event: 'ioc.watch_hit' }).includes('list.name'))
  assert.ok(names({ event: 'ioc.watch_hit' }).includes('incident.id'))
  assert.deepEqual(names({ event: 'storage.low' }), ['disk.total', 'disk.used', 'disk.free', 'disk.free_percent'])
  assert.deepEqual(names({ webhook: true }), ['body', 'headers', 'query'])
  assert.deepEqual(names({ event: 'not.an.event' }), [])

  assert.equal(runsOn({ event: 'ioc.watch_hit' }), 'incident')
  assert.equal(runsOn({ event: 'url.analysed' }), 'url')
  assert.equal(runsOn({ event: 'storage.low' }), '')
  assert.equal(runsOn({ manual: true }), '')
  assert.equal(objectName('mail'), 'an e-mail')
  assert.equal(objectName(''), 'nothing')
  assert.equal(eventLabel('file.analysed'), 'A file is analysed · file.analysed')
  // The analyses the workers make say when they end: a playbook reads what they found, and their status.
  assert.ok(names({ event: 'code.analysed' }).includes('code.status'))
  assert.ok(names({ event: 'code.analysed' }).includes('file.sha256'))
  assert.ok(names({ event: 'capabilities.analysed' }).includes('capabilities.attack'))
  assert.ok(names({ event: 'capture.analysed' }).includes('capture.packets'))
  assert.equal(runsOn({ event: 'capabilities.analysed' }), 'file')
  assert.equal(runsOn({ event: 'capture.analysed' }), 'pcap')
  assert.equal(objectName('pcap'), 'a capture')
  assert.equal(eventLabel('later.event'), 'later.event')
  assert.deepEqual(sampleFilter('mail.analysed'), {
    all: [{ left: '{{ trigger.mail.verdict }}', op: 'eq', right: 'phishing' }],
  })
  assert.equal(sampleFilter('storage.low').all[0].op, 'lt')
  // Every event the server offers is described here.
  for (const event of Object.keys(EVENTS)) assert.ok(triggerFields({ event }).length > 0, event)
  assert.equal(summaryOf({ kind: 'trigger', config: { webhook: true, manual: true } }, null), 'webhook · by hand')
})

test('positions: under the lowest node, beside what is in the way, and tidied in rows', async () => {
  assert.deepEqual(freePosition({ nodes: [] }), { x: 40, y: 40 })
  const two = {
    nodes: [node('a', 'trigger', {}, { x: 40, y: 40 }), node('b', 'end', {}, { x: 40, y: 150 })],
    edges: [],
  }
  assert.deepEqual(freePosition(two), { x: 40, y: 260 })
  assert.deepEqual(freePosition(two, 'a'), { x: 260, y: 150 })

  const rows = layered(GRAPH)
  assert.equal(rows.start.y, 40)
  assert.ok(rows.check.y > rows.start.y && rows.search.y > rows.check.y && rows.report.y > rows.loop.y)
  assert.equal(rows.search.y, rows.stop.y)
  assert.notEqual(rows.search.x, rows.stop.x)
  const tidied = (await tidy(GRAPH)).positions
  assert.equal(Object.keys(tidied).length, GRAPH.nodes.length)
  assert.ok(tidied.check.y > tidied.start.y)
})

test('the addresses of the Automations area', () => {
  assert.equal(automationFromPath('/incident/x'), null)
  assert.deepEqual(automationFromPath('/automation'), { area: 'playbooks', id: null, tab: null })
  assert.deepEqual(automationFromPath('/automation/playbooks/'), { area: 'playbooks', id: null, tab: null })
  assert.deepEqual(automationFromPath('/automation/playbooks/ab12'), { area: 'playbooks', id: 'ab12', tab: 'canvas' })
  assert.deepEqual(automationFromPath('/automation/playbooks/ab12/settings'), {
    area: 'playbooks',
    id: 'ab12',
    tab: 'settings',
  })
  assert.deepEqual(automationFromPath('/automation/playbooks/ab12/nope'), {
    area: 'playbooks',
    id: 'ab12',
    tab: 'canvas',
  })
  assert.deepEqual(automationFromPath('/automation/nowhere/1'), { area: 'playbooks', id: null, tab: null })
  assert.deepEqual(automationFromPath('/automation/runs'), { area: 'runs', id: null, tab: null })
  assert.deepEqual(automationFromPath('/automation/runs/r1'), { area: 'runs', id: 'r1', tab: null })
  assert.deepEqual(automationFromPath('/automation/approvals/x'), { area: 'approvals', id: null, tab: null })
  assert.deepEqual(automationFromPath('/automation/playbooks/ab12/runs'), {
    area: 'playbooks',
    id: 'ab12',
    tab: 'runs',
  })
  assert.equal(automationPath('runs', 'r1'), '/automation/runs/r1')
  assert.deepEqual(automationFromPath('/automation/scripts/s1'), { area: 'scripts', id: 's1', tab: null })
  const canOf =
    (...granted) =>
    (permission) =>
      granted.includes(permission)
  assert.deepEqual(
    visibleAreas(canOf('automation.run')).map((area) => area.id),
    ['playbooks', 'runs', 'approvals'],
  )
  assert.deepEqual(
    visibleAreas(canOf('automation.run', 'automation.edit')).map((area) => area.id),
    ['playbooks', 'scripts', 'runs', 'approvals'],
  )
  assert.equal(automationPath(), '/automation/playbooks')
  assert.equal(automationPath('playbooks', 'a b'), '/automation/playbooks/a%20b')
  assert.equal(automationPath('playbooks', 'ab12', 'canvas'), '/automation/playbooks/ab12')
  assert.equal(automationPath('playbooks', 'ab12', 'versions'), '/automation/playbooks/ab12/versions')
  // A branch of a playbook has an address of its own, on the canvas.
  assert.equal(automationPath('playbooks', 'ab12', null, 'b 1'), '/automation/playbooks/ab12/branches/b%201')
  assert.equal(automationPath('playbooks', 'ab12', 'runs', 'b1'), '/automation/playbooks/ab12/runs')
  assert.equal(automationPath('runs', 'r1', null, 'b1'), '/automation/runs/r1')
  assert.deepEqual(automationFromPath('/automation/playbooks/ab12/branches/b%201'), {
    area: 'playbooks',
    id: 'ab12',
    tab: 'canvas',
    branch: 'b 1',
  })
  assert.deepEqual(automationFromPath('/automation/playbooks/ab12/branches'), {
    area: 'playbooks',
    id: 'ab12',
    tab: 'canvas',
  })
})

test('a pasted address is listed as its host', () => {
  assert.equal(hostOf(' https://Hooks.Example.org/path?x=1 '), 'hooks.example.org')
  assert.equal(hostOf('api.example.org:8443'), 'api.example.org:8443')
  assert.equal(hostOf('http://10.0.0.5:8080/'), '10.0.0.5:8080')
  assert.equal(hostOf('example.org.'), 'example.org')
  assert.equal(hostOf('not a host'), 'not a host') // the server says why it is refused
  assert.equal(hostOf(null), '')
})

test('a question leaves by its choices, a task by done and overdue', () => {
  const ask = node('q', 'ask', { question: 'Encrypted?', choices: ['Yes', 'No, not at all'] })
  assert.deepEqual(portsOf(ask), ['yes', 'no_not_at_all', 'timeout'])
  assert.deepEqual(portsOf(node('q', 'ask', { question: 'Serial?' })), ['answered', 'timeout'])
  assert.deepEqual(portsOf(node('t', 'task', { title: 'x' })), ['done', 'overdue'])
  assert.equal(slug('  Yes, block it!  '), 'yes_block_it')
  assert.equal(slug('???'), 'answer')
  // An edge is named as the choice it follows.
  assert.equal(portLabel(ask, 'no_not_at_all'), 'No, not at all')
  assert.equal(portLabel(ask, 'timeout'), 'no answer')
  assert.equal(portName(node('t', 'task'), 'overdue'), 'when overdue')
  assert.equal(portName(node('a', 'action'), 'out'), 'then')

  const graph = {
    nodes: [node('start', 'trigger', { manual: true }), ask, node('a', 'end'), node('b', 'end')],
    edges: [{ from: 'start', to: 'q' }],
  }
  const drawn = connect(connect(graph, 'q', 'yes', 'a').graph, 'q', 'no_not_at_all', 'b').graph
  assert.equal(drawn.edges.length, 3)
  assert.match(connect(graph, 'q', 'answered', 'a').problem, /no "answered" port/)
  // A choice that is gone takes its edges with it; the others stay.
  const fewer = pruneEdges(updateNode(drawn, 'q', { config: { question: 'Encrypted?', choices: ['Yes'] } }), 'q')
  assert.deepEqual(
    fewer.edges.map((edge) => edge.port ?? ''),
    ['', 'yes'],
  )
  assert.equal(pruneEdges(drawn, 'q'), drawn)

  assert.equal(
    summaryOf(node('t', 'task', { title: 'Pull the disk', assignee: { role: 'analyst' } })),
    'Pull the disk · for the role analyst',
  )
  assert.equal(summaryOf(node('t', 'task', { title: 'Pull the disk' })), 'Pull the disk · for the owner')
  assert.equal(summaryOf(ask), 'Encrypted? · to anyone')
})

test('the values a node can read go into what the blocks before give', async () => {
  const { subFields, withSubFields } = await import('./catalog.js')
  const sample = {
    uid: 0,
    from: '',
    to: [''],
    attachments: [{ name: '', size: 0, 'content-type': '' }],
    headers: { subject: '', nested: { deep: { deeper: { deepest: 1 } } } },
    empty: [],
  }
  assert.deepEqual(
    subFields('attachments', sample.attachments).map((field) => [field.name, field.type]),
    [
      ['attachments[0].name', 'text'],
      ['attachments[0].size', 'number'],
    ], // a key that is not a plain name is left out
  )
  assert.deepEqual(subFields('to', sample.to), [{ name: 'to[0]', type: 'text', description: 'The first of to' }])
  assert.deepEqual(subFields('empty', []), [])
  assert.deepEqual(subFields('uid', 0), [])
  // Three levels and no further.
  assert.deepEqual(
    subFields('headers', sample.headers).map((field) => field.name),
    ['headers.subject', 'headers.nested', 'headers.nested.deep', 'headers.nested.deep.deeper'],
  )

  const outputs = [
    { name: 'from', type: 'any' },
    { name: 'attachments', type: 'any' },
    { name: 'gone', type: 'any' },
  ]
  assert.deepEqual(
    withSubFields(outputs, sample).map((field) => field.name),
    ['from', 'attachments', 'attachments[0].name', 'attachments[0].size', 'gone'],
  )
  assert.equal(withSubFields(outputs, null), outputs)
  assert.equal(withSubFields(outputs, []), outputs)

  // In the tree of a node: the paths are under the block that gives them.
  const graph = {
    nodes: [
      { id: 'start', kind: 'trigger', config: { manual: true } },
      { id: 'read', kind: 'action', name: 'Read', config: { action: 'mail.get-message', args: {} } },
      { id: 'say', kind: 'action', name: 'Say', config: { action: 'nik.add-note', args: {} } },
    ],
    edges: [
      { from: 'start', to: 'read' },
      { from: 'read', to: 'say' },
    ],
  }
  const entries = [
    { id: 'mail.get-message', kind: 'action', group: 'Mail', name: 'get-message', outputs, sample },
    { id: 'nik.add-note', kind: 'action', group: 'Nik', name: 'Add a note', outputs: [] },
  ]
  const read = valueTree(graph, 'say', entries).find((root) => root.name === 'read')
  assert.deepEqual(
    read.fields.map((field) => field.path),
    ['read.from', 'read.attachments', 'read.attachments[0].name', 'read.attachments[0].size', 'read.gone'],
  )
})

test('the library is in tabs, and its search looks in all of them', async () => {
  const { libraryOf, tabOf } = await import('./catalog.js')
  const entries = [
    { id: 'condition', kind: 'condition', group: 'Flow', name: 'Condition' },
    { id: 'nik.add-note', kind: 'action', group: 'Nik', name: 'Add a note' },
    { id: 'mail.send', kind: 'action', group: 'Mail', name: 'send', connector: 'mail', available: true },
    { id: 'jira.create', kind: 'action', group: 'Jira', name: 'create-issue', connector: 'jira', available: false },
    { id: 'jira.get', kind: 'action', group: 'Jira', name: 'get-issue', connector: 'jira', available: false },
    { id: 'email.send', kind: 'action', group: 'E-mail', name: 'Send an e-mail', retired: true },
    { id: 'script.Count', kind: 'script', group: 'Scripts', name: 'CountWords' },
  ]
  assert.deepEqual(entries.map(tabOf), ['flow', 'commands', 'commands', 'commands', 'commands', 'commands', 'scripts'])
  const names = (found) => found.groups.map((group) => [group.name, group.entries.map((entry) => entry.name)])

  const commands = libraryOf(entries, 'commands')
  // Only the connectors with an instance that is on; nothing that is kept for older playbooks.
  assert.deepEqual(names(commands), [
    ['Nik', ['Add a note']],
    ['Mail', ['send']],
  ])
  assert.deepEqual(commands.counts, { commands: 2, scripts: 1, flow: 1 })
  assert.equal(commands.hidden, 1) // Jira, whatever the number of its commands
  assert.equal(commands.searching, false)
  assert.deepEqual(names(libraryOf(entries, 'scripts')), [['Scripts', ['CountWords']]])
  assert.deepEqual(names(libraryOf(entries, 'flow')), [['Flow', ['Condition']]])

  // Typed, the search does not mind which tab is open.
  const found = libraryOf(entries, 'scripts', 'cond')
  assert.deepEqual(names(found), [['Flow', ['Condition']]])
  assert.equal(found.searching, true)
  assert.deepEqual(found.counts, { commands: 2, scripts: 1, flow: 1 })
  assert.deepEqual(names(libraryOf(entries, 'commands', 'issue')), []) // not offered, so not found
  assert.deepEqual(libraryOf(null).groups, [])

  // The nodes for files are Nik's own, in a group of their own: after Nik, before the connectors.
  const files = [
    { id: 'acme.block', kind: 'action', group: 'Acme', name: 'block', connector: 'acme', available: true },
    { id: 'nik.add-file', kind: 'action', group: 'Files', name: 'Add a file' },
    { id: 'nik.get-analysis', kind: 'action', group: 'Files', name: 'Read an analysis' },
    { id: 'http.request', kind: 'action', group: 'HTTP', name: 'HTTP request' },
  ]
  assert.deepEqual(names(libraryOf([...files, ...entries], 'commands')), [
    ['Nik', ['Add a note']],
    ['Files', ['Add a file', 'Read an analysis']],
    ['Acme', ['block']],
    ['Mail', ['send']],
    ['HTTP', ['HTTP request']],
  ])
  assert.deepEqual(names(libraryOf(files, 'commands', 'analysis')), [['Files', ['Read an analysis']]])
})

test('an output that says what is inside it is listed with it, from the shapes of the catalog', async () => {
  const { withSubFields } = await import('./catalog.js')
  const shapes = {
    incident: [
      { name: 'id', type: 'text', description: 'Its id' },
      { name: 'name', type: 'text', description: 'Its name' },
    ],
    fields: [
      { name: 'owner', type: 'user', description: 'Owner. The analyst who has it.' },
      { name: 'business_unit', type: 'choice', description: 'Business unit (a field of yours)' },
      { name: 'effort[0].hours', type: 'number', description: 'Hours, in the first row of Effort' },
    ],
    context: { Ticket: ['ID', 'Number'] },
  }
  const outputs = [
    { name: 'incident', type: 'object', description: 'The incident', shape: 'incident' },
    { name: 'lists', type: 'list', shape: [{ name: '[0].name', type: 'text', description: 'Its name' }] },
    { name: 'count', type: 'number' },
    { name: 'unknown', type: 'object', shape: 'nothing-of-the-kind' },
  ]
  // The object stays, to be picked whole; what is inside follows it.
  assert.deepEqual(
    withSubFields(outputs, null, shapes).map((field) => [field.name, field.type]),
    [
      ['incident', 'object'],
      ['incident.id', 'text'],
      ['incident.name', 'text'],
      ['lists', 'list'],
      ['lists[0].name', 'text'],
      ['count', 'number'],
      ['unknown', 'object'],
    ],
  )
  // Without the shapes of the catalog a named one lists nothing, and a written one still does.
  assert.deepEqual(
    withSubFields(outputs, null).map((field) => field.name),
    ['incident', 'lists', 'lists[0].name', 'count', 'unknown'],
  )
  // What is declared wins over a sample; a sample still fills the outputs that declare nothing.
  assert.deepEqual(
    withSubFields(outputs, { incident: { other: 1 }, count: 3, unknown: { a: 1 } }, shapes).map((field) => field.name),
    ['incident', 'incident.id', 'incident.name', 'lists', 'lists[0].name', 'count', 'unknown', 'unknown.a'],
  )

  const graph = {
    nodes: [
      { id: 'start', kind: 'trigger', config: { event: 'incident.created' } },
      { id: 'made', kind: 'action', name: 'Create an incident', config: { action: 'nik.create-incident', args: {} } },
      { id: 'say', kind: 'action', name: 'Say', config: { action: 'nik.add-note', args: {} } },
    ],
    edges: [
      { from: 'start', to: 'made' },
      { from: 'made', to: 'say' },
    ],
  }
  const entries = [
    { id: 'nik.create-incident', kind: 'action', group: 'Nik', name: 'Create an incident', outputs: [outputs[0]] },
    { id: 'nik.add-note', kind: 'action', group: 'Nik', name: 'Add a note', outputs: [] },
  ]
  const tree = valueTree(graph, 'say', entries, shapes)
  const paths = (name) => tree.find((root) => root.name === name).fields.map((field) => field.path)
  // The incident a node gave and the incident of the trigger are listed the same way.
  assert.deepEqual(paths('made'), ['made.incident', 'made.incident.id', 'made.incident.name'])
  assert.deepEqual(paths('trigger'), ['trigger.incident.id', 'trigger.incident.name'])
  // The fields of the registry, those made in Settings among them, with their label and type.
  assert.deepEqual(paths('incident'), ['incident.owner', 'incident.business_unit', 'incident.effort[0].hours'])
  assert.equal(tree.find((root) => root.name === 'incident').fields[1].type, 'choice')
  assert.deepEqual(paths('context'), ['context.Ticket', 'context.Ticket[0].ID', 'context.Ticket[0].Number'])
  // An event that may come without an incident says so of each of its fields.
  assert.ok(triggerFields({ manual: true }, shapes).every((field) => field.name === 'actor' || field.optional))
  // Until the catalog is read, what is written in the editor is listed.
  assert.equal(valueTree(graph, 'say', entries)[0].fields[0].path, 'trigger.incident.id')
})
