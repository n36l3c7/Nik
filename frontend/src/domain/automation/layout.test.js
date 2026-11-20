import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { arrange, cleanRoute, copyOf, lineKey, moveNodes, normalise, portOf } from './graph.js'
import {
  NODE_HEIGHT,
  NODE_WIDTH,
  crossings,
  drawingOf,
  handlePlaces,
  labelSize,
  longestMiddle,
  pathThrough,
  routeStops,
  tidy,
} from './layout.js'

const node = (id, kind, config = {}) => ({ id, kind, name: id, position: { x: 40, y: 40 }, config })
const action = (id) => node(id, 'action', { action: 'nik.add-note', args: {} })

/** The graph after "Tidy up", as the page makes it. */
const tidied = async (graph) => arrange(graph, await tidy(graph))

/** What is wrong with a tidied graph: a line with no route, a line over a node, words on a node. */
function wrong(graph) {
  const { boxes, lines, labels } = drawingOf(graph)
  return [
    ...graph.edges.filter((edge) => !edge.route).map((edge) => `${edge.from} → ${edge.to} has no route`),
    ...crossings(boxes, lines, labels).map((found) => `${found.what} ${found.from} → ${found.to} over ${found.node}`),
  ]
}

/* The playbook of the report: a "for each" whose body is two nodes long, and whose "when done" goes past it. */
const LOOP = {
  nodes: [
    node('start', 'trigger', { manual: true }),
    node('each', 'for_each', { items: '{{ trigger.body }}' }),
    action('create_incident'),
    action('set_status'),
    node('end', 'end'),
  ],
  edges: [
    { from: 'start', to: 'each' },
    { from: 'each', port: 'each', to: 'create_incident' },
    { from: 'create_incident', to: 'set_status' },
    { from: 'set_status', to: 'end' },
    { from: 'each', port: 'done', to: 'end' },
  ],
}

test('a line that skips a row gets a lane beside the column, and its words a place on no node', async () => {
  // As it was drawn before: one column, and "when done" straight down through the two nodes of the body.
  const column = {
    ...LOOP,
    nodes: LOOP.nodes.map((item, index) => ({ ...item, position: { x: 40, y: 40 + index * 118 } })),
  }
  const straight = (edge) => {
    const [from, to] = [edge.from, edge.to].map((id) => column.nodes.find((item) => item.id === id).position)
    const out = handlePlaces(column.nodes.find((item) => item.id === edge.from)).below
    const left = out.find((place) => place.port === portOf(edge, column))?.left ?? 0.5
    return {
      from: edge.from,
      to: edge.to,
      points: [
        { x: from.x + NODE_WIDTH * left, y: from.y + NODE_HEIGHT },
        { x: from.x + NODE_WIDTH * left, y: to.y },
      ],
    }
  }
  const boxes = drawingOf(column).boxes
  assert.deepEqual(crossings(boxes, column.edges.map(straight)), [
    { from: 'each', to: 'end', node: 'create_incident', what: 'line' },
    { from: 'each', to: 'end', node: 'set_status', what: 'line' },
  ])

  const graph = await tidied(LOOP)
  assert.deepEqual(wrong(graph), [])
  // The long line turns: it is more than the straight way down, and its words have a place.
  const done = graph.edges.find((edge) => edge.port === 'done')
  assert.ok(done.route.points.length > 2)
  assert.ok(done.route.label)
  // A line starts under the output it leaves by, and arrives at the middle of the top of its node.
  const each = graph.nodes.find((item) => item.id === 'each').position
  const end = graph.nodes.find((item) => item.id === 'end').position
  assert.deepEqual(done.route.points[0], { x: each.x + Math.round((NODE_WIDTH * 2) / 3), y: each.y + NODE_HEIGHT })
  assert.deepEqual(done.route.points.at(-1), { x: end.x + NODE_WIDTH / 2, y: end.y })
  // Every part of every route is straight: across or down.
  for (const edge of graph.edges) {
    edge.route.points.forEach((point, index) => {
      if (index) assert.ok(point.x === edge.route.points[index - 1].x || point.y === edge.route.points[index - 1].y)
    })
  }
  // Tidied again, nothing changes: it is the same graph.
  assert.equal(await tidied(graph), graph)
})

test('no line runs over a node after Tidy up: branches that join, an error far down, several answers', async () => {
  const diamond = {
    nodes: [
      node('start', 'trigger', { manual: true }),
      node('check', 'condition', { all: [] }),
      action('yes_1'),
      action('yes_2'),
      action('no_1'),
      action('join'),
      node('end', 'end'),
    ],
    edges: [
      { from: 'start', to: 'check' },
      { from: 'check', port: 'yes', to: 'yes_1' },
      { from: 'yes_1', to: 'yes_2' },
      { from: 'yes_2', to: 'join' },
      { from: 'check', port: 'no', to: 'no_1' },
      { from: 'no_1', to: 'join' },
      { from: 'join', to: 'end' },
    ],
  }
  assert.deepEqual(wrong(await tidied(diamond)), [])

  const failing = {
    nodes: [
      node('start', 'trigger', { manual: true }),
      ...['a', 'b', 'c', 'd'].map(action),
      action('tell'),
      node('end', 'end'),
    ],
    edges: [
      { from: 'start', to: 'a' },
      { from: 'a', to: 'b' },
      { from: 'b', to: 'c' },
      { from: 'c', to: 'd' },
      { from: 'd', to: 'end' },
      // "on error" leaves from the right side of the first node and goes down past all the others.
      { from: 'a', port: 'error', to: 'tell' },
      { from: 'b', port: 'error', to: 'tell' },
      { from: 'tell', to: 'end' },
    ],
  }
  const failed = await tidied(failing)
  assert.deepEqual(wrong(failed), [])
  const a = failed.nodes.find((item) => item.id === 'a').position
  assert.deepEqual(failed.edges.find((edge) => edge.from === 'a' && edge.port === 'error').route.points[0], {
    x: a.x + NODE_WIDTH,
    y: a.y + NODE_HEIGHT / 2,
  })

  const asked = {
    nodes: [
      node('start', 'trigger', { manual: true }),
      node('ask', 'ask', { question: 'What now?', choices: ['Block it', 'Watch it', 'Nothing'] }),
      node('approve', 'approval', { question: 'Sure?' }),
      action('block'),
      action('watch'),
      action('after'),
      node('end', 'end'),
    ],
    edges: [
      { from: 'start', to: 'ask' },
      { from: 'ask', port: 'block_it', to: 'approve' },
      { from: 'approve', port: 'approved', to: 'block' },
      { from: 'approve', port: 'refused', to: 'end' },
      { from: 'block', to: 'after' },
      { from: 'ask', port: 'watch_it', to: 'watch' },
      { from: 'watch', to: 'after' },
      { from: 'ask', port: 'nothing', to: 'end' },
      { from: 'ask', port: 'timeout', to: 'end' },
      { from: 'after', to: 'end' },
    ],
  }
  assert.deepEqual(wrong(await tidied(asked)), [])
})

test('the playbooks Nik ships are tidied with no line over a node', async () => {
  for (const name of ['phishing-triage', 'recheck-watched-lists', 'storage-low-notice', 'mail-attachments']) {
    const file = new URL(`../../../../backend/app/automation/seed/playbooks/${name}.json`, import.meta.url)
    const graph = normalise(JSON.parse(readFileSync(file, 'utf8')).playbook.graph)
    assert.deepEqual(wrong(await tidied(graph)), [], name)
  }
  // And a long one: twelve steps in a row, each with a way out on error, and a loop in the middle.
  const steps = Array.from({ length: 12 }, (_, index) => `step_${index + 1}`)
  const long = {
    nodes: [
      node('start', 'trigger', { manual: true }),
      ...steps.map(action),
      node('loop', 'for_each', { items: '' }),
      action('inside'),
      action('failed'),
      node('end', 'end'),
    ],
    edges: [
      { from: 'start', to: 'step_1' },
      ...steps.slice(1).map((id, index) => ({ from: steps[index], to: id })),
      ...steps.filter((_, index) => index % 3 === 0).map((id) => ({ from: id, port: 'error', to: 'failed' })),
      { from: 'step_12', to: 'loop' },
      { from: 'loop', port: 'each', to: 'inside' },
      { from: 'loop', port: 'done', to: 'end' },
      { from: 'failed', to: 'end' },
    ],
  }
  assert.deepEqual(wrong(await tidied(long)), [])
})

test('crossings: a line over a box, the nodes it joins, an edge only touched, words on a node', () => {
  const boxes = [
    { id: 'a', x: 0, y: 0, width: 100, height: 50 },
    { id: 'b', x: 0, y: 200, width: 100, height: 50 },
    { id: 'c', x: 0, y: 100, width: 100, height: 50 },
  ]
  const line = (points) => [{ from: 'a', to: 'b', points }]
  const through = [
    { x: 50, y: 50 },
    { x: 50, y: 200 },
  ]
  assert.deepEqual(crossings(boxes, line(through)), [{ from: 'a', to: 'b', node: 'c', what: 'line' }])
  // Round it, along its very edge, or slanting past its corner: not over it.
  const round = [
    { x: 50, y: 50 },
    { x: 50, y: 75 },
    { x: 130, y: 75 },
    { x: 130, y: 175 },
    { x: 50, y: 175 },
    { x: 50, y: 200 },
  ]
  assert.deepEqual(crossings(boxes, line(round)), [])
  assert.deepEqual(
    crossings(
      boxes,
      line([
        { x: 100, y: 50 },
        { x: 100, y: 200 },
      ]),
    ),
    [],
  )
  assert.deepEqual(
    crossings(
      boxes,
      line([
        { x: 100, y: 60 },
        { x: 160, y: 150 },
      ]),
    ),
    [],
  )
  // A slanting line through a corner of it is over it.
  assert.equal(
    crossings(
      boxes,
      line([
        { x: 120, y: 90 },
        { x: 80, y: 160 },
      ]),
    ).length,
    1,
  )
  // The nodes a line joins are its own: a line that ends inside one is not over it.
  assert.deepEqual(
    crossings(boxes, [
      {
        from: 'a',
        to: 'c',
        points: [
          { x: 50, y: 25 },
          { x: 50, y: 120 },
        ],
      },
    ]),
    [],
  )
  // The words of a line: beside a node, or on it.
  const words = (x) => [{ from: 'a', to: 'b', x, y: 110, width: 60, height: 16 }]
  assert.deepEqual(crossings(boxes, [], words(104)), [])
  assert.deepEqual(crossings(boxes, [], words(80)), [{ from: 'a', to: 'b', node: 'c', what: 'label' }])
  assert.deepEqual(labelSize('when done'), { width: 65, height: 16 })
})

test('a route is drawn from handle to handle, its turns following the handles', () => {
  const route = [
    { x: 100, y: 62 },
    { x: 100, y: 90 },
    { x: 300, y: 90 },
    { x: 300, y: 400 },
    { x: 135, y: 400 },
    { x: 135, y: 420 },
  ]
  // The handles are a little off where the layout thought: the first and the last turn follow them.
  const stops = routeStops(route, { x: 102, y: 64 }, { x: 134, y: 421 })
  assert.deepEqual(stops, [
    { x: 102, y: 64 },
    { x: 102, y: 90 },
    { x: 300, y: 90 },
    { x: 300, y: 400 },
    { x: 134, y: 400 },
    { x: 134, y: 421 },
  ])
  // A line that leaves sideways (on error) keeps its first part level.
  assert.deepEqual(
    routeStops(
      [
        { x: 190, y: 31 },
        { x: 240, y: 31 },
        { x: 240, y: 300 },
      ],
      { x: 192, y: 33 },
      { x: 240, y: 302 },
    )[1],
    { x: 240, y: 33 },
  )
  // No turn: straight, or one small step when the handles are not in line.
  const down = [
    { x: 50, y: 62 },
    { x: 50, y: 118 },
  ]
  assert.deepEqual(routeStops(down, { x: 50, y: 62 }, { x: 50, y: 118 }).length, 2)
  assert.deepEqual(routeStops(down, { x: 50, y: 62 }, { x: 54, y: 118 }), [
    { x: 50, y: 62 },
    { x: 50, y: 90 },
    { x: 54, y: 90 },
    { x: 54, y: 118 },
  ])
  assert.deepEqual(longestMiddle(stops), { x: 300, y: 245 })
  const path = pathThrough(stops)
  assert.ok(path.startsWith('M 102 64 L 102 85 Q 102 90 107 90 L 295 90 Q 300 90 300 95'))
  assert.ok(path.endsWith('L 134 421'))
  assert.equal(pathThrough([stops[0], stops[1]]), 'M 102 64 L 102 90')
})

test('a route belongs to where the layout put the nodes: moved, copied or badly kept, it goes', () => {
  const route = {
    points: [
      { x: 1.2, y: 2 },
      { x: 1, y: 9 },
    ],
    label: { x: 4, y: 5.6 },
  }
  const graph = {
    nodes: LOOP.nodes,
    edges: [
      { from: 'start', to: 'each', route },
      { from: 'each', port: 'each', to: 'create_incident', route, points: [{ x: 0, y: 0 }] },
      { from: 'create_incident', to: 'set_status', route: { points: [{ x: 1, y: 2 }] } },
    ],
  }
  const kept = {
    points: [
      { x: 1, y: 2 },
      { x: 1, y: 9 },
    ],
    label: { x: 4, y: 6 },
  }
  // Read: a route is kept, whole numbers; the corners of earlier releases and what is no route are not.
  const read = normalise(graph)
  assert.deepEqual(read.edges, [
    { from: 'start', to: 'each', route: kept },
    { from: 'each', port: 'each', to: 'create_incident', route: kept },
    { from: 'create_incident', to: 'set_status' },
  ])
  assert.equal(cleanRoute({ points: 'no' }), null)
  assert.equal(cleanRoute(null), null)
  // A node moved by hand: its lines draw themselves again; the others keep their route.
  const moved = moveNodes(read, { create_incident: { x: 300, y: 300 } })
  assert.deepEqual(
    moved.edges.map((edge) => Boolean(edge.route)),
    [true, false, false],
  )
  assert.equal(moveNodes(read, {}).edges, read.edges)
  // A copy lands somewhere else: without the routes.
  assert.deepEqual(copyOf(read, ['each', 'create_incident']).edges, [
    { from: 'each', port: 'each', to: 'create_incident' },
  ])
  // A layout that gives no route for a line takes the one it had.
  const arranged = arrange(read, { positions: {}, routes: { [lineKey('start', 'out', 'each')]: route } })
  assert.deepEqual(
    arranged.edges.map((edge) => Boolean(edge.route)),
    [true, false, false],
  )
})
