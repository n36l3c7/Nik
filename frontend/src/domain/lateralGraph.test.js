import test from 'node:test'
import assert from 'node:assert/strict'
import {
  LABEL_SCALE,
  ZOOM_MAX,
  ZOOM_MIN,
  busiest,
  countCrossings,
  countText,
  cutText,
  edgeFilters,
  fitTransform,
  layerNodes,
  layout,
  nodeFilters,
  orderLayers,
  panBy,
  showsLabels,
  strokeOf,
  zoomAt,
} from './lateralGraph.js'

const host = (id, extra = {}) => ({ id: `host:${id}`, kind: 'host', label: id, inEvidence: true, ...extra })
const address = (id) => ({ id: `address:${id}`, kind: 'address', label: id, inEvidence: false })
const edge = (from, to, count = 1, extra = {}) => ({
  from: `host:${from}`,
  to: `host:${to}`,
  count,
  failed: 0,
  ...extra,
})

test('the machines logons come from are on the left, the ones they reach on the right', () => {
  const nodes = [host('c'), host('a'), host('b')]
  const { layer, back } = layerNodes(nodes, [edge('a', 'b'), edge('b', 'c')])
  assert.equal(layer.get('host:a'), 0)
  assert.equal(layer.get('host:b'), 1)
  assert.equal(layer.get('host:c'), 2)
  assert.equal(back.size, 0)
})

test('a node is as far right as its longest path asks', () => {
  const nodes = [host('a'), host('b'), host('c')]
  const { layer } = layerNodes(nodes, [edge('a', 'c'), edge('a', 'b'), edge('b', 'c')])
  assert.equal(layer.get('host:c'), 2)
})

test('a cycle is broken at the edge that closes it, the first seen', () => {
  const nodes = [host('a'), host('b'), host('c')]
  const edges = [edge('a', 'b'), edge('b', 'c'), edge('c', 'a')]
  const { layer, back } = layerNodes(nodes, edges)
  assert.deepEqual([...back], [2])
  assert.equal(layer.get('host:a'), 0)
  assert.equal(layer.get('host:c'), 2)
  // A host that logged on to itself is no cycle to break, and is drawn as a loop.
  assert.equal(layerNodes([host('a')], [edge('a', 'a')]).back.size, 0)
})

test('the barycentre passes put the nodes where their neighbours are, and cross fewer edges', () => {
  // a1 -> b2 and a2 -> b1 cross when each layer is in the order of the input.
  const nodes = [host('a1'), host('a2'), host('b1'), host('b2')]
  const edges = [edge('a1', 'b2'), edge('a2', 'b1')]
  const { layer } = layerNodes(nodes, edges)
  const before = orderLayers(nodes, edges, layer, 0)
  assert.equal(countCrossings(before, edges, layer), 1)
  const after = orderLayers(nodes, edges, layer)
  assert.equal(countCrossings(after, edges, layer), 0)
})

test('the same input gives the same picture', () => {
  const nodes = [host('a'), host('b'), host('c'), host('d'), address('10.0.0.9')]
  const edges = [
    edge('a', 'b', 5),
    edge('a', 'c', 2),
    edge('c', 'd', 9),
    edge('d', 'a', 1),
    { from: 'address:10.0.0.9', to: 'host:b', count: 3, failed: 3 },
  ]
  const first = layout({ nodes, edges })
  const second = layout({ nodes: structuredClone(nodes), edges: structuredClone(edges) })
  assert.deepEqual(first, second)
  // Every node and edge is there, nodes in the order of the input, each edge with a path.
  assert.deepEqual(
    first.nodes.map((node) => node.id),
    nodes.map((node) => node.id),
  )
  assert.equal(first.edges.length, 5)
  assert.ok(first.edges.every((item) => item.path.startsWith('M') && Number.isFinite(item.mid.x)))
  assert.equal(first.edges.filter((item) => item.reversed).length, 1)
  // An address is smaller than a host.
  assert.ok(first.nodes.find((node) => node.kind === 'address').r < first.nodes[0].r)
  assert.ok(first.width > 0 && first.height >= 0)
})

test('an edge to a machine that is not in the graph is left out, an empty graph has no size', () => {
  const picture = layout({ nodes: [host('a')], edges: [edge('a', 'zzz')] })
  assert.equal(picture.edges.length, 0)
  assert.deepEqual(layout({ nodes: [], edges: [] }), { nodes: [], edges: [], width: 0, height: 0, layers: [] })
  assert.deepEqual(layout(null).nodes, [])
})

test('300 machines and 1500 links are laid out at once', () => {
  const nodes = Array.from({ length: 300 }, (_, i) => host(`h${i}`))
  const edges = []
  for (let i = 0; edges.length < 1500; i += 1) {
    const from = (i * 7) % 300
    const to = (i * 13 + 5) % 300
    if (from !== to) edges.push(edge(`h${from}`, `h${to}`, 1 + (i % 9)))
  }
  const started = Date.now()
  const picture = layout({ nodes, edges })
  assert.equal(picture.nodes.length, 300)
  assert.ok(picture.edges.length > 1000)
  assert.ok(Date.now() - started < 2000)
})

test('an edge is thicker with its count, up to a limit', () => {
  assert.ok(strokeOf(1) < strokeOf(10))
  assert.ok(strokeOf(10) < strokeOf(100))
  assert.equal(strokeOf(1_000_000), 8)
  assert.ok(strokeOf(0) > 0)
})

test('the picture fits its box, and a zoom keeps the point under the pointer', () => {
  const fit = fitTransform({ width: 800, height: 400 }, { width: 400, height: 400 })
  assert.ok(fit.k < 1)
  assert.ok(fit.x >= 0 && fit.y >= 0)
  assert.deepEqual(fitTransform({ width: 0, height: 0 }, { width: 400, height: 400 }), { k: 1, x: 0, y: 0 })
  // A small picture is not enlarged past the maximum.
  assert.equal(fitTransform({ width: 10, height: 10 }, { width: 1000, height: 1000 }).k, 1.5)
  const start = { k: 1, x: 10, y: 20 }
  const at = { x: 100, y: 100 }
  const zoomed = zoomAt(start, at, 2)
  assert.equal(zoomed.k, 2)
  // The point of the picture under `at` is the same before and after.
  assert.equal((at.x - start.x) / start.k, (at.x - zoomed.x) / zoomed.k)
  assert.equal((at.y - start.y) / start.k, (at.y - zoomed.y) / zoomed.k)
  assert.equal(zoomAt(start, at, 100).k, ZOOM_MAX)
  assert.equal(zoomAt(start, at, 0.0001).k, ZOOM_MIN)
  assert.deepEqual(panBy(start, 5, -5), { k: 1, x: 15, y: 15 })
})

test('the labels of the edges are drawn from a scale up', () => {
  assert.equal(showsLabels(LABEL_SCALE - 0.01), false)
  assert.equal(showsLabels(LABEL_SCALE), true)
})

test('a click on an edge or a node filters the logons by the machine, or by the address', () => {
  const a = host('ws-01')
  const b = host('srv-02')
  const ip = address('203.0.113.45')
  assert.deepEqual(edgeFilters(a, b), { sourceHost: 'ws-01', host: 'srv-02' })
  assert.deepEqual(edgeFilters(ip, b), { sourceIp: '203.0.113.45', host: 'srv-02' })
  assert.deepEqual(nodeFilters(b, 'in'), { host: 'srv-02' })
  assert.deepEqual(nodeFilters(b, 'out'), { sourceHost: 'srv-02' })
  // Logons only come from an address.
  assert.deepEqual(nodeFilters(ip, 'in'), { sourceIp: '203.0.113.45' })
})

test('the words under the graph', () => {
  assert.equal(countText({ count: 1, failed: 0 }), '1 logon')
  assert.equal(countText({ count: 1204, failed: 3 }), '1,204 logons, 3 failed')
  assert.equal(cutText({ cut: false }), '')
  assert.equal(cutText(null), '')
  const said = cutText({ cut: true, caps: { nodes: 300, edges: 1500 } }, { nodes: 300, edges: 1500 })
  assert.match(said, /at most 300 machines and 1,500 links/)
  assert.match(said, /Narrow the time range/)
  assert.equal(busiest({ edges: [{ count: 4 }, { count: 12 }] }), 12)
  assert.equal(busiest({ edges: [] }), 1)
})
