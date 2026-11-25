/*
 * The lateral-movement graph of the Logons page (components/tabs/eventlogs/LateralGraph.jsx): where it
 * puts the hosts and the addresses, and the small rules around it (the zoom, the words, what a click
 * filters). Pure functions; the same input gives the same picture.
 *
 * The input is the answer of `GET .../logons/graph`: `nodes` (`id, kind, label, logonsIn, logonsOut, failed,
 * inEvidence`) and `edges` (`from, to, count, failed, users, types, firstTs, lastTs`), which may hold 300
 * nodes and 1500 edges. The layout is layered: the machines the logons come from are on the left, the machines
 * they reach on the right; a cycle is broken at the edge that closes it, the first seen; inside a layer the
 * nodes are ordered by a few passes of the barycentre of their neighbours, to cross fewer edges.
 */

export const LAYER_GAP = 230
export const ROW_GAP = 46
export const MARGIN = 60
export const PASSES = 4
export const ZOOM_MIN = 0.15
export const ZOOM_MAX = 4
// Labels of the edges and of the addresses are drawn from this scale up (or when hovered or chosen).
export const LABEL_SCALE = 0.9

const HOST_RADIUS = 10
const ADDRESS_RADIUS = 6

/** The radius of a node: a host is larger than an address. */
export const radiusOf = (node) => (node.kind === 'address' ? ADDRESS_RADIUS : HOST_RADIUS)

/**
 * The layer of each node (a number from 0, the left), by the longest path from a machine nothing came
 * to. A depth-first walk in the order of the input finds the edges that close a cycle: they are left out
 * of the layering (the first seen stays), and drawn as they are.
 * @returns {{ layer: Map<string, number>, back: Set<number> }} `back` holds the indexes of the edges left out.
 */
export function layerNodes(nodes, edges) {
  const ids = new Set(nodes.map((node) => node.id))
  const out = new Map(nodes.map((node) => [node.id, []]))
  edges.forEach((edge, index) => {
    if (edge.from !== edge.to && ids.has(edge.from) && ids.has(edge.to)) out.get(edge.from).push({ to: edge.to, index })
  })
  const back = new Set()
  const state = new Map() // 1 on the walk, 2 done
  const order = [] // the nodes in the order they were finished
  for (const start of nodes) {
    if (state.has(start.id)) continue
    const stack = [{ id: start.id, at: 0 }]
    state.set(start.id, 1)
    while (stack.length) {
      const top = stack[stack.length - 1]
      const next = out.get(top.id)[top.at]
      if (next === undefined) {
        state.set(top.id, 2)
        order.push(top.id)
        stack.pop()
        continue
      }
      top.at += 1
      const seen = state.get(next.to)
      if (seen === 1) back.add(next.index)
      else if (!seen) {
        state.set(next.to, 1)
        stack.push({ id: next.to, at: 0 })
      }
    }
  }
  // The finishing order reversed is a topological order of the edges that are left.
  const layer = new Map(nodes.map((node) => [node.id, 0]))
  for (const id of [...order].reverse()) {
    for (const { to, index } of out.get(id)) {
      if (!back.has(index)) layer.set(to, Math.max(layer.get(to), layer.get(id) + 1))
    }
  }
  return { layer, back }
}

/**
 * The order of the nodes in each layer, from a few passes of the barycentre: a sweep to the right puts a node
 * where the machines it comes from are, a sweep to the left where the ones it reaches are. Ties keep the
 * order of the last pass, so the result does not depend on anything but the input.
 * @returns {string[][]} the ids of each layer, top to bottom
 */
export function orderLayers(nodes, edges, layer, passes = PASSES) {
  const count = Math.max(0, ...layer.values()) + 1
  const layers = Array.from({ length: nodes.length ? count : 0 }, () => [])
  for (const node of nodes) layers[layer.get(node.id)].push(node.id)
  const neighbours = new Map(nodes.map((node) => [node.id, { before: [], after: [] }]))
  for (const edge of edges) {
    if (edge.from === edge.to || !neighbours.has(edge.from) || !neighbours.has(edge.to)) continue
    const a = layer.get(edge.from)
    const b = layer.get(edge.to)
    if (a < b) {
      neighbours.get(edge.to).before.push(edge.from)
      neighbours.get(edge.from).after.push(edge.to)
    } else if (b < a) {
      neighbours.get(edge.from).before.push(edge.to)
      neighbours.get(edge.to).after.push(edge.from)
    }
  }
  // Where a node stands in its layer, from 0 to 1: the unit the barycentre is made in.
  const place = new Map()
  const note = () => {
    for (const ids of layers) ids.forEach((id, index) => place.set(id, (index + 0.5) / ids.length))
  }
  const sweep = (ids, side) => {
    const key = new Map()
    ids.forEach((id, index) => {
      const near = neighbours.get(id)[side]
      key.set(id, near.length ? near.reduce((sum, other) => sum + place.get(other), 0) / near.length : place.get(id))
      // A stable tie-break: the place it had.
      key.set(`${id}#`, index)
    })
    ids.sort((a, b) => key.get(a) - key.get(b) || key.get(`${a}#`) - key.get(`${b}#`))
    ids.forEach((id, index) => place.set(id, (index + 0.5) / ids.length))
  }
  note()
  for (let pass = 0; pass < passes; pass += 1) {
    if (pass % 2 === 0) for (let i = 1; i < layers.length; i += 1) sweep(layers[i], 'before')
    else for (let i = layers.length - 2; i >= 0; i -= 1) sweep(layers[i], 'after')
  }
  return layers
}

/** How many pairs of edges between neighbouring layers cross, for the orders given: what the passes reduce. */
export function countCrossings(layers, edges, layer) {
  const index = new Map()
  layers.forEach((ids) => ids.forEach((id, at) => index.set(id, at)))
  const between = new Map() // the layer on the left of the gap -> its edges as [from index, to index]
  for (const edge of edges) {
    const a = layer.get(edge.from)
    const b = layer.get(edge.to)
    if (b !== a + 1 || !index.has(edge.from) || !index.has(edge.to)) continue
    if (!between.has(a)) between.set(a, [])
    between.get(a).push([index.get(edge.from), index.get(edge.to)])
  }
  let crossings = 0
  for (const list of between.values()) {
    for (let i = 0; i < list.length; i += 1) {
      for (let j = i + 1; j < list.length; j += 1) {
        if ((list[i][0] - list[j][0]) * (list[i][1] - list[j][1]) < 0) crossings += 1
      }
    }
  }
  return crossings
}

/** The thickness of an edge: it grows with the logons it stands for, but never past 8. */
export const strokeOf = (count) => Math.min(8, 1.2 + Math.log2(Math.max(1, count)) * 0.8)

/** A quadratic curve between two points, bent by `bend` of its length to the side; the arrow keeps off the nodes. */
function curve(a, b, bend, ra, rb) {
  const dx = b.x - a.x
  const dy = b.y - a.y
  const length = Math.hypot(dx, dy) || 1
  const control = {
    x: (a.x + b.x) / 2 - (dy / length) * bend * length,
    y: (a.y + b.y) / 2 + (dx / length) * bend * length,
  }
  const trim = (from, to, radius) => {
    const tx = to.x - from.x
    const ty = to.y - from.y
    const size = Math.hypot(tx, ty) || 1
    return { x: from.x + (tx / size) * radius, y: from.y + (ty / size) * radius }
  }
  const start = trim(a, control, ra + 1)
  const end = trim(b, control, rb + 5) // room for the arrowhead
  const mid = { x: 0.25 * start.x + 0.5 * control.x + 0.25 * end.x, y: 0.25 * start.y + 0.5 * control.y + 0.25 * end.y }
  const round = (n) => Math.round(n * 10) / 10
  return {
    path: `M${round(start.x)} ${round(start.y)}Q${round(control.x)} ${round(control.y)} ${round(end.x)} ${round(end.y)}`,
    mid: { x: round(mid.x), y: round(mid.y) },
  }
}

/** A small loop above a node: a host that logged on to itself over the network. */
function loop(at, radius) {
  const x = at.x
  const y = at.y - radius
  return {
    path: `M${x - 4} ${y - 1}C${x - 30} ${y - 40} ${x + 30} ${y - 40} ${x + 4} ${y - 1}`,
    mid: { x, y: y - 30 },
  }
}

/**
 * The picture of a graph: `{ nodes, edges, width, height, layers }`. A node gets `x`, `y`, `r` and `layer`; an edge
 * gets `key`, `path`, `mid` (where its count is written), `width` and `reversed` (it closes a cycle).
 * @param {{ nodes: object[], edges: object[] }} graph
 */
export function layout(graph) {
  const nodes = graph?.nodes ?? []
  const edges = graph?.edges ?? []
  if (nodes.length === 0) return { nodes: [], edges: [], width: 0, height: 0, layers: [] }
  const { layer, back } = layerNodes(nodes, edges)
  const layers = orderLayers(nodes, edges, layer)
  const tallest = Math.max(...layers.map((ids) => ids.length))
  const byId = new Map()
  const given = new Map(nodes.map((node) => [node.id, node]))
  const placed = []
  layers.forEach((ids, column) => {
    const offset = ((tallest - ids.length) * ROW_GAP) / 2
    ids.forEach((id, row) => {
      const node = {
        ...given.get(id),
        x: MARGIN + column * LAYER_GAP,
        y: MARGIN + offset + row * ROW_GAP,
        layer: column,
      }
      node.r = radiusOf(node)
      byId.set(id, node)
      placed.push(node)
    })
  })
  // The nodes are read back in the order of the input, whatever the layers say.
  const rank = new Map(nodes.map((node, index) => [node.id, index]))
  placed.sort((a, b) => rank.get(a.id) - rank.get(b.id))
  const pairs = new Set(edges.map((edge) => `${edge.from}\n${edge.to}`))
  const drawn = []
  edges.forEach((edge, index) => {
    const a = byId.get(edge.from)
    const b = byId.get(edge.to)
    if (!a || !b) return
    let shape
    if (a === b) shape = loop(a, a.r)
    else {
      // Two edges that go both ways must not lie on each other; one that goes back bends too.
      const both = pairs.has(`${edge.to}\n${edge.from}`)
      const bend = both ? 0.18 : back.has(index) || a.layer === b.layer ? 0.25 : 0
      shape = curve(a, b, bend, a.r, b.r)
    }
    drawn.push({
      ...edge,
      key: `${edge.from}>${edge.to}`,
      ...shape,
      width: strokeOf(edge.count),
      reversed: back.has(index),
    })
  })
  return {
    nodes: placed,
    edges: drawn,
    layers,
    width: MARGIN * 2 + (layers.length - 1) * LAYER_GAP,
    height: MARGIN * 2 + (tallest - 1) * ROW_GAP,
  }
}

/** The pan and zoom that put a picture of `width` x `height` whole into a `box`, centred: `{ k, x, y }`. */
export function fitTransform(size, box, { max = 1.5, margin = 16 } = {}) {
  if (!size.width || !size.height || !box.width || !box.height) return { k: 1, x: 0, y: 0 }
  const k = Math.max(
    ZOOM_MIN,
    Math.min(max, (box.width - margin * 2) / size.width, (box.height - margin * 2) / size.height),
  )
  return { k, x: (box.width - size.width * k) / 2, y: (box.height - size.height * k) / 2 }
}

/** The transform after a zoom by `factor` that keeps the point `at` (in the box) where it is. */
export function zoomAt(transform, at, factor) {
  const k = Math.max(ZOOM_MIN, Math.min(ZOOM_MAX, transform.k * factor))
  const ratio = k / transform.k
  return { k, x: at.x - (at.x - transform.x) * ratio, y: at.y - (at.y - transform.y) * ratio }
}

/** The transform after the picture was dragged by `dx`, `dy` pixels. */
export const panBy = (transform, dx, dy) => ({ ...transform, x: transform.x + dx, y: transform.y + dy })

/** Whether the labels of edges and addresses are drawn at this scale. */
export const showsLabels = (scale) => scale >= LABEL_SCALE

/** The node with this id in a laid-out graph. */
export const nodeOf = (picture, id) => picture.nodes.find((node) => node.id === id) ?? null

/**
 * The filters of the table of logons for a click on an edge: what came from the node `from` (its source host, or its
 * source address) and reached the node `to` (the host that recorded it).
 */
export function edgeFilters(from, to) {
  return { ...sourceFilter(from), host: to.label }
}

const sourceFilter = (node) => (node.kind === 'address' ? { sourceIp: node.label } : { sourceHost: node.label })

/**
 * The filters for a click on a node: the logons that reached it (`in`, the host that recorded them) or that
 * came from it (`out`). An address only has logons that came from it.
 */
export function nodeFilters(node, direction) {
  if (direction === 'out' || node.kind === 'address') return sourceFilter(node)
  return { host: node.label }
}

const number = (n) => n.toLocaleString('en-US')

/** "12 logons, 3 failed" (or "1 logon"). */
export function countText(edge) {
  const logons = `${number(edge.count)} ${edge.count === 1 ? 'logon' : 'logons'}`
  return edge.failed > 0 ? `${logons}, ${number(edge.failed)} failed` : logons
}

/** What the logon types of an edge are called: "network, remote interactive". */
export const typesText = (types = [], nameOf = String) => types.map(nameOf).join(', ')

/** The line under the graph when the server left some out. */
export function cutText(graph, shown = null) {
  if (!graph?.cut) return ''
  const caps = graph.caps ?? {}
  const limit =
    caps.nodes && caps.edges ? ` (at most ${number(caps.nodes)} machines and ${number(caps.edges)} links)` : ''
  const where = shown ? ` ${number(shown.nodes)} machines and ${number(shown.edges)} links are shown.` : ''
  return `The graph was cut${limit}: only the busiest links are drawn.${where} Narrow the time range, the users or the types, or raise the minimum count.`
}

/** The biggest count of an edge, for the "minimum count" slider (at least 1). */
export const busiest = (graph) => Math.max(1, ...(graph?.edges ?? []).map((edge) => edge.count))
