/*
 * The graph of a playbook as the canvas edits it (the server's rules are in
 * backend/app/automation/graph.py, and the server decides what can be saved
 * as a version):
 *
 *   { nodes: [{ id, kind, name, position: { x, y }, config }],
 *     edges: [{ from, port?, to, route? }], inputs: [...], outputs: [...] }
 *
 * `route` is the way "Tidy up" gave a line between the nodes (layout.js):
 * `{ points: [{ x, y }], label?: { x, y } }`. It belongs to the positions the
 * layout gave: moving one of the two nodes of a line forgets it, and nobody
 * edits it. The engine does not read it.
 *
 * Everything here is pure: an edit returns a new graph and leaves the old one
 * as it was, which is what undo and redo rely on.
 */
import { references, renameRoot } from './expressions.js'

export const KINDS = [
  'trigger',
  'condition',
  'for_each',
  'wait',
  'approval',
  'task',
  'ask',
  'action',
  'script',
  'playbook',
  'end',
]

/** The ports a node leaves by. `error` is drawn only when a failure is handled. */
export const PORTS = {
  trigger: ['out'],
  condition: ['yes', 'no'],
  for_each: ['each', 'done', 'error'],
  wait: ['out'],
  approval: ['approved', 'refused'],
  // A task that passes its due time is also left by "overdue", and stays to do.
  task: ['done', 'overdue'],
  // A question with choices has a port for each of them instead of "answered" (portsOf).
  ask: ['answered', 'timeout'],
  action: ['out', 'error'],
  script: ['out', 'error'],
  playbook: ['out', 'error'],
  end: [],
}

export const DEFAULT_PORT = {
  ...Object.fromEntries(KINDS.map((kind) => [kind, PORTS[kind][0] ?? ''])),
  for_each: 'done',
}

/** What an edge shows next to its line; a plain "then" has no label. */
export const PORT_LABELS = {
  out: '',
  yes: 'yes',
  no: 'no',
  each: 'for each item',
  done: 'when done',
  error: 'on error',
  approved: 'approved',
  refused: 'refused',
  overdue: 'when overdue',
  answered: 'answered',
  timeout: 'no answer',
}

/** The port an answer leaves by: "Yes, block it" gives "yes_block_it" (as the server does). */
export function slug(text) {
  const out = String(text ?? '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return out.slice(0, 24).replace(/^_+|_+$/g, '') || 'answer'
}

const choicesOf = (node) => (Array.isArray(node?.config?.choices) ? node.config.choices : [])

/** The ports a node leaves by. Those of a question are its choices, then "timeout". */
export function portsOf(node) {
  if (node?.kind !== 'ask') return PORTS[node?.kind] ?? []
  const choices = choicesOf(node)
  return [...(choices.length ? choices.map(slug) : ['answered']), 'timeout']
}

/** What an edge of a node shows next to its line: the choice itself for an answer. */
export function portLabel(node, port) {
  if (node?.kind === 'ask' && port !== 'timeout') {
    const choice = choicesOf(node).find((item) => slug(item) === port)
    if (choice !== undefined) return String(choice)
  }
  return PORT_LABELS[port] ?? port
}

/** What a port of a node is called where it has to be named. */
export const portName = (node, port) => portLabel(node, port) || 'then'

/** The graph without the edges that leave a node by a port it has no more (a choice removed or renamed). */
export function pruneEdges(graph, id) {
  const node = graph.nodes.find((item) => item.id === id)
  if (!node) return graph
  const ports = portsOf(node)
  const edges = graph.edges.filter((edge) => edge.from !== id || ports.includes(edge.port ?? DEFAULT_PORT[node.kind]))
  return edges.length === graph.edges.length ? graph : { ...graph, edges }
}

export const KIND_LABELS = {
  trigger: 'Trigger',
  condition: 'Condition',
  for_each: 'For each',
  wait: 'Wait',
  approval: 'Approval',
  task: 'Task',
  ask: 'Question',
  action: 'Action',
  script: 'Script',
  playbook: 'Playbook',
  end: 'End',
}

export const OPERATORS = [
  { id: 'eq', label: 'is' },
  { id: 'ne', label: 'is not' },
  { id: 'gt', label: 'is more than' },
  { id: 'gte', label: 'is at least' },
  { id: 'lt', label: 'is less than' },
  { id: 'lte', label: 'is at most' },
  { id: 'contains', label: 'contains' },
  { id: 'in', label: 'is one of' },
  { id: 'matches', label: 'matches the pattern' },
  { id: 'exists', label: 'is there' },
  { id: 'empty', label: 'is empty' },
]
/** Operators that compare with nothing. */
export const UNARY = new Set(['exists', 'empty'])

/** Names an expression may read besides the nodes before it. */
export const ALWAYS = ['trigger', 'run', 'inputs', 'context', 'incident']
export const IN_LOOP = ['item', 'index']
const RESERVED = new Set([
  ...ALWAYS,
  ...IN_LOOP,
  'context',
  'incident',
  'args',
  'config',
  'response',
  'steps',
  'secret',
  'poll',
])

export const ID_RE = /^[a-z][a-z0-9_]{0,31}$/
export const MAX_NODES = 200

const list = (value) => (Array.isArray(value) ? value : [])

/**
 * A graph with the parts the canvas relies on: lists, and a position for every node.
 *
 * An edge keeps what it joins, and the route the layout gave it when it has one. From 5.2 to
 * 6.3 a line could be given corners by hand, kept in `edges[].points`; nobody draws corners any
 * more (6.4), so those a stored graph still holds are left behind here, and are gone from the
 * graph the next time it is saved. Nothing else ever read them: the engine does not, and a
 * comparison of two graphs ignores them.
 */
export function normalise(graph) {
  const source = graph && typeof graph === 'object' ? graph : {}
  return {
    ...source,
    nodes: list(source.nodes)
      .filter((node) => node && typeof node.id === 'string')
      .map((node, index) => ({
        ...node,
        config: node.config && typeof node.config === 'object' ? node.config : {},
        position:
          Number.isFinite(node.position?.x) && Number.isFinite(node.position?.y)
            ? node.position
            : { x: 40, y: 40 + index * 110 },
      })),
    edges: list(source.edges)
      .filter((edge) => edge && typeof edge.from === 'string' && typeof edge.to === 'string')
      .map(({ points: _corners, route, ...edge }) => {
        const kept = cleanRoute(route)
        return kept ? { ...edge, route: kept } : edge
      }),
  }
}

export const MAX_ROUTE_POINTS = 60
const isPoint = (point) => point && Number.isFinite(point.x) && Number.isFinite(point.y)

/** A route as it is kept: its points (two at least) and where its words go; null for anything else. */
export function cleanRoute(route) {
  const points = route?.points
  if (!Array.isArray(points) || points.length < 2 || points.length > MAX_ROUTE_POINTS || !points.every(isPoint)) {
    return null
  }
  const whole = ({ x, y }) => ({ x: Math.round(x), y: Math.round(y) })
  return { points: points.map(whole), ...(isPoint(route.label) ? { label: whole(route.label) } : {}) }
}

/** What tells a line apart: where it leaves, by which port, where it arrives. */
export const lineKey = (from, port, to) => `${from}\u0000${port}\u0000${to}`

const withoutRoute = ({ route: _route, ...edge }) => edge

export const nodesOf = (graph) => new Map(list(graph?.nodes).map((node) => [node.id, node]))
export const nodeOf = (graph, id) => list(graph?.nodes).find((node) => node.id === id) ?? null
export const triggerOf = (graph) => {
  const found = list(graph?.nodes).filter((node) => node.kind === 'trigger')
  return found.length === 1 ? found[0] : null
}

/** The port an edge leaves by (the node's first one when it names none). */
export function portOf(edge, graph) {
  return edge.port || DEFAULT_PORT[nodeOf(graph, edge.from)?.kind] || 'out'
}

/** node id → [{ port, to }]. */
export function edgesFrom(graph) {
  const out = new Map(list(graph?.nodes).map((node) => [node.id, []]))
  for (const edge of list(graph?.edges)) out.get(edge.from)?.push({ port: portOf(edge, graph), to: edge.to })
  return out
}

/** node id → [{ from, port }]. */
export function edgesTo(graph) {
  const out = new Map(list(graph?.nodes).map((node) => [node.id, []]))
  for (const edge of list(graph?.edges)) {
    if (out.has(edge.from)) out.get(edge.to)?.push({ from: edge.from, port: portOf(edge, graph) })
  }
  return out
}

/** Everything a node leads to (from one of its ports only, when named). */
export function reachable(graph, start, port = null) {
  const outgoing = edgesFrom(graph)
  const todo = (outgoing.get(start) ?? []).filter((edge) => port === null || edge.port === port).map((edge) => edge.to)
  const seen = new Set()
  while (todo.length) {
    const id = todo.pop()
    if (seen.has(id) || !outgoing.has(id)) continue
    seen.add(id)
    for (const edge of outgoing.get(id)) todo.push(edge.to)
  }
  return seen
}

/** for_each node id → the ids of its body (what its `each` port leads to). */
export function loopBodies(graph) {
  return new Map(
    list(graph?.nodes)
      .filter((node) => node.kind === 'for_each')
      .map((node) => [node.id, reachable(graph, node.id, 'each')]),
  )
}

/** The nodes in an order where each comes after what leads to it; null when there is a cycle. */
export function topological(graph) {
  const outgoing = edgesFrom(graph)
  const incoming = new Map([...edgesTo(graph)].map(([id, sources]) => [id, sources.length]))
  const ready = [...incoming]
    .filter(([, count]) => count === 0)
    .map(([id]) => id)
    .sort()
  const order = []
  while (ready.length) {
    const id = ready.shift()
    order.push(id)
    for (const edge of outgoing.get(id) ?? []) {
      if (!incoming.has(edge.to)) continue
      incoming.set(edge.to, incoming.get(edge.to) - 1)
      if (incoming.get(edge.to) === 0) ready.push(edge.to)
    }
  }
  return order.length === incoming.size ? order : null
}

/** node id → the nodes every path from the start to it passes through (itself left out). */
export function dominators(graph, order = topological(graph)) {
  const out = new Map()
  if (!order) return out
  const incoming = edgesTo(graph)
  const dom = new Map()
  for (const id of order) {
    const sources = incoming
      .get(id)
      .map((edge) => edge.from)
      .filter((source) => dom.has(source))
    if (sources.length === 0) {
      dom.set(id, new Set([id]))
      continue
    }
    let shared = new Set(dom.get(sources[0]))
    for (const source of sources.slice(1)) shared = new Set([...shared].filter((item) => dom.get(source).has(item)))
    shared.add(id)
    dom.set(id, shared)
  }
  for (const [id, found] of dom) out.set(id, new Set([...found].filter((item) => item !== id)))
  return out
}

/**
 * What the expressions of a node can read: `{ nodes, loop, poll }`. `nodes`
 * are the ids of the nodes certain to have run before it (the trigger among
 * them), in the order they run; `loop` is the "for each" whose body holds the
 * node, or null; `poll` says a wait reads the last answer of its action.
 */
export function readable(graph, id) {
  const node = nodeOf(graph, id)
  const order = topological(graph)
  if (!node || !order) return { nodes: [], loop: null, poll: false }
  const inBody = new Map()
  for (const [loop, body] of loopBodies(graph)) for (const member of body) inBody.set(member, loop)
  const loop = inBody.get(id) ?? null
  const before = dominators(graph, order).get(id) ?? new Set()
  return {
    // A result inside another loop is one per item: outside it, the loop's results are read instead.
    nodes: order.filter((other) => before.has(other) && (!inBody.has(other) || inBody.get(other) === loop)),
    loop,
    poll: node.kind === 'wait' && Boolean(node.config?.poll),
  }
}

/** The names a node's expressions use that it cannot read: `[{ name, reason }]`. */
export function unreadable(graph, id) {
  const node = nodeOf(graph, id)
  if (!node) return []
  const { nodes, loop, poll } = readable(graph, id)
  const allowed = new Set([...ALWAYS, ...nodes, ...(loop ? IN_LOOP : []), ...(poll ? ['poll'] : [])])
  let found
  try {
    found = references(node.config)
  } catch {
    return []
  }
  const known = nodesOf(graph)
  const out = []
  for (const { name } of found) {
    if (allowed.has(name) || out.some((item) => item.name === name)) continue
    const reason = known.has(name)
      ? 'is not certain to have run before this node'
      : IN_LOOP.includes(name)
        ? 'can be read only inside a "for each"'
        : 'is not a node of this playbook'
    out.push({ name, reason })
  }
  return out
}

// --------------------------------------------------------------------------- //
// Edits                                                                       //
// --------------------------------------------------------------------------- //
/** An id for a new node, from what it is called: `add_a_note`, then `add_a_note_2`. */
export function newId(graph, base) {
  let stem = String(base ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^[^a-z]+/, '')
    .replace(/_+$/, '')
    .slice(0, 24)
  if (!stem) stem = 'node'
  const taken = new Set(list(graph?.nodes).map((node) => node.id))
  if (!taken.has(stem) && !RESERVED.has(stem)) return stem
  for (let counter = 2; ; counter += 1) {
    const candidate = `${stem}_${counter}`
    if (!taken.has(candidate)) return candidate
  }
}

/** Why `id` cannot be the id of a node (`except`: the node being renamed), or null. */
export function idProblem(graph, id, except = null) {
  if (!ID_RE.test(id)) return 'A lower-case letter, then letters, digits or _ (32 at most)'
  if (RESERVED.has(id)) return `"${id}" is a name of the expressions: choose another`
  if (list(graph?.nodes).some((node) => node.id === id && node.id !== except)) return 'Another node has this id'
  return null
}

export function addNode(graph, node) {
  return { ...graph, nodes: [...list(graph.nodes), node] }
}

/** Change a node: `patch` is merged into it; a `config` in it replaces the node's. */
export function updateNode(graph, id, patch) {
  return { ...graph, nodes: graph.nodes.map((node) => (node.id === id ? { ...node, ...patch } : node)) }
}

/** Remove nodes and every edge that touches them. The trigger stays: a playbook has exactly one. */
export function removeNodes(graph, ids) {
  const gone = new Set([...ids].filter((id) => nodeOf(graph, id)?.kind !== 'trigger'))
  if (gone.size === 0) return graph
  return {
    ...graph,
    nodes: graph.nodes.filter((node) => !gone.has(node.id)),
    edges: graph.edges.filter((edge) => !gone.has(edge.from) && !gone.has(edge.to)),
  }
}

/**
 * New positions for some nodes: `{ id: { x, y } }`. The same graph when nothing moved. A line
 * of a node that moved forgets the route the layout gave it: the route was for where the node was.
 */
export function moveNodes(graph, positions) {
  const moved = new Set()
  const nodes = graph.nodes.map((node) => {
    const next = positions[node.id]
    if (!next || (next.x === node.position?.x && next.y === node.position?.y)) return node
    moved.add(node.id)
    return { ...node, position: { x: Math.round(next.x), y: Math.round(next.y) } }
  })
  if (moved.size === 0) return graph
  const stale = (edge) => edge.route && (moved.has(edge.from) || moved.has(edge.to))
  return {
    ...graph,
    nodes,
    edges: graph.edges.some(stale) ? graph.edges.map((edge) => (stale(edge) ? withoutRoute(edge) : edge)) : graph.edges,
  }
}

/**
 * Put a layout in the graph (layout.js, `tidy`): each node where it says, each line with the
 * route it gives, and no route for a line it gives none. The same graph when that changes nothing.
 */
export function arrange(graph, { positions, routes = {} }) {
  const placed = moveNodes(graph, positions)
  const edges = placed.edges.map((edge) => {
    const route = cleanRoute(routes[lineKey(edge.from, portOf(edge, graph), edge.to)])
    return route ? { ...withoutRoute(edge), route } : withoutRoute(edge)
  })
  return JSON.stringify(edges) === JSON.stringify(graph.edges) && placed.nodes === graph.nodes
    ? graph
    : { ...placed, edges }
}

/** Why an edge cannot be drawn, or null. */
export function connectProblem(graph, from, port, to) {
  const source = nodeOf(graph, from)
  const target = nodeOf(graph, to)
  if (!source || !target) return 'An edge joins two nodes of the playbook'
  if (!portsOf(source).includes(port)) return `A ${KIND_LABELS[source.kind].toLowerCase()} node has no "${port}" port`
  if (from === to) return 'A node cannot lead to itself'
  if (target.kind === 'trigger') return 'Nothing leads to the trigger'
  if (graph.edges.some((edge) => edge.from === from && edge.to === to && portOf(edge, graph) === port)) {
    return 'This edge is drawn already'
  }
  if (reachable(graph, to).has(from)) return 'That would go round in a circle: use a "for each" to repeat'
  return null
}

/** Draw an edge: `{ graph, problem }` (the graph is unchanged when there is a problem). */
export function connect(graph, from, port, to) {
  const usedPort = port || DEFAULT_PORT[nodeOf(graph, from)?.kind] || 'out'
  const problem = connectProblem(graph, from, usedPort, to)
  if (problem) return { graph, problem }
  return { graph: { ...graph, edges: [...graph.edges, { from, port: usedPort, to }] }, problem: null }
}

export function disconnect(graph, from, port, to) {
  const edges = graph.edges.filter((edge) => !(edge.from === from && edge.to === to && portOf(edge, graph) === port))
  return edges.length === graph.edges.length ? graph : { ...graph, edges }
}

/** The graph without any line that arrives at, or leaves, one of these nodes. The same graph when there is none. */
export function disconnectNodes(graph, ids) {
  const chosen = new Set(ids)
  const edges = graph.edges.filter((edge) => !chosen.has(edge.from) && !chosen.has(edge.to))
  return edges.length === graph.edges.length ? graph : { ...graph, edges }
}

/** How many lines arrive at, or leave, one of these nodes. */
export function linesOf(graph, ids) {
  const chosen = new Set(ids)
  return list(graph?.edges).filter((edge) => chosen.has(edge.from) || chosen.has(edge.to)).length
}

/**
 * Give a node another id: its edges follow, and so does every expression
 * that reads it. `{ graph, problem }`.
 */
export function renameNode(graph, from, to) {
  if (from === to) return { graph, problem: null }
  const problem = idProblem(graph, to, from)
  if (problem) return { graph, problem }
  return {
    problem: null,
    graph: {
      ...graph,
      nodes: graph.nodes.map((node) => ({
        ...node,
        id: node.id === from ? to : node.id,
        config: renameRoot(node.config, from, to),
      })),
      edges: graph.edges.map((edge) => ({
        ...edge,
        from: edge.from === from ? to : edge.from,
        to: edge.to === from ? to : edge.to,
      })),
      outputs: list(graph.outputs).length ? renameRoot(graph.outputs, from, to) : graph.outputs,
    },
  }
}

/** What "copy" keeps: the chosen nodes (never the trigger) and the edges between them. */
export function copyOf(graph, ids) {
  const chosen = new Set([...ids].filter((id) => nodeOf(graph, id) && nodeOf(graph, id).kind !== 'trigger'))
  return {
    nodes: graph.nodes.filter((node) => chosen.has(node.id)),
    edges: graph.edges
      .filter((edge) => chosen.has(edge.from) && chosen.has(edge.to))
      // A copy is pasted somewhere else: the route of a line is not copied with it.
      .map((edge) => ({ ...withoutRoute(edge), port: portOf(edge, graph) })),
  }
}

/**
 * Paste what was copied: new ids, the expressions among the pasted nodes
 * following them, each node moved by `offset`. `{ graph, ids }`.
 */
export function paste(graph, copied, offset = { x: 40, y: 40 }) {
  let next = graph
  const renamed = new Map()
  let nodes = structuredClone(list(copied?.nodes))
  for (const node of nodes) {
    const id = newId(
      { nodes: [...next.nodes, ...[...renamed.values()].map((taken) => ({ id: taken }))] },
      node.id.replace(/_\d+$/, ''),
    )
    renamed.set(node.id, id)
  }
  // Two passes, so that a new id never collides with one still waiting to be renamed.
  const pairs = [...renamed]
  const rewrite = (config) => {
    let out = config
    pairs.forEach(([from], index) => (out = renameRoot(out, from, `__pasted_${index}`)))
    pairs.forEach(([, to], index) => (out = renameRoot(out, `__pasted_${index}`, to)))
    return out
  }
  nodes = nodes.map((node) => ({
    ...node,
    id: renamed.get(node.id),
    config: rewrite(node.config),
    position: { x: (node.position?.x ?? 0) + offset.x, y: (node.position?.y ?? 0) + offset.y },
  }))
  next = {
    ...next,
    nodes: [...next.nodes, ...nodes],
    edges: [
      ...next.edges,
      ...list(copied?.edges).map((edge) => ({ ...edge, from: renamed.get(edge.from), to: renamed.get(edge.to) })),
    ],
  }
  return { graph: next, ids: nodes.map((node) => node.id) }
}

/**
 * Paste what was copied so that it lands at `position`: the node that was highest, and of those
 * the leftmost, is put there, and the others keep their places around it. `{ graph, ids }`.
 */
export function pasteAt(graph, copied, position) {
  const nodes = list(copied?.nodes)
  if (nodes.length === 0) return { graph, ids: [] }
  const first = nodes.reduce((found, node) => {
    const [a, b] = [node.position ?? { x: 0, y: 0 }, found.position ?? { x: 0, y: 0 }]
    return a.y < b.y || (a.y === b.y && a.x < b.x) ? node : found
  })
  return paste(graph, copied, {
    x: Math.round(position.x - (first.position?.x ?? 0)),
    y: Math.round(position.y - (first.position?.y ?? 0)),
  })
}

/** True when two graphs are the same playbook (what decides "draft changed"). */
export const sameGraph = (a, b) => JSON.stringify(a ?? null) === JSON.stringify(b ?? null)

// --------------------------------------------------------------------------- //
// Undo and redo                                                               //
// --------------------------------------------------------------------------- //
const HISTORY_MAX = 100

export const historyOf = (present) => ({ past: [], present, future: [] })

/** A new state after an edit. An edit that changed nothing is not a step. */
export function record(history, present) {
  if (present === history.present) return history
  return { past: [...history.past.slice(-(HISTORY_MAX - 1)), history.present], present, future: [] }
}

export function undo(history) {
  if (history.past.length === 0) return history
  return {
    past: history.past.slice(0, -1),
    present: history.past.at(-1),
    future: [history.present, ...history.future],
  }
}

export function redo(history) {
  if (history.future.length === 0) return history
  return { past: [...history.past, history.present], present: history.future[0], future: history.future.slice(1) }
}
