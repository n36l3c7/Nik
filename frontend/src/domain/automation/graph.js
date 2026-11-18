/*
 * The graph of a playbook as the canvas edits it (the server's rules are in
 * backend/app/automation/graph.py, and the server decides what can be saved
 * as a version):
 *
 *   { nodes: [{ id, kind, name, position: { x, y }, config }],
 *     edges: [{ from, port?, to }], inputs: [...], outputs: [...] }
 *
 * Everything here is pure: an edit returns a new graph and leaves the old one
 * as it was, which is what undo and redo rely on.
 */
import { references, renameRoot } from './expressions.js'

export const KINDS = ['trigger', 'condition', 'for_each', 'wait', 'approval', 'action', 'script', 'playbook', 'end']

/** The ports a node leaves by. `error` is drawn only when a failure is handled. */
export const PORTS = {
  trigger: ['out'],
  condition: ['yes', 'no'],
  for_each: ['each', 'done', 'error'],
  wait: ['out'],
  approval: ['approved', 'refused'],
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
}

/** What a port is called where it has to be named (the inspector, the node list). */
export const PORT_NAMES = { ...PORT_LABELS, out: 'then' }

export const KIND_LABELS = {
  trigger: 'Trigger',
  condition: 'Condition',
  for_each: 'For each',
  wait: 'Wait',
  approval: 'Approval',
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

export const emptyGraph = () => ({ nodes: [], edges: [] })

const list = (value) => (Array.isArray(value) ? value : [])

/** A graph with the parts the canvas relies on: lists, and a position for every node. */
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
    edges: list(source.edges).filter((edge) => edge && typeof edge.from === 'string' && typeof edge.to === 'string'),
  }
}

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

/** New positions for some nodes: `{ id: { x, y } }`. The same graph when nothing moved. */
export function moveNodes(graph, positions) {
  let moved = false
  const nodes = graph.nodes.map((node) => {
    const next = positions[node.id]
    if (!next || (next.x === node.position?.x && next.y === node.position?.y)) return node
    moved = true
    return { ...node, position: { x: Math.round(next.x), y: Math.round(next.y) } }
  })
  return moved ? { ...graph, nodes } : graph
}

/** Why an edge cannot be drawn, or null. */
export function connectProblem(graph, from, port, to) {
  const source = nodeOf(graph, from)
  const target = nodeOf(graph, to)
  if (!source || !target) return 'An edge joins two nodes of the playbook'
  if (!PORTS[source.kind]?.includes(port))
    return `A ${KIND_LABELS[source.kind].toLowerCase()} node has no "${port}" port`
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
      .map((edge) => ({ ...edge, port: portOf(edge, graph) })),
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
