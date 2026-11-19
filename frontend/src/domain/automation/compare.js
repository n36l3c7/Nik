/*
 * Two graphs of a playbook compared: main as it is now, and a branch before it
 * is pushed over it (6.3). Graphs are not merged, so what a push replaces is
 * worth seeing first.
 *
 * Nodes are matched by id. A node is **added** (in the branch only),
 * **removed** (in main only) or **changed** (in both, with another kind, name
 * or configuration); one that only sits somewhere else on the canvas is not a
 * change, and is counted apart. The configuration is compared key by key, down
 * to the values, so that what differs can be shown field by field; a script
 * version pinned on a node is a key like any other. Lines are compared by
 * where they leave (node and port) and where they go: the corners somebody
 * gave a line are drawing, like positions.
 *
 * Everything here is pure: two graphs in, what differs out.
 */
import { normalise, portLabel, portOf } from './graph.js'

/** What a change is told by besides its colour: the sign in front of it. */
export const SIGNS = { added: '+', changed: '~', removed: '-', moved: '~', same: '' }

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)
const plain = (items) => items.every((item) => item === null || typeof item !== 'object')
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b)

/**
 * The values a thing holds, by where they are: `args.url`, `choices`, `inputs[0].type`. A list of plain
 * values is one value; a list of objects is gone into, item by item.
 */
function leaves(value, path, out) {
  if (isObject(value) && Object.keys(value).length > 0) {
    for (const key of Object.keys(value)) leaves(value[key], path ? `${path}.${key}` : key, out)
  } else if (Array.isArray(value) && value.length > 0 && !plain(value)) {
    value.forEach((item, index) => leaves(item, `${path}[${index}]`, out))
  } else if (path) {
    out.set(path, value)
  }
  return out
}

// What a node is besides what it holds: neither is compared.
const NOT_COMPARED = new Set(['id', 'position', 'config'])

/** The fields of a node: its kind, its name, then its configuration, each key by its path. */
export function fieldsOf(node) {
  const out = new Map()
  for (const key of Object.keys(node ?? {})) if (!NOT_COMPARED.has(key)) leaves(node[key], key, out)
  for (const [path, value] of leaves(node?.config ?? {}, '', new Map())) {
    // A key of the configuration called like the name or the kind of the node says where it is.
    out.set(out.has(path) ? `config.${path}` : path, value)
  }
  return out
}

/**
 * Two sets of fields, field by field, in the order they are met:
 * `[{ path, change: 'same' | 'changed' | 'added' | 'removed', before?, after? }]`.
 */
export function compareFields(before, after) {
  const out = []
  for (const [path, value] of before) {
    if (!after.has(path)) out.push({ path, change: 'removed', before: value })
    else if (same(value, after.get(path))) out.push({ path, change: 'same', before: value, after: value })
    else out.push({ path, change: 'changed', before: value, after: after.get(path) })
  }
  for (const [path, value] of after) if (!before.has(path)) out.push({ path, change: 'added', after: value })
  return out
}

const differs = (fields) => fields.some((field) => field.change !== 'same')

/** How a line is known in both graphs, and to the canvas: where it leaves, by which port, where it goes. */
export const edgeKey = (from, port, to) => `${from}\u0000${port}\u0000${to}`

function linesOf(graph) {
  const out = new Map()
  for (const edge of graph.edges) {
    const port = portOf(edge, graph)
    out.set(edgeKey(edge.from, port, edge.to), { from: edge.from, port, to: edge.to })
  }
  return out
}

/**
 * What differs between two graphs, `main` and `branch`:
 *
 *   nodes     [{ id, change, kind, name, fields }], the changed, then the added, then the removed
 *   lines     [{ change: 'added' | 'removed' | 'moved', from, port, to, was?, implied }]: a line that
 *             leaves the same port for another node has `moved` (`was` is where it went); `implied`
 *             is a line that came or went with a node, which the node already tells
 *   playbook  the fields of the playbook itself that differ (its inputs, its outputs)
 *   moved     how many nodes only sit somewhere else
 *   counts    { added, changed, removed, linesAdded, linesRemoved, linesMoved, playbook, moved }
 *   same      nothing differs but, at most, where nodes sit
 */
export function compareGraphs(main, branch) {
  const a = normalise(main)
  const b = normalise(branch)
  const before = new Map(a.nodes.map((node) => [node.id, node]))
  const after = new Map(b.nodes.map((node) => [node.id, node]))

  const changed = []
  const added = []
  const removed = []
  let moved = 0
  for (const node of b.nodes) {
    const old = before.get(node.id)
    const entry = { id: node.id, kind: node.kind, name: node.name || node.id }
    if (!old) {
      added.push({ ...entry, change: 'added', fields: compareFields(new Map(), fieldsOf(node)) })
      continue
    }
    const fields = compareFields(fieldsOf(old), fieldsOf(node))
    if (differs(fields)) changed.push({ ...entry, change: 'changed', fields })
    else if (old.position.x !== node.position.x || old.position.y !== node.position.y) moved += 1
  }
  for (const node of a.nodes) {
    if (after.has(node.id)) continue
    removed.push({
      id: node.id,
      kind: node.kind,
      name: node.name || node.id,
      change: 'removed',
      fields: compareFields(fieldsOf(node), new Map()),
    })
  }

  const was = linesOf(a)
  const now = linesOf(b)
  const gone = [...was].filter(([key]) => !now.has(key)).map(([, line]) => line)
  const come = [...now].filter(([key]) => !was.has(key)).map(([, line]) => line)
  const lines = []
  for (const line of come) {
    // The same way out of the same node, to somewhere else: the line was moved, not drawn anew.
    const at = gone.findIndex((old) => old.from === line.from && old.port === line.port)
    if (at >= 0) {
      const [old] = gone.splice(at, 1)
      lines.push({ change: 'moved', ...line, was: old.to, implied: false })
    } else {
      lines.push({ change: 'added', ...line, implied: !before.has(line.from) || !before.has(line.to) })
    }
  }
  for (const line of gone) {
    lines.push({ change: 'removed', ...line, implied: !after.has(line.from) || !after.has(line.to) })
  }

  const rest = (graph) => {
    const out = new Map()
    for (const key of Object.keys(graph)) if (key !== 'nodes' && key !== 'edges') leaves(graph[key], key, out)
    return out
  }
  const playbook = compareFields(rest(a), rest(b)).filter((field) => field.change !== 'same')

  const told = lines.filter((line) => !line.implied)
  const counts = {
    added: added.length,
    changed: changed.length,
    removed: removed.length,
    linesAdded: told.filter((line) => line.change === 'added').length,
    linesRemoved: told.filter((line) => line.change === 'removed').length,
    linesMoved: told.filter((line) => line.change === 'moved').length,
    playbook: playbook.length,
    moved,
  }
  return {
    nodes: [...changed, ...added, ...removed],
    lines,
    playbook,
    moved,
    counts,
    same: changed.length + added.length + removed.length + lines.length + playbook.length === 0,
  }
}

const some = (count, one, many) => `${count} ${count === 1 ? one : many}`

/**
 * The counts on top of the comparison, each with what it is of: "+2 added", "~1 changed", "-1 removed",
 * "1 line moved"… What is not there is not said; nothing at all is said as such.
 */
export function countsOf(diff) {
  const { counts } = diff
  const out = []
  if (counts.added) out.push({ change: 'added', text: `+${counts.added} added` })
  if (counts.changed) out.push({ change: 'changed', text: `~${counts.changed} changed` })
  if (counts.removed) out.push({ change: 'removed', text: `-${counts.removed} removed` })
  if (counts.linesAdded) out.push({ change: 'line', text: `${some(counts.linesAdded, 'line', 'lines')} added` })
  if (counts.linesRemoved) out.push({ change: 'line', text: `${some(counts.linesRemoved, 'line', 'lines')} removed` })
  if (counts.linesMoved) out.push({ change: 'line', text: `${some(counts.linesMoved, 'line', 'lines')} moved` })
  if (counts.playbook) out.push({ change: 'changed', text: '~inputs or outputs changed' })
  if (out.length === 0) out.push({ change: 'same', text: 'nothing differs' })
  if (counts.moved) out.push({ change: 'same', text: `${some(counts.moved, 'node', 'nodes')} only moved` })
  return out
}

/** A line in words: "Line: Look up, on error, to Tell (was to Give up)". `nodeOf` gives a node by its id. */
export function lineText(line, nodeOf = () => null) {
  const nameOf = (id) => nodeOf(id)?.name || id
  const port = portLabel(nodeOf(line.from), line.port)
  const way = port ? `, ${port},` : ''
  const went = line.change === 'moved' ? ` (was to ${nameOf(line.was)})` : ''
  return `Line: ${nameOf(line.from)}${way} to ${nameOf(line.to)}${went}`
}

/**
 * Every change, as the list of the comparison shows it: the nodes, then the lines no node already tells,
 * then the playbook itself. `{ key, change, sign, text, node? }`, where `node` is the id to choose.
 */
export function changesOf(diff, main, branch) {
  const a = new Map(normalise(main).nodes.map((node) => [node.id, node]))
  const b = new Map(normalise(branch).nodes.map((node) => [node.id, node]))
  const nodeOf = (id) => b.get(id) ?? a.get(id) ?? null
  const out = diff.nodes.map((node) => ({
    key: `node:${node.id}`,
    change: node.change,
    sign: SIGNS[node.change],
    text: node.name,
    node: node.id,
  }))
  for (const line of diff.lines) {
    if (line.implied) continue
    out.push({
      key: `line:${edgeKey(line.from, line.port, line.to)}`,
      change: line.change,
      sign: SIGNS[line.change],
      text: `${lineText(line, nodeOf)} · ${line.change}`,
    })
  }
  if (diff.playbook.length) {
    out.push({ key: 'playbook', change: 'changed', sign: SIGNS.changed, text: 'Inputs and outputs of the playbook' })
  }
  return out
}

/**
 * What each side of the comparison marks: `{ nodes: { id: change }, edges: { key: change } }`. Main shows
 * what was removed, the branch what was added; a changed node and a moved line are marked on both.
 */
export function marksOf(diff, side) {
  const mine = side === 'main' ? 'removed' : 'added'
  const nodes = {}
  for (const node of diff.nodes) if (node.change === 'changed' || node.change === mine) nodes[node.id] = node.change
  const edges = {}
  for (const line of diff.lines) {
    if (line.change === mine) edges[edgeKey(line.from, line.port, line.to)] = mine
    else if (line.change === 'moved') {
      edges[edgeKey(line.from, line.port, side === 'main' ? line.was : line.to)] = 'moved'
    }
  }
  return { nodes, edges }
}

/** A field's path as a person reads it: `on_error.mode` is "on error.mode". */
export const fieldLabel = (path) => String(path).replaceAll('_', ' ')

/** A value of a field in a line of text: a text as it is, anything else as JSON. */
export function fieldText(value) {
  if (typeof value === 'string') return value === '' ? '(empty)' : value
  return value === undefined ? '' : JSON.stringify(value)
}

/**
 * The rectangle both graphs are drawn in, so that one viewport shows the same place of each:
 * `{ x, y, width, height }`, or null when neither has a node.
 */
export function boundsOf(graphs, nodeWidth, nodeHeight) {
  const nodes = graphs.flatMap((graph) => normalise(graph).nodes)
  if (nodes.length === 0) return null
  const left = Math.min(...nodes.map((node) => node.position.x))
  const top = Math.min(...nodes.map((node) => node.position.y))
  const right = Math.max(...nodes.map((node) => node.position.x + nodeWidth))
  const bottom = Math.max(...nodes.map((node) => node.position.y + nodeHeight))
  return { x: left, y: top, width: right - left, height: bottom - top }
}
