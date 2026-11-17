/*
 * "Tidy up": positions for the nodes of a playbook, top to bottom.
 *
 * ELK (elkjs, already used by the disassembly graph, loaded on first use)
 * does the work; `layered` is the plain fallback when it cannot (and what the
 * unit tests check): each node one row under the furthest node that leads to
 * it, the nodes of a row side by side.
 */
import { edgesFrom, portOf, topological } from './graph.js'

export const NODE_WIDTH = 190
export const NODE_HEIGHT = 62
const GAP_X = 50
const GAP_Y = 56

/** Positions without ELK: `{ id: { x, y } }`. */
export function layered(graph) {
  const order = topological(graph) ?? graph.nodes.map((node) => node.id)
  const outgoing = edgesFrom(graph)
  const row = new Map(order.map((id) => [id, 0]))
  for (const id of order) {
    for (const edge of outgoing.get(id) ?? []) {
      if (row.has(edge.to)) row.set(edge.to, Math.max(row.get(edge.to), row.get(id) + 1))
    }
  }
  const columns = new Map()
  const positions = {}
  for (const id of order) {
    const y = row.get(id)
    const x = columns.get(y) ?? 0
    columns.set(y, x + 1)
    positions[id] = { x: 40 + x * (NODE_WIDTH + GAP_X), y: 40 + y * (NODE_HEIGHT + GAP_Y) }
  }
  return positions
}

let elkPromise = null

/** Positions by ELK, or by `layered` when it is not there or fails. */
export async function tidy(graph) {
  try {
    elkPromise ??= import('elkjs/lib/elk.bundled.js').then((module) => new module.default())
    const elk = await elkPromise
    const result = await elk.layout({
      id: 'root',
      layoutOptions: {
        'elk.algorithm': 'layered',
        'elk.direction': 'DOWN',
        'elk.layered.spacing.nodeNodeBetweenLayers': String(GAP_Y),
        'elk.spacing.nodeNode': String(GAP_X),
        'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
        'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
      },
      children: graph.nodes.map((node) => ({ id: node.id, width: NODE_WIDTH, height: NODE_HEIGHT })),
      edges: graph.edges.map((edge, index) => ({
        id: `e${index}:${portOf(edge, graph)}`,
        sources: [edge.from],
        targets: [edge.to],
      })),
    })
    const positions = {}
    for (const child of result.children ?? [])
      positions[child.id] = { x: Math.round(child.x + 40), y: Math.round(child.y + 40) }
    if (Object.keys(positions).length === graph.nodes.length) return positions
  } catch {
    /* the fallback below */
  }
  return layered(graph)
}
