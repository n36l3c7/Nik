/*
 * "Tidy up": where the nodes of a playbook go, top to bottom, and the way each
 * line takes between them.
 *
 * ELK (elkjs, already used by the disassembly graph, loaded on first use) does
 * the work. It is told what the canvas draws: every node with its size, the
 * place on its top edge a line arrives at, the place of each of its outputs
 * along its bottom edge (and of "on error" on its right side), and the words a
 * line carries. It answers with a place for each node and, for each line, a
 * route of straight parts that goes round the nodes it does not join: a line
 * that skips a row (the "when done" of a "for each", an "on error" that goes
 * far down) gets a lane of its own beside the column instead of running
 * through it, and its words a place that is on no node.
 *
 * The routes are the layout's, kept with the positions it gave
 * (`edges[].route`, graph.js): nobody draws or drags them, the next "Tidy up"
 * computes them again, and the route of a line is forgotten as soon as one of
 * its two nodes is moved by hand (the canvas then draws that line by itself).
 *
 * `layered` is the plain fallback when ELK cannot be had (positions only):
 * each node one row under the furthest node that leads to it, the nodes of a
 * row side by side.
 *
 * `crossings` says whether what is drawn keeps the promise: no line over the
 * box of a node it does not join, no words of a line on a node.
 */
import { edgesFrom, lineKey, nodeOf, portLabel, portOf, portsOf, topological } from './graph.js'

export const NODE_WIDTH = 190
export const NODE_HEIGHT = 62
const GAP_X = 50
const GAP_Y = 56
// Where the layout starts, in the coordinates of the canvas.
const ORIGIN = 40
// The room ELK leaves between a line and a node it passes, and between two lines side by side.
const LANE = 28
const BETWEEN_LINES = 16
// What a letter of the words of a line takes (10 px, monospaced), and the box around them.
const LETTER = 6.1
const LABEL_HEIGHT = 16

/**
 * Where the handles of a node sit: its outputs along its lower edge, each at
 * `left` (a share of its width), and whether `error` leaves from its right side.
 */
export function handlePlaces(node) {
  const ports = portsOf(node)
  const below = ports.filter((port) => port !== 'error')
  return {
    below: below.map((port, index) => ({ port, left: (index + 1) / (below.length + 1) })),
    side: ports.includes('error'),
  }
}

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
    positions[id] = { x: ORIGIN + x * (NODE_WIDTH + GAP_X), y: ORIGIN + y * (NODE_HEIGHT + GAP_Y) }
  }
  return positions
}

/** The size of the words of a line, as the layout is told to leave room for them. */
export const labelSize = (text) => ({ width: Math.ceil(String(text).length * LETTER) + 10, height: LABEL_HEIGHT })

/** The playbook as ELK reads it: nodes with their ports where the canvas draws them, lines with their words. */
function elkGraph(graph) {
  const fixed = (id, x, y, side) => ({ id, x, y, width: 0, height: 0, layoutOptions: { 'elk.port.side': side } })
  return {
    id: 'root',
    layoutOptions: {
      'elk.algorithm': 'layered',
      'elk.direction': 'DOWN',
      // Lines in straight parts, each with room of its own beside the nodes it passes.
      'elk.edgeRouting': 'ORTHOGONAL',
      'elk.layered.spacing.nodeNodeBetweenLayers': String(GAP_Y),
      'elk.spacing.nodeNode': String(GAP_X),
      'elk.spacing.edgeNode': String(LANE),
      'elk.layered.spacing.edgeNodeBetweenLayers': String(LANE),
      'elk.spacing.edgeEdge': String(BETWEEN_LINES),
      'elk.layered.spacing.edgeEdgeBetweenLayers': String(BETWEEN_LINES),
      'elk.spacing.edgeLabel': '4',
      'elk.layered.nodePlacement.strategy': 'BRANDES_KOEPF',
      'elk.layered.considerModelOrder.strategy': 'NODES_AND_EDGES',
    },
    children: graph.nodes.map((node) => {
      const places = handlePlaces(node)
      return {
        id: node.id,
        width: NODE_WIDTH,
        height: NODE_HEIGHT,
        // The ports are where the canvas draws the handles, and stay there.
        layoutOptions: { 'elk.portConstraints': 'FIXED_POS' },
        ports: [
          fixed(`${node.id}\u0000in`, NODE_WIDTH / 2, 0, 'NORTH'),
          ...places.below.map(({ port, left }) =>
            fixed(`${node.id}\u0000out\u0000${port}`, Math.round(NODE_WIDTH * left), NODE_HEIGHT, 'SOUTH'),
          ),
          ...(places.side ? [fixed(`${node.id}\u0000out\u0000error`, NODE_WIDTH, NODE_HEIGHT / 2, 'EAST')] : []),
        ],
      }
    }),
    edges: graph.edges.map((edge, index) => {
      const port = portOf(edge, graph)
      const words = portLabel(nodeOf(graph, edge.from), port)
      return {
        id: `e${index}`,
        sources: [`${edge.from}\u0000out\u0000${port}`],
        targets: [`${edge.to}\u0000in`],
        labels: words
          ? [
              {
                id: `l${index}`,
                text: words,
                ...labelSize(words),
                layoutOptions: { 'elk.edgeLabels.placement': 'CENTER' },
              },
            ]
          : [],
      }
    }),
  }
}

const at = (point) => ({ x: Math.round(point.x + ORIGIN), y: Math.round(point.y + ORIGIN) })

/** What ELK answered, as the canvas keeps it: `{ positions, routes }`, or null when something is missing. */
function readLayout(result, graph) {
  const positions = {}
  for (const child of result.children ?? []) positions[child.id] = at(child)
  if (Object.keys(positions).length !== graph.nodes.length) return null
  const routes = {}
  for (const drawn of result.edges ?? []) {
    const edge = graph.edges[Number(drawn.id.slice(1))]
    const section = drawn.sections?.[0]
    if (!edge || !section || drawn.sections.length !== 1) continue
    const points = [section.startPoint, ...(section.bendPoints ?? []), section.endPoint].map(at)
    const words = drawn.labels?.[0]
    routes[lineKey(edge.from, portOf(edge, graph), edge.to)] = {
      points,
      // The middle of the room that was left for the words of the line.
      ...(words && Number.isFinite(words.x)
        ? { label: at({ x: words.x + words.width / 2, y: words.y + words.height / 2 }) }
        : {}),
    }
  }
  return { positions, routes }
}

let elkPromise = null

/**
 * The layout of a playbook: `{ positions: { id: { x, y } }, routes: { lineKey:
 * { points, label? } } }`. By ELK; by `layered`, with no route, when ELK is
 * not there or fails. `arrange` (graph.js) puts it in the graph.
 */
export async function tidy(graph) {
  try {
    elkPromise ??= import('elkjs/lib/elk.bundled.js').then((module) => new module.default())
    const elk = await elkPromise
    const found = readLayout(await elk.layout(elkGraph(graph)), graph)
    if (found) return found
  } catch {
    /* the fallback below */
  }
  return { positions: layered(graph), routes: {} }
}

// --------------------------------------------------------------------------- //
// Drawing a route                                                             //
// --------------------------------------------------------------------------- //
const CORNER = 5

/**
 * The points a routed line is drawn through, from the handle it leaves to the
 * handle it arrives at. The route says where the line turns; its two ends are
 * the handles as the canvas has them (`source`, `target`), which may be a
 * pixel or two from where the layout thought, and the first and the last turn
 * are moved with them so that every part stays straight.
 */
export function routeStops(route, source, target) {
  const points = route.map((point) => ({ x: point.x, y: point.y }))
  if (points.length < 2) return [source, target]
  if (points.length === 2) {
    // No turn was needed. When the handles are not quite in line, one small step in the middle.
    const upright = Math.abs(points[0].x - points[1].x) <= Math.abs(points[0].y - points[1].y)
    if (upright && source.x !== target.x) {
      const middle = Math.round((source.y + target.y) / 2)
      return [source, { x: source.x, y: middle }, { x: target.x, y: middle }, target]
    }
    if (!upright && source.y !== target.y) {
      const middle = Math.round((source.x + target.x) / 2)
      return [source, { x: middle, y: source.y }, { x: middle, y: target.y }, target]
    }
    return [source, target]
  }
  const follow = (end, turn, handle) => (end.x === turn.x ? { ...turn, x: handle.x } : { ...turn, y: handle.y })
  const turns = points.slice(1, -1)
  turns[0] = follow(points[0], turns[0], source)
  turns[turns.length - 1] = follow(points.at(-1), turns.at(-1), target)
  return [source, ...turns, target]
}

/** The SVG path through some points: straight parts, the turns a little rounded. */
export function pathThrough(stops) {
  const round = (value) => Math.round(value * 10) / 10
  let path = `M ${round(stops[0].x)} ${round(stops[0].y)}`
  for (let index = 1; index < stops.length; index += 1) {
    const here = stops[index]
    const next = stops[index + 1]
    if (!next) {
      path += ` L ${round(here.x)} ${round(here.y)}`
      break
    }
    const before = stops[index - 1]
    const reach = (other) => Math.min(CORNER, Math.hypot(other.x - here.x, other.y - here.y) / 2)
    const toward = (other, distance) => {
      const length = Math.hypot(other.x - here.x, other.y - here.y) || 1
      return {
        x: here.x + ((other.x - here.x) / length) * distance,
        y: here.y + ((other.y - here.y) / length) * distance,
      }
    }
    const enter = toward(before, reach(before))
    const leave = toward(next, reach(next))
    path += ` L ${round(enter.x)} ${round(enter.y)} Q ${round(here.x)} ${round(here.y)} ${round(leave.x)} ${round(leave.y)}`
  }
  return path
}

/** The middle of the longest straight part of a line: where its × goes, and its words when the layout gave no place. */
export function longestMiddle(stops) {
  let best = { x: stops[0].x, y: stops[0].y }
  let longest = -1
  for (let index = 1; index < stops.length; index += 1) {
    const length = Math.hypot(stops[index].x - stops[index - 1].x, stops[index].y - stops[index - 1].y)
    if (length > longest) {
      longest = length
      best = { x: (stops[index].x + stops[index - 1].x) / 2, y: (stops[index].y + stops[index - 1].y) / 2 }
    }
  }
  return best
}

// --------------------------------------------------------------------------- //
// Checking what is drawn                                                      //
// --------------------------------------------------------------------------- //
/** Whether the straight part from `a` to `b` passes inside a box (Liang and Barsky). */
function passesInside(a, b, box) {
  let enter = 0
  let leave = 1
  const sides = [
    [-(b.x - a.x), a.x - box.left],
    [b.x - a.x, box.right - a.x],
    [-(b.y - a.y), a.y - box.top],
    [b.y - a.y, box.bottom - a.y],
  ]
  for (const [along, room] of sides) {
    if (along === 0) {
      if (room <= 0) return false
    } else if (along < 0) enter = Math.max(enter, room / along)
    else leave = Math.min(leave, room / along)
  }
  return enter < leave
}

/**
 * Where a drawing breaks the promise of the layout: the lines that pass over
 * the box of a node they do not join, and the words of a line that sit on a
 * node. `[{ from, to, node, what: 'line' | 'label' }]`, empty when all is well.
 *
 * @param {{ id: string, x: number, y: number, width: number, height: number }[]} boxes  the nodes
 * @param {{ from: string, to: string, points: { x: number, y: number }[] }[]} lines     each line as its points
 * @param {{ from: string, to: string, x: number, y: number, width: number, height: number }[]} labels
 * @param {number} slack  how far inside a box something must be to count (touching an edge does not)
 */
export function crossings(boxes, lines, labels = [], slack = 1) {
  const inner = boxes.map((box) => ({
    id: box.id,
    left: box.x + slack,
    right: box.x + box.width - slack,
    top: box.y + slack,
    bottom: box.y + box.height - slack,
  }))
  const found = []
  for (const line of lines) {
    for (const box of inner) {
      if (box.id === line.from || box.id === line.to) continue
      const over = line.points.some((point, index) => index > 0 && passesInside(line.points[index - 1], point, box))
      if (over) found.push({ from: line.from, to: line.to, node: box.id, what: 'line' })
    }
  }
  for (const label of labels) {
    for (const box of inner) {
      const apart =
        label.x + label.width <= box.left ||
        label.x >= box.right ||
        label.y + label.height <= box.top ||
        label.y >= box.bottom
      if (!apart) found.push({ from: label.from, to: label.to, node: box.id, what: 'label' })
    }
  }
  return found
}

/**
 * A graph as it is drawn, for `crossings`: the box of each node, each line as
 * the points of its route (a line with no route is left out: the canvas draws
 * it), and the box of the words of each line that has a place for them.
 */
export function drawingOf(graph) {
  const boxes = graph.nodes.map((node) => ({
    id: node.id,
    x: node.position.x,
    y: node.position.y,
    width: NODE_WIDTH,
    height: NODE_HEIGHT,
  }))
  const lines = []
  const labels = []
  for (const edge of graph.edges) {
    if (!edge.route) continue
    lines.push({ from: edge.from, to: edge.to, points: edge.route.points })
    const words = portLabel(nodeOf(graph, edge.from), portOf(edge, graph))
    if (words && edge.route.label) {
      const size = labelSize(words)
      labels.push({
        from: edge.from,
        to: edge.to,
        x: edge.route.label.x - size.width / 2,
        y: edge.route.label.y - size.height / 2,
        ...size,
      })
    }
  }
  return { boxes, lines, labels }
}
