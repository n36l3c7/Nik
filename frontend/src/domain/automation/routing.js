/*
 * The line of a connection that somebody routed by hand (5.2).
 *
 * A connection is drawn by itself (a stepped line) until someone gives it
 * corners: then it goes from its source through its `points`, in order, to its
 * target, in straight parts. The points are kept in the graph
 * (`edges[].points`, `[{ x, y }]` in the coordinates of the canvas), so the
 * drawing is the same for everyone and in every version.
 *
 * The handles on a line are of two kinds: one at each corner, to move it or
 * take it away, and one in the middle of each straight part, which becomes a
 * corner when it is dragged.
 */

export const MAX_POINTS = 20
export const GRID = 10

const round = (value) => Math.round(Number(value) || 0)

/** A coordinate on the grid of the canvas. */
export const snap = (value, grid = GRID) => Math.round((Number(value) || 0) / grid) * grid

/** The points of an edge as they are kept: whole numbers, twenty at most; [] for none. */
export function cleanPoints(points) {
  if (!Array.isArray(points)) return []
  return points
    .filter((point) => point && Number.isFinite(Number(point.x)) && Number.isFinite(Number(point.y)))
    .slice(0, MAX_POINTS)
    .map((point) => ({ x: round(point.x), y: round(point.y) }))
}

/** Every place the line goes through: the source, its corners, the target. */
export const stops = (source, target, points) => [source, ...cleanPoints(points), target]

/** The SVG path of a routed line: straight parts through its corners. */
export function routePath(source, target, points) {
  return stops(source, target, points)
    .map((point, index) => `${index === 0 ? 'M' : 'L'} ${round(point.x)} ${round(point.y)}`)
    .join(' ')
}

/** The middle of each straight part: `index` is where a corner made there goes in `points`. */
export function middles(source, target, points) {
  const all = stops(source, target, points)
  return all.slice(1).map((point, index) => ({
    index,
    x: round((all[index].x + point.x) / 2),
    y: round((all[index].y + point.y) / 2),
  }))
}

/** The point half way along the line, by length: where its label and its × are. */
export function halfWay(source, target, points) {
  const all = stops(source, target, points)
  const lengths = all.slice(1).map((point, index) => Math.hypot(point.x - all[index].x, point.y - all[index].y))
  const total = lengths.reduce((sum, length) => sum + length, 0)
  if (total === 0) return { x: round(source.x), y: round(source.y) }
  let left = total / 2
  for (let index = 0; index < lengths.length; index += 1) {
    if (left <= lengths[index]) {
      const share = lengths[index] === 0 ? 0 : left / lengths[index]
      return {
        x: round(all[index].x + (all[index + 1].x - all[index].x) * share),
        y: round(all[index].y + (all[index + 1].y - all[index].y) * share),
      }
    }
    left -= lengths[index]
  }
  return { x: round(target.x), y: round(target.y) }
}

/**
 * Where the × and the label of a routed line are: the middle of its longest
 * straight part, which is never on a corner. `index` is that part's.
 */
export function labelSpot(source, target, points) {
  const found = middles(source, target, points)
  const all = stops(source, target, points)
  let best = found[0]
  let longest = -1
  for (const middle of found) {
    const length = Math.hypot(
      all[middle.index + 1].x - all[middle.index].x,
      all[middle.index + 1].y - all[middle.index].y,
    )
    if (length > longest) {
      longest = length
      best = middle
    }
  }
  return best
}

/** `points` with a corner added at `index` (where `middles` said), on the grid. Unchanged when full. */
export function insertPoint(points, index, point) {
  const all = cleanPoints(points)
  if (all.length >= MAX_POINTS) return all
  const at = Math.max(0, Math.min(index, all.length))
  return [...all.slice(0, at), { x: snap(point.x), y: snap(point.y) }, ...all.slice(at)]
}

/** `points` with the corner at `index` moved, on the grid. */
export function movePoint(points, index, point) {
  return cleanPoints(points).map((existing, at) => (at === index ? { x: snap(point.x), y: snap(point.y) } : existing))
}

/** `points` without the corner at `index`. */
export const removePoint = (points, index) => cleanPoints(points).filter((_point, at) => at !== index)

/**
 * The graph with the corners of one edge set (`[]` lets it draw itself
 * again). The same graph when nothing changes, or there is no such edge.
 */
export function setEdgePoints(graph, matches, points) {
  const cleaned = cleanPoints(points)
  let changed = false
  const edges = graph.edges.map((edge) => {
    if (!matches(edge)) return edge
    const before = JSON.stringify(cleanPoints(edge.points))
    if (before === JSON.stringify(cleaned)) return edge
    changed = true
    const { points: _gone, ...rest } = edge
    return cleaned.length ? { ...rest, points: cleaned } : rest
  })
  return changed ? { ...graph, edges } : graph
}
