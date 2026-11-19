import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  MAX_POINTS,
  cleanPoints,
  halfWay,
  insertPoint,
  labelSpot,
  middles,
  movePoint,
  removePoint,
  routePath,
  setEdgePoints,
  snap,
} from './routing.js'

const A = { x: 0, y: 0 }
const B = { x: 100, y: 200 }

test('a routed line goes through its corners, in straight parts', () => {
  assert.equal(routePath(A, B, []), 'M 0 0 L 100 200')
  assert.equal(routePath(A, B, [{ x: 0, y: 200 }]), 'M 0 0 L 0 200 L 100 200')
  assert.equal(routePath(A, B, null), 'M 0 0 L 100 200')
  // What is not a point is left out; coordinates are whole numbers.
  assert.deepEqual(cleanPoints([{ x: 1.6, y: '2' }, null, { x: 'a', y: 1 }, { y: 3 }]), [{ x: 2, y: 2 }])
  assert.equal(cleanPoints(Array.from({ length: 40 }, () => ({ x: 1, y: 1 }))).length, MAX_POINTS)
  assert.equal(snap(14), 10)
  assert.equal(snap(15), 20)
  assert.equal(snap(-6), -10)
})

test('each straight part has a middle, and the line a half way point', () => {
  assert.deepEqual(middles(A, B, []), [{ index: 0, x: 50, y: 100 }])
  assert.deepEqual(middles(A, B, [{ x: 0, y: 200 }]), [
    { index: 0, x: 0, y: 100 },
    { index: 1, x: 50, y: 200 },
  ])
  // Half way by length: 200 down and 100 across, so 150 along, which is on the first part.
  assert.deepEqual(halfWay(A, B, [{ x: 0, y: 200 }]), { x: 0, y: 150 })
  assert.deepEqual(halfWay(A, { x: 0, y: 100 }, []), { x: 0, y: 50 })
  assert.deepEqual(halfWay(A, A, []), { x: 0, y: 0 })
  // The × and the label sit in the middle of the longest part, never on a corner.
  assert.deepEqual(labelSpot(A, B, [{ x: 0, y: 200 }]), { index: 0, x: 0, y: 100 })
  assert.deepEqual(labelSpot(A, B, [{ x: 0, y: 20 }]), { index: 1, x: 50, y: 110 })
  assert.deepEqual(labelSpot(A, B, []), { index: 0, x: 50, y: 100 })
})

test('corners are added, moved and taken away, on the grid', () => {
  const one = insertPoint([], 0, { x: 3, y: 198 })
  assert.deepEqual(one, [{ x: 0, y: 200 }])
  const two = insertPoint(one, 1, { x: 52, y: 204 })
  assert.deepEqual(two, [
    { x: 0, y: 200 },
    { x: 50, y: 200 },
  ])
  assert.deepEqual(insertPoint(two, 0, { x: 0, y: 97 })[0], { x: 0, y: 100 })
  assert.deepEqual(movePoint(two, 1, { x: 71, y: 138 }), [
    { x: 0, y: 200 },
    { x: 70, y: 140 },
  ])
  assert.deepEqual(removePoint(two, 0), [{ x: 50, y: 200 }])
  assert.deepEqual(removePoint(two, 9), two)
  // A line holds twenty corners and no more.
  const full = Array.from({ length: MAX_POINTS }, (_, index) => ({ x: index, y: index }))
  assert.equal(insertPoint(full, 3, { x: 0, y: 0 }).length, MAX_POINTS)
})

test('the corners of an edge are kept in the graph, and taken out when there are none', () => {
  const graph = {
    nodes: [],
    edges: [
      { from: 'a', to: 'b' },
      { from: 'a', port: 'error', to: 'c', points: [{ x: 1, y: 2 }] },
    ],
  }
  const first = (edge) => edge.from === 'a' && edge.to === 'b'
  const routed = setEdgePoints(graph, first, [{ x: 10.4, y: 20 }])
  assert.deepEqual(routed.edges[0], { from: 'a', to: 'b', points: [{ x: 10, y: 20 }] })
  assert.equal(routed.edges[1], graph.edges[1])
  // The same corners again: the same graph, so nothing is saved for nothing.
  assert.equal(setEdgePoints(routed, first, [{ x: 10, y: 20 }]), routed)
  assert.equal(
    setEdgePoints(graph, () => false, [{ x: 1, y: 1 }]),
    graph,
  )
  const plain = setEdgePoints(graph, (edge) => edge.to === 'c', [])
  assert.deepEqual(plain.edges[1], { from: 'a', port: 'error', to: 'c' })
})
