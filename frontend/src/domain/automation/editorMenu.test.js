import assert from 'node:assert/strict'
import { test } from 'node:test'
import { SHORTCUTS, editorMenu } from './editorMenu.js'
import { MAX_NODES, disconnectNodes, linesOf, normalise, pasteAt, copyOf } from './graph.js'

const node = (id, kind, position = { x: 0, y: 0 }) => ({ id, kind, name: id, position, config: {} })

/* start → check ─yes→ note → stop ; check ─no→ stop */
const GRAPH = {
  nodes: [
    node('start', 'trigger'),
    node('check', 'condition', { x: 0, y: 100 }),
    node('note', 'action', { x: -100, y: 200 }),
    node('stop', 'end', { x: 0, y: 300 }),
    node('alone', 'action', { x: 400, y: 0 }),
  ],
  edges: [
    { from: 'start', to: 'check' },
    { from: 'check', port: 'yes', to: 'note' },
    { from: 'check', port: 'no', to: 'stop' },
    { from: 'note', to: 'stop' },
  ],
}

const ids = (menu) => menu.items.map((item) => (item === 'separator' ? '-' : item.id))
const item = (menu, id) => menu.items.find((entry) => entry !== 'separator' && entry.id === id)
const off = (menu) =>
  Object.fromEntries(
    menu.items.filter((entry) => entry !== 'separator' && entry.disabled).map((entry) => [entry.id, entry.title]),
  )

test('a node offers what is done to a node, in the order every menu of Nik has', () => {
  const menu = editorMenu({ kind: 'node', id: 'note' }, { graph: GRAPH, canDebug: true })
  assert.equal(menu.title, 'note')
  assert.deepEqual(ids(menu), ['open', 'debug', '-', 'duplicate', 'copy', 'cut', '-', 'disconnect', '-', 'remove'])
  assert.deepEqual(off(menu), {})
  // Each entry shows the key that does the same, where there is one.
  assert.deepEqual(
    menu.items.filter((entry) => entry !== 'separator').map((entry) => entry.hint ?? ''),
    ['enter', '', 'ctrl d', 'ctrl c', 'ctrl x', '', 'del'],
  )
  assert.equal(SHORTCUTS.paste, 'ctrl v')
  // Without the right to debug there is no such entry; a node with no line says so.
  const alone = editorMenu({ kind: 'node', id: 'alone' }, { graph: GRAPH })
  assert.ok(!ids(alone).includes('debug'))
  assert.deepEqual(off(alone), { disconnect: 'No line arrives at it or leaves it' })
})

test('the trigger is opened and disconnected, and never copied or deleted', () => {
  const menu = editorMenu({ kind: 'node', id: 'start' }, { graph: GRAPH, canDebug: true })
  assert.deepEqual(Object.keys(off(menu)).sort(), ['copy', 'cut', 'debug', 'duplicate', 'remove'])
  assert.equal(item(menu, 'remove').title, 'A playbook keeps its trigger')
  assert.ok(!item(menu, 'disconnect').disabled)
})

test('several selected nodes get the entries that make sense for all of them', () => {
  const menu = editorMenu({ kind: 'selection', ids: ['start', 'note', 'stop', 'gone'] }, { graph: GRAPH })
  assert.equal(menu.title, '3 nodes')
  assert.deepEqual(ids(menu), ['duplicate', 'copy', 'cut', '-', 'disconnect', '-', 'remove'])
  assert.equal(item(menu, 'disconnect').label, 'Disconnect their lines')
  // The trigger among them is left out of what is copied and deleted: the others are not held back.
  assert.deepEqual(off(menu), {})
})

test('a line offers its deletion, and says what it joins', () => {
  const menu = editorMenu({ kind: 'edge', from: 'check', port: 'yes', to: 'note' }, { graph: GRAPH })
  assert.equal(menu.title, 'check → note · yes')
  assert.deepEqual(menu.items, [{ id: 'removeLine', label: 'Delete this connection', hint: 'del' }])
  assert.equal(
    editorMenu({ kind: 'edge', from: 'note', port: 'out', to: 'stop' }, { graph: GRAPH }).title,
    'note → stop',
  )
})

test('the empty canvas offers what is added, pasted, selected, and undone', () => {
  const menu = editorMenu({ kind: 'pane' }, { graph: GRAPH, copied: 2, canUndo: true })
  assert.deepEqual(ids(menu), ['add', 'paste', '-', 'selectAll', 'fit', 'tidy', '-', 'undo', 'redo'])
  assert.deepEqual(off(menu), { redo: 'Nothing to redo' })
  assert.deepEqual(off(editorMenu({ kind: 'pane' }, { graph: GRAPH })), {
    paste: 'Nothing was copied yet',
    undo: 'Nothing to undo',
    redo: 'Nothing to redo',
  })
  // A playbook that is full takes no more.
  const full = { nodes: Array.from({ length: MAX_NODES }, (_, index) => node(`n${index}`, 'action')), edges: [] }
  const said = off(editorMenu({ kind: 'pane' }, { graph: full, copied: 1, canUndo: true, canRedo: true }))
  assert.deepEqual(said, { add: `A playbook has at most ${MAX_NODES} nodes`, paste: said.add })
  assert.equal(item(editorMenu({ kind: 'node', id: 'n1' }, { graph: full }), 'duplicate').title, said.add)
})

test('where nothing can be changed the menu says why, and keeps what changes nothing', () => {
  const why = 'This is the branch of anna: only they, or an admin, change it'
  const state = { graph: GRAPH, readOnly: why, copied: 1, canUndo: true, canRedo: true, canDebug: true }
  const onNode = editorMenu({ kind: 'node', id: 'note' }, state)
  assert.equal(onNode.title, 'note · read-only')
  assert.deepEqual(off(onNode), { duplicate: why, cut: why, disconnect: why, remove: why })
  assert.deepEqual(off(editorMenu({ kind: 'edge', from: 'note', port: 'out', to: 'stop' }, state)), { removeLine: why })
  assert.deepEqual(off(editorMenu({ kind: 'pane' }, state)), { add: why, paste: why, tidy: why, undo: why, redo: why })
})

test('lines are counted and taken away for the nodes chosen', () => {
  assert.equal(linesOf(GRAPH, ['note']), 2)
  assert.equal(linesOf(GRAPH, ['note', 'stop']), 3)
  assert.equal(linesOf(GRAPH, ['alone']), 0)
  assert.deepEqual(disconnectNodes(GRAPH, ['note']).edges, [
    { from: 'start', to: 'check' },
    { from: 'check', port: 'no', to: 'stop' },
  ])
  assert.equal(disconnectNodes(GRAPH, ['alone']), GRAPH)
  assert.equal(disconnectNodes(GRAPH, ['note']).nodes, GRAPH.nodes)
})

test('what was copied is pasted where the click was, its nodes placed as they were', () => {
  const copied = copyOf(GRAPH, ['check', 'note'])
  const { graph, ids: pasted } = pasteAt(GRAPH, copied, { x: 500.4, y: 40 })
  assert.deepEqual(pasted, ['check_2', 'note_2'])
  // The highest node lands on the click; the other keeps its place beside it.
  assert.deepEqual(graph.nodes.at(-2).position, { x: 500, y: 40 })
  assert.deepEqual(graph.nodes.at(-1).position, { x: 400, y: 140 })
  assert.deepEqual(graph.edges.at(-1), { from: 'check_2', port: 'yes', to: 'note_2' })
  assert.deepEqual(pasteAt(GRAPH, { nodes: [], edges: [] }, { x: 0, y: 0 }), { graph: GRAPH, ids: [] })
})

test('the corners a stored line holds are left behind when the graph is read', () => {
  const stored = {
    nodes: GRAPH.nodes,
    edges: [
      { from: 'start', to: 'check', points: [{ x: 10, y: 20 }] },
      { from: 'check', port: 'yes', to: 'note', points: [] },
      { from: 'check', port: 'no', to: 'stop' },
    ],
  }
  assert.deepEqual(normalise(stored).edges, [
    { from: 'start', to: 'check' },
    { from: 'check', port: 'yes', to: 'note' },
    { from: 'check', port: 'no', to: 'stop' },
  ])
})
