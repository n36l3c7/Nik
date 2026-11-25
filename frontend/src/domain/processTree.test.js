import test from 'node:test'
import assert from 'node:assert/strict'
import {
  ROOTS,
  apiFilters,
  breadcrumb,
  childrenText,
  commandPreview,
  createCache,
  flatten,
  freshNode,
  hostLine,
  isFiltered,
  nameOf,
  navigate,
  ranText,
  seedFromTree,
  withPage,
} from './processTree.js'

const proc = (id, extra = {}) => ({ id, name: `p${id}.exe`, children: 0, parentId: null, parent: null, ...extra })

const loaded = (items, next = null) => ({ ...freshNode(), items, next, loaded: true })

test('the rows are the roots, and the children of the nodes that are open', () => {
  const state = {
    nodes: {
      [ROOTS]: loaded([proc(1, { children: 2 }), proc(2)]),
      1: loaded([proc(3, { parentId: 1 }), proc(4, { parentId: 1 })]),
    },
    open: new Set([1]),
  }
  const rows = flatten(state)
  assert.deepEqual(
    rows.map((row) => [row.process.id, row.depth, row.open, row.expandable]),
    [
      [1, 0, true, true],
      [3, 1, false, false],
      [4, 1, false, false],
      [2, 0, false, false],
    ],
  )
  // Closed: the children are loaded but not drawn.
  assert.equal(flatten({ ...state, open: new Set() }).length, 2)
})

test('a ghost parent is a greyed row above its child, which moves one level in', () => {
  const ghost = { image: 'C:\\Windows\\explorer.exe', commandLine: '' }
  const state = { nodes: { [ROOTS]: loaded([proc(7, { parent: ghost, children: 1 })]) }, open: new Set() }
  const rows = flatten(state)
  assert.deepEqual(
    rows.map((row) => [row.kind, row.depth]),
    [
      ['ghost', 0],
      ['process', 1],
    ],
  )
  assert.equal(rows[0].ghost.image, 'C:\\Windows\\explorer.exe')
})

test('a list with more to load ends with a "more" row, and one being read with nothing yet with a wait row', () => {
  const rows = flatten({ nodes: { [ROOTS]: loaded([proc(1)], 'cursor') }, open: new Set() })
  assert.deepEqual(
    rows.map((row) => row.kind),
    ['process', 'more'],
  )
  assert.equal(rows[1].node, ROOTS)
  const waiting = flatten({ nodes: { [ROOTS]: { ...freshNode(), loading: true } }, open: new Set() })
  assert.deepEqual(
    waiting.map((row) => row.kind),
    ['wait'],
  )
  const failed = flatten({ nodes: { [ROOTS]: { ...freshNode(), error: 'down' } }, open: new Set() })
  assert.equal(failed[0].kind, 'error')
  assert.equal(failed[0].message, 'down')
})

test('a page is added to the processes held, each process once', () => {
  const first = withPage(freshNode(), { processes: [proc(1), proc(2)], next: 'c1' })
  assert.equal(first.next, 'c1')
  const second = withPage(first, { processes: [proc(2), proc(3)], next: null })
  assert.deepEqual(
    second.items.map((item) => item.id),
    [1, 2, 3],
  )
  assert.equal(second.next, null)
  assert.equal(second.loaded, true)
})

test('the keys move through the rows and open and close nodes', () => {
  const state = {
    nodes: { [ROOTS]: loaded([proc(1, { children: 1 }), proc(2)]), 1: loaded([proc(3, { parentId: 1 })]) },
    open: new Set(),
  }
  let rows = flatten(state)
  assert.deepEqual(navigate(rows, 0, 'ArrowDown'), { index: 1, action: null })
  assert.deepEqual(navigate(rows, 1, 'ArrowDown'), { index: 1, action: null })
  assert.deepEqual(navigate(rows, 0, 'ArrowUp'), { index: 0, action: null })
  assert.deepEqual(navigate(rows, 1, 'End'), { index: 1, action: null })
  assert.deepEqual(navigate(rows, 1, 'Home'), { index: 0, action: null })
  // Right opens a closed node.
  assert.deepEqual(navigate(rows, 0, 'ArrowRight'), { index: 0, action: 'open' })
  // A leaf stays where it is.
  assert.deepEqual(navigate(rows, 1, 'ArrowRight'), { index: 1, action: null })
  rows = flatten({ ...state, open: new Set([1]) })
  // Open: Right goes to the first child, Left closes, Left on a child goes to its parent.
  assert.deepEqual(navigate(rows, 0, 'ArrowRight'), { index: 1, action: null })
  assert.deepEqual(navigate(rows, 0, 'ArrowLeft'), { index: 0, action: 'close' })
  assert.deepEqual(navigate(rows, 1, 'ArrowLeft'), { index: 0, action: null })
  assert.deepEqual(navigate(rows, 0, 'x'), { index: 0, action: null })
  assert.deepEqual(navigate([], 0, 'ArrowDown'), { index: 0, action: null })
})

test('the name of a process is its file name, whatever the separator', () => {
  assert.equal(nameOf({ name: 'cmd.exe', image: 'C:\\Windows\\cmd.exe' }), 'cmd.exe')
  assert.equal(nameOf({ image: 'C:\\Windows\\System32\\cmd.exe' }), 'cmd.exe')
  assert.equal(nameOf({ image: '/usr/bin/bash' }), 'bash')
  assert.equal(nameOf({}), '(unnamed)')
})

test('a command line is one line and cut with an ellipsis', () => {
  assert.equal(commandPreview('a  b\n c'), 'a b c')
  assert.equal(commandPreview('x'.repeat(10), 5), 'xxxx…')
  assert.equal(commandPreview(undefined), '')
})

test('how long a process ran is said in the two nearest units, and nothing when the end is not known', () => {
  assert.equal(ranText(1000, 1850), '850 ms')
  assert.equal(ranText(0, 42_000), '42 s')
  assert.equal(ranText(0, 243_000), '4 min 3 s')
  assert.equal(ranText(0, 300_000), '5 min')
  assert.equal(ranText(0, 7_500_000), '2 h 5 min')
  assert.equal(ranText(0, 3 * 86_400_000 + 3_600_000), '3 d 1 h')
  assert.equal(ranText(5, null), '')
  assert.equal(ranText(null, 5), '')
  assert.equal(ranText(10, 5), '')
})

test('the number of children and the breadcrumb of the ancestors', () => {
  assert.equal(childrenText(0), '')
  assert.equal(childrenText(1), '1 child')
  assert.equal(childrenText(1204), '1,204 children')
  assert.deepEqual(breadcrumb([{ name: 'winword.exe' }, { name: 'cmd.exe' }]), ['winword.exe', 'cmd.exe'])
  assert.deepEqual(breadcrumb([{ name: 'cmd.exe' }], { image: 'C:\\x\\explorer.exe' }), ['explorer.exe', 'cmd.exe'])
  assert.deepEqual(breadcrumb(), [])
})

test('a filter other than the host asks for the flat list, and only the filters that say something are sent', () => {
  assert.equal(isFiltered({}), false)
  assert.equal(isFiltered({ q: '' }), false)
  assert.equal(isFiltered({ q: 'powershell' }), true)
  assert.equal(isFiltered({ level: '3' }), true)
  assert.deepEqual(apiFilters('ws-01', { q: 'x', user: '', level: '4', other: 1 }), {
    host: 'ws-01',
    q: 'x',
    level: '4',
  })
  assert.deepEqual(apiFilters('ws-01', {}, { roots: true }), { host: 'ws-01', roots: true })
  assert.equal(hostLine({ host: 'ws-01', processes: 1204 }), 'ws-01 · 1,204 processes')
  assert.equal(hostLine({ host: '', processes: 1 }), '(no host name) · 1 process')
})

test('the cache forgets the oldest entry', () => {
  const cache = createCache(2)
  cache.set('a', 1)
  cache.set('b', 2)
  cache.set('a', 3) // touched: b is now the oldest
  cache.set('c', 4)
  assert.equal(cache.has('b'), false)
  assert.equal(cache.get('a'), 3)
  assert.equal(cache.size, 2)
})

test('"Show in the tree" seeds a chain from the root to the process, every ancestor open', () => {
  const answer = {
    ancestors: [proc(1, { children: 2 }), proc(2, { parentId: 1, children: 5 })],
    node: proc(3, { parentId: 2 }),
  }
  const state = seedFromTree(answer)
  assert.deepEqual([...state.open], [1, 2])
  const rows = flatten(state)
  assert.deepEqual(
    rows.map((row) => `${row.kind}:${row.process?.id ?? row.node}:${row.depth}`),
    ['process:1:0', 'process:2:1', 'process:3:2', 'more:2:2', 'more:1:1', 'more:roots:0'],
  )
  assert.equal(rows.at(-1).partial, true)
})
