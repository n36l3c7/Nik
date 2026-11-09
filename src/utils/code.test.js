import test from 'node:test'
import assert from 'node:assert/strict'
import { analyzeFunctions, callGraph, cfgGraph, decompiledLines, displayName, hex, nodeSize } from './code.js'
import { createSocEngine } from './soc.js'
import { DEFAULT_MALWARE_KEYWORDS } from '../config/detectionRules.js'

const engine = createSocEngine({ keywords: [], malwareKeywords: DEFAULT_MALWARE_KEYWORDS })

// entry0 → main → inject → VirtualAllocEx (import); main → log (benign); inject ↔ retry (cycle)
const FUNCTIONS = [
  { addr: 0x1000, name: 'entry0', kind: 'function', calls: [{ addr: 0x1100, name: 'main' }] },
  {
    addr: 0x1100,
    name: 'main',
    kind: 'function',
    calls: [
      { addr: 0x1200, name: 'fcn.inject' },
      { addr: 0x1300, name: 'fcn.log' },
    ],
  },
  {
    addr: 0x1200,
    name: 'fcn.inject',
    kind: 'function',
    calls: [
      { addr: 0x9000, name: 'sym.imp.KERNEL32.dll_VirtualAllocEx' },
      { addr: 0x1250, name: 'fcn.retry' },
    ],
  },
  { addr: 0x1250, name: 'fcn.retry', kind: 'function', calls: [{ addr: 0x1200, name: 'fcn.inject' }] },
  { addr: 0x1300, name: 'fcn.log', kind: 'function', calls: [{ addr: null, name: 'dword [0x403010]' }] },
  { addr: 0x9000, name: 'sym.imp.KERNEL32.dll_VirtualAllocEx', kind: 'import', calls: [] },
]

test('names and addresses are readable', () => {
  assert.equal(displayName('sym.imp.KERNEL32.dll_VirtualAllocEx'), 'VirtualAllocEx')
  assert.equal(displayName('sym.imp.puts'), 'puts')
  assert.equal(displayName('sym.imp.libc.so.6_malloc'), 'malloc')
  assert.equal(displayName('reloc.__libc_start_main'), '__libc_start_main')
  assert.equal(displayName('fcn.00401000'), 'fcn.00401000')
  assert.equal(hex(0x401a30), '0x401a30')
  assert.equal(hex(null), '—')
})

test('severity propagates from the API to every function that reaches it, cycles included', () => {
  const fns = Object.fromEntries(analyzeFunctions(FUNCTIONS, engine).map((f) => [f.name, f]))
  assert.equal(fns['fcn.inject'].direct, 'high')
  assert.deepEqual(fns['fcn.inject'].rules, ['process injection'])
  assert.equal(fns['fcn.retry'].direct, null)
  assert.equal(fns['fcn.retry'].reaches, 'high') // through the cycle back to inject
  assert.equal(fns.main.reaches, 'high')
  assert.equal(fns.entry0.reaches, 'high')
  assert.equal(fns['fcn.log'].reaches, null)
  assert.equal(fns['sym.imp.KERNEL32.dll_VirtualAllocEx'].display, 'VirtualAllocEx')
})

test('the call graph is cut at the requested depth and marks hot edges', () => {
  const fns = analyzeFunctions(FUNCTIONS, engine)
  const graph = callGraph(fns, 0x1100, engine, { depth: 2 })
  assert.deepEqual(
    graph.nodes.map((n) => n.label),
    ['main', 'fcn.inject', 'fcn.log', 'VirtualAllocEx', 'fcn.retry', 'dword [0x403010]'],
  )
  assert.equal(graph.nodes[0].root, true)
  const hot = graph.edges.filter((e) => e.hot).map((e) => e.id)
  assert.deepEqual(hot, ['4352->4608', '4608->36864', '4608->4688'])
  assert.equal(callGraph(fns, 0x1100, engine, { depth: 1 }).nodes.length, 3)
  assert.equal(callGraph(fns, 0x1100, engine, { depth: 2, limit: 2 }).truncated, true)
  assert.deepEqual(callGraph(fns, 0xdead, engine).nodes, [])
})

test('the CFG has typed edges, loops and hot blocks', () => {
  const cfg = {
    blocks: [
      {
        addr: 0x10,
        jump: 0x30,
        fail: 0x20,
        ops: [
          { text: 'test eax, eax', type: 'acmp' },
          { text: 'jz 0x30', type: 'cjmp' },
        ],
      },
      {
        addr: 0x20,
        jump: 0x10,
        fail: null,
        ops: [
          { text: 'call sym.imp.KERNEL32.dll_CreateRemoteThread', type: 'call' },
          { text: 'jmp 0x10', type: 'jmp' },
        ],
      },
      { addr: 0x30, jump: null, fail: null, ops: [{ text: 'ret', type: 'ret' }] },
    ],
  }
  const graph = cfgGraph(cfg, engine)
  assert.deepEqual(
    graph.edges.map((e) => [e.from, e.to, e.kind, e.back]),
    [
      ['16', '48', 't', false],
      ['16', '32', 'f', false],
      ['32', '16', 'j', true],
    ],
  )
  assert.deepEqual(
    graph.nodes.map((n) => n.hot),
    [false, true, false],
  )
})

test('pseudo-C becomes lines of styled segments with call targets', () => {
  const code = 'void entry0(void)\n{\n    fcn.0040100f();\n    return;\n}'
  const spans = [
    [0, 4, 't'],
    [5, 11, 'f', 0x401000],
    [12, 16, 'k'],
    [24, 36, 'f', 0x40100f],
    [44, 50, 'k'],
  ]
  const lines = decompiledLines(code, spans)
  assert.equal(lines.length, 5)
  assert.deepEqual(lines[0], [
    { text: 'void', kind: 't', target: null },
    { text: ' ', kind: null, target: null },
    { text: 'entry0', kind: 'f', target: 0x401000 },
    { text: '(', kind: null, target: null },
    { text: 'void', kind: 'k', target: null },
    { text: ')', kind: null, target: null },
  ])
  assert.deepEqual(lines[2][1], { text: 'fcn.0040100f', kind: 'f', target: 0x40100f })
  assert.equal(lines.map((segments) => segments.map((s) => s.text).join('')).join('\n'), code)
  // A span over a line break is split; broken or overlapping spans are ignored.
  assert.deepEqual(decompiledLines('a\nb', [[0, 3, 'c']]), [
    [{ text: 'a', kind: 'c', target: null }],
    [{ text: 'b', kind: 'c', target: null }],
  ])
  assert.deepEqual(
    decompiledLines('abc', [
      [0, 2, 'k'],
      [1, 3, 't'],
      [2, 9, 'n'],
    ]),
    [
      [
        { text: 'ab', kind: 'k', target: null },
        { text: 'c', kind: null, target: null },
      ],
    ],
  )
})

test('node size grows with the longest line and the line count', () => {
  const small = nodeSize(['ret'])
  const big = nodeSize(['call sym.imp.KERNEL32.dll_VirtualAllocEx', 'ret'])
  assert.ok(big.width > small.width && big.height > small.height)
})

test('cfgGraph shows the analyst names of called functions', () => {
  const cfg = {
    blocks: [
      {
        addr: 0x10,
        jump: null,
        fail: null,
        ops: [
          { text: 'call fcn.00401020', type: 'call' },
          { text: 'mov eax, dword [fcn.00401020x]', type: 'mov' },
        ],
      },
    ],
  }
  const graph = cfgGraph(cfg, engine, new Map([['fcn.00401020', 'send_beacon']]))
  assert.deepEqual(
    graph.nodes[0].lines.map((line) => line.text),
    ['call send_beacon', 'mov eax, dword [fcn.00401020x]'],
  )
})
