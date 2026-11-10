import test from 'node:test'
import assert from 'node:assert/strict'
import {
  classifyFunction,
  functionAt,
  iocKey,
  linkStrings,
  nameOf,
  placeCapabilities,
  startHere,
  stringRanges,
} from './triage.js'

test('functions are classified by signature, Rust crate, symbol, runtime name or shape', () => {
  const inventory = new Set(['hyper', 'tokio'])
  const cases = [
    [{ name: 'sym.imp.KERNEL32.dll_Sleep', kind: 'import' }, 'import', null],
    [{ name: 'flirt.memcpy', kind: 'function' }, 'library', 'FLIRT'],
    [{ name: 'fcn.140012340', kind: 'function', crates: { tokio: 1, hyper: 4 } }, 'library', 'hyper'],
    [{ name: 'sym.core::fmt::write', kind: 'function' }, 'library', 'std'],
    [{ name: 'sym.tokio::runtime::spawn', kind: 'function' }, 'library', 'tokio'],
    [{ name: 'sym.MalVSTunnel::main', kind: 'function' }, 'unknown', null], // not in the inventory
    [{ name: 'entry0', kind: 'function' }, 'runtime', null],
    [{ name: 'sym.__scrt_common_main_seh', kind: 'function' }, 'runtime', null],
    [{ name: 'sym.__security_check_cookie', kind: 'function' }, 'runtime', null],
    [{ name: 'sym.runtime.mallocgc', kind: 'function' }, 'runtime', null],
    [{ name: 'sub.KERNEL32.dll_Sleep', kind: 'function' }, 'thunk', null],
    [{ name: 'case.0x140001234.3', kind: 'function' }, 'thunk', null],
    [{ name: 'main', kind: 'function' }, 'unknown', null],
    [{ name: 'fcn.00401000', kind: 'function' }, 'unknown', null],
  ]
  for (const [fn, origin, library] of cases) {
    const result = classifyFunction(fn, inventory)
    assert.equal(result.origin, origin, fn.name)
    assert.equal(result.library, library, fn.name)
  }
})

// A merged Rust string: a crate path, then a URL literal at byte 40 (file offsets from 0x400).
const STRINGS = [
  {
    offset: 0x400,
    encoding: 'ascii',
    value: 'C:\\x\\.cargo\\registry\\src\\i\\lib.rs.....http://185.220.101.47/gate.php',
  },
  { offset: 0x500, encoding: 'utf-16', value: 'Software\\Run' },
  { offset: 0x600, encoding: 'ascii', value: 'unrelated text' },
]
const URL_AT = 0x400 + STRINGS[0].value.indexOf('http')
const IOCS = [
  { kind: 'url', value: 'http://185.220.101.47/gate.php', offset: URL_AT },
  { kind: 'ip', value: '185.220.101.47', offset: URL_AT + 7 },
  { kind: 'registry', value: 'Software\\Run', offset: 0x500 },
  { kind: 'domain', value: 'never-used.top', offset: 0x900 },
]

test('string ranges count two bytes per UTF-16 character', () => {
  const ranges = stringRanges(STRINGS)
  assert.deepEqual(
    ranges.map((r) => [r.start, r.end]),
    [
      [0x400, 0x400 + STRINGS[0].value.length],
      [0x500, 0x500 + 24],
      [0x600, 0x600 + 14],
    ],
  )
})

test('functions are linked to the strings and indicators they reference', () => {
  const functions = [
    { addr: 0x10, strings: [URL_AT] }, // the &str starts at the URL inside the merged string
    { addr: 0x20, strings: [0x400] }, // the crate path, before the URL in the same string
    { addr: 0x30, strings: [0x500] }, // the UTF-16 registry key
    { addr: 0x35, strings: [0x500 + 4] }, // two characters into it: uses only the tail, not the indicator
    { addr: 0x40, strings: [0x600, 0x7777] }, // unrelated, and an offset outside the stored strings
    { addr: 0x50 },
  ]
  const { byFunction, byIoc } = linkStrings(functions, STRINGS, IOCS)
  assert.equal(byFunction.get(0x10)[0].text, 'http://185.220.101.47/gate.php')
  assert.deepEqual(
    byFunction.get(0x10)[0].iocs.map((i) => i.kind),
    ['url', 'ip'],
  )
  assert.equal(byFunction.get(0x35)[0].text, 'ftware\\Run') // 4 bytes = 2 UTF-16 characters in
  assert.deepEqual(byFunction.get(0x35)[0].iocs, [])
  assert.equal(byFunction.get(0x40)[1].text, null) // not among the stored strings
  assert.equal(byFunction.has(0x50), false)
  // The URL is used by both functions whose reference precedes it in the merged string
  // (rizin cannot tell where the first &str ends); the registry key by the third.
  assert.deepEqual(byIoc.get(iocKey(IOCS[0])), [0x10, 0x20])
  assert.deepEqual(byIoc.get(iocKey(IOCS[2])), [0x30])
  assert.equal(byIoc.has(iocKey(IOCS[3])), false)
})

test('start here ranks unrecognised functions by suspicious APIs, indicators and complexity', () => {
  const fns = [
    { addr: 1, kind: 'function', origin: 'unknown', direct: 'high', rules: ['process injection'], cc: 4 },
    { addr: 2, kind: 'function', origin: 'unknown', direct: null, reaches: 'high', rules: [], cc: 12 },
    { addr: 3, kind: 'function', origin: 'library', direct: 'high', rules: ['process injection'], cc: 30 },
    { addr: 4, kind: 'function', origin: 'unknown', direct: null, rules: [], cc: 2 },
    { addr: 5, kind: 'function', origin: 'unknown', direct: 'medium', rules: ['anti-analysis'], cc: 1 },
  ]
  const links = { byFunction: new Map([[4, [{ offset: 1, text: 'x', iocs: [IOCS[0], IOCS[1]] }]]]) }
  const ranked = startHere(fns, links)
  assert.deepEqual(
    ranked.map((r) => r.fn.addr),
    [1, 4, 5, 2], // library code and functions with nothing notable are left out
  )
  assert.match(ranked[1].reasons[0], /uses 2 indicators: http:\/\/185\.220\.101\.47\/gate\.php, 185\.220\.101\.47/)
  assert.deepEqual(ranked[3].reasons, ['reaches a suspicious API through its callees', 'complex (cyclomatic 12)'])
})

test('the analyst name wins over the rizin name', () => {
  assert.equal(nameOf({ addr: 1, name: 'fcn.00401000' }, { 1: { name: 'inject_payload' } }), 'inject_payload')
  assert.equal(nameOf({ addr: 1, name: 'sym.imp.KERNEL32.dll_Sleep' }, {}), 'Sleep')
})

test('capa addresses are credited to the rizin function containing them', () => {
  const functions = [
    { addr: 0x1000, size: 0x40, kind: 'function' },
    { addr: 0x1100, size: 0x10, kind: 'function' },
    { addr: 0x9000, size: 6, kind: 'import' },
  ]
  const sorted = functions.slice(0, 2)
  assert.equal(functionAt(sorted, 0x1000).addr, 0x1000)
  assert.equal(functionAt(sorted, 0x103f).addr, 0x1000)
  assert.equal(functionAt(sorted, 0x1040), null) // in the gap between functions
  assert.equal(functionAt(sorted, 0x0fff), null)

  const { byFunction, placed } = placeCapabilities(functions, [
    { name: 'send data', addresses: [0x1004, 0x1008, 0x1104] },
    { name: 'create process', addresses: [0x1010, 0x5000] },
    { name: 'compiled with rust', addresses: [] },
  ])
  assert.deepEqual(byFunction.get(0x1000), ['send data', 'create process'])
  assert.deepEqual(byFunction.get(0x1100), ['send data'])
  assert.deepEqual(placed.get('send data'), [0x1000, 0x1100])
  assert.deepEqual(placed.get('create process'), [0x1000]) // 0x5000 is in no function
  assert.deepEqual(placed.get('compiled with rust'), [])
})

test('capa capabilities raise an unrecognised function in start here', () => {
  const plain = { addr: 1, origin: 'unknown', kind: 'function', rules: [], cc: 2 }
  const capable = { ...plain, addr: 2, capabilities: ['send data on socket', 'resolve DNS', 'create mutex'] }
  const library = { ...capable, addr: 3, origin: 'library' }
  const ranked = startHere([plain, capable, library])
  assert.deepEqual(
    ranked.map((r) => r.fn.addr),
    [2],
  )
  assert.equal(ranked[0].reasons[0], 'capa: send data on socket, resolve DNS +1')
})
