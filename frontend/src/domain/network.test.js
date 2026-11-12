import test from 'node:test'
import assert from 'node:assert/strict'
import {
  fieldValue,
  filterRequests,
  findField,
  followTarget,
  formatBytesShort,
  formatMs,
  networkEvents,
  highlight,
  normalizeTree,
  payloadFields,
  requestName,
  requestStatus,
  timeSpan,
  waterfall,
} from './network.js'

const b64 = (text) => Buffer.from(text).toString('base64')

const ENTRIES = [
  {
    id: 1,
    method: 'GET',
    url: 'https://x.example/',
    resourceType: 'document',
    state: 'done',
    response: { status: 200 },
  },
  { id: 2, method: 'POST', url: 'https://x.example/api/login', resourceType: 'fetch', state: 'held' },
  { id: 3, method: 'GET', url: 'https://cdn.example/a.png', resourceType: 'image', state: 'blocked' },
  { id: 4, method: 'GET', url: 'wss://x.example/live', resourceType: 'websocket', state: 'done' },
  { id: 5, method: 'GET', url: 'https://x.example/m.wasm', resourceType: 'other', state: 'done' },
]

test('request filters like DevTools', () => {
  assert.deepEqual(
    filterRequests(ENTRIES, { type: 'fetch' }).map((e) => e.id),
    [2],
  )
  assert.deepEqual(
    filterRequests(ENTRIES, { type: 'other' }).map((e) => e.id),
    [5],
  )
  assert.deepEqual(
    filterRequests(ENTRIES, { refused: true }).map((e) => e.id),
    [2, 3],
  )
  assert.deepEqual(
    filterRequests(ENTRIES, { posts: true }).map((e) => e.id),
    [2],
  )
  assert.deepEqual(
    filterRequests(ENTRIES, { text: 'CDN' }).map((e) => e.id),
    [3],
  )
})

test('names, statuses and sizes', () => {
  assert.equal(requestName('https://x.example/api/login?x=1'), 'login?x=1')
  assert.equal(requestName('https://x.example/'), 'x.example')
  assert.deepEqual(requestStatus(ENTRIES[1]), { text: 'held', tone: 'high' })
  assert.deepEqual(requestStatus({ state: 'done', response: { status: 302 } }), { text: '302', tone: 'med' })
  assert.equal(formatBytesShort(2048), '2.0 kB')
  assert.equal(formatMs(1500), '1.50 s')
  assert.equal(formatMs(-1), '—')
})

test('waterfall bars sit within the session span', () => {
  const entries = [
    { startedAt: 1000, timing: { total: 100 } },
    { startedAt: 1500, timing: { total: 500 } },
  ]
  const { start, span } = timeSpan(entries)
  assert.deepEqual({ start, span }, { start: 1000, span: 1000 })
  assert.deepEqual(waterfall(entries[1], start, span), { offset: 50, width: 50 })
})

test('form and JSON payloads become fields', () => {
  assert.deepEqual(payloadFields(b64('email=mario%40contoso.it&pass=W1'), 'application/x-www-form-urlencoded'), [
    ['email', 'mario@contoso.it'],
    ['pass', 'W1'],
  ])
  assert.deepEqual(payloadFields(b64('{"user":"m","n":2}'), 'application/json'), [
    ['user', 'm'],
    ['n', '2'],
  ])
  assert.equal(payloadFields(b64('\u0000binary'), 'application/octet-stream'), null)
})

test('the protocol tree, its bytes and what to follow', () => {
  const tree = normalizeTree([
    { l: 'Frame 8', h: [0, 54], fn: 'frame', n: [{ l: 'Arrival', f: 'frame.time', fn: 'frame.time' }] },
    {
      l: 'Transmission Control Protocol',
      h: [34, 20],
      fn: 'tcp',
      n: [{ l: 'Stream index: 3', f: 'tcp.stream == 3', fn: 'tcp.stream' }],
    },
    { l: 'Hypertext Transfer Protocol', fn: 'http', n: [] },
  ])
  assert.equal(tree[1].children[0].path, '1.0')
  assert.deepEqual(highlight(tree[1]), { start: 34, end: 54 })
  assert.equal(fieldValue(findField(tree, 'tcp.stream')), '3')
  assert.deepEqual(followTarget(tree), { kind: 'HTTP', filter: 'tcp.stream eq 3' })
  assert.equal(followTarget(normalizeTree([{ l: 'Frame', fn: 'frame' }])), null)
})

test('captures, held submissions and beacons are timeline events', () => {
  const engine = { analyze: () => ({ keywordMatches: [], isAnomalousTime: false, severity: null, isFlagged: false }) }
  const events = networkEvents(
    [
      {
        id: 'c1',
        kind: 'browser',
        label: 'attachment login.html',
        fileName: 'isolated-browser.pcapng',
        first: 1000,
        packets: 21,
        held: [{ id: 2, method: 'POST', url: 'https://x.example/p', time: 2000 }],
        beacons: [{ destination: '198.51.100.7', port: '443', count: 6, interval: 30, first: 3 }],
      },
    ],
    engine,
  )
  assert.deepEqual(
    events.map((e) => [e.id, e.time, e.soc.severity]),
    [
      ['capture:c1', 1000, null],
      ['held:c1:2', 2000, 'high'],
      ['beacon:c1:198.51.100.7:443', 3000, 'medium'],
    ],
  )
  assert.equal(events[0].label, 'attachment login.html')
})

test('column sorting: numbers by value, addresses in natural order, three-state headers', async () => {
  const { compareCells, nextSort, requestSortValue, sortRows } = await import('./network.js')
  assert.deepEqual(nextSort(null, 5), { key: 5, dir: 'asc' })
  assert.deepEqual(nextSort({ key: 5, dir: 'asc' }, 5), { key: 5, dir: 'desc' })
  assert.equal(nextSort({ key: 5, dir: 'desc' }, 5), null)
  assert.deepEqual(nextSort({ key: 5, dir: 'desc' }, 2), { key: 2, dir: 'asc' })
  assert.ok(compareCells('9', '10') < 0) // lengths, packet numbers
  assert.ok(compareCells('10.0.0.2', '10.0.0.10') < 0)
  assert.ok(compareCells('TCP', 'dns') > 0)

  const packets = [
    { c: ['1', '0.5', '10.0.0.10', 'TLS', '1514'] },
    { c: ['2', '0.1', '10.0.0.2', 'DNS', '74'] },
    { c: ['3', '', '10.0.0.2', 'DNS', '90'] },
  ]
  const cell = (row, column) => row.c[column]
  assert.equal(sortRows(packets, null, cell), packets)
  assert.deepEqual(
    sortRows(packets, { key: 4, dir: 'asc' }, cell).map((r) => r.c[0]),
    ['2', '3', '1'],
  )
  assert.deepEqual(
    sortRows(packets, { key: 4, dir: 'desc' }, cell).map((r) => r.c[0]),
    ['1', '3', '2'],
  )
  // Equal values keep the capture's order; empty values stay last either way.
  assert.deepEqual(
    sortRows(packets, { key: 3, dir: 'asc' }, cell).map((r) => r.c[0]),
    ['2', '3', '1'],
  )
  assert.deepEqual(
    sortRows(packets, { key: 1, dir: 'desc' }, cell).map((r) => r.c[0]),
    ['1', '2', '3'],
  )

  const entry = { url: 'https://x.example/a/login.php?x=1', method: 'POST', state: 'held', resourceType: 'document' }
  assert.equal(requestSortValue(entry, 'status'), 'held')
  assert.equal(requestSortValue({ ...entry, response: { status: 302, bodySize: 12 } }, 'size'), 12)
})
