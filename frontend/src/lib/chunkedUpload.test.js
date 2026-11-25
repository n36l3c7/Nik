import assert from 'node:assert/strict'
import { test } from 'node:test'
import { backoffMs, isRetryable, nextPart, overallSent, receivedOf, uploadFile, withFileTime } from './chunkedUpload.js'

test('the parts follow each other and the last one is the rest', () => {
  assert.deepEqual(nextPart(0, 10, 4), { offset: 0, length: 4 })
  assert.deepEqual(nextPart(4, 10, 4), { offset: 4, length: 4 })
  assert.deepEqual(nextPart(8, 10, 4), { offset: 8, length: 2 })
  assert.equal(nextPart(10, 10, 4), null)
  assert.equal(nextPart(0, 0, 4), null)
  assert.equal(nextPart(0, 10, 0), null)
})

test('the wait doubles and stops growing at its cap', () => {
  assert.deepEqual(
    [1, 2, 3, 4].map((n) => backoffMs(n, 100, 1000)),
    [100, 200, 400, 800],
  )
  assert.equal(backoffMs(10, 100, 1000), 1000)
})

test('a cut or a failing server is retried, a refusal and a cancel are not', () => {
  assert.equal(isRetryable(Object.assign(new Error('cut'), { interrupted: true })), true)
  assert.equal(isRetryable(Object.assign(new Error('x'), { status: 502 })), true)
  assert.equal(isRetryable(Object.assign(new Error('x'), { status: 429 })), true)
  assert.equal(isRetryable(Object.assign(new Error('x'), { status: 413 })), false)
  assert.equal(isRetryable(Object.assign(new Error('x'), { status: 400 })), false)
  assert.equal(isRetryable(Object.assign(new Error('x'), { name: 'AbortError' })), false)
})

test('the offset of the server is read only when it is a whole number', () => {
  assert.equal(receivedOf({ data: { received: 12 } }), 12)
  assert.equal(receivedOf({ data: { received: -1 } }), null)
  assert.equal(receivedOf({ data: { received: '12' } }), null)
  assert.equal(receivedOf(new Error('x')), null)
})

test('the bar counts what the server holds and the part that is going up', () => {
  assert.equal(overallSent(100, 20, 1000), 120)
  assert.equal(overallSent(990, 50, 1000), 1000)
  assert.equal(overallSent(0, -5, 1000), 0)
})

// A server that keeps what it is sent, and fails when it is told to.
function fakeServer(size, { chunk = 4, failures = [] } = {}) {
  const log = []
  let polls = 0
  const server = {
    held: 0,
    log,
    open: async () => ({ id: 'u1', chunk, received: 0 }),
    status: async () => {
      if (server.held < size) return { state: 'open', received: server.held }
      polls += 1
      return polls < 2 ? { state: 'finishing', received: size } : { state: 'complete', received: size, sourceId: 's1' }
    },
    putPart: async (_id, offset, blob, { onProgress } = {}) => {
      log.push(['put', offset, blob.size])
      const fail = failures.shift()
      if (fail) {
        if (fail.keep) server.held = offset + blob.size // the part arrived, the answer did not
        throw fail.error
      }
      if (offset !== server.held) throw Object.assign(new Error('x'), { status: 409, data: { received: server.held } })
      server.held += blob.size
      onProgress?.({ sent: blob.size, total: blob.size })
      return { received: server.held }
    },
    complete: async () => {
      log.push(['complete'])
      return { state: 'finishing' }
    },
    abort: async () => log.push(['abort']),
  }
  return server
}

const file = (size) => Object.assign(new Blob([new Uint8Array(size)]), { name: 'a.evtx' })
const fast = { sleep: async () => {}, pollMs: 0 }
test('the time of the file goes with every upload, and what the server made of an auto file comes back', async () => {
  const server = fakeServer(10)
  const opened = []
  const open = server.open
  server.open = async (body, options) => {
    opened.push(body.params)
    return open(body, options)
  }
  server.status = async () => ({
    state: 'complete',
    received: 10,
    sourceId: 's9',
    kind: 'eventlog',
    source: 'windows.evtx',
  })
  const dated = Object.assign(file(10), { lastModified: 1_700_000_000_123 })
  const done = await uploadFile(dated, { incidentId: 'i1', params: { kind: 'auto' }, api: server, ...fast })
  assert.deepEqual(opened, [{ kind: 'auto', fileTime: 1_700_000_000_123 }])
  assert.equal(done.kind, 'eventlog')
  assert.equal(done.source, 'windows.evtx')
  assert.deepEqual(withFileTime({ kind: 'x' }, {}), { kind: 'x' })
  assert.deepEqual(withFileTime({ kind: 'x' }, { lastModified: 0 }), { kind: 'x' })
})

const puts = (server) => server.log.filter((entry) => entry[0] === 'put')

test('a file goes up part by part and ends with its source', async () => {
  const server = fakeServer(10)
  const phases = []
  const done = await uploadFile(file(10), {
    incidentId: 'i1',
    params: { kind: 'eventlog' },
    api: server,
    onProgress: (p) => phases.push(p.phase),
    ...fast,
  })
  assert.deepEqual(done, { uploadId: 'u1', sourceId: 's1', kind: null, source: null, duplicate: false })
  assert.deepEqual(puts(server), [
    ['put', 0, 4],
    ['put', 4, 4],
    ['put', 8, 2],
  ])
  assert.equal(phases.includes('keeping'), true)
})

test('after a cut it goes on from where the server is, not from the start', async () => {
  const cut = Object.assign(new Error('cut'), { interrupted: true })
  // The second part arrived but its answer was lost: it must not be sent twice.
  const server = fakeServer(10, { failures: [undefined, { error: cut, keep: true }] })
  await uploadFile(file(10), { incidentId: 'i1', params: {}, api: server, ...fast })
  assert.deepEqual(
    puts(server).map((entry) => entry[1]),
    [0, 4, 8],
  )
})

test('retries are bounded, and a session that gave up is aborted', async () => {
  const cut = Object.assign(new Error('cut'), { interrupted: true })
  const server = fakeServer(10, { failures: [{ error: cut }, { error: cut }, { error: cut }, { error: cut }] })
  await assert.rejects(uploadFile(file(10), { incidentId: 'i1', params: {}, api: server, retries: 2, ...fast }), /cut/)
  assert.equal(puts(server).length, 3)
  assert.equal(server.log.at(-1)[0], 'abort')
})

test('a refusal is not retried', async () => {
  const refused = Object.assign(new Error('The file is larger'), { status: 413 })
  const server = fakeServer(10, { failures: [{ error: refused }] })
  await assert.rejects(uploadFile(file(10), { incidentId: 'i1', params: {}, api: server, ...fast }), /larger/)
  assert.equal(puts(server).length, 1)
})

test('cancelling stops the upload and gives the session up', async () => {
  const server = fakeServer(10)
  const controller = new AbortController()
  const put = server.putPart
  server.putPart = async (...args) => {
    const answer = await put(...args)
    controller.abort()
    return answer
  }
  await assert.rejects(
    uploadFile(file(10), { incidentId: 'i1', params: {}, api: server, signal: controller.signal, ...fast }),
    (error) => error.name === 'AbortError',
  )
  assert.equal(puts(server).length, 1)
  assert.equal(server.log.at(-1)[0], 'abort')
})
