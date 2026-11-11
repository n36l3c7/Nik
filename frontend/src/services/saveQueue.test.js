import assert from 'node:assert/strict'
import { test } from 'node:test'
import { applyMergePatch } from '../lib/mergePatch.js'
import { createSaveQueue } from './saveQueue.js'

const failure = (status, message = `HTTP ${status}`) => Object.assign(new Error(message), { status })
/** Let the queue's pending promises settle. */
const settle = async () => {
  for (let i = 0; i < 20; i += 1) await Promise.resolve()
}

/**
 * A queue wired to a fake server that holds one document and counts versions,
 * as the API does: a save is refused (412) unless it names the current version.
 */
function harness(initial, { failures = [] } = {}) {
  const server = { doc: initial, rev: 0 }
  const locals = { i1: initial }
  const sent = []
  const timers = []
  const queue = createSaveQueue({
    send: async (id, patch, etag) => {
      sent.push({ patch, etag })
      const error = failures.shift()
      if (error) throw error
      if (etag !== String(server.rev)) throw failure(412)
      server.doc = applyMergePatch(server.doc, patch)
      server.rev += 1
      return { etag: String(server.rev) }
    },
    load: async (id, etag) => (etag === String(server.rev) ? null : { doc: server.doc, etag: String(server.rev) }),
    getLocal: (id) => locals[id] ?? null,
    setLocal: (id, doc) => {
      locals[id] = doc
    },
    setTimer: (fn) => timers.push(fn),
    clearTimer: () => {},
  })
  queue.track('i1', initial, '0')
  const edit = (change) => {
    locals.i1 = { ...locals.i1, ...change }
    queue.touch('i1')
  }
  /** Somebody else saves a change straight to the server. */
  const elsewhere = (change) => {
    server.doc = { ...server.doc, ...change }
    server.rev += 1
  }
  return { queue, server, locals, sent, timers, edit, elsewhere }
}

test('an edit is sent as a merge patch that names the version it started from', async () => {
  const { queue, server, sent, edit } = harness({ host: 'a', os: 'windows' })
  edit({ host: 'b' })
  assert.equal(queue.status().pending, true)
  await settle()
  assert.deepEqual(sent, [{ patch: { host: 'b' }, etag: '0' }])
  assert.deepEqual(server.doc, { host: 'b', os: 'windows' })
  assert.deepEqual(queue.status(), { pending: false, error: null, unauthorized: false })
  assert.equal(queue.etagOf('i1'), '1')
})

test('edits of the same tick leave in one save', async () => {
  const { sent, edit } = harness({ flags: {} })
  edit({ flags: { x: { key: 'x', comments: [] } } })
  edit({ flags: { x: { key: 'x', comments: [{ id: 'c', text: 'why' }] } } })
  await settle()
  assert.equal(sent.length, 1)
})

test('an edit made while a save travels goes with the next one, in order', async () => {
  const { server, sent, edit } = harness({ host: 'a', os: 'windows' })
  edit({ host: 'b' })
  await Promise.resolve()
  await Promise.resolve()
  edit({ os: 'linux' })
  await settle()
  assert.deepEqual(
    sent.map((save) => save.patch),
    [{ host: 'b' }, { os: 'linux' }],
  )
  assert.deepEqual(server.doc, { host: 'b', os: 'linux' })
})

test('a failed save is reported, retried, and not forgotten', async () => {
  const { queue, server, timers, edit } = harness({ host: 'a', os: 'windows' }, { failures: [new Error('offline')] })
  edit({ host: 'b' })
  await settle()
  assert.deepEqual(queue.status(), { pending: true, error: 'offline', unauthorized: false })
  assert.equal(timers.length, 1)
  // Another edit meanwhile: the retry carries both.
  edit({ os: 'linux' })
  await settle()
  assert.deepEqual(server.doc, { host: 'b', os: 'linux' })
  assert.deepEqual(queue.status(), { pending: false, error: null, unauthorized: false })
})

test('the timer retries on its own', async () => {
  const { queue, server, timers, edit } = harness({ host: 'a' }, { failures: [failure(503)] })
  edit({ host: 'b' })
  await settle()
  assert.equal(queue.status().error, 'HTTP 503')
  timers[0]()
  await settle()
  assert.equal(server.doc.host, 'b')
  assert.equal(queue.status().error, null)
})

test('when somebody else saved meanwhile, both changes are kept', async () => {
  const first = { id: '1', text: 'first' }
  const { queue, server, locals, edit, elsewhere } = harness({ notes: [first], host: 'a' })
  elsewhere({ notes: [first, { id: 'a', text: 'from A' }], host: 'theirs' })
  edit({ notes: [first, { id: 'b', text: 'from B' }] })
  await settle()
  assert.deepEqual(
    server.doc.notes.map((note) => note.id),
    ['1', 'a', 'b'],
  )
  assert.equal(server.doc.host, 'theirs')
  // The local copy shows their changes too.
  assert.deepEqual(locals.i1, server.doc)
  assert.equal(queue.status().pending, false)
})

test('an expired session waits for retry(), without a timer', async () => {
  const { queue, server, timers, edit } = harness({ host: 'a' }, { failures: [failure(401, 'Not authenticated')] })
  edit({ host: 'b' })
  await settle()
  assert.deepEqual(queue.status(), { pending: true, error: 'Not authenticated', unauthorized: true })
  assert.equal(timers.length, 0)
  queue.retry()
  await settle()
  assert.equal(server.doc.host, 'b')
  assert.deepEqual(queue.status(), { pending: false, error: null, unauthorized: false })
})

test('a refused save (403) is reported and not hammered', async () => {
  const { queue, timers, edit } = harness({ host: 'a' }, { failures: [failure(403, 'Read-only key')] })
  edit({ host: 'b' })
  await settle()
  assert.equal(queue.status().error, 'Read-only key')
  assert.equal(timers.length, 0)
})

test('an incident deleted elsewhere is dropped from the queue', async () => {
  const { queue, edit } = harness({ host: 'a' }, { failures: [failure(404)] })
  edit({ host: 'b' })
  await settle()
  assert.equal(queue.isTracked('i1'), false)
  assert.deepEqual(queue.status(), { pending: false, error: null, unauthorized: false })
})

test('adopt: a change that must not be sent', async () => {
  const { queue, locals, sent } = harness({ host: 'a', view: 'chrome' })
  const prev = locals.i1
  locals.i1 = { ...prev, view: 'firefox' }
  queue.adopt('i1', prev, locals.i1)
  queue.touch('i1')
  await settle()
  assert.equal(sent.length, 0)
  assert.equal(queue.status().pending, false)
})

test('adopt keeps a pending edit pending', async () => {
  const { queue, server, locals, edit } = harness({ host: 'a', view: 'chrome' }, { failures: [new Error('offline')] })
  edit({ host: 'b' })
  await settle()
  const prev = locals.i1
  locals.i1 = { ...prev, view: 'firefox' }
  queue.adopt('i1', prev, locals.i1)
  queue.retry()
  await settle()
  assert.deepEqual(server.doc, { host: 'b', view: 'chrome' })
})

test('refresh merges a newer version into an untouched local copy', async () => {
  const { queue, locals, sent, elsewhere } = harness({ host: 'a' })
  elsewhere({ host: 'theirs' })
  queue.refresh('i1')
  await settle()
  assert.equal(locals.i1.host, 'theirs')
  assert.equal(sent.length, 0)
  assert.equal(queue.etagOf('i1'), '1')
})

test('an untracked incident is never sent; forget stops the saves', async () => {
  const { queue, sent, edit } = harness({ host: 'a' })
  queue.forget('i1')
  edit({ host: 'b' })
  queue.touch('other')
  await settle()
  assert.equal(sent.length, 0)
})
