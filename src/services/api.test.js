import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readBody } from './api.js'

/** A Response whose body arrives in the given chunks. */
function streamed(chunks, headers) {
  const encoder = new TextEncoder()
  const stream = new ReadableStream({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk))
      controller.close()
    },
  })
  return new Response(stream, { headers })
}

test('reports progress with the total from Content-Length', async () => {
  const seen = []
  const text = await readBody(streamed(['{"a":', '1}'], { 'Content-Length': '7' }), (p) => seen.push(p))
  assert.equal(text, '{"a":1}')
  assert.deepEqual(seen, [
    { received: 0, total: 7 },
    { received: 5, total: 7 },
    { received: 7, total: 7 },
  ])
})

test('leaves the total unknown for a compressed or unsized body', async () => {
  const totals = []
  await readBody(streamed(['ab'], { 'Content-Length': '2', 'Content-Encoding': 'gzip' }), (p) => totals.push(p.total))
  await readBody(streamed(['ab'], {}), (p) => totals.push(p.total))
  assert.ok(totals.every((t) => t === null))
})

test('decodes multi-byte characters split across chunks', async () => {
  const bytes = new TextEncoder().encode('Caffè')
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue(bytes.slice(0, 4))
      controller.enqueue(bytes.slice(4))
      controller.close()
    },
  })
  assert.equal(await readBody(new Response(stream), () => {}), 'Caffè')
})

test('without a progress callback it simply reads the text', async () => {
  assert.equal(await readBody(new Response('plain')), 'plain')
})
