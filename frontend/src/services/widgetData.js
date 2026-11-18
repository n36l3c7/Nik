import { api } from './api.js'

/*
 * What the widgets of a dashboard ask the server, kept orderly: six requests
 * in flight at most (a page of forty widgets does not open forty
 * connections), and an answer kept for as long as the dashboard goes without
 * refreshing, so that moving a widget or opening the page again asks nothing.
 */

const IN_FLIGHT = 6
const KEEP_MS = 60_000
const MAX_KEPT = 300

let running = 0
const waiting = []
const kept = new Map() // key → { at, promise }

function next() {
  while (running < IN_FLIGHT && waiting.length) {
    const job = waiting.shift()
    running += 1
    job().finally(() => {
      running -= 1
      next()
    })
  }
}

function queued(work) {
  return new Promise((resolve, reject) => {
    waiting.push(() => work().then(resolve, reject))
    next()
  })
}

/**
 * The answer to a request, asked once for everyone who wants it.
 *
 * @param {'POST' | 'GET'} method
 * @param {string} path
 * @param {object | undefined} body
 * @param {{ maxAge?: number, fresh?: boolean }} [options]  how old a kept answer may be (ms); fresh asks again
 */
export function ask(method, path, body, { maxAge = KEEP_MS, fresh = false } = {}) {
  const key = `${method} ${path} ${body ? JSON.stringify(body) : ''}`
  const held = kept.get(key)
  if (held && !fresh && Date.now() - held.at < maxAge) return held.promise
  const promise = queued(() => (method === 'GET' ? api.get(path) : api.post(path, body)))
  kept.set(key, { at: Date.now(), promise })
  // An answer that failed is not kept: the next look asks again.
  promise.catch(() => kept.get(key)?.promise === promise && kept.delete(key))
  if (kept.size > MAX_KEPT) kept.delete(kept.keys().next().value)
  return promise
}

/** Forget every answer (at sign-out: the next account must not see them). */
export function forgetAnswers() {
  kept.clear()
}
