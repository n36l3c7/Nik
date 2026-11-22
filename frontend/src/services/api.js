/*
 * ============================================================================
 * REST API CLIENT
 * ============================================================================
 *
 * Thin fetch wrapper around the FastAPI backend mounted under `/api` (same
 * origin, reverse-proxied by nginx). All requests send the session cookie
 * (`credentials: 'include'`) and speak JSON.
 *
 * On any non-2xx response the wrapper throws `Error(payload.detail)` so callers
 * can surface the server's message directly (the backend returns
 * `{ "detail": "<message>" }` on errors — FastAPI's default shape). The error
 * carries the HTTP `status` and, as `data`, the whole answer; a network
 * failure has neither.
 *
 * A 401 means the session ended while the app was open (except from the routes
 * of the sign-in itself, where it is an answer): the handler registered with
 * `onUnauthorized` (AuthContext) asks to sign in again.
 * A 403 that carries a `code` is a refusal the whole app must hear of (the
 * account has to set a second factor up, the administrator is not on a listed
 * network): the handler registered with `onRefused` gets it.
 *
 * A request sent while the person is doing nothing is the page's own (a list
 * that refreshes): it carries `X-Nik-Background`, and the server does not count
 * it as the session being used (lib/activity.js).
 *
 * 204 (No Content) resolves to `null`; 304 (Not Modified, after a conditional
 * request with `If-None-Match`) resolves to the `NOT_MODIFIED` sentinel.
 *
 * This is the ONLY file that knows how to talk to the server; every context
 * (auth, audit, settings, incidents) builds on top of it.
 */

import { CUT } from '../domain/transfers.js'
import { noteForeground, requestIsBackground } from '../lib/activity.js'

const BASE = '/api'
const BACKGROUND_HEADER = 'X-Nik-Background'

/** Returned instead of a payload when the server answers 304 Not Modified. */
export const NOT_MODIFIED = Symbol('NOT_MODIFIED')

let unauthorizedHandler = null

/** Register what happens when the server answers 401 to a signed-in client. */
export function onUnauthorized(handler) {
  unauthorizedHandler = handler
}

// A 401 from these is an answer, not a session that ended: a wrong password, nobody signed in yet,
// the state of a session whoever asks deals with.
const NOT_A_SESSION_END = /^\/auth\/(login|logout|me|bootstrap|session)(\/|\?|$)/

function reportUnauthorized(status, path) {
  if (status === 401 && !NOT_A_SESSION_END.test(path)) unauthorizedHandler?.()
}

let refusedHandler = null

/** Register what happens when the server refuses a signed-in client with a code (`{ detail, code }`). */
export function onRefused(handler) {
  refusedHandler = handler
}

function reportRefused(status, path, payload) {
  // The answers of a sign-in are shown where the sign-in is.
  if (status === 403 && typeof payload?.code === 'string' && !path.startsWith('/auth/login')) {
    refusedHandler?.(payload.code, typeof payload.detail === 'string' ? payload.detail : '')
  }
}

/** Mark a request as the page's own or the person's; returns the headers to send. */
function withActivity(headers, background) {
  if (background ?? requestIsBackground()) return { ...headers, [BACKGROUND_HEADER]: '1' }
  noteForeground()
  return headers
}

/**
 * Perform an API request.
 * @param {string} method  HTTP verb.
 * @param {string} path    Path relative to `/api` (e.g. '/incidents').
 * @param {*} [body]       Optional JSON-serializable request body.
 * @param {object} [opts]
 * @param {object} [opts.headers]      Extra request headers (e.g. If-None-Match).
 * @param {AbortSignal} [opts.signal]  Cancels the request when aborted.
 * @param {string} [opts.contentType]  Body media type (default application/json).
 * @param {(headers: Headers) => void} [opts.onHeaders]  Receives the response headers (ETag).
 * @param {boolean} [opts.background]  Says whose request it is instead of asking lib/activity.js:
 *        true for one the page sends by itself whatever the person is doing.
 * @param {(p: {received: number, total: number|null}) => void} [opts.onProgress]
 *        Download progress while the response body streams in; `total` is
 *        null when the size is unknown (no Content-Length, or compressed).
 * @returns {Promise<*>}   Parsed JSON payload, null for empty responses, or
 *                         NOT_MODIFIED for a 304.
 * @throws {Error} With the server's `detail` message on non-2xx; an aborted
 *                 request rejects with the fetch AbortError.
 */
async function request(
  method,
  path,
  body,
  { headers = {}, signal, contentType, onProgress, onHeaders, background } = {},
) {
  const options = {
    method,
    credentials: 'include', // send/receive the httpOnly session cookie
    headers: withActivity({ ...headers }, background),
    signal,
  }

  if (body instanceof Blob) {
    // A file sent as it is (the logo of a connector): its own type, its own bytes.
    options.headers['Content-Type'] = contentType ?? (body.type || 'application/octet-stream')
    options.body = body
  } else if (body !== undefined) {
    options.headers['Content-Type'] = contentType ?? 'application/json'
    options.body = JSON.stringify(body)
  }

  let response
  try {
    response = await fetch(`${BASE}${path}`, options)
  } catch (networkError) {
    if (networkError?.name === 'AbortError') throw networkError
    // fetch only rejects on network failure (server unreachable, DNS, CORS…).
    throw new Error(networkError?.message || 'Cannot reach the server.', { cause: networkError })
  }

  onHeaders?.(response.headers)
  // 204 No Content — nothing to parse; 304 — the caller's copy is current.
  if (response.status === 204) return null
  if (response.status === 304) return NOT_MODIFIED

  // Parse the body defensively: some error responses may be empty.
  let payload = null
  const text = await readBody(response, onProgress)
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }

  if (!response.ok) {
    const detail =
      (payload && typeof payload.detail === 'string' && payload.detail) || `Request failed (${response.status})`
    reportUnauthorized(response.status, path)
    reportRefused(response.status, path, payload)
    // `query`: for a query that cannot be read, where and why (position, code, suggestion).
    // `data`: whatever else the server said (the problems of a playbook, the result of a script's test).
    throw Object.assign(new Error(detail), {
      status: response.status,
      code: typeof payload?.code === 'string' ? payload.code : null,
      query: payload?.query ?? null,
      data: payload,
    })
  }

  return payload
}

/**
 * Read a response body as text, reporting progress chunk by chunk when asked.
 * A compressed body's Content-Length counts encoded bytes while the stream
 * yields decoded ones, so the total is only trusted for an unencoded body.
 */
export async function readBody(response, onProgress) {
  if (!onProgress || !response.body) return response.text()
  const encoding = (response.headers.get('Content-Encoding') || 'identity').toLowerCase()
  const length = Number(response.headers.get('Content-Length'))
  const total = encoding === 'identity' && length > 0 ? length : null
  const reader = response.body.getReader()
  const chunks = []
  let received = 0
  onProgress({ received, total })
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
    received += value.byteLength
    onProgress({ received, total })
  }
  const bytes = new Uint8Array(received)
  let offset = 0
  for (const chunk of chunks) {
    bytes.set(chunk, offset)
    offset += chunk.byteLength
  }
  return new TextDecoder('utf-8').decode(bytes)
}

/**
 * Upload one file as multipart form data (the raw bytes, no JSON wrapping).
 * Uses XMLHttpRequest because fetch cannot report upload progress.
 *
 * @param {string} path            API path, e.g. `/incidents/<id>/samples`
 * @param {File} file
 * @param {object} [opts]
 * @param {(p: {sent: number, total: number}) => void} [opts.onProgress]
 * @param {AbortSignal} [opts.signal]
 * @param {Record<string, string>} [opts.fields] other form fields sent with the file
 * @param {string} [opts.method] POST (default) or PUT
 * @returns {Promise<any>} The parsed JSON response.
 */
export function upload(path, file, { onProgress, signal, fields = {}, method = 'POST' } = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open(method, `${BASE}${path}`)
    xhr.withCredentials = true
    // A file is sent because somebody chose it.
    noteForeground()
    xhr.responseType = 'json'
    if (onProgress) {
      xhr.upload.onprogress = (event) => onProgress({ sent: event.loaded, total: event.total })
    }
    // The connection broke while the file went up: the server stopped or is restarting. Said so,
    // and marked, so that who shows the transfer can offer to send it again (lib/transfers.js).
    xhr.onerror = () => reject(Object.assign(new Error(CUT), { interrupted: true }))
    xhr.onabort = () => reject(Object.assign(new Error('Upload cancelled.'), { name: 'AbortError' }))
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response)
        return
      }
      reportUnauthorized(xhr.status, path)
      reportRefused(xhr.status, path, xhr.response)
      reject(Object.assign(new Error(xhr.response?.detail || `Request failed (${xhr.status})`), { status: xhr.status }))
    }
    signal?.addEventListener('abort', () => xhr.abort())
    const form = new FormData()
    for (const [key, value] of Object.entries(fields)) form.append(key, value)
    form.append('file', file, file.name)
    xhr.send(form)
  })
}

/** A request whose answer is a file: the response as a Blob. Errors carry the server's `detail`. */
async function blobOf(path, init) {
  let response
  try {
    response = await fetch(`${BASE}${path}`, { credentials: 'include', ...init })
  } catch (networkError) {
    if (networkError?.name === 'AbortError') throw networkError
    throw new Error(networkError?.message || 'Cannot reach the server.', { cause: networkError })
  }
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const payload = await response.json()
      if (typeof payload?.detail === 'string') detail = payload.detail
    } catch {
      /* not JSON */
    }
    reportUnauthorized(response.status, path)
    throw Object.assign(new Error(detail), { status: response.status })
  }
  return response.blob()
}

/**
 * POST a JSON body and return the response as a Blob (a generated file: the
 * incident report as HTML or PDF).
 */
export const postForBlob = (path, body, { signal } = {}) =>
  blobOf(path, {
    method: 'POST',
    headers: withActivity({ 'Content-Type': 'application/json' }),
    body: JSON.stringify(body ?? {}),
    signal,
  })

/** GET a file the server keeps (a pack) and return it as a Blob. */
export const getBlob = (path, { signal } = {}) => blobOf(path, { method: 'GET', headers: withActivity({}), signal })

/** Absolute URL of an API path, for links the browser follows itself (downloads). */
export function apiUrl(path) {
  return `${BASE}${path}`
}

export const api = {
  get: (path, opts) => request('GET', path, undefined, opts),
  post: (path, body, opts) => request('POST', path, body, opts),
  patch: (path, body, opts) => request('PATCH', path, body, opts),
  put: (path, body, opts) => request('PUT', path, body, opts),
  del: (path, opts) => request('DELETE', path, undefined, opts),
}
