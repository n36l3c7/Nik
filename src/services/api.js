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
 * `{ "detail": "<message>" }` on errors — FastAPI's default shape).
 *
 * 204 (No Content) resolves to `null`; 304 (Not Modified, after a conditional
 * request with `If-None-Match`) resolves to the `NOT_MODIFIED` sentinel.
 *
 * This is the ONLY file that knows how to talk to the server; every context
 * (auth, audit, settings, incidents) builds on top of it.
 */

const BASE = '/api'

/** Returned instead of a payload when the server answers 304 Not Modified. */
export const NOT_MODIFIED = Symbol('NOT_MODIFIED')

/**
 * Perform an API request.
 * @param {string} method  HTTP verb.
 * @param {string} path    Path relative to `/api` (e.g. '/incidents').
 * @param {*} [body]       Optional JSON-serializable request body.
 * @param {object} [opts]
 * @param {object} [opts.headers]      Extra request headers (e.g. If-None-Match).
 * @param {AbortSignal} [opts.signal]  Cancels the request when aborted.
 * @param {string} [opts.contentType]  Body media type (default application/json).
 * @param {(p: {received: number, total: number|null}) => void} [opts.onProgress]
 *        Download progress while the response body streams in; `total` is
 *        null when the size is unknown (no Content-Length, or compressed).
 * @returns {Promise<*>}   Parsed JSON payload, null for empty responses, or
 *                         NOT_MODIFIED for a 304.
 * @throws {Error} With the server's `detail` message on non-2xx; an aborted
 *                 request rejects with the fetch AbortError.
 */
async function request(method, path, body, { headers = {}, signal, contentType, onProgress } = {}) {
  const options = {
    method,
    credentials: 'include', // send/receive the httpOnly session cookie
    headers: { ...headers },
    signal,
  }

  if (body !== undefined) {
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
    throw new Error(detail)
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
 * @returns {Promise<any>} The parsed JSON response.
 */
export function upload(path, file, { onProgress, signal, fields = {} } = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', `${BASE}${path}`)
    xhr.withCredentials = true
    xhr.responseType = 'json'
    if (onProgress) {
      xhr.upload.onprogress = (event) => onProgress({ sent: event.loaded, total: event.total })
    }
    xhr.onerror = () => reject(new Error('Cannot reach the server.'))
    xhr.onabort = () => reject(Object.assign(new Error('Upload cancelled.'), { name: 'AbortError' }))
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response)
      else reject(new Error(xhr.response?.detail || `Request failed (${xhr.status})`))
    }
    signal?.addEventListener('abort', () => xhr.abort())
    const form = new FormData()
    for (const [key, value] of Object.entries(fields)) form.append(key, value)
    form.append('file', file, file.name)
    xhr.send(form)
  })
}

/**
 * POST a JSON body and return the response as a Blob (a generated file: the
 * incident report as HTML or PDF). Errors carry the server's `detail`.
 */
export async function postForBlob(path, body, { signal } = {}) {
  let response
  try {
    response = await fetch(`${BASE}${path}`, {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body ?? {}),
      signal,
    })
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
    throw new Error(detail)
  }
  return response.blob()
}

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

/**
 * Convenience wrapper that never throws: resolves to `{ ok, data, error }`.
 * Useful for boot-time probes (bootstrap / me) where a rejection is an
 * expected, non-exceptional outcome (e.g. a 401 "not signed in").
 *
 * @param {Promise<*>} promise  A promise returned by one of the `api.*` calls.
 */
export async function apiSafe(promise) {
  try {
    return { ok: true, data: await promise, error: null }
  } catch (err) {
    return { ok: false, data: null, error: err?.message || 'Request failed' }
  }
}
