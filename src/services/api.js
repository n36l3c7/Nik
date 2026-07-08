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
 * 204 (No Content) resolves to `null`.
 *
 * This is the ONLY file that knows how to talk to the server; every context
 * (auth, audit, settings, incidents) builds on top of it.
 */

const BASE = '/api'

/**
 * Perform an API request.
 * @param {string} method  HTTP verb.
 * @param {string} path    Path relative to `/api` (e.g. '/incidents').
 * @param {*} [body]       Optional JSON-serializable request body.
 * @returns {Promise<*>}   Parsed JSON payload, or null for empty responses.
 * @throws {Error} With the server's `detail` message on non-2xx.
 */
async function request(method, path, body) {
  const options = {
    method,
    credentials: 'include', // send/receive the httpOnly session cookie
    headers: {},
  }

  if (body !== undefined) {
    options.headers['Content-Type'] = 'application/json'
    options.body = JSON.stringify(body)
  }

  let response
  try {
    response = await fetch(`${BASE}${path}`, options)
  } catch (networkError) {
    // fetch only rejects on network failure (server unreachable, DNS, CORS…).
    throw new Error(networkError?.message || 'Cannot reach the server.')
  }

  // 204 No Content — nothing to parse.
  if (response.status === 204) return null

  // Parse the body defensively: some error responses may be empty.
  let payload = null
  const text = await response.text()
  if (text) {
    try {
      payload = JSON.parse(text)
    } catch {
      payload = null
    }
  }

  if (!response.ok) {
    const detail =
      (payload && typeof payload.detail === 'string' && payload.detail) ||
      `Request failed (${response.status})`
    throw new Error(detail)
  }

  return payload
}

export const api = {
  get: (path) => request('GET', path),
  post: (path, body) => request('POST', path, body),
  patch: (path, body) => request('PATCH', path, body),
  put: (path, body) => request('PUT', path, body),
  del: (path) => request('DELETE', path),
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
