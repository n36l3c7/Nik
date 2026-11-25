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
import { queryString, recordFilters } from '../domain/evidenceQuery.js'
import { saveUrl } from '../lib/download.js'

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

/*
 * ============================================================================
 * HOST EVIDENCE (7.0)
 * ============================================================================
 *
 * The files of host evidence of an incident ("sources"), their records, the views over them and the
 * parts a file is sent in. The shapes are the ones of routers/evidence.py, evidence_views.py and
 * uploads.py. Every call that lists or reads takes an AbortSignal; `background: true` is for the polls
 * of a page that waits for the worker (they do not count as the person using the session).
 */

const evidencePath = (incidentId, rest = '') => `/incidents/${encodeURIComponent(incidentId)}/evidence${rest}`
const sourcePath = (incidentId, sourceId, rest = '') =>
  evidencePath(incidentId, `/sources/${encodeURIComponent(sourceId)}${rest}`)

export const evidence = {
  /** `{ sources }`, newest first, without their reports. `kind`: one section (`eventlog`, `browser`, ...). */
  sources: (incidentId, { kind = '', signal, background } = {}) =>
    api.get(evidencePath(incidentId, `/sources${queryString({ kind })}`), { signal, background }),
  /** One source with its parse `report` and the id of its artifact. */
  source: (incidentId, sourceId, { signal, background } = {}) =>
    api.get(sourcePath(incidentId, sourceId), { signal, background }),
  /** Have the file read again (202): its records are replaced, the marks stay. */
  readAgain: (incidentId, sourceId) => api.post(sourcePath(incidentId, sourceId, '/again')),
  /** Say a file read in part was looked at; the note goes to the audit log and the War Room. */
  seen: (incidentId, sourceId, note = '') => api.post(sourcePath(incidentId, sourceId, '/seen'), { note }),
  forgetSeen: (incidentId, sourceId) => api.del(sourcePath(incidentId, sourceId, '/seen')),
  /** Remove the file and its records (`{ removed }`); the flags and notes stay. */
  remove: (incidentId, sourceId) => api.del(sourcePath(incidentId, sourceId)),

  /**
   * One page of records: `{ records, next, count, countCapped }` (`count` on the first page only).
   * `filters` are the names of the API (domain/evidenceQuery.js); `order` is `time`, `-time` or `file`.
   */
  records: (incidentId, { filters = {}, order = 'time', limit = 100, cursor = '', fields = [], signal } = {}) =>
    api.get(
      evidencePath(
        incidentId,
        `/records${queryString({ ...recordFilters(filters), order, limit, cursor, fields: fields.join(',') })}`,
      ),
      { signal },
    ),
  /** One record whole: `data`, `locator`, its `source` and its `detections`. */
  record: (incidentId, recordId, { signal } = {}) =>
    api.get(evidencePath(incidentId, `/records/${encodeURIComponent(recordId)}`), { signal }),
  /** What the viewer of the worker shows of a record (404 no original, 503 no worker). */
  view: (incidentId, recordId, { signal } = {}) =>
    api.get(evidencePath(incidentId, `/records/${encodeURIComponent(recordId)}/view`), { signal }),
  /** Bytes `[offset, offset + length)` of the original, `as` `hex` or `text`: `{ offset, length, size, as, data }`. */
  sourcePage: (incidentId, sourceId, { offset = 0, length = 65536, as = 'hex', signal } = {}) =>
    api.get(sourcePath(incidentId, sourceId, `/page${queryString({ offset, length, as })}`), { signal }),
  /** The original in an encrypted zip: the browser streams it to the disk (needs evidence.download). */
  downloadOriginal: (incidentId, source) => {
    saveUrl(`${BASE}${sourcePath(incidentId, source.id, '/download')}`, `${source.fileName || 'evidence'}.zip`)
  },

  histogram: (incidentId, { filters = {}, buckets, gapMinutes, burstFactor, signal } = {}) =>
    api.get(
      evidencePath(
        incidentId,
        `/histogram${queryString({ ...recordFilters(filters), buckets, gapMinutes, burstFactor })}`,
      ),
      { signal },
    ),
  /** The values of a field with their counts: `{ field, values, distinct, distinctCapped, missing }`. */
  stack: (incidentId, { field, order = 'rare', limit = 100, filters = {}, signal } = {}) =>
    api.get(evidencePath(incidentId, `/stack${queryString({ ...recordFilters(filters), field, order, limit })}`), {
      signal,
    }),
  /** The fields the records have: `{ fields: [{ name, seen }] }`. */
  fields: (incidentId, { kind, type, sourceId, signal } = {}) =>
    api.get(evidencePath(incidentId, `/fields${queryString({ kind, type, sourceId })}`), { signal }),
  /** Per section: its files, records and what needs a look. */
  summary: (incidentId, { signal, background } = {}) =>
    api.get(evidencePath(incidentId, '/summary'), { signal, background }),
  /** Flag a record and annotate it; no flag and no note removes the mark. */
  putMark: (incidentId, { key, flagged = false, note = '' }) =>
    api.put(evidencePath(incidentId, '/marks'), { key, flagged, note }),
  exportDocument: (incidentId, { signal } = {}) => api.get(evidencePath(incidentId, '/export'), { signal }),
  /**
   * What the rules found, one row for each rule (highest level first): `{ rules, total, detections, byLevel }`.
   * `kind` is a section, `sourceId` one file, `source` the kind of file (a shell), `level` the lowest level.
   */
  detections: (incidentId, { kind, sourceId, source, level, limit = 200, signal } = {}) =>
    api.get(evidencePath(incidentId, `/detections${queryString({ kind, sourceId, source, level, limit })}`), {
      signal,
    }),

  /**
   * The `load` of a ServerTable over the records of an incident (components/ui/ServerTable.jsx).
   * `base` are filters that always apply (the section of the page).
   */
  recordsLoader:
    (incidentId, base = {}, fields = []) =>
    async ({ cursor, limit, order, filters, signal }) => {
      const page = await evidence.records(incidentId, {
        filters: { ...filters, ...base },
        order,
        limit,
        cursor,
        fields,
        signal,
      })
      return { items: page.records, next: page.next, total: cursor ? undefined : page.count, capped: page.countCapped }
    },
}

/*
 * The Sigma rules (routers/sigma_rules.py). A list takes the filters of `domain/sigma.js`; a text the worker
 * refuses comes back as an error with `data.errors` (`{ line, column, message }`).
 */
const RULES = '/sigma/rules'

export const sigmaRules = {
  list: (params = {}, { signal } = {}) => api.get(`${RULES}${queryString(params)}`, { signal }),
  summary: ({ signal } = {}) => api.get(`${RULES}/summary`, { signal }),
  get: (id, { signal } = {}) => api.get(`${RULES}/${encodeURIComponent(id)}`, { signal }),
  /** Read a text without saving it: `{ ok, engine, errors, rules }`. */
  validate: (source, { signal } = {}) => api.post(`${RULES}/validate`, { source }, { signal }),
  /** Run a text over the records of an incident, saving nothing. */
  tryOn: ({ source, incidentId, kind = '', sourceId = '' }, { signal } = {}) =>
    api.post(`${RULES}/try`, { source, incidentId, kind, sourceId }, { signal }),
  create: (source, enabled) => api.post(RULES, enabled === undefined ? { source } : { source, enabled }),
  update: (id, source, enabled) =>
    api.put(`${RULES}/${encodeURIComponent(id)}`, enabled === undefined ? { source } : { source, enabled }),
  setEnabled: (id, enabled) => api.patch(`${RULES}/${encodeURIComponent(id)}`, { enabled }),
  reset: (id) => api.post(`${RULES}/${encodeURIComponent(id)}/reset`),
  remove: (id) => api.del(`${RULES}/${encodeURIComponent(id)}`),
  /** `{ enabled, ids }` or `{ enabled, filters }`: `{ matched, changed }`. */
  bulk: (body) => api.post(`${RULES}/bulk`, body),
  recheck: () => api.post(`${RULES}/recheck`),
}

/**
 * One part of a file: raw bytes by PUT, with the progress of what goes up. XMLHttpRequest, as `upload`:
 * fetch cannot report it. A refusal carries `status` and `data` (the 409 of a part that is not where the
 * server is says `received`).
 */
function sendPart(path, blob, { onProgress, signal } = {}) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('PUT', `${BASE}${path}`)
    xhr.withCredentials = true
    noteForeground()
    xhr.responseType = 'json'
    xhr.setRequestHeader('Content-Type', 'application/octet-stream')
    if (onProgress) xhr.upload.onprogress = (event) => onProgress({ sent: event.loaded, total: event.total })
    xhr.onerror = () => reject(Object.assign(new Error(CUT), { interrupted: true }))
    xhr.onabort = () => reject(Object.assign(new Error('Upload cancelled.'), { name: 'AbortError' }))
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response)
        return
      }
      reportUnauthorized(xhr.status, path)
      reportRefused(xhr.status, path, xhr.response)
      reject(
        Object.assign(new Error(xhr.response?.detail || `Request failed (${xhr.status})`), {
          status: xhr.status,
          data: xhr.response,
        }),
      )
    }
    if (signal?.aborted) {
      xhr.abort()
      return
    }
    signal?.addEventListener('abort', () => xhr.abort(), { once: true })
    xhr.send(blob)
  })
}

/** The upload of a file in parts (lib/chunkedUpload.js drives it; evidence/uploads.py says how it works). */
export const uploads = {
  /** `{ incidentId, fileName, size, sha256?, params: { kind, source?, host?, user?, profile? } }` -> `{ id, chunk, received, ... }`. */
  open: (body, { signal } = {}) => api.post('/uploads', body, { signal }),
  /** How much the server received: where to go on from after a cut. */
  status: (uploadId, { signal, background } = {}) =>
    api.get(`/uploads/${encodeURIComponent(uploadId)}`, { signal, background }),
  /** The bytes from `offset` on (`{ received }`). */
  putPart: (uploadId, offset, blob, { onProgress, signal } = {}) =>
    sendPart(`/uploads/${encodeURIComponent(uploadId)}?offset=${offset}`, blob, { onProgress, signal }),
  /** Every part was sent: the file is kept and read in the background (202). */
  complete: (uploadId) => api.post(`/uploads/${encodeURIComponent(uploadId)}/complete`),
  abort: (uploadId) => api.del(`/uploads/${encodeURIComponent(uploadId)}`),
}
