/*
 * ============================================================================
 * CHUNKED UPLOAD: one file to /api/uploads, in the parts the server asks for
 * ============================================================================
 *
 * A file of host evidence can be tens of gigabytes: it goes up in parts of `chunk` bytes (the size the
 * server states when the session is opened), in order, and a cut connection does not mean sending it
 * all again. After a failed part the client asks the server how much it holds and goes on from there;
 * the retries are bounded and wait longer each time. The file is never read whole: a part is a
 * `file.slice()`. No whole-file SHA-256 is sent (the field is optional): the server hashes the parts
 * itself once, and a digest of a file of that size cannot be computed incrementally in a browser
 * (Web Crypto has no streaming digest).
 *
 * The planning (what part is next, when to retry, how long to wait) is pure and tested; `uploadFile`
 * runs it against `uploads` of services/api.js, or against whatever `api` it is given.
 */

export const MAX_RETRIES = 5
export const BACKOFF_BASE_MS = 500
export const BACKOFF_CAP_MS = 15000
export const POLL_MS = 1000

/** The params of an upload with the file's own last-modified time (ms), when the browser knows it. */
export function withFileTime(params, file) {
  const time = Number(file?.lastModified)
  return Number.isFinite(time) && time > 0 ? { ...params, fileTime: Math.round(time) } : { ...params }
}

/** The next part to send: `{ offset, length }`, or null when the whole file is there. */
export function nextPart(received, size, chunk) {
  if (!(chunk > 0) || !(size > 0) || received >= size) return null
  const offset = Math.max(0, received)
  return { offset, length: Math.min(chunk, size - offset) }
}

/** Milliseconds to wait before attempt `attempt` (1 is the first retry): doubles, up to a cap. */
export function backoffMs(attempt, base = BACKOFF_BASE_MS, cap = BACKOFF_CAP_MS) {
  return Math.min(cap, base * 2 ** Math.max(0, attempt - 1))
}

/** A cut connection, a server that fails or is busy, a timeout: worth another try. A refusal is not. */
export function isRetryable(error) {
  if (!error || error.name === 'AbortError') return false
  const status = error.status
  if (status === undefined || status === null) return true
  return status === 408 || status === 429 || status >= 500
}

/** What the server says it holds when it refuses a part that is not where it is (409): a whole number, or null. */
export function receivedOf(error) {
  const value = error?.data?.received
  return Number.isInteger(value) && value >= 0 ? value : null
}

/** What was sent in all, for a bar: the bytes the server holds plus the part that is going up. */
export function overallSent(received, partSent, size) {
  return Math.max(0, Math.min(size, received + Math.max(0, partSent)))
}

function cancelled() {
  return Object.assign(new Error('Upload cancelled.'), { name: 'AbortError' })
}

/** A wait that ends early, rejecting, when the signal is aborted. */
function pause(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(cancelled())
      return
    }
    const stop = () => {
      clearTimeout(timer)
      reject(cancelled())
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', stop)
      resolve()
    }, ms)
    signal?.addEventListener('abort', stop, { once: true })
  })
}

/**
 * Upload one File and wait until the server has kept it.
 *
 * @param {File} file
 * @param {object} options
 * @param {string} options.incidentId
 * @param {object} options.params  `{ kind, source?, host?, user?, profile? }` (what `POST /uploads` takes); the
 *   file's own last-modified time goes with it as `fileTime` (ms), which the parsers of logs use to date lines
 *   that carry no year
 * @param {(p: { phase: 'sending'|'keeping', sent: number, total: number, work?: object|null }) => void} [options.onProgress]
 * @param {AbortSignal} [options.signal]
 * @param {object} [options.api]       `uploads` of services/api.js (given by the tests)
 * @param {number} [options.retries]   failed parts in a row before it gives up
 * @param {(ms: number, signal?: AbortSignal) => Promise<void>} [options.sleep]
 * @param {number} [options.pollMs]    how often it asks whether the server has kept the file
 * @returns {Promise<{ uploadId: string, sourceId: string|null, kind: string|null, source: string|null, duplicate: boolean }>}
 *   `sourceId` is the file's report; `kind` and `source` say where the file went (the server's guess for `kind: "auto"`)
 * @throws an Error with the server's sentence; an AbortError when cancelled (the session is given up)
 */
export async function uploadFile(
  file,
  { incidentId, params, onProgress, signal, api, retries = MAX_RETRIES, sleep = pause, pollMs = POLL_MS },
) {
  const server = api ?? (await import('../services/api.js')).uploads
  const size = file.size
  const session = await server.open(
    { incidentId, fileName: file.name, size, params: withFileTime(params, file) },
    { signal },
  )
  const id = session.id
  const chunk = session.chunk
  let received = session.received ?? 0
  const report = (phase, partSent = 0, work = null) =>
    onProgress?.({ phase, sent: overallSent(received, partSent, size), total: size, work })

  try {
    report('sending')
    let failures = 0
    for (let part = nextPart(received, size, chunk); part; part = nextPart(received, size, chunk)) {
      if (signal?.aborted) throw cancelled()
      try {
        const answer = await server.putPart(id, part.offset, file.slice(part.offset, part.offset + part.length), {
          signal,
          onProgress: ({ sent }) => report('sending', sent),
        })
        received = Number.isInteger(answer?.received) ? answer.received : part.offset + part.length
        failures = 0
        report('sending')
      } catch (error) {
        if (error?.name === 'AbortError' || signal?.aborted) throw cancelled()
        // A part the server does not take where it is: it says where it is, and the next part starts there.
        const held = receivedOf(error)
        if (error?.status === 409 && held !== null && held !== part.offset) {
          if (++failures > retries) throw error
          received = held
          continue
        }
        if (!isRetryable(error) || ++failures > retries) throw error
        await sleep(backoffMs(failures), signal)
        // Where the server is, not where this client thinks it is: the part may have arrived while the answer did not.
        received = (await server.status(id, { signal })).received ?? received
      }
    }

    report('keeping')
    let shown = await server.complete(id)
    // The file is hashed and kept in the background: ask until the server says it is done.
    while (shown.state === 'finishing') {
      onProgress?.({ phase: 'keeping', sent: size, total: size, work: shown.work ?? null })
      await sleep(pollMs, signal)
      shown = await server.status(id, { signal, background: true })
    }
    if (shown.state !== 'complete') {
      throw new Error(shown.error || `The upload ended ${shown.state}`)
    }
    return {
      uploadId: id,
      sourceId: shown.sourceId ?? null,
      kind: shown.kind ?? null,
      source: shown.source ?? null,
      duplicate: Boolean(shown.duplicate),
    }
  } catch (error) {
    // Given up (cancelled, refused, out of retries): the server removes the parts it holds.
    try {
      await server.abort(id)
    } catch {
      /* already gone, or finishing: nothing to give up */
    }
    throw error
  }
}
