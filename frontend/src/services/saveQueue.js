import { applyMergePatch, createMergePatch } from '../lib/mergePatch.js'
import { rebase } from '../lib/rebase.js'

/*
 * ============================================================================
 * SAVE QUEUE
 * ============================================================================
 *
 * Every edit of an incident is applied to the local copy at once and saved in
 * the background. This queue is what makes that safe:
 *
 *  - one save at a time per incident, in order; edits made while a save is
 *    travelling leave together with the next one;
 *  - what is sent is the difference between the local copy and `base`, the
 *    last version the server is known to hold, so a save that failed is not
 *    forgotten: its changes are still in the next difference;
 *  - each save states the version it started from (`If-Match`). When somebody
 *    else saved meanwhile the server answers 412: the queue reads their
 *    version, carries the local changes over it (see lib/rebase.js) and sends
 *    again, so neither side's work is lost;
 *  - a failed save is retried, at growing intervals, and reported until it
 *    goes through; an expired session (401) waits for the analyst to sign in
 *    again.
 *
 * The queue knows nothing about React or fetch: the caller gives it the four
 * functions it needs, which is also how the tests drive it.
 */

const RETRY_DELAYS = [2000, 5000, 15000, 30000]
const MAX_CONFLICTS = 5

/** A save worth sending again as it is: the server was unreachable or busy. */
const isTransient = (error) =>
  error?.status === undefined || error.status >= 500 || error.status === 408 || error.status === 429

/**
 * @param {object} options
 * @param {(id: string, patch: object, etag: string|null) => Promise<{etag: string|null}>} options.send
 *        Sends a merge patch; rejects with an error carrying the HTTP `status`.
 * @param {(id: string, etag: string|null) => Promise<{doc: object, etag: string|null}|null>} options.load
 *        Reads the server's version; null when it is still `etag`.
 * @param {(id: string) => object|null} options.getLocal  The local copy.
 * @param {(id: string, doc: object) => void} options.setLocal  Replaces the local copy.
 * @param {(remote: object, local: object) => object} [options.prepare]
 *        Adjusts a version read from the server before it is merged (view preferences).
 * @param {() => void} [options.onChange]  Called whenever `status()` may have changed.
 */
export function createSaveQueue({
  send,
  load,
  getLocal,
  setLocal,
  prepare = (remote) => remote,
  onChange = () => {},
  retryDelays = RETRY_DELAYS,
  setTimer = (fn, ms) => setTimeout(fn, ms),
  clearTimer = (timer) => clearTimeout(timer),
}) {
  const states = new Map()

  /** Read the server's version and carry the local changes over it. */
  async function pull(id, state) {
    const result = await load(id, state.etag)
    if (!result || states.get(id) !== state) return
    const local = getLocal(id)
    if (!local) return
    const remote = prepare(result.doc, local)
    const merged = rebase(state.base, local, remote)
    state.base = remote
    state.etag = result.etag
    if (merged !== local) setLocal(id, merged)
  }

  async function drain(id, state) {
    let conflicts = 0
    for (;;) {
      if (states.get(id) !== state) return
      if (state.stale) {
        state.stale = false
        await pull(id, state)
        continue
      }
      const local = getLocal(id)
      if (!local) return
      const patch = createMergePatch(state.base, local)
      if (Object.keys(patch).length === 0) {
        state.base = local
        return
      }
      try {
        const { etag } = await send(id, patch, state.etag)
        // What was sent is what the server holds now; later edits are a new difference.
        state.base = local
        state.etag = etag ?? state.etag
        conflicts = 0
      } catch (error) {
        if (error?.status !== 412) throw error
        conflicts += 1
        if (conflicts > MAX_CONFLICTS) throw error
        state.stale = true
      }
    }
  }

  async function run(id) {
    const state = states.get(id)
    if (!state || state.running) return
    state.running = true
    clearTimer(state.timer)
    state.timer = null
    try {
      await drain(id, state)
      state.error = null
      state.attempt = 0
      state.unauthorized = false
    } catch (error) {
      if (error?.status === 404) {
        // Deleted by somebody else: there is nothing left to save to.
        states.delete(id)
      } else {
        state.error = error?.message || 'Unable to save changes to the server.'
        state.unauthorized = error?.status === 401
        if (isTransient(error) || error?.status === 412) {
          const delay = retryDelays[Math.min(state.attempt, retryDelays.length - 1)]
          state.attempt += 1
          state.timer = setTimer(() => run(id), delay)
        }
      }
    } finally {
      state.running = false
      onChange()
    }
  }

  const isDirty = (id, state) => {
    const local = getLocal(id)
    return Boolean(local) && local !== state.base
  }

  return {
    /** Start saving an incident: `base` is the version the server holds, tagged `etag`. */
    track(id, base, etag = null) {
      const previous = states.get(id)
      if (previous) clearTimer(previous.timer)
      states.set(id, {
        base,
        etag,
        running: false,
        stale: false,
        timer: null,
        attempt: 0,
        error: null,
        unauthorized: false,
      })
      onChange()
    },

    isTracked: (id) => states.has(id),
    etagOf: (id) => states.get(id)?.etag ?? null,

    /** The local copy changed: save it (edits of the same tick leave together). */
    touch(id) {
      if (!states.has(id)) return
      onChange()
      Promise.resolve().then(() => run(id))
    },

    /**
     * A change that must not be sent: a view preference, or something the
     * server wrote itself and the local copy only mirrors.
     */
    adopt(id, prev, next) {
      const state = states.get(id)
      if (!state) return
      state.base = Object.is(state.base, prev) ? next : applyMergePatch(state.base, createMergePatch(prev, next))
    },

    /** Check the server for a newer version (and merge it), then save what is pending. */
    refresh(id) {
      const state = states.get(id)
      if (!state) return
      state.stale = true
      Promise.resolve().then(() => run(id))
    },

    /** Try again now what failed (after signing in again, or on request). */
    retry() {
      for (const [id, state] of states) {
        if (state.error || isDirty(id, state)) run(id)
      }
    },

    forget(id) {
      const state = states.get(id)
      if (!state) return
      clearTimer(state.timer)
      states.delete(id)
      onChange()
    },

    clear() {
      for (const state of states.values()) clearTimer(state.timer)
      states.clear()
      onChange()
    },

    /** `pending`: something is not on the server yet; `error`: why the last save failed. */
    status() {
      let pending = false
      let error = null
      let unauthorized = false
      for (const [id, state] of states) {
        if (state.running || isDirty(id, state)) pending = true
        if (state.error && !error) error = state.error
        if (state.unauthorized) unauthorized = true
      }
      return { pending, error, unauthorized }
    },
  }
}
