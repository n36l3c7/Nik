import { BULK_LISTS, jobEnded, jobProgress } from '../domain/bulk.js'
import { wasCut } from '../domain/transfers.js'
import { api } from '../services/api.js'
import { transfer } from './transfers.js'

/*
 * Bulk jobs, as the browser asks for them and follows them (the rules are the
 * server's, app/bulk.py; what the screens say is in domain/bulk.js).
 *
 * A job the server did before answering comes back whole. One that goes on
 * in the background is followed here: it is shown in the tray at the foot of
 * the window until it ends, and it goes on by itself on the server whatever
 * happens to this page. While the server restarts the reading fails for a
 * moment: it is tried again, not given up.
 */

const POLL_MS = 1000
// How long the server may stay unreachable before the page stops asking (the job goes on there).
const SILENT_MS = 10 * 60 * 1000

// What is told when a job ends: the lists that show what it changed read again.
const listeners = new Set()

/** Be told of every bulk job that ends: `listener(job)`. Returns what stops it. */
export function onBulkEnded(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

const ended = (job) => {
  listeners.forEach((listener) => listener(job))
  return job
}

/** What an action would do to a selection: the plan of the server. Changes nothing. */
export const planBulk = (list, request) => api.post(`${BULK_LISTS[list].path}/bulk/plan`, request)

const pause = (ms) => new Promise((resolve) => setTimeout(resolve, ms))

/** Read a running job until it ends, with its progress in the tray. Resolves with the job. */
export function followBulk(job) {
  return transfer(job.label, async (report) => {
    let current = job
    let silentSince = null
    report(jobProgress(current))
    while (!jobEnded(current)) {
      await pause(POLL_MS)
      try {
        current = await api.get(`/bulk/${current.id}`, { background: true })
        silentSince = null
        report(jobProgress(current))
      } catch (error) {
        // The server is restarting: the job goes on when it is back, and so does the reading.
        if (!wasCut(error)) throw error
        silentSince ??= Date.now()
        if (Date.now() - silentSince > SILENT_MS) throw error
      }
    }
    return current
  }).then(ended)
}

/**
 * Ask for a bulk action. Resolves with the job once it is over, whichever way it ran; `onStarted`
 * is told as soon as the server has it (a job in the background: the dialog can close).
 */
export async function runBulk(list, request, { onStarted } = {}) {
  const job = await api.post(`${BULK_LISTS[list].path}/bulk`, request)
  onStarted?.(job)
  return jobEnded(job) ? ended(job) : followBulk(job)
}

/** Stop a running job after the item it is on. */
export const cancelBulk = (id) => api.post(`/bulk/${id}/cancel`, {})

/** A new job on what an ended one did not do. Resolves with it once it is over. */
export async function retryBulk(id, { onStarted } = {}) {
  const job = await api.post(`/bulk/${id}/retry`, {})
  onStarted?.(job)
  return jobEnded(job) ? ended(job) : followBulk(job)
}
