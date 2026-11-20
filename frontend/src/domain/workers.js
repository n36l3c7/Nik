/*
 * The workers Nik leans on, as GET /api/workers answers: what to show for each.
 *
 * A worker that is configured is `up`, `failing` (it stopped answering, not
 * for long enough to tell anybody) or `down` (the administrators were told);
 * before its first check it has no state yet.
 */

/** "1 minute", "12 minutes", "2 hours 5 minutes": how long, in words. */
export function lastedWords(ms) {
  const minutes = Math.max(1, Math.round((Number(ms) || 0) / 60000))
  const hours = Math.floor(minutes / 60)
  const rest = minutes % 60
  const parts = []
  if (hours) parts.push(`${hours} hour${hours === 1 ? '' : 's'}`)
  if (rest || !hours) parts.push(`${rest} minute${rest === 1 ? '' : 's'}`)
  return parts.join(' ')
}

/**
 * What a row says: `{ text, color, detail }`, the badge and the line under it.
 * `now` is a time in milliseconds.
 */
export function workerStatus(worker, now) {
  if (!worker?.configured) return { text: 'not configured', color: 'slate', detail: '' }
  const since = Date.parse(worker.since ?? '')
  const lasted = Number.isFinite(since) ? lastedWords(Math.max(0, now - since)) : ''
  if (worker.state === 'up') return { text: 'answering', color: 'emerald', detail: '' }
  if (worker.state === 'failing') {
    return { text: 'not answering', color: 'amber', detail: lasted ? `For ${lasted}: ${worker.waits}.` : '' }
  }
  if (worker.state === 'down') {
    return { text: 'down', color: 'red', detail: lasted ? `For ${lasted}: ${worker.waits}.` : `${worker.waits}.` }
  }
  return { text: 'not checked yet', color: 'slate', detail: '' }
}

/** "Automation worker": the name of a worker as a row's heading. */
export const workerName = (worker) => {
  const label = String(worker?.label ?? '')
  return label.charAt(0).toUpperCase() + label.slice(1)
}

/** How many configured workers are not answering (failing or down). */
export const notAnswering = (workers) =>
  (workers ?? []).filter((worker) => worker.configured && (worker.state === 'failing' || worker.state === 'down'))
    .length
