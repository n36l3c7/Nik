/*
 * Bulk actions: one action on many rows of a list (the server's side is
 * app/bulk.py). What is here is what the screens say of a plan and of a job,
 * as functions that can be tested: the bar, the confirmation and the result
 * only draw them.
 */

/** The address of each list's bulk routes, and what its rows are called. */
export const BULK_LISTS = {
  incidents: { path: '/incidents', one: 'incident', many: 'incidents' },
  artifacts: { path: '/artifacts', one: 'artifact', many: 'artifacts' },
  indicators: { path: '/iocs', one: 'indicator', many: 'indicators' },
}

const number = (count) => Number(count ?? 0).toLocaleString('en-US')

/** "1 incident", "1,284 incidents". */
export function counted(count, list) {
  const words = BULK_LISTS[list] ?? { one: 'item', many: 'items' }
  return `${number(count)} ${Number(count) === 1 ? words.one : words.many}`
}

/** An indicator as a bulk request names it: `domain:evil.example`. */
export const indicatorRef = (row) => `${row.type}:${row.value}`

/** Whether a job is over: nothing more will change in it. */
export const jobEnded = (job) => ['done', 'cancelled', 'failed'].includes(job?.state)

/** How far a job is, as the tray draws a transfer: items, not bytes. */
export function jobProgress(job) {
  const through = (job?.done ?? 0) + (job?.skipped ?? 0) + (job?.refused ?? 0) + (job?.failed ?? 0)
  return { sent: through, total: job?.total ?? 0, items: true }
}

/** "1,280 done · 3 skipped · 1 refused": only what there is, in this order. */
export function resultWords(job) {
  const parts = [
    ['done', job?.done],
    ['skipped', job?.skipped],
    ['refused', job?.refused],
    ['failed', job?.failed],
    ['not done', job?.pending],
  ]
    .filter(([, count]) => count > 0)
    .map(([word, count]) => `${number(count)} ${word}`)
  return parts.length ? parts.join(' · ') : 'nothing to do'
}

/** Whether everything a job was asked was done: the toast is enough, nobody has to read a result. */
export const jobClean = (job) => job?.state === 'done' && !job.skipped && !job.refused && !job.failed && !job.pending

/** How many items "Try again" would take: those that failed, and those the job never reached. */
export const retryCount = (job) => (jobEnded(job) ? (job.failed ?? 0) + (job.pending ?? 0) : 0)

/** What a job says of itself in a line: its state in words, then its counts. */
export function jobLine(job) {
  const state =
    job.state === 'running'
      ? job.cancelling
        ? 'Stopping'
        : 'Running'
      : job.state === 'done'
        ? 'Done'
        : job.state === 'cancelled'
          ? 'Cancelled'
          : 'Given up'
  return `${state}: ${resultWords(job)}`
}

/**
 * What the confirmation says before anything is done, from the plan of the server:
 * `{ lines: [sentence, …], problem: sentence | null, typed: phrase | null }`.
 * `problem` is why it cannot be asked for at all.
 */
export function planWords(plan) {
  const lines = []
  if (plan.applies < plan.count) {
    lines.push(`It applies to ${number(plan.applies)} of ${number(plan.count)}: the others are left as they are.`)
  }
  lines.push(...(plan.notes ?? []))
  lines.push(
    plan.inline
      ? 'It is done at once.'
      : 'It goes on in the background: its progress is at the foot of the window, and it goes on after a restart of the server.',
  )
  let problem = null
  if (plan.count === 0) problem = 'Nothing is selected by that.'
  else if (plan.over) {
    problem = `That is ${counted(plan.count, plan.list)}: a bulk action takes ${number(plan.limit)} at most. Narrow the filter and do it in parts.`
  } else if (plan.applies === 0) problem = 'It applies to none of them.'
  return { lines, problem, typed: plan.typed ?? null }
}

/** Whether the confirmation can be sent: no problem, and the words typed when they are asked for. */
export function canConfirm(plan, typed) {
  const { problem, typed: phrase } = planWords(plan)
  return !problem && (!phrase || String(typed ?? '').trim() === phrase)
}

/** What is sent to confirm: the count that was shown (for a selection by filter), and the words. */
export function confirmBody(plan, typed, byQuery) {
  return {
    ...(byQuery ? { count: plan.count } : {}),
    ...(plan.typed ? { typed: String(typed ?? '').trim() } : {}),
  }
}

/**
 * What closing many incidents asks: when they are all of one type, the reasons and the fields
 * that type wants to close; otherwise a reason in words, and a sentence that says why.
 * `{ type, reasons: [..], wanted: [name, …], mixed: boolean }`.
 */
export function closeAsk(rows, types) {
  const kinds = [...new Set(rows.map((row) => row.type || 'unclassified'))]
  if (kinds.length !== 1) return { type: null, reasons: [], wanted: [], mixed: kinds.length > 1 }
  const type = types.find((item) => item.id === kinds[0]) ?? null
  return {
    type,
    reasons: type?.closeReasons ?? [],
    wanted: (type?.fields ?? []).filter((item) => item.requiredOnClose).map((item) => item.name),
    mixed: false,
  }
}

/** The lines of a result worth reading first: what was refused or failed, then what was skipped. */
export function notable(items) {
  const rank = { failed: 0, refused: 1, pending: 2, skipped: 3, done: 4 }
  return [...items].filter((item) => item.state !== 'done').sort((a, b) => rank[a.state] - rank[b.state])
}
