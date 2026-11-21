/*
 * What a restart of the server did to work in progress, as the screens say it.
 *
 * Two shapes come from the server:
 *
 * - a step of a run carries `restarts`, oldest first: `{ at, what, by? }` with
 *   `what` = interrupted | again | waiting | happened | stopped | away
 *   (GET /api/automation/runs/<id>);
 * - a job of the API process (a disassembly, capa, a capture, a scan, a
 *   mailbox) carries `work`: `{ state, attempts, interruptedAt, resumedAt,
 *   progress, note }`, times in seconds since 1970.
 *
 * A step whose `status` is `interrupted` waits for a person: the worker
 * stopped while the step called another system, and nobody knows whether the
 * call was made. The three answers are in ANSWERS.
 */

/** The three things a person can say of a step a restart interrupted, in the order of the buttons. */
export const ANSWERS = [
  {
    answer: 'happened',
    label: 'It happened, go on',
    hint: 'The other system did what was asked. The run goes on from the next node, and this step has no result of its own.',
  },
  {
    answer: 'again',
    label: 'It did not, do it again',
    hint: 'The other system did nothing. The step is done again from the beginning.',
  },
  {
    answer: 'stop',
    label: 'Stop the run',
    hint: 'The run stops at this step. What was done before stays done.',
  },
]

/** The steps of a run that wait for a person to say what happened. */
export const interruptedSteps = (steps) => (steps ?? []).filter((step) => step.status === 'interrupted')

/** What the badge of a run says: `interrupted` when it waits at a step a restart interrupted. */
export const runStatus = (run) => (run?.interrupted ? 'interrupted' : (run?.status ?? ''))

const plain = (at) => new Date(at).toLocaleString()

/** A line of the history of a step: `{ at, what, by }` in words. `format` turns its time into text. */
export function restartLine(line, format = plain) {
  const when = line?.at ? format(Date.parse(line.at)) : ''
  const by = line?.by ? String(line.by) : 'Someone'
  switch (line?.what) {
    case 'interrupted':
      return `Interrupted by a restart at ${when}`
    case 'again':
      return line.by ? `${by} said it did not happen: done again at ${when}` : `Started again at ${when}`
    case 'waiting':
      return `It is not known whether it happened: it waits for a person since ${when}`
    case 'happened':
      return `${by} said it happened: the run went on at ${when}`
    case 'stopped':
      return `${by} stopped the run at ${when}`
    case 'away':
      return `Its worker was not there at ${when}: taken again a moment later`
    default:
      return ''
  }
}

/** The history of a step as lines, oldest first; none for a step no restart touched. */
export const restartLines = (restarts, format = plain) =>
  (restarts ?? []).map((line) => restartLine(line, format)).filter(Boolean)

/**
 * What a job says of the restarts that touched it, in one sentence; '' when none did.
 * "Interrupted by a restart at 10:02, started again at 10:03 (try 2 of 3)."
 */
export function workLine(work, format = plain, max = 3) {
  if (!work || !work.interruptedAt) return ''
  const cut = format(work.interruptedAt * 1000)
  if (work.state === 'aside') return `Interrupted by a restart at ${cut}, ${work.attempts} times in all: set aside.`
  if (work.state === 'failed') return `Interrupted by a restart at ${cut}: it could not be gone on with.`
  if (!work.resumedAt) return `Interrupted by a restart at ${cut}: it starts again by itself within a minute.`
  const tries = work.attempts > 1 ? ` (try ${work.attempts} of ${max})` : ''
  return `Interrupted by a restart at ${cut}, started again at ${format(work.resumedAt * 1000)}${tries}.`
}

/** How far a job is, as its worker says it ('' when it says nothing, or the job is not running). */
export const workProgress = (work) => (work?.state === 'held' ? String(work.progress ?? '') : '')
