/*
 * A run as the screens show it: what happened to each node, how long things
 * took, how a run and a step are named. The server's shapes are those of
 * GET /api/automation/runs and /runs/<id>.
 */

/** Badge colours (components/ui/Badge) of a run and of a step. */
export const RUN_COLORS = { running: 'cyan', waiting: 'amber', done: 'emerald', failed: 'red', stopped: 'slate' }
export const STEP_COLORS = {
  pending: 'slate',
  running: 'cyan',
  waiting: 'amber',
  done: 'emerald',
  failed: 'red',
  skipped: 'slate',
}

export const RUN_STATUSES = ['running', 'waiting', 'done', 'failed', 'stopped']
export const isFinished = (status) => ['done', 'failed', 'stopped'].includes(status)

const TRIGGERS = { manual: 'by hand', schedule: 'a schedule', event: 'an event', playbook: 'another playbook' }

/** "by hand", "incident.created"…: what started a run. */
export function triggerLabel(run) {
  const kind = String(run?.trigger ?? '')
  return TRIGGERS[kind] ?? (kind || 'unknown')
}

// What a node shows when its steps differ (a node inside a "for each" has one step per item).
const WORST_FIRST = ['failed', 'waiting', 'running', 'pending', 'done', 'skipped']

/** node id → the status the canvas colours it with. A node no step reached is not in the map. */
export function nodeStatuses(steps) {
  const found = new Map()
  for (const step of steps ?? []) {
    if (!found.has(step.node)) found.set(step.node, new Set())
    found.get(step.node).add(step.status)
  }
  return Object.fromEntries(
    [...found].map(([node, statuses]) => [node, WORST_FIRST.find((status) => statuses.has(status)) ?? 'pending']),
  )
}

/** The steps of one node, in the order they were taken. */
export const stepsOf = (steps, node) => (steps ?? []).filter((step) => step.node === node)

/** "38 ms", "4.2 s", "3 min", "2 h 5 min" between two ISO instants (to now when the second is missing). */
export function duration(from, to, now = Date.now()) {
  const start = Date.parse(from)
  if (!Number.isFinite(start)) return ''
  const end = to ? Date.parse(to) : now
  const ms = Math.max(0, end - start)
  if (ms < 1000) return `${Math.round(ms)} ms`
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} s`
  const minutes = Math.floor(ms / 60_000)
  if (minutes < 60) return `${minutes} min`
  const hours = Math.floor(minutes / 60)
  if (hours < 48) return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`
  return `${Math.floor(hours / 24)} d`
}

/** What a step says in one line under its name. */
export function stepLine(step) {
  if (!step) return ''
  if (step.status === 'failed') return step.error || 'failed'
  if (step.status === 'waiting') {
    if (step.waiting === 'approval') return 'waiting for an approval'
    if (step.waiting === 'task') return 'waiting for a person'
    if (step.waiting === 'run') return 'waiting for the playbook it started'
    if (step.waiting === 'each') return 'going through the items'
    return 'waiting'
  }
  if (step.status === 'skipped') return step.error || 'skipped'
  const parts = []
  if (step.port && step.port !== 'out') parts.push(step.port)
  if (step.attempt > 1) parts.push(`${step.attempt}${ordinal(step.attempt)} try`)
  if (step.itemIndex !== null && step.itemIndex !== undefined) parts.push(`item ${step.itemIndex + 1}`)
  const took = step.startedAt && step.finishedAt ? duration(step.startedAt, step.finishedAt) : ''
  if (took) parts.push(took)
  return parts.join(' · ')
}

function ordinal(number) {
  if (number % 100 >= 11 && number % 100 <= 13) return 'th'
  return { 1: 'st', 2: 'nd', 3: 'rd' }[number % 10] ?? 'th'
}

/**
 * The playbooks that can be run by hand: with a version and a trigger that
 * allows it. `dry`: any with a version. `on`: what it would run on (incident,
 * mail, file, url, indicator): a playbook whose event is about something
 * else is left out, one with no event runs on anything.
 */
export function runnable(playbooks, { dry = false, on = '' } = {}) {
  return (playbooks ?? []).filter(
    (playbook) =>
      playbook.version &&
      (dry || playbook.triggerConfig?.manual) &&
      (!on || !playbook.runsOn || playbook.runsOn === on),
  )
}

/** What "Run a playbook…" sends for an artifact: null for a kind no playbook runs on (a mailbox). */
export function artifactTarget(artifact) {
  if (!artifact || !['mail', 'file', 'pcap', 'url'].includes(artifact.kind)) return null
  return { kind: 'artifact', id: artifact.id, what: artifact.kind, label: artifact.name || artifact.id }
}

/** What "Run a playbook…" sends for an indicator. */
export const indicatorTarget = (type, value) => ({
  kind: 'indicator',
  id: `${type}:${value}`,
  what: 'indicator',
  label: String(value),
})

/** What the inputs form sends: each input as its type says, empty ones left out. Throws on a required one missing. */
export function inputValues(inputs, typed) {
  const values = {}
  for (const input of inputs ?? []) {
    const raw = typed?.[input.name]
    const text = typeof raw === 'string' ? raw.trim() : raw
    if (text === undefined || text === '' || text === null) {
      if (input.required) throw new Error(`"${input.name}" is required`)
      continue
    }
    if (input.type === 'number') {
      const number = Number(text)
      if (!Number.isFinite(number)) throw new Error(`"${input.name}" is a number`)
      values[input.name] = number
    } else if (input.type === 'bool') {
      values[input.name] = text === true || text === 'true' || text === 'yes'
    } else if (input.type === 'list' || input.type === 'object') {
      try {
        values[input.name] = JSON.parse(text)
      } catch {
        // A list typed as words: one per line or separated by commas.
        if (input.type === 'object') throw new Error(`"${input.name}" is an object, written as JSON`)
        values[input.name] = String(text)
          .split(/[\n,]/)
          .map((part) => part.trim())
          .filter(Boolean)
      }
    } else {
      values[input.name] = text
    }
  }
  return values
}
