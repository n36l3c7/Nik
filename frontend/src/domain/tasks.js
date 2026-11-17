/*
 * Tasks and questions (GET /api/tasks, /api/incidents/<id>/work-plan) as the
 * screens read them: what a task is called, when it is due, what its form
 * sends, and the work plan of an incident step by step.
 */
import { fromInput, toInput } from './fields.js'

export const TASKS_ROOT = '/tasks'

export const isTasksPath = (pathname) => /^\/tasks(\/|$)/.test(String(pathname ?? ''))

/** What a path asks for: null when it is not the tasks page, else `{ id }` (null for the list alone). */
export function tasksFromPath(pathname) {
  const path = String(pathname ?? '').split('?')[0]
  if (!isTasksPath(path)) return null
  const [, , raw] = path.replace(/\/+$/, '').split('/')
  try {
    return { id: raw ? decodeURIComponent(raw) : null }
  } catch {
    return { id: null }
  }
}

export const tasksPath = (id = null) => (id ? `${TASKS_ROOT}/${encodeURIComponent(id)}` : TASKS_ROOT)

export const isOpen = (task) => task?.status === 'open' || task?.status === 'overdue'

/** The state of a task as a badge: `{ label, color }`. */
export function statusBadge(task) {
  switch (task?.status) {
    case 'overdue':
      return { label: 'overdue', color: 'red' }
    case 'done':
      return { label: task.kind === 'ask' ? 'answered' : 'done', color: 'emerald' }
    case 'skipped':
      return { label: task.kind === 'ask' ? 'no answer' : 'skipped', color: 'slate' }
    default:
      return { label: task?.kind === 'ask' ? 'asked' : 'to do', color: 'amber' }
  }
}

const span = (seconds) => {
  const value = Math.abs(seconds)
  if (value < 3600) return `${Math.max(1, Math.round(value / 60))} min`
  if (value < 172_800) return `${Math.round(value / 3600)} h`
  return `${Math.round(value / 86_400)} d`
}

/** When an open task is due, in words: "due in 2 h", "3 h late"; '' with no due time or once closed. */
export function dueText(task, now = Date.now()) {
  if (!task?.dueAt || !isOpen(task)) return ''
  const left = task.dueAt - now / 1000
  return left >= 0 ? `due in ${span(left)}` : `${span(left)} late`
}

/** The most pressing first: overdue, then by due time, then the oldest. */
export function byUrgency(tasks) {
  const rank = (task) => (task.status === 'overdue' ? 0 : 1)
  return [...(tasks ?? [])].sort(
    (a, b) =>
      rank(a) - rank(b) ||
      (a.dueAt ?? Infinity) - (b.dueAt ?? Infinity) ||
      String(a.createdAt).localeCompare(String(b.createdAt)),
  )
}

/** What the form of a task starts with: `{ choice, fields, values, comment }`, every input empty. */
export function emptyForm(task) {
  return {
    choice: '',
    fields: Object.fromEntries((task?.fields ?? []).map((field) => [field.name, toInput(field, null)])),
    values: Object.fromEntries((task?.inputs ?? []).map((item) => [item.name, ''])),
    comment: '',
  }
}

const blank = (value) =>
  value === null || value === undefined || value === '' || (Array.isArray(value) && value.length === 0)

/** What is still needed before the form can be sent: labels, in the order of the form. */
export function missing(task, form) {
  const out = []
  if ((task?.choices ?? []).length > 0 && !form.choice) out.push('a choice')
  for (const field of task?.fields ?? []) {
    let value
    try {
      value = fromInput(field, form.fields?.[field.name])
    } catch {
      value = form.fields?.[field.name]
    }
    if (blank(value)) out.push(field.label || field.name)
  }
  for (const item of task?.inputs ?? []) {
    if (item.required && blank(form.values?.[item.name])) out.push(item.label || item.name)
  }
  return out
}

/** The body POST /api/tasks/<id>/complete takes, from what the form holds. */
export function answerOf(task, form) {
  const body = { comment: String(form.comment ?? '').trim() }
  if ((task?.choices ?? []).length > 0) body.choice = form.choice
  if ((task?.fields ?? []).length > 0) {
    body.fields = Object.fromEntries(
      task.fields.map((field) => [field.name, fromInput(field, form.fields?.[field.name])]),
    )
  }
  if ((task?.inputs ?? []).length > 0) {
    body.values = Object.fromEntries(
      task.inputs.map((item) => {
        const typed = form.values?.[item.name]
        if (item.type === 'bool') return [item.name, typed === '' || typed === undefined ? null : typed === 'yes']
        return [item.name, typed === '' || typed === undefined ? null : typed]
      }),
    )
  }
  return body
}

/** What a task was answered with, as lines to show: `[{ label, text }]`. */
export function answerLines(task) {
  const answer = task?.answer
  if (!answer) return []
  const lines = []
  if (answer.skipped) lines.push({ label: 'Skipped', text: String(answer.skipped) })
  if (answer.choice) lines.push({ label: 'Answer', text: String(answer.choice) })
  const show = (value) =>
    value === null || value === undefined
      ? '—'
      : typeof value === 'boolean'
        ? value
          ? 'yes'
          : 'no'
        : typeof value === 'object'
          ? JSON.stringify(value)
          : String(value)
  const labels = Object.fromEntries((task.fields ?? []).map((field) => [field.name, field.label || field.name]))
  for (const [name, value] of Object.entries(answer.fields ?? {}))
    lines.push({ label: labels[name] ?? name, text: show(value) })
  const asked = Object.fromEntries((task.inputs ?? []).map((item) => [item.name, item.label || item.name]))
  for (const [name, value] of Object.entries(answer.values ?? {}))
    lines.push({ label: asked[name] ?? name, text: show(value) })
  if (answer.comment) lines.push({ label: 'Comment', text: String(answer.comment) })
  return lines
}

/* ---------------------------------------------------------------- work plan */

/** What happened to a step of a plan, as a badge: `{ label, color }`. */
export function stepBadge(step) {
  // A step that is a task or a question says what the task says: to do, overdue, answered, skipped.
  if (step?.task) return statusBadge(step.task)
  switch (step?.status) {
    case 'done':
      return { label: 'done', color: 'emerald' }
    case 'failed':
      return { label: 'failed', color: 'red' }
    case 'waiting':
      return { label: 'waiting', color: 'amber' }
    case 'running':
    case 'pending':
      return { label: 'running', color: 'cyan' }
    case 'skipped':
      return { label: 'skipped', color: 'slate' }
    default:
      return { label: 'not reached', color: 'slate' }
  }
}

/** How far a plan is: `{ done, total }`, counting the steps that are over (done, skipped, failed). */
export function progress(plan) {
  const steps = (plan?.phases ?? []).flatMap((phase) => phase.steps ?? [])
  const over = steps.filter((step) => ['done', 'skipped', 'failed'].includes(step.status)).length
  return { done: over, total: steps.length }
}

/** The plans worth showing first: those still running, then the newest. */
export function orderPlans(plans) {
  const live = (plan) => (['done', 'failed', 'stopped'].includes(plan.status) ? 1 : 0)
  return [...(plans ?? [])].sort((a, b) => live(a) - live(b) || String(b.startedAt).localeCompare(String(a.startedAt)))
}

/** The name of a phase as its heading; steps that name none come under "Steps". */
export const phaseTitle = (phase, alone) => phase?.name || (alone ? 'Steps' : 'Other steps')
