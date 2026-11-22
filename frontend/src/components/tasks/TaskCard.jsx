import { useEffect, useId, useState } from 'react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useTasks } from '../../context/TasksContext.jsx'
import { formatDateTime } from '../../lib/time.js'
import { api } from '../../services/api.js'
import { answerLines, answerOf, dueText, emptyForm, isOpen, missing, statusBadge } from '../../domain/tasks.js'
import { authorLabel, entryLine } from '../../domain/warRoom.js'
import FieldInput from '../fields/FieldInput.jsx'
import { Badge, Button, Wait } from '../ui/index.js'
import Markdown from './Markdown.jsx'
import { numberedName } from '../../domain/incidentName.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'

/*
 * ============================================================================
 * A TASK — what to do, its form, and what was said of it
 * ============================================================================
 *
 * The same card is the page of a task (My tasks) and a task opened in the
 * Work plan of an incident. Whoever the task is for completes it here: a
 * choice when it is a question with choices, the fields of the incident it
 * asks for, the values it asks for, a comment. Anyone else reads it.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const LABEL = 'text-xs font-medium text-fg-muted'

/** The form whoever the task is for fills. */
function TaskForm({ task, onDone, guard }) {
  const { assignees } = useIncidents()
  const formId = useId()
  const [form, setForm] = useState(() => emptyForm(task))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [skipping, setSkipping] = useState(false)
  const [why, setWhy] = useState('')
  const needed = missing(task, form)
  const question = task.kind === 'ask'
  // What was answered or commented and not sent. A dialog that shows the card asks through `guard`
  // before it closes; a page is asked by the address it leaves.
  const unsaved = useUnsavedChanges(JSON.stringify(form) !== JSON.stringify(emptyForm(task)) || Boolean(why.trim()), {
    what: question ? 'The answer to the question' : 'The task',
    name: task.title,
  })
  useEffect(() => {
    if (!guard) return undefined
    guard.current = unsaved
    return () => {
      guard.current = null
    }
  }, [guard, unsaved])

  const send = async (event) => {
    event.preventDefault()
    setBusy(true)
    setError(null)
    try {
      onDone(await api.post(`/tasks/${encodeURIComponent(task.id)}/complete`, answerOf(task, form)))
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }
  const skip = async () => {
    setBusy(true)
    setError(null)
    try {
      onDone(await api.post(`/tasks/${encodeURIComponent(task.id)}/skip`, { why: why.trim() }))
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={send} aria-label={question ? 'Answer' : 'Complete the task'} className="flex flex-col gap-3">
      {task.choices.length > 0 && (
        <fieldset className="flex flex-col gap-1.5">
          <legend className={LABEL}>Your answer</legend>
          <div className="flex flex-wrap gap-2">
            {task.choices.map((choice) => (
              <label
                key={choice.port}
                className={[
                  'flex cursor-pointer items-center gap-2 border px-3 py-1.5 text-sm focus-within:ring-2 focus-within:ring-accent',
                  form.choice === choice.port ? 'border-accent bg-accent-soft text-accent-fg' : 'border-line text-fg',
                ].join(' ')}
              >
                <input
                  type="radio"
                  name={`${formId}-choice`}
                  value={choice.port}
                  checked={form.choice === choice.port}
                  onChange={() => setForm({ ...form, choice: choice.port })}
                  className="sr-only"
                />
                {choice.label}
              </label>
            ))}
          </div>
        </fieldset>
      )}
      {task.inputs.map((item) => {
        const id = `${formId}-value-${item.name}`
        const value = form.values[item.name] ?? ''
        const set = (next) => setForm({ ...form, values: { ...form.values, [item.name]: next } })
        return (
          <div key={item.name} className="flex flex-col gap-1">
            <label htmlFor={id} className={LABEL}>
              {item.label}
              {item.required ? ' *' : ''}
            </label>
            {item.type === 'bool' ? (
              <select id={id} value={value} onChange={(event) => set(event.target.value)} className={INPUT}>
                <option value="">(not said)</option>
                <option value="yes">yes</option>
                <option value="no">no</option>
              </select>
            ) : (
              <input
                id={id}
                type={item.type === 'number' ? 'number' : 'text'}
                step={item.type === 'number' ? 'any' : undefined}
                value={value}
                autoComplete="off"
                onChange={(event) => set(event.target.value)}
                className={`${INPUT} ${item.type === 'number' ? 'font-mono' : ''}`}
              />
            )}
          </div>
        )
      })}
      {task.fields.map((field) => {
        const id = `${formId}-field-${field.name}`
        return (
          <div key={field.name} className="flex flex-col gap-1">
            <label htmlFor={id} className={LABEL}>
              {field.label} *
            </label>
            <FieldInput
              id={id}
              field={field}
              value={form.fields[field.name]}
              users={field.type === 'user' ? assignees : null}
              onChange={(next) => setForm({ ...form, fields: { ...form.fields, [field.name]: next } })}
            />
            {field.description && <span className="text-xs text-fg-subtle">{field.description}</span>}
          </div>
        )
      })}
      <div className="flex flex-col gap-1">
        <label htmlFor={`${formId}-comment`} className={LABEL}>
          Comment
        </label>
        <textarea
          id={`${formId}-comment`}
          rows={2}
          value={form.comment}
          maxLength={2000}
          onChange={(event) => setForm({ ...form, comment: event.target.value })}
          className={INPUT}
        />
      </div>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
          {error}
        </p>
      )}
      {skipping ? (
        <div className="flex flex-col gap-2 border border-line p-3">
          <label htmlFor={`${formId}-why`} className={LABEL}>
            Why it is skipped
          </label>
          <input
            id={`${formId}-why`}
            type="text"
            value={why}
            maxLength={500}
            onChange={(event) => setWhy(event.target.value)}
            className={INPUT}
          />
          <p className="text-xs text-fg-subtle">
            {question
              ? 'A playbook that waits for this goes on as if nobody had answered.'
              : 'A playbook that waits for this goes on as if it were done.'}
          </p>
          <div className="flex gap-2">
            <Button type="button" variant="danger" size="sm" disabled={busy} onClick={skip}>
              Skip it
            </Button>
            <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setSkipping(false)}>
              Keep it
            </Button>
          </div>
        </div>
      ) : (
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" variant="primary" size="sm" disabled={busy || needed.length > 0}>
            {question ? 'Send the answer' : 'Mark as done'}
          </Button>
          <Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => setSkipping(true)}>
            Skip…
          </Button>
          {needed.length > 0 && <span className="text-xs text-fg-muted">Still needed: {needed.join(', ')}</span>}
        </div>
      )}
    </form>
  )
}

/**
 * @param {{
 *   taskId: string,
 *   onChanged?: (task: object) => void,         // completed or skipped here
 *   onOpenIncident?: (id: string) => void,      // left out where the incident is already open
 * }} props
 */
export default function TaskCard({ taskId, onChanged, onOpenIncident, guard }) {
  const { can } = useAuth()
  const { refresh, version } = useTasks()
  const [task, setTask] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    api.get(`/tasks/${encodeURIComponent(taskId)}`).then(
      (found) => {
        if (cancelled) return
        setTask(found)
        setError(null)
      },
      (failure) => !cancelled && setError(failure.message),
    )
    return () => {
      cancelled = true
    }
  }, [taskId, version])

  if (error) {
    return (
      <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
        {error}
      </p>
    )
  }
  if (!task || task.id !== taskId) {
    return <Wait>Loading the task…</Wait>
  }
  const badge = statusBadge(task)
  const due = dueText(task)
  const lines = answerLines(task)
  return (
    <article aria-label={task.title} className="flex flex-col gap-4">
      <header className="flex flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2">
          <Badge color={badge.color}>{badge.label}</Badge>
          {due && (
            <span className={`font-mono text-xs ${task.status === 'overdue' ? 'text-high' : 'text-fg-muted'}`}>
              {due}
            </span>
          )}
        </div>
        <h2 className="text-lg font-semibold text-fg">{task.title}</h2>
        <p className="text-xs text-fg-muted">
          For {task.for}
          {task.incidentId && (
            <>
              {' · '}
              {onOpenIncident ? (
                <button
                  type="button"
                  onClick={() => onOpenIncident(task.incidentId)}
                  className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  {task.incidentName
                    ? numberedName({ number: task.incidentNumber, name: task.incidentName })
                    : 'the incident'}
                </button>
              ) : (
                task.incidentName
              )}
            </>
          )}
          {task.createdBy ? ` · asked by ${authorLabel(task.createdBy)}` : ''}
          {task.createdAt ? ` · ${formatDateTime(Date.parse(task.createdAt))}` : ''}
        </p>
      </header>

      {task.instructions && (
        <section aria-label="Instructions" className="border-l-2 border-line pl-3">
          <Markdown text={task.instructions} />
        </section>
      )}

      {isOpen(task) ? (
        task.mine ? (
          <TaskForm
            guard={guard}
            key={task.id}
            task={task}
            onDone={(next) => {
              setTask({ ...task, ...next })
              refresh()
              onChanged?.(next)
            }}
          />
        ) : (
          <p className="border border-line bg-raised px-3 py-2 text-sm text-fg-muted">
            This is for {task.for}
            {can('write') ? ': it can be given to someone else from the work plan of its incident.' : '.'}
          </p>
        )
      ) : (
        <section aria-label="What was answered" className="flex flex-col gap-1 border border-line p-3">
          <p className="text-xs text-fg-muted">
            {task.status === 'skipped' ? 'Skipped' : task.kind === 'ask' ? 'Answered' : 'Done'} by{' '}
            {authorLabel(task.completedBy)}
            {task.completedAt ? ` · ${formatDateTime(Date.parse(task.completedAt))}` : ''}
          </p>
          {lines.length > 0 && (
            <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-1 text-sm">
              {lines.map((line, index) => (
                <div key={index} className="contents">
                  <dt className="text-fg-muted">{line.label}</dt>
                  <dd className="min-w-0 break-words text-fg">{line.text}</dd>
                </div>
              ))}
            </dl>
          )}
        </section>
      )}

      {task.entries?.length > 0 && (
        <section aria-label="In the War Room" className="flex flex-col gap-1">
          <p className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">In the War Room</p>
          <ul className="flex flex-col divide-y divide-line-soft border border-line">
            {task.entries.map((entry) => {
              const line = entryLine(entry)
              return (
                <li key={entry.id} className="flex flex-wrap items-baseline gap-x-2 px-3 py-1.5 text-sm">
                  <span className="text-fg">{line.text}</span>
                  <span className="text-xs text-fg-muted">
                    {authorLabel(entry.author)} · {formatDateTime(Date.parse(entry.at))}
                  </span>
                </li>
              )
            })}
          </ul>
        </section>
      )}
    </article>
  )
}
