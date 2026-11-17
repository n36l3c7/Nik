import { Suspense, lazy, useCallback, useEffect, useMemo, useState } from 'react'
import { ListChecks, Plus, RefreshCw, Workflow } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useTasks } from '../../../context/TasksContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { api } from '../../../services/api.js'
import { KIND_LABELS, normalise } from '../../../domain/automation/graph.js'
import { RUN_COLORS, isFinished } from '../../../domain/automation/runs.js'
import { dueText, isOpen, orderPlans, phaseTitle, progress, statusBadge, stepBadge } from '../../../domain/tasks.js'
import { Badge, Button, Modal } from '../../ui/index.js'
import Assign, { assigneeOf } from '../../tasks/Assign.jsx'
import NewTaskDialog from '../../tasks/NewTaskDialog.jsx'
import TaskCard from '../../tasks/TaskCard.jsx'

// The canvas brings its own library: it is loaded when the graph is asked for.
const Canvas = lazy(() => import('../../automation/Canvas.jsx'))

/*
 * ============================================================================
 * WORK PLAN — what the playbooks of an incident do, step by step, and its tasks
 * ============================================================================
 *
 * For each playbook that runs or ran on the incident: its steps in order,
 * under the phases the playbook names, each with what happened to it. A step
 * that is a task or a question opens it, with its form for whom it is for.
 * The same plan can be seen as the graph of the playbook (read-only), and
 * the choice is remembered. Tasks added by hand are listed under the plans.
 *
 * Whoever reads the incident reads its plan; what an action was given stays
 * on the page of the run.
 */

const VIEW_KEY = 'nik.workplan.view'
const REFRESH_MS = 5000

const readView = () => {
  try {
    return localStorage.getItem(VIEW_KEY) === 'graph' ? 'graph' : 'list'
  } catch {
    return 'list'
  }
}

/** One step of a plan, as a row: a task or a question opens. */
function StepRow({ step, onOpen }) {
  const badge = stepBadge(step)
  const due = step.task ? dueText(step.task) : ''
  const body = (
    <>
      <span className="w-24 shrink-0">
        <Badge color={badge.color}>{badge.label}</Badge>
      </span>
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm text-fg">{step.task?.title || step.name}</span>
        <span className="block truncate text-xs text-fg-muted">
          {KIND_LABELS[step.kind] ?? step.kind}
          {step.summary ? ` · ${step.summary}` : ''}
          {step.error ? ` · ${step.error}` : ''}
        </span>
      </span>
      {due && (
        <span
          className={`shrink-0 font-mono text-[11px] ${step.task.status === 'overdue' ? 'text-high' : 'text-fg-muted'}`}
        >
          {due}
        </span>
      )}
    </>
  )
  if (!step.task) return <li className="flex items-center gap-3 px-3 py-2">{body}</li>
  return (
    <li>
      <button
        type="button"
        onClick={() => onOpen(step.task.id)}
        aria-label={`Open the task ${step.task.title}`}
        className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
      >
        {body}
      </button>
    </li>
  )
}

/** The plan of one run: its phases as a list, or the graph of its playbook. */
function Plan({ plan, view, onOpen }) {
  const { done, total } = progress(plan)
  const graph = useMemo(() => normalise(plan.graph), [plan.graph])
  const tasksByNode = useMemo(
    () =>
      Object.fromEntries(
        plan.phases.flatMap((phase) =>
          phase.steps.filter((step) => step.task).map((step) => [step.node, step.task.id]),
        ),
      ),
    [plan.phases],
  )
  return (
    <section aria-label={`Plan of ${plan.playbook}`} className="flex flex-col border border-line">
      <header className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line bg-panel px-3 py-2">
        <h3 className="text-sm font-semibold text-fg">{plan.playbook || 'A playbook'}</h3>
        <Badge color={RUN_COLORS[plan.status] ?? 'slate'}>{plan.status}</Badge>
        <span className="font-mono text-xs text-fg-muted">
          {done} of {total} steps
        </span>
      </header>
      {view === 'graph' ? (
        <div className="h-[420px]">
          <Suspense
            fallback={
              <p role="status" className="p-4 font-mono text-sm text-fg-muted">
                Drawing the plan…
              </p>
            }
          >
            <Canvas
              graph={graph}
              catalog={[]}
              statuses={plan.statuses}
              readOnly
              plain
              onSelect={(ids) => ids.length === 1 && tasksByNode[ids[0]] && onOpen(tasksByNode[ids[0]])}
            />
          </Suspense>
        </div>
      ) : (
        plan.phases.map((phase) => (
          <div key={phase.name} role="group" aria-label={phaseTitle(phase, plan.phases.length === 1)}>
            <p className="border-b border-line-soft bg-raised px-3 py-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              {phaseTitle(phase, plan.phases.length === 1)}
            </p>
            <ol className="flex flex-col divide-y divide-line-soft">
              {phase.steps.map((step) => (
                <StepRow key={step.node} step={step} onOpen={onOpen} />
              ))}
            </ol>
          </div>
        ))
      )}
    </section>
  )
}

/** A task opened from the plan: its card, and for who writes incidents a way to give it to someone else. */
function OpenTask({ taskId, tasks, canWrite, onClose, onChanged }) {
  const { showToast } = useToast()
  const task = tasks.find((item) => item.id === taskId)
  const [assignee, setAssignee] = useState(() => assigneeOf(task))
  const [busy, setBusy] = useState(false)
  const give = async () => {
    setBusy(true)
    try {
      await api.put(`/tasks/${encodeURIComponent(taskId)}/assignee`, assignee)
      onChanged()
    } catch (failure) {
      showToast({ message: failure.message })
    } finally {
      setBusy(false)
    }
  }
  return (
    <Modal open onClose={onClose} title={task?.kind === 'ask' ? 'Question' : 'Task'} maxWidth="max-w-2xl">
      <div className="flex flex-col gap-5">
        <TaskCard taskId={taskId} onChanged={onChanged} />
        {canWrite && task && isOpen(task) && (
          <div className="flex flex-wrap items-end gap-2 border-t border-line pt-4">
            <Assign value={assignee} onChange={setAssignee} disabled={busy} label="Give it to" />
            <Button variant="secondary" size="sm" disabled={busy} onClick={give}>
              Give
            </Button>
          </div>
        )}
      </div>
    </Modal>
  )
}

export default function WorkPlanTab({ incident }) {
  const { can } = useAuth()
  const { version, refresh } = useTasks()
  const [plan, setPlan] = useState(null)
  const [error, setError] = useState(null)
  const [view, setView] = useState(readView)
  const [openId, setOpenId] = useState(null)
  const [adding, setAdding] = useState(false)

  const load = useCallback(async () => {
    try {
      setPlan(await api.get(`/incidents/${encodeURIComponent(incident.id)}/work-plan`))
      setError(null)
    } catch (failure) {
      // An incident not saved yet has no plan.
      if (failure.status === 404) setPlan({ plans: [], tasks: [], counts: { tasks: 0, open: 0, done: 0 } })
      else setError(failure.message)
    }
  }, [incident.id])
  useEffect(() => {
    setPlan(null)
    load()
  }, [load])
  useEffect(() => {
    load()
  }, [version, load])
  // While a playbook still runs, the plan follows it.
  const live = Boolean(plan?.plans.some((item) => !isFinished(item.status)))
  useEffect(() => {
    if (!live) return undefined
    const timer = setInterval(() => document.visibilityState === 'visible' && load(), REFRESH_MS)
    return () => clearInterval(timer)
  }, [live, load])

  const choose = (next) => {
    setView(next)
    try {
      localStorage.setItem(VIEW_KEY, next)
    } catch {
      /* the choice is kept for this visit only */
    }
  }
  const plans = useMemo(() => orderPlans(plan?.plans), [plan?.plans])
  const everyTask = useMemo(
    () =>
      [
        ...(plan?.tasks ?? []),
        ...(plan?.plans ?? []).flatMap((item) => item.phases.flatMap((phase) => phase.steps.map((step) => step.task))),
      ].filter(Boolean),
    [plan],
  )
  const changed = () => {
    refresh()
    load()
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-fg">Work plan</h2>
          <p className="text-sm text-fg-muted">
            What the playbooks of this incident do, step by step, and its tasks
            {plan?.counts.tasks ? ` · ${plan.counts.done} of ${plan.counts.tasks} tasks done` : ''}.
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div role="group" aria-label="Show the plan as" className="flex border border-line">
            {[
              { id: 'list', label: 'List', icon: ListChecks },
              { id: 'graph', label: 'Graph', icon: Workflow },
            ].map((item) => (
              <button
                key={item.id}
                type="button"
                aria-pressed={view === item.id}
                onClick={() => choose(item.id)}
                className={[
                  'flex h-8 items-center gap-1.5 px-2.5 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                  view === item.id ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-raised hover:text-fg',
                ].join(' ')}
              >
                <item.icon className="h-4 w-4" aria-hidden="true" />
                {item.label}
              </button>
            ))}
          </div>
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={load}>
            Refresh
          </Button>
          {can('write') && (
            <Button size="sm" icon={Plus} onClick={() => setAdding(true)}>
              Add a task
            </Button>
          )}
        </div>
      </div>

      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {!plan && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the plan…
        </p>
      )}
      {plan && plans.length === 0 && plan.tasks.length === 0 && (
        <p className="text-sm text-fg-muted">
          Nothing is planned for this incident yet. A plan appears when a playbook runs on it; a task can be added by
          hand, or typed in the War Room as <code className="font-mono">/task Call the user @anna due=2h</code>.
        </p>
      )}
      {plans.map((item) => (
        <Plan key={item.runId} plan={item} view={view} onOpen={setOpenId} />
      ))}
      {plan?.tasks.length > 0 && (
        <section aria-label="Tasks added by hand" className="flex flex-col border border-line">
          <h3 className="border-b border-line bg-panel px-3 py-2 text-sm font-semibold text-fg">Tasks added by hand</h3>
          <ul className="flex flex-col divide-y divide-line-soft">
            {plan.tasks.map((task) => {
              const badge = statusBadge(task)
              const due = dueText(task)
              return (
                <li key={task.id}>
                  <button
                    type="button"
                    onClick={() => setOpenId(task.id)}
                    aria-label={`Open the task ${task.title}`}
                    className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
                  >
                    <span className="w-24 shrink-0">
                      <Badge color={badge.color}>{badge.label}</Badge>
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm text-fg">{task.title}</span>
                      <span className="block truncate text-xs text-fg-muted">for {task.for}</span>
                    </span>
                    {due && (
                      <span
                        className={`shrink-0 font-mono text-[11px] ${task.status === 'overdue' ? 'text-high' : 'text-fg-muted'}`}
                      >
                        {due}
                      </span>
                    )}
                  </button>
                </li>
              )
            })}
          </ul>
        </section>
      )}

      {openId && (
        <OpenTask
          key={openId}
          taskId={openId}
          tasks={everyTask}
          canWrite={can('write')}
          onClose={() => setOpenId(null)}
          onChanged={changed}
        />
      )}
      {adding && (
        <NewTaskDialog
          incidentId={incident.id}
          onClose={() => setAdding(false)}
          onAdded={() => {
            setAdding(false)
            changed()
          }}
        />
      )}
    </div>
  )
}
