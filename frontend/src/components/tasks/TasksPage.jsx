import { useEffect, useRef, useState } from 'react'
import { FolderClosed, FolderOpen, X } from 'lucide-react'
import { useTasks } from '../../context/TasksContext.jsx'
import { api } from '../../services/api.js'
import { byUrgency, dueText, statusBadge, tasksPath } from '../../domain/tasks.js'
import { Badge, EmptyState, Wait } from '../ui/index.js'
import TaskCard from './TaskCard.jsx'
import { numberedName } from '../../domain/incidentName.js'
import { useObjectMenu } from '../menu/useObjectMenu.js'
import SearchBar from '../layout/SearchBar.jsx'

/*
 * ============================================================================
 * MY TASKS — what waits for the account that is signed in
 * ============================================================================
 *
 * A page next to the rail, like Settings and Automations: the list on the
 * left (mine, or everyone's, open or closed), the task that is chosen on the
 * right with its form. Its address is /tasks and /tasks/<id>, so a
 * notification or a line of the War Room can link to one task.
 */

const VIEWS = [
  { id: 'mine', label: 'Mine', query: 'which=mine' },
  { id: 'open', label: 'All open', query: 'which=all&status=open' },
  { id: 'closed', label: 'Closed', query: 'which=all&status=closed' },
]

/**
 * @param {{
 *   taskId: string | null,
 *   onSelect: (id: string | null, options?: { replace?: boolean }) => void,
 *   onClose: () => void,
 *   onOpenIncident: (id: string) => void,
 *   onFirstScreen?: (first: boolean) => void,  // told whether the page shows what a fresh visit shows
 * }} props
 */
export default function TasksPage({ taskId, onSelect, onClose, onOpenIncident, onFirstScreen }) {
  const { version, count } = useTasks()
  const menu = useObjectMenu()
  const ref = useRef(null)
  const [view, setView] = useState('mine')
  const [tasks, setTasks] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    ref.current?.focus()
  }, [])

  useEffect(() => {
    let cancelled = false
    const query = VIEWS.find((item) => item.id === view).query
    api.get(`/tasks?${query}`).then(
      (found) => {
        if (cancelled) return
        setTasks(view === 'closed' ? [...found.tasks].reverse() : byUrgency(found.tasks))
        setError(null)
      },
      (failure) => !cancelled && setError(failure.message),
    )
    return () => {
      cancelled = true
    }
  }, [view, version])

  // With the list alone open, the first task is shown.
  useEffect(() => {
    if (!taskId && tasks?.length) onSelect(tasks[0].id, { replace: true })
  }, [taskId, tasks, onSelect])

  // What a fresh visit shows: the tasks that wait for the person, on the first of them. The entry of
  // the rail does nothing then, and comes back here from anything else.
  const first = view === 'mine' && tasks !== null && (taskId ?? null) === (tasks[0]?.id ?? null)
  useEffect(() => {
    onFirstScreen?.(first)
    return () => onFirstScreen?.(false)
  }, [first, onFirstScreen])

  return (
    <section
      ref={ref}
      aria-label="My tasks"
      tabIndex={-1}
      className="flex min-w-0 flex-1 flex-col bg-canvas outline-none"
    >
      <header className="@container flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-panel px-6">
        <div className="flex flex-1 basis-0 items-center gap-4">
          <h1 className="text-sm font-semibold text-fg">My tasks</h1>
          <nav aria-label="Which tasks" className="flex gap-1">
            {VIEWS.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-current={item.id === view ? 'page' : undefined}
                onClick={() => setView(item.id)}
                className={[
                  'px-2.5 py-1 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                  item.id === view ? 'bg-accent-soft text-accent' : 'text-fg-muted hover:bg-canvas hover:text-fg',
                ].join(' ')}
              >
                {item.label}
                {item.id === 'mine' && count.mine > 0 && (
                  <span className="ml-1.5 bg-med-line px-1 font-mono text-[11px] text-canvas">{count.mine}</span>
                )}
              </button>
            ))}
          </nav>
        </div>
        <SearchBar />
        <div className="flex flex-1 basis-0 justify-end">
          <button
            type="button"
            onClick={onClose}
            aria-label="Close my tasks"
            title="Close my tasks"
            className="p-1.5 text-fg-muted transition-colors hover:bg-canvas hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </header>

      <div className="flex min-h-0 flex-1 flex-col min-[900px]:flex-row">
        <div className="max-h-[40vh] shrink-0 overflow-y-auto border-b border-line min-[900px]:max-h-none min-[900px]:w-[360px] min-[900px]:border-b-0 min-[900px]:border-r">
          {error ? (
            <p role="alert" className="p-4 text-sm text-high-fg">
              {error}
            </p>
          ) : tasks === null ? (
            <div className="p-4">
              <Wait>Loading tasks…</Wait>
            </div>
          ) : tasks.length === 0 ? (
            <div className="p-4">
              <EmptyState
                skull
                title={view === 'mine' ? 'Nothing waits for you' : 'No task here'}
                message={
                  view === 'mine'
                    ? 'A task appears here when a playbook or a colleague gives you something to do, or asks you a question.'
                    : 'Tasks are made by the Task and Question nodes of playbooks, and by hand in the work plan of an incident.'
                }
              />
            </div>
          ) : (
            <ul aria-label="Tasks" className="flex flex-col divide-y divide-line-soft">
              {tasks.map((task) => {
                const badge = statusBadge(task)
                const due = dueText(task)
                return (
                  <li
                    key={task.id}
                    onContextMenu={(event) =>
                      menu(event, {
                        title: task.title,
                        actions: [
                          { label: 'Open', icon: FolderOpen, onSelect: () => onSelect(task.id) },
                          task.incidentId &&
                            onOpenIncident && {
                              label: 'Open the incident',
                              icon: FolderClosed,
                              onSelect: () => onOpenIncident(task.incidentId),
                            },
                        ],
                        link: tasksPath(task.id),
                        copy: [{ label: 'Copy the title', text: task.title }],
                      })
                    }
                  >
                    <button
                      type="button"
                      aria-current={task.id === taskId ? 'true' : undefined}
                      onClick={() => onSelect(task.id)}
                      className={[
                        'flex w-full flex-col gap-1 px-4 py-2.5 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                        task.id === taskId ? 'bg-accent-soft' : 'hover:bg-raised',
                      ].join(' ')}
                    >
                      <span className="flex items-center gap-2">
                        <Badge color={badge.color}>{badge.label}</Badge>
                        {due && (
                          <span
                            className={`font-mono text-[11px] ${task.status === 'overdue' ? 'text-high' : 'text-fg-muted'}`}
                          >
                            {due}
                          </span>
                        )}
                      </span>
                      <span className="text-sm font-medium text-fg">{task.title}</span>
                      <span className="truncate text-xs text-fg-muted">
                        {task.incidentName
                          ? numberedName({ number: task.incidentNumber, name: task.incidentName })
                          : 'no incident'}{' '}
                        · for {task.for}
                      </span>
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
        </div>
        <div className="min-h-0 min-w-0 flex-1 overflow-y-auto p-6">
          {taskId ? (
            <div className="max-w-3xl">
              <TaskCard taskId={taskId} onOpenIncident={onOpenIncident} />
            </div>
          ) : (
            tasks?.length === 0 && <p className="text-sm text-fg-muted">Choose a task to see it here.</p>
          )}
        </div>
      </div>
    </section>
  )
}
