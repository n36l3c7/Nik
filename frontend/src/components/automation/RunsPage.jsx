import { useCallback, useEffect, useMemo, useState } from 'react'
import { FolderClosed, FolderOpen, RefreshCw, Workflow } from 'lucide-react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { api } from '../../services/api.js'
import { RUN_COLORS, RUN_STATUSES, duration, isFinished, triggerLabel } from '../../domain/automation/runs.js'
import { formatDateTime } from '../../lib/time.js'
import { Badge, Button, EmptyState } from '../ui/index.js'
import { SelectInput } from './fields.jsx'
import { useObjectMenu } from '../menu/useObjectMenu.js'
import { usePageMenu } from '../menu/usePageMenu.js'
import { automationPath } from '../../domain/automationNav.js'
import { setPath } from '../../lib/location.js'

/*
 * The runs: every one (the Runs screen), or those of one playbook (its Runs
 * tab). Newest first, narrowed by status and playbook; a run in progress is
 * read again every few seconds.
 */

const PAGE = 50
const REFRESH_MS = 5000

/**
 * @param {{
 *   playbookId?: string | null,                  // only the runs of this playbook
 *   playbooks?: Array<{ id: string, name: string }>,
 *   onOpenRun: (id: string) => void,
 *   onOpenIncident?: (id: string) => void,
 * }} props
 */
export default function RunsPage({ playbookId = null, playbooks = [], onOpenRun, onOpenIncident }) {
  const menu = useObjectMenu()
  const { incidents } = useIncidents()
  const [status, setStatus] = useState('')
  const [playbook, setPlaybook] = useState('')
  const [limit, setLimit] = useState(PAGE)
  const [debug, setDebug] = useState(false) // the runs of the debugger instead: one's own
  const [found, setFound] = useState(null) // { runs, total }
  const [error, setError] = useState(null)
  const names = useMemo(() => new Map(incidents.map((incident) => [incident.id, incident.name])), [incidents])

  const load = useCallback(async () => {
    const query = new URLSearchParams({ limit: String(limit) })
    if (status) query.set('status', status)
    if (playbookId || playbook) query.set('playbook', playbookId || playbook)
    if (debug) query.set('debug', 'true')
    try {
      setFound(await api.get(`/automation/runs?${query}`))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [limit, status, playbook, playbookId, debug])
  useEffect(() => {
    load()
  }, [load])
  // While something is still going, the list follows it.
  const active = Boolean(found?.runs.some((run) => !isFinished(run.status)))
  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(load, REFRESH_MS)
    return () => clearInterval(timer)
  }, [active, load])

  const pageMenu = usePageMenu(() => [{ label: 'Refresh', icon: RefreshCw, onSelect: load }])

  return (
    <div className="flex flex-col gap-4 p-6" onContextMenu={pageMenu}>
      <div className="flex flex-wrap items-end gap-3">
        <label className="flex flex-col gap-1 text-xs text-fg-muted">
          Status
          <SelectInput
            value={status}
            onChange={(next) => {
              setStatus(next)
              setLimit(PAGE)
            }}
            options={[
              { value: '', label: 'every status' },
              ...RUN_STATUSES.map((item) => ({ value: item, label: item })),
            ]}
          />
        </label>
        {!playbookId && (
          <label className="flex flex-col gap-1 text-xs text-fg-muted">
            Playbook
            <SelectInput
              value={playbook}
              onChange={(next) => {
                setPlaybook(next)
                setLimit(PAGE)
              }}
              options={[
                { value: '', label: 'every playbook' },
                ...playbooks.map((item) => ({ value: item.id, label: item.name })),
              ]}
            />
          </label>
        )}
        <label className="flex items-center gap-2 pb-1.5 text-xs text-fg-muted">
          <input
            type="checkbox"
            checked={debug}
            onChange={(event) => {
              setDebug(event.target.checked)
              setLimit(PAGE)
            }}
            className="h-4 w-4 accent-[var(--color-accent)]"
          />
          Debug runs
        </label>
        <Button variant="secondary" size="sm" icon={RefreshCw} onClick={load}>
          Refresh
        </Button>
        {found && (
          <span role="status" className="ml-auto font-mono text-xs text-fg-muted">
            {found.total} {found.total === 1 ? 'run' : 'runs'}
          </span>
        )}
      </div>

      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {!found && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the runs…
        </p>
      )}
      {found?.runs.length === 0 &&
        (debug ? (
          <EmptyState
            skull
            title="No debug run"
            message="No debug run of yours is kept: they are deleted after a week."
          />
        ) : status || playbook ? (
          <EmptyState
            skull
            title="No run matches"
            message="No run matches. Change the status or the playbook asked for."
          />
        ) : (
          <EmptyState
            skull
            title="No run yet"
            message="Nothing has run yet. A playbook runs when its trigger fires, or when someone runs it by hand."
          />
        ))}
      {found?.runs.length > 0 && (
        <div className="overflow-x-auto border border-line">
          <table className="w-full min-w-[820px] border-collapse text-left text-xs">
            <caption className="sr-only">Runs</caption>
            <thead className="bg-panel font-mono text-fg-muted">
              <tr>
                {['Playbook', 'Status', 'Started by', 'On', 'Started', 'Took'].map((heading) => (
                  <th
                    key={heading}
                    scope="col"
                    className="whitespace-nowrap border-b border-line px-3 py-1.5 font-normal"
                  >
                    {heading}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {found.runs.map((run) => (
                <tr
                  key={run.id}
                  className="hover:bg-raised/40"
                  onContextMenu={(event) =>
                    menu(event, {
                      title: `${run.playbook || 'a deleted playbook'} · ${formatDateTime(Date.parse(run.startedAt))}`,
                      actions: [
                        { label: 'Open the run', icon: FolderOpen, onSelect: () => onOpenRun(run.id) },
                        run.playbookId && {
                          label: 'Open the playbook',
                          icon: Workflow,
                          onSelect: () => setPath(automationPath('playbooks', run.playbookId)),
                        },
                        run.incidentId &&
                          onOpenIncident &&
                          names.has(run.incidentId) && {
                            label: 'Open the incident',
                            icon: FolderClosed,
                            onSelect: () => onOpenIncident(run.incidentId),
                          },
                      ],
                      link: automationPath('runs', run.id),
                      copy: [{ label: 'Copy the id', text: run.id }],
                    })
                  }
                >
                  <th scope="row" className="border-b border-line-soft px-3 py-2 font-normal">
                    <button
                      type="button"
                      onClick={() => onOpenRun(run.id)}
                      aria-label={`Open the run of ${run.playbook} started ${formatDateTime(Date.parse(run.startedAt))}`}
                      className="text-left text-sm font-medium text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {run.playbook || 'a deleted playbook'}
                    </button>
                    {run.branch ? (
                      <Badge color="amber" className="ml-2">
                        branch: {run.branch.name}
                      </Badge>
                    ) : (
                      <span className="ml-2 font-mono text-fg-subtle">v{run.version}</span>
                    )}
                    {run.dryRun && (
                      <Badge color="violet" className="ml-2">
                        dry run
                      </Badge>
                    )}
                  </th>
                  <td className="border-b border-line-soft px-3 py-2">
                    <Badge color={RUN_COLORS[run.status] ?? 'slate'}>{run.status}</Badge>
                    {run.error && <span className="ml-2 text-high-fg">{run.error}</span>}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 text-fg-muted">
                    {triggerLabel(run)}
                    {run.startedBy ? <span className="font-mono"> · {run.startedBy}</span> : null}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2">
                    {run.incidentId ? (
                      onOpenIncident && names.has(run.incidentId) ? (
                        <button
                          type="button"
                          onClick={() => onOpenIncident(run.incidentId)}
                          className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          {names.get(run.incidentId)}
                        </button>
                      ) : (
                        <span className="text-fg-muted">{names.get(run.incidentId) ?? 'an incident that is gone'}</span>
                      )
                    ) : (
                      <span className="text-fg-muted">—</span>
                    )}
                  </td>
                  <td className="whitespace-nowrap border-b border-line-soft px-3 py-2 font-mono text-fg-muted">
                    {formatDateTime(Date.parse(run.startedAt))}
                  </td>
                  <td className="whitespace-nowrap border-b border-line-soft px-3 py-2 font-mono text-fg-muted">
                    {duration(run.startedAt, run.finishedAt)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {found && found.runs.length < found.total && (
        <Button
          variant="secondary"
          size="sm"
          className="self-start"
          onClick={() => setLimit((current) => Math.min(current + PAGE, 200))}
        >
          Show more
        </Button>
      )}
    </div>
  )
}
