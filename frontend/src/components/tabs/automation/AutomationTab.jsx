import { useCallback, useEffect, useState } from 'react'
import { Play, RefreshCw } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useAutomation } from '../../../context/AutomationContext.jsx'
import { api } from '../../../services/api.js'
import { automationPath } from '../../../domain/automationNav.js'
import { RUN_COLORS, duration, isFinished, triggerLabel } from '../../../domain/automation/runs.js'
import { setPath } from '../../../lib/location.js'
import { formatDateTime } from '../../../lib/time.js'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { usePageMenu } from '../../menu/usePageMenu.js'
import { Badge, Button } from '../../ui/index.js'

/*
 * ============================================================================
 * AUTOMATION — the runs that worked on this incident
 * ============================================================================
 *
 * What playbooks did here: each run with what started it, how it ended and
 * when; a run opens on its own page (the canvas coloured by what happened).
 * "Run a playbook…" starts one by hand on this incident. An approval that
 * waits on one of these runs is shown above the tabs, wherever the incident
 * is open.
 */

const REFRESH_MS = 5000

export default function AutomationTab({ incident }) {
  const { can } = useAuth()
  const { askRun, approvals } = useAutomation()
  const [runs, setRuns] = useState(null)
  const [error, setError] = useState(null)

  const load = useCallback(async () => {
    try {
      const found = await api.get(`/incidents/${encodeURIComponent(incident.id)}/runs`)
      setRuns(found.runs)
      setError(null)
    } catch (failure) {
      // An incident not saved yet has no run.
      if (failure.status === 404) setRuns([])
      else setError(failure.message)
    }
  }, [incident.id])
  useEffect(() => {
    setRuns(null)
    load()
  }, [load])
  // A run still going, or an approval just answered: the list follows.
  const active = Boolean(runs?.some((run) => !isFinished(run.status)))
  const waitingHere = approvals.filter((approval) => approval.incidentId === incident.id).length
  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(load, REFRESH_MS)
    return () => clearInterval(timer)
  }, [active, load])
  useEffect(() => {
    load()
  }, [waitingHere, load])

  const menu = useObjectMenu()
  const pageMenu = usePageMenu(() => [
    { label: 'Refresh', icon: RefreshCw, onSelect: load },
    {
      label: 'Run a playbook…',
      icon: Play,
      onSelect: () => askRun({ incidentId: incident.id, incidentName: incident.name }),
    },
  ])

  if (!can('automation.run')) {
    return <p className="text-sm text-fg-muted">Your roles do not include running playbooks.</p>
  }

  return (
    <div className="flex flex-col gap-4" onContextMenu={pageMenu}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-base font-semibold text-fg">Automation</h2>
          <p className="text-sm text-fg-muted">The runs of playbooks that worked on this incident, newest first.</p>
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={load}>
            Refresh
          </Button>
          <Button
            size="sm"
            icon={Play}
            onClick={() => askRun({ incidentId: incident.id, incidentName: incident.name })}
          >
            Run a playbook…
          </Button>
        </div>
      </div>

      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {!runs && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the runs…
        </p>
      )}
      {runs?.length === 0 && (
        <p className="text-sm text-fg-muted">
          No playbook has run on this incident. One runs when its trigger matches what happens here, or when you run it
          by hand.
        </p>
      )}
      {runs?.length > 0 && (
        <div className="overflow-x-auto border border-line">
          <table className="w-full min-w-[640px] border-collapse text-left text-xs">
            <caption className="sr-only">Runs on this incident</caption>
            <thead className="bg-panel font-mono text-fg-muted">
              <tr>
                {['Playbook', 'Status', 'Started by', 'Started', 'Took'].map((heading) => (
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
              {runs.map((run) => (
                <tr
                  key={run.id}
                  className="hover:bg-raised/40"
                  onContextMenu={(event) =>
                    menu(event, {
                      title: run.playbook || 'a deleted playbook',
                      actions: [{ label: 'Open the run', onSelect: () => setPath(automationPath('runs', run.id)) }],
                      link: automationPath('runs', run.id),
                      copy: [{ label: 'Copy the id', text: run.id }],
                    })
                  }
                >
                  <th scope="row" className="border-b border-line-soft px-3 py-2 font-normal">
                    <button
                      type="button"
                      onClick={() => setPath(automationPath('runs', run.id))}
                      className="text-left text-sm font-medium text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {run.playbook || 'a deleted playbook'}
                    </button>
                    <span className="ml-2 font-mono text-fg-subtle">v{run.version}</span>
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
    </div>
  )
}
