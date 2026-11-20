import { useState } from 'react'
import { Bug } from 'lucide-react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { api } from '../../services/api.js'
import { Button, Modal } from '../ui/index.js'

/*
 * Debug on…: start a debug run of a playbook, of its saved version or of its
 * draft as it is drawn, on an incident or on nothing. The run opens on its
 * page, stopped before its first node.
 *
 * On a branch there is nothing to choose: the branch is what runs, as it is
 * saved, and a debug run is the only run it has.
 */

const FIELD =
  'h-8 w-full min-w-0 border border-line bg-canvas px-2 text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   playbook: { id: string, name: string, version: number | null, draft: object | null },
 *   branch?: { id: string, name: string } | null,  // the branch on the canvas: it is what is debugged
 *   breakpoints?: string[],            // the nodes selected on the canvas: where to stop
 *   onStarted: (runId: string) => void,
 *   onClose: () => void,
 * }} props
 */
export default function DebugDialog({ playbook, branch = null, breakpoints = [], onStarted, onClose }) {
  const { incidents, activeIncidentId } = useIncidents()
  const hasDraft = Boolean(playbook.draft)
  const [what, setWhat] = useState(hasDraft ? 'draft' : 'version')
  const [incident, setIncident] = useState(activeIncidentId ?? '')
  const [every, setEvery] = useState(breakpoints.length === 0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [problems, setProblems] = useState([])

  const start = () => {
    setBusy(true)
    setError(null)
    setProblems([])
    api
      .post(`/automation/playbooks/${encodeURIComponent(playbook.id)}/debug`, {
        objectKind: incident ? 'incident' : '',
        objectId: incident,
        ...(branch ? { branch: branch.id } : { draft: what === 'draft' }),
        stepMode: every,
        breakpoints,
      })
      .then(
        (run) => onStarted(run.id),
        (failure) => {
          const detail = failure.data?.detail
          setError(typeof detail === 'object' && detail ? detail.message : failure.message)
          setProblems(typeof detail === 'object' && detail ? (detail.problems ?? []) : [])
        },
      )
      .finally(() => setBusy(false))
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Debug "${playbook.name}"`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button waiting={busy} icon={Bug} onClick={start} disabled={busy}>
            {busy ? 'Starting…' : 'Start debugging'}
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm">
        <p className="text-fg-muted">
          A debug run stops before its nodes and waits to be told what to do. What it would send outside is held, as in
          a dry run, unless you let one node through. It counts for no limit and is deleted after a week.
        </p>
        {branch && (
          <p className="text-fg">
            <span className="mb-1 block text-xs font-medium text-fg-muted">What to run</span>
            The branch <span className="font-mono">{branch.name}</span>, as it is saved. A branch runs only here: no
            trigger, no schedule and no “Run…” starts it until it is pushed to main.
          </p>
        )}
        {!branch && (
          <fieldset className="space-y-1.5">
            <legend className="mb-1 text-xs font-medium text-fg-muted">What to run</legend>
            <label className="flex items-center gap-2 text-fg">
              <input
                type="radio"
                name="debug-what"
                checked={what === 'draft'}
                disabled={!hasDraft}
                onChange={() => setWhat('draft')}
                className="h-4 w-4 accent-[var(--color-accent)]"
              />
              The draft, as it is drawn now{hasDraft ? '' : ' (there is none)'}
            </label>
            <label className="flex items-center gap-2 text-fg">
              <input
                type="radio"
                name="debug-what"
                checked={what === 'version'}
                disabled={!playbook.version}
                onChange={() => setWhat('version')}
                className="h-4 w-4 accent-[var(--color-accent)]"
              />
              {playbook.version
                ? `Version ${playbook.version}, the one in use`
                : 'The saved version (there is none yet)'}
            </label>
          </fieldset>
        )}
        <label className="block">
          <span className="mb-1 block text-xs font-medium text-fg-muted">On</span>
          <select value={incident} onChange={(event) => setIncident(event.target.value)} className={FIELD}>
            <option value="">Nothing: the playbook is given no object</option>
            {incidents.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <fieldset className="space-y-1.5">
          <legend className="mb-1 text-xs font-medium text-fg-muted">Where to stop</legend>
          <label className="flex items-center gap-2 text-fg">
            <input
              type="radio"
              name="debug-stop"
              checked={every}
              onChange={() => setEvery(true)}
              className="h-4 w-4 accent-[var(--color-accent)]"
            />
            Before every node, one at a time
          </label>
          <label className="flex items-center gap-2 text-fg">
            <input
              type="radio"
              name="debug-stop"
              checked={!every}
              disabled={breakpoints.length === 0}
              onChange={() => setEvery(false)}
              className="h-4 w-4 accent-[var(--color-accent)]"
            />
            {breakpoints.length
              ? `Before the ${breakpoints.length === 1 ? 'node' : `${breakpoints.length} nodes`} selected on the canvas`
              : 'Before the nodes selected on the canvas (none is selected)'}
          </label>
          <p className="text-xs text-fg-muted">Breakpoints can be moved while the run is stopped.</p>
        </fieldset>
        {error && (
          <div role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high-fg">
            <p>{error}</p>
            {problems.length > 0 && (
              <ul className="mt-1 list-disc pl-5 text-xs">
                {problems.slice(0, 8).map((problem, index) => (
                  <li key={index}>{problem.message}</li>
                ))}
              </ul>
            )}
          </div>
        )}
      </div>
    </Modal>
  )
}
