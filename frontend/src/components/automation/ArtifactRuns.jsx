import { useCallback, useEffect, useState } from 'react'
import { Play } from 'lucide-react'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { api } from '../../services/api.js'
import { automationPath } from '../../domain/automationNav.js'
import { RUN_COLORS, artifactTarget, isFinished } from '../../domain/automation/runs.js'
import { setPath } from '../../lib/location.js'
import { formatDateTime } from '../../lib/time.js'
import { Badge, Button } from '../ui/index.js'

/*
 * The playbooks that ran on an artifact (an analysed e-mail, file or address),
 * as a strip in the artifact's header: the last few runs, each opening on its
 * own page, and "Run a playbook…" to start one by hand on this artifact.
 *
 * Draws nothing for an account that may not run playbooks, and for a kind of
 * artifact no playbook runs on (a capture, a mailbox).
 */

const SHOWN = 5
const REFRESH_MS = 5000

/**
 * @param {{ artifact: { id: string, kind: string, name: string } }} props
 */
export default function ArtifactRuns({ artifact }) {
  const { allowed, askRun, runRequest } = useAutomation()
  const target = allowed ? artifactTarget(artifact) : null
  const [runs, setRuns] = useState(null)
  const [total, setTotal] = useState(0)

  const id = target?.id
  const load = useCallback(async () => {
    if (!id) return
    try {
      const found = await api.get(`/automation/runs?artifact=${encodeURIComponent(id)}&limit=${SHOWN}`)
      setRuns(found.runs)
      setTotal(found.total)
    } catch {
      setRuns([])
    }
  }, [id])
  // Read when the artifact opens, and again when "Run a playbook…" closes: a run may have started.
  const asking = Boolean(runRequest)
  useEffect(() => {
    if (!asking) load()
  }, [load, asking])
  const active = Boolean(runs?.some((run) => !isFinished(run.status)))
  useEffect(() => {
    if (!active) return undefined
    const timer = setInterval(load, REFRESH_MS)
    return () => clearInterval(timer)
  }, [active, load])

  if (!target) return null
  return (
    <div className="flex flex-wrap items-center gap-2" aria-label="Playbook runs on this artifact">
      <span className="w-20 shrink-0 font-mono text-[11px] tracking-wider text-fg-muted">PLAYBOOKS</span>
      {runs?.length === 0 && <span className="text-xs text-fg-muted">No playbook has run on this.</span>}
      {runs?.map((run) => (
        <button
          key={run.id}
          type="button"
          title={`Started ${formatDateTime(Date.parse(run.startedAt))} by ${run.startedBy || 'nik'}`}
          onClick={() => setPath(automationPath('runs', run.id))}
          className="inline-flex items-center gap-1.5 border border-line bg-canvas px-2 py-0.5 text-xs text-fg hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <span className="max-w-[220px] truncate">{run.playbook || 'A playbook'}</span>
          <Badge color={RUN_COLORS[run.status] ?? 'slate'}>{run.dryRun ? `dry · ${run.status}` : run.status}</Badge>
        </button>
      ))}
      {total > SHOWN && <span className="text-xs text-fg-muted">and {total - SHOWN} more</span>}
      <Button variant="ghost" size="xs" icon={Play} onClick={() => askRun({ object: target })}>
        Run a playbook…
      </Button>
    </div>
  )
}
