import { useCallback, useEffect, useMemo, useState } from 'react'
import { ArrowLeft, OctagonX } from 'lucide-react'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { entryOf, headingOf } from '../../domain/automation/catalog.js'
import { nodeOf, normalise } from '../../domain/automation/graph.js'
import {
  RUN_COLORS,
  STEP_COLORS,
  duration,
  isFinished,
  nodeStatuses,
  stepLine,
  triggerLabel,
} from '../../domain/automation/runs.js'
import { interruptedSteps, restartLines, runStatus } from '../../domain/restarts.js'
import { formatDateTime } from '../../lib/time.js'
import { useObjectMenu } from '../menu/useObjectMenu.js'
import { Badge, Button, EmptyState, Modal } from '../ui/index.js'
import ApprovalBanner from './ApprovalBanner.jsx'
import InterruptedBanner from './InterruptedBanner.jsx'
import Canvas from './Canvas.jsx'
import DebugPanel, { DebugStepTools } from './DebugPanel.jsx'
import { SectionTitle } from './fields.jsx'
import { numberedName } from '../../domain/incidentName.js'
import JsonBlock from '../ui/JsonBlock.jsx'
import ResizeHandle, { useResizablePane } from '../ui/ResizeHandle.jsx'

/*
 * ============================================================================
 * A RUN — the playbook as it went
 * ============================================================================
 *
 * The canvas of the version the run uses, read-only, each node coloured by
 * what happened to it. Beside it the steps in the order they were taken; a
 * step (or its node) shows what went in, what came out, what was sent, the
 * tries and the script's log. A run still going is read again every two
 * seconds; an approval that waits is answered here, and so is a step a
 * restart of the server interrupted (InterruptedBanner). A step says what
 * restarts did to it: when it was interrupted, when it started again.
 *
 * A dry run stops before every action that would change or send something
 * and shows what it would have done. A debug run also stops before its
 * nodes, and is told what to do from the debugger above the canvas.
 */

const REFRESH_MS = 2000

function Json({ label, value }) {
  if (value === null || value === undefined || (typeof value === 'object' && Object.keys(value).length === 0))
    return null
  return (
    <div className="flex flex-col gap-1">
      <SectionTitle>{label}</SectionTitle>
      <JsonBlock value={value} what={label.toLowerCase()} className="max-h-64 border border-line bg-sunken text-xs" />
    </div>
  )
}

function StepDetail({ step, node, entry, dryRun }) {
  return (
    <div className="flex flex-col gap-3">
      <div>
        <h3 className="text-sm font-semibold text-fg">{node?.name || step.node}</h3>
        <p className="font-mono text-[11px] text-fg-muted">
          {node ? headingOf(node, entry) : step.kind} · <span className="text-fg-subtle">{step.node}</span>
        </p>
      </div>
      <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
        <dt className="text-fg-muted">Status</dt>
        <dd>
          <Badge color={STEP_COLORS[step.status] ?? 'slate'}>{step.status}</Badge>
          {step.port && step.port !== 'out' ? (
            <span className="ml-2 font-mono text-fg-muted">→ {step.port}</span>
          ) : null}
        </dd>
        {step.maxAttempts > 1 || step.attempt > 1 ? (
          <>
            <dt className="text-fg-muted">Tries</dt>
            <dd className="font-mono">
              {step.attempt} of {step.maxAttempts}
            </dd>
          </>
        ) : null}
        {step.itemIndex !== null && step.itemIndex !== undefined ? (
          <>
            <dt className="text-fg-muted">Item</dt>
            <dd className="font-mono">{step.itemIndex + 1}</dd>
          </>
        ) : null}
        {step.startedAt && (
          <>
            <dt className="text-fg-muted">Started</dt>
            <dd className="font-mono">{formatDateTime(Date.parse(step.startedAt))}</dd>
          </>
        )}
        {step.startedAt && step.finishedAt && (
          <>
            <dt className="text-fg-muted">Took</dt>
            <dd className="font-mono">{duration(step.startedAt, step.finishedAt)}</dd>
          </>
        )}
        {step.status === 'pending' && step.nextAt ? (
          <>
            <dt className="text-fg-muted">Next try</dt>
            <dd className="font-mono">{formatDateTime(step.nextAt * 1000)}</dd>
          </>
        ) : null}
      </dl>
      {step.error && (
        <p
          role="alert"
          className="whitespace-pre-wrap break-words border border-high-line bg-high-soft p-2 text-xs text-high-fg"
        >
          {step.error}
        </p>
      )}
      {step.restarts?.length > 0 && (
        <div className="flex flex-col gap-1">
          <SectionTitle>Restarts</SectionTitle>
          <ol aria-label="What restarts did to this step" className="flex flex-col gap-0.5 text-xs text-fg-muted">
            {restartLines(step.restarts, formatDateTime).map((line, index) => (
              <li key={index}>{line}</li>
            ))}
          </ol>
        </div>
      )}
      {dryRun && step.request ? (
        <p className="border border-violet-line bg-violet-soft p-2 text-xs text-fg">
          A dry run: this was not sent. It is what the node would have done.
        </p>
      ) : null}
      <Json label={dryRun ? 'Would have sent' : 'Sent'} value={step.request} />
      <Json label="Went in" value={step.input} />
      <Json label="Came out" value={step.output} />
      <Json label="Log" value={step.log} />
    </div>
  )
}

/**
 * @param {{
 *   id: string,
 *   onBack: () => void,
 *   onOpenPlaybook: (id: string, branch?: string | null) => void,  // the branch a debug run was of
 *   onOpenIncident: (id: string) => void,
 * }} props
 */
export default function RunPage({ id, onBack, onOpenPlaybook, onOpenIncident }) {
  const { catalog, loadCatalog, refreshApprovals } = useAutomation()
  const { incidents } = useIncidents()
  const { showToast } = useToast()
  const menu = useObjectMenu()
  const [run, setRun] = useState(null)
  const stepsPane = useResizablePane('automation.run-steps', { initial: 380, min: 300, max: 720, edge: 'left' })
  const [error, setError] = useState(null)
  const [stepId, setStepId] = useState(null)
  const [selection, setSelection] = useState(null)
  const [stopping, setStopping] = useState(false)
  const [confirmStop, setConfirmStop] = useState(false)

  const load = useCallback(async () => {
    try {
      setRun(await api.get(`/automation/runs/${encodeURIComponent(id)}`))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [id])
  useEffect(() => {
    setRun(null)
    setStepId(null)
    load()
    loadCatalog().catch(() => {})
  }, [load, loadCatalog])
  const going = Boolean(run && !isFinished(run.status))
  useEffect(() => {
    if (!going) return undefined
    const timer = setInterval(load, REFRESH_MS)
    return () => clearInterval(timer)
  }, [going, load])

  const graph = useMemo(() => normalise(run?.graph), [run?.graph])
  const statuses = useMemo(() => nodeStatuses(run?.steps), [run?.steps])
  const step = run?.steps.find((item) => item.id === stepId) ?? null
  const waiting = (run?.approvals ?? []).filter((approval) => approval.status === 'waiting')
  const interrupted = interruptedSteps(run?.steps)
  const answered = (run?.approvals ?? []).filter((approval) => approval.status !== 'waiting')
  const incident = run?.incidentId ? incidents.find((item) => item.id === run.incidentId) : null

  // The count on the rail and the banner on the incident follow what this run asks.
  const waitingCount = waiting.length
  useEffect(() => {
    refreshApprovals()
  }, [waitingCount, refreshApprovals])

  const selectStep = (item) => {
    setStepId(item.id)
    setSelection({ ids: [item.node] })
  }
  // A node chosen on the canvas shows its last step.
  const onSelectNodes = useCallback(
    (ids) => {
      if (ids.length !== 1) return
      const last = [...(run?.steps ?? [])].reverse().find((item) => item.node === ids[0])
      if (last)
        setStepId((current) => (run.steps.find((item) => item.id === current)?.node === ids[0] ? current : last.id))
    },
    [run?.steps],
  )

  const stop = async () => {
    setStopping(true)
    try {
      await api.post(`/automation/runs/${encodeURIComponent(id)}/stop`)
      setConfirmStop(false)
      showToast({ message: 'The run was stopped.' })
      await load()
      refreshApprovals()
    } catch (failure) {
      showToast({ message: failure.message })
    } finally {
      setStopping(false)
    }
  }

  if (error && !run) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <EmptyState
          skull="error"
          title="This run cannot be opened"
          message={error}
          action={
            <Button icon={ArrowLeft} onClick={onBack}>
              All runs
            </Button>
          }
        />
      </div>
    )
  }
  if (!run) {
    return (
      <p role="status" className="p-6 font-mono text-sm text-fg-muted">
        Loading the run…
      </p>
    )
  }

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <Button variant="ghost" size="sm" icon={ArrowLeft} aria-label="All runs" title="All runs" onClick={onBack} />
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold text-fg">
              {run.playbook || 'A deleted playbook'} · run of {formatDateTime(Date.parse(run.startedAt))}
            </h2>
            <p className="font-mono text-xs text-fg-muted">
              {run.playbookId ? (
                <button
                  type="button"
                  onClick={() => onOpenPlaybook(run.playbookId, run.branch?.id ?? null)}
                  className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  {run.branch
                    ? `its branch ${run.branch.name}`
                    : run.debug?.draft
                      ? 'its draft'
                      : `version ${run.version}`}
                </button>
              ) : (
                `version ${run.version}`
              )}{' '}
              · started {triggerLabel(run) === 'by hand' ? 'by hand' : `by ${triggerLabel(run)}`}
              {run.startedBy ? ` (${run.startedBy})` : ''}
              {run.incidentId && (
                <>
                  {' · on '}
                  {incident ? (
                    <button
                      type="button"
                      onClick={() => onOpenIncident(run.incidentId)}
                      className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {numberedName(incident)}
                    </button>
                  ) : (
                    'an incident that is gone'
                  )}
                </>
              )}
              {' · '}
              {duration(run.startedAt, run.finishedAt)}
            </p>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {run.dryRun && !run.debug && <Badge color="violet">dry run</Badge>}
          {run.branch && (
            <Badge color="amber" title="A debug run of a branch: the only run a branch has">
              branch: {run.branch.name}
            </Badge>
          )}
          <span role="status" aria-label="Status of the run">
            <Badge color={RUN_COLORS[run.status] ?? 'slate'}>
              {run.status === 'waiting' && interrupted.length
                ? 'interrupted by a restart'
                : run.status === 'waiting' && waiting.length
                  ? 'waiting for approval'
                  : run.status === 'waiting' && run.debug?.at?.length
                    ? 'stopped at a node'
                    : runStatus(run)}
            </Badge>
          </span>
          {going && !run.debug && (
            <Button variant="secondary" size="sm" icon={OctagonX} onClick={() => setConfirmStop(true)}>
              Stop the run
            </Button>
          )}
        </div>
      </div>

      {(run.error || waiting.length > 0 || interrupted.length > 0) && (
        <div className="flex shrink-0 flex-col gap-2 border-b border-line px-4 py-3">
          {run.error && (
            <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
              {run.error}
            </p>
          )}
          {interrupted.map((item) => (
            <InterruptedBanner
              key={item.id}
              runId={run.id}
              step={item}
              name={nodeOf(graph, item.node)?.name || item.node}
              sent={item.input}
              onAnswered={load}
            />
          ))}
          {waiting.map((approval) => (
            <ApprovalBanner key={approval.id} approval={approval} onAnswered={load} />
          ))}
        </div>
      )}

      {run.debug && <DebugPanel run={run} graph={graph} onChanged={load} />}

      <div className="flex min-h-0 flex-1 flex-col lg:flex-row">
        <div className="min-h-[300px] min-w-0 flex-1">
          <Canvas
            graph={graph}
            catalog={catalog.nodes}
            statuses={statuses}
            readOnly
            selection={selection}
            onSelect={onSelectNodes}
          />
        </div>
        <ResizeHandle {...stepsPane.handle} label="Resize the steps of the run" className="hidden lg:block" />
        <aside
          aria-label="Steps of the run"
          style={stepsPane.style}
          className="flex min-h-0 w-full shrink-0 flex-col border-l border-line bg-panel lg:w-[var(--pane-w)]"
        >
          <div className="max-h-[45%] min-h-[120px] shrink-0 overflow-y-auto border-b border-line p-3">
            <SectionTitle>Steps</SectionTitle>
            {run.steps.length === 0 && <p className="mt-2 text-xs text-fg-muted">No step has been taken yet.</p>}
            <ol className="mt-2 flex flex-col">
              {run.steps.map((item) => {
                const node = nodeOf(graph, item.node)
                const on = item.id === stepId
                return (
                  <li
                    key={item.id}
                    onContextMenu={(event) =>
                      menu(event, {
                        title: node?.name || item.node,
                        actions: [{ label: 'Show what this step did', onSelect: () => selectStep(item) }],
                        copy: [
                          { label: 'Copy the name of the node', text: node?.name || item.node },
                          { label: 'Copy the error', text: item.error },
                        ],
                      })
                    }
                  >
                    <button
                      type="button"
                      aria-pressed={on}
                      onClick={() => selectStep(item)}
                      className={[
                        'grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-2 border-b border-line-soft px-1 py-1.5 text-left text-xs',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
                        on ? 'bg-accent-soft/50' : 'hover:bg-raised/60',
                      ].join(' ')}
                    >
                      <Badge color={STEP_COLORS[item.status] ?? 'slate'}>{item.status}</Badge>
                      <span className="min-w-0">
                        <span className="block truncate text-fg">{node?.name || item.node}</span>
                        <span className="block truncate text-fg-muted">{stepLine(item)}</span>
                      </span>
                      <time className="whitespace-nowrap font-mono text-[11px] text-fg-subtle">
                        {item.startedAt ? new Date(item.startedAt).toLocaleTimeString() : ''}
                      </time>
                    </button>
                  </li>
                )
              })}
            </ol>
            {answered.length > 0 && (
              <div className="mt-3 flex flex-col gap-1">
                <SectionTitle>Approvals</SectionTitle>
                {answered.map((approval) => (
                  <p key={approval.id} className="text-xs text-fg-muted">
                    <Badge
                      color={
                        approval.status === 'approved' ? 'emerald' : approval.status === 'refused' ? 'red' : 'slate'
                      }
                    >
                      {approval.status}
                    </Badge>{' '}
                    {approval.question}
                    {approval.answeredBy ? ` · ${approval.answeredBy}` : ''}
                    {approval.comment ? `: “${approval.comment}”` : ''}
                  </p>
                ))}
              </div>
            )}
          </div>
          <div className="min-h-0 flex-1 overflow-y-auto p-3">
            {step && run.debug && <DebugStepTools run={run} graph={graph} step={step} onChanged={load} />}
            {step ? (
              <StepDetail
                step={step}
                node={nodeOf(graph, step.node)}
                entry={entryOf(nodeOf(graph, step.node), catalog.nodes)}
                dryRun={run.dryRun}
              />
            ) : (
              <p className="text-xs text-fg-muted">
                Choose a step, or a node on the canvas, to see what went in and what came out.
              </p>
            )}
          </div>
        </aside>
      </div>

      <Modal
        open={confirmStop}
        onClose={() => setConfirmStop(false)}
        title="Stop this run?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirmStop(false)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={stopping} onClick={stop}>
              Stop the run
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          What is still to do is skipped. A step already talking to another system finishes, and what it gives is
          discarded; what was done before stays done.
        </p>
      </Modal>
    </div>
  )
}
