import { useCallback, useEffect, useId, useState } from 'react'
import { Bug, FastForward, OctagonX, RotateCcw, SkipForward, StepForward } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { nodeOf } from '../../domain/automation/graph.js'
import {
  argsText,
  canBreak,
  canRerun,
  debugLine,
  overridesOf,
  parseObject,
  parseValue,
  stoppedAt,
  toggleBreakpoint,
} from '../../domain/automation/debug.js'
import { isFinished } from '../../domain/automation/runs.js'
import { Badge, Button } from '../ui/index.js'
import { SectionTitle } from './fields.jsx'

/*
 * ============================================================================
 * DEBUGGER — a run that stops before its nodes, and is told what to do next
 * ============================================================================
 *
 * Two parts of the page of a debug run. The bar above the canvas says where
 * the run is and moves it: one node on, to the next breakpoint, past the
 * node, or to a stop; when it is stopped before a node, that node's
 * arguments can be changed for this once, and an action can be let through
 * for real. Beside the step that is selected (`DebugStepTools`): a
 * breakpoint on its node, running it again, and changing what the nodes
 * after it read.
 */

const TEXTAREA =
  'w-full border border-line bg-canvas p-2 font-mono text-xs text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** Tell the run what to do, then read it again: `[tell, busy]`. */
function useTell(run, onChanged) {
  const { showToast } = useToast()
  const [busy, setBusy] = useState(false)
  const tell = useCallback(
    async (action, body = {}) => {
      setBusy(true)
      try {
        await api.post(`/automation/runs/${encodeURIComponent(run.id)}/debug`, { action, ...body })
        await onChanged()
      } catch (failure) {
        showToast({ message: failure.message })
      } finally {
        setBusy(false)
      }
    },
    [run.id, onChanged, showToast],
  )
  return [tell, busy]
}

/**
 * @param {{
 *   run: object,                       // the run, as GET /automation/runs/<id> gives it
 *   graph: object,                     // its graph, normalised
 *   onChanged: () => Promise<void>,    // read the run again
 * }} props
 */
export default function DebugPanel({ run, graph, onChanged }) {
  const { can } = useAuth()
  const argsId = useId()
  const [tell, busy] = useTell(run, onChanged)
  const stopped = stoppedAt(run)
  const at = stopped.length === 1 ? stopped[0] : null
  const atNode = at ? nodeOf(graph, at.node) : null
  const over = isFinished(run.status)
  const nameOf = (id) => nodeOf(graph, id)?.name || id

  // The arguments of the node the run is stopped before, to be changed for this once.
  const [args, setArgs] = useState('')
  const [real, setReal] = useState(false)
  useEffect(() => {
    setArgs(argsText(at))
    setReal(false)
    // A new stop, new arguments: the step is its id.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [at?.id])
  const typed = parseObject(args)

  const go = (action) => {
    const body = at ? { stepId: at.id } : {}
    if (at && action !== 'skip') {
      const overrides = overridesOf(at, typed.value)
      if (overrides) body.overrides = overrides
      if (real) body.sendForReal = true
    }
    return tell(action, body)
  }
  const breakpoints = run.debug?.breakpoints ?? []
  const idle = !stopped.length || busy || Boolean(at && typed.error)

  return (
    <section aria-label="Debugger" className="flex shrink-0 flex-col gap-2 border-b border-line bg-panel px-4 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <Badge color="violet">
          <Bug className="mr-1 inline h-3 w-3" aria-hidden="true" />
          debug run
        </Badge>
        <p role="status" className="min-w-0 flex-1 truncate text-sm text-fg">
          {debugLine(run, nameOf)}
          {run.debug?.draft ? ' It runs the draft, as it was when the run started.' : ''}
        </p>
        {!over && (
          <>
            <Button
              size="sm"
              icon={StepForward}
              disabled={idle}
              onClick={() => go('step')}
              title="Run this node and stop before the next"
            >
              Step
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={FastForward}
              disabled={idle}
              onClick={() => go('continue')}
              title={
                breakpoints.length
                  ? `Go on to the next breakpoint (${breakpoints.map(nameOf).join(', ')}), or to the end`
                  : 'Go on to the end: there is no breakpoint'
              }
            >
              Continue
            </Button>
            <Button
              size="sm"
              variant="secondary"
              icon={SkipForward}
              disabled={!stopped.length || busy}
              onClick={() => go('skip')}
              title="Do not run this node: go on as if it had"
            >
              Skip
            </Button>
            <Button size="sm" variant="ghost" icon={OctagonX} disabled={busy} onClick={() => tell('stop')}>
              Stop
            </Button>
          </>
        )}
      </div>

      {at && atNode && !over && (
        <div className="grid items-start gap-3 lg:grid-cols-[minmax(0,1fr)_minmax(0,1fr)]">
          <div className="min-w-0">
            <label htmlFor={argsId} className="mb-1 block text-xs font-medium text-fg-muted">
              {argsText(at)
                ? `What ${nameOf(at.node)} will be given (change it for this once)`
                : `${nameOf(at.node)} takes no arguments`}
            </label>
            {argsText(at) ? (
              <textarea
                id={argsId}
                rows={Math.min(6, Math.max(2, args.split('\n').length))}
                value={args}
                spellCheck={false}
                onChange={(event) => setArgs(event.target.value)}
                aria-invalid={Boolean(typed.error)}
                className={TEXTAREA}
              />
            ) : (
              at.input &&
              Object.keys(at.input).length > 0 && (
                <pre className="max-h-28 overflow-auto border border-line bg-sunken p-2 font-mono text-xs text-fg">
                  {JSON.stringify(at.input, null, 2)}
                </pre>
              )
            )}
            {typed.error && <p className="mt-1 text-xs text-high">{typed.error}</p>}
            {at.input?.problem && <p className="mt-1 text-xs text-high">{at.input.problem}</p>}
          </div>
          {atNode.kind === 'action' && (
            <label className="flex items-start gap-2 pt-5 text-sm text-fg">
              <input
                type="checkbox"
                checked={real}
                disabled={!can('automation.run')}
                onChange={(event) => setReal(event.target.checked)}
                className="mt-0.5 h-4 w-4 accent-[var(--color-high-line)]"
              />
              <span>
                Send for real, this once
                <span className="block text-xs text-fg-muted">
                  {can('automation.run')
                    ? 'Otherwise this node shows what it would have sent, as in a dry run. For real, it asks the approval it normally needs.'
                    : 'It needs the permission to run playbooks.'}
                </span>
              </span>
            </label>
          )}
        </div>
      )}
    </section>
  )
}

/**
 * What the debugger offers for the step that is selected: a breakpoint on its node, running it again,
 * and changing what the nodes after it read.
 *
 * @param {{ run: object, graph: object, step: object, onChanged: () => Promise<void> }} props
 */
export function DebugStepTools({ run, graph, step, onChanged }) {
  const outputId = useId()
  const [tell, busy] = useTell(run, onChanged)
  const node = nodeOf(graph, step.node)
  // The breakpoints as they are being set: the box answers at once, the run follows.
  const held = JSON.stringify(run.debug?.breakpoints ?? [])
  const [breakpoints, setBreakpoints] = useState(() => JSON.parse(held))
  useEffect(() => setBreakpoints(JSON.parse(held)), [held])

  // What the node gave, to be changed for the nodes after it.
  const [output, setOutput] = useState('')
  useEffect(() => {
    const held = run.debug?.context?.[step.node]
    setOutput(held === undefined ? '' : JSON.stringify(held, null, 2))
    // The context is read when another step is chosen, not at every refresh (it would undo what is typed).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step.id, step.status])
  const patched = parseValue(output)

  if (!node || isFinished(run.status) || (!canBreak(node) && !canRerun(step, node))) return null
  return (
    <section aria-label="Debugging this node" className="mb-3 flex flex-col gap-2 border border-line bg-sunken p-2">
      <SectionTitle>Debugger</SectionTitle>
      <div className="flex flex-wrap items-center gap-3">
        {canBreak(node) && (
          <label className="flex items-center gap-2 text-xs text-fg">
            <input
              type="checkbox"
              checked={breakpoints.includes(step.node)}
              disabled={busy}
              onChange={() => {
                const next = toggleBreakpoint(breakpoints, step.node)
                setBreakpoints(next)
                tell('set', { breakpoints: next })
              }}
              className="h-4 w-4 accent-[var(--color-accent)]"
            />
            Stop before this node
          </label>
        )}
        {canRerun(step, node) && (
          <Button
            size="xs"
            variant="secondary"
            icon={RotateCcw}
            disabled={busy}
            onClick={() => tell('rerun', { stepId: step.id })}
          >
            Run this node again
          </Button>
        )}
      </div>
      {canRerun(step, node) && output !== '' && (
        <div>
          <label htmlFor={outputId} className="mb-1 block text-xs font-medium text-fg-muted">
            What it gave: change it, and the nodes after read what you wrote
          </label>
          <textarea
            id={outputId}
            rows={Math.min(6, Math.max(2, output.split('\n').length))}
            value={output}
            spellCheck={false}
            onChange={(event) => setOutput(event.target.value)}
            aria-invalid={Boolean(patched.error)}
            className={TEXTAREA}
          />
          {patched.error && <p className="mt-1 text-xs text-high">{patched.error}</p>}
          <Button
            size="xs"
            variant="secondary"
            className="mt-1"
            disabled={busy || patched.empty || Boolean(patched.error)}
            onClick={() => tell('set', { contextPatch: { [step.node]: patched.value } })}
          >
            Write it
          </Button>
        </div>
      )}
    </section>
  )
}
