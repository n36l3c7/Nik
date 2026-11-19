import { useCallback, useEffect, useRef, useState } from 'react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { api } from '../../../services/api.js'
import {
  WARN_RUNS,
  againLabel,
  mergeRuns,
  runLabel,
  shownValue,
  sourceText,
  tally,
  tookText,
} from '../../../domain/scriptButtons.js'
import { Button, Modal } from '../../ui/index.js'

/*
 * ============================================================================
 * SCRIPT BUTTONS — a script run on the incident from a button of its page (6.2)
 * ============================================================================
 *
 * The type of the incident put the buttons there: each has its text, its
 * colours, a script, and for every argument of the script a template or
 * nothing. Pressing one opens a dialog that shows what the script will be
 * given: the arguments filled from the incident, read-only, with the field
 * each comes from, and those to fill. A field that holds several values means
 * one run for each. The server works all of this out, on the incident as it
 * is when the button is pressed; what is here only shows it.
 *
 * Then the same dialog lists the runs as they finish. Each is a command in
 * the War Room of the incident, with its arguments and its output, and a line
 * of the audit log.
 *
 * Pressing a button is running a script: for who holds `automation.run`.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const MUTED = 'text-sm text-fg-muted'
const POLL_MS = 1000
const STATUS_CHUNK = 200

/** What an argument that is asked is typed in, by its type. */
function Asked({ id, argument, value, onChange }) {
  if (argument.type === 'bool') {
    return (
      <select id={id} value={value} onChange={(event) => onChange(event.target.value)} className={INPUT}>
        <option value="">(not set)</option>
        <option value="true">yes</option>
        <option value="false">no</option>
      </select>
    )
  }
  return (
    <input
      id={id}
      type="text"
      inputMode={argument.type === 'number' ? 'decimal' : undefined}
      value={value}
      autoComplete="off"
      placeholder={argument.type === 'list' ? 'values separated by commas' : ''}
      onChange={(event) => onChange(event.target.value)}
      className={INPUT}
    />
  )
}

function RunRow({ run, single, script }) {
  const [shown, setShown] = useState(false)
  const dot = run.status === 'done' ? 'bg-accent' : run.status === 'failed' ? 'bg-high' : 'bg-med animate-pulse'
  return (
    <li className="border border-line-soft bg-canvas px-3 py-2">
      <div className="flex items-center gap-3">
        <span aria-hidden="true" className={`h-2 w-2 shrink-0 ${dot}`} />
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={shownValue(run.item)}>
          {single ? script : shownValue(run.item)}
        </span>
        {run.status === 'running' && <span className="shrink-0 text-xs text-fg-muted">running…</span>}
        {run.status === 'done' && (
          <span className="shrink-0 text-xs text-fg-muted">
            done{run.durationMs !== null ? ` · ${tookText(run.durationMs)}` : ''}
          </span>
        )}
        {run.status === 'failed' && (
          <span className="shrink-0 text-xs text-high-fg">
            failed ·{' '}
            <button
              type="button"
              aria-expanded={shown}
              onClick={() => setShown((open) => !open)}
              className="underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {shown ? 'hide why' : 'show why'}
            </button>
          </span>
        )}
      </div>
      {run.status === 'failed' && shown && (
        <p role="note" className="mt-2 whitespace-pre-wrap break-words font-mono text-xs text-high-fg">
          {run.error || 'The run failed and did not say why.'}
        </p>
      )}
    </li>
  )
}

/**
 * The dialog of a press: what is missing is asked, then the runs are listed as they finish.
 * @param {{ incident: object, button: object, onClose: () => void }} props
 */
export function RunButtonDialog({ incident, button, onClose }) {
  const [plan, setPlan] = useState(null)
  const [typed, setTyped] = useState({})
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [warned, setWarned] = useState(false)
  const [runs, setRuns] = useState(null) // null until the press started
  const base = `/incidents/${encodeURIComponent(incident.id)}/script-buttons`
  const press = { script: button.script, label: button.label, args: button.args ?? {} }
  const alive = useRef(true)
  useEffect(
    () => () => {
      alive.current = false
    },
    [],
  )

  // What the press would run, worked out by the server on the incident as it is now.
  useEffect(() => {
    let current = true
    api
      .post(`${base}/plan`, press)
      .then((found) => current && setPlan(found))
      .catch((failure) => current && setError(failure.message))
    return () => {
      current = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- asked once, when the dialog opens
  }, [])

  // The runs that are not finished are asked about until they are.
  const waiting = (runs ?? []).filter((run) => run.status === 'running').map((run) => run.runId)
  const waitingKey = waiting.join('|')
  useEffect(() => {
    if (!waitingKey) return undefined
    const ids = waitingKey.split('|')
    const timer = setTimeout(async () => {
      try {
        const found = []
        for (let at = 0; at < ids.length; at += STATUS_CHUNK) {
          const answer = await api.post(`${base}/status`, { runs: ids.slice(at, at + STATUS_CHUNK) })
          found.push(...answer.runs)
        }
        if (alive.current) setRuns((before) => mergeRuns(before, found))
      } catch {
        // A status that could not be read is asked again: the runs go on whatever happens here.
        if (alive.current) setRuns((before) => [...before])
      }
    }, POLL_MS)
    return () => clearTimeout(timer)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the ids, by value; `runs` changes at every answer
  }, [waitingKey, runs])

  const asked = (plan?.arguments ?? []).filter((argument) => argument.state === 'ask')
  const lacking = asked.filter((argument) => argument.required && !String(typed[argument.name] ?? '').trim())
  const total = plan?.runs ?? 1
  const many = total > (plan?.warnAbove ?? WARN_RUNS)

  const start = useCallback(
    async (only = null) => {
      setBusy(true)
      setError(null)
      try {
        const answer = await api.post(`${base}/run`, {
          ...press,
          values: typed,
          expect: total,
          ...(only ? { only } : {}),
        })
        const started = answer.runs.map((run) => ({ ...run, status: 'running', durationMs: null, error: null }))
        // Run again: each new run takes the place of the one that failed.
        setRuns((before) =>
          only && before ? before.map((run) => started.find((fresh) => fresh.index === run.index) ?? run) : started,
        )
      } catch (failure) {
        setError(failure.message)
      } finally {
        setBusy(false)
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps -- `press` is the button, which does not change
    [base, typed, total],
  )

  const submit = (event) => {
    event.preventDefault()
    if (!plan || lacking.length > 0) return
    // Many runs are started only when asked twice.
    if (many && !warned) {
      setWarned(true)
      return
    }
    start()
  }

  const counts = tally(runs)
  const failed = (runs ?? []).filter((run) => run.status === 'failed')
  const title = runs ? `${button.label} · ${runs.length} ${runs.length === 1 ? 'run' : 'runs'}` : button.label

  return (
    <Modal
      open
      onClose={onClose}
      title={title}
      footer={
        runs ? (
          <>
            {failed.length > 0 && counts.running === 0 && (
              <Button variant="secondary" disabled={busy} onClick={() => start(failed.map((run) => run.index))}>
                {againLabel(failed.length)}
              </Button>
            )}
            <Button onClick={onClose}>Done</Button>
          </>
        ) : (
          <>
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" form="form-run-button" disabled={busy || !plan || lacking.length > 0}>
              {runLabel(total)}
            </Button>
          </>
        )
      }
    >
      {runs ? (
        <div className="flex flex-col gap-3">
          <p role="status" className={MUTED}>
            {counts.running > 0
              ? `${counts.done + counts.failed} of ${runs.length} finished.`
              : counts.failed > 0
                ? `${counts.failed} of ${runs.length} failed.`
                : runs.length === 1
                  ? 'The run is done.'
                  : `The ${runs.length} runs are done.`}
          </p>
          <ul aria-label="Runs" className="flex max-h-[40vh] flex-col gap-1.5 overflow-y-auto">
            {runs.map((run) => (
              <RunRow key={run.index} run={run} single={runs.length === 1 && !plan?.each} script={button.script} />
            ))}
          </ul>
          <p className="text-xs text-fg-muted">
            Each run is an entry of the War Room, with its arguments and its output, and a line of the audit log.
          </p>
        </div>
      ) : (
        <form id="form-run-button" onSubmit={submit} className="flex flex-col gap-4">
          {!plan && !error && (
            <p role="status" className="font-mono text-fg-muted">
              Reading the incident…
            </p>
          )}
          {plan && (
            <>
              <p className={MUTED}>
                Runs <span className="font-mono text-fg">{plan.script}</span>
                {plan.description ? `: ${plan.description}` : '.'}
              </p>
              {plan.arguments.length === 0 && <p className={MUTED}>This script takes no argument.</p>}
              {plan.arguments.map((argument) => {
                const id = `run-arg-${argument.name}`
                if (argument.state === 'filled') {
                  return (
                    <div key={argument.name} className="flex flex-col gap-1">
                      <span className="text-fg-muted">
                        <span className="font-mono text-fg">{argument.name}</span> · {sourceText(argument)}
                      </span>
                      <div
                        role="group"
                        aria-label={`${argument.name}, ${sourceText(argument)}`}
                        className="max-h-24 overflow-y-auto break-words border border-line-soft bg-canvas px-3 py-1.5 font-mono text-xs text-fg-muted"
                      >
                        {argument.count > 1 ? `${argument.count} runs, one for each value` : shownValue(argument.value)}
                      </div>
                    </div>
                  )
                }
                return (
                  <label key={argument.name} className="flex flex-col gap-1" htmlFor={id}>
                    <span className="text-fg-muted">
                      <span className="font-mono text-fg">{argument.name}</span> · to fill
                      {argument.required && <span className="text-med"> · required</span>}
                    </span>
                    <Asked
                      id={id}
                      argument={argument}
                      value={typed[argument.name] ?? ''}
                      onChange={(value) => setTyped({ ...typed, [argument.name]: value })}
                    />
                    {(argument.problem || argument.description) && (
                      <span className="text-xs text-fg-muted">
                        {[argument.problem && `${argument.problem}.`, argument.description].filter(Boolean).join(' ')}
                      </span>
                    )}
                  </label>
                )
              })}
              {many && (
                <p role="alert" className="border border-med-line bg-med-soft px-3 py-2 text-med-fg">
                  {warned
                    ? `Press “${runLabel(total)}” again to start them.`
                    : `This starts ${total} runs, one for each value of ${plan.each}.`}
                </p>
              )}
            </>
          )}
        </form>
      )}
      {error && (
        <p role="alert" className="mt-3 border border-high-line bg-high-soft px-3 py-2 text-high-fg">
          {error}
        </p>
      )}
    </Modal>
  )
}

/**
 * The buttons of a widget, on an incident.
 * @param {{ incident: object, widget: object }} props
 */
export default function ScriptButtons({ incident, widget }) {
  const { can } = useAuth()
  const [pressed, setPressed] = useState(null)
  const buttons = widget.buttons ?? []
  const allowed = can('automation.run')
  if (buttons.length === 0) return <p className={MUTED}>No button was set up in this widget.</p>
  return (
    <div className="flex h-full flex-col gap-2 overflow-y-auto">
      <div className="flex flex-wrap content-start gap-2">
        {buttons.map((button, index) => {
          const why = !allowed
            ? 'Your roles do not include running scripts'
            : !button.script
              ? 'No script was chosen for this button'
              : ''
          return (
            <button
              key={`${button.label}:${index}`}
              type="button"
              disabled={Boolean(why)}
              title={why || `Run ${button.script} on this incident`}
              onClick={() => setPressed(button)}
              style={{ backgroundColor: button.background, color: button.color }}
              className="inline-flex h-8 max-w-full shrink-0 items-center border border-transparent px-3 text-sm font-medium focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-50 disabled:grayscale"
            >
              <span className="truncate">{button.label}</span>
            </button>
          )
        })}
      </div>
      {!allowed && (
        <p role="note" className="text-xs text-fg-muted">
          Your roles do not include running scripts.
        </p>
      )}
      {pressed && <RunButtonDialog incident={incident} button={pressed} onClose={() => setPressed(null)} />}
    </div>
  )
}
