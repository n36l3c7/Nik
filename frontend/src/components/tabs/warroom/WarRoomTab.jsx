import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  FolderOpen,
  HelpCircle,
  Info,
  RefreshCw,
  Send,
  Star,
  StickyNote,
  Terminal,
  X,
} from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useToast } from '../../../context/ToastContext.jsx'
import { api } from '../../../services/api.js'
import { automationPath } from '../../../domain/automationNav.js'
import { argumentHints, completions, lineKind, recall, remember } from '../../../domain/commandLine.js'
import {
  EVIDENCE,
  FILTERS,
  asTable,
  authorLabel,
  cell,
  contextWrites,
  entryLine,
  threaded,
} from '../../../domain/warRoom.js'
import { setPath } from '../../../lib/location.js'
import { formatDateTime } from '../../../lib/time.js'
import { Badge, Button, Modal } from '../../ui/index.js'
import IocText from '../../ioc/IocText.jsx'
import ResizeHandle, { useResizablePane } from '../../ui/ResizeHandle.jsx'
import { useObjectMenu } from '../../menu/useObjectMenu.js'

/*
 * ============================================================================
 * WAR ROOM — everything said and done on this incident, in the order it happened
 * ============================================================================
 *
 * Left, the stream: notes, the steps playbooks ran here, approvals answered,
 * commands and what they gave. The chips keep one kind, or what was marked as
 * evidence. At the bottom, a line to write in: plain text is a note, `/note`,
 * `/assign @user` and `/close` are what they say, and `!name arg=value` runs
 * a command (of a connector, of Nik, a script, or `!ip` `!domain` `!url`
 * `!file` `!email` for what is known of an indicator). The name of a command
 * is completed while it is typed, its arguments are hinted, ↑ brings back the
 * lines typed before. A command that changes something outside asks first.
 *
 * Right, the inspector of the chosen entry: a result as a table when it is a
 * list of flat objects, as JSON otherwise; what was sent; what was written to
 * the context; and its actions (mark as evidence, copy as JSON, open the run).
 * Below 1100 px the inspector is a drawer over the stream.
 *
 * The Timeline is another thing: the forensic timeline of the evidence.
 */

const REFRESH_MS = 8000
// While a command runs its result is looked for more often.
const WAITING_MS = 1000
const TONES = {
  note: { icon: StickyNote, className: 'text-fg-muted' },
  ok: { icon: CheckCircle2, className: 'text-accent' },
  error: { icon: AlertTriangle, className: 'text-high' },
  ask: { icon: HelpCircle, className: 'text-med' },
  command: { icon: Terminal, className: 'text-info' },
  system: { icon: Info, className: 'text-fg-subtle' },
}

function Json({ value }) {
  return (
    <pre className="max-h-80 overflow-auto bg-canvas p-2 font-mono text-[11px] leading-relaxed text-fg">
      {JSON.stringify(value, null, 2)}
    </pre>
  )
}

function Result({ value }) {
  const table = asTable(value)
  if (!table) return <Json value={value} />
  return (
    <div className="max-h-80 overflow-auto border border-line">
      <table className="w-full border-collapse text-left text-xs">
        <caption className="sr-only">The result</caption>
        <thead className="bg-panel font-mono text-fg-muted">
          <tr>
            {table.columns.map((column) => (
              <th key={column} scope="col" className="whitespace-nowrap border-b border-line px-2 py-1 font-normal">
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {table.rows.map((row, index) => (
            <tr key={index}>
              {table.columns.map((column) => (
                <td key={column} className="border-b border-line-soft px-2 py-1 align-top text-fg">
                  <IocText text={cell(row[column])} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Heading({ children }) {
  return <h4 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">{children}</h4>
}

function Inspector({ incident, entry, raw, canWrite, onClose, onChanged, onRerun }) {
  const { showToast } = useToast()
  const [detail, setDetail] = useState(null)
  const pane = useResizablePane('warroom.entry', { initial: 380, min: 300, max: 720, edge: 'left' })

  useEffect(() => {
    let alive = true
    setDetail(null)
    api
      .get(`/incidents/${encodeURIComponent(incident.id)}/war-room/${encodeURIComponent(entry.id)}`)
      .then((found) => alive && setDetail(found))
      .catch(() => alive && setDetail({ ...entry, step: null }))
    return () => {
      alive = false
    }
  }, [incident.id, entry])

  const line = entryLine(entry)
  const step = detail?.step ?? null
  const evidence = entry.tags.includes(EVIDENCE)
  const wrote = contextWrites(step?.log)

  const mark = async () => {
    const tags = evidence ? entry.tags.filter((tag) => tag !== EVIDENCE) : [...entry.tags, EVIDENCE]
    try {
      await api.put(`/incidents/${encodeURIComponent(incident.id)}/war-room/${encodeURIComponent(entry.id)}/tags`, {
        tags,
      })
      onChanged()
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(JSON.stringify(detail ?? entry, null, 2))
      showToast({ message: 'Copied as JSON.' })
    } catch {
      showToast({ message: 'The browser refused to copy.' })
    }
  }

  return (
    <>
      <ResizeHandle {...pane.handle} label="Resize the chosen entry" className="hidden min-[1100px]:block" />
      <aside
        aria-label="The chosen entry"
        style={pane.style}
        className="absolute inset-y-0 right-0 z-10 flex w-full max-w-md flex-col gap-3 overflow-y-auto border-l border-line bg-panel p-3 shadow-xl min-[1100px]:static min-[1100px]:w-[var(--pane-w)] min-[1100px]:max-w-none min-[1100px]:shrink-0 min-[1100px]:shadow-none"
      >
        <div className="flex items-start gap-2">
          <div className="min-w-0 flex-1">
            <p className="break-words text-sm font-semibold text-fg">{line.title || 'A note'}</p>
            <p className="text-xs text-fg-muted">
              {authorLabel(entry.author)} · {formatDateTime(Date.parse(entry.at))}
            </p>
          </div>
          <button
            type="button"
            aria-label="Close the entry"
            onClick={onClose}
            className="text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          {canWrite && (
            <Button
              variant={evidence ? 'secondary' : 'ghost'}
              size="xs"
              icon={Star}
              aria-pressed={evidence}
              onClick={mark}
            >
              {evidence ? 'Evidence' : 'Mark as evidence'}
            </Button>
          )}
          <Button variant="ghost" size="xs" icon={Copy} onClick={copy}>
            Copy JSON
          </Button>
          {entry.runId && (
            <Button
              variant="ghost"
              size="xs"
              icon={ExternalLink}
              onClick={() => setPath(automationPath('runs', entry.runId))}
            >
              Open the run
            </Button>
          )}
          {onRerun && entry.kind === 'command' && (
            <Button variant="ghost" size="xs" icon={RefreshCw} onClick={() => onRerun(entry.body.line)}>
              Run again
            </Button>
          )}
        </div>
        {line.text && (
          <p className="whitespace-pre-wrap break-words text-sm text-fg">
            <IocText text={line.text} />
          </p>
        )}
        {!detail && (
          <p role="status" className="font-mono text-xs text-fg-muted">
            Loading…
          </p>
        )}
        {step && (
          <>
            {step.error && (
              <p role="alert" className="border border-high-line bg-high-soft p-2 text-xs text-high-fg">
                {step.error}
              </p>
            )}
            {step.output !== null && step.output !== undefined && (
              <section className="flex flex-col gap-1">
                <Heading>Result</Heading>
                {raw ? <Json value={step.output} /> : <Result value={step.output} />}
              </section>
            )}
            {step.request && (
              <section className="flex flex-col gap-1">
                <Heading>What was sent</Heading>
                <Json value={step.request} />
              </section>
            )}
            {step.input && (
              <section className="flex flex-col gap-1">
                <Heading>What it was given</Heading>
                <Json value={step.input} />
              </section>
            )}
            {wrote.length > 0 && (
              <section className="flex flex-col gap-1">
                <Heading>Written to the context</Heading>
                <ul className="flex flex-wrap gap-1">
                  {wrote.map((item) => (
                    <li key={item} className="border border-line bg-canvas px-1.5 py-0.5 font-mono text-[11px] text-fg">
                      {item}
                    </li>
                  ))}
                </ul>
              </section>
            )}
          </>
        )}
      </aside>
    </>
  )
}

/**
 * @param {{ incident: object }} props
 */
export default function WarRoomTab({ incident }) {
  const { can } = useAuth()
  const { retryActiveIncident, refreshIncidents, askClose } = useIncidents()
  const canWrite = can('write')
  const canRun = can('automation.run')
  const [commands, setCommands] = useState([])
  const [history, setHistory] = useState([])
  const [historyAt, setHistoryAt] = useState(0)
  const [draft, setDraft] = useState('')
  const [picked, setPicked] = useState(0)
  const [lineError, setLineError] = useState(null)
  const [confirm, setConfirm] = useState(null) // { line, command }: a command that changes something outside
  const [show, setShow] = useState('all')
  const [entries, setEntries] = useState(null)
  const [error, setError] = useState(null)
  const [chosen, setChosen] = useState(null)
  const menu = useObjectMenu()
  const [text, setText] = useState('')
  const [busy, setBusy] = useState(false)
  const end = useRef(null)
  const count = useRef(0)

  const load = useCallback(async () => {
    try {
      const found = await api.get(`/incidents/${encodeURIComponent(incident.id)}/war-room?show=${show}`)
      setEntries(found.entries)
      setError(null)
    } catch (failure) {
      // An incident not saved yet has nothing here.
      if (failure.status === 404) setEntries([])
      else setError(failure.message)
    }
  }, [incident.id, show])
  // A command that has no result under it yet is still running.
  const waiting = Boolean(
    entries?.some(
      (entry) => entry.kind === 'command' && entry.runId && !entries.some((other) => other.parentId === entry.id),
    ),
  )
  useEffect(() => {
    setEntries(null)
    load()
  }, [load])
  useEffect(() => {
    const timer = setInterval(load, waiting ? WAITING_MS : REFRESH_MS)
    return () => clearInterval(timer)
  }, [load, waiting])
  // The commands there are, for the completion of the line.
  useEffect(() => {
    if (!canRun) return undefined
    let alive = true
    api
      .get('/automation/catalog?prefix=')
      .then((found) => alive && setCommands(found.commands ?? []))
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [canRun])
  // A new line at the end is brought into view; reading older ones is left alone.
  useEffect(() => {
    const length = entries?.length ?? 0
    if (length > count.current) end.current?.scrollIntoView({ block: 'nearest' })
    count.current = length
  }, [entries])

  const list = useMemo(() => threaded(entries), [entries])
  const open = list.find((entry) => entry.id === chosen) ?? null

  const suggestions = useMemo(
    () => (canRun || lineKind(text) === 'slash' ? completions(commands, text) : []),
    [canRun, commands, text],
  )
  const hints = useMemo(() => argumentHints(commands, text), [commands, text])
  const write = (next) => {
    setText(next)
    setPicked(0)
    setLineError(null)
    setHistoryAt(history.length)
  }

  const run = async (line, confirmed = false) => {
    setBusy(true)
    setLineError(null)
    try {
      const answer = await api.post(`/incidents/${encodeURIComponent(incident.id)}/war-room/command`, {
        line,
        confirm: confirmed,
      })
      const next = remember(history, line)
      setHistory(next)
      setHistoryAt(next.length)
      setText('')
      setDraft('')
      setConfirm(null)
      if (answer?.action === 'close') {
        askClose(incident.id)
        return
      }
      await load()
      // A note, a new owner: the copy of the incident held here is read again.
      if (lineKind(line) !== 'command') {
        refreshIncidents()
        retryActiveIncident()
      }
    } catch (failure) {
      if (failure.status === 409 && failure.data?.needsConfirm) setConfirm({ line, command: failure.data.command })
      else {
        setConfirm(null)
        setLineError(failure.message)
      }
    } finally {
      setBusy(false)
    }
  }
  const send = (event) => {
    event.preventDefault()
    const written = text.trim()
    if (written) run(written)
  }
  const onKey = (event) => {
    if (suggestions.length > 0 && (event.key === 'ArrowDown' || event.key === 'ArrowUp')) {
      event.preventDefault()
      const step = event.key === 'ArrowDown' ? 1 : -1
      setPicked((picked + step + suggestions.length) % suggestions.length)
      return
    }
    if (suggestions.length > 0 && (event.key === 'Tab' || (event.key === 'Enter' && !event.shiftKey))) {
      // The name is completed; the line is sent with the next Enter.
      event.preventDefault()
      write(suggestions[picked]?.value ?? text)
      return
    }
    if ((event.key === 'ArrowUp' || event.key === 'ArrowDown') && !text.includes('\n') && history.length > 0) {
      const at = event.key === 'ArrowUp' ? -1 : 1
      if (historyAt === history.length && at === 1) return
      event.preventDefault()
      if (historyAt === history.length) setDraft(text)
      const found = recall(history, historyAt, at, historyAt === history.length ? text : draft)
      setHistoryAt(found.at)
      setText(found.text)
      return
    }
    // Enter sends; Shift+Enter is a new line.
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault()
      event.currentTarget.form.requestSubmit()
    }
  }

  return (
    <div className="relative flex h-[calc(100vh-220px)] min-h-[420px] gap-0 border border-line">
      <div className="flex min-w-0 flex-1 flex-col">
        <div className="flex flex-wrap items-center gap-1 border-b border-line bg-panel px-3 py-2">
          <div role="group" aria-label="Show" className="flex flex-wrap gap-1">
            {FILTERS.map((filter) => (
              <button
                key={filter.id}
                type="button"
                aria-pressed={show === filter.id}
                onClick={() => setShow(filter.id)}
                className={`border px-2 py-0.5 font-mono text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                  show === filter.id
                    ? 'border-accent-strong bg-accent-soft text-accent-fg'
                    : 'border-line text-fg-muted hover:bg-raised hover:text-fg'
                }`}
              >
                {filter.label}
              </button>
            ))}
          </div>
          <span className="flex-1" />
          <Button variant="ghost" size="xs" icon={RefreshCw} onClick={load}>
            Refresh
          </Button>
        </div>

        <ol aria-label="War Room" className="min-h-0 flex-1 overflow-y-auto">
          {error && (
            <li role="alert" className="px-3 py-2 text-sm text-high-fg">
              {error}
            </li>
          )}
          {!entries && !error && (
            <li role="status" className="px-3 py-2 font-mono text-sm text-fg-muted">
              Loading the War Room…
            </li>
          )}
          {entries?.length === 0 && (
            <li className="px-3 py-6 text-center text-sm text-fg-muted">
              {show === 'all'
                ? 'Nothing here yet. What is written below, and what playbooks do on this incident, appears here.'
                : 'Nothing of this kind.'}
            </li>
          )}
          {list.map((entry) => {
            const line = entryLine(entry)
            const tone = TONES[line.tone] ?? TONES.system
            const Icon = tone.icon
            return (
              <li key={entry.id} className={entry.depth ? 'pl-6' : ''}>
                {/* The row opens the entry wherever it is clicked; the button is how the keyboard does it.
                    An indicator in the text is a button of its own, so the row cannot be one. */}
                <div
                  onContextMenu={(event) =>
                    menu(event, {
                      title: line.title || 'A note',
                      actions: [
                        { label: 'Open the entry', icon: FolderOpen, onSelect: () => setChosen(entry.id) },
                        entry.runId && {
                          label: 'Open the run',
                          icon: ExternalLink,
                          onSelect: () => setPath(automationPath('runs', entry.runId)),
                        },
                      ],
                      copy: [
                        { label: 'Copy the text', text: [line.title, line.text].filter(Boolean).join('\n') },
                        entry.kind === 'command' && { label: 'Copy the command', text: entry.body?.line ?? '' },
                      ],
                      record: entry,
                    })
                  }
                  onClick={() => setChosen(entry.id === chosen ? null : entry.id)}
                  className={`flex w-full cursor-pointer items-start gap-2 border-b border-line-soft px-3 py-2 text-left hover:bg-raised ${entry.id === chosen ? 'bg-raised' : ''}`}
                >
                  <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${tone.className}`} aria-hidden="true" />
                  <span className="min-w-0 flex-1">
                    <button
                      type="button"
                      title="Open the entry"
                      aria-current={entry.id === chosen ? 'true' : undefined}
                      onClick={(event) => {
                        event.stopPropagation()
                        setChosen(entry.id === chosen ? null : entry.id)
                      }}
                      className="flex flex-wrap items-baseline gap-x-2 text-left text-xs text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      <span className="font-medium text-fg">{authorLabel(entry.author)}</span>
                      <span>{formatDateTime(Date.parse(entry.at))}</span>
                      {entry.body?.automation && <Badge color="cyan">automation</Badge>}
                      {entry.tags.includes(EVIDENCE) && <Badge color="amber">evidence</Badge>}
                    </button>
                    {line.title && (
                      <span
                        className={`block break-words text-sm ${entry.kind === 'command' ? 'font-mono' : 'font-medium'} text-fg`}
                      >
                        <IocText text={line.title} />
                      </span>
                    )}
                    {line.text && (
                      <span
                        className={`block whitespace-pre-wrap break-words text-sm ${line.tone === 'error' ? 'text-high-fg' : line.title ? 'text-fg-muted' : 'text-fg'}`}
                      >
                        <IocText text={line.text} />
                      </span>
                    )}
                  </span>
                </div>
              </li>
            )
          })}
          <li ref={end} aria-hidden="true" />
        </ol>

        {canWrite && (
          <form onSubmit={send} className="relative flex flex-col gap-1 border-t border-line bg-panel p-2">
            {suggestions.length > 0 && (
              <ul
                id="war-room-commands"
                role="listbox"
                aria-label="Commands"
                className="absolute bottom-full left-2 right-2 z-10 max-h-64 overflow-y-auto border border-line bg-panel shadow-xl"
              >
                {suggestions.map((item, index) => (
                  <li
                    key={item.value}
                    role="option"
                    aria-selected={index === picked}
                    onMouseDown={(event) => {
                      event.preventDefault()
                      write(item.value)
                    }}
                    className={`flex cursor-pointer items-baseline gap-3 px-3 py-1 text-xs ${index === picked ? 'bg-raised' : ''}`}
                  >
                    <span className="shrink-0 font-mono text-fg">{item.label}</span>
                    <span className="min-w-0 flex-1 truncate text-fg-muted">{item.description}</span>
                  </li>
                ))}
              </ul>
            )}
            {hints.length > 0 && (
              <p
                aria-label="Arguments of the command"
                className="flex flex-wrap gap-x-3 gap-y-0.5 px-1 font-mono text-[11px]"
              >
                {hints.map((hint) => (
                  <span
                    key={hint.name}
                    title={hint.description}
                    className={hint.required ? 'text-fg' : 'text-fg-muted'}
                  >
                    {hint.name}={hint.required && <span className="text-med"> *</span>}
                  </span>
                ))}
              </p>
            )}
            {lineError && (
              <p role="alert" className="px-1 text-xs text-high-fg">
                {lineError}
              </p>
            )}
            <div className="flex items-end gap-2">
              <label className="sr-only" htmlFor="war-room-line">
                Write in the War Room
              </label>
              <textarea
                id="war-room-line"
                value={text}
                rows={Math.min(5, Math.max(1, text.split('\n').length))}
                placeholder={canRun ? 'Write a note, or ! for a command, / for /note /assign /close' : 'Write a note…'}
                spellCheck={lineKind(text) === 'note'}
                autoComplete="off"
                aria-controls={suggestions.length > 0 ? 'war-room-commands' : undefined}
                onChange={(event) => write(event.target.value)}
                onKeyDown={onKey}
                className={`min-h-[36px] flex-1 resize-none border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${lineKind(text) === 'note' ? '' : 'font-mono'}`}
              />
              <Button type="submit" size="sm" icon={Send} disabled={busy || !text.trim()}>
                {lineKind(text) === 'command' ? 'Run' : 'Send'}
              </Button>
            </div>
          </form>
        )}
      </div>
      {open && (
        <Inspector
          incident={incident}
          entry={open}
          canWrite={canWrite}
          onClose={() => setChosen(null)}
          raw={Boolean(
            (entries ?? []).find((entry) => entry.id === (open.kind === 'command' ? open.id : open.parentId))?.body
              ?.raw,
          )}
          onChanged={load}
          onRerun={
            canRun
              ? (line) => {
                  write(line)
                  document.getElementById('war-room-line')?.focus()
                }
              : null
          }
        />
      )}
      <Modal
        open={confirm !== null}
        onClose={() => setConfirm(null)}
        title="Run this command?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={busy} onClick={() => run(confirm.line, true)}>
              Run it
            </Button>
          </>
        }
      >
        <div className="flex flex-col gap-2 text-sm text-fg">
          <p>
            <span className="font-mono">{confirm?.command}</span> changes something outside Nik. It is sent as soon as
            you confirm, with your name on it.
          </p>
          <pre className="overflow-x-auto bg-canvas p-2 font-mono text-xs text-fg">{confirm?.line}</pre>
        </div>
      </Modal>
    </div>
  )
}
