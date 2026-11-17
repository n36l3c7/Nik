import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
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
import { Badge, Button } from '../../ui/index.js'

/*
 * ============================================================================
 * WAR ROOM — everything said and done on this incident, in the order it happened
 * ============================================================================
 *
 * Left, the stream: notes, the steps playbooks ran here, approvals answered,
 * commands and what they gave. The chips keep one kind, or what was marked as
 * evidence. At the bottom, a line to write in: plain text is a note.
 *
 * Right, the inspector of the chosen entry: a result as a table when it is a
 * list of flat objects, as JSON otherwise; what was sent; what was written to
 * the context; and its actions (mark as evidence, copy as JSON, open the run).
 * Below 1100 px the inspector is a drawer over the stream.
 *
 * The Timeline is another thing: the forensic timeline of the evidence.
 */

const REFRESH_MS = 8000
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
                  {cell(row[column])}
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

function Inspector({ incident, entry, canWrite, onClose, onChanged, onRerun }) {
  const { showToast } = useToast()
  const [detail, setDetail] = useState(null)

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
    <aside
      aria-label="The chosen entry"
      className="absolute inset-y-0 right-0 z-10 flex w-full max-w-md flex-col gap-3 overflow-y-auto border-l border-line bg-panel p-3 shadow-xl min-[1100px]:static min-[1100px]:w-[380px] min-[1100px]:max-w-none min-[1100px]:shrink-0 min-[1100px]:shadow-none"
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
      {line.text && <p className="whitespace-pre-wrap break-words text-sm text-fg">{line.text}</p>}
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
              <Result value={step.output} />
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
  )
}

/**
 * @param {{ incident: object }} props
 */
export default function WarRoomTab({ incident }) {
  const { can } = useAuth()
  const { showToast } = useToast()
  const { retryActiveIncident } = useIncidents()
  const canWrite = can('write')
  const [show, setShow] = useState('all')
  const [entries, setEntries] = useState(null)
  const [error, setError] = useState(null)
  const [chosen, setChosen] = useState(null)
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
  useEffect(() => {
    setEntries(null)
    load()
    const timer = setInterval(load, REFRESH_MS)
    return () => clearInterval(timer)
  }, [load])
  // A new line at the end is brought into view; reading older ones is left alone.
  useEffect(() => {
    const length = entries?.length ?? 0
    if (length > count.current) end.current?.scrollIntoView({ block: 'nearest' })
    count.current = length
  }, [entries])

  const list = useMemo(() => threaded(entries), [entries])
  const open = list.find((entry) => entry.id === chosen) ?? null

  const send = async (event) => {
    event.preventDefault()
    const written = text.trim()
    if (!written) return
    setBusy(true)
    try {
      await api.post(`/incidents/${encodeURIComponent(incident.id)}/war-room`, { text: written })
      setText('')
      await load()
      // The note is a note of the incident: the copy of it held here is read again.
      retryActiveIncident()
    } catch (failure) {
      showToast({ message: failure.message })
    } finally {
      setBusy(false)
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
                <button
                  type="button"
                  aria-current={entry.id === chosen ? 'true' : undefined}
                  onClick={() => setChosen(entry.id === chosen ? null : entry.id)}
                  className={`flex w-full items-start gap-2 border-b border-line-soft px-3 py-2 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${entry.id === chosen ? 'bg-raised' : ''}`}
                >
                  <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${tone.className}`} aria-hidden="true" />
                  <span className="min-w-0 flex-1">
                    <span className="flex flex-wrap items-baseline gap-x-2 text-xs text-fg-muted">
                      <span className="font-medium text-fg">{authorLabel(entry.author)}</span>
                      <span>{formatDateTime(Date.parse(entry.at))}</span>
                      {entry.body?.automation && <Badge color="cyan">automation</Badge>}
                      {entry.tags.includes(EVIDENCE) && <Badge color="amber">evidence</Badge>}
                    </span>
                    {line.title && (
                      <span
                        className={`block break-words text-sm ${entry.kind === 'command' ? 'font-mono' : 'font-medium'} text-fg`}
                      >
                        {line.title}
                      </span>
                    )}
                    {line.text && (
                      <span
                        className={`block whitespace-pre-wrap break-words text-sm ${line.tone === 'error' ? 'text-high-fg' : line.title ? 'text-fg-muted' : 'text-fg'}`}
                      >
                        {line.text}
                      </span>
                    )}
                  </span>
                </button>
              </li>
            )
          })}
          <li ref={end} aria-hidden="true" />
        </ol>

        {canWrite && (
          <form onSubmit={send} className="flex items-end gap-2 border-t border-line bg-panel p-2">
            <label className="sr-only" htmlFor="war-room-line">
              Write in the War Room
            </label>
            <textarea
              id="war-room-line"
              value={text}
              rows={Math.min(5, Math.max(1, text.split('\n').length))}
              placeholder="Write a note…"
              onChange={(event) => setText(event.target.value)}
              onKeyDown={(event) => {
                // Enter sends; Shift+Enter is a new line.
                if (event.key === 'Enter' && !event.shiftKey) {
                  event.preventDefault()
                  event.currentTarget.form.requestSubmit()
                }
              }}
              className="min-h-[36px] flex-1 resize-none border border-line bg-canvas px-3 py-1.5 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            />
            <Button type="submit" size="sm" icon={Send} disabled={busy || !text.trim()}>
              Send
            </Button>
          </form>
        )}
      </div>
      {open && (
        <Inspector
          incident={incident}
          entry={open}
          canWrite={canWrite}
          onClose={() => setChosen(null)}
          onChanged={load}
          onRerun={null}
        />
      )}
    </div>
  )
}
