import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Download, FolderPlus, Inbox, Mail, Paperclip, Trash2 } from 'lucide-react'
import { api } from '../../services/api.js'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { formatBytes } from '../../domain/events.js'
import {
  MAILBOX_FORMATS,
  dateRange,
  dayToMs,
  edgePath,
  layoutGraph,
  planLine,
  threadColour,
} from '../../domain/mailbox.js'
import { verdictBadge } from '../../domain/artifactRegistry.js'
import { formatDateTime } from '../../lib/time.js'
import { AsciiSkull, Badge, Button, EmptyState, MicroSkull, Modal, StatCard } from '../ui/index.js'

/*
 * A mailbox (mbox, Maildir archive, Outlook PST) as an artifact: what the file
 * holds, the messages imported from it, and the graph of its conversations.
 *
 * The graph is drawn like a source-control tree: a row per message, newest
 * first, joined to the message it answers; a colour is a conversation. A
 * hollow node is a message of the file that was not imported: nothing of a
 * mailbox is analysed until it is chosen.
 */

const POLL_MS = 2000
const IMPORT_MAX = 500
const PAGE = 300
const ROW = 30
const LANE = 16
const INSET = 12
const INPUT =
  'h-8 border border-line bg-canvas px-2.5 font-mono text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** The filter of an import as POST /mailboxes/{id}/import takes it. */
function importBody(form) {
  return {
    dateFrom: dayToMs(form.from),
    dateTo: dayToMs(form.to, true),
    sender: form.sender.trim(),
    subject: form.subject.trim(),
    attachments: form.attachments,
    threads: form.threads,
  }
}

function ImportDialog({ box, open, onClose, onStarted }) {
  const [form, setForm] = useState({ from: '', to: '', sender: '', subject: '', attachments: false, threads: true })
  const [plan, setPlan] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const set = (patch) => setForm((current) => ({ ...current, ...patch }))

  // What the filter would import, asked a moment after the last change.
  useEffect(() => {
    if (!open) return undefined
    let cancelled = false
    const timer = setTimeout(() => {
      api
        .post(`/mailboxes/${box.id}/import`, { ...importBody(form), dryRun: true })
        .then((result) => !cancelled && (setPlan(result), setError(null)))
        .catch((err) => !cancelled && setError(err.message))
    }, 300)
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [open, box.id, form])

  if (!open) return null
  const start = async () => {
    setBusy(true)
    try {
      await api.post(`/mailboxes/${box.id}/import`, importBody(form))
      onStarted()
      onClose()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  const most = Math.max(1, ...box.topSenders.map((entry) => entry.count))
  return (
    <Modal
      open
      onClose={onClose}
      title={`Import from ${box.fileName}`}
      maxWidth="max-w-3xl"
      footer={
        <div className="flex w-full flex-wrap items-center justify-between gap-2">
          <span className="text-xs text-fg-muted">Each message is analysed like an .eml, in the background.</span>
          <span className="flex gap-2">
            <Button variant="ghost" onClick={onClose}>
              Cancel
            </Button>
            <Button disabled={busy || !plan || plan.toImport === 0} onClick={start}>
              {busy ? 'Starting…' : `Import ${plan?.toImport ?? 0} ${plan?.toImport === 1 ? 'message' : 'messages'}`}
            </Button>
          </span>
        </div>
      }
    >
      <div className="grid gap-5 md:grid-cols-2">
        <section className="min-w-0 space-y-2">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Main senders</h3>
          <ul className="space-y-1">
            {box.topSenders.map((entry) => (
              <li key={entry.sender}>
                <button
                  type="button"
                  onClick={() => set({ sender: entry.sender })}
                  title="Import from this sender"
                  className="grid w-full grid-cols-[minmax(0,1fr)_5rem_2.5rem] items-center gap-2 text-left font-mono text-xs hover:text-accent-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <span className="truncate">{entry.sender || '(no sender)'}</span>
                  <span className="h-2 bg-line-soft" aria-hidden="true">
                    <i className="block h-full bg-info-line" style={{ width: `${(entry.count / most) * 100}%` }} />
                  </span>
                  <span className="text-right tabular-nums text-fg-muted">{entry.count}</span>
                </button>
              </li>
            ))}
          </ul>
        </section>
        <section className="min-w-0 space-y-2">
          <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">What to import</h3>
          <div className="flex flex-wrap items-center gap-2 text-xs text-fg-muted">
            <input
              type="date"
              aria-label="From date"
              value={form.from}
              onChange={(e) => set({ from: e.target.value })}
              className={INPUT}
            />
            to
            <input
              type="date"
              aria-label="To date"
              value={form.to}
              onChange={(e) => set({ to: e.target.value })}
              className={INPUT}
            />
          </div>
          <input
            aria-label="Sender or domain"
            placeholder="sender or domain"
            value={form.sender}
            onChange={(e) => set({ sender: e.target.value })}
            className={`${INPUT} w-full`}
          />
          <input
            aria-label="Subject contains"
            placeholder="subject contains"
            value={form.subject}
            onChange={(e) => set({ subject: e.target.value })}
            className={`${INPUT} w-full`}
          />
          <label className="flex items-center gap-2 text-sm">
            <input
              type="checkbox"
              checked={form.attachments}
              onChange={(e) => set({ attachments: e.target.checked })}
            />
            Only with attachments
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={form.threads} onChange={(e) => set({ threads: e.target.checked })} />
            Take the whole conversation of each match
          </label>
        </section>
      </div>
      <p
        role="status"
        aria-label="Import plan"
        className="mt-4 border-l-2 border-info-line bg-info-soft/30 px-3 py-2 text-sm"
      >
        {error ? <span className="text-high">{error}</span> : plan ? planLine(plan) : 'Counting…'}
      </p>
      <p className="mt-2 text-xs text-fg-subtle">
        At most {box.importMax} messages at a time, the newest first. The file stays on the server: more can be imported
        later.
      </p>
    </Modal>
  )
}

function Graph({ messages, selected, onSelect, picked, onPick }) {
  const layout = useMemo(() => layoutGraph(messages), [messages])
  const width = INSET * 2 + (layout.lanes - 1) * LANE
  const size = { rowHeight: ROW, laneWidth: LANE, inset: INSET }
  const columns = `1.75rem ${width}px minmax(10rem,1fr) 12rem 10.5rem 7rem`
  return (
    <div className="overflow-x-auto border border-line bg-panel">
      <div className="min-w-[42rem]">
        <div
          className="grid border-b border-line px-0 py-1.5 font-mono text-[11px] text-fg-muted"
          style={{ gridTemplateColumns: columns }}
        >
          <span />
          <span />
          <span>Subject</span>
          <span>From</span>
          <span>Date</span>
          <span>Verdict</span>
        </div>
        <div className="relative" role="list" aria-label="Messages">
          <svg
            width={width}
            height={messages.length * ROW}
            aria-hidden="true"
            className="pointer-events-none absolute top-0"
            style={{ left: '1.75rem' }}
          >
            {layout.edges.map((edge) => (
              <path
                key={`${edge.from}-${edge.to}`}
                d={edgePath(edge, size)}
                fill="none"
                stroke={threadColour(edge.thread)}
                strokeWidth="2"
              />
            ))}
            {layout.nodes.map((node) => {
              const message = messages[node.row]
              const colour = threadColour(message.thread)
              return (
                <circle
                  key={node.seq}
                  cx={INSET + node.lane * LANE}
                  cy={node.row * ROW + ROW / 2}
                  r="5"
                  fill={message.imported ? colour : 'var(--color-panel)'}
                  stroke={colour}
                  strokeWidth="2"
                />
              )
            })}
          </svg>
          {messages.map((message) => {
            const badge = message.imported
              ? verdictBadge({ verdict: message.verdict || 'clean', score: message.score })
              : null
            const active = selected === message.seq
            return (
              <div
                key={message.seq}
                role="listitem"
                className={`grid items-center border-b border-line-soft font-mono text-xs ${active ? 'bg-accent-soft' : 'hover:bg-raised'}`}
                style={{ gridTemplateColumns: columns, height: ROW }}
              >
                <span className="flex justify-center">
                  {message.imported && (
                    <input
                      type="checkbox"
                      aria-label={`Select ${message.subject || 'message'}`}
                      checked={picked.has(message.seq)}
                      onChange={() => onPick(message.seq)}
                    />
                  )}
                </span>
                <span />
                <button
                  type="button"
                  onClick={() => onSelect(message.seq)}
                  aria-current={active ? 'true' : undefined}
                  className={`col-span-4 grid h-full items-center text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${message.imported ? '' : 'italic text-fg-subtle'}`}
                  style={{ gridTemplateColumns: 'minmax(10rem,1fr) 12rem 10.5rem 7rem' }}
                >
                  <span className="flex min-w-0 items-center gap-1.5 pr-2">
                    <span className="truncate">{message.subject || '(no subject)'}</span>
                    {message.attachments && (
                      <Paperclip className="h-3 w-3 shrink-0 text-fg-muted" aria-label="Has attachments" />
                    )}
                  </span>
                  <span className="truncate pr-2">{message.sender}</span>
                  <span className="truncate pr-2 text-fg-muted">
                    {message.date ? formatDateTime(message.date) : '—'}
                  </span>
                  <span>{badge ? <Badge color={badge.color}>{badge.label}</Badge> : 'not imported'}</span>
                </button>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

/**
 * @param {{ artifact: object, onOpenArtifact: (id: string) => void, onOpenIncident: (id: string) => void,
 *   onDelete: () => void, onExport?: () => void }} props
 */
export default function MailboxPage({ artifact, onOpenArtifact, onOpenIncident, onDelete }) {
  const { incidents } = useIncidents()
  const { showToast } = useToast()
  const [box, setBox] = useState(null)
  const [error, setError] = useState(null)
  const [data, setData] = useState(null) // { total, messages }
  const [filters, setFilters] = useState({ q: '', flagged: false, scope: 'imported', thread: null })
  const [selected, setSelected] = useState(null)
  const [picked, setPicked] = useState(() => new Set())
  const [importing, setImporting] = useState(false)
  const [linking, setLinking] = useState(false)
  const [target, setTarget] = useState('')
  const [version, setVersion] = useState(0)
  const reload = useCallback(() => setVersion((v) => v + 1), [])
  const lastStatus = useRef(null)

  // The mailbox, polled while it is being indexed or imported.
  useEffect(() => {
    let cancelled = false
    let timer = null
    const load = () =>
      api
        .get(`/mailboxes/${artifact.ref}`)
        .then((doc) => {
          if (cancelled) return
          setBox(doc)
          setError(null)
          if (lastStatus.current && lastStatus.current !== doc.status && doc.status === 'ready') reload()
          lastStatus.current = doc.status
          if (doc.status === 'indexing' || doc.status === 'importing') timer = setTimeout(load, POLL_MS)
        })
        .catch((err) => !cancelled && setError(err.message))
    load()
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [artifact.ref, version, reload])

  const importNext = async () => {
    try {
      await api.post(`/mailboxes/${artifact.ref}/import`, { next: true })
      reload()
    } catch (err) {
      showToast({ message: err.message })
    }
  }

  const ready = box?.status === 'ready' || box?.status === 'importing'
  useEffect(() => {
    if (!ready) return undefined
    let cancelled = false
    const params = new URLSearchParams({ scope: filters.scope, limit: String(PAGE) })
    if (filters.q.trim()) params.set('q', filters.q.trim())
    if (filters.flagged) params.set('flagged', 'true')
    if (filters.thread !== null) params.set('thread', String(filters.thread))
    const timer = setTimeout(
      () =>
        api
          .get(`/mailboxes/${artifact.ref}/messages?${params}`)
          .then((doc) => !cancelled && setData(doc))
          .catch((err) => !cancelled && setError(err.message)),
      filters.q ? 250 : 0,
    )
    return () => {
      cancelled = true
      clearTimeout(timer)
    }
  }, [artifact.ref, ready, filters, version, box?.imported])

  const messages = useMemo(() => data?.messages ?? [], [data])
  const current = messages.find((message) => message.seq === selected) ?? null
  const bySeq = useMemo(() => new Map(messages.map((message) => [message.seq, message])), [messages])
  const togglePick = (seq) =>
    setPicked((now) => {
      const next = new Set(now)
      if (next.has(seq)) next.delete(seq)
      else next.add(seq)
      return next
    })
  const importOne = async (seq) => {
    try {
      await api.post(`/mailboxes/${artifact.ref}/import`, { seqs: [seq], threads: false })
      showToast({ message: 'Importing the message…' })
      reload()
    } catch (err) {
      showToast({ message: err.message })
    }
  }
  const link = async () => {
    try {
      const body = { incidentId: target, ...(picked.size ? { seqs: [...picked] } : {}) }
      const result = await api.post(`/mailboxes/${artifact.ref}/link`, body)
      setLinking(false)
      setPicked(new Set())
      showToast({
        message: `${result.linked} ${result.linked === 1 ? 'message is' : 'messages are'} in ${result.incident.name}.`,
        action: { label: 'Open', run: () => onOpenIncident(result.incident.id) },
      })
    } catch (err) {
      showToast({ message: err.message })
    }
  }

  if (error && !box) return <EmptyState icon={Inbox} title="Unable to load the mailbox" message={error} />
  if (!box) return <MicroSkull className="text-lg text-fg-muted" />
  const flaggedCount = (box.verdicts.phishing ?? 0) + (box.verdicts.suspicious ?? 0)

  return (
    <section aria-label="Artifact" className="space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 className="flex flex-wrap items-center gap-2 font-mono text-lg font-bold">
            <Inbox className="h-5 w-5 text-fg-muted" aria-hidden="true" />
            <span className="break-all">{box.fileName}</span>
            {box.verdicts.phishing > 0 && <Badge color="red">{box.verdicts.phishing} phishing</Badge>}
            {box.verdicts.suspicious > 0 && <Badge color="amber">{box.verdicts.suspicious} suspicious</Badge>}
          </h2>
          <p className="text-sm text-fg-muted">
            mailbox · {MAILBOX_FORMATS[box.format] ?? box.format} · {formatBytes(box.size)}
            {ready && ` · ${box.imported} of ${box.total} messages imported · ${dateRange(box.from, box.to)}`}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button icon={Download} disabled={box.status !== 'ready'} onClick={() => setImporting(true)}>
            {box.imported ? 'Import more' : 'Import messages'}
          </Button>
          <Button
            variant="secondary"
            icon={FolderPlus}
            disabled={box.imported === 0 || incidents.length === 0}
            onClick={() => {
              setTarget(incidents[0]?.id ?? '')
              setLinking(true)
            }}
          >
            {picked.size ? `Put ${picked.size} in an incident` : 'Put in an incident'}
          </Button>
          <Button variant="ghost" icon={Trash2} onClick={onDelete}>
            Delete
          </Button>
        </div>
      </div>

      {box.status === 'indexing' && (
        <div aria-busy="true" className="flex flex-col items-center gap-3 py-12">
          <AsciiSkull preset="medium" />
          <p role="status" className="font-mono text-sm text-fg-muted">
            Reading the mailbox: finding its messages and conversations…
          </p>
        </div>
      )}
      {box.status === 'error' && (
        <div role="alert" className="border-l-2 border-high-line bg-high-soft/50 px-3 py-2 text-sm">
          <b>The mailbox could not be read.</b> {box.error}
        </div>
      )}
      {box.status === 'ready' && box.pending && (
        <div
          role="status"
          aria-label="Waiting to import"
          className="flex flex-wrap items-center justify-between gap-3 border border-line bg-panel px-3.5 py-2.5 text-sm"
        >
          <span>
            <b>{box.pending.waiting}</b> more {box.pending.waiting === 1 ? 'message matches' : 'messages match'} your
            last import and {box.pending.waiting === 1 ? 'was' : 'were'} left for later.
          </span>
          <Button onClick={importNext}>Import the next {Math.min(box.pending.waiting, IMPORT_MAX)}</Button>
        </div>
      )}
      {box.status === 'importing' && box.progress && (
        <div
          role="status"
          aria-label="Import"
          className="border border-info-line bg-info-soft/30 px-3.5 py-2.5 text-sm"
        >
          <b>Importing</b> · {box.progress.done} of {box.progress.total}
          {box.progress.failed > 0 && <span className="text-fg-muted"> · {box.progress.failed} could not be read</span>}
          <div className="mt-2 flex h-1.5 bg-line-soft" aria-hidden="true">
            <i
              className="block h-full bg-accent"
              style={{ width: `${(box.progress.done / Math.max(1, box.progress.total)) * 100}%` }}
            />
          </div>
        </div>
      )}

      {ready && (
        <>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
            <StatCard label="Messages in the file" value={box.total} />
            <StatCard label="Conversations" value={box.threads} />
            <StatCard label="With attachments" value={box.attachments} />
            <StatCard label="Imported" value={box.imported} />
            <StatCard label="Phishing or suspicious" value={flaggedCount} tone={flaggedCount ? 'danger' : 'default'} />
          </div>

          {box.imported === 0 && box.status === 'ready' ? (
            <EmptyState
              icon={Mail}
              title="Nothing imported yet"
              message="The mailbox is indexed, not analysed. Choose which messages to import: each becomes an e-mail artifact, with its verdict."
              action={<Button onClick={() => setImporting(true)}>Import messages</Button>}
            />
          ) : (
            <>
              <div className="flex flex-wrap items-center gap-2">
                <input
                  type="search"
                  aria-label="Filter messages"
                  placeholder="filter subject, sender, recipient…"
                  value={filters.q}
                  onChange={(e) => setFilters({ ...filters, q: e.target.value })}
                  className={`${INPUT} min-w-0 flex-1 sm:max-w-xs`}
                />
                <label className="flex items-center gap-1.5 text-sm">
                  <input
                    type="checkbox"
                    checked={filters.flagged}
                    onChange={(e) => setFilters({ ...filters, flagged: e.target.checked })}
                  />
                  Only phishing and suspicious
                </label>
                <label className="flex items-center gap-1.5 text-sm">
                  <input
                    type="checkbox"
                    checked={filters.scope === 'all'}
                    onChange={(e) => setFilters({ ...filters, scope: e.target.checked ? 'all' : 'imported' })}
                  />
                  Whole file
                </label>
                {filters.thread !== null && (
                  <Button size="xs" variant="secondary" onClick={() => setFilters({ ...filters, thread: null })}>
                    Showing one conversation · show all
                  </Button>
                )}
                <span className="ml-auto font-mono text-xs text-fg-muted">
                  {messages.length} of {data?.total ?? 0}
                </span>
              </div>
              <div className="space-y-3">
                <Graph
                  messages={messages}
                  selected={selected}
                  onSelect={setSelected}
                  picked={picked}
                  onPick={togglePick}
                />
                <aside aria-label="Message" className="min-w-0 border border-line bg-panel">
                  {!current ? (
                    <p className="px-3 py-3 text-sm text-fg-muted">
                      A row is a message, joined to the one it answers; a colour is a conversation. Click a row to see
                      it here. A hollow node is a message of the file that was not imported.
                    </p>
                  ) : (
                    <div className="space-y-2 px-3 py-3">
                      <p className="flex flex-wrap items-center gap-2 font-semibold">
                        <span
                          className="h-2.5 w-2.5 shrink-0 rounded-full"
                          style={{ background: threadColour(current.thread) }}
                          aria-hidden="true"
                        />
                        <span className="min-w-0 break-words">{current.subject || '(no subject)'}</span>
                      </p>
                      <dl className="grid grid-cols-[6rem_minmax(0,1fr)] gap-x-3 gap-y-0.5 font-mono text-xs">
                        <dt className="text-fg-muted">From</dt>
                        <dd className="break-all">{current.sender}</dd>
                        <dt className="text-fg-muted">To</dt>
                        <dd className="break-all">{current.recipients || '—'}</dd>
                        <dt className="text-fg-muted">Date</dt>
                        <dd>{current.date ? formatDateTime(current.date) : '—'}</dd>
                        <dt className="text-fg-muted">Answers</dt>
                        <dd>
                          {current.parent === null ? (
                            'nothing: it starts the conversation'
                          ) : bySeq.has(current.parent) ? (
                            <button
                              type="button"
                              className="text-left text-link hover:underline"
                              onClick={() => setSelected(current.parent)}
                            >
                              {bySeq.get(current.parent).subject || '(no subject)'}
                            </button>
                          ) : (
                            'a message not listed here'
                          )}
                        </dd>
                        <dt className="text-fg-muted">Answered by</dt>
                        <dd>{messages.filter((message) => message.parent === current.seq).length} listed</dd>
                      </dl>
                      <div className="flex flex-wrap gap-2 pt-1">
                        {current.imported ? (
                          <Button size="sm" icon={Mail} onClick={() => onOpenArtifact(current.artifactId)}>
                            Open the e-mail
                          </Button>
                        ) : (
                          <Button
                            size="sm"
                            icon={Download}
                            disabled={box.status !== 'ready'}
                            onClick={() => importOne(current.seq)}
                          >
                            Import this message
                          </Button>
                        )}
                        {filters.thread === null && (
                          <Button
                            size="sm"
                            variant="secondary"
                            onClick={() => setFilters({ ...filters, thread: current.thread })}
                          >
                            Show only this conversation
                          </Button>
                        )}
                      </div>
                    </div>
                  )}
                </aside>
              </div>
              {(data?.total ?? 0) > messages.length && (
                <p className="text-xs text-fg-muted">
                  The newest {messages.length} are listed: filter, or show one conversation, to see the others.
                </p>
              )}
            </>
          )}
        </>
      )}

      <ImportDialog box={box} open={importing} onClose={() => setImporting(false)} onStarted={reload} />
      <Modal
        open={linking}
        onClose={() => setLinking(false)}
        title="Put messages in an incident"
        footer={
          <>
            <Button variant="ghost" onClick={() => setLinking(false)}>
              Cancel
            </Button>
            <Button icon={FolderPlus} disabled={!target} onClick={link}>
              {picked.size ? `Put the ${picked.size} selected` : `Put all ${box.imported}`}
            </Button>
          </>
        }
      >
        <div className="space-y-3">
          <p>
            {picked.size
              ? `The ${picked.size} selected ${picked.size === 1 ? 'message goes' : 'messages go'} in the incident's Mail Analysis tab.`
              : `All the ${box.imported} imported messages go in the incident's Mail Analysis tab. Tick rows first to put only some.`}
          </p>
          <p className="text-sm text-fg-muted">
            Only the phishing and suspicious ones add indicators to the incident: a mailbox is mostly ordinary mail.
          </p>
          <label className="block space-y-1.5">
            <span className="block font-mono text-xs text-fg-muted">Incident</span>
            <select
              aria-label="Incident"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full border border-line bg-canvas px-2.5 py-1.5 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {incidents.map((incident) => (
                <option key={incident.id} value={incident.id}>
                  {incident.name}
                </option>
              ))}
            </select>
          </label>
        </div>
      </Modal>
    </section>
  )
}
