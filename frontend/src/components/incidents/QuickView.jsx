import { useEffect, useMemo, useState } from 'react'
import { FolderOpen, X } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { api } from '../../services/api.js'
import { getOsById } from '../../config/os.js'
import { formatNumber, numberedName } from '../../domain/incidentName.js'
import { shortDateTime } from '../../domain/incidentList.js'
import { blockTitle, countFigures, lastLines, nearestTimer, quickBlocks } from '../../domain/quickView.js'
import { formatRelative } from '../../lib/time.js'
import { Badge, Button, SeverityTag, StatusTag, Wait } from '../ui/index.js'
import ResizeHandle, { useResizablePane } from '../ui/ResizeHandle.jsx'
import LayoutWidget from '../tabs/summary/LayoutWidgets.jsx'
import IncidentTags from '../incident/IncidentTags.jsx'

/*
 * ============================================================================
 * THE QUICK VIEW — an incident of the list, read without opening it
 * ============================================================================
 *
 * A panel over the right side of the incident list, for the row that was
 * clicked. Its header is the number, the type, the title and the tags of the
 * incident; its blocks are those the type of the incident chose
 * (domain/quickView.js), one under the other; its foot opens the incident,
 * takes it, or closes it.
 *
 * It is drawn from the row of the list and from GET /api/incidents/<id>/quick,
 * which gives the fields, the numbers and the last lines of the War Room
 * without the evidence: going down the list with the arrows never downloads a
 * document. The sections, the timers and the texts are the widgets of the
 * Summary; the others are small ones made for a narrow column.
 */

const TERM = 'font-mono text-[11px] uppercase tracking-wider text-fg-muted'
const MUTED = 'text-sm text-fg-muted'
const TONES = {
  note: 'text-fg',
  ok: 'text-fg',
  error: 'text-high',
  ask: 'text-med-fg',
  command: 'font-mono text-fg',
  system: 'text-fg-muted',
}

/** What the incident is, in two columns: what the row of the list holds. */
function Facts({ row }) {
  const facts = [
    ['Owner', row.assignee || 'nobody'],
    ['Opened', shortDateTime(row.createdAt) || '—'],
    ['User', row.username || '—'],
    ['Host', row.host || '—'],
    ['Ticket', row.ticketId || '—'],
    ['System', getOsById(row.os)?.label ?? 'not set'],
  ]
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
      {facts.map(([label, value]) => (
        <div key={label} className="min-w-0">
          <dt className={TERM}>{label}</dt>
          <dd className="break-words text-sm text-fg">{value}</dd>
        </div>
      ))}
    </dl>
  )
}

function Numbers({ counts }) {
  return (
    <dl className="grid grid-cols-3 gap-2">
      {countFigures(counts).map(([label, value]) => (
        <div key={label} className="border border-line-soft bg-canvas px-2 py-1.5">
          <dd className={`font-mono text-lg ${label === 'Flagged' && value > 0 ? 'text-accent' : 'text-fg'}`}>
            {value}
          </dd>
          <dt className="font-mono text-[10px] uppercase tracking-wider text-fg-muted">{label}</dt>
        </div>
      ))}
    </dl>
  )
}

function Last({ entries }) {
  const lines = lastLines(entries)
  if (lines.length === 0) return <p className={MUTED}>Nothing was said or done here yet.</p>
  return (
    <ul className="flex flex-col gap-1.5">
      {lines.map((line) => (
        <li key={line.id} className="text-xs leading-snug">
          <span className="font-mono text-fg-muted" title={shortDateTime(line.at)}>
            {formatRelative(line.at)} · {line.who}
          </span>
          <span className={`line-clamp-2 break-words ${TONES[line.tone] ?? TONES.system}`}>{line.text || '—'}</span>
        </li>
      ))}
    </ul>
  )
}

/** The incidents linked to this one (GET /api/incidents/<id>/linked): each opens that incident. */
function Linked({ incidentId, onOpen }) {
  const [found, setFound] = useState(null)
  const [failed, setFailed] = useState(false)
  useEffect(() => {
    let alive = true
    setFound(null)
    setFailed(false)
    api
      .get(`/incidents/${encodeURIComponent(incidentId)}/linked`)
      .then((answer) => alive && setFound(answer?.incidents ?? []))
      .catch(() => alive && setFailed(true))
    return () => {
      alive = false
    }
  }, [incidentId])
  if (failed) return <p className={MUTED}>The linked incidents could not be read.</p>
  if (found === null) return <Wait>Loading…</Wait>
  if (found.length === 0) return <p className={MUTED}>No incident is linked to this one.</p>
  return (
    <ul className="flex flex-col">
      {found.map((item) => (
        <li key={item.id}>
          <button
            type="button"
            onClick={() => onOpen(item.id)}
            title={`Open ${numberedName(item)}`}
            className="flex w-full items-baseline gap-2 py-0.5 text-left text-sm text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <span className="shrink-0 font-mono text-xs">{formatNumber(item.number)}</span>
            <span className="min-w-0 flex-1 truncate">{item.name}</span>
            <span className="shrink-0 text-xs text-fg-muted">{item.related ? 'related' : `${item.shared} shared`}</span>
          </button>
        </li>
      ))}
    </ul>
  )
}

/**
 * @param {{
 *   row: object,                      // the row of the list that is shown
 *   type: object | null,              // its type of incident
 *   onClose: () => void,
 *   onOpen: (incidentId: string) => void,
 *   onTag?: (tag: string) => void,    // a click on a tag: the list is filtered by it
 * }} props
 */
export default function QuickView({ row, type, onClose, onOpen, onTag }) {
  const { currentUser, can } = useAuth()
  const { setIncidentTriage, askClose } = useIncidents()
  const pane = useResizablePane('incidents.quick', { initial: 440, min: 340, max: 720, edge: 'left' })
  const canWrite = can('write')
  const me = currentUser?.username ?? ''
  const [quick, setQuick] = useState(null)
  const [error, setError] = useState(null)

  // Read again when the incident changes (an owner, a closing, a field edited from here).
  useEffect(() => {
    let alive = true
    setError(null)
    api
      .get(`/incidents/${encodeURIComponent(row.id)}/quick`)
      .then((answer) => alive && setQuick(answer))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [row.id, row.updatedAt])
  // What was read is of another row until the answer for this one comes.
  const held = quick?.id === row.id ? quick : null

  const blocks = useMemo(() => quickBlocks(type), [type])
  // A section is drawn in one column here, whatever it has on the Summary.
  const narrowType = useMemo(
    () =>
      type?.layout
        ? {
            ...type,
            layout: {
              ...type.layout,
              sections: (type.layout.sections ?? []).map((section) => ({ ...section, columns: 1 })),
            },
          }
        : type,
    [type],
  )
  // The incident as the widgets of the Summary read it: the row, and the fields the server gave.
  const incident = useMemo(() => ({ ...row, fields: held?.fields ?? {}, data: {}, flags: {}, notes: [] }), [row, held])
  const timer = nearestTimer(held?.timers)
  const mine = Boolean(me) && row.assignee.toLowerCase() === me.toLowerCase()
  const label = formatNumber(row.number) || row.name

  const draw = (block) => {
    if (block.kind === 'facts') return <Facts row={row} />
    if (block.kind === 'linked') return <Linked incidentId={row.id} onOpen={onOpen} />
    if (!held) return <Wait>Loading…</Wait>
    if (block.kind === 'stats') return <Numbers counts={held.counts} />
    if (block.kind === 'last') return <Last entries={held.last} />
    if (block.kind === 'timers' && held.timers.length === 0) return <p className={MUTED}>No timer was started.</p>
    return <LayoutWidget widget={block} incident={incident} type={narrowType} />
  }

  return (
    <aside
      aria-label={`Quick view of incident ${label}`}
      style={pane.style}
      className="absolute inset-y-0 right-0 z-20 flex w-full max-w-full border-l border-line bg-panel shadow-2xl sm:w-[var(--pane-w)]"
    >
      <ResizeHandle {...pane.handle} label="Resize the quick view" className="hidden sm:block" />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex shrink-0 flex-col gap-2 border-b border-line px-4 py-3">
          <div className="flex items-start gap-2">
            <div className="min-w-0 flex-1">
              <p className="truncate font-mono text-xs text-fg-muted">
                {[formatNumber(row.number), type?.name].filter(Boolean).join(' · ')}
              </p>
              <h2 className="break-words text-[15px] font-semibold leading-snug text-fg">{row.name}</h2>
            </div>
            <Button variant="ghost" size="sm" icon={X} aria-label="Close the quick view" onClick={onClose} />
          </div>
          <div className="flex flex-wrap items-center gap-1.5">
            <SeverityTag severity={row.severity} />
            <StatusTag status={row.status} showOpen />
            {timer && (
              <Badge color={timer.late ? 'red' : 'slate'} title={timer.label}>
                {timer.text}
              </Badge>
            )}
          </div>
          <IncidentTags incidentId={row.id} tags={row.tags} onPick={onTag} />
        </header>

        <div className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto px-4 py-3">
          {error && (
            <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">
              {error}
            </p>
          )}
          {blocks.map((block) => {
            const title = blockTitle(block, type?.layout)
            return (
              <section key={block.id} aria-label={title || 'A text'}>
                {/* The button of a widget of the Summary stands in the line of its title, as on the page. */}
                {title && <h3 className={`flex h-8 items-center ${TERM}`}>{title}</h3>}
                {draw(block)}
              </section>
            )
          })}
        </div>

        <footer className="flex shrink-0 flex-wrap gap-2 border-t border-line px-4 py-3">
          <Button size="sm" icon={FolderOpen} onClick={() => onOpen(row.id)}>
            Open the incident
          </Button>
          {canWrite && me && !mine && (
            <Button size="sm" variant="secondary" onClick={() => setIncidentTriage(row.id, { assignee: me })}>
              Assign to me
            </Button>
          )}
          {canWrite && row.status !== 'closed' && (
            <Button size="sm" variant="secondary" onClick={() => askClose(row.id)}>
              Close…
            </Button>
          )}
        </footer>
      </div>
    </aside>
  )
}
