import { useEffect, useMemo, useState } from 'react'
import {
  Bug,
  CornerDownRight,
  Download,
  Flag,
  Link2,
  Mail,
  Network,
  Plus,
  ScrollText,
  Search,
  StickyNote,
  Terminal,
  Trash2,
  X,
} from 'lucide-react'
import { useItemMenu, useRowMenu } from '../../menu/useRowMenu.js'
import { Badge, Button, EmptyState } from '../../ui/index.js'
import NoteBlock from './NoteBlock.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { useNavigation } from '../../../context/NavigationContext.jsx'
import { formatDateTime, formatRelative } from '../../../lib/time.js'
import { truncate } from '../../../lib/url.js'
import { HOST_KIND_META, recordLabel } from '../../../domain/timeline.js'
import { useCanWrite } from '../../../lib/useCanWrite.js'
import { evidence } from '../../../services/api.js'
import { useEvidenceSummary } from '../../../lib/useEvidenceSummary.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * ============================================================================
 * INCIDENT TIMELINE
 * ============================================================================
 *
 * A vertical timeline that merges two kinds of items into a single, time-sorted
 * stream:
 *   - FLAGS: entries the analyst marked as malicious (Object.values(incident.flags));
 *            sorted by `.time` (Unix ms). Each flag can carry free-form comments.
 *   - MARKS: the host records flagged on the pages of host evidence; they live on the
 *            server (`evidence.records` with `flagged`), with the note each carries.
 *   - NOTES: standalone note blocks (incident.notes); sorted by `.createdAt`.
 *
 * A composer at the top lets the analyst add a free note. Items with no usable
 * timestamp sink to the bottom of the list.
 */

/** Resolve the sortable Unix-ms timestamp of a merged item (null → +Infinity). */
function itemMs(item) {
  if (item.kind === 'mark') return Number.isFinite(item.data.ts) ? item.data.ts : Number.POSITIVE_INFINITY
  if (item.kind === 'flag') {
    return Number.isFinite(item.data.time) ? item.data.time : Number.POSITIVE_INFINITY
  }
  const ms = Date.parse(item.data.createdAt)
  return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY
}

export default function IncidentTimeline({ incident }) {
  const { addFlagComment, removeFlagComment, addNote, updateNote, removeNote } = useIncidents()
  const [noteDraft, setNoteDraft] = useState('')
  const canWrite = useCanWrite(incident)
  const { goTo } = useNavigation()

  // The host records flagged (a page of them: a few are flagged out of millions).
  const { summary } = useEvidenceSummary(incident.id)
  const [marks, setMarks] = useState([])
  const [marked, setMarked] = useState(0)
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .records(incident.id, { filters: { flagged: true }, order: 'time', limit: 100, signal: controller.signal })
      .then((page) => setMarks(page.records ?? []))
      .catch(() => {})
    return () => controller.abort()
  }, [incident.id, summary, marked])
  const unflag = async (record) => {
    await evidence.putMark(incident.id, { key: record.key, flagged: false, note: record.note })
    setMarked((count) => count + 1)
  }

  const rowMenu = useRowMenu(incident)
  const menu = useItemMenu(incident)

  // Merge flags + notes into one chronologically ordered stream (oldest first).
  const items = useMemo(() => {
    const flags = Object.values(incident.flags ?? {}).map((flag) => ({
      kind: 'flag',
      key: `flag:${flag.key}`,
      data: flag,
    }))
    const notes = (incident.notes ?? []).map((note) => ({
      kind: 'note',
      key: `note:${note.id}`,
      data: note,
    }))
    const hosts = marks.map((record) => ({ kind: 'mark', key: `mark:${record.key}`, data: record }))
    return [...flags, ...hosts, ...notes].sort((a, b) => itemMs(a) - itemMs(b))
  }, [incident.flags, incident.notes, marks])

  const isEmpty = items.length === 0

  const handleAddNote = () => {
    const text = noteDraft.trim()
    if (!text) return
    addNote(incident.id, text)
    setNoteDraft('')
  }
  useUnsavedChanges(Boolean(noteDraft.trim()), {
    what: 'The note being written on the incident',
    name: incident.name,
    save: async () => handleAddNote(),
  })

  return (
    <div className="space-y-5">
      {/* ---- Composer: add a free note block ---- */}
      <div className="border border-line bg-canvas p-3">
        <label htmlFor="timeline-note" className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-fg-muted">
          <StickyNote className="h-3.5 w-3.5" aria-hidden="true" />
          Add a note
        </label>
        <textarea
          id="timeline-note"
          value={noteDraft}
          onChange={(e) => setNoteDraft(e.target.value)}
          rows={2}
          placeholder="Add a note to the incident timeline…"
          className="w-full resize-y border border-line bg-panel px-3 py-2 text-sm text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <div className="mt-2 flex justify-end">
          <Button size="sm" icon={Plus} onClick={handleAddNote} disabled={!noteDraft.trim()}>
            Add note
          </Button>
        </div>
      </div>

      {/* ---- Timeline / empty state ---- */}
      {isEmpty ? (
        <EmptyState
          skull
          compact
          title="No flags or notes yet"
          message="No flagged entries or notes yet. Flag entries in the evidence pages to build the incident timeline."
        />
      ) : (
        <div className="relative">
          {/* Vertical rail passing through the centre of every dot. */}
          <span aria-hidden="true" className="pointer-events-none absolute bottom-2 left-[11px] top-2 w-px bg-raised" />
          <ol className="space-y-5">
            {items.map((item) =>
              item.kind === 'mark' ? (
                <MarkTimelineItem
                  key={item.key}
                  record={item.data}
                  canWrite={canWrite}
                  onOpen={() => goTo(HOST_KIND_META[item.data.kind]?.tab ?? 'evidence')}
                  onUnflag={() => unflag(item.data)}
                />
              ) : item.kind === 'flag' ? (
                <FlagTimelineItem
                  key={item.key}
                  flag={item.data}
                  onAddComment={(text) => addFlagComment(incident.id, item.data.key, text)}
                  onRemoveComment={(commentId) => removeFlagComment(incident.id, item.data.key, commentId)}
                  onMenu={(event) => rowMenu(event, { flaggable: item.data, record: item.data })}
                />
              ) : (
                <TimelineRow
                  key={item.key}
                  icon={StickyNote}
                  tone="note"
                  onMenu={(event) =>
                    menu(event, {
                      title: 'Note',
                      text: item.data.text,
                      record: item.data,
                      danger: [
                        {
                          label: 'Delete the note',
                          icon: Trash2,
                          onSelect: () => removeNote(incident.id, item.data.id),
                        },
                      ],
                    })
                  }
                >
                  <NoteBlock
                    note={item.data}
                    onSave={(text) => updateNote(incident.id, item.data.id, text)}
                    onRemove={() => removeNote(incident.id, item.data.id)}
                  />
                </TimelineRow>
              ),
            )}
          </ol>
        </div>
      )}
    </div>
  )
}

/* -------------------------------------------------------------------------- */
/* Timeline row: the left dot + rail gap + the item content.                  */
/* -------------------------------------------------------------------------- */

// Dot colour per item kind (icon box on the rail). Every colour has a dark pair.
const DOT_TONES = {
  flag: 'bg-accent-soft text-accent',
  note: 'bg-med-soft text-med',
}

function TimelineRow({ icon: Icon, tone, children, onMenu }) {
  return (
    <li className="relative pl-9" onContextMenu={onMenu}>
      {/* The ring matches the Card body background so the rail visually breaks. */}
      <span
        className={`absolute left-0 top-0.5 flex h-6 w-6 items-center justify-center rounded-full ring-4 ring-panel ${
          DOT_TONES[tone] ?? DOT_TONES.note
        }`}
      >
        <Icon className="h-3 w-3" aria-hidden="true" />
      </span>
      {children}
    </li>
  )
}

const TYPE_ICONS = {
  visit: Link2,
  search: Search,
  redirect: CornerDownRight,
  download: Download,
  command: Terminal,
  sample: Bug,
  eventlog: ScrollText,
  syslog: ScrollText,
  mail: Mail,
  network: Network,
}

/** The small icon of what a flagged entry is (a visit, a command, a sample…). */
function TypeIcon({ type }) {
  const Icon = TYPE_ICONS[type] ?? Link2
  return <Icon className="mt-0.5 h-4 w-4 shrink-0 text-fg-muted" aria-hidden="true" />
}

/* -------------------------------------------------------------------------- */
/* Mark item: a host record flagged on the server, with its note.             */
/* -------------------------------------------------------------------------- */

function MarkTimelineItem({ record, canWrite, onOpen, onUnflag }) {
  const meta = HOST_KIND_META[record.kind]
  return (
    <TimelineRow icon={Flag} tone="flag">
      <div className="border border-line border-l-2 border-l-accent-strong bg-accent-soft p-3">
        <div className="flex items-start gap-2">
          <TypeIcon
            type={
              record.kind === 'eventlog' || record.kind === 'syslog'
                ? 'eventlog'
                : record.kind === 'commands'
                  ? 'command'
                  : record.type
            }
          />
          <span className="min-w-0 flex-1 break-words text-sm font-medium text-fg">{recordLabel(record)}</span>
        </div>
        {record.note && <p className="mt-1 whitespace-pre-wrap break-words text-sm text-fg">{record.note}</p>}
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-fg-muted">{record.ts ? formatDateTime(record.ts) : '—'}</span>
          <Badge color={meta?.color ?? 'slate'}>{meta?.label ?? record.kind}</Badge>
          {record.host && <Badge color="slate">{record.host}</Badge>}
          <Button variant="ghost" size="xs" onClick={onOpen}>
            Open its page
          </Button>
          {canWrite && (
            <Button variant="ghost" size="xs" onClick={onUnflag}>
              Remove the flag
            </Button>
          )}
        </div>
      </div>
    </TimelineRow>
  )
}

/* -------------------------------------------------------------------------- */
/* Flag item: event summary + per-flag comments (add / remove).               */
/* -------------------------------------------------------------------------- */

function FlagTimelineItem({ flag, onAddComment, onRemoveComment, onMenu }) {
  const [comment, setComment] = useState('')
  const comments = flag.comments ?? []

  const submit = () => {
    const text = comment.trim()
    if (!text) return
    onAddComment(text)
    setComment('')
  }
  useUnsavedChanges(Boolean(comment.trim()), {
    what: 'The comment being written on a flag',
    save: async () => submit(),
  })

  return (
    <TimelineRow icon={Flag} tone="flag" onMenu={onMenu}>
      <div className="border border-line border-l-2 border-l-accent-strong bg-accent-soft p-3">
        {/* Header: event type icon + title */}
        <div className="flex items-start gap-2">
          <TypeIcon type={flag.eventType} />
          <span className="min-w-0 flex-1 break-words text-sm font-medium text-fg">
            {flag.title || flag.url || flag.key}
          </span>
        </div>

        {/* URL (mono, truncated) */}
        {flag.url && (
          <p className="mt-1 truncate font-mono text-xs text-fg-muted" title={flag.url}>
            {truncate(flag.url, 90)}
          </p>
        )}

        {/* Meta: time + browser + section badges */}
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <span className="font-mono text-xs text-fg-muted">{formatDateTime(flag.time)}</span>
          {flag.browserId && <Badge color="cyan">{flag.browserId}</Badge>}
          {flag.section && <Badge color="slate">{flag.section}</Badge>}
        </div>

        {/* Existing comments */}
        {comments.length > 0 && (
          <ul className="mt-3 space-y-2 border-t border-line pt-3">
            {comments.map((c) => (
              <li key={c.id} className="group/comment flex items-start gap-2">
                <div className="min-w-0 flex-1">
                  <div className="text-xs text-fg-muted">
                    <span className="font-medium text-fg-muted">{c.author || 'unknown'}</span> · {formatRelative(c.at)}
                  </div>
                  <p className="whitespace-pre-wrap break-words text-sm text-fg">{c.text}</p>
                </div>
                <button
                  type="button"
                  onClick={() => onRemoveComment(c.id)}
                  aria-label="Remove comment"
                  className="shrink-0 p-1 text-fg-muted opacity-0 transition-opacity hover:bg-high-soft hover:text-high focus-visible:opacity-100 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent group-hover/comment:opacity-100"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </li>
            ))}
          </ul>
        )}

        {/* Add a comment */}
        <div className="mt-3 flex items-center gap-2">
          <input
            type="text"
            value={comment}
            onChange={(e) => setComment(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault()
                submit()
              }
            }}
            placeholder="Add a comment…"
            className="min-w-0 flex-1 border border-line bg-panel px-3 py-1.5 text-sm text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <Button variant="secondary" size="sm" icon={Plus} onClick={submit} disabled={!comment.trim()}>
            Comment
          </Button>
        </div>
      </div>
    </TimelineRow>
  )
}
