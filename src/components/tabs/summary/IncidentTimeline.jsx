import { useMemo, useState } from 'react'
import { Flag, ListTree, Plus, StickyNote, X } from 'lucide-react'
import { Badge, Button } from '../../ui/index.js'
import EventTypeIcon from '../browser/EventTypeIcon.jsx'
import NoteBlock from './NoteBlock.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { formatDateTime, formatRelative } from '../../../utils/time.js'
import { truncate } from '../../../utils/url.js'
import { flagProfile } from '../../../utils/browserProfiles.js'

/*
 * ============================================================================
 * INCIDENT TIMELINE
 * ============================================================================
 *
 * A vertical timeline that merges two kinds of items into a single, time-sorted
 * stream:
 *   - FLAGS: entries the analyst marked as malicious in the Browser Forensics
 *            tab (Object.values(incident.flags)); sorted by `.time` (Unix ms).
 *            Each flag can carry free-form comments.
 *   - NOTES: standalone note blocks (incident.notes); sorted by `.createdAt`.
 *
 * A composer at the top lets the analyst add a free note. Items with no usable
 * timestamp sink to the bottom of the list.
 */

/** Resolve the sortable Unix-ms timestamp of a merged item (null → +Infinity). */
function itemMs(item) {
  if (item.kind === 'flag') {
    return Number.isFinite(item.data.time) ? item.data.time : Number.POSITIVE_INFINITY
  }
  const ms = Date.parse(item.data.createdAt)
  return Number.isFinite(ms) ? ms : Number.POSITIVE_INFINITY
}

export default function IncidentTimeline({ incident }) {
  const { addFlagComment, removeFlagComment, addNote, updateNote, removeNote } = useIncidents()
  const [noteDraft, setNoteDraft] = useState('')

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
    return [...flags, ...notes].sort((a, b) => itemMs(a) - itemMs(b))
  }, [incident.flags, incident.notes])

  const isEmpty = items.length === 0

  const handleAddNote = () => {
    const text = noteDraft.trim()
    if (!text) return
    addNote(incident.id, text)
    setNoteDraft('')
  }

  return (
    <div className="space-y-5">
      {/* ---- Composer: add a free note block ---- */}
      <div className="border border-line bg-canvas p-3">
        <label
          htmlFor="timeline-note"
          className="mb-1.5 flex items-center gap-1.5 text-xs font-medium text-fg-muted"
        >
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
        <div className="flex flex-col items-center gap-2 border border-dashed border-line px-6 py-10 text-center">
          <div className="flex h-12 w-12 items-center justify-center bg-canvas">
            <ListTree className="h-6 w-6 text-fg-muted" aria-hidden="true" />
          </div>
          <p className="max-w-md text-sm text-fg-muted">
            No flagged entries or notes yet. Flag entries in the Browser Forensics tab to build
            the incident timeline.
          </p>
        </div>
      ) : (
        <div className="relative">
          {/* Vertical rail passing through the centre of every dot. */}
          <span
            aria-hidden="true"
            className="pointer-events-none absolute bottom-2 left-[11px] top-2 w-px bg-raised"
          />
          <ol className="space-y-5">
            {items.map((item) =>
              item.kind === 'flag' ? (
                <FlagTimelineItem
                  key={item.key}
                  flag={item.data}
                  profile={flagProfile(incident.data?.browser?.browsers, item.data)}
                  onAddComment={(text) => addFlagComment(incident.id, item.data.key, text)}
                  onRemoveComment={(commentId) =>
                    removeFlagComment(incident.id, item.data.key, commentId)
                  }
                />
              ) : (
                <TimelineRow key={item.key} icon={StickyNote} tone="note">
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

function TimelineRow({ icon: Icon, tone, children }) {
  return (
    <li className="relative pl-9">
      {/* The ring matches the Card body background so the rail visually breaks. */}
      <span
        className={`absolute left-0 top-0.5 flex h-6 w-6 items-center justify-center rounded-full ring-4 ring-white ${
          DOT_TONES[tone] ?? DOT_TONES.note
        }`}
      >
        <Icon className="h-3 w-3" aria-hidden="true" />
      </span>
      {children}
    </li>
  )
}

/* -------------------------------------------------------------------------- */
/* Flag item: event summary + per-flag comments (add / remove).               */
/* -------------------------------------------------------------------------- */

function FlagTimelineItem({ flag, profile, onAddComment, onRemoveComment }) {
  const [comment, setComment] = useState('')
  const comments = flag.comments ?? []

  const submit = () => {
    const text = comment.trim()
    if (!text) return
    onAddComment(text)
    setComment('')
  }

  return (
    <TimelineRow icon={Flag} tone="flag">
      <div className="border border-line border-l-2 border-l-accent-strong bg-accent-soft p-3">
        {/* Header: event type icon + title */}
        <div className="flex items-start gap-2">
          <EventTypeIcon type={flag.eventType} />
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
          <span className="font-mono text-xs text-fg-muted">
            {formatDateTime(flag.time)}
          </span>
          {flag.browserId && <Badge color="cyan">{flag.browserId}</Badge>}
          {profile && (
            <Badge color={profile.deleted ? 'amber' : 'slate'}>
              {profile.deleted ? `${profile.name} (deleted profile)` : profile.name}
            </Badge>
          )}
          {flag.section && <Badge color="slate">{flag.section}</Badge>}
        </div>

        {/* Existing comments */}
        {comments.length > 0 && (
          <ul className="mt-3 space-y-2 border-t border-line pt-3">
            {comments.map((c) => (
              <li key={c.id} className="group/comment flex items-start gap-2">
                <div className="min-w-0 flex-1">
                  <div className="text-xs text-fg-muted">
                    <span className="font-medium text-fg-muted">
                      {c.author || 'unknown'}
                    </span>{' '}
                    · {formatRelative(c.at)}
                  </div>
                  <p className="whitespace-pre-wrap break-words text-sm text-fg">
                    {c.text}
                  </p>
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
