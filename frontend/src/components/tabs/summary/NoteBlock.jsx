import { useState } from 'react'
import { Check, Pencil, Trash2, X } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { formatDateTime } from '../../../lib/time.js'

/*
 * NoteBlock — a small, self-contained editable note card.
 *
 * Two modes:
 *   - view: renders the note text, its author and creation time (plus an
 *     "edited" hint when it was later modified), with Edit / Remove actions.
 *   - edit: a textarea with Save / Cancel.
 *
 * Notes carry an amber tint so they are visually distinct from the cyan
 * flag cards on the incident timeline.
 *
 * @param {{
 *   note: { id, text, createdAt, updatedAt, author },
 *   onSave: (text: string) => void,
 *   onRemove: () => void,
 * }} props
 */
export default function NoteBlock({ note, onSave, onRemove }) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(note.text)

  // Enter edit mode with a fresh copy of the current text.
  const startEdit = () => {
    setDraft(note.text)
    setEditing(true)
  }

  const save = () => {
    const text = draft.trim()
    if (!text) return
    onSave(text)
    setEditing(false)
  }

  const cancel = () => {
    setDraft(note.text)
    setEditing(false)
  }

  // The note was modified after creation (small "edited" hint in the footer).
  const wasEdited = note.updatedAt && note.updatedAt !== note.createdAt

  return (
    <div className="border border-med-line bg-med-soft p-3">
      {editing ? (
        /* ---- Edit mode ---- */
        <div className="space-y-2">
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={3}
            autoFocus
            className="w-full resize-y border border-line bg-panel px-3 py-2 text-sm text-fg placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            placeholder="Note text…"
          />
          <div className="flex items-center justify-end gap-2">
            <Button variant="ghost" size="xs" icon={X} onClick={cancel}>
              Cancel
            </Button>
            <Button size="xs" icon={Check} onClick={save} disabled={!draft.trim()}>
              Save
            </Button>
          </div>
        </div>
      ) : (
        /* ---- View mode ---- */
        <div className="group/note">
          <p className="whitespace-pre-wrap break-words text-sm text-fg">{note.text}</p>
          <div className="mt-2 flex items-center gap-2">
            <span className="min-w-0 truncate text-xs text-fg-muted">
              {note.author || 'unknown'} · {formatDateTime(Date.parse(note.createdAt))}
              {wasEdited && ' · edited'}
            </span>
            {/* Actions appear on hover to keep the card calm at rest. */}
            <div className="ml-auto flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover/note:opacity-100 focus-within:opacity-100">
              <button
                type="button"
                onClick={startEdit}
                aria-label="Edit note"
                className="p-1 text-fg-muted hover:bg-canvas hover:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <Pencil className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                onClick={onRemove}
                aria-label="Remove note"
                className="p-1 text-fg-muted hover:bg-high-soft hover:text-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
