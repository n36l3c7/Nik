import { useState } from 'react'
import { Check, Pencil, Trash2, X } from 'lucide-react'
import { Button } from '../../ui/index.js'
import { formatDateTime } from '../../../utils/time.js'

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
    <div className="rounded-lg border border-amber-200 bg-amber-50/60 p-3 dark:border-amber-500/20 dark:bg-amber-500/5">
      {editing ? (
        /* ---- Edit mode ---- */
        <div className="space-y-2">
          <textarea
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={3}
            autoFocus
            className="w-full resize-y rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-800 placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder:text-slate-500"
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
          <p className="whitespace-pre-wrap break-words text-sm text-slate-700 dark:text-slate-200">
            {note.text}
          </p>
          <div className="mt-2 flex items-center gap-2">
            <span className="min-w-0 truncate text-xs text-slate-500 dark:text-slate-400">
              {note.author || 'unknown'} · {formatDateTime(Date.parse(note.createdAt))}
              {wasEdited && ' · edited'}
            </span>
            {/* Actions appear on hover to keep the card calm at rest. */}
            <div className="ml-auto flex shrink-0 items-center gap-1 opacity-0 transition-opacity group-hover/note:opacity-100 focus-within:opacity-100">
              <button
                type="button"
                onClick={startEdit}
                aria-label="Edit note"
                className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:hover:bg-slate-800 dark:hover:text-slate-200"
              >
                <Pencil className="h-3.5 w-3.5" />
              </button>
              <button
                type="button"
                onClick={onRemove}
                aria-label="Remove note"
                className="rounded-md p-1 text-slate-400 hover:bg-red-50 hover:text-red-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:hover:bg-red-500/10 dark:hover:text-red-400"
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
