import { useCallback, useEffect, useState } from 'react'
import { Flag, StickyNote } from 'lucide-react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { evidence } from '../../services/api.js'

/*
 * The small pieces the pages of host evidence that came with 7.0 (Disk, Linux and macOS logs) share: a text
 * filter, the values of a field for a select, and the flag and note of a record (`evidence.putMark`).
 */

const INPUT =
  'border border-line bg-canvas px-2 py-1.5 font-mono text-[13px] text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** A text filter: typed freely, applied on Enter or when the field is left. */
export function FilterInput({ label, value, onCommit, width = 'w-28', inputMode }) {
  const [text, setText] = useState(value)
  useEffect(() => setText(value), [value])
  const commit = () => {
    if (text.trim() !== value) onCommit(text.trim())
  }
  return (
    <label className="inline-flex items-center gap-2">
      <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{label}</span>
      <input
        value={text}
        inputMode={inputMode}
        onChange={(event) => setText(event.target.value)}
        onBlur={commit}
        onKeyDown={(event) => event.key === 'Enter' && commit()}
        className={`${INPUT} ${width}`}
      />
    </label>
  )
}

const NO_VALUES = []

/** The stack of a field (`values`: `{ value, count }`, the most common first, 100 at most) for the filters given. */
export function useStackValues(incidentId, field, filters, refresh = 0) {
  const [values, setValues] = useState(NO_VALUES)
  const key = JSON.stringify(filters)
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .stack(incidentId, { field, order: 'common', limit: 100, filters: JSON.parse(key), signal: controller.signal })
      .then((answer) => setValues(answer.values))
      .catch(() => setValues(NO_VALUES))
    return () => controller.abort()
  }, [incidentId, field, key, refresh])
  return values
}

/**
 * The flag and the note of the rows of a table: `{ flagged(row), noteOf(row), mark(row, changes), addNote(row) }`.
 * What was marked since the page loaded is kept here, so the row shows it without loading the page again.
 */
export function useMarks(incidentId) {
  const { askText } = useContextMenu()
  const { showToast } = useToast()
  const [flags, setFlags] = useState({})
  const [notes, setNotes] = useState({})
  useEffect(() => {
    setFlags({})
    setNotes({})
  }, [incidentId])
  const flagged = useCallback((row) => flags[row.key] ?? row.flagged, [flags])
  const noteOf = useCallback((row) => notes[row.key] ?? row.note, [notes])
  const mark = useCallback(
    async (row, changes = {}) => {
      const next = { flagged: flagged(row), note: noteOf(row), ...changes }
      try {
        await evidence.putMark(incidentId, { key: row.key, flagged: next.flagged, note: next.note })
        setFlags((before) => ({ ...before, [row.key]: next.flagged }))
        setNotes((before) => ({ ...before, [row.key]: next.note }))
      } catch (failure) {
        showToast({ message: failure?.message || 'The mark could not be saved.' })
      }
    },
    [incidentId, flagged, noteOf, showToast],
  )
  const addNote = useCallback(
    async (row) => {
      const text = await askText({
        title: 'Note on this record',
        label: 'Note',
        placeholder: 'What this record shows',
        confirm: 'Save',
      })
      if (text !== null && text !== undefined) mark(row, { note: text.trim() })
    },
    [askText, mark],
  )
  return { flagged, noteOf, mark, addNote }
}

/** The cell of the flag column: the flag button and, when the row has one, its note. */
export function FlagCell({ row, marks, canWrite }) {
  const on = marks.flagged(row)
  const note = marks.noteOf(row)
  return (
    <span className="inline-flex items-center gap-1">
      <button
        type="button"
        disabled={!canWrite}
        onClick={(event) => {
          event.stopPropagation()
          marks.mark(row, { flagged: !on })
        }}
        aria-label={on ? 'Remove flag' : 'Flag as malicious'}
        aria-pressed={on}
        title={on ? 'Remove flag' : 'Flag as malicious'}
        className={[
          'inline-flex items-center justify-center p-1 transition-colors disabled:cursor-not-allowed',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
          on ? 'text-accent hover:text-accent-fg' : 'text-fg-muted hover:text-accent',
        ].join(' ')}
      >
        <Flag className="h-4 w-4" fill={on ? 'currentColor' : 'none'} aria-hidden="true" />
      </button>
      {note && <StickyNote className="h-3.5 w-3.5 text-fg-muted" aria-label={`Note: ${note}`} />}
    </span>
  )
}

export const FLAG_HIGHLIGHT = 'bg-accent-soft border-l-2 border-l-accent-strong'
