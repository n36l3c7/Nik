import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { Plus } from 'lucide-react'
import { useCanWrite } from '../../lib/useCanWrite.js'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { TAGS_FIELD, addTag, removeTag, suggestTags, tagsInUse } from '../../domain/incidentTags.js'
import { api } from '../../services/api.js'
import { Chip } from '../ui/index.js'

/*
 * The tags of an incident as chips, changed where they are read: in the
 * header of the incident, in the quick view of the list, in the dialog the
 * menu of a row opens.
 *
 * Whoever may change incidents has an × on each chip and a "+" that opens an
 * input: it offers the tags the other incidents carry, Enter adds what is
 * typed (or the tag chosen with the arrows), Backspace in the empty input
 * takes the last tag off, Escape closes it. Each change is saved at once
 * through the field registry (PATCH /api/incidents/<id>/fields, the field
 * `labels`), which checks it and leaves the trace a field change leaves.
 * A read-only account sees the chips and nothing else.
 */

const ADD =
  'inline-flex h-[22px] items-center gap-1 border border-dashed border-line px-1.5 font-mono text-xs text-fg-muted ' +
  'hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   incidentId: string,
 *   tags: string[],                    // what the incident carries, as it was last read
 *   onPick?: (tag: string) => void,    // a click on a tag (the list: filter by it)
 *   pickLabel?: (tag: string) => string,
 *   startOpen?: boolean,               // the input is open at once (the dialog of the list)
 *   empty?: string,                    // what is said when there is no tag and nothing to add with
 *   className?: string,
 * }} props
 */
export default function IncidentTags({
  incidentId,
  tags,
  onPick,
  pickLabel = (tag) => `Filter by the tag ${tag}`,
  startOpen = false,
  empty = '',
  className = '',
}) {
  const { incidents, refreshIncidents, retryActiveIncident } = useIncidents()
  const canWrite = useCanWrite()
  const listId = useId()
  const inputRef = useRef(null)
  // What was saved from here and the lists have not caught up with yet.
  const [saved, setSaved] = useState(null)
  const [adding, setAdding] = useState(startOpen)
  const [typed, setTyped] = useState('')
  const [cursor, setCursor] = useState(-1)
  const [error, setError] = useState(null)
  // The changes go to the server one after the other, each with the whole list as it then is.
  const queue = useRef(Promise.resolve())
  const pending = useRef(0)

  const read = Array.isArray(tags) ? tags : []
  const readKey = read.join('\n')
  useEffect(() => {
    if (pending.current === 0) setSaved(null)
  }, [incidentId, readKey])
  useEffect(() => {
    setError(null)
    setTyped('')
  }, [incidentId])

  const shown = saved ?? read
  const inUse = useMemo(() => tagsInUse(incidents), [incidents])
  const offered = adding ? suggestTags(inUse, shown, typed) : []

  const save = (next) => {
    setSaved(next)
    setError(null)
    pending.current += 1
    queue.current = queue.current
      .then(() =>
        api.patch(`/incidents/${encodeURIComponent(incidentId)}/fields`, {
          changes: { [TAGS_FIELD]: next.length > 0 ? next : null },
        }),
      )
      .then((answer) => {
        pending.current -= 1
        if (pending.current === 0) setSaved(answer?.fields?.[TAGS_FIELD] ?? [])
        // The server wrote them: the list and the open incident are read again.
        refreshIncidents()
        retryActiveIncident()
      })
      .catch((failure) => {
        pending.current -= 1
        // Nothing was saved: what the incident carries is shown again, with why.
        setSaved(null)
        setError(failure.message)
      })
  }

  const add = (text) => {
    const result = addTag(shown, text)
    if (result.error) {
      setError(result.error)
      return
    }
    setTyped('')
    setCursor(-1)
    if (result.tags !== shown) save(result.tags)
    else setError(null)
  }

  const close = () => {
    setAdding(false)
    setTyped('')
    setCursor(-1)
    setError(null)
  }

  const onKeyDown = (event) => {
    if (event.key === 'Enter' || event.key === ',') {
      event.preventDefault()
      const chosen = cursor >= 0 ? offered[cursor] : typed
      if (String(chosen ?? '').trim()) add(chosen)
    } else if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      if (offered.length === 0) return
      event.preventDefault()
      const step = event.key === 'ArrowDown' ? 1 : -1
      setCursor((current) => {
        const next = current + step
        return next < -1 ? offered.length - 1 : next >= offered.length ? -1 : next
      })
    } else if (event.key === 'Backspace' && typed === '' && shown.length > 0) {
      event.preventDefault()
      save(shown.slice(0, -1))
    } else if (event.key === 'Escape' && !startOpen) {
      // The input closes, and nothing else: not the quick view it is in.
      event.preventDefault()
      event.stopPropagation()
      close()
    }
  }

  if (!canWrite && shown.length === 0) {
    return empty ? <span className={`text-xs text-fg-subtle ${className}`}>{empty}</span> : null
  }

  return (
    <div role="group" aria-label="Tags" className={`flex min-w-0 flex-wrap items-center gap-1 ${className}`}>
      {shown.map((tag) => (
        <Chip
          key={tag}
          onClick={onPick ? () => onPick(tag) : undefined}
          label={onPick ? pickLabel(tag) : undefined}
          title={onPick ? pickLabel(tag) : undefined}
          onRemove={canWrite ? () => save(removeTag(shown, tag)) : undefined}
          removeLabel={`Remove the tag ${tag}`}
        >
          #{tag}
        </Chip>
      ))}
      {canWrite && !adding && (
        <button
          type="button"
          aria-label="Add a tag"
          title="Add a tag"
          onClick={() => {
            setAdding(true)
            // Opened by a person: the input takes the focus once it is drawn.
            requestAnimationFrame(() => inputRef.current?.focus())
          }}
          className={ADD}
        >
          <Plus className="h-3 w-3" aria-hidden="true" />
          {shown.length === 0 && <span>tag</span>}
        </button>
      )}
      {canWrite && adding && (
        <span className="relative inline-flex">
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-label="New tag"
            aria-expanded={offered.length > 0}
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={cursor >= 0 ? `${listId}-${cursor}` : undefined}
            autoFocus={startOpen}
            autoComplete="off"
            spellCheck={false}
            maxLength={60}
            value={typed}
            placeholder="tag, then Enter"
            onChange={(event) => {
              setTyped(event.target.value)
              setCursor(-1)
              setError(null)
            }}
            onKeyDown={onKeyDown}
            onBlur={() => {
              // Left empty, it closes; with something typed it waits to be finished.
              if (!startOpen && typed.trim() === '') close()
            }}
            className="h-[22px] w-36 border border-line bg-canvas px-1.5 font-mono text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <ul
            id={listId}
            role="listbox"
            aria-label="Tags in use"
            hidden={offered.length === 0}
            className="absolute left-0 top-full z-30 mt-0.5 max-h-56 min-w-full overflow-y-auto border border-line bg-panel py-0.5 shadow-2xl"
          >
            {offered.map((tag, index) => (
              <li
                key={tag}
                id={`${listId}-${index}`}
                role="option"
                aria-selected={index === cursor}
                // The input keeps the focus: a click on a tag is not a blur.
                onMouseDown={(event) => event.preventDefault()}
                onClick={() => add(tag)}
                onMouseEnter={() => setCursor(index)}
                className={`cursor-default whitespace-nowrap px-2 py-0.5 font-mono text-xs ${
                  index === cursor ? 'bg-raised text-fg' : 'text-fg-muted'
                }`}
              >
                #{tag}
              </li>
            ))}
          </ul>
        </span>
      )}
      {error && (
        <span role="alert" className="basis-full text-xs text-high-fg">
          {error}
        </span>
      )}
    </div>
  )
}
