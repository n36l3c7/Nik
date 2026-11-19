import { useEffect, useId, useMemo, useRef, useState } from 'react'
import { Plus, SlidersHorizontal, X } from 'lucide-react'
import { modern, tryParse } from '../../domain/query/parse.js'
import { tokenize } from '../../domain/query/tokenize.js'
import { applyCompletion, completions, fieldCaption, fieldOf } from '../../domain/query/complete.js'
import { emptyRow, opLabel, opsFor, toModel, toText } from '../../domain/query/builder.js'
import { useQuerySchema } from '../../services/querySchema.js'

/*
 * ============================================================================
 * QUERY INPUT — a query as text, and as rows of a builder
 * ============================================================================
 *
 * The value is always the text of the query (app/query on the server decides
 * what it means). On top of a plain input this gives:
 *
 *  - colours: fields, operators, values and connectives are told apart, and
 *    what cannot be read is underlined where it goes wrong;
 *  - autocomplete: the fields of the entity at the start of a condition, the
 *    values of a field after its colon (arrows, Enter or Tab; Ctrl+Space asks);
 *  - a builder: the same query as rows of field / operator / value, for a
 *    query it can represent; for any other it says "edit as text".
 */

const TOKEN_CLASS = {
  field: 'text-accent',
  op: 'text-fg-muted',
  value: 'text-fg',
  range: 'text-fg',
  quote: 'text-fg',
  text: 'text-fg',
  keyword: 'font-semibold text-fg-muted',
  not: 'font-semibold text-fg-muted',
  paren: 'text-fg-muted',
  space: '',
}

const CONTROL =
  'h-7 min-w-0 border border-line bg-canvas px-1.5 font-mono text-xs text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/** The query in colours, under the transparent text of the input. */
function Highlight({ text, errorAt, schema }) {
  const tokens = useMemo(() => tokenize(text), [text])
  return tokens.map((token) => {
    const wrong = errorAt !== null && token.start <= errorAt && errorAt < Math.max(token.end, token.start + 1)
    // A field the entity does not have is not coloured as one.
    const unknown = token.type === 'field' && schema && !fieldOf(schema, token.text)
    return (
      <span
        key={token.start}
        className={[
          unknown ? 'text-fg' : TOKEN_CLASS[token.type],
          wrong ? 'underline decoration-high decoration-wavy underline-offset-4' : '',
        ].join(' ')}
      >
        {token.text}
      </span>
    )
  })
}

/** One condition of the builder. */
function Row({ row, schema, onChange, onRemove, label }) {
  const spec = row.field ? fieldOf(schema, row.field) : null
  const kind = row.field ? (spec?.kind ?? 'text') : ''
  const ops = opsFor(kind)
  const choices = spec?.kind === 'bool' ? ['true', 'false'] : (spec?.values ?? [])
  const noValue = row.op === 'empty' || row.op === 'filled'
  const set = (changes) => onChange({ ...row, ...changes })

  const valueControl = (key, placeholder) =>
    choices.length > 0 && row.op !== 'between' ? (
      <select
        aria-label={`${label}: value`}
        value={row[key]}
        onChange={(event) => set({ [key]: event.target.value })}
        className={`${CONTROL} flex-1`}
      >
        <option value="">choose…</option>
        {/* A value typed in the text that is not one of the choices stays selectable. */}
        {row[key] && !choices.includes(row[key]) && <option value={row[key]}>{row[key]}</option>}
        {choices.map((choice) => (
          <option key={choice} value={choice}>
            {choice}
          </option>
        ))}
      </select>
    ) : (
      <input
        type="text"
        aria-label={`${label}: ${placeholder}`}
        value={row[key]}
        onChange={(event) => set({ [key]: event.target.value })}
        placeholder={kind === 'date' ? 'today, now-7d, 2026-11-10' : placeholder}
        autoComplete="off"
        spellCheck={false}
        className={`${CONTROL} flex-1 basis-24 placeholder:text-fg-subtle`}
      />
    )

  return (
    <li className="flex flex-wrap items-center gap-1">
      <select
        aria-label={`${label}: field`}
        value={spec ? spec.name : row.field}
        onChange={(event) => {
          const next = event.target.value ? fieldOf(schema, event.target.value) : null
          const allowed = opsFor(event.target.value ? (next?.kind ?? 'text') : '')
          set({
            field: event.target.value,
            op: allowed.some((op) => op.id === row.op) ? row.op : '=',
            value: '',
            value2: '',
          })
        }}
        className={`${CONTROL} max-w-[9rem]`}
      >
        <option value="">any text</option>
        {row.field && !spec && <option value={row.field}>{row.field}</option>}
        {(schema?.fields ?? []).map((field) => (
          <option key={field.name} value={field.name} title={field.description}>
            {fieldCaption(field)}
          </option>
        ))}
      </select>
      <select
        aria-label={`${label}: operator`}
        value={row.op}
        onChange={(event) => set({ op: event.target.value })}
        className={`${CONTROL} max-w-[9rem]`}
      >
        {ops.map((op) => (
          <option key={op.id} value={op.id}>
            {opLabel(op, kind)}
          </option>
        ))}
      </select>
      {!noValue && valueControl('value', row.op === 'between' ? 'from' : 'value')}
      {row.op === 'between' && valueControl('value2', 'to')}
      <button
        type="button"
        onClick={onRemove}
        aria-label={`Remove ${label}`}
        title="Remove this condition"
        className="flex h-7 w-7 shrink-0 items-center justify-center text-fg-muted hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        <X className="h-3.5 w-3.5" aria-hidden="true" />
      </button>
    </li>
  )
}

function JoinSelect({ value, onChange, label }) {
  return (
    <select aria-label={label} value={value} onChange={(event) => onChange(event.target.value)} className={CONTROL}>
      <option value="and">all of these</option>
      <option value="or">any of these</option>
    </select>
  )
}

/** The query as rows: a text the builder can represent, or the note that says to edit it as text. */
function Builder({ value, schema, onChange }) {
  // The rows being edited: an unfinished one has no place in the text, so it lives here.
  const [model, setModel] = useState(() => toModel(value))
  useEffect(() => {
    // The text changed from outside (typed, or a filter wrote into it): show that.
    setModel((current) => (current && toText(current) === value.trim() ? current : toModel(value)))
  }, [value])

  if (model === null) {
    return (
      <p className="border border-dashed border-line px-2 py-1.5 text-xs text-fg-muted">
        {tryParse(value).error
          ? 'The builder shows the query once it can be read: correct it in the text.'
          : 'This query nests or negates conditions in a way the builder does not show. Edit it as text.'}
      </p>
    )
  }

  const apply = (next) => {
    setModel(next)
    onChange(toText(next))
  }
  const setItem = (index, item) => apply({ ...model, rows: model.rows.map((old, i) => (i === index ? item : old)) })
  const removeItem = (index) => apply({ ...model, rows: model.rows.filter((_, i) => i !== index) })

  return (
    <div className="space-y-1.5 border border-line bg-panel p-2">
      {model.rows.length > 1 && (
        <div className="flex items-center gap-1.5 text-xs text-fg-muted">
          Match
          <JoinSelect
            value={model.join}
            onChange={(join) => apply({ ...model, join })}
            label="How the conditions combine"
          />
        </div>
      )}
      {model.rows.length === 0 && <p className="text-xs text-fg-muted">No condition yet: everything is listed.</p>}
      <ul className="space-y-1">
        {model.rows.map((item, index) =>
          item.rows ? (
            <li key={index} className="space-y-1 border-l-2 border-line-soft pl-2">
              <div className="flex items-center gap-1.5 text-xs text-fg-muted">
                Group:
                <JoinSelect
                  value={item.join}
                  onChange={(join) => setItem(index, { ...item, join })}
                  label={`How the conditions of group ${index + 1} combine`}
                />
                <button
                  type="button"
                  onClick={() => setItem(index, { ...item, rows: [...item.rows, emptyRow()] })}
                  className="ml-auto text-xs text-accent hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  add to the group
                </button>
              </div>
              <ul className="space-y-1">
                {item.rows.map((row, inner) => (
                  <Row
                    key={inner}
                    row={row}
                    schema={schema}
                    label={`Group ${index + 1}, condition ${inner + 1}`}
                    onChange={(next) =>
                      setItem(index, { ...item, rows: item.rows.map((old, i) => (i === inner ? next : old)) })
                    }
                    onRemove={() => {
                      const rows = item.rows.filter((_, i) => i !== inner)
                      if (rows.length === 0) removeItem(index)
                      else setItem(index, { ...item, rows })
                    }}
                  />
                ))}
              </ul>
            </li>
          ) : (
            <Row
              key={index}
              row={item}
              schema={schema}
              label={`Condition ${index + 1}`}
              onChange={(next) => setItem(index, next)}
              onRemove={() => removeItem(index)}
            />
          ),
        )}
      </ul>
      <div className="flex flex-wrap gap-3 text-xs">
        <button
          type="button"
          onClick={() => apply({ ...model, rows: [...model.rows, emptyRow()] })}
          className="inline-flex items-center gap-1 text-accent hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <Plus className="h-3 w-3" aria-hidden="true" />
          Add a condition
        </button>
        <button
          type="button"
          onClick={() =>
            apply({
              ...model,
              rows: [...model.rows, { join: model.join === 'and' ? 'or' : 'and', rows: [emptyRow(), emptyRow()] }],
            })
          }
          className="text-fg-muted hover:text-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          Add a group
        </button>
      </div>
    </div>
  )
}

/**
 * @param {{
 *   entity: 'incidents' | 'artifacts' | 'indicators' | 'audit',
 *   value: string,
 *   onChange: (text: string) => void,
 *   label: string,                 // the accessible name of the input
 *   placeholder?: string,
 *   error?: { message: string, position?: number } | string | null,   // what the server said of the query
 *   className?: string,
 * }} props
 */
export default function QueryInput({ entity, value, onChange, label, placeholder = '', error = null, className = '' }) {
  const schema = useQuerySchema(entity)
  const id = useId()
  const inputRef = useRef(null)
  const layerRef = useRef(null)
  const [builder, setBuilder] = useState(false)
  const [offer, setOffer] = useState(null) // { from, to, items }
  const [active, setActive] = useState(0)
  // Where the caret must go after an item is taken (set once the new text is rendered).
  const caretRef = useRef(null)

  // What is wrong: the text cannot be read (said at once), or the server refused it.
  const local = useMemo(() => tryParse(value).error, [value])
  const problem = local ?? (error ? (typeof error === 'string' ? { message: error } : error) : null)
  const errorAt =
    problem && Number.isInteger(problem.position) ? Math.min(problem.position, Math.max(value.length - 1, 0)) : null

  useEffect(() => {
    if (caretRef.current === null || !inputRef.current) return
    inputRef.current.setSelectionRange(caretRef.current, caretRef.current)
    caretRef.current = null
  })

  // The colours follow the text when it scrolls sideways.
  const syncScroll = () => {
    if (layerRef.current && inputRef.current) {
      layerRef.current.style.transform = `translateX(${-inputRef.current.scrollLeft}px)`
    }
  }
  useEffect(syncScroll)

  const suggest = (text, caret, force = false) => {
    const found = completions(text, caret, schema, { force })
    setOffer(found)
    setActive(0)
  }

  const take = (item) => {
    const next = applyCompletion(value, offer, item)
    caretRef.current = next.caret
    onChange(next.text)
    // A field was written: its values come next.
    suggest(next.text, next.caret, false)
  }

  const onKeyDown = (event) => {
    if ((event.ctrlKey || event.metaKey) && event.key === ' ') {
      event.preventDefault()
      suggest(value, event.currentTarget.selectionStart ?? value.length, true)
      return
    }
    if (!offer) {
      if (event.key === 'ArrowDown') {
        event.preventDefault()
        suggest(value, event.currentTarget.selectionStart ?? value.length, true)
      }
      return
    }
    if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
      event.preventDefault()
      const step = event.key === 'ArrowDown' ? 1 : -1
      setActive((index) => (index + step + offer.items.length) % offer.items.length)
    } else if (event.key === 'Enter' || event.key === 'Tab') {
      event.preventDefault()
      take(offer.items[active])
    } else if (event.key === 'Escape') {
      // Only the list closes: a dialog or a page this input is in stays.
      event.preventDefault()
      event.stopPropagation()
      setOffer(null)
    }
  }

  const listId = `${id}-list`
  return (
    <div className={`space-y-1 ${className}`}>
      <div className="flex gap-1">
        <div className="relative min-w-0 flex-1">
          <div
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 overflow-hidden border border-transparent px-2.5"
          >
            <div ref={layerRef} className="whitespace-pre font-mono text-xs leading-8">
              <Highlight text={value} errorAt={errorAt} schema={schema} />
            </div>
          </div>
          <input
            ref={inputRef}
            type="text"
            role="combobox"
            aria-label={label}
            aria-expanded={Boolean(offer)}
            aria-controls={listId}
            aria-autocomplete="list"
            aria-activedescendant={offer ? `${id}-item-${active}` : undefined}
            aria-invalid={problem ? 'true' : undefined}
            aria-describedby={problem ? `${id}-problem` : undefined}
            value={value}
            placeholder={placeholder}
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            onChange={(event) => {
              onChange(event.target.value)
              suggest(event.target.value, event.target.selectionStart ?? event.target.value.length)
            }}
            onKeyDown={onKeyDown}
            onScroll={syncScroll}
            onBlur={() => {
              setOffer(null)
              // "Is not" as it was written before 5.0 (status:!closed) is shown as it is written now.
              const now = modern(value)
              if (now !== value) onChange(now)
            }}
            // Transparent text over the coloured copy: the caret and the selection are the input's own.
            className="h-8 w-full border border-line bg-transparent px-2.5 font-mono text-xs leading-8 text-transparent caret-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <ul
            id={listId}
            role="listbox"
            aria-label="Suggestions"
            hidden={!offer}
            className="absolute left-0 top-full z-30 mt-1 max-h-64 w-full min-w-[14rem] overflow-y-auto border border-line bg-panel py-1 shadow-xl"
          >
            {offer?.items.map((item, index) => (
              <li
                key={item.label}
                id={`${id}-item-${index}`}
                role="option"
                aria-selected={index === active}
                // Before the input loses the focus, which would close the list.
                onMouseDown={(event) => {
                  event.preventDefault()
                  take(item)
                }}
                onMouseEnter={() => setActive(index)}
                className={[
                  'flex cursor-pointer items-baseline gap-2 px-2.5 py-1 font-mono text-xs',
                  index === active ? 'bg-accent-soft text-accent' : 'text-fg',
                ].join(' ')}
              >
                <span className="shrink-0">{item.label}</span>
                {item.detail && (
                  <span className="min-w-0 truncate font-sans text-[11px] text-fg-muted">{item.detail}</span>
                )}
              </li>
            ))}
          </ul>
        </div>
        <button
          type="button"
          aria-pressed={builder}
          onClick={() => setBuilder((open) => !open)}
          title={builder ? 'Hide the builder' : 'Build the query from rows of field, operator and value'}
          aria-label="Query builder"
          className={[
            'flex h-8 w-8 shrink-0 items-center justify-center border transition-colors',
            'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
            builder ? 'border-accent text-accent' : 'border-line text-fg-muted hover:bg-raised hover:text-fg',
          ].join(' ')}
        >
          <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>
      {problem && (
        <p id={`${id}-problem`} role="status" className="font-mono text-[11px] text-high">
          {problem.message}
        </p>
      )}
      {builder && <Builder value={value} schema={schema} onChange={onChange} />}
    </div>
  )
}
