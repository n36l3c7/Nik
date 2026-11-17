import { useMemo, useRef, useState } from 'react'
import { Braces } from 'lucide-react'
import { problemOf } from '../../domain/automation/expressions.js'
import { useLayer } from '../../lib/layers.js'
import { INPUT } from './fields.jsx'

/*
 * A text that may hold {{ expressions }}.
 *
 * The button beside it opens "Pick a value": everything this node can read
 * (what started the run, the nodes certain to have run before it, the item of
 * a "for each"), as a list to choose from; the choice is written at the
 * caret. What is typed is checked as it is typed: an expression that cannot
 * be read says why under the field. The server checks again, and decides.
 */

function ValuePicker({ tree, onPick, onClose }) {
  const ref = useRef(null)
  const [query, setQuery] = useState('')
  useLayer(ref, { open: true, onClose, trap: false })
  const shown = useMemo(() => {
    const words = query.toLowerCase().split(/\s+/).filter(Boolean)
    return tree
      .map((root) => ({
        ...root,
        fields: root.fields.filter((field) => {
          const text = `${field.path} ${root.label} ${field.description ?? ''}`.toLowerCase()
          return words.every((word) => text.includes(word))
        }),
      }))
      .filter((root) => root.fields.length > 0)
  }, [tree, query])

  return (
    <div
      ref={ref}
      role="dialog"
      aria-label="Pick a value"
      tabIndex={-1}
      className="absolute right-0 top-full z-30 mt-1 flex max-h-80 w-72 flex-col border border-line bg-raised shadow-lg shadow-sunken/60 focus:outline-none"
    >
      <input
        type="search"
        value={query}
        onChange={(event) => setQuery(event.target.value)}
        placeholder="Find a value"
        aria-label="Find a value"
        autoComplete="off"
        className={`${INPUT} border-0 border-b`}
      />
      <div className="min-h-0 flex-1 overflow-y-auto py-1">
        {shown.length === 0 && <p className="px-3 py-2 text-xs text-fg-muted">Nothing to pick matches.</p>}
        {shown.map((root) => (
          <div key={root.name} role="group" aria-label={root.label}>
            <p className="px-3 pb-0.5 pt-2 text-[11px] text-fg-muted">
              <span className="font-mono text-fg">{root.name}</span> · {root.label}
            </p>
            {root.fields.map((field) => (
              <button
                key={field.path}
                type="button"
                title={field.description || undefined}
                onClick={() => onPick(field.path)}
                className="flex w-full items-baseline justify-between gap-2 px-3 py-1 text-left hover:bg-panel focus-visible:bg-panel focus-visible:outline-none"
              >
                <span className="min-w-0 break-all font-mono text-xs text-info">{field.path}</span>
                <span className="shrink-0 font-mono text-[10px] text-fg-subtle">{field.type}</span>
              </button>
            ))}
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * @param {{
 *   id?: string,
 *   value: string,
 *   onChange: (value: string) => void,
 *   tree?: Array<{ name: string, label: string, fields: object[] }>,  // what can be picked
 *   multiline?: boolean,
 *   placeholder?: string,
 *   disabled?: boolean,
 *   label?: string,        // the accessible name, when no <label> points at `id`
 * }} props
 */
export default function ExpressionInput({
  id,
  value,
  onChange,
  tree = [],
  multiline = false,
  placeholder = '',
  disabled = false,
  label,
}) {
  const inputRef = useRef(null)
  const [open, setOpen] = useState(false)
  const text = typeof value === 'string' ? value : value === null || value === undefined ? '' : String(value)
  const problem = problemOf(text)

  const pick = (path) => {
    const input = inputRef.current
    const start = input?.selectionStart ?? text.length
    const end = input?.selectionEnd ?? text.length
    const inserted = `{{ ${path} }}`
    onChange(text.slice(0, start) + inserted + text.slice(end))
    setOpen(false)
    // After React has written the new value: the caret goes after what was inserted.
    requestAnimationFrame(() => {
      input?.focus()
      input?.setSelectionRange(start + inserted.length, start + inserted.length)
    })
  }

  const shared = {
    id,
    ref: inputRef,
    value: text,
    disabled,
    placeholder,
    'aria-label': label,
    'aria-invalid': problem ? true : undefined,
    autoComplete: 'off',
    spellCheck: false,
    onChange: (event) => onChange(event.target.value),
    className: `${INPUT} ${problem ? 'border-high-line' : ''}`,
  }

  return (
    <div className="flex min-w-0 flex-col gap-1">
      <div className="relative flex min-w-0 items-start gap-1">
        {multiline ? <textarea rows={3} {...shared} /> : <input type="text" {...shared} />}
        {!disabled && tree.length > 0 && (
          <button
            type="button"
            title="Pick a value"
            aria-label={label ? `Pick a value for ${label}` : 'Pick a value'}
            aria-haspopup="dialog"
            aria-expanded={open}
            onClick={() => setOpen((shown) => !shown)}
            className="flex h-[30px] w-7 shrink-0 items-center justify-center border border-line text-fg-muted hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <Braces className="h-3.5 w-3.5" aria-hidden="true" />
          </button>
        )}
        {open && <ValuePicker tree={tree} onPick={pick} onClose={() => setOpen(false)} />}
      </div>
      {problem && (
        <p role="alert" className="text-xs text-high-fg">
          {problem.message} (character {problem.position + 1})
        </p>
      )}
    </div>
  )
}
