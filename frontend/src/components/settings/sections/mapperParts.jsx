import { withField } from '../../../domain/mappers.js'

/*
 * What the tables of a classifier and of a mapper are made of: the classes of
 * their cells, and an expression with the fields of the product beside it.
 */

export const INPUT =
  'w-full border border-line bg-canvas px-2 py-1 text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
export const SELECT = `${INPUT} cursor-pointer`
export const LABEL = 'text-xs font-medium text-fg-muted'
export const TH = 'border-b border-line px-2 py-1.5 font-normal'
export const TD = 'border-b border-line-soft px-2 py-1 align-top'

/** An expression with, beside it, the fields of the product to put into it. */
export function Expression({ label, value, onChange, fields, root = 'item', placeholder = '' }) {
  return (
    <div className="flex gap-1">
      <input
        type="text"
        aria-label={label}
        value={value}
        spellCheck={false}
        autoComplete="off"
        placeholder={placeholder}
        onChange={(event) => onChange(event.target.value)}
        className={`${INPUT} font-mono text-xs`}
      />
      {fields.length > 0 && (
        <select
          aria-label={`${label}: put a field in`}
          value=""
          onChange={(event) => event.target.value && onChange(withField(value, event.target.value, root))}
          className="w-9 shrink-0 cursor-pointer border border-line bg-canvas px-1 text-sm text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <option value="">+</option>
          {fields.map((field) => (
            <option key={field.name} value={field.name}>
              {field.name}
            </option>
          ))}
        </select>
      )}
    </div>
  )
}
