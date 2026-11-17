import { useId, useState } from 'react'

/*
 * The small controls the Automations area is made of: a labelled field, a
 * text box, a number, a segmented choice, a switch and a duration. They look
 * like the rest of Nik (square, mono for values) and are sized for the
 * narrow inspector.
 */

export const INPUT =
  'w-full min-w-0 border border-line bg-sunken px-2 py-1.5 font-mono text-[13px] text-fg placeholder:text-fg-subtle ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:cursor-not-allowed disabled:opacity-60'

/** A label over a control, with a hint under it and a problem in red. `children` gets the id as a function. */
export function Field({ label, hint = null, problem = null, required = false, children }) {
  const id = useId()
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <label htmlFor={id} className="text-xs text-fg-muted">
        {label}
        {required && (
          <span className="text-med" title="Required">
            {' '}
            *
          </span>
        )}
      </label>
      {children(id)}
      {hint && <p className="text-xs text-fg-muted">{hint}</p>}
      {problem && (
        <p role="alert" className="text-xs text-high-fg">
          {problem}
        </p>
      )}
    </div>
  )
}

export function SectionTitle({ children, action = null }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">{children}</h3>
      {action}
    </div>
  )
}

export function TextInput({ id, value, onChange, disabled = false, placeholder = '', ...rest }) {
  return (
    <input
      id={id}
      type="text"
      value={value ?? ''}
      disabled={disabled}
      placeholder={placeholder}
      autoComplete="off"
      spellCheck={false}
      onChange={(event) => onChange(event.target.value)}
      className={INPUT}
      {...rest}
    />
  )
}

/** A whole number. What is typed is kept while it is being typed; `onChange` gets a number or null. */
export function NumberInput({ id, value, onChange, min, max, disabled = false, className = '', ...rest }) {
  const [draft, setDraft] = useState(null)
  const shown = draft ?? (value === null || value === undefined ? '' : String(value))
  return (
    <input
      id={id}
      type="number"
      inputMode="numeric"
      value={shown}
      min={min}
      max={max}
      disabled={disabled}
      onChange={(event) => {
        setDraft(event.target.value)
        const number = Number(event.target.value)
        onChange(event.target.value.trim() === '' || !Number.isFinite(number) ? null : Math.trunc(number))
      }}
      onBlur={() => setDraft(null)}
      className={`${INPUT} ${className}`}
      {...rest}
    />
  )
}

/** One choice of a few, side by side. `options`: [{ value, label }]. */
export function Seg({ value, onChange, options, label, disabled = false }) {
  return (
    <div role="radiogroup" aria-label={label} className="inline-flex w-fit flex-wrap border border-line">
      {options.map((option) => {
        const on = option.value === value
        return (
          <button
            key={String(option.value)}
            type="button"
            role="radio"
            aria-checked={on}
            disabled={disabled}
            onClick={() => onChange(option.value)}
            className={[
              'border-r border-line px-2.5 py-1 font-mono text-[11px] font-semibold last:border-r-0',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent',
              'disabled:cursor-not-allowed disabled:opacity-60',
              on ? 'bg-accent-soft text-accent-fg' : 'text-fg-muted hover:bg-raised hover:text-fg',
            ].join(' ')}
          >
            {option.label}
          </button>
        )
      })}
    </div>
  )
}

export function Switch({ checked, onChange, label, disabled = false }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      aria-label={label}
      disabled={disabled}
      onClick={() => onChange(!checked)}
      className={[
        'relative h-4 w-8 shrink-0 border transition-colors',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent focus-visible:ring-offset-2 focus-visible:ring-offset-panel',
        'disabled:cursor-not-allowed disabled:opacity-60',
        checked ? 'border-accent bg-accent-soft' : 'border-line bg-sunken',
      ].join(' ')}
    >
      <span
        aria-hidden="true"
        className={[
          'absolute top-px h-3 w-3 transition-all',
          checked ? 'left-[17px] bg-accent' : 'left-px bg-fg-subtle',
        ].join(' ')}
      />
    </button>
  )
}

const UNITS = [
  { value: 60, label: 'minutes' },
  { value: 3600, label: 'hours' },
  { value: 86400, label: 'days' },
]

/** The unit a number of seconds reads best in. */
export function unitOf(seconds) {
  if (Number.isFinite(seconds) && seconds > 0) {
    if (seconds % 86400 === 0) return 86400
    if (seconds % 3600 === 0) return 3600
  }
  return 60
}

/** A time span, stored in seconds and typed as minutes, hours or days. */
export function DurationInput({ id, value, onChange, disabled = false }) {
  const [unit, setUnit] = useState(() => unitOf(value))
  const amount = Number.isFinite(value) ? Math.round((value / unit) * 100) / 100 : null
  return (
    <div className="flex gap-1">
      <NumberInput
        id={id}
        value={amount}
        min={1}
        disabled={disabled}
        className="w-20!"
        onChange={(next) => onChange(next === null ? null : next * unit)}
      />
      <select
        aria-label="Unit"
        value={unit}
        disabled={disabled}
        onChange={(event) => {
          const next = Number(event.target.value)
          setUnit(next)
          if (amount !== null) onChange(Math.round(amount) * next)
        }}
        className={`${INPUT} w-auto! cursor-pointer`}
      >
        {UNITS.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  )
}

export function SelectInput({ id, value, onChange, options, disabled = false, ...rest }) {
  return (
    <select
      id={id}
      value={value ?? ''}
      disabled={disabled}
      onChange={(event) => onChange(event.target.value)}
      className={`${INPUT} cursor-pointer`}
      {...rest}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  )
}
