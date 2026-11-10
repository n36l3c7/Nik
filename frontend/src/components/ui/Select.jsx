/**
 * Select — controlled dropdown with an optional label.
 *
 * `onChange` receives the selected string directly (not the event).
 * `options` is an array of `{ value, label }`.
 */
export default function Select({ value, onChange, options = [], label = null, className = '' }) {
  return (
    <label className={`inline-flex items-center gap-2 ${className}`}>
      {label && <span className="whitespace-nowrap font-mono text-xs text-fg-muted">{label}</span>}
      <select
        value={value}
        onChange={(event) => onChange?.(event.target.value)}
        className={[
          'w-full cursor-pointer border border-line bg-canvas py-1.5 pl-3 pr-8 font-mono text-[13px] text-fg',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
        ].join(' ')}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </label>
  )
}
