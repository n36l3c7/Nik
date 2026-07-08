/**
 * Select — controlled dropdown with an optional label.
 *
 * `onChange` receives the selected string directly (not the event).
 * `options` is an array of `{ value, label }`.
 */
export default function Select({
  value,
  onChange,
  options = [],
  label = null,
  className = '',
}) {
  return (
    <label className={`inline-flex items-center gap-2 ${className}`}>
      {label && (
        <span className="whitespace-nowrap text-xs font-medium text-slate-500 dark:text-slate-400">
          {label}
        </span>
      )}
      <select
        value={value}
        onChange={(event) => onChange?.(event.target.value)}
        className={[
          'w-full cursor-pointer rounded-lg border py-1.5 pl-3 pr-8 text-sm',
          'border-slate-200 bg-white text-slate-700',
          'dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
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
