import { Search, X } from 'lucide-react'

/**
 * SearchInput — controlled search field with a magnifier icon and a
 * quick clear button when there is text.
 *
 * `onChange` receives the string directly (not the event).
 */
export default function SearchInput({
  value,
  onChange,
  placeholder = 'Search…',
  className = '',
}) {
  return (
    <div className={`relative ${className}`}>
      <Search
        className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400 dark:text-slate-500"
        aria-hidden="true"
      />
      <input
        type="text"
        value={value}
        onChange={(event) => onChange?.(event.target.value)}
        placeholder={placeholder}
        aria-label={placeholder}
        className={[
          'w-full rounded-lg border py-2 pl-9 pr-8 text-sm',
          'border-slate-200 bg-white text-slate-800 placeholder:text-slate-400',
          'dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200 dark:placeholder:text-slate-500',
          'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
        ].join(' ')}
      />
      {/* Button to clear the search, visible only when there is text */}
      {value ? (
        <button
          type="button"
          onClick={() => onChange?.('')}
          aria-label="Clear search"
          className="absolute right-2 top-1/2 -translate-y-1/2 rounded p-0.5 text-slate-400 transition-colors hover:text-slate-600 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 dark:hover:text-slate-300"
        >
          <X className="h-4 w-4" aria-hidden="true" />
        </button>
      ) : null}
    </div>
  )
}
