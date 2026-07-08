import { OS_LIST } from '../../config/os.js'

/*
 * Segmented control to pick the incident's host OS (Windows / macOS / Linux).
 * Used in the "New incident" modal and the Summary details form.
 */

/**
 * @param {{ value: string, onChange: (osId: string) => void, idPrefix?: string }} props
 */
export default function OsPicker({ value, onChange, idPrefix = 'os' }) {
  return (
    <div role="radiogroup" aria-label="Host operating system" className="flex flex-wrap gap-2">
      {OS_LIST.map((os) => {
        const isActive = os.id === value
        const OsIcon = os.icon
        return (
          <button
            key={os.id}
            id={`${idPrefix}-${os.id}`}
            type="button"
            role="radio"
            aria-checked={isActive}
            onClick={() => onChange(os.id)}
            className={[
              'inline-flex flex-1 items-center justify-center gap-2 rounded-lg border px-3 py-2 text-sm font-medium transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
              isActive
                ? 'border-cyan-500/60 bg-cyan-50 text-cyan-700 dark:border-cyan-500/50 dark:bg-cyan-500/10 dark:text-cyan-300'
                : 'border-slate-200 text-slate-600 hover:bg-slate-50 dark:border-slate-800 dark:text-slate-400 dark:hover:bg-slate-800/60',
            ].join(' ')}
          >
            <OsIcon className={`h-4 w-4 ${isActive ? '' : os.accent}`} />
            {os.label}
          </button>
        )
      })}
    </div>
  )
}
