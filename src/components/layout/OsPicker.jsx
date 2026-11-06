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
              'inline-flex flex-1 items-center justify-center gap-2 border px-3 py-2 font-mono text-[13px] transition-colors',
              'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
              isActive
                ? 'border-accent-strong bg-accent-soft text-accent-fg'
                : 'border-line text-fg-muted hover:bg-raised hover:text-fg',
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
