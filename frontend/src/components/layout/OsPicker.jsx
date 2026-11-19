import { OS_LIST } from '../../config/os.js'

/*
 * Segmented control to pick the incident's host OS (Windows / macOS / Linux).
 * Used in the "New incident" dialog and in "Edit the incident". The choice is
 * optional: the one that is chosen is let go by choosing it again.
 */

/**
 * @param {{ value: string, onChange: (osId: string) => void, idPrefix?: string }} props   // '' for none
 */
export default function OsPicker({ value, onChange, idPrefix = 'os' }) {
  return (
    <div role="group" aria-label="Host operating system (optional)" className="flex flex-wrap gap-2">
      {OS_LIST.map((os) => {
        const isActive = os.id === value
        const OsIcon = os.icon
        return (
          <button
            key={os.id}
            id={`${idPrefix}-${os.id}`}
            type="button"
            aria-pressed={isActive}
            title={isActive ? `${os.label}: choose it again to leave the system out` : os.label}
            onClick={() => onChange(isActive ? '' : os.id)}
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
