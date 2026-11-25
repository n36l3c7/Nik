import { RefreshCw } from 'lucide-react'
import { CHOICES, refreshNote } from '../../domain/autoRefresh.js'
import Button from './Button.jsx'
import Select from './Select.jsx'

/**
 * The refresh of a screen as the incident list and the dashboards draw it: a button that refreshes now
 * (the icon turns while it runs), the choice of the automatic refresh, and when the screen was last
 * brought up to date. The state comes from useAutoRefresh (lib/useAutoRefresh.js).
 *
 * @param {{
 *   what: string,                       // what is refreshed: "the list", "the dashboard"
 *   refreshing: boolean,
 *   lastAt: number | null,
 *   error: string | null,
 *   onRefresh: () => void,
 *   choice: string,                     // an id of CHOICES
 *   onChoice: (id: string) => void,
 *   options?: { id: string, label: string }[],   // what the chooser offers (default: CHOICES)
 *   className?: string,
 * }} props
 */
export default function RefreshControl({
  what,
  refreshing,
  lastAt,
  error,
  onRefresh,
  choice,
  onChoice,
  options = CHOICES,
  className = '',
}) {
  const note = refreshNote({ lastAt, error })
  const label = `Refresh ${what}`
  // Below `lg` the note is not drawn: the button says it. A failure also turns the button to the warning colour.
  const title = error ? `${note}: ${error}` : note ? `${label} · ${note}` : label
  return (
    <div className={`flex items-center gap-2 ${className}`}>
      {note && (
        <span
          className={`hidden whitespace-nowrap font-mono text-xs lg:inline ${error ? 'text-med-fg' : 'text-fg-muted'}`}
          title={error ?? undefined}
        >
          {note}
        </span>
      )}
      <Button
        variant="secondary"
        size="sm"
        title={title}
        className={error ? 'border-med-line! text-med-fg!' : ''}
        aria-label={label}
        aria-busy={refreshing || undefined}
        onClick={onRefresh}
      >
        <RefreshCw className={`h-4 w-4 shrink-0 ${refreshing ? 'animate-spin' : ''}`} aria-hidden="true" />
      </Button>
      <Select
        label="Auto-refresh:"
        // The select takes the width of its longest choice: squeezed by the toolbar it showed no value.
        className="shrink-0 [&_select]:w-auto"
        value={choice}
        onChange={onChoice}
        options={options.map((item) => ({ value: item.id, label: item.label }))}
      />
    </div>
  )
}
