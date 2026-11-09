import { useEffect, useMemo, useRef } from 'react'
import { X } from 'lucide-react'
import { useSocEngine } from '../../context/SettingsContext.jsx'
import { buildTimelineEvents, tailLines } from '../../utils/timeline.js'

/*
 * ============================================================================
 * TAIL PANEL — `tail -f` of the incident's super-timeline
 * ============================================================================
 * A collapsible side panel, available on every tab, listing the latest
 * timestamped events of the incident (browser, commands, endpoint) the way
 * `tail -f` would: oldest first, newest at the bottom, scrolled to the end.
 * Severity and flags use the same colours as the tables. It recomputes only
 * while open (closing it unmounts it).
 *
 * @param {{ incident: object, onClose: () => void, className?: string }} props
 */

const LIMIT = 60

const SOURCE_TONES = {
  browser: 'text-info',
  command: 'text-violet',
  endpoint: 'text-med',
  sample: 'text-high',
}

const SEVERITY = {
  high: { mark: '!!', tone: 'text-high' },
  medium: { mark: '! ', tone: 'text-med' },
}

// Events span days, so each line carries its date: "04/11 02:14".
const stamp = (ms) =>
  new Date(ms)
    .toLocaleString('en-GB', { day: '2-digit', month: '2-digit', hour: '2-digit', minute: '2-digit' })
    .replace(',', '')

export default function TailPanel({ incident, onClose, className = '' }) {
  const engine = useSocEngine()
  const data = incident.data
  const events = useMemo(() => buildTimelineEvents(data, engine), [data, engine])
  const lines = useMemo(() => tailLines(events, incident.flags, LIMIT), [events, incident.flags])
  const scrollRef = useRef(null)

  // Like `tail -f`: keep the newest line in view.
  useEffect(() => {
    const el = scrollRef.current
    if (el) el.scrollTop = el.scrollHeight
  }, [lines])

  return (
    <aside
      aria-label="Latest incident events"
      className={`flex-col border-l border-line bg-sunken font-mono text-xs ${className}`}
    >
      <div className="flex items-center justify-between gap-2 border-b border-line px-4 py-2.5">
        <span className="text-fg-muted">
          $ tail -f timeline <span className="text-fg-subtle">· {events.length.toLocaleString('en-US')}</span>
        </span>
        <button
          type="button"
          onClick={onClose}
          aria-label="Close the tail panel"
          className="p-1 text-fg-muted transition-colors hover:bg-raised hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        >
          <X className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      </div>

      <ol ref={scrollRef} className="flex-1 space-y-2 overflow-y-auto px-4 py-3">
        {lines.length === 0 ? (
          <li className="text-fg-muted">no timestamped events yet</li>
        ) : (
          lines.map((line) => {
            const severity = SEVERITY[line.severity]
            return (
              <li key={line.id} className="leading-snug">
                <div className="flex items-baseline gap-1.5 whitespace-nowrap">
                  <span className="text-fg-muted">{stamp(line.time)}</span>
                  <span className={SOURCE_TONES[line.source] ?? 'text-fg-muted'}>[{line.sourceLabel}]</span>
                  {severity && (
                    <span className={severity.tone} title={`${line.severity} severity`}>
                      {severity.mark}
                    </span>
                  )}
                  {line.flagged && (
                    <span className="text-accent" title="Flagged">
                      ⚑
                    </span>
                  )}
                </div>
                <div className="truncate text-fg" title={line.label}>
                  {line.label || '(no label)'}
                </div>
              </li>
            )
          })
        )}
        <li aria-hidden="true" className="text-accent motion-safe:animate-pulse">
          ▍
        </li>
      </ol>
    </aside>
  )
}
