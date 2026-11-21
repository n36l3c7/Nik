/*
 * DateTimeRangeFilter — a compact "From / To" range picker built on native
 * `<input type="datetime-local">` fields (which natively provide a calendar +
 * time selector). Values are exchanged as Unix ms | null with the parent.
 *
 * The fields show and read the viewer's local time (`lib/time.js`).
 */

import { localInputToMs, msToLocalInput } from '../../../lib/time.js'

// Shared field styling (kept in sync with the Select component look & feel).
const FIELD_CLASSES = [
  'border py-1.5 px-2 text-xs',
  'border-line bg-panel text-fg',
  '',
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
  '[color-scheme:light]',
].join(' ')

/**
 * @param {{ start: number|null, end: number|null,
 *           onChange: (range: {start: number|null, end: number|null}) => void }} props
 */
export default function DateTimeRangeFilter({ start, end, onChange }) {
  const handleFrom = (event) => onChange({ start: localInputToMs(event.target.value), end })

  const handleTo = (event) => onChange({ start, end: localInputToMs(event.target.value) })

  return (
    <div className="inline-flex flex-wrap items-center gap-2">
      <span className="whitespace-nowrap text-xs font-medium text-fg-muted">Time range</span>
      <label className="inline-flex items-center gap-1">
        <span className="text-xs text-fg-muted">From</span>
        <input
          type="datetime-local"
          value={msToLocalInput(start)}
          onChange={handleFrom}
          aria-label="Range start"
          className={FIELD_CLASSES}
        />
      </label>
      <label className="inline-flex items-center gap-1">
        <span className="text-xs text-fg-muted">To</span>
        <input
          type="datetime-local"
          value={msToLocalInput(end)}
          onChange={handleTo}
          aria-label="Range end"
          className={FIELD_CLASSES}
        />
      </label>
    </div>
  )
}
