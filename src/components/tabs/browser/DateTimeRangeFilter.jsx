/*
 * DateTimeRangeFilter — a compact "From / To" range picker built on native
 * `<input type="datetime-local">` fields (which natively provide a calendar +
 * time selector). Values are exchanged as Unix ms | null with the parent.
 *
 * The two exported helpers convert between Unix ms and the `datetime-local`
 * string representation (`YYYY-MM-DDTHH:mm`), always in the viewer's LOCAL time.
 */

/**
 * Convert a Unix-ms timestamp to a `datetime-local` input value (local time,
 * `YYYY-MM-DDTHH:mm`). Returns '' for null / non-finite values.
 */
export function msToLocalInput(ms) {
  if (ms == null || !Number.isFinite(ms)) return ''
  // Shift by the local timezone offset so the ISO string reflects local
  // wall-clock time, then keep only the `YYYY-MM-DDTHH:mm` part.
  const offsetMs = new Date(ms).getTimezoneOffset() * 60000
  return new Date(ms - offsetMs).toISOString().slice(0, 16)
}

/**
 * Convert a `datetime-local` input value (local wall-clock time) back to
 * Unix ms. Returns null for empty / unparseable input. A date-time string with
 * no timezone suffix is interpreted by the engine as local time — exactly what
 * the input produced.
 */
export function localInputToMs(str) {
  if (!str) return null
  const ms = new Date(str).getTime()
  return Number.isFinite(ms) ? ms : null
}

// Shared field styling (kept in sync with the Select component look & feel).
const FIELD_CLASSES = [
  'rounded-lg border py-1.5 px-2 text-xs',
  'border-slate-200 bg-white text-slate-700',
  'dark:border-slate-700 dark:bg-slate-900 dark:text-slate-200',
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500',
  '[color-scheme:light] dark:[color-scheme:dark]',
].join(' ')

/**
 * @param {{ start: number|null, end: number|null,
 *           onChange: (range: {start: number|null, end: number|null}) => void }} props
 */
export default function DateTimeRangeFilter({ start, end, onChange }) {
  const handleFrom = (event) =>
    onChange({ start: localInputToMs(event.target.value), end })

  const handleTo = (event) =>
    onChange({ start, end: localInputToMs(event.target.value) })

  return (
    <div className="inline-flex flex-wrap items-center gap-2">
      <span className="whitespace-nowrap text-xs font-medium text-slate-500 dark:text-slate-400">
        Time range
      </span>
      <label className="inline-flex items-center gap-1">
        <span className="text-xs text-slate-400 dark:text-slate-500">From</span>
        <input
          type="datetime-local"
          value={msToLocalInput(start)}
          onChange={handleFrom}
          aria-label="Range start"
          className={FIELD_CLASSES}
        />
      </label>
      <label className="inline-flex items-center gap-1">
        <span className="text-xs text-slate-400 dark:text-slate-500">To</span>
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
