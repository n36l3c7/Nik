import { Select } from '../../ui/index.js'
import { BURST_OPTIONS, GAP_OPTIONS, markerItems, summaryText } from '../../../domain/gapsBursts.js'
import { formatDateTime } from '../../../lib/time.js'

/*
 * The control of the gaps and bursts of the Timeline, and the line that lists them. A gap is a stretch with no
 * record for at least the first threshold; a burst is a slice with at least that many times the usual. Each item
 * of the line sets the time range of the page to itself. What is drawn on the bars is in TimelineTab.jsx.
 */

const KIND = {
  gap: 'border-line text-fg-muted hover:text-fg',
  burst: 'border-high-line bg-high-soft/40 text-high-fg hover:text-fg',
}

/** The switch and the two thresholds. */
export function GapControls({ thresholds, onChange }) {
  return (
    <div className="flex flex-wrap items-center gap-3">
      <label className="inline-flex items-center gap-2 font-mono text-xs text-fg-muted">
        <input
          type="checkbox"
          checked={thresholds.show}
          onChange={(event) => onChange({ show: event.target.checked })}
          className="accent-[var(--color-accent)]"
        />
        Show gaps and bursts
      </label>
      <Select
        label="Gap ≥"
        value={String(thresholds.gap)}
        disabled={!thresholds.show}
        onChange={(value) => onChange({ gap: Number(value) })}
        options={GAP_OPTIONS.map((item) => ({ value: String(item.value), label: item.label }))}
      />
      <Select
        label="Burst ≥"
        value={String(thresholds.burst)}
        disabled={!thresholds.show}
        onChange={(value) => onChange({ burst: Number(value) })}
        options={BURST_OPTIONS.map((item) => ({ value: String(item.value), label: `${item.label} usual` }))}
      />
    </div>
  )
}

/**
 * "3 gaps, the longest 6 h 12 min · 2 bursts", and the items under it (each sets the range).
 * @param {{ gaps: object[], bursts: object[], width: number, onPick: (range: { start: number, end: number }) => void }} props
 */
export function GapList({ gaps, bursts, width, onPick }) {
  const { items, more } = markerItems(gaps, bursts, width)
  return (
    <div className="space-y-1.5">
      <p className="m-0 font-mono text-xs text-fg" aria-live="polite">
        {summaryText(gaps, bursts)}
      </p>
      {items.length > 0 && (
        <ul className="m-0 flex list-none flex-wrap gap-1.5 p-0">
          {items.map((item) => (
            <li key={item.key}>
              <button
                type="button"
                title={`Set the range to ${formatDateTime(item.start)} – ${formatDateTime(item.end)}`}
                onClick={() => onPick({ start: item.start, end: item.end })}
                className={`border px-2 py-0.5 font-mono text-[11px] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${KIND[item.kind]}`}
              >
                {item.label} · {formatDateTime(item.start)}
              </button>
            </li>
          ))}
          {more > 0 && <li className="self-center text-xs text-fg-muted">and {more.toLocaleString('en-US')} more</li>}
        </ul>
      )}
    </div>
  )
}
