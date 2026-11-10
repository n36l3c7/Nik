import { formatDateTime } from '../../../utils/time.js'

/*
 * Log coverage: one bar per channel on a shared time axis, from the first to
 * the last record of the log. Hatched spans are silences of 6 h or more (no
 * record of ANY id), red ticks the moments a log was cleared, and the green
 * band the incident's suspicious-activity window. A gap or a clear inside the
 * window is where evidence may be missing.
 */

const pct = (value, min, span) => `${(((value - min) / span) * 100).toFixed(3)}%`
const width = (from, to, span) => `${Math.max(((to - from) / span) * 100, 0.4).toFixed(3)}%`

/**
 * @param {{ data: { rows: Array, min: number|null, max: number|null },
 *           windowStart?: number|null, windowEnd?: number|null }} props
 */
export default function CoverageChart({ data, windowStart = null, windowEnd = null }) {
  const { rows } = data
  const min = Math.min(...[data.min, windowStart].filter(Number.isFinite))
  const max = Math.max(...[data.max, windowEnd].filter(Number.isFinite))
  if (!Number.isFinite(min) || !Number.isFinite(max) || rows.length === 0) {
    return <p className="font-mono text-sm text-fg-muted">No timestamps yet.</p>
  }
  const span = Math.max(max - min, 1)
  const hasWindow = Number.isFinite(windowStart) || Number.isFinite(windowEnd)
  const wStart = Number.isFinite(windowStart) ? windowStart : min
  const wEnd = Number.isFinite(windowEnd) ? windowEnd : max

  return (
    <div className="space-y-2 font-mono text-[11px]">
      <div className="grid grid-cols-[minmax(7rem,11rem)_minmax(0,1fr)] gap-x-3 gap-y-1.5">
        {rows.map((row) => (
          <div key={row.name} className="contents">
            <div className="truncate text-fg-muted" title={row.name}>
              {row.label}
              <span className="ml-1 text-fg-subtle">{row.kept.toLocaleString('en-US')}</span>
            </div>
            <div
              className="relative h-4 bg-canvas"
              role="img"
              aria-label={`${row.label}: ${
                Number.isFinite(row.first) ? `${formatDateTime(row.first)} – ${formatDateTime(row.last)}` : 'no dates'
              }, ${row.gaps.length} silences, ${row.cleared.length} clears`}
            >
              {hasWindow && (
                <div
                  className="absolute inset-y-0 bg-accent-soft"
                  style={{ left: pct(wStart, min, span), width: width(wStart, wEnd, span) }}
                />
              )}
              {Number.isFinite(row.first) && Number.isFinite(row.last) && (
                <div
                  className="absolute inset-y-1 bg-info-line"
                  style={{ left: pct(row.first, min, span), width: width(row.first, row.last, span) }}
                  title={`${formatDateTime(row.first)} – ${formatDateTime(row.last)} · ${row.total.toLocaleString(
                    'en-US',
                  )} records`}
                />
              )}
              {row.gaps.map(([from, to]) => (
                <div
                  key={`${from}-${to}`}
                  className="absolute inset-y-1 border-x border-med-line bg-[repeating-linear-gradient(135deg,var(--color-med-line)_0_2px,transparent_2px_5px)]"
                  style={{ left: pct(from, min, span), width: width(from, to, span) }}
                  title={`Silent ${formatDateTime(from)} – ${formatDateTime(to)}${row.approximate ? ' (from curated events only)' : ''}`}
                />
              ))}
              {row.cleared.map((time) => (
                <div
                  key={time}
                  className="absolute -inset-y-0.5 w-0.5 bg-high-line"
                  style={{ left: pct(time, min, span) }}
                  title={`Cleared ${formatDateTime(time)}`}
                />
              ))}
            </div>
          </div>
        ))}
        <div />
        <div className="flex justify-between text-fg-subtle">
          <span>{formatDateTime(min)}</span>
          <span>{formatDateTime(max)}</span>
        </div>
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-fg-muted">
        <span className="inline-flex items-center gap-1.5">
          <i className="inline-block h-2.5 w-4 bg-info-line" /> log coverage
        </span>
        <span className="inline-flex items-center gap-1.5">
          <i className="inline-block h-2.5 w-4 border-x border-med-line bg-[repeating-linear-gradient(135deg,var(--color-med-line)_0_2px,transparent_2px_5px)]" />
          silent ≥ 6 h
        </span>
        <span className="inline-flex items-center gap-1.5">
          <i className="inline-block h-3 w-0.5 bg-high-line" /> log cleared
        </span>
        {hasWindow && (
          <span className="inline-flex items-center gap-1.5">
            <i className="inline-block h-2.5 w-4 bg-accent-soft" /> suspicious window
          </span>
        )}
      </div>
    </div>
  )
}
