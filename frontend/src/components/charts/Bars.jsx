import { useRef, useState } from 'react'
import { SERIES_COLORS, seriesColor } from '../../domain/dashboards.js'
import { Legend, Tip, markProps, placeOf, useSize } from './shared.jsx'

/*
 * Horizontal bars: one row for each value of a field, its name on the left,
 * the bar from a single baseline and the figure at its tip. With `series`
 * each row is one bar split into parts (a stacked bar), with a legend.
 *
 * Bars are thin (16px at most), square at the baseline and rounded at the
 * data end; the parts of a stack are kept apart by a gap, not by a border.
 */

/**
 * @param {{
 *   rows: { key: string, label: string, value?: number | null, values?: (number | null)[] }[],
 *   series?: { key: string, label: string }[] | null,   // the parts of each row, for a stacked bar
 *   format: (value: number | null) => string,
 *   onPick?: ((rowKey: string, seriesKey?: string) => void) | null,
 *   ranked?: boolean,                                  // a list of top values: rank numbers, no axis feel
 * }} props
 */
export default function Bars({ rows, series = null, format, onPick = null, ranked = false }) {
  const box = useRef(null)
  const [ref, size] = useSize()
  const [tip, setTip] = useState(null)
  const totals = rows.map((row) =>
    series ? row.values.reduce((sum, value) => sum + (value ?? 0), 0) : Number(row.value ?? 0),
  )
  const max = Math.max(1e-9, ...totals)
  const legend = (series ?? []).map((item, index) => ({ ...item, color: seriesColor(index, item.key) }))

  if (!rows.length) return <p className="p-3 text-center text-xs text-fg-muted">Nothing to show</p>
  return (
    <div ref={box} className="relative flex h-full min-h-0 flex-col gap-2">
      <Legend items={legend} />
      <ul ref={ref} className="min-h-0 flex-1 space-y-1.5 overflow-y-auto pr-1">
        {rows.map((row, index) => {
          const parts = series
            ? series.map((item, at) => ({ ...item, value: row.values[at], color: seriesColor(at, item.key) }))
            : [{ key: row.key, label: row.label, value: row.value, color: SERIES_COLORS[0] }]
          return (
            <li key={row.key} className="grid grid-cols-[minmax(0,34%)_minmax(0,1fr)_auto] items-center gap-2 text-xs">
              <span className="truncate text-fg-muted" title={row.label}>
                {ranked && <span className="mr-1.5 tabular-nums text-fg-subtle">{index + 1}</span>}
                {row.label}
              </span>
              <span className="flex h-3.5 items-stretch gap-0.5">
                {parts.map((part, at) => {
                  const share = (Number(part.value ?? 0) / max) * 100
                  if (share <= 0) return null
                  const last = parts.slice(at + 1).every((later) => !(Number(later.value ?? 0) > 0))
                  return (
                    <span
                      key={part.key}
                      {...markProps({
                        label: `${row.label}${series ? `, ${part.label}` : ''}: ${format(part.value)}`,
                        onTip: (event) =>
                          setTip(
                            event && {
                              ...placeOf(event, box),
                              title: series ? row.label : null,
                              rows: [{ color: part.color, label: part.label, value: format(part.value) }],
                            },
                          ),
                        onPick: onPick ? () => onPick(row.key, series ? part.key : undefined) : null,
                      })}
                      className="block min-w-[2px] hover:brightness-125 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      style={{
                        width: `${share}%`,
                        background: part.color,
                        borderRadius: last ? '0 4px 4px 0' : 0,
                        cursor: onPick ? 'pointer' : undefined,
                      }}
                    />
                  )
                })}
              </span>
              <span className="tabular-nums text-fg">{format(series ? totals[index] : row.value)}</span>
            </li>
          )
        })}
      </ul>
      <Tip tip={tip} width={size.width} />
    </div>
  )
}
