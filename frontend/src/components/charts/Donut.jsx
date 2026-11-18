import { useRef, useState } from 'react'
import { seriesColor } from '../../domain/dashboards.js'
import { Tip, markProps, placeOf, useSize } from './shared.jsx'

/*
 * The parts of a whole as a ring, with the total in the middle and the parts
 * by name beside it, each with its figure and its share. Parts are kept
 * apart by a gap; past eight the smallest are one "Other".
 */

const MAX_PARTS = 8

function arc(cx, cy, outer, inner, from, to) {
  const point = (radius, angle) => [cx + radius * Math.sin(angle), cy - radius * Math.cos(angle)]
  const large = to - from > Math.PI ? 1 : 0
  const [x0, y0] = point(outer, from)
  const [x1, y1] = point(outer, to)
  const [x2, y2] = point(inner, to)
  const [x3, y3] = point(inner, from)
  return `M${x0},${y0}A${outer},${outer} 0 ${large} 1 ${x1},${y1}L${x2},${y2}A${inner},${inner} 0 ${large} 0 ${x3},${y3}Z`
}

/**
 * @param {{
 *   rows: { key: string, label: string, value: number | null }[],
 *   format: (value: number | null) => string,
 *   onPick?: ((key: string) => void) | null,
 *   more?: number,                              // groups the answer left out
 * }} props
 */
export default function Donut({ rows, format, onPick = null, more = 0 }) {
  const box = useRef(null)
  const [ref, size] = useSize()
  const [tip, setTip] = useState(null)
  let parts = rows.filter((row) => Number(row.value) > 0)
  if (parts.length > MAX_PARTS) {
    const rest = parts.slice(MAX_PARTS - 1)
    parts = [
      ...parts.slice(0, MAX_PARTS - 1),
      { key: '\u0000other', label: 'Other', value: rest.reduce((sum, row) => sum + Number(row.value), 0) },
    ]
  }
  const total = parts.reduce((sum, row) => sum + Number(row.value), 0)
  const side = Math.max(0, Math.min(size.height, size.width * 0.45, 220))
  const outer = side / 2 - 2
  const inner = outer * 0.62
  const gap = parts.length > 1 ? 0.03 : 0
  let angle = 0

  if (!parts.length) return <p className="p-3 text-center text-xs text-fg-muted">Nothing to show</p>
  return (
    <div ref={box} className="relative h-full min-h-0">
      <div ref={ref} className="flex h-full min-h-0 items-center gap-3">
        {side > 40 && (
          <svg width={side} height={side} className="shrink-0" role="group" aria-label="Parts of the whole">
            {parts.map((part, index) => {
              const sweep = (Number(part.value) / total) * Math.PI * 2
              const from = angle + gap / 2
              const to = Math.max(from + 0.001, angle + sweep - gap / 2)
              angle += sweep
              const share = Math.round((Number(part.value) / total) * 100)
              const picks = onPick && part.key !== '\u0000other'
              return (
                <path
                  key={part.key}
                  d={
                    parts.length === 1
                      ? `${arc(side / 2, side / 2, outer, inner, 0, Math.PI)}${arc(side / 2, side / 2, outer, inner, Math.PI, Math.PI * 2)}`
                      : arc(side / 2, side / 2, outer, inner, from, to)
                  }
                  fill={seriesColor(index, part.key)}
                  className="hover:brightness-125 focus-visible:outline-none"
                  {...markProps({
                    label: `${part.label}: ${format(part.value)}, ${share}%`,
                    onTip: (event) =>
                      setTip(
                        event && {
                          ...placeOf(event, box),
                          title: null,
                          rows: [{ label: `${part.label} · ${share}%`, value: format(part.value) }],
                        },
                      ),
                    onPick: picks ? () => onPick(part.key) : null,
                  })}
                />
              )
            })}
            <text
              x={side / 2}
              y={side / 2 + 2}
              textAnchor="middle"
              fontSize="18"
              fontWeight="600"
              fill="var(--color-fg)"
            >
              {format(total)}
            </text>
            <text x={side / 2} y={side / 2 + 17} textAnchor="middle" fontSize="10" fill="var(--color-fg-muted)">
              total
            </text>
          </svg>
        )}
        <ul className="min-h-0 min-w-0 flex-1 space-y-1 self-stretch overflow-y-auto text-xs">
          {parts.map((part, index) => (
            <li key={part.key} className="flex items-center gap-1.5">
              <span
                aria-hidden="true"
                className="h-2.5 w-2.5 shrink-0 rounded-[2px]"
                style={{ background: seriesColor(index, part.key) }}
              />
              <span className="min-w-0 flex-1 truncate text-fg-muted" title={part.label}>
                {part.label}
              </span>
              <span className="tabular-nums text-fg">{format(part.value)}</span>
              <span className="w-9 text-right tabular-nums text-fg-muted">
                {Math.round((Number(part.value) / total) * 100)}%
              </span>
            </li>
          ))}
          {more > 0 && <li className="text-fg-subtle">and {more} more</li>}
        </ul>
      </div>
      <Tip tip={tip} width={size.width} />
    </div>
  )
}
