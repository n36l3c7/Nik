import { useRef, useState } from 'react'
import { seriesColor } from '../../domain/dashboards.js'
import { Legend, Tip, useSize } from './shared.jsx'

/*
 * A chart over an axis of time (or of any ordered values): lines, or columns
 * stacked by series. One vertical scale from zero, round ticks, hairline
 * grid; the pointer finds the position on the axis and one tooltip lists
 * every series there. Arrow keys move the same reading when the chart has
 * the focus, Enter opens the objects behind it.
 */

const PAD = { top: 8, right: 10, bottom: 20, left: 40 }

/** As many axis labels as fit side by side: every n-th, from the first. */
function shownLabels(count, width, longest) {
  const room = Math.max(1, Math.floor(width / (longest * 6 + 16)))
  const every = Math.max(1, Math.ceil(count / room))
  return (index) => index % every === 0
}

/**
 * @param {{
 *   kind: 'line' | 'columns',
 *   x: { key: string, label: string }[],
 *   series: { key: string, label: string, values: (number | null)[] }[],
 *   ticksOf: (max: number) => number[],
 *   format: (value: number | null) => string,
 *   onPick?: ((xKey: string) => void) | null,
 *   label: string,                               // what the chart shows, for who cannot see it
 * }} props
 */
export default function Plot({ kind, x, series, ticksOf, format, onPick = null, label }) {
  const box = useRef(null)
  const [ref, size] = useSize()
  const [at, setAt] = useState(null)
  const width = Math.max(0, size.width)
  const height = Math.max(0, size.height)
  const inner = { width: Math.max(1, width - PAD.left - PAD.right), height: Math.max(1, height - PAD.top - PAD.bottom) }
  const stacked = kind === 'columns'
  const tops = x.map((_, index) =>
    stacked
      ? series.reduce((sum, item) => sum + Math.max(0, item.values[index] ?? 0), 0)
      : Math.max(0, ...series.map((item) => item.values[index] ?? 0)),
  )
  const scale = ticksOf(Math.max(0, ...tops))
  const top = scale[scale.length - 1] || 1
  const yOf = (value) => PAD.top + inner.height - (Math.max(0, value) / top) * inner.height
  const band = inner.width / Math.max(1, x.length)
  const xOf = (index) =>
    stacked || x.length === 1
      ? PAD.left + band * (index + 0.5)
      : PAD.left + (inner.width * index) / Math.max(1, x.length - 1)
  const colours = series.map((item, index) => seriesColor(index, item.key))
  const longest = Math.max(1, ...x.map((point) => point.label.length))
  const shows = shownLabels(x.length, inner.width, longest)
  const columnWidth = Math.max(2, Math.min(24, band - 2))

  const indexAt = (event) => {
    const frame = box.current?.getBoundingClientRect()
    if (!frame || !x.length) return null
    const offset = event.clientX - frame.left - PAD.left
    const found = stacked ? Math.floor(offset / band) : Math.round((offset / inner.width) * (x.length - 1))
    return Math.max(0, Math.min(x.length - 1, found))
  }
  const onKey = (event) => {
    if (!x.length) return
    if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
      event.preventDefault()
      const step = event.key === 'ArrowRight' ? 1 : -1
      setAt((old) => Math.max(0, Math.min(x.length - 1, (old ?? (step > 0 ? -1 : x.length)) + step)))
    } else if ((event.key === 'Enter' || event.key === ' ') && at != null && onPick) {
      event.preventDefault()
      onPick(x[at].key)
    } else if (event.key === 'Escape') setAt(null)
  }
  const tip =
    at == null || !x[at]
      ? null
      : {
          x: xOf(at),
          y: PAD.top,
          title: x[at].label,
          rows: series.map((item, index) => ({
            color: series.length > 1 ? colours[index] : null,
            label: item.label,
            value: format(item.values[at]),
          })),
        }

  if (!x.length) return <p className="p-3 text-center text-xs text-fg-muted">Nothing to show</p>
  return (
    <div className="flex h-full min-h-0 flex-col gap-1.5">
      <Legend items={series.map((item, index) => ({ ...item, color: colours[index] }))} line={!stacked} />
      <div ref={box} className="relative min-h-0 flex-1">
        <div ref={ref} className="absolute inset-0">
          {width > 0 && height > 0 && (
            <svg
              width={width}
              height={height}
              role="img"
              aria-label={`${label}. ${x.length} points; arrow keys read them.`}
              tabIndex={0}
              onPointerMove={(event) => setAt(indexAt(event))}
              onPointerLeave={() => setAt(null)}
              onBlur={() => setAt(null)}
              onKeyDown={onKey}
              onClick={(event) => {
                const found = indexAt(event)
                if (found != null && onPick) onPick(x[found].key)
              }}
              className="block focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              style={{ cursor: onPick ? 'pointer' : 'default' }}
            >
              {scale.map((value) => (
                <g key={value}>
                  <line
                    x1={PAD.left}
                    x2={width - PAD.right}
                    y1={yOf(value)}
                    y2={yOf(value)}
                    stroke="var(--color-line-soft)"
                    strokeWidth="1"
                  />
                  <text
                    x={PAD.left - 6}
                    y={yOf(value) + 3}
                    textAnchor="end"
                    fontSize="10"
                    fill="var(--color-fg-muted)"
                    style={{ fontVariantNumeric: 'tabular-nums' }}
                  >
                    {format(value)}
                  </text>
                </g>
              ))}
              {x.map(
                (point, index) =>
                  shows(index) && (
                    <text
                      key={point.key}
                      x={xOf(index)}
                      y={height - 5}
                      textAnchor={index === 0 && !stacked ? 'start' : 'middle'}
                      fontSize="10"
                      fill="var(--color-fg-muted)"
                    >
                      {point.label}
                    </text>
                  ),
              )}
              {at != null && (
                <line
                  x1={xOf(at)}
                  x2={xOf(at)}
                  y1={PAD.top}
                  y2={PAD.top + inner.height}
                  stroke="var(--color-fg-subtle)"
                  strokeWidth="1"
                />
              )}
              {stacked
                ? x.map((point, index) => {
                    let base = 0
                    const filled = series
                      .map((item, order) => ({ order, value: Math.max(0, item.values[index] ?? 0) }))
                      .filter((part) => part.value > 0)
                    return filled.map((part, position) => {
                      const y0 = yOf(base)
                      base += part.value
                      const y1 = yOf(base)
                      const isTop = position === filled.length - 1
                      const gap = position === 0 ? 0 : 2 // parts are kept apart by a gap in the surface colour
                      const tall = Math.max(1, y0 - y1 - gap)
                      const left = xOf(index) - columnWidth / 2
                      const round = isTop ? Math.min(4, columnWidth / 2, tall) : 0
                      // Square at the baseline, rounded at the data end.
                      const path =
                        `M${left},${y1 + tall}V${y1 + round}q0,${-round} ${round},${-round}` +
                        `H${left + columnWidth - round}q${round},0 ${round},${round}V${y1 + tall}Z`
                      return (
                        <path
                          key={`${point.key}-${part.order}`}
                          d={path}
                          fill={colours[part.order]}
                          opacity={at == null || at === index ? 1 : 0.55}
                        />
                      )
                    })
                  })
                : series.map((item, order) => {
                    const points = item.values
                      .map((value, index) => (value == null ? null : [xOf(index), yOf(value)]))
                      .filter(Boolean)
                    if (!points.length) return null
                    const path = points.map(([px, py], index) => `${index ? 'L' : 'M'}${px},${py}`).join('')
                    const [lastX] = points[points.length - 1]
                    return (
                      <g key={item.key}>
                        {series.length === 1 && points.length > 1 && (
                          <path
                            d={`${path}L${lastX},${yOf(0)}L${points[0][0]},${yOf(0)}Z`}
                            fill={colours[order]}
                            opacity="0.1"
                          />
                        )}
                        <path
                          d={path}
                          fill="none"
                          stroke={colours[order]}
                          strokeWidth="2"
                          strokeLinejoin="round"
                          strokeLinecap="round"
                        />
                        {(points.length === 1 || at != null) && item.values[at ?? 0] != null && (
                          <circle
                            cx={xOf(at ?? 0)}
                            cy={yOf(item.values[at ?? 0])}
                            r="4"
                            fill={colours[order]}
                            stroke="var(--color-panel)"
                            strokeWidth="2"
                          />
                        )}
                      </g>
                    )
                  })}
            </svg>
          )}
        </div>
        <Tip tip={tip} width={width} />
      </div>
    </div>
  )
}
