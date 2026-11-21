import { useLayoutEffect, useRef, useState } from 'react'

/*
 * What every chart of a dashboard shares: its measured size, the tooltip, the
 * legend and the table that says the same as the picture. Charts are plain
 * SVG drawn in pixels of the box they are given; text is never in a series
 * colour (a swatch beside it carries the identity).
 */

/** The size of an element in pixels, kept up to date: `[ref, { width, height }]`. */
export function useSize() {
  const ref = useRef(null)
  const [size, setSize] = useState({ width: 0, height: 0 })
  useLayoutEffect(() => {
    const node = ref.current
    if (!node) return undefined
    const measure = () => {
      const box = node.getBoundingClientRect()
      setSize((old) =>
        Math.abs(old.width - box.width) < 1 && Math.abs(old.height - box.height) < 1
          ? old
          : { width: box.width, height: box.height },
      )
    }
    measure()
    if (typeof ResizeObserver === 'undefined') return undefined
    const observer = new ResizeObserver(measure)
    observer.observe(node)
    return () => observer.disconnect()
  }, [])
  return [ref, size]
}

/**
 * The tooltip of a chart: what is under the pointer, the value first.
 * `tip` is `{ x, y, title, rows: [{ color?, label, value }] }` in pixels of the chart's box.
 */
export function Tip({ tip, width }) {
  if (!tip) return null
  const left = Math.max(4, Math.min(tip.x + 12, Math.max(4, width - 190)))
  return (
    <div
      role="status"
      className="pointer-events-none absolute z-10 max-w-[180px] border border-line bg-raised px-2 py-1.5 text-xs shadow-lg"
      style={{ left, top: Math.max(0, tip.y - 8) }}
    >
      {tip.title && <p className="mb-0.5 truncate text-fg-muted">{tip.title}</p>}
      {tip.rows.map((row) => (
        <p key={row.label} className="flex items-center gap-1.5">
          {row.color && <span aria-hidden="true" className="h-0.5 w-3 shrink-0" style={{ background: row.color }} />}
          <span className="font-semibold tabular-nums text-fg">{row.value}</span>
          <span className="truncate text-fg-muted">{row.label}</span>
        </p>
      ))}
    </div>
  )
}

/** The series of a chart by name, each with its swatch: always there with two series or more. */
export function Legend({ items, line = false }) {
  if (items.length < 2) return null
  return (
    <ul className="flex shrink-0 flex-wrap gap-x-3 gap-y-0.5 text-xs text-fg-muted">
      {items.map((item) => (
        <li key={item.key} className="flex min-w-0 items-center gap-1.5">
          <span
            aria-hidden="true"
            className={line ? 'h-0.5 w-3 shrink-0' : 'h-2.5 w-2.5 shrink-0 rounded-[2px]'}
            style={{ background: item.color }}
          />
          <span className="truncate">{item.label}</span>
        </li>
      ))}
    </ul>
  )
}

/** The same figures as a table: what a chart shows, for who reads rather than looks. */
export function TableView({ columns, rows, onPick = null }) {
  return (
    <div className="h-full overflow-auto">
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-panel">
          <tr className="border-b border-line text-fg-muted">
            {columns.map((column, index) => (
              <th key={column} className={`px-2 py-1 font-medium ${index === columns.length - 1 ? 'text-right' : ''}`}>
                {column}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.key} className="border-b border-line-soft last:border-0">
              {row.cells.map((cell, index) => (
                <td
                  key={index}
                  className={`px-2 py-1 text-fg ${index === row.cells.length - 1 ? 'text-right tabular-nums' : ''}`}
                >
                  {index === 0 && onPick && row.keys ? (
                    <button
                      type="button"
                      onClick={() => onPick(row.keys)}
                      className="text-left hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {cell}
                    </button>
                  ) : (
                    cell
                  )}
                </td>
              ))}
            </tr>
          ))}
          {rows.length === 0 && (
            <tr>
              <td colSpan={columns.length} className="px-2 py-3 text-center text-fg-muted">
                Nothing to show
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}

/** A mark that answers the pointer and the keyboard: its tooltip on hover and focus, its objects on click. */
export function markProps({ label, onTip, onPick }) {
  const props = {
    'aria-label': label,
    onPointerMove: onTip,
    onPointerLeave: () => onTip(null),
    onFocus: onTip,
    onBlur: () => onTip(null),
  }
  if (!onPick) return { ...props, role: 'img', tabIndex: 0 }
  return {
    ...props,
    role: 'button',
    tabIndex: 0,
    onClick: onPick,
    onKeyDown: (event) => {
      if (event.key === 'Enter' || event.key === ' ') {
        event.preventDefault()
        onPick()
      }
    },
    style: { cursor: 'pointer' },
  }
}

/** Where the pointer (or the focused mark) is, in pixels of the chart's box. */
export function placeOf(event, box) {
  const frame = box.current?.getBoundingClientRect()
  if (!frame) return { x: 0, y: 0 }
  if (event.clientX != null && (event.clientX || event.clientY)) {
    return { x: event.clientX - frame.left, y: event.clientY - frame.top }
  }
  const mark = event.currentTarget.getBoundingClientRect()
  return { x: mark.left + mark.width / 2 - frame.left, y: mark.top - frame.top }
}
