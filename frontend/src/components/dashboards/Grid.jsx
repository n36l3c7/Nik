import { useRef, useState } from 'react'
import { Copy, GripVertical, Pencil, Table2, ChartNoAxesColumn, Trash2 } from 'lucide-react'
import {
  COLUMNS,
  GAP_PX,
  MAX_HEIGHT,
  NARROW_PX,
  ROW_PX,
  arrange,
  gridHeight,
  keyStep,
  readingOrder,
  typeOf,
} from '../../domain/dashboards.js'
import { useSize } from '../charts/shared.jsx'

/*
 * ============================================================================
 * GRID — the widgets of a dashboard on 12 columns
 * ============================================================================
 *
 * Reading: each widget in its box. Editing: a widget is dragged by its grip
 * and resized by its corner, snapping to the columns and to rows of 80 px;
 * the others make room and nothing overlaps. With the grip focused the arrow
 * keys move the widget and Shift+arrows resize it. Below 860 px the grid is
 * one column, in reading order (top-left first).
 */

const ICON_BUTTON =
  'flex h-6 w-6 items-center justify-center text-fg-muted hover:bg-raised hover:text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

// The types whose picture can be read as a table instead.
const CHARTS = new Set(['trend', 'bar', 'stacked_bar', 'pie', 'top', 'duration'])

/**
 * @param {{
 *   widgets: object[],
 *   editing: boolean,
 *   onChange: (widgets: object[]) => void,          // the grid after a move or a resize
 *   render: (widget: object, options: { asTable: boolean }) => import('react').ReactNode,
 *   onEdit: (widget: object) => void,
 *   onDuplicate: (widget: object) => void,
 *   onRemove: (widget: object) => void,
 * }} props
 */
export default function Grid({ widgets, editing, onChange, render, onEdit, onDuplicate, onRemove, onMenu = null }) {
  const [ref, size] = useSize()
  const [preview, setPreview] = useState(null) // the grid while a widget is dragged
  const [tables, setTables] = useState(() => new Set())
  const [said, setSaid] = useState('')
  const drag = useRef(null)
  const shown = preview ?? widgets
  const narrow = size.width > 0 && size.width < NARROW_PX
  const column = (size.width + GAP_PX) / COLUMNS

  const start = (event, widget, mode) => {
    if (event.button !== 0) return
    event.preventDefault()
    event.currentTarget.setPointerCapture(event.pointerId)
    drag.current = { id: widget.id, mode, x: event.clientX, y: event.clientY, from: widget, base: widgets, last: null }
    setPreview(widgets)
  }
  const move = (event) => {
    const held = drag.current
    if (!held) return
    const dx = Math.round((event.clientX - held.x) / column)
    const dy = Math.round((event.clientY - held.y) / ROW_PX)
    const patch =
      held.mode === 'move'
        ? { x: held.from.x + dx, y: Math.max(0, held.from.y + dy) }
        : { w: Math.max(1, held.from.w + dx), h: Math.max(1, Math.min(MAX_HEIGHT, held.from.h + dy)) }
    const key = JSON.stringify(patch)
    if (key === held.last) return
    held.last = key
    setPreview(arrange(held.base, held.id, patch))
  }
  const end = () => {
    if (!drag.current) return
    drag.current = null
    if (preview) onChange(preview)
    setPreview(null)
  }
  const onKey = (event, widget) => {
    const step = keyStep(event.key, event.shiftKey)
    if (!step) return
    event.preventDefault()
    const patch =
      step.dx != null
        ? { x: widget.x + step.dx, y: Math.max(0, widget.y + step.dy) }
        : { w: widget.w + step.dw, h: widget.h + step.dh }
    const next = arrange(widgets, widget.id, patch)
    const now = next.find((item) => item.id === widget.id)
    onChange(next)
    setSaid(`${widget.title || widget.type}: column ${now.x + 1}, row ${now.y + 1}, ${now.w} wide, ${now.h} tall`)
  }
  const toggleTable = (id) =>
    setTables((old) => {
      const next = new Set(old)
      if (!next.delete(id)) next.add(id)
      return next
    })

  const frame = (widget) => {
    const title = widget.title || typeOf(widget.type)?.label || widget.type
    const moving = drag.current?.id === widget.id
    const asTable = tables.has(widget.id)
    return (
      <article
        onContextMenu={onMenu ? (event) => onMenu(event, widget) : undefined}
        key={widget.id}
        aria-label={title}
        data-widget={widget.id}
        className={[
          'flex min-h-0 flex-col border bg-panel',
          moving ? 'z-10 border-accent shadow-xl' : 'border-line',
          narrow ? '' : 'absolute',
          preview && !moving ? 'transition-[top,left] duration-150 motion-reduce:transition-none' : '',
        ].join(' ')}
        style={
          narrow
            ? { height: widget.h * ROW_PX - GAP_PX }
            : {
                left: widget.x * column,
                top: widget.y * ROW_PX,
                width: Math.max(0, widget.w * column - GAP_PX),
                height: widget.h * ROW_PX - GAP_PX,
              }
        }
      >
        <header className="flex h-8 shrink-0 items-center gap-1 pl-3 pr-1">
          {editing && !narrow && (
            <button
              type="button"
              aria-label={`Move ${title}: drag, or use the arrow keys; Shift and the arrow keys resize it`}
              title="Drag to move · arrow keys move · Shift+arrows resize"
              onPointerDown={(event) => start(event, widget, 'move')}
              onPointerMove={move}
              onPointerUp={end}
              onPointerCancel={end}
              onKeyDown={(event) => onKey(event, widget)}
              className={`${ICON_BUTTON} -ml-2 cursor-grab touch-none active:cursor-grabbing`}
            >
              <GripVertical className="h-4 w-4" aria-hidden="true" />
            </button>
          )}
          <h2 className="min-w-0 flex-1 truncate text-xs font-semibold text-fg" title={title}>
            {title}
          </h2>
          {editing ? (
            <>
              <button
                type="button"
                aria-label={`Edit ${title}`}
                title="Edit"
                onClick={() => onEdit(widget)}
                className={ICON_BUTTON}
              >
                <Pencil className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
              <button
                type="button"
                aria-label={`Duplicate ${title}`}
                title="Duplicate"
                onClick={() => onDuplicate(widget)}
                className={ICON_BUTTON}
              >
                <Copy className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
              <button
                type="button"
                aria-label={`Remove ${title}`}
                title="Remove"
                onClick={() => onRemove(widget)}
                className={ICON_BUTTON}
              >
                <Trash2 className="h-3.5 w-3.5" aria-hidden="true" />
              </button>
            </>
          ) : (
            CHARTS.has(widget.type) &&
            (widget.groupBy ?? []).length > 0 && (
              <button
                type="button"
                aria-pressed={asTable}
                aria-label={asTable ? `Show ${title} as a chart` : `Show ${title} as a table`}
                title={asTable ? 'Show as a chart' : 'Show as a table'}
                onClick={() => toggleTable(widget.id)}
                className={ICON_BUTTON}
              >
                {asTable ? (
                  <ChartNoAxesColumn className="h-3.5 w-3.5" aria-hidden="true" />
                ) : (
                  <Table2 className="h-3.5 w-3.5" aria-hidden="true" />
                )}
              </button>
            )
          )}
        </header>
        <div className={`min-h-0 flex-1 px-3 pb-3 ${preview ? 'pointer-events-none' : ''}`}>
          {render(widget, { asTable })}
        </div>
        {editing && !narrow && (
          <span
            role="presentation"
            title="Drag to resize"
            onPointerDown={(event) => start(event, widget, 'resize')}
            onPointerMove={move}
            onPointerUp={end}
            onPointerCancel={end}
            className="absolute bottom-0 right-0 h-4 w-4 cursor-nwse-resize touch-none border-b-2 border-r-2 border-fg-subtle hover:border-accent"
          />
        )}
      </article>
    )
  }

  return (
    <div ref={ref} className="relative w-full">
      <p aria-live="polite" className="sr-only">
        {said}
      </p>
      {narrow ? (
        <div className="flex flex-col" style={{ gap: GAP_PX }}>
          {readingOrder(shown).map(frame)}
        </div>
      ) : (
        <div className="relative" style={{ height: Math.max(0, gridHeight(shown) * ROW_PX - GAP_PX) }}>
          {size.width > 0 && shown.map(frame)}
        </div>
      )}
    </div>
  )
}
