import { useEffect, useRef, useState } from 'react'
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath, useReactFlow } from '@xyflow/react'
import {
  insertPoint,
  labelSpot,
  middles,
  movePoint,
  removePoint,
  routePath,
  cleanPoints,
} from '../../domain/automation/routing.js'

/*
 * A connection of the canvas.
 *
 * It draws itself as a stepped line until somebody routes it: then it goes
 * through its corners in straight parts (`data.points`, kept in the graph).
 * While the pointer is on it, or it is selected, an editable connection shows
 *
 *   - an × half way, which removes it;
 *   - a small filled square at each corner: drag it to move the corner,
 *     double-click it to take the corner away;
 *   - a small hollow square in the middle of each straight part: drag it and
 *     it becomes a corner.
 *
 * `data`: { points, label, labelColor, editable, onPoints(points), onRemove() }.
 */

const HANDLE =
  'nodrag nopan pointer-events-auto absolute z-[2000] -translate-x-1/2 -translate-y-1/2 border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

export default function RoutedEdge(props) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, selected } = props
  const data = props.data ?? {}
  const flow = useReactFlow()
  const [hovered, setHoveredNow] = useState(false)
  // The handles stay a moment after the pointer leaves the line: long enough to reach one.
  const leaving = useRef(null)
  const setHovered = (on) => {
    clearTimeout(leaving.current)
    if (on) setHoveredNow(true)
    else leaving.current = setTimeout(() => setHoveredNow(false), 250)
  }
  useEffect(() => () => clearTimeout(leaving.current), [])
  // The corners while one is dragged: drawn at once, saved when it is let go.
  const [dragging, setDragging] = useState(null)
  const source = { x: sourceX, y: sourceY }
  const target = { x: targetX, y: targetY }
  const points = dragging ?? cleanPoints(data.points)
  const routed = points.length > 0

  let path
  let spot
  if (routed) {
    path = routePath(source, target, points)
    // In the middle of the longest straight part: never on a corner.
    spot = labelSpot(source, target, points)
  } else {
    const [auto, labelX, labelY] = getSmoothStepPath({
      sourceX,
      sourceY,
      targetX,
      targetY,
      sourcePosition,
      targetPosition,
    })
    path = auto
    spot = { x: labelX, y: labelY }
  }

  const shown = Boolean(data.editable) && (hovered || selected || dragging !== null)

  /** Follow the pointer with the corners `make(point)` gives, and save them when it is let go. */
  const drag = (event, make) => {
    if (event.button !== 0) return
    event.preventDefault()
    event.stopPropagation()
    let last = null
    const move = (moved) => {
      last = make(flow.screenToFlowPosition({ x: moved.clientX, y: moved.clientY }))
      setDragging(last)
    }
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      window.removeEventListener('pointercancel', up)
      setDragging(null)
      if (last) data.onPoints?.(last)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    window.addEventListener('pointercancel', up)
  }

  /** A corner moved by keyboard: the arrows, ten at a time. */
  const nudge = (event, index) => {
    const step = { ArrowLeft: [-10, 0], ArrowRight: [10, 0], ArrowUp: [0, -10], ArrowDown: [0, 10] }[event.key]
    if (step) {
      event.preventDefault()
      event.stopPropagation()
      data.onPoints?.(movePoint(points, index, { x: points[index].x + step[0], y: points[index].y + step[1] }))
    } else if (event.key === 'Delete' || event.key === 'Backspace') {
      event.preventDefault()
      event.stopPropagation()
      data.onPoints?.(removePoint(points, index))
    }
  }

  const at = (point) => ({ left: point.x, top: point.y })
  return (
    <>
      <g onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
        <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} interactionWidth={22} />
      </g>
      <EdgeLabelRenderer>
        {data.label && !shown && (
          <span
            style={{ ...at(spot), color: data.labelColor }}
            className="pointer-events-none absolute -translate-x-1/2 -translate-y-1/2 bg-canvas px-1 font-mono text-[10px]"
          >
            {data.label}
          </span>
        )}
        {shown && (
          <div onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
            <button
              type="button"
              aria-label={`Remove the connection${data.name ? ` ${data.name}` : ''}`}
              title="Remove this connection"
              style={at(spot)}
              onClick={(event) => {
                event.stopPropagation()
                data.onRemove?.()
              }}
              className={`${HANDLE} flex h-5 w-5 items-center justify-center rounded-full border-high-line bg-high-soft text-[13px] font-bold leading-none text-high-fg hover:bg-high hover:text-canvas`}
            >
              ×
            </button>
            {points.map((point, index) => (
              <button
                key={`corner-${index}`}
                type="button"
                aria-label={`Corner ${index + 1} of the connection: drag to move, double-click to remove`}
                title="Drag to move · double-click to remove"
                style={at(point)}
                onPointerDown={(event) => drag(event, (to) => movePoint(points, index, to))}
                onDoubleClick={(event) => {
                  event.stopPropagation()
                  data.onPoints?.(removePoint(points, index))
                }}
                onKeyDown={(event) => nudge(event, index)}
                className={`${HANDLE} h-2.5 w-2.5 cursor-move border-med-line bg-med`}
              />
            ))}
            {(routed
              ? // Not under the ×, and not on a part too short to hold one.
                middles(source, target, points).map((middle) =>
                  middle.index === spot.index ? { ...middle, x: middle.x + 18 } : middle,
                )
              : // A line that draws itself has one, beside its ×: dragged, it is its first corner.
                [{ index: 0, x: spot.x + 18, y: spot.y }]
            ).map((middle) => (
              <button
                key={`middle-${middle.index}`}
                type="button"
                tabIndex={-1}
                aria-label="Drag to make a corner here"
                title="Drag to make a corner here"
                style={at(middle)}
                onPointerDown={(event) => drag(event, (to) => insertPoint(cleanPoints(data.points), middle.index, to))}
                className={`${HANDLE} h-2 w-2 cursor-crosshair border-med-line bg-canvas`}
              />
            ))}
          </div>
        )}
      </EdgeLabelRenderer>
    </>
  )
}
