import { useEffect, useRef, useState } from 'react'
import { BaseEdge, EdgeLabelRenderer, getSmoothStepPath } from '@xyflow/react'
import { longestMiddle, pathThrough, routeStops } from '../../domain/automation/layout.js'

/*
 * A connection of the canvas.
 *
 * After "Tidy up" it follows the route the layout gave it (`data.route`):
 * straight parts that go round the nodes it does not join, its words where the
 * layout left room for them. Without a route (a line just drawn, a node moved
 * by hand since) it is a stepped line the canvas draws by itself.
 *
 * While the pointer is on it, or it is selected, a connection that can be
 * edited shows an ×, which removes it. Nothing else is on a line: there is no
 * corner to make or to drag.
 *
 * `data`: { route, label, labelColor, name, editable, onRemove() }.
 */

export default function CanvasEdge(props) {
  const { id, sourceX, sourceY, targetX, targetY, sourcePosition, targetPosition, markerEnd, style, selected } = props
  const data = props.data ?? {}
  const [hovered, setHoveredNow] = useState(false)
  // The × stays a moment after the pointer leaves the line: long enough to reach it.
  const leaving = useRef(null)
  const setHovered = (on) => {
    clearTimeout(leaving.current)
    if (on) setHoveredNow(true)
    else leaving.current = setTimeout(() => setHoveredNow(false), 250)
  }
  useEffect(() => () => clearTimeout(leaving.current), [])

  let path
  let spot
  if (data.route) {
    const stops = routeStops(data.route.points, { x: sourceX, y: sourceY }, { x: targetX, y: targetY })
    const middle = data.route.label ?? longestMiddle(stops)
    path = pathThrough(stops)
    spot = { left: middle.x, top: middle.y }
  } else {
    const [stepped, labelX, labelY] = getSmoothStepPath({
      sourceX,
      sourceY,
      targetX,
      targetY,
      sourcePosition,
      targetPosition,
    })
    path = stepped
    spot = { left: labelX, top: labelY }
  }
  const shown = Boolean(data.editable) && (hovered || selected)

  return (
    <>
      <g onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
        <BaseEdge id={id} path={path} markerEnd={markerEnd} style={style} interactionWidth={22} />
      </g>
      <EdgeLabelRenderer>
        {data.label && !shown && (
          <span
            style={{ ...spot, color: data.labelColor }}
            className="pointer-events-none absolute -translate-x-1/2 -translate-y-1/2 bg-canvas px-1 font-mono text-[10px]"
          >
            {data.label}
          </span>
        )}
        {shown && (
          <button
            type="button"
            aria-label={`Remove the connection${data.name ? ` ${data.name}` : ''}`}
            title="Remove this connection"
            style={spot}
            onMouseEnter={() => setHovered(true)}
            onMouseLeave={() => setHovered(false)}
            onClick={(event) => {
              event.stopPropagation()
              data.onRemove?.()
            }}
            className="nodrag nopan pointer-events-auto absolute z-[2000] flex h-5 w-5 -translate-x-1/2 -translate-y-1/2 items-center justify-center rounded-full border border-high-line bg-high-soft text-[13px] font-bold leading-none text-high-fg hover:bg-high hover:text-canvas focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            ×
          </button>
        )}
      </EdgeLabelRenderer>
    </>
  )
}
