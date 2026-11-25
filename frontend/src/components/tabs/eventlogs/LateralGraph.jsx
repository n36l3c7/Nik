import { memo, useCallback, useEffect, useId, useMemo, useRef, useState } from 'react'
import { Maximize2, Minus, Plus } from 'lucide-react'
import { Button, Wait } from '../../ui/index.js'
import {
  LABEL_SCALE,
  busiest,
  countText,
  cutText,
  edgeFilters,
  fitTransform,
  layout,
  nodeFilters,
  panBy,
  showsLabels,
  typesText,
  zoomAt,
} from '../../../domain/lateralGraph.js'
import { logonTypeName } from '../../../domain/logons.js'
import { formatDateTime } from '../../../lib/time.js'

/*
 * The lateral-movement graph, drawn as inline SVG (no library): the machines and addresses logons came from
 * on the left, the ones they reached on the right (domain/lateralGraph.js lays it out, the same every time).
 * Wheel and drag move and zoom it, "Fit" puts it whole in the box. A host the incident has evidence of is a
 * solid disc, the others are hollow, an address is smaller; an edge is thicker with its count and red when
 * some of its logons failed. Edges are plain paths and their counts are written from a scale up (or on hover),
 * so 300 machines and 1,500 links stay quick. The table under the graph is its text alternative: the SVG
 * says so in its description.
 */

const HEIGHT = 420
const STYLE = {
  edge: { stroke: 'var(--color-info-line)' },
  failed: { stroke: 'var(--color-high-line)' },
  picked: { stroke: 'var(--color-accent)' },
}
const LABEL_HALO = { stroke: 'var(--color-canvas)', strokeWidth: 3, paintOrder: 'stroke', fill: 'var(--color-fg)' }
const LABEL_MAX = 26

const short = (text) => (text.length > LABEL_MAX ? `${text.slice(0, LABEL_MAX - 1)}…` : text)

/** The edges: plain paths, each with a wider invisible one to be hit; drawn again only when what is picked changes. */
const Edges = memo(function Edges({ edges, picked, labels }) {
  return (
    <g fill="none">
      {edges.map((edge) => {
        const on = edge.key === picked
        const look = on ? STYLE.picked : edge.failed > 0 ? STYLE.failed : STYLE.edge
        return (
          <g key={edge.key}>
            <path
              d={edge.path}
              strokeWidth={on ? edge.width + 1.5 : edge.width}
              strokeOpacity={on ? 1 : 0.65}
              strokeLinecap="round"
              markerEnd={`url(#arrow-${on ? 'picked' : edge.failed > 0 ? 'failed' : 'edge'})`}
              style={look}
            />
            <path
              d={edge.path}
              data-edge={edge.key}
              strokeWidth={Math.max(12, edge.width + 6)}
              stroke="transparent"
              style={{ cursor: 'pointer', pointerEvents: 'stroke' }}
            />
            {(labels || on) && (
              <text
                x={edge.mid.x}
                y={edge.mid.y - 3}
                textAnchor="middle"
                fontSize="11"
                style={{ ...LABEL_HALO, pointerEvents: 'none' }}
              >
                {edge.count}
              </text>
            )}
          </g>
        )
      })}
    </g>
  )
})

/** The machines and addresses. */
const Nodes = memo(function Nodes({ nodes, picked, labels, focusable }) {
  return (
    <g>
      {nodes.map((node) => {
        const solid = node.kind === 'host' && node.inEvidence
        const on = node.id === picked
        return (
          <g
            key={node.id}
            data-node={node.id}
            style={{ cursor: 'pointer' }}
            role={focusable ? 'button' : undefined}
            tabIndex={focusable ? 0 : undefined}
            aria-label={focusable ? `${node.label}: ${node.logonsIn} in, ${node.logonsOut} out` : undefined}
            onKeyDown={
              focusable
                ? (event) => {
                    if (event.key === 'Enter' || event.key === ' ') {
                      event.preventDefault()
                      event.currentTarget.dispatchEvent(new MouseEvent('click', { bubbles: true }))
                    }
                  }
                : undefined
            }
          >
            <circle
              cx={node.x}
              cy={node.y}
              r={node.r + (on ? 2 : 0)}
              strokeWidth={node.failed > 0 ? 3 : 2}
              style={{
                fill: solid ? 'var(--color-accent-strong)' : 'var(--color-canvas)',
                stroke: on
                  ? 'var(--color-accent)'
                  : node.failed > 0
                    ? 'var(--color-high-line)'
                    : solid
                      ? 'var(--color-accent-fg)'
                      : 'var(--color-fg-muted)',
              }}
            />
            {(labels || on) && (
              <text x={node.x} y={node.y + node.r + 13} textAnchor="middle" fontSize="11" style={LABEL_HALO}>
                {short(node.label)}
              </text>
            )}
          </g>
        )
      })}
    </g>
  )
})

/** What the pointer is over, in words (a small box near it). */
function Tip({ tip }) {
  if (!tip) return null
  return (
    <div
      role="status"
      className="pointer-events-none absolute z-20 max-w-xs border border-line bg-raised px-3 py-2 text-xs shadow-2xl"
      style={{ left: Math.min(tip.x + 14, tip.width - 280), top: tip.y + 14 }}
    >
      {tip.lines.map((line, index) => (
        <p key={index} className={index === 0 ? 'm-0 font-mono font-semibold text-fg' : 'm-0 text-fg-muted'}>
          {line}
        </p>
      ))}
    </div>
  )
}

/**
 * @param {{ graph: object | null, loading: boolean, error: string, minCount: number,
 *   onMinCount: (count: number) => void, onFilter: (filters: object) => void }} props
 * `onFilter(filters)` is called with the filters of the table for a click on an edge or a node.
 */
export default function LateralGraph({ graph, loading, error, minCount, onMinCount, onFilter }) {
  const titleId = useId()
  const boxRef = useRef(null)
  const svgRef = useRef(null)
  const [box, setBox] = useState({ width: 900, height: HEIGHT })
  const [transform, setTransform] = useState({ k: 1, x: 0, y: 0 })
  const [tip, setTip] = useState(null)
  const [node, setNode] = useState(null) // the node clicked: the direction is chosen under the graph
  const [pickedEdge, setPickedEdge] = useState('') // the edge clicked
  const dragged = useRef(false)

  const picture = useMemo(() => layout(graph), [graph])
  const byEdge = useMemo(() => new Map(picture.edges.map((edge) => [edge.key, edge])), [picture])
  const byNode = useMemo(() => new Map(picture.nodes.map((item) => [item.id, item])), [picture])
  const labels = showsLabels(transform.k)
  const nodeLabels = picture.nodes.length <= 40 || labels

  // The size of the box: the picture is fitted to it.
  useEffect(() => {
    const element = boxRef.current
    if (!element) return undefined
    const read = () => setBox({ width: element.clientWidth || 900, height: HEIGHT })
    read()
    if (typeof ResizeObserver === 'undefined') return undefined
    const watcher = new ResizeObserver(read)
    watcher.observe(element)
    return () => watcher.disconnect()
  }, [])
  const fit = useCallback(
    () => setTransform(fitTransform({ width: picture.width, height: picture.height }, box)),
    [picture, box],
  )
  useEffect(() => {
    fit()
  }, [fit])
  // A new picture (other filters): what was picked is not in it any more.
  useEffect(() => {
    setNode(null)
    setPickedEdge('')
  }, [graph])

  // The wheel zooms where the pointer is; a listener of its own because React's is passive.
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return undefined
    const onWheel = (event) => {
      event.preventDefault()
      const rect = svg.getBoundingClientRect()
      const at = { x: event.clientX - rect.left, y: event.clientY - rect.top }
      setTransform((held) => zoomAt(held, at, event.deltaY < 0 ? 1.15 : 1 / 1.15))
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => svg.removeEventListener('wheel', onWheel)
  }, [])

  const onPointerDown = (event) => {
    if (event.button !== 0) return
    dragged.current = false
    const start = { x: event.clientX, y: event.clientY }
    let last = start
    const move = (next) => {
      if (Math.hypot(next.clientX - start.x, next.clientY - start.y) > 4) dragged.current = true
      if (!dragged.current) return
      const dx = next.clientX - last.x
      const dy = next.clientY - last.y
      last = { x: next.clientX, y: next.clientY }
      setTransform((held) => panBy(held, dx, dy))
      setTip(null)
    }
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
    }
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
  }

  const describe = (target) => {
    const edge = byEdge.get(target.closest('[data-edge]')?.dataset.edge)
    if (edge) {
      const from = byNode.get(edge.from)
      const to = byNode.get(edge.to)
      return [
        `${from?.label ?? edge.from} → ${to?.label ?? edge.to}`,
        countText(edge),
        edge.users?.length ? `Users: ${edge.users.join(', ')}` : '',
        edge.types?.length ? `Types: ${typesText(edge.types, logonTypeName)}` : '',
        `First ${formatDateTime(edge.firstTs)} · last ${formatDateTime(edge.lastTs)}`,
      ].filter(Boolean)
    }
    const item = byNode.get(target.closest('[data-node]')?.dataset.node)
    if (item) {
      return [
        item.label,
        `${item.kind === 'address' ? 'Address' : item.inEvidence ? 'Host with evidence in the incident' : 'Host with no evidence in the incident'}`,
        `${item.logonsIn.toLocaleString('en-US')} logons in · ${item.logonsOut.toLocaleString('en-US')} out${item.failed > 0 ? ` · ${item.failed.toLocaleString('en-US')} failed` : ''}`,
      ]
    }
    return null
  }
  const onMove = (event) => {
    if (dragged.current && event.buttons) return
    const lines = describe(event.target)
    if (!lines) return setTip(null)
    const rect = boxRef.current.getBoundingClientRect()
    setTip({ lines, x: event.clientX - rect.left, y: event.clientY - rect.top, width: rect.width })
  }

  const choose = (item, direction) => {
    setNode({ id: item.id, direction })
    setPickedEdge('')
    onFilter(nodeFilters(item, direction))
  }
  const onClick = (event) => {
    if (dragged.current) return
    const edge = byEdge.get(event.target.closest('[data-edge]')?.dataset.edge)
    if (edge) {
      setNode(null)
      setPickedEdge(edge.key)
      onFilter(edgeFilters(byNode.get(edge.from), byNode.get(edge.to)))
      return
    }
    const item = byNode.get(event.target.closest('[data-node]')?.dataset.node)
    if (item) choose(item, 'in')
  }

  const zoomBy = (factor) => setTransform((held) => zoomAt(held, { x: box.width / 2, y: box.height / 2 }, factor))
  const chosen = node ? byNode.get(node.id) : null
  const slider = Math.max(busiest(graph), minCount, 2)
  const summary = `${picture.nodes.length.toLocaleString('en-US')} machines and addresses, ${picture.edges.length.toLocaleString('en-US')} links`

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <Button variant="secondary" size="xs" icon={Maximize2} onClick={fit}>
          Fit
        </Button>
        <Button variant="ghost" size="xs" icon={Plus} aria-label="Zoom in" onClick={() => zoomBy(1.3)} />
        <Button variant="ghost" size="xs" icon={Minus} aria-label="Zoom out" onClick={() => zoomBy(1 / 1.3)} />
        <label className="inline-flex items-center gap-2 font-mono text-xs text-fg-muted">
          Minimum count
          <input
            type="range"
            min={1}
            max={slider}
            value={Math.max(1, minCount)}
            onChange={(event) => onMinCount(Number(event.target.value))}
            className="w-40 accent-[var(--color-accent)] focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <span className="w-8 text-fg">{Math.max(1, minCount)}</span>
        </label>
        <p className="m-0 ml-auto text-xs text-fg-muted" aria-live="polite">
          {loading ? 'Reading…' : summary}
        </p>
      </div>

      <div
        ref={boxRef}
        className="relative overflow-hidden border border-line bg-canvas"
        style={{ height: HEIGHT }}
        onMouseLeave={() => setTip(null)}
      >
        {error && (
          <p role="alert" className="absolute left-3 top-3 z-10 m-0 text-sm text-high-fg">
            {error}
          </p>
        )}
        {loading && !graph && (
          <div className="absolute left-3 top-3 z-10">
            <Wait>Reading the logons…</Wait>
          </div>
        )}
        {!loading && !error && picture.nodes.length === 0 && (
          <p className="absolute inset-0 m-0 flex items-center justify-center font-mono text-sm text-fg-muted">
            No logon from another machine matches: nothing to draw
          </p>
        )}
        <svg
          ref={svgRef}
          width={box.width}
          height={HEIGHT}
          role="img"
          aria-labelledby={`${titleId}-t ${titleId}-d`}
          className={`block touch-none select-none ${loading ? 'opacity-60' : ''}`}
          style={{ cursor: 'grab' }}
          onPointerDown={onPointerDown}
          onMouseMove={onMove}
          onClick={onClick}
        >
          <title id={`${titleId}-t`}>Lateral movement between machines</title>
          <desc id={`${titleId}-d`}>
            {summary}. An arrow goes from where a logon came to the machine that recorded it; the table under the graph
            lists every logon.
          </desc>
          <defs>
            {[
              ['edge', 'var(--color-info-line)'],
              ['failed', 'var(--color-high-line)'],
              ['picked', 'var(--color-accent)'],
            ].map(([name, colour]) => (
              <marker
                key={name}
                id={`arrow-${name}`}
                viewBox="0 0 10 10"
                refX="9"
                refY="5"
                markerWidth="9"
                markerHeight="9"
                markerUnits="userSpaceOnUse"
                orient="auto"
              >
                <path d="M0 0L10 5L0 10z" style={{ fill: colour }} />
              </marker>
            ))}
          </defs>
          <g transform={`translate(${transform.x} ${transform.y}) scale(${transform.k})`}>
            <Edges edges={picture.edges} picked={pickedEdge} labels={labels} />
            <Nodes
              nodes={picture.nodes}
              picked={chosen?.id ?? ''}
              labels={nodeLabels}
              focusable={picture.nodes.length <= 40}
            />
          </g>
        </svg>
        <Tip tip={tip} />
      </div>

      <ul className="m-0 flex list-none flex-wrap items-center gap-x-5 gap-y-1 p-0 font-mono text-[11px] text-fg-muted">
        <li className="inline-flex items-center gap-1.5">
          <svg width="14" height="14" aria-hidden="true">
            <circle
              cx="7"
              cy="7"
              r="5"
              style={{ fill: 'var(--color-accent-strong)', stroke: 'var(--color-accent-fg)' }}
            />
          </svg>
          host with evidence
        </li>
        <li className="inline-flex items-center gap-1.5">
          <svg width="14" height="14" aria-hidden="true">
            <circle
              cx="7"
              cy="7"
              r="5"
              strokeWidth="2"
              style={{ fill: 'var(--color-canvas)', stroke: 'var(--color-fg-muted)' }}
            />
          </svg>
          host with none
        </li>
        <li className="inline-flex items-center gap-1.5">
          <svg width="14" height="14" aria-hidden="true">
            <circle
              cx="7"
              cy="7"
              r="3"
              strokeWidth="2"
              style={{ fill: 'var(--color-canvas)', stroke: 'var(--color-fg-muted)' }}
            />
          </svg>
          address
        </li>
        <li className="inline-flex items-center gap-1.5">
          <i className="inline-block h-0.5 w-5" style={{ background: 'var(--color-high-line)' }} /> has failed logons
        </li>
        <li>
          Thickness: how many logons. Drag to move, wheel to zoom
          {labels ? '' : `, from ${LABEL_SCALE}× the counts show`}.
        </li>
      </ul>

      {chosen && (
        <p className="m-0 flex flex-wrap items-center gap-2 text-xs text-fg-muted">
          <span className="font-mono text-fg">{chosen.label}</span>
          {chosen.kind === 'address' ? (
            <span>Logons that came from this address.</span>
          ) : (
            <>
              <span>Show the logons</span>
              {['in', 'out'].map((direction) => (
                <Button
                  key={direction}
                  size="xs"
                  variant={node.direction === direction ? 'primary' : 'secondary'}
                  aria-pressed={node.direction === direction}
                  onClick={() => choose(chosen, direction)}
                >
                  {direction === 'in' ? 'in (it recorded)' : 'out (they came from it)'}
                </Button>
              ))}
            </>
          )}
        </p>
      )}
      {graph?.cut && (
        <p role="note" className="m-0 text-xs text-med-fg">
          {cutText(graph, { nodes: picture.nodes.length, edges: picture.edges.length })}
        </p>
      )}
    </div>
  )
}
