import { memo, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Position,
  ReactFlow,
  ReactFlowProvider,
  useReactFlow,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { asksApproval, entryOf, headingOf, summaryOf } from '../../domain/automation/catalog.js'
import {
  KIND_LABELS,
  portLabel,
  connect,
  connectProblem,
  disconnect,
  moveNodes,
  nodeOf,
  portOf,
  removeNodes,
} from '../../domain/automation/graph.js'
import { SIGNS } from '../../domain/automation/compare.js'
import { NODE_WIDTH, handlePlaces } from '../../domain/automation/layout.js'
import CanvasEdge from './CanvasEdge.jsx'

/*
 * ============================================================================
 * CANVAS — a playbook drawn as nodes and edges (@xyflow/react)
 * ============================================================================
 *
 * The graph (domain/automation/graph.js) is the one source of truth and
 * belongs to the page: the canvas shows it, and reports every edit as a new
 * graph through `onChange`. Only what happens while the pointer is down (a
 * node being dragged, what is selected) lives here.
 *
 * Reachable without a pointer: Tab moves through the nodes, Enter selects
 * one, the arrow keys move it, Delete removes it; edges are drawn from the
 * inspector ("Goes to"), and the node list under the canvas shows the same
 * playbook as a table.
 *
 * A right-click, on a node, on several selected ones, on a line or on the
 * empty canvas, is told to the page (`onMenu`), which opens the menu; so are
 * the menu key and Shift+F10 on what has the focus. A node that is
 * right-clicked becomes the selection, unless it is one of several selected:
 * then the menu is about all of them.
 *
 * `readOnly` with `statuses` draws a run: the same nodes, coloured by what
 * happened to each. `readOnly` with `marks` draws one side of a comparison:
 * what was added, removed or changed is told by a sign and by the style of
 * its border, never by colour alone; with `viewport` and `onViewportChange`
 * the page holds where the canvas looks, so that two of them move together.
 */

export const DRAG_TYPE = 'application/x-nik-node'

// The strip on top of a node, by kind.
const HEADS = {
  trigger: 'bg-accent-soft text-accent-fg',
  condition: 'bg-med-soft text-med',
  for_each: 'bg-med-soft text-med',
  wait: 'bg-raised text-fg-muted',
  approval: 'bg-high-soft text-high',
  task: 'bg-accent-soft text-accent-fg',
  ask: 'bg-high-soft text-high',
  action: 'bg-info-soft/60 text-info',
  script: 'bg-violet-soft text-violet',
  playbook: 'bg-info-soft/60 text-info',
  end: 'bg-raised text-fg-muted',
}

// A node of a run, by what happened to it.
const STATUS_BORDERS = {
  done: 'border-accent',
  running: 'border-info-line',
  waiting: 'border-med-line',
  interrupted: 'border-2 border-dashed border-med-line',
  failed: 'border-high-line',
  skipped: 'border-line opacity-50',
  pending: 'border-line opacity-70',
}

// A node of a comparison, by what happened to it between main and the branch.
const MARK_BORDERS = {
  added: 'border-2 border-solid border-accent bg-accent-soft',
  removed: 'border-2 border-dashed border-high-line bg-high-soft',
  changed: 'border-2 border-dotted border-med-line bg-med-soft',
}
// A line of a comparison: drawn anew, taken away, or going somewhere else.
const MARK_LINES = {
  added: { stroke: '#3fb950', strokeWidth: 2.5 },
  removed: { stroke: '#f85149', strokeWidth: 2.5, strokeDasharray: '6 4' },
  moved: { stroke: '#e3b341', strokeWidth: 2.5, strokeDasharray: '2 3' },
}

const HANDLE = '!h-2.5 !w-2.5 !rounded-none !border !border-line !bg-raised'

const PlaybookNode = memo(function PlaybookNode({ data, selected }) {
  const { node, entry, problems, status, approval, readOnly, plain, mark } = data
  // A plain node (the work plan of an incident) is its kind and a few words given with it.
  const heading = plain ? (KIND_LABELS[node.kind] ?? node.kind) : headingOf(node, entry)
  const summary = plain ? (node.summary ?? '') : summaryOf(node, entry)
  const places = handlePlaces(node)
  const border = status ? (STATUS_BORDERS[status] ?? 'border-line') : problems ? 'border-high-line' : 'border-line'
  return (
    <div
      style={{ width: NODE_WIDTH }}
      className={[
        'text-xs text-fg',
        mark ? MARK_BORDERS[mark] : `border bg-panel ${border}`,
        selected ? 'outline outline-2 outline-offset-2 outline-accent' : '',
      ].join(' ')}
    >
      {node.kind !== 'trigger' && (
        <Handle type="target" position={Position.Top} className={HANDLE} isConnectable={!readOnly} />
      )}
      <p
        className={[
          'flex items-center justify-between gap-2 border-b border-line px-2 py-0.5 font-mono text-[10px] font-semibold uppercase tracking-wider',
          HEADS[node.kind] ?? HEADS.end,
        ].join(' ')}
      >
        <span className="truncate">
          {mark ? `${SIGNS[mark]} ` : ''}
          {heading}
          {mark ? ` · ${mark}` : ''}
        </span>
        {approval && (
          <span className="shrink-0 normal-case tracking-normal text-med" title="Asks a person before it runs">
            asks first
          </span>
        )}
        {problems > 0 && !status && (
          <span className="shrink-0 text-high-fg" title={`${problems} to fix before this can be saved as a version`}>
            {problems} to fix
          </span>
        )}
        {status && <span className="shrink-0 normal-case tracking-normal">{status}</span>}
      </p>
      <p className="truncate px-2 pt-1 font-medium" title={node.name || node.id}>
        {node.name || node.id}
      </p>
      <p className="truncate px-2 pb-1.5 text-[11px] text-fg-muted" title={summary}>
        {summary}
      </p>
      {places.below.map(({ port, left }) => (
        <Handle
          key={port}
          id={port}
          type="source"
          position={Position.Bottom}
          // Where the layout is told the port is (layout.js): a line arrives where it was routed to.
          style={{ left: `${left * 100}%` }}
          className={HANDLE}
          isConnectable={!readOnly}
          title={portLabel(node, port) || 'then'}
        />
      ))}
      {places.side && (
        <Handle
          id="error"
          type="source"
          position={Position.Right}
          className={`${HANDLE} !border-high-line`}
          isConnectable={!readOnly}
          title="on error"
        />
      )}
    </div>
  )
})

const NODE_TYPES = { playbook: PlaybookNode }
const FIT = { maxZoom: 1, padding: 0.2 }

const EDGE_TYPES = { line: CanvasEdge }

const edgeId = (edge, graph) => `${edge.from}\u0000${portOf(edge, graph)}\u0000${edge.to}`
const edgeParts = (id) => {
  const [from, port, to] = id.split('\u0000')
  return { from, port, to }
}

const LABEL_COLORS = { yes: '#7ee787', approved: '#7ee787', no: '#e3b341', refused: '#e3b341', error: '#ff7b72' }

function Flow({
  graph,
  catalog,
  problems,
  statuses,
  approvalDefault,
  readOnly,
  plain = false,
  marks = null,
  viewport,
  onViewportChange,
  selection,
  onSelect,
  onChange,
  onDropEntry,
  onRefused,
  onMenu,
}) {
  const flow = useReactFlow()
  const [chosen, setChosen] = useState({ nodes: new Set(), edges: new Set() })
  // While a node is dragged: where the pointer has it, before the graph is told.
  const [dragged, setDragged] = useState(null)
  const draggedRef = useRef(null)
  // What xyflow measured of each node. It is given back with the nodes: a node without its
  // measure is hidden until it is measured again, which a redraw would cause every time.
  const [sizes, setSizes] = useState({})

  // The page chose nodes (a new node, a row of the node list): the canvas follows.
  useEffect(() => {
    if (!selection) return
    setChosen({ nodes: new Set(selection.ids), edges: new Set() })
  }, [selection])

  const counts = useMemo(() => {
    const found = new Map()
    for (const problem of problems ?? []) if (problem.node) found.set(problem.node, (found.get(problem.node) ?? 0) + 1)
    return found
  }, [problems])

  const nodes = useMemo(
    () =>
      graph.nodes.map((node) => {
        const entry = entryOf(node, catalog)
        return {
          id: node.id,
          type: 'playbook',
          position: dragged?.[node.id] ?? node.position,
          measured: sizes[node.id],
          selected: chosen.nodes.has(node.id),
          deletable: node.kind !== 'trigger',
          ariaLabel: `${headingOf(node, entry)}: ${node.name || node.id}${marks?.nodes[node.id] ? `, ${marks.nodes[node.id]}` : ''}`,
          data: {
            node,
            entry,
            mark: marks?.nodes[node.id] ?? null,
            problems: counts.get(node.id) ?? 0,
            status: statuses ? (statuses[node.id] ?? 'pending') : null,
            approval: !statuses && asksApproval(node, entry, approvalDefault),
            readOnly,
            plain,
          },
        }
      }),
    [graph, catalog, chosen.nodes, counts, statuses, approvalDefault, readOnly, plain, marks, dragged, sizes],
  )

  const edges = useMemo(
    () =>
      graph.edges.map((edge) => {
        const port = portOf(edge, graph)
        const id = edgeId(edge, graph)
        const label = portLabel(nodeOf(graph, edge.from), port)
        const failing = port === 'error'
        const mark = marks?.edges[id] ?? null
        const stroke = mark ? MARK_LINES[mark].stroke : failing ? '#f85149' : '#6e7681'
        return {
          id,
          source: edge.from,
          target: edge.to,
          sourceHandle: port,
          // Drawn by CanvasEdge: along the route "Tidy up" gave it, or as a stepped line; with an × to remove it.
          type: 'line',
          selected: chosen.edges.has(id),
          data: {
            // While one of its nodes is dragged the route is not the line's any more.
            route: dragged?.[edge.from] || dragged?.[edge.to] ? null : (edge.route ?? null),
            label: label || '',
            labelColor: LABEL_COLORS[port] ?? '#9da7b3',
            name: `from ${edge.from} to ${edge.to}`,
            editable: !readOnly,
            onRemove: () => onChange?.(disconnect(graph, edge.from, port, edge.to)),
          },
          style: mark ? MARK_LINES[mark] : { stroke, strokeWidth: 1.5, strokeDasharray: failing ? '4 3' : undefined },
          markerEnd: { type: MarkerType.ArrowClosed, color: stroke, width: 14, height: 14 },
          ariaLabel: `From ${edge.from} to ${edge.to}${label ? `, ${label}` : ''}${mark ? `, ${mark}` : ''}`,
        }
      }),
    [graph, chosen.edges, readOnly, onChange, marks, dragged],
  )

  const commitDrag = useCallback(() => {
    const positions = draggedRef.current
    draggedRef.current = null
    setDragged(null)
    if (positions) onChange?.(moveNodes(graph, positions))
  }, [graph, onChange])

  // What xyflow reports while the pointer works: positions of a drag, and what is selected.
  const onNodesChange = useCallback(
    (changes) => {
      let moving = null
      let settled = false
      let picked = null
      let measured = null
      for (const change of changes.toArray()) {
        if (change.type === 'dimensions' && change.dimensions) {
          measured ??= {}
          measured[change.id] = { width: change.dimensions.width, height: change.dimensions.height }
          continue
        }
        if (change.type === 'position' && !readOnly) {
          if (change.position) {
            moving ??= {}
            moving[change.id] = change.position
          }
          // A move by the arrow keys has no "drag stop": it is told to the graph at once.
          if (change.dragging === false) settled = true
        } else if (change.type === 'select') {
          picked ??= new Map()
          picked.set(change.id, change.selected)
        }
      }
      if (measured) {
        setSizes((before) => {
          const same = Object.entries(measured).every(
            ([id, size]) => before[id]?.width === size.width && before[id]?.height === size.height,
          )
          return same ? before : { ...before, ...measured }
        })
      }
      if (moving) {
        draggedRef.current = { ...draggedRef.current, ...moving }
        setDragged(draggedRef.current)
      }
      if (settled) commitDrag()
      if (picked) {
        setChosen((before) => {
          const next = new Set(before.nodes)
          for (const [id, on] of picked) {
            if (on) next.add(id)
            else next.delete(id)
          }
          return { ...before, nodes: next }
        })
      }
    },
    [readOnly, commitDrag],
  )

  const onEdgesChange = useCallback((changes) => {
    const picked = changes.toArray().filter((change) => change.type === 'select')
    if (picked.length === 0) return
    setChosen((before) => {
      const next = new Set(before.edges)
      for (const change of picked) {
        if (change.selected) next.add(change.id)
        else next.delete(change.id)
      }
      return { ...before, edges: next }
    })
  }, [])

  // The page learns what is selected after the canvas has settled on it.
  const reported = useRef('')
  useEffect(() => {
    const ids = [...chosen.nodes].filter((id) => graph.nodes.some((node) => node.id === id))
    const key = ids.join('\u0000')
    if (key === reported.current) return
    reported.current = key
    onSelect?.(ids)
  }, [chosen.nodes, graph.nodes, onSelect])

  const onConnect = useCallback(
    ({ source, sourceHandle, target }) => {
      const result = connect(graph, source, sourceHandle, target)
      if (result.problem) onRefused?.(result.problem)
      else onChange?.(result.graph)
    },
    [graph, onChange, onRefused],
  )

  const onDelete = useCallback(
    ({ nodes: goneNodes, edges: goneEdges }) => {
      let next = graph
      for (const edge of goneEdges) {
        const { from, port, to } = edgeParts(edge.id)
        next = disconnect(next, from, port, to)
      }
      next = removeNodes(
        next,
        goneNodes.map((node) => node.id),
      )
      setChosen({ nodes: new Set(), edges: new Set() })
      if (next !== graph) onChange?.(next)
    },
    [graph, onChange],
  )

  const onDrop = useCallback(
    (event) => {
      const id = event.dataTransfer.getData(DRAG_TYPE)
      if (!id) return
      event.preventDefault()
      event.stopPropagation()
      onDropEntry?.(id, flow.screenToFlowPosition({ x: event.clientX, y: event.clientY }))
    },
    [flow, onDropEntry],
  )

  // ---- The menu: a right-click, or the menu key on what has the focus ---------------
  const view = useMemo(() => ({ fit: () => flow.fitView(FIT) }), [flow])
  const menuOfNode = useCallback(
    (event, id) => {
      const among = chosen.nodes.has(id) && chosen.nodes.size > 1
      if (!among) setChosen({ nodes: new Set([id]), edges: new Set() })
      onMenu(event, among ? { kind: 'selection', ids: [...chosen.nodes] } : { kind: 'node', id }, view)
    },
    [chosen.nodes, onMenu, view],
  )
  const menuOfEdge = useCallback(
    (event, id) => {
      setChosen({ nodes: new Set(), edges: new Set([id]) })
      onMenu(event, { kind: 'edge', ...edgeParts(id) }, view)
    },
    [onMenu, view],
  )
  const menuOfPane = useCallback(
    (event) => {
      const position = flow.screenToFlowPosition({ x: event.clientX, y: event.clientY })
      onMenu(event, { kind: 'pane', position }, view)
    },
    [flow, onMenu, view],
  )
  const onMenuKey = useCallback(
    (event) => {
      if (!(event.key === 'ContextMenu' || (event.key === 'F10' && event.shiftKey))) return
      const element = event.target.closest?.('.react-flow__node, .react-flow__edge') ?? event.currentTarget
      const box = element.getBoundingClientRect()
      // What a right-click in the middle of it would have said.
      const asked = {
        clientX: box.left + box.width / 2,
        clientY: box.top + box.height / 2,
        shiftKey: false,
        target: element,
        preventDefault: () => {},
        stopPropagation: () => {},
      }
      event.preventDefault()
      const id = element.getAttribute('data-id')
      if (id && element.classList.contains('react-flow__node')) menuOfNode(asked, id)
      else if (id && element.classList.contains('react-flow__edge')) menuOfEdge(asked, id)
      else if (chosen.nodes.size > 1) onMenu(asked, { kind: 'selection', ids: [...chosen.nodes] }, view)
      else menuOfPane(asked)
    },
    [chosen.nodes, menuOfEdge, menuOfNode, menuOfPane, onMenu, view],
  )
  const menus = onMenu
    ? {
        onNodeContextMenu: (event, node) => menuOfNode(event, node.id),
        onEdgeContextMenu: (event, edge) => menuOfEdge(event, edge.id),
        onPaneContextMenu: (event) => menuOfPane(event),
        onSelectionContextMenu: (event, picked) =>
          onMenu(event, { kind: 'selection', ids: picked.map((node) => node.id) }, view),
      }
    : null

  const drawn = (
    <ReactFlow
      nodes={nodes}
      edges={edges}
      nodeTypes={NODE_TYPES}
      edgeTypes={EDGE_TYPES}
      forceColorMode="dark"
      // A canvas whose page holds where it looks is put there by the page.
      {...(viewport ? { viewport, onViewportChange } : { fitView: true, fitViewOptions: FIT })}
      minZoom={0.2}
      maxZoom={1.5}
      nodesDraggable={!readOnly}
      nodesConnectable={!readOnly}
      edgesReconnectable={false}
      deleteKeyCode={readOnly ? null : ['Backspace', 'Delete']}
      onNodesChange={onNodesChange}
      onEdgesChange={onEdgesChange}
      onNodeDragStop={commitDrag}
      onSelectionDragStop={commitDrag}
      onConnect={onConnect}
      isValidConnection={({ source, sourceHandle, target }) =>
        !readOnly && connectProblem(graph, source, sourceHandle || 'out', target) === null
      }
      onDelete={onDelete}
      onDragOver={(event) => {
        if (readOnly || !Array.from(event.dataTransfer.types).includes(DRAG_TYPE)) return
        event.preventDefault()
        event.dataTransfer.dropEffect = 'copy'
      }}
      onDrop={readOnly ? undefined : onDrop}
      {...menus}
      ariaLabelConfig={{
        'node.a11yDescription.default':
          'Press Enter to select the node; then the arrow keys move it and Delete removes it.',
      }}
    >
      <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#21262d" />
      <Controls showInteractive={false} showFitView={!viewport} position="bottom-left" />
      {/* Two canvases side by side have no room for a map each. */}
      {!viewport && <PlaybookMap />}
    </ReactFlow>
  )
  return onMenu ? (
    <div className="h-full w-full" onKeyDown={onMenuKey}>
      {drawn}
    </div>
  ) : (
    drawn
  )
}

function PlaybookMap() {
  return (
    <MiniMap
      pannable
      zoomable
      position="bottom-right"
      bgColor="#010409"
      maskColor="rgba(13, 17, 23, 0.7)"
      nodeColor="#30363d"
      nodeStrokeColor="#6e7681"
      nodeBorderRadius={0}
      ariaLabel="Map of the playbook"
    />
  )
}

/**
 * @param {{
 *   graph: { nodes: object[], edges: object[] },
 *   catalog: object[],                               // the library's entries
 *   problems?: Array<{ node: string | null }>,       // what keeps the draft from being a version
 *   statuses?: Record<string, string> | null,        // a run: node id → status
 *   approvalDefault?: boolean,
 *   readOnly?: boolean,
 *   plain?: boolean,                                 // nodes by kind and `node.summary`, without the library
 *   marks?: { nodes: object, edges: object } | null, // a side of a comparison: id → added, removed, changed
 *   viewport?: { x: number, y: number, zoom: number }, // where the canvas looks, held by the page…
 *   onViewportChange?: (viewport: object) => void,   // …which is told when it is panned or zoomed
 *   selection?: { ids: string[] } | null,            // set by the page to select nodes
 *   onSelect?: (ids: string[]) => void,
 *   onChange?: (graph: object) => void,
 *   onDropEntry?: (entryId: string, position: { x: number, y: number }) => void,
 *   onRefused?: (why: string) => void,               // an edge that cannot be drawn
 *   onMenu?: (event: object, target: object, view: { fit: () => void }) => void,
 *       // a right-click (or the menu key): target is { kind: 'node', id }, { kind: 'selection', ids },
 *       // { kind: 'edge', from, port, to } or { kind: 'pane', position }; without it, the browser's menu
 * }} props
 */
export default function Canvas(props) {
  return (
    <div className="nik-flow h-full min-h-0 w-full" data-testid="playbook-canvas">
      <ReactFlowProvider>
        <Flow {...props} />
      </ReactFlowProvider>
    </div>
  )
}
