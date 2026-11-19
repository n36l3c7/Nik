import { useCallback, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { getViewportForBounds } from '@xyflow/react'
import { ArrowLeft, Maximize2 } from 'lucide-react'
import {
  boundsOf,
  changesOf,
  compareGraphs,
  countsOf,
  fieldLabel,
  fieldText,
  marksOf,
} from '../../domain/automation/compare.js'
import { nodeOf } from '../../domain/automation/graph.js'
import { NODE_HEIGHT, NODE_WIDTH } from '../../domain/automation/layout.js'
import { formatRelative } from '../../lib/time.js'
import { Badge, Button } from '../ui/index.js'
import Canvas from './Canvas.jsx'

/*
 * ============================================================================
 * COMPARE — main as it is now beside a branch, before the branch is pushed
 * ============================================================================
 *
 * A push replaces the graph of main with the one of the branch: nothing is
 * merged. This page shows what that replaces. Main is on the left, the branch
 * on the right, both read-only and looking at the same place: panning or
 * zooming one moves the other. What differs (domain/automation/compare.js) is
 * marked on the canvases and listed on the right; choosing a node, on either
 * canvas or in the list, shows what changed in it field by field.
 *
 * A change is told by its sign (+ added, ~ changed, - removed) and by the
 * style of its border (solid, dotted, dashed): the colour only repeats it.
 */

const CAP = 'font-mono text-[11px] uppercase tracking-[0.08em] text-fg-muted'
const COUNT_COLORS = { added: 'emerald', changed: 'amber', removed: 'red', line: 'slate', same: 'slate' }
const SIGN_COLORS = { added: 'text-accent-fg', changed: 'text-med-fg', moved: 'text-med-fg', removed: 'text-high-fg' }
// Chosen in the list instead of a node: what changed in the playbook itself.
const PLAYBOOK = '\u0000playbook'
const START = { x: 0, y: 0, zoom: 1 }

/** One field of a node: its name, then what it was (-) and what it is (+), or that it is the same. */
function FieldRow({ field }) {
  return (
    <div className="py-1">
      <dt className="text-fg-muted">{fieldLabel(field.path)}</dt>
      {field.change === 'same' ? (
        <dd className="break-words text-fg">
          {fieldText(field.after)} <span className="text-fg-muted">· same</span>
        </dd>
      ) : (
        <>
          {field.change !== 'added' && (
            <dd className="break-words text-high-fg">
              <span className="font-semibold">- </span>
              {fieldText(field.before)}
            </dd>
          )}
          {field.change !== 'removed' && (
            <dd className="break-words text-accent-fg">
              <span className="font-semibold">+ </span>
              {fieldText(field.after)}
            </dd>
          )}
        </>
      )}
    </div>
  )
}

/**
 * @param {{
 *   playbook: { name: string, version: number | null },
 *   branch: { name: string, baseVersion: number | null, behind: boolean, updatedAt?: string },
 *   main: object,                     // the graph of the version in use, as it is now
 *   graph: object,                    // the graph of the branch, as it is saved
 *   catalog: object[],                // the library's entries: how nodes are named
 *   onBack: () => void,
 *   onPush?: (() => void) | null,     // absent when this account may not push the branch
 * }} props
 */
export default function BranchCompare({ playbook, branch, main, graph, catalog, onBack, onPush = null }) {
  const diff = useMemo(() => compareGraphs(main, graph), [main, graph])
  const changes = useMemo(() => changesOf(diff, main, graph), [diff, main, graph])
  const marks = useMemo(() => ({ main: marksOf(diff, 'main'), branch: marksOf(diff, 'branch') }), [diff])

  // Where both canvases look. It is worked out once the panes have a size: both graphs fit.
  const pane = useRef(null)
  const [viewport, setViewport] = useState(null)
  const fit = useCallback(() => {
    const bounds = boundsOf([main, graph], NODE_WIDTH, NODE_HEIGHT)
    const { clientWidth: width = 0, clientHeight: height = 0 } = pane.current ?? {}
    setViewport(bounds && width > 0 && height > 0 ? getViewportForBounds(bounds, width, height, 0.2, 1, 0.15) : START)
  }, [main, graph])
  useLayoutEffect(fit, [fit])

  const [chosen, setChosen] = useState(null) // a node id, or PLAYBOOK
  const [selection, setSelection] = useState(null) // what both canvases are asked to select
  const chosenRef = useRef(null)
  const choose = useCallback((id) => {
    chosenRef.current = id
    setChosen(id)
    setSelection({ ids: id && id !== PLAYBOOK ? [id] : [] })
  }, [])

  /** A canvas says what is selected on it. One that lost a node it never had says nothing new. */
  const selected = useCallback(
    (side, ids) => {
      const now = chosenRef.current
      if (ids.length > 0) {
        const id = ids[ids.length - 1]
        if (id !== now) choose(id)
      } else if (now && now !== PLAYBOOK && nodeOf(side, now)) {
        choose(null)
      }
    },
    [choose],
  )
  const onMain = useCallback((ids) => selected(main, ids), [selected, main])
  const onBranch = useCallback((ids) => selected(graph, ids), [selected, graph])

  /** A change of the list: its node is chosen and both canvases go to it. */
  const goTo = (change) => {
    if (!change.node) {
      if (change.key === 'playbook') choose(PLAYBOOK)
      return
    }
    choose(change.node)
    const node = nodeOf(graph, change.node) ?? nodeOf(main, change.node)
    const { clientWidth: width = 0, clientHeight: height = 0 } = pane.current ?? {}
    if (!node?.position || !width || !height) return
    setViewport((before) => {
      const zoom = before?.zoom ?? 1
      return {
        zoom,
        x: width / 2 - (node.position.x + NODE_WIDTH / 2) * zoom,
        y: height / 2 - (node.position.y + NODE_HEIGHT / 2) * zoom,
      }
    })
  }

  const entry = chosen && chosen !== PLAYBOOK ? diff.nodes.find((node) => node.id === chosen) : null
  const chosenNode = chosen && chosen !== PLAYBOOK ? (nodeOf(graph, chosen) ?? nodeOf(main, chosen)) : null
  const fields = chosen === PLAYBOOK ? diff.playbook : (entry?.fields ?? [])
  const version = playbook.version ? `v${playbook.version}` : 'no version yet'

  return (
    <section aria-label="Compare with main" className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-end gap-3 border-b border-line px-4 py-2.5">
        <div className="min-w-0 flex-1">
          <p className={CAP}>Playbook · {playbook.name}</p>
          <h2 className="mt-1 truncate text-base font-semibold text-fg">
            Compare <span className="font-mono">main {version}</span> with the branch{' '}
            <span className="font-mono">{branch.name}</span>
          </h2>
        </div>
        <ul aria-label="What differs" className="flex flex-wrap items-center gap-2">
          {countsOf(diff).map((count) => (
            <li key={count.text}>
              <Badge color={COUNT_COLORS[count.change]}>{count.text}</Badge>
            </li>
          ))}
        </ul>
        <Button variant="secondary" size="sm" icon={ArrowLeft} onClick={onBack}>
          Back to the branch
        </Button>
        {onPush && (
          <Button
            size="sm"
            title={`Make this branch version ${(playbook.version ?? 0) + 1} of the playbook, over the one in use`}
            onClick={onPush}
          >
            Push to main…
          </Button>
        )}
      </div>
      {branch.behind && (
        <p role="note" className="shrink-0 border-b border-med-line bg-med-soft px-4 py-2 text-sm text-med-fg">
          main moved since this branch was made (v{branch.baseVersion ?? 0} to v{playbook.version ?? 0}): the left side
          is main as it is now.
        </p>
      )}
      <div className="flex min-h-0 flex-1 flex-col gap-3 p-3 lg:flex-row">
        <section aria-label="Main" className="flex min-h-[260px] min-w-0 flex-1 flex-col gap-1.5">
          <p className={CAP}>main · {version}</p>
          <div ref={pane} className="min-h-0 flex-1 border border-line">
            {viewport && (
              <Canvas
                graph={main}
                catalog={catalog}
                readOnly
                marks={marks.main}
                viewport={viewport}
                onViewportChange={setViewport}
                selection={selection}
                onSelect={onMain}
              />
            )}
          </div>
        </section>
        <section aria-label="Branch" className="flex min-h-[260px] min-w-0 flex-1 flex-col gap-1.5">
          <p className={CAP}>
            branch · {branch.name}
            {branch.updatedAt ? ` · saved ${formatRelative(branch.updatedAt)}` : ''}
          </p>
          <div className="min-h-0 flex-1 border border-line">
            {viewport && (
              <Canvas
                graph={graph}
                catalog={catalog}
                readOnly
                marks={marks.branch}
                viewport={viewport}
                onViewportChange={setViewport}
                selection={selection}
                onSelect={onBranch}
              />
            )}
          </div>
        </section>
        <aside
          aria-label="Changes"
          className="flex shrink-0 flex-col gap-2.5 overflow-y-auto border border-line bg-panel p-3 lg:w-[330px]"
        >
          <h3 className={CAP}>What changed in the chosen node</h3>
          {chosen === null ? (
            <p className="text-sm text-fg-muted">Choose a node on a canvas, or a change in the list.</p>
          ) : (
            <>
              <p className="text-sm font-semibold text-fg">
                {chosen === PLAYBOOK ? 'Inputs and outputs of the playbook' : chosenNode?.name || chosen}
                {entry && <span className="ml-2 font-mono text-xs font-normal text-fg-muted">{entry.change}</span>}
              </p>
              {fields.length > 0 ? (
                <dl
                  aria-label="Fields of the chosen node"
                  className="divide-y divide-line-soft border border-line bg-canvas px-2.5 py-1 font-mono text-xs"
                >
                  {fields.map((field) => (
                    <FieldRow key={field.path} field={field} />
                  ))}
                </dl>
              ) : (
                <p className="text-sm text-fg-muted">Nothing changed in this node.</p>
              )}
            </>
          )}
          <h3 className={`${CAP} mt-1.5`}>All the changes</h3>
          {changes.length === 0 ? (
            <p className="text-sm text-fg-muted">
              {diff.moved > 0
                ? 'The branch is main with nodes somewhere else on the canvas: a push changes nothing a run does.'
                : 'The branch is what main is: a push changes nothing.'}
            </p>
          ) : (
            <ul aria-label="All the changes" className="flex flex-col gap-1.5 text-xs">
              {changes.map((change) => {
                const sign = (
                  <span aria-hidden="true" className={`mr-1 font-mono font-semibold ${SIGN_COLORS[change.change]}`}>
                    {change.sign}
                  </span>
                )
                const on = (change.node ?? (change.key === 'playbook' ? PLAYBOOK : null)) === chosen && chosen !== null
                return (
                  <li key={change.key}>
                    {change.node || change.key === 'playbook' ? (
                      <button
                        type="button"
                        aria-pressed={on}
                        aria-label={`${change.sign} ${change.text}, ${change.change}`}
                        onClick={() => goTo(change)}
                        className={[
                          'w-full text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                          on ? 'bg-accent-soft/50' : '',
                        ].join(' ')}
                      >
                        {sign}
                        {change.text}
                      </button>
                    ) : (
                      <span className="text-fg">
                        {sign}
                        {change.text}
                      </span>
                    )}
                  </li>
                )
              })}
            </ul>
          )}
          <div className="mt-auto flex flex-col gap-2 pt-2">
            <Button variant="ghost" size="xs" icon={Maximize2} className="self-start" onClick={fit}>
              Show both graphs whole
            </Button>
            <p className="text-xs text-fg-muted">
              The two sides pan and zoom together. A change is told by its sign and its border, not by colour alone.
            </p>
          </div>
        </aside>
      </div>
    </section>
  )
}
