import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowLeft, LayoutGrid, List, Redo2, Undo2 } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { isTypingTarget } from '../../domain/search.js'
import { PLAYBOOK_TABS } from '../../domain/automationNav.js'
import { entryOf, freePosition, headingOf, nodeFrom } from '../../domain/automation/catalog.js'
import {
  DEFAULT_PORT,
  MAX_NODES,
  PORT_NAMES,
  addNode,
  connect,
  copyOf,
  edgesFrom,
  historyOf,
  moveNodes,
  nodeOf,
  normalise,
  paste,
  record,
  redo,
  removeNodes,
  sameGraph,
  undo,
} from '../../domain/automation/graph.js'
import { tidy } from '../../domain/automation/layout.js'
import { AsciiSkull, Badge, Button, EmptyState } from '../ui/index.js'
import Canvas from './Canvas.jsx'
import Inspector from './Inspector.jsx'
import NodeLibrary from './NodeLibrary.jsx'
import PlaybookSettingsTab from './PlaybookSettingsTab.jsx'
import PlaybookVersionsTab from './PlaybookVersionsTab.jsx'
import { Seg, Switch } from './fields.jsx'

/*
 * ============================================================================
 * A PLAYBOOK — its canvas, its versions, its settings
 * ============================================================================
 *
 * The canvas edits a **draft**: every change is saved by itself a moment
 * after it is made, and a draft may be anything. What runs is the last
 * **version**: "Save as version" asks the server to check the draft and, when
 * nothing is wrong, makes it the version triggers use from then on. What is
 * wrong is shown on the nodes and in the inspector.
 *
 * An account that may run playbooks but not build them sees the same canvas,
 * read-only.
 */

const TAB_LABELS = { canvas: 'Canvas', runs: 'Runs', versions: 'Versions', settings: 'Settings' }
// The tabs this release has (the runs of a playbook come with the runs screen).
const TABS = PLAYBOOK_TABS.filter((tab) => tab !== 'runs')
const SAVE_DELAY_MS = 900

const SAVE_TEXT = {
  idle: '',
  pending: 'draft not saved yet',
  saving: 'saving the draft…',
  saved: 'draft saved',
  error: 'the draft was not saved',
}

/** The same playbook as a table: every node, where it goes, what is to fix. */
function NodeList({ graph, catalog, problems, selected, onSelect }) {
  const outgoing = edgesFrom(graph)
  return (
    <div className="max-h-56 shrink-0 overflow-auto border-t border-line bg-panel">
      <table className="w-full min-w-[640px] border-collapse text-left text-xs">
        <caption className="sr-only">The nodes of the playbook</caption>
        <thead className="sticky top-0 bg-panel font-mono text-[11px] text-fg-muted">
          <tr>
            <th scope="col" className="border-b border-line px-3 py-1.5 font-normal">
              Node
            </th>
            <th scope="col" className="border-b border-line px-3 py-1.5 font-normal">
              Kind
            </th>
            <th scope="col" className="border-b border-line px-3 py-1.5 font-normal">
              Goes to
            </th>
            <th scope="col" className="border-b border-line px-3 py-1.5 font-normal">
              To fix
            </th>
          </tr>
        </thead>
        <tbody>
          {graph.nodes.map((node) => {
            const mine = problems.filter((problem) => problem.node === node.id)
            const on = selected.includes(node.id)
            return (
              <tr key={node.id} className={on ? 'bg-accent-soft/50' : undefined}>
                <th scope="row" className="border-b border-line-soft px-3 py-1.5 font-normal">
                  <button
                    type="button"
                    aria-pressed={on}
                    onClick={() => onSelect(node.id)}
                    className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {node.name || node.id}
                  </button>
                  <span className="ml-2 font-mono text-[11px] text-fg-subtle">{node.id}</span>
                </th>
                <td className="border-b border-line-soft px-3 py-1.5 text-fg-muted">
                  {headingOf(node, entryOf(node, catalog))}
                </td>
                <td className="border-b border-line-soft px-3 py-1.5 text-fg-muted">
                  {(outgoing.get(node.id) ?? [])
                    .map((edge) => `${PORT_NAMES[edge.port]} → ${nodeOf(graph, edge.to)?.name || edge.to}`)
                    .join('; ') || '—'}
                </td>
                <td className="border-b border-line-soft px-3 py-1.5 text-high-fg">
                  {mine.map((problem) => problem.message).join('; ')}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

/**
 * @param {{
 *   id: string,
 *   tab: string,
 *   onTab: (tab: string) => void,
 *   onBack: () => void,
 *   onDeleted: () => void,
 *   onChanged?: () => void,   // the list of playbooks should be read again
 * }} props
 */
export default function PlaybookPage({ id, tab, onTab, onBack, onDeleted, onChanged }) {
  const { can } = useAuth()
  const canEdit = can('automation.edit')
  const { catalog, loadCatalog } = useAutomation()
  const { showToast } = useToast()

  const [detail, setDetail] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [history, setHistory] = useState(null)
  const [problems, setProblems] = useState([])
  const [saveState, setSaveState] = useState('idle')
  const [selected, setSelected] = useState([])
  const [selection, setSelection] = useState(null) // what the page asks the canvas to select
  const [listOpen, setListOpen] = useState(false)
  const [savingVersion, setSavingVersion] = useState(false)
  const [playbookNames, setPlaybookNames] = useState([])

  const savedGraph = useRef(null) // the graph the server has as the draft
  const latestGraph = useRef(null)
  const saveTimer = useRef(null)
  const clipboard = useRef(null)
  const wrapper = useRef(null)

  const graph = history?.present ?? null
  latestGraph.current = graph
  const activeTab = TABS.includes(tab) ? tab : 'canvas'

  // ---- Loading --------------------------------------------------------------
  useEffect(() => {
    let alive = true
    setDetail(null)
    setHistory(null)
    setLoadError(null)
    setProblems([])
    setSelected([])
    setSaveState('idle')
    api
      .get(`/automation/playbooks/${encodeURIComponent(id)}`)
      .then((found) => {
        if (!alive) return
        const shape = normalise(found.draft ?? found.graph)
        savedGraph.current = shape
        setDetail(found)
        setHistory(historyOf(shape))
      })
      .catch((error) => alive && setLoadError(error.message))
    loadCatalog({ reload: true }).catch(() => {})
    api
      .get('/automation/playbooks')
      .then(
        (found) =>
          alive &&
          setPlaybookNames(found.playbooks.filter((item) => item.id !== id && item.version).map((item) => item.name)),
      )
      .catch(() => {})
    return () => {
      alive = false
    }
  }, [id, loadCatalog])

  const validate = useCallback(
    async (shape) => {
      if (!canEdit) return
      try {
        const found = await api.post(`/automation/playbooks/${encodeURIComponent(id)}/validate`, { graph: shape })
        if (latestGraph.current === shape) setProblems(found.problems)
      } catch {
        /* the next save asks again */
      }
    },
    [id, canEdit],
  )
  useEffect(() => {
    if (detail && savedGraph.current) validate(savedGraph.current)
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once per playbook loaded
  }, [detail?.id])

  // ---- The draft saves itself ------------------------------------------------
  const saveDraft = useCallback(
    async (shape) => {
      setSaveState('saving')
      try {
        const found = await api.put(`/automation/playbooks/${encodeURIComponent(id)}`, { draft: shape })
        savedGraph.current = shape
        setDetail(found)
        setSaveState(latestGraph.current === shape ? 'saved' : 'pending')
        validate(shape)
      } catch (error) {
        setSaveState('error')
        showToast({ message: `The draft was not saved: ${error.message}` })
      }
    },
    [id, showToast, validate],
  )
  useEffect(() => {
    if (!graph || !canEdit || graph === savedGraph.current) return undefined
    setSaveState('pending')
    saveTimer.current = setTimeout(() => {
      saveTimer.current = null
      saveDraft(graph)
    }, SAVE_DELAY_MS)
    return () => clearTimeout(saveTimer.current)
  }, [graph, canEdit, saveDraft])
  // Leaving with a change not saved yet: it is sent on the way out.
  useEffect(
    () => () => {
      const shape = latestGraph.current
      if (canEdit && shape && shape !== savedGraph.current) {
        api.put(`/automation/playbooks/${encodeURIComponent(id)}`, { draft: shape }).catch(() => {})
      }
    },
    [id, canEdit],
  )

  // ---- Edits ------------------------------------------------------------------
  const apply = useCallback((next) => setHistory((before) => (before ? record(before, next) : before)), [])
  const select = useCallback((ids) => {
    setSelection({ ids })
    setSelected(ids)
  }, [])
  const refuse = useCallback((why) => showToast({ message: why }), [showToast])

  const addEntry = useCallback(
    (entry, position = null) => {
      const current = latestGraph.current
      if (!current || !canEdit) return
      if (current.nodes.length >= MAX_NODES) {
        refuse(`A playbook has at most ${MAX_NODES} nodes`)
        return
      }
      const after = selected.length === 1 ? selected[0] : null
      const node = nodeFrom(entry, current, position ?? freePosition(current, after))
      let next = addNode(current, node)
      // Added with a click while a node is selected: it comes after that node, when its line is free.
      const source = !position && after ? nodeOf(current, after) : null
      if (source) {
        const port = DEFAULT_PORT[source.kind]
        const free = port && !(edgesFrom(current).get(source.id) ?? []).some((edge) => edge.port === port)
        if (free) next = connect(next, source.id, port, node.id).graph
      }
      apply(next)
      select([node.id])
    },
    [apply, canEdit, refuse, select, selected],
  )

  const tidyUp = useCallback(async () => {
    const current = latestGraph.current
    if (!current) return
    const positions = await tidy(current)
    if (latestGraph.current === current) apply(moveNodes(current, positions))
  }, [apply])

  const remove = useCallback(
    (ids) => {
      const current = latestGraph.current
      if (!current) return
      apply(removeNodes(current, ids))
      select([])
    },
    [apply, select],
  )

  // Undo, redo, copy and paste, when the keys are not typing into a field.
  useEffect(() => {
    if (!canEdit || activeTab !== 'canvas') return undefined
    const onKeyDown = (event) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || isTypingTarget(event.target)) return
      if (!wrapper.current?.contains(event.target) && event.target !== document.body) return
      const key = event.key.toLowerCase()
      if (key === 'z' || key === 'y') {
        event.preventDefault()
        setHistory((before) => (before ? (key === 'y' || event.shiftKey ? redo(before) : undo(before)) : before))
      } else if (key === 'c' && selected.length && !window.getSelection()?.toString()) {
        clipboard.current = copyOf(latestGraph.current, selected)
      } else if (key === 'v' && clipboard.current?.nodes.length) {
        event.preventDefault()
        const result = paste(latestGraph.current, clipboard.current)
        clipboard.current = copyOf(result.graph, result.ids)
        apply(result.graph)
        select(result.ids)
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [canEdit, activeTab, selected, apply, select])

  // ---- Versions, on and off ------------------------------------------------------
  const saveVersion = async () => {
    const shape = latestGraph.current
    clearTimeout(saveTimer.current)
    setSavingVersion(true)
    try {
      const found = await api.post(`/automation/playbooks/${encodeURIComponent(id)}/versions`, { graph: shape })
      savedGraph.current = shape
      setDetail(found)
      setProblems([])
      setSaveState('idle')
      showToast({ message: `Version ${found.version} saved: it is what runs from now on.` })
      onChanged?.()
    } catch (error) {
      const found = error.data?.problems
      if (error.status === 422 && Array.isArray(found)) {
        setProblems(found)
        const first = found.find((problem) => problem.node)
        if (first) select([first.node])
        else select([])
        showToast({
          message: `${found.length === 1 ? 'One thing' : `${found.length} things`} to fix before this can be a version.`,
        })
        // The draft is kept as it is.
        if (shape !== savedGraph.current) saveDraft(shape)
      } else {
        showToast({ message: error.message })
      }
    } finally {
      setSavingVersion(false)
    }
  }

  const setEnabled = async (enabled) => {
    try {
      setDetail(await api.put(`/automation/playbooks/${encodeURIComponent(id)}/enabled`, { enabled }))
      onChanged?.()
    } catch (error) {
      showToast({ message: error.message })
    }
  }

  /** A version was restored, or the settings changed: what the server has now. */
  const adopt = useCallback(
    (found, { resetGraph = false } = {}) => {
      setDetail(found)
      if (resetGraph) {
        const shape = normalise(found.draft ?? found.graph)
        savedGraph.current = shape
        setHistory(historyOf(shape))
        setProblems([])
        setSaveState('idle')
        select([])
      }
      onChanged?.()
    },
    [onChanged, select],
  )

  const draftChanged = useMemo(
    () => Boolean(detail && graph && (!detail.version || !sameGraph(graph, normalise(detail.graph)))),
    [detail, graph],
  )

  if (loadError) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <EmptyState
          illustration={<AsciiSkull preset="medium" eyes="x" tone="muted" />}
          title="This playbook cannot be opened"
          message={loadError}
          action={
            <Button icon={ArrowLeft} onClick={onBack}>
              All playbooks
            </Button>
          }
        />
      </div>
    )
  }
  if (!detail || !graph) {
    return (
      <p role="status" className="p-6 font-mono text-sm text-fg-muted">
        Loading the playbook…
      </p>
    )
  }

  const nextVersion = (detail.version ?? 0) + 1
  const selectedId = selected.length === 1 ? selected[0] : null

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-2.5">
        <div className="flex min-w-0 items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            icon={ArrowLeft}
            aria-label="All playbooks"
            title="All playbooks"
            onClick={onBack}
          />
          <div className="min-w-0">
            <h2 className="truncate text-base font-semibold text-fg">{detail.name}</h2>
            <p className="font-mono text-xs text-fg-muted">
              playbook · {detail.version ? `version ${detail.version}` : 'no version yet'}
              {draftChanged && detail.version ? ' · draft changed' : ''}
              {canEdit && SAVE_TEXT[saveState] ? (
                <span role="status" className={saveState === 'error' ? 'text-high-fg' : undefined}>
                  {' '}
                  · {SAVE_TEXT[saveState]}
                </span>
              ) : null}
            </p>
          </div>
          {detail.builtin && <Badge color="cyan">shipped with Nik</Badge>}
          {detail.warnings.includes('any host') && <Badge color="red">any host</Badge>}
          {detail.warnings.includes('data opened') && <Badge color="amber">data opened</Badge>}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <Seg
            label="Parts of the playbook"
            value={activeTab}
            onChange={onTab}
            options={TABS.map((item) => ({ value: item, label: TAB_LABELS[item] }))}
          />
          <label className="flex items-center gap-2 text-xs text-fg-muted">
            <Switch
              label={detail.enabled ? 'The playbook is on: turn it off' : 'The playbook is off: turn it on'}
              checked={detail.enabled}
              disabled={!canEdit || (!detail.version && !detail.enabled)}
              onChange={setEnabled}
            />
            {detail.enabled ? 'on' : 'off'}
          </label>
          {canEdit && (
            <Button
              size="sm"
              disabled={savingVersion || (!draftChanged && Boolean(detail.version))}
              onClick={saveVersion}
            >
              {savingVersion ? 'Checking…' : `Save as version ${nextVersion}`}
            </Button>
          )}
        </div>
      </div>

      {activeTab === 'canvas' && (
        <div ref={wrapper} className="flex min-h-0 flex-1 flex-col md:flex-row">
          {canEdit && <NodeLibrary entries={catalog.nodes} onAdd={(entry) => addEntry(entry)} />}
          <div className="flex min-h-[320px] min-w-0 flex-1 flex-col">
            <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-line-soft bg-panel px-2 py-1">
              {canEdit && (
                <>
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Undo2}
                    disabled={history.past.length === 0}
                    aria-label="Undo"
                    title="Undo (Ctrl+Z)"
                    onClick={() => setHistory(undo)}
                  />
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={Redo2}
                    disabled={history.future.length === 0}
                    aria-label="Redo"
                    title="Redo (Ctrl+Shift+Z)"
                    onClick={() => setHistory(redo)}
                  />
                  <Button
                    variant="ghost"
                    size="xs"
                    icon={LayoutGrid}
                    title="Put the nodes in order, top to bottom"
                    onClick={tidyUp}
                  >
                    Tidy up
                  </Button>
                </>
              )}
              <Button
                variant="ghost"
                size="xs"
                icon={List}
                aria-pressed={listOpen}
                title="The same playbook as a table"
                onClick={() => setListOpen((open) => !open)}
              >
                Node list
              </Button>
              <span className="ml-auto font-mono text-[11px] text-fg-muted">
                {graph.nodes.length} nodes
                {problems.length > 0 && <span className="text-high-fg"> · {problems.length} to fix</span>}
                {!canEdit && ' · read-only'}
              </span>
            </div>
            <div className="min-h-0 flex-1">
              <Canvas
                graph={graph}
                catalog={catalog.nodes}
                problems={problems}
                approvalDefault={detail.approvalDefault}
                readOnly={!canEdit}
                selection={selection}
                onSelect={setSelected}
                onChange={apply}
                onDropEntry={(entryId, position) => {
                  const entry = catalog.nodes.find((item) => item.id === entryId)
                  if (entry) addEntry(entry, position)
                }}
                onRefused={refuse}
              />
            </div>
            {listOpen && (
              <NodeList
                graph={graph}
                catalog={catalog.nodes}
                problems={problems}
                selected={selected}
                onSelect={(nodeId) => select([nodeId])}
              />
            )}
          </div>
          <Inspector
            graph={graph}
            nodeId={selectedId}
            catalog={catalog.nodes}
            events={catalog.events}
            playbooks={playbookNames}
            problems={problems}
            updates={detail.updates ?? []}
            approvalDefault={detail.approvalDefault}
            readOnly={!canEdit}
            onGraph={apply}
            onRenamed={(from, to) => select(selected.map((item) => (item === from ? to : item)))}
            onRefused={refuse}
            onSelectNode={(nodeId) => select([nodeId])}
            onRemove={(nodeId) => remove([nodeId])}
          />
        </div>
      )}

      {activeTab === 'versions' && (
        <div className="min-h-0 flex-1 overflow-y-auto p-6">
          <PlaybookVersionsTab
            playbook={detail}
            canEdit={canEdit}
            onRestored={(found) => adopt(found, { resetGraph: true })}
          />
        </div>
      )}

      {activeTab === 'settings' && (
        <div className="min-h-0 flex-1 overflow-y-auto p-6">
          <PlaybookSettingsTab playbook={detail} canEdit={canEdit} onChanged={adopt} onDeleted={onDeleted} />
        </div>
      )}
    </div>
  )
}
