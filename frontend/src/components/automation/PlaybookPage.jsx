import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ArrowLeft, Bug, GitBranch, GitCompareArrows, LayoutGrid, List, Play, Redo2, Undo2 } from 'lucide-react'
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
  portName,
  addNode,
  arrange,
  connect,
  copyOf,
  disconnect,
  disconnectNodes,
  edgesFrom,
  historyOf,
  nodeOf,
  normalise,
  paste,
  pasteAt,
  record,
  redo,
  removeNodes,
  sameGraph,
  undo,
} from '../../domain/automation/graph.js'
import { tidy } from '../../domain/automation/layout.js'
import { Badge, Button, EmptyState, Modal } from '../ui/index.js'
import AddNodeDialog from './AddNodeDialog.jsx'
import BranchCompare from './BranchCompare.jsx'
import BranchTree from './BranchTree.jsx'
import Canvas from './Canvas.jsx'
import DebugDialog from './DebugDialog.jsx'
import Inspector from './Inspector.jsx'
import NodeLibrary from './NodeLibrary.jsx'
import PlaybookSettingsTab from './PlaybookSettingsTab.jsx'
import PlaybookVersionsTab from './PlaybookVersionsTab.jsx'
import RunsPage from './RunsPage.jsx'
import { useEditorMenu } from './useEditorMenu.js'
import { Field, Seg, Switch, TextInput } from './fields.jsx'
import { useUnsavedChanges } from '../../lib/unsaved.js'

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
 *
 * What is done to a node, to several, to a line and to the canvas itself is
 * also in a right-click menu (6.4), beside the keys that do the same: Ctrl+C,
 * X, V and D, Ctrl+A, Ctrl+Z, Delete. The menu and the keys call the same
 * functions here. Where nothing can be changed the menu still opens, with what
 * cannot be done greyed and why.
 *
 * A **branch** (5.2) is a copy of the graph somebody works on beside all that:
 * it has an address of its own, saves itself like the draft, and "Push to
 * main" makes it the next version, over the one in use. The draft of main is
 * kept as it was. Graphs are not merged: when the playbook got a newer version
 * since the branch started, the push says so and asks before replacing it.
 * Who edits playbooks sees every branch; who made one (or an admin) changes it.
 *
 * A branch **runs only in the debugger** (6.3): on a branch there is no "Run…"
 * and no switch, and the trigger drawn on it starts nothing until it is
 * pushed. "Debug…" runs the branch as it is saved. "Compare with main" puts
 * main as it is now beside the branch (BranchCompare.jsx), to see what a push
 * would replace before pushing.
 */

const TAB_LABELS = { canvas: 'Canvas', runs: 'Runs', versions: 'Versions', settings: 'Settings' }
const TABS = PLAYBOOK_TABS
const SAVE_DELAY_MS = 900

/** What the line under the name says of the draft, or of the branch, being saved. */
const saveText = (state, what) =>
  ({
    pending: `${what} not saved yet`,
    saving: `saving the ${what}…`,
    saved: `${what} saved`,
    error: `the ${what} was not saved`,
  })[state] ?? ''

/** The same playbook as a table: every node, where it goes, what is to fix. */
function NodeList({ graph, catalog, problems, selected, onSelect, onMenu }) {
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
              <tr
                key={node.id}
                className={on ? 'bg-accent-soft/50' : undefined}
                // The menu the node has on the canvas (nothing of it needs the view).
                onContextMenu={(event) => onMenu(event, { kind: 'node', id: node.id }, { fit: () => {} })}
              >
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
                    .map((edge) => `${portName(node, edge.port)} → ${nodeOf(graph, edge.to)?.name || edge.to}`)
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
 *   branchId?: string | null,     // the branch on the canvas; null for main and its draft
 *   playbooks?: object[],         // every playbook, with its branches: the tree of the side panel
 *   onOpenPlaybook?: (id: string, branch?: string | null, options?: object) => void,
 *   tab: string,
 *   onTab: (tab: string) => void,
 *   onBack: () => void,
 *   onDeleted: () => void,
 *   onChanged?: () => void,   // the list of playbooks should be read again
 *   onOpenRun: (id: string) => void,
 *   onOpenIncident?: (id: string) => void,
 * }} props
 */
export default function PlaybookPage({
  id,
  branchId = null,
  playbooks = [],
  onOpenPlaybook,
  tab,
  onTab,
  onBack,
  onDeleted,
  onChanged,
  onOpenRun,
  onOpenIncident,
}) {
  const { can, currentUser } = useAuth()
  const canEdit = can('automation.edit')
  // The branch on the canvas (null on main), and whether this account may change it.
  const [branch, setBranch] = useState(null)
  const mine = !branchId || !branch || branch.createdBy === currentUser?.username || can('admin')
  const canDraw = canEdit && mine
  const what = branchId ? 'branch' : 'draft'
  const playbookUrl = `/automation/playbooks/${encodeURIComponent(id)}`
  const target = branchId ? `${playbookUrl}/branches/${encodeURIComponent(branchId)}` : playbookUrl
  const [naming, setNaming] = useState(null) // the name of the branch being made
  const [pushing, setPushing] = useState(null) // { note, moved } while "Push to main" asks
  const [removingBranch, setRemovingBranch] = useState(false)
  const [comparing, setComparing] = useState(null) // { main, graph }: the two graphs compared, while that is open
  const [busy, setBusy] = useState(false)
  const { catalog, loadCatalog, askRun } = useAutomation()
  const { showToast } = useToast()
  const [discarding, setDiscarding] = useState(false)

  const [detail, setDetail] = useState(null)
  const [loadError, setLoadError] = useState(null)
  const [history, setHistory] = useState(null)
  const [problems, setProblems] = useState([])
  const [saveState, setSaveState] = useState('idle')
  const [selected, setSelected] = useState([])
  const [selection, setSelection] = useState(null) // what the page asks the canvas to select
  const [listOpen, setListOpen] = useState(false)
  const [savingVersion, setSavingVersion] = useState(false)
  const [debugging, setDebugging] = useState(false)
  const [adding, setAdding] = useState(null) // { position }: "Add a node here…" asks which, for that place
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
    setBranch(null)
    Promise.all([
      api.get(`/automation/playbooks/${encodeURIComponent(id)}`),
      branchId
        ? api.get(`/automation/playbooks/${encodeURIComponent(id)}/branches/${encodeURIComponent(branchId)}`)
        : null,
    ])
      .then(([found, onBranch]) => {
        if (!alive) return
        const shape = normalise(onBranch ? onBranch.graph : (found.draft ?? found.graph))
        savedGraph.current = shape
        setDetail(found)
        setBranch(onBranch)
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
  }, [id, branchId, loadCatalog])

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
        const found = await api.put(target, branchId ? { graph: shape } : { draft: shape })
        savedGraph.current = shape
        if (branchId) setBranch(found)
        else setDetail(found)
        setSaveState(latestGraph.current === shape ? 'saved' : 'pending')
        validate(shape)
      } catch (error) {
        setSaveState('error')
        showToast({ message: `The ${what} was not saved: ${error.message}` })
      }
    },
    [target, branchId, what, showToast, validate],
  )
  useEffect(() => {
    if (!graph || !canDraw || graph === savedGraph.current) return undefined
    setSaveState('pending')
    saveTimer.current = setTimeout(() => {
      saveTimer.current = null
      saveDraft(graph)
    }, SAVE_DELAY_MS)
    return () => clearTimeout(saveTimer.current)
  }, [graph, canDraw, saveDraft])
  // Leaving with a change not saved yet: it is sent on the way out.
  useEffect(
    () => () => {
      const shape = latestGraph.current
      if (canDraw && shape && shape !== savedGraph.current) {
        api.put(target, branchId ? { graph: shape } : { draft: shape }).catch(() => {})
      }
    },
    [target, branchId, canDraw],
  )

  // Nothing unsaved is lost without asking (lib/unsaved.js). Between two saves the canvas is ahead of
  // the server and leaving sends it (above): only the browser's tab closing could lose it. A save the
  // server refused is another matter: it is not sent again by itself, and leaving asks.
  useUnsavedChanges(saveState === 'pending' || saveState === 'saving', {
    what: 'The playbook',
    name: detail?.name,
    sent: true,
  })
  useUnsavedChanges(saveState === 'error', {
    what: `The ${what} of the playbook`,
    name: detail?.name,
    save: () => flush(),
  })
  const namingBranch = useUnsavedChanges(Boolean((naming ?? '').trim()), { what: 'The new branch' })
  const pushingBranch = useUnsavedChanges(Boolean(pushing?.note?.trim()), { what: 'The note of the push to main' })

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
      if (!current || !canDraw) return
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
    [apply, canDraw, refuse, select, selected],
  )

  const tidyUp = useCallback(async () => {
    const current = latestGraph.current
    if (!current) return
    // Where each node goes, and the way each line takes round the nodes it does not join.
    const layout = await tidy(current)
    if (latestGraph.current === current) apply(arrange(current, layout))
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

  // ---- Copy, cut, paste, duplicate: by the keys and by the right-click menu -----------
  const copy = useCallback((ids) => {
    const copied = copyOf(latestGraph.current, ids)
    if (copied.nodes.length) clipboard.current = copied
    return copied
  }, [])

  /** Add what a paste made, unless the playbook would hold too many nodes. True when it was added. */
  const addPasted = useCallback(
    (result) => {
      if (result.ids.length === 0) return false
      if (result.graph.nodes.length > MAX_NODES) {
        refuse(`A playbook has at most ${MAX_NODES} nodes`)
        return false
      }
      apply(result.graph)
      select(result.ids)
      return true
    },
    [apply, refuse, select],
  )

  /** Paste what was copied: beside where it was, or with its first node at `position`. */
  const pasteCopied = useCallback(
    (position = null) => {
      const current = latestGraph.current
      if (!current || !canDraw || !clipboard.current?.nodes.length) return
      if (position) {
        addPasted(pasteAt(current, clipboard.current, position))
        return
      }
      const result = paste(current, clipboard.current)
      // Pasted again, the next copy lands beside this one and not on it.
      if (addPasted(result)) clipboard.current = copyOf(result.graph, result.ids)
    },
    [addPasted, canDraw],
  )

  const duplicate = useCallback(
    (ids) => {
      const current = latestGraph.current
      if (current && canDraw) addPasted(paste(current, copyOf(current, ids)))
    },
    [addPasted, canDraw],
  )

  const cut = useCallback(
    (ids) => {
      if (canDraw && copy(ids).nodes.length) remove(ids)
    },
    [canDraw, copy, remove],
  )

  const selectAll = useCallback(() => select((latestGraph.current?.nodes ?? []).map((node) => node.id)), [select])

  // The keys, when they are not typing into a field. Copy and "select all" change nothing: they
  // work on a canvas that is read-only too.
  useEffect(() => {
    if (activeTab !== 'canvas' || comparing) return undefined
    const onKeyDown = (event) => {
      if (!(event.ctrlKey || event.metaKey) || event.altKey || isTypingTarget(event.target)) return
      if (!wrapper.current?.contains(event.target) && event.target !== document.body) return
      const key = event.key.toLowerCase()
      const textChosen = Boolean(window.getSelection()?.toString())
      if (key === 'a') {
        event.preventDefault()
        selectAll()
      } else if (key === 'c' && selected.length && !textChosen) {
        copy(selected)
      } else if (!canDraw) {
        return
      } else if (key === 'z' || key === 'y') {
        event.preventDefault()
        setHistory((before) => (before ? (key === 'y' || event.shiftKey ? redo(before) : undo(before)) : before))
      } else if (key === 'x' && selected.length && !textChosen) {
        event.preventDefault()
        cut(selected)
      } else if (key === 'd' && selected.length) {
        event.preventDefault()
        duplicate(selected)
      } else if (key === 'v' && clipboard.current?.nodes.length) {
        event.preventDefault()
        pasteCopied()
      }
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [canDraw, activeTab, comparing, selected, copy, cut, duplicate, pasteCopied, selectAll])

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

  /** Throw the draft away: back to the version in use. Asked once, since it cannot be taken back. */
  const discardDraft = async () => {
    setDiscarding(false)
    try {
      await api.del(`/automation/playbooks/${encodeURIComponent(id)}/draft`)
      adopt(await api.get(`/automation/playbooks/${encodeURIComponent(id)}`), { resetGraph: true })
    } catch (failure) {
      setSaveState('error')
      showToast({ message: failure.message })
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

  // ---- Branches ---------------------------------------------------------------------
  /** What is on the canvas, saved now: before a branch is pushed, copied or left. */
  const flush = async () => {
    clearTimeout(saveTimer.current)
    const shape = latestGraph.current
    if (!canDraw || !shape || shape === savedGraph.current) return
    await api.put(target, branchId ? { graph: shape } : { draft: shape })
    savedGraph.current = shape
    setSaveState('saved')
  }

  /** A branch of what is on the canvas: of main with its draft, or of the branch that is open. */
  const makeBranch = async (event) => {
    event.preventDefault()
    setBusy(true)
    try {
      await flush()
      const made = await api.post(
        `${playbookUrl}/branches`,
        branchId ? { name: naming, from: branchId } : { name: naming, graph: latestGraph.current },
      )
      setNaming(null)
      onChanged?.()
      onOpenPlaybook?.(id, made.id)
    } catch (failure) {
      showToast({ message: failure.message })
    } finally {
      setBusy(false)
    }
  }

  /** The branch becomes the next version, over the one in use; `overwrite` after the playbook moved on. */
  const pushBranch = async (overwrite) => {
    setBusy(true)
    try {
      await flush()
      const found = await api.post(`${target}/push`, { note: pushing?.note ?? '', overwrite })
      setDetail(found)
      setBranch((before) => ({ ...before, ...(found.branches ?? []).find((item) => item.id === branchId) }))
      setProblems([])
      setPushing(null)
      setComparing(null)
      showToast({
        message: `Version ${found.version} saved from the branch “${branch?.name}”: it is what runs from now on.`,
      })
      onChanged?.()
    } catch (failure) {
      const found = failure.data?.problems
      if (failure.status === 422 && Array.isArray(found)) {
        setPushing(null)
        // What is to fix is shown on the canvas of the branch.
        setComparing(null)
        setProblems(found)
        const first = found.find((problem) => problem.node)
        select(first ? [first.node] : [])
        showToast({
          message: `${found.length === 1 ? 'One thing' : `${found.length} things`} to fix before this can be pushed.`,
        })
      } else if (failure.status === 409 && failure.data?.moved) {
        setPushing((before) => ({ ...(before ?? { note: '' }), moved: failure.data }))
      } else {
        showToast({ message: failure.message })
      }
    } finally {
      setBusy(false)
    }
  }

  /** Main as it is now beside the branch as it is saved: both are read again, since either may have moved. */
  const openCompare = async () => {
    setBusy(true)
    try {
      await flush()
      const [found, onBranch] = await Promise.all([api.get(playbookUrl), api.get(target)])
      setDetail(found)
      setBranch(onBranch)
      setPushing(null)
      setComparing({ main: normalise(found.graph), graph: normalise(onBranch.graph) })
    } catch (failure) {
      showToast({ message: failure.message })
    } finally {
      setBusy(false)
    }
  }

  const removeBranch = async () => {
    setRemovingBranch(false)
    try {
      clearTimeout(saveTimer.current)
      await api.del(target)
      // Nothing is sent on the way out: the branch is gone.
      savedGraph.current = latestGraph.current
      showToast({ message: `The branch “${branch?.name}” was deleted.` })
      onChanged?.()
      onOpenPlaybook?.(id, null, { replace: true })
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  // ---- The right-click menu of the canvas -------------------------------------------
  const idsOf = (target) => (target.kind === 'node' ? [target.id] : target.ids)
  const canDebug = can('automation.debug') && Boolean(branchId ? branch : detail?.version || detail?.draft)
  const whyReadOnly = canDraw
    ? null
    : !canEdit
      ? 'Your account runs playbooks and does not change them'
      : `This is the branch of ${branch?.createdBy ?? 'somebody else'}: only they, or an admin, change it`
  const onMenu = useEditorMenu(
    () => ({
      graph: latestGraph.current,
      readOnly: whyReadOnly,
      copied: clipboard.current?.nodes.length ?? 0,
      canUndo: (history?.past.length ?? 0) > 0,
      canRedo: (history?.future.length ?? 0) > 0,
      canDebug,
    }),
    {
      open: (target) => {
        select([target.id])
        // The first thing of the inspector that can be changed gets the focus.
        requestAnimationFrame(() =>
          wrapper.current?.querySelector('aside[aria-label="Inspector"] :is(input, textarea, select)')?.focus(),
        )
      },
      debug: (target) => {
        // The nodes selected on the canvas are where a debug run stops.
        select(idsOf(target))
        flush().then(
          () => setDebugging(true),
          (failure) => showToast({ message: failure.message }),
        )
      },
      duplicate: (target) => duplicate(idsOf(target)),
      copy: (target) => copy(idsOf(target)),
      cut: (target) => cut(idsOf(target)),
      disconnect: (target) => apply(disconnectNodes(latestGraph.current, idsOf(target))),
      remove: (target) => remove(idsOf(target)),
      removeLine: (target) => apply(disconnect(latestGraph.current, target.from, target.port, target.to)),
      add: (target) => setAdding({ position: target.position }),
      paste: (target) => pasteCopied(target.position),
      selectAll,
      fit: (_target, view) => view.fit(),
      tidy: tidyUp,
      undo: () => setHistory(undo),
      redo: () => setHistory(redo),
    },
  )

  const draftChanged = useMemo(
    () => Boolean(detail && graph && (!detail.version || !sameGraph(graph, normalise(detail.graph)))),
    [detail, graph],
  )

  if (loadError) {
    return (
      <div className="flex h-full items-center justify-center p-6">
        <EmptyState
          skull="error"
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

  // "Push to main…" asks here: from the editor of the branch, and from the comparison.
  const pushDialog = (
    <Modal
      open={pushing !== null}
      onClose={() => pushingBranch.leave(() => setPushing(null))}
      title={pushing?.moved ? 'The playbook moved on' : `Push “${branch?.name ?? ''}” to main?`}
      footer={
        <>
          <Button variant="secondary" onClick={() => setPushing(null)}>
            Cancel
          </Button>
          {pushing?.moved ? (
            <Button key="over" variant="danger" disabled={busy} onClick={() => pushBranch(true)}>
              Push over it
            </Button>
          ) : (
            <Button waiting={busy} key="push" disabled={busy} onClick={() => pushBranch(false)}>
              {busy ? 'Checking…' : 'Push'}
            </Button>
          )}
        </>
      }
    >
      {pushing?.moved ? (
        <p role="alert" className="text-sm text-fg">
          The playbook is at version {pushing.moved.currentVersion ?? 0} and this branch started from version{' '}
          {pushing.moved.baseVersion ?? 0}. Graphs are not merged: pushing makes the branch version {nextVersion} and
          what was saved since is left in the earlier versions, where it can be restored.
        </p>
      ) : (
        <div className="flex flex-col gap-3">
          <p className="text-sm text-fg">
            The branch is checked and becomes version {nextVersion}: it is what runs from then on. The branch stays, to
            go on from; the draft of main is not touched.
          </p>
          {!comparing && (
            <button
              type="button"
              disabled={busy}
              onClick={openCompare}
              className="self-start text-sm text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              Compare with main first
            </button>
          )}
          <Field label="Note" hint="What changed, for who reads the versions.">
            {(fieldId) => (
              <TextInput
                id={fieldId}
                value={pushing?.note ?? ''}
                maxLength={500}
                onChange={(value) => setPushing((before) => (before ? { ...before, note: value } : before))}
              />
            )}
          </Field>
        </div>
      )}
    </Modal>
  )

  if (comparing && branch) {
    return (
      <div className="flex h-full min-h-0 flex-col">
        <BranchCompare
          playbook={detail}
          branch={branch}
          main={comparing.main}
          graph={comparing.graph}
          catalog={catalog.nodes}
          onBack={() => setComparing(null)}
          onPush={canDraw ? () => setPushing({ note: '', moved: null }) : null}
        />
        {pushDialog}
      </div>
    )
  }

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
              {!branchId && draftChanged && detail.version ? ' · draft changed' : ''}
              {branch && !mine ? ` · ${branch.createdBy}’s branch, read-only` : ''}
              {branch?.behind ? ` · started from version ${branch.baseVersion ?? 0}` : ''}
              {branchId ? ' · runs only in the debugger' : ''}
              {!branchId && canEdit && detail.draft && detail.version ? (
                <>
                  {' · '}
                  <button
                    type="button"
                    onClick={() => setDiscarding(true)}
                    title="Throw the draft away: the playbook is its version in use again"
                    className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    discard the draft
                  </button>
                </>
              ) : null}
              {canDraw && saveText(saveState, what) ? (
                <span role="status" className={saveState === 'error' ? 'text-high-fg' : undefined}>
                  {' '}
                  · {saveText(saveState, what)}
                </span>
              ) : null}
            </p>
          </div>
          {branch && (
            <Badge color="amber">
              <GitBranch size={11} aria-hidden="true" className="mr-1 inline" />
              branch: {branch.name}
            </Badge>
          )}
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
          {/* A branch is not turned on and not run: it is debugged, and pushed when it is ready. */}
          {!branchId && (
            <label className="flex items-center gap-2 text-xs text-fg-muted">
              <Switch
                label={detail.enabled ? 'The playbook is on: turn it off' : 'The playbook is off: turn it on'}
                checked={detail.enabled}
                disabled={!canEdit || (!detail.version && !detail.enabled)}
                onChange={setEnabled}
              />
              {detail.enabled ? 'on' : 'off'}
            </label>
          )}
          {!branchId && (
            <Button
              variant="secondary"
              size="sm"
              icon={Play}
              disabled={!detail.version}
              title={
                detail.version
                  ? 'Run version ' + detail.version + ' by hand, or try it as a dry run'
                  : 'Save a version first: a run uses a version, not the draft'
              }
              onClick={() => askRun({ playbookId: detail.id, dryRun: !detail.triggerConfig?.manual })}
            >
              Run…
            </Button>
          )}
          {can('automation.debug') && (
            <Button
              variant="secondary"
              size="sm"
              icon={Bug}
              disabled={branchId ? !branch : !detail.version && !detail.draft}
              title={
                branchId
                  ? 'A debug run of this branch as it is saved, the only way a branch runs: step through it, change what a node is given, skip a node'
                  : 'A run that stops before its nodes: step through it, change what a node is given, skip a node'
              }
              onClick={() =>
                // The branch is debugged as it is saved: what is on the canvas is saved first.
                flush().then(
                  () => setDebugging(true),
                  (failure) => showToast({ message: failure.message }),
                )
              }
            >
              Debug…
            </Button>
          )}
          {canEdit && branch && (
            <Button
              variant="secondary"
              size="sm"
              icon={GitCompareArrows}
              disabled={busy}
              title="Main as it is now beside this branch: what a push would replace"
              onClick={openCompare}
            >
              Compare with main
            </Button>
          )}
          {canEdit && !branchId && (
            <Button
              waiting={savingVersion}
              size="sm"
              disabled={savingVersion || (!draftChanged && Boolean(detail.version))}
              onClick={saveVersion}
            >
              {savingVersion ? 'Checking…' : `Save as version ${nextVersion}`}
            </Button>
          )}
          {canDraw && branch && (
            <>
              <Button
                variant="secondary"
                size="sm"
                disabled={saveState !== 'pending' && saveState !== 'error'}
                title="A branch saves itself a moment after each change: this saves it now"
                onClick={() => flush().catch((failure) => showToast({ message: failure.message }))}
              >
                Save branch
              </Button>
              <Button
                size="sm"
                disabled={busy}
                title={`Make this branch version ${nextVersion} of the playbook, over the one in use`}
                onClick={() => setPushing({ note: '', moved: null })}
              >
                Push to main…
              </Button>
              <Button
                variant="ghost"
                size="sm"
                title="Delete this branch: main and its versions stay as they are"
                onClick={() => setRemovingBranch(true)}
              >
                Delete branch…
              </Button>
            </>
          )}
        </div>
      </div>

      {debugging && (
        <DebugDialog
          playbook={detail}
          branch={branch}
          breakpoints={selected.filter((nodeId) => nodeId !== 'start')}
          onClose={() => setDebugging(false)}
          onStarted={(runId) => {
            setDebugging(false)
            onOpenRun(runId)
          }}
        />
      )}
      {activeTab === 'canvas' && (
        <div ref={wrapper} className="flex min-h-0 flex-1 flex-col md:flex-row">
          {canEdit && (
            <NodeLibrary
              entries={catalog.nodes}
              disabled={!canDraw}
              onAdd={(entry) => addEntry(entry)}
              header={
                <BranchTree
                  playbooks={playbooks}
                  current={detail}
                  branchId={branchId}
                  onOpen={(playbookId, toBranch) => {
                    if (playbookId !== id || (toBranch ?? null) !== branchId) onOpenPlaybook?.(playbookId, toBranch)
                  }}
                  onNew={() => setNaming('')}
                />
              }
            />
          )}
          <div className="flex min-h-[320px] min-w-0 flex-1 flex-col">
            <div className="flex shrink-0 flex-wrap items-center gap-1 border-b border-line-soft bg-panel px-2 py-1">
              {canDraw && (
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
                {!canDraw && ' · read-only'}
              </span>
            </div>
            <div className="min-h-0 flex-1">
              <Canvas
                graph={graph}
                catalog={catalog.nodes}
                problems={problems}
                approvalDefault={detail.approvalDefault}
                readOnly={!canDraw}
                selection={selection}
                onSelect={setSelected}
                onChange={apply}
                onDropEntry={(entryId, position) => {
                  const entry = catalog.nodes.find((item) => item.id === entryId)
                  if (entry) addEntry(entry, position)
                }}
                onRefused={refuse}
                onMenu={onMenu}
              />
            </div>
            {listOpen && (
              <NodeList
                graph={graph}
                catalog={catalog.nodes}
                problems={problems}
                selected={selected}
                onSelect={(nodeId) => select([nodeId])}
                onMenu={onMenu}
              />
            )}
          </div>
          <Inspector
            graph={graph}
            nodeId={selectedId}
            catalog={catalog.nodes}
            shapes={catalog.shapes}
            events={catalog.events}
            connections={catalog.instances ?? {}}
            playbooks={playbookNames}
            problems={problems}
            updates={detail.updates ?? []}
            approvalDefault={detail.approvalDefault}
            readOnly={!canDraw}
            onGraph={apply}
            onRenamed={(from, to) => select(selected.map((item) => (item === from ? to : item)))}
            onRefused={refuse}
            onSelectNode={(nodeId) => select([nodeId])}
            onRemove={(nodeId) => remove([nodeId])}
          />
        </div>
      )}

      {activeTab === 'runs' && (
        <div className="min-h-0 flex-1 overflow-y-auto">
          <RunsPage playbookId={detail.id} onOpenRun={onOpenRun} onOpenIncident={onOpenIncident} />
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
      <AddNodeDialog
        open={adding !== null}
        entries={catalog.nodes}
        onClose={() => setAdding(null)}
        onAdd={(entry) => addEntry(entry, adding.position)}
      />
      <Modal
        open={discarding}
        onClose={() => setDiscarding(false)}
        title="Discard the draft?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDiscarding(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={discardDraft}>
              Discard
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          What was changed since version {detail?.version} is thrown away, and the playbook is its version in use again.
          A branch keeps work that is not ready: make one first to keep this.
        </p>
      </Modal>
      <Modal
        open={naming !== null}
        onClose={() => namingBranch.leave(() => setNaming(null))}
        title="New branch"
        footer={
          <>
            <Button variant="secondary" onClick={() => setNaming(null)}>
              Cancel
            </Button>
            <Button type="submit" form="form-new-branch" disabled={busy || !(naming ?? '').trim()}>
              Make the branch
            </Button>
          </>
        }
      >
        <form id="form-new-branch" onSubmit={makeBranch} className="flex flex-col gap-3">
          <Field
            label="Name"
            required
            hint={
              branch
                ? `A copy of the branch “${branch.name}”, yours to change.`
                : 'A copy of what is on the canvas, to work on beside main: nothing a run uses changes until it is pushed.'
            }
          >
            {(fieldId) => (
              <TextInput
                id={fieldId}
                value={naming ?? ''}
                maxLength={80}
                autoFocus
                onChange={(value) => setNaming(value)}
              />
            )}
          </Field>
        </form>
      </Modal>
      {pushDialog}
      <Modal
        open={removingBranch}
        onClose={() => setRemovingBranch(false)}
        title="Delete this branch?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setRemovingBranch(false)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={removeBranch}>
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-semibold">{branch?.name}</span> goes with what was drawn on it. The playbook, its draft
          and its versions stay as they are.
        </p>
      </Modal>
    </div>
  )
}
