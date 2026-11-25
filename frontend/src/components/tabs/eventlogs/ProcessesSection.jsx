import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { ChevronDown, ChevronRight, RefreshCw, X } from 'lucide-react'
import { Button, DateTimeRangeFilter, EmptyState, Select, Wait, tabId } from '../../ui/index.js'
import LevelBadge from '../../evidence/LevelBadge.jsx'
import SourceViewer from '../../evidence/SourceViewer.jsx'
import { LevelFilter } from '../../evidence/DetectionControls.jsx'
import { FilterInput } from '../../evidence/hostTable.jsx'
import ProcessDetail from './ProcessDetail.jsx'
import { sourceOfRecord } from '../../../domain/eventLogSources.js'
import {
  PAGE,
  ROOTS,
  apiFilters,
  breadcrumb,
  childrenText,
  commandPreview,
  createCache,
  flatten,
  freshNode,
  hostLine,
  isFiltered,
  nameOf,
  navigate,
  ranText,
  seedFromTree,
  withPage,
} from '../../../domain/processTree.js'
import { formatDateTime } from '../../../lib/time.js'
import { evidence } from '../../../services/api.js'

/*
 * "Processes" of the event logs: the processes the logs show started (Sysmon 1, Security 4688, auditd), as a
 * tree per host. Nothing here ever holds more than a page of the roots or of one node's children, and no
 * count is made in the browser: the tree opens a node when asked (`parentId`), and a filter turns it into a flat
 * list in which each row shows its ancestors as a breadcrumb (asked for the rows in view only) and can be
 * shown in the tree again. The rules of the tree are in domain/processTree.js.
 */

const EMPTY_TREE = { nodes: {}, open: new Set() }
const EMPTY_FLAT = { items: [], next: null, count: null, capped: false, loading: false, error: '' }
const COLUMNS =
  'grid grid-cols-[10rem_5.5rem_minmax(11rem,18rem)_minmax(8rem,1fr)_7rem_3.5rem_5rem_5.5rem] items-center gap-x-3'
const MOVE_KEYS = ['ArrowDown', 'ArrowUp', 'ArrowLeft', 'ArrowRight', 'Home', 'End']
const LEVEL_ROW = {
  5: 'border-l-high-line bg-high-soft/40',
  4: 'border-l-high-line bg-high-soft/40',
  3: 'border-l-med-line bg-med-soft/40',
}

const Cell = ({ children, title, className = '' }) => (
  <span title={title} className={`min-w-0 truncate font-mono text-xs ${className}`}>
    {children}
  </span>
)

/** The columns of a process, the same in the tree and in the flat list (`lead` is what goes before the name). */
function ProcessCells({ process, lead = null, below = null }) {
  return (
    <>
      <Cell className="whitespace-nowrap text-fg-muted">
        {Number.isFinite(process.startTs) ? formatDateTime(process.startTs) : '—'}
      </Cell>
      <span className="min-w-0">
        <LevelBadge level={process.level} />
      </span>
      <span className="flex min-w-0 items-center" title={process.image}>
        {lead}
        <span className="min-w-0 truncate font-mono text-xs font-semibold text-fg">{nameOf(process)}</span>
        {process.detections > 0 && (
          <span
            className="ml-1.5 shrink-0 font-mono text-[10px] text-med-fg"
            title={`${process.detections} detection${process.detections === 1 ? '' : 's'} on this process`}
          >
            ·{process.detections}
          </span>
        )}
      </span>
      <span className="min-w-0">
        <Cell title={process.commandLine} className="block text-fg-muted">
          {commandPreview(process.commandLine) || '—'}
        </Cell>
        {below}
      </span>
      <Cell title={process.user} className="text-fg">
        {process.user || '—'}
      </Cell>
      <Cell className="text-fg-muted">{process.pid ?? '—'}</Cell>
      <Cell className="text-fg-muted">{ranText(process.startTs, process.endTs) || '—'}</Cell>
      <Cell className="text-fg-muted">{childrenText(process.children) || '—'}</Cell>
    </>
  )
}

const HEADER = ['Started', 'Detection', 'Process', 'Command line', 'User', 'PID', 'Ran', 'Children']

function Header() {
  return (
    <div
      role="presentation"
      className={`${COLUMNS} sticky top-0 z-10 border-b border-line bg-panel px-3 py-2 font-mono text-xs text-fg-muted`}
    >
      {HEADER.map((label) => (
        <span key={label}>{label}</span>
      ))}
    </div>
  )
}

/** The ancestors of a row of the flat list, asked for when the row comes into view (and kept in a small cache). */
function Ancestors({ incidentId, process, cache, pending }) {
  const ref = useRef(null)
  const [names, setNames] = useState(() => cache.get(process.id) ?? null)
  useEffect(() => {
    if (names) return undefined
    // The row decides, not the cell: its cell may be scrolled away to the right while the row is on screen.
    const node = ref.current?.closest('li') ?? ref.current
    let gone = false
    const ask = () => {
      if (cache.has(process.id)) return setNames(cache.get(process.id))
      let job = pending.get(process.id)
      if (!job) {
        job = evidence
          .processTree(incidentId, process.id, { up: 16, down: 0 })
          .then((answer) => breadcrumb(answer.ancestors, answer.ghost))
          .catch(() => [])
          .finally(() => pending.delete(process.id))
        pending.set(process.id, job)
      }
      job.then((found) => {
        cache.set(process.id, found)
        if (!gone) setNames(found)
      })
    }
    if (typeof IntersectionObserver === 'undefined' || !node) {
      ask()
      return undefined
    }
    const watcher = new IntersectionObserver((entries) => {
      if (entries.some((entry) => entry.isIntersecting)) {
        watcher.disconnect()
        ask()
      }
    })
    watcher.observe(node)
    return () => {
      gone = true
      watcher.disconnect()
    }
  }, [incidentId, process.id, names, cache, pending])
  return (
    <span ref={ref} className="block min-h-4 min-w-0 truncate font-mono text-[11px] text-fg-subtle">
      {names === null ? ' ' : names.length === 0 ? 'No ancestor in the evidence' : `${names.join(' › ')} ›`}
    </span>
  )
}

/**
 * @param {{ incident: object, sources: object[], reload: number, group?: string }} props
 * `sources`: the files of the section, to open the original behind a process; `reload` changes when files were
 * added or read again; `group` is the `idPrefix` of the page's tabs (for the label of the panel).
 */
export default function ProcessesSection({ incident, sources, reload, group = 'eventlogs' }) {
  const [hosts, setHosts] = useState({ loading: true, items: [], cut: false, error: '' })
  const [host, setHost] = useState('')
  const [filters, setFilters] = useState({})
  const [again, setAgain] = useState(0)
  const [tree, setTree] = useState(EMPTY_TREE)
  const [rootCount, setRootCount] = useState({ count: null, capped: false })
  const [flat, setFlat] = useState(EMPTY_FLAT)
  const [selected, setSelected] = useState(null)
  const [focusKey, setFocusKey] = useState('')
  const [viewing, setViewing] = useState(null)
  const treeRef = useRef(tree)
  const epoch = useRef(0)
  const flatEpoch = useRef(0) // the flat list's own: a filter must not cancel what the tree is reading
  const rowRefs = useRef(new Map())
  const byKeyboard = useRef(false)
  const cache = useMemo(() => createCache(300), [])
  const pending = useMemo(() => new Map(), [])
  const filtered = isFiltered(filters)

  // The hosts that have processes; the busiest first is chosen until someone chooses.
  useEffect(() => {
    const controller = new AbortController()
    evidence
      .processHosts(incident.id, { signal: controller.signal })
      .then((answer) => {
        setHosts({ loading: false, items: answer.hosts ?? [], cut: Boolean(answer.cut), error: '' })
        setHost((chosen) =>
          (answer.hosts ?? []).some((item) => item.host === chosen) ? chosen : (answer.hosts?.[0]?.host ?? ''),
        )
      })
      .catch((failure) => {
        if (failure?.name !== 'AbortError') {
          setHosts({ loading: false, items: [], cut: false, error: failure?.message || 'The hosts were not read.' })
        }
      })
    return () => controller.abort()
  }, [incident.id, reload, again])

  const setTreeNow = useCallback((next) => {
    treeRef.current = next
    setTree(next)
  }, [])
  const patchNode = useCallback((key, change) => {
    const next = { ...treeRef.current, nodes: { ...treeRef.current.nodes, [key]: change } }
    treeRef.current = next
    setTree(next)
  }, [])

  /** Load the first page of a node (the roots, or the children of a process), or the page that follows. */
  const loadNode = useCallback(
    (key, { first = false } = {}) => {
      const held = treeRef.current.nodes[key] ?? freshNode()
      if (held.loading) return
      const mine = epoch.current
      const cursor = first ? '' : (held.next ?? '')
      patchNode(key, { ...held, loading: true, error: '' })
      const asked = key === ROOTS ? { host, roots: true } : { parentId: key }
      evidence
        .processes(incident.id, { filters: asked, order: 'time', limit: PAGE, cursor })
        .then((page) => {
          if (mine !== epoch.current) return
          if (key === ROOTS && cursor === '')
            setRootCount({ count: page.count ?? null, capped: Boolean(page.countCapped) })
          patchNode(key, withPage(treeRef.current.nodes[key], page))
        })
        .catch((failure) => {
          if (mine !== epoch.current) return
          patchNode(key, {
            ...treeRef.current.nodes[key],
            loading: false,
            error: failure?.message || 'The processes were not read.',
          })
        })
    },
    [incident.id, host, patchNode],
  )

  // Another host, new files or a refresh: the tree starts again from the roots.
  useEffect(() => {
    epoch.current += 1
    setTreeNow(EMPTY_TREE)
    setSelected(null)
    setFocusKey('')
    setRootCount({ count: null, capped: false })
    if (host) loadNode(ROOTS, { first: true })
    // eslint-disable-next-line react-hooks/exhaustive-deps -- only the host and the reloads restart the tree
  }, [host, reload, again, incident.id])

  // The flat list of a filter.
  const loadFlat = useCallback(
    (cursor = '', held = EMPTY_FLAT) => {
      const mine = flatEpoch.current
      setFlat({ ...held, loading: true, error: '' })
      evidence
        .processes(incident.id, { filters: apiFilters(host, filters), order: 'time', limit: PAGE, cursor })
        .then((page) => {
          if (mine !== flatEpoch.current) return
          setFlat({
            items: [...held.items, ...(page.processes ?? [])],
            next: page.next ?? null,
            count: cursor ? held.count : (page.count ?? null),
            capped: cursor ? held.capped : Boolean(page.countCapped),
            loading: false,
            error: '',
          })
        })
        .catch((failure) => {
          if (mine !== flatEpoch.current) return
          setFlat({ ...held, loading: false, error: failure?.message || 'The processes were not read.' })
        })
    },
    [incident.id, host, filters],
  )
  useEffect(() => {
    if (!filtered || !host) return undefined
    flatEpoch.current += 1 // an answer of the earlier filters must not land
    loadFlat()
    return () => {
      flatEpoch.current += 1
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the filters and the host restart the list
  }, [filtered, host, filters, reload, again, incident.id])

  const rows = useMemo(() => flatten(tree), [tree])
  const focusIndex = Math.max(
    0,
    rows.findIndex((row) => row.key === focusKey),
  )

  useEffect(() => {
    if (!byKeyboard.current) return
    byKeyboard.current = false
    rowRefs.current.get(rows[focusIndex]?.key)?.focus()
  }, [focusIndex, rows])

  const toggle = useCallback(
    (process, open) => {
      const next = new Set(treeRef.current.open)
      if (open) next.add(process.id)
      else next.delete(process.id)
      setTreeNow({ ...treeRef.current, open: next })
      const node = treeRef.current.nodes[process.id]
      if (open && (!node || (!node.loaded && !node.loading && !node.partial))) loadNode(process.id, { first: true })
    },
    [loadNode, setTreeNow],
  )

  const choose = useCallback((process) => {
    setSelected(process)
  }, [])

  const showInTree = useCallback(
    async (process) => {
      try {
        const answer = await evidence.processTree(incident.id, process.id, { up: 64, down: 0 })
        epoch.current += 1
        setFilters({})
        setTreeNow(seedFromTree(answer))
        setSelected(answer.node)
        setFocusKey(`p:${answer.node.id}`)
        byKeyboard.current = true
      } catch {
        // The row stays where it is: nothing was changed.
      }
    },
    [incident.id, setTreeNow],
  )

  const onKeyDown = (event) => {
    const row = rows[focusIndex]
    if (!row) return
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      if (row.kind === 'process') choose(row.process)
      else if (row.kind === 'more' && !row.loading) loadNode(row.node, { first: row.partial })
      return
    }
    if (!MOVE_KEYS.includes(event.key)) return
    event.preventDefault()
    const { index, action } = navigate(rows, focusIndex, event.key)
    if (action) toggle(row.process, action === 'open')
    byKeyboard.current = true
    setFocusKey(rows[index].key)
  }

  const setFilter = (name, value) => setFilters((before) => ({ ...before, [name]: value }))
  const current = hosts.items.find((item) => item.host === host)

  if (hosts.loading) return <Wait>Reading the processes…</Wait>
  if (hosts.error) {
    return <EmptyState skull="error" compact title="Unable to read the processes" message={hosts.error} />
  }
  if (hosts.items.length === 0) {
    return (
      <EmptyState
        skull
        compact
        title="No processes yet"
        message="They come from process creations in the logs (Sysmon 1, Security 4688 with its command line, auditd execve). A file read by an older parser is offered to be analysed again in its row above."
        action={
          <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => setAgain((n) => n + 1)}>
            Refresh
          </Button>
        }
      />
    )
  }

  const hostOptions = hosts.items.map((item) => ({ value: item.host, label: hostLine(item) }))

  return (
    <div role="tabpanel" aria-labelledby={tabId(group, 'processes')} className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <Select label="Host" value={host} onChange={setHost} options={hostOptions} />
        {current && (
          <p className="m-0 flex flex-wrap items-center gap-x-3 gap-y-1 font-mono text-xs text-fg-muted">
            <span>
              {Number.isFinite(current.firstTs) ? formatDateTime(current.firstTs) : '—'} →{' '}
              {Number.isFinite(current.lastTs) ? formatDateTime(current.lastTs) : '—'}
            </span>
            <span>
              {current.detections > 0
                ? `${current.detections.toLocaleString('en-US')} matched by chain rules`
                : 'no chain rule matched'}
            </span>
            <LevelBadge level={current.level} />
          </p>
        )}
        {hosts.cut && <span className="text-xs text-fg-muted">The busiest 1,000 hosts are listed.</span>}
        <Button
          variant="ghost"
          size="xs"
          icon={RefreshCw}
          className="ml-auto"
          title="Read the hosts and the tree again (a file may have been linked since)"
          onClick={() => setAgain((n) => n + 1)}
        >
          Refresh
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <FilterInput
          label="Image or command"
          width="w-52"
          value={filters.q ?? ''}
          onCommit={(value) => setFilter('q', value)}
        />
        <FilterInput label="User" value={filters.user ?? ''} onCommit={(value) => setFilter('user', value)} />
        <LevelFilter filters={filters} onChange={(value) => setFilter('level', value)} />
        <DateTimeRangeFilter
          start={filters.from || null}
          end={filters.to || null}
          onChange={({ start, end }) => setFilters((before) => ({ ...before, from: start ?? '', to: end ?? '' }))}
        />
        {filtered && (
          <Button variant="ghost" size="xs" icon={X} onClick={() => setFilters({})}>
            Clear the filters
          </Button>
        )}
      </div>

      <p className="m-0 text-xs text-fg-muted" aria-live="polite">
        {filtered
          ? flat.count === null
            ? 'Matching processes of this host, by start time.'
            : `${flat.count.toLocaleString('en-US')}${flat.capped ? '+' : ''} matching processes of this host, by start time. Each row shows its ancestors.`
          : rootCount.count === null
            ? 'The tree of this host: the roots first, a node opens its children.'
            : `${rootCount.count.toLocaleString('en-US')}${rootCount.capped ? '+' : ''} roots (processes whose parent is not in the evidence). Open a node to read its children.`}
      </p>

      <div className={`grid gap-3 ${selected ? 'xl:grid-cols-[minmax(0,1fr)_26rem]' : ''}`}>
        <div className="min-w-0 border border-line bg-canvas">
          <div className="max-h-[70vh] overflow-auto">
            <div className="min-w-[62rem]">
              <Header />
              {filtered ? (
                <ul aria-label="Processes that match" className="m-0 list-none p-0">
                  {flat.items.map((process) => (
                    <li key={process.id} className="border-b border-line-soft">
                      <button
                        type="button"
                        aria-pressed={selected?.id === process.id}
                        onClick={() => choose(process)}
                        className={`${COLUMNS} w-full border-l-2 px-3 py-1.5 text-left hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${selected?.id === process.id ? 'bg-accent-soft border-l-accent-strong' : (LEVEL_ROW[process.level] ?? 'border-l-transparent')}`}
                      >
                        <ProcessCells
                          process={process}
                          below={
                            <Ancestors incidentId={incident.id} process={process} cache={cache} pending={pending} />
                          }
                        />
                      </button>
                      <div className="px-3 pb-1">
                        <button
                          type="button"
                          onClick={() => showInTree(process)}
                          className="text-xs text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          Show in the tree
                        </button>
                      </div>
                    </li>
                  ))}
                  {flat.loading && (
                    <li className="p-3">
                      <Wait>Reading the processes…</Wait>
                    </li>
                  )}
                  {flat.error && (
                    <li role="alert" className="p-3 text-sm text-high-fg">
                      {flat.error}
                    </li>
                  )}
                  {!flat.loading && !flat.error && flat.items.length === 0 && (
                    <li className="p-6 text-center font-mono text-sm text-fg-muted">No process matches the filters</li>
                  )}
                  {flat.next && !flat.loading && (
                    <li className="p-2">
                      <Button variant="secondary" size="xs" onClick={() => loadFlat(flat.next, flat)}>
                        Show more
                      </Button>
                    </li>
                  )}
                </ul>
              ) : (
                <div
                  role="tree"
                  aria-label={`Processes of ${host || 'the host'}`}
                  onKeyDown={onKeyDown}
                  className="py-0.5"
                >
                  {rows.map((row, index) => {
                    const tabIndex = index === focusIndex ? 0 : -1
                    const register = (node) => {
                      if (node) rowRefs.current.set(row.key, node)
                      else rowRefs.current.delete(row.key)
                    }
                    const lead = { paddingLeft: `${row.depth * 18}px` }
                    if (row.kind === 'ghost') {
                      return (
                        <div
                          key={row.key}
                          ref={register}
                          role="treeitem"
                          aria-level={row.depth + 1}
                          aria-disabled="true"
                          aria-selected="false"
                          tabIndex={tabIndex}
                          onFocus={() => setFocusKey(row.key)}
                          title={[row.ghost.image, row.ghost.commandLine].filter(Boolean).join('\n')}
                          className="flex items-center gap-2 border-b border-line-soft px-3 py-1 font-mono text-xs italic text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
                          style={lead}
                        >
                          <span className="w-4 shrink-0" aria-hidden="true" />
                          {nameOf({ image: row.ghost.image })} · not in the evidence
                        </div>
                      )
                    }
                    if (row.kind === 'more' || row.kind === 'wait' || row.kind === 'error') {
                      return (
                        <div
                          key={row.key}
                          ref={register}
                          role="treeitem"
                          aria-level={row.depth + 1}
                          aria-selected="false"
                          tabIndex={tabIndex}
                          onFocus={() => setFocusKey(row.key)}
                          className="border-b border-line-soft px-3 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
                          style={lead}
                        >
                          {row.kind === 'wait' && <Wait>Reading…</Wait>}
                          {row.kind === 'error' && (
                            <span role="alert" className="text-high-fg">
                              {row.message}
                            </span>
                          )}
                          {row.kind === 'more' && (
                            <Button
                              variant="secondary"
                              size="xs"
                              tabIndex={-1}
                              disabled={row.loading}
                              onClick={() => loadNode(row.node, { first: row.partial })}
                            >
                              {row.partial ? 'Show all' : 'Show more'}
                            </Button>
                          )}
                        </div>
                      )
                    }
                    const { process } = row
                    const on = selected?.id === process.id
                    return (
                      <div
                        key={row.key}
                        ref={register}
                        role="treeitem"
                        aria-level={row.depth + 1}
                        aria-expanded={row.expandable ? row.open : undefined}
                        aria-selected={on}
                        tabIndex={tabIndex}
                        onFocus={() => setFocusKey(row.key)}
                        onClick={() => choose(process)}
                        className={`${COLUMNS} cursor-pointer border-b border-l-2 border-b-line-soft px-3 py-1.5 hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${on ? 'bg-accent-soft border-l-accent-strong' : (LEVEL_ROW[process.level] ?? 'border-l-transparent')}`}
                      >
                        <ProcessCells
                          process={process}
                          lead={
                            <span className="flex shrink-0 items-center" style={lead}>
                              {row.expandable ? (
                                <button
                                  type="button"
                                  tabIndex={-1}
                                  aria-label={`${row.open ? 'Close' : 'Open'} the children of ${nameOf(process)}`}
                                  onClick={(event) => {
                                    event.stopPropagation()
                                    toggle(process, !row.open)
                                  }}
                                  className="mr-1 p-0.5 text-fg-muted hover:text-fg"
                                >
                                  {row.open ? (
                                    <ChevronDown className="h-3.5 w-3.5" aria-hidden="true" />
                                  ) : (
                                    <ChevronRight className="h-3.5 w-3.5" aria-hidden="true" />
                                  )}
                                </button>
                              ) : (
                                <span className="mr-1 inline-block w-5" aria-hidden="true" />
                              )}
                            </span>
                          }
                        />
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        </div>
        {selected && (
          <ProcessDetail
            incidentId={incident.id}
            process={selected}
            onClose={() => setSelected(null)}
            onSelect={choose}
            onOpenEvent={setViewing}
            onShowInTree={showInTree}
          />
        )}
      </div>

      {viewing && (
        <SourceViewer
          incidentId={incident.id}
          source={sourceOfRecord(viewing, sources) ?? { id: viewing.sourceId, fileName: '' }}
          record={{ id: viewing.recordId }}
          onClose={() => setViewing(null)}
        />
      )}
    </div>
  )
}
