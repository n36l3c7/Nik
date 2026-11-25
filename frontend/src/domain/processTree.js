/*
 * The process tree of the Processes page (components/tabs/eventlogs/ProcessesSection.jsx): the rules that
 * turn the pages the server gave into the rows on screen. A host can hold 300,000 processes, so the tree
 * is never loaded whole: the roots come a page at a time, the children of a node come when it is opened,
 * and what is drawn is only what was loaded and opened. Every function here is pure.
 *
 * The state: `{ nodes, open }`. `nodes` maps a node key (`ROOTS`, or the id of a process) to
 * `{ items, next, loading, error, partial }`: the processes loaded under it, the cursor of the page that
 * follows (null at the end), and `partial` when the list was seeded by "Show in the tree" and is not the
 * whole list of children. `open` is the set of the ids of the processes shown open.
 */

export const ROOTS = 'roots'
export const PAGE = 100
export const FILTER_NAMES = ['q', 'user', 'level', 'from', 'to']

const number = (n) => n.toLocaleString('en-US')

/** A node with nothing loaded yet. */
export const freshNode = () => ({ items: [], next: null, loading: false, error: '', partial: false, loaded: false })

/** The node after a page arrived: the items are added to the ones held, a process once (a page can overlap a seed). */
export function withPage(node, page) {
  const held = node?.items ?? []
  const seen = new Set(held.map((item) => item.id))
  const added = (page.processes ?? []).filter((item) => !seen.has(item.id))
  return {
    items: [...held, ...added],
    next: page.next ?? null,
    loading: false,
    error: '',
    partial: false,
    loaded: true,
  }
}

/**
 * The rows of the tree on screen, in order: `{ kind: 'process', key, process, depth, open, expandable }`, a greyed
 * `{ kind: 'ghost', key, depth, ghost }` above a process whose parent the evidence does not hold, a
 * `{ kind: 'more', key, node, depth, partial, loading }` where a list has more to load, and `{ kind: 'wait' | 'error' }`.
 */
export function flatten(state, root = ROOTS) {
  const rows = []
  const walk = (key, depth) => {
    const node = state.nodes[key]
    if (!node) return
    for (const process of node.items) {
      let at = depth
      if (key === ROOTS && process.parentId == null && process.parent) {
        rows.push({ kind: 'ghost', key: `ghost:${process.id}`, depth, ghost: process.parent })
        at = depth + 1
      }
      const open = state.open.has(process.id)
      rows.push({
        kind: 'process',
        key: `p:${process.id}`,
        process,
        depth: at,
        open,
        expandable: process.children > 0,
      })
      if (open) walk(process.id, at + 1)
    }
    if (node.loading && node.items.length === 0) rows.push({ kind: 'wait', key: `wait:${key}`, depth })
    else if (node.error) rows.push({ kind: 'error', key: `error:${key}`, depth, message: node.error })
    else if (node.next || node.partial) {
      rows.push({ kind: 'more', key: `more:${key}`, node: key, depth, partial: node.partial, loading: node.loading })
    }
  }
  walk(root, 0)
  return rows
}

/**
 * Where a key moves the focus among the rows, and what it does to the node: `{ index, action }` with `action`
 * `'open'` or `'close'` (of the process in the row at `index`) or null. The tree keys of the WAI-ARIA pattern:
 * arrows up and down, Home and End; Right opens a closed node, or goes to its first child; Left closes an
 * open node, or goes to its parent.
 */
export function navigate(rows, index, key) {
  const last = rows.length - 1
  const row = rows[index]
  if (!row || last < 0) return { index: Math.max(0, Math.min(index, last)), action: null }
  if (key === 'ArrowDown') return { index: Math.min(index + 1, last), action: null }
  if (key === 'ArrowUp') return { index: Math.max(index - 1, 0), action: null }
  if (key === 'Home') return { index: 0, action: null }
  if (key === 'End') return { index: last, action: null }
  if (key === 'ArrowRight' && row.kind === 'process') {
    if (row.expandable && !row.open) return { index, action: 'open' }
    const next = rows[index + 1]
    return { index: row.open && next && next.depth > row.depth ? index + 1 : index, action: null }
  }
  if (key === 'ArrowLeft') {
    if (row.kind === 'process' && row.open) return { index, action: 'close' }
    for (let at = index - 1; at >= 0; at -= 1) {
      if (rows[at].kind === 'process' && rows[at].depth < row.depth) return { index: at, action: null }
    }
    return { index, action: null }
  }
  return { index, action: null }
}

/** The name a process goes by: the file name of its image (the API gives it; the path is the fallback). */
export const nameOf = (process) =>
  process?.name ||
  String(process?.image ?? '')
    .split(/[\\/]/)
    .filter(Boolean)
    .pop() ||
  '(unnamed)'

/** The command line on one line, cut to `max` characters with an ellipsis; the whole of it is in the detail. */
export function commandPreview(text, max = 120) {
  const line = String(text ?? '')
    .replace(/\s+/g, ' ')
    .trim()
  return line.length > max ? `${line.slice(0, max - 1)}…` : line
}

/** How long a process ran: "850 ms", "4 min 3 s", "2 h 5 min"; '' when the end is not known (or is before the start). */
export function ranText(startTs, endTs) {
  if (!Number.isFinite(startTs) || !Number.isFinite(endTs) || endTs < startTs) return ''
  const ms = endTs - startTs
  if (ms < 1000) return `${ms} ms`
  const seconds = Math.round(ms / 1000)
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return seconds % 60 ? `${minutes} min ${seconds % 60} s` : `${minutes} min`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`
  const days = Math.floor(hours / 24)
  return hours % 24 ? `${days} d ${hours % 24} h` : `${days} d`
}

/** The children of a process as a short phrase: "3 children", "1 child"; '' for none. */
export function childrenText(count) {
  if (!count) return ''
  return `${number(count)} ${count === 1 ? 'child' : 'children'}`
}

/** The ancestors of a process as a breadcrumb of names, the root first; a ghost parent comes before them. */
export function breadcrumb(ancestors = [], ghost = null) {
  const names = ancestors.map(nameOf)
  if (ghost) names.unshift(nameOf({ image: ghost.image }))
  return names
}

/** Whether the filters other than the host ask for a flat list (with breadcrumbs) rather than the tree. */
export const isFiltered = (filters = {}) =>
  FILTER_NAMES.some((name) => filters[name] !== undefined && filters[name] !== null && filters[name] !== '')

/** The filters of the API for a host and the person's filters; empty ones are left out. */
export function apiFilters(host, filters = {}, extra = {}) {
  const out = { host, ...extra }
  for (const name of FILTER_NAMES) {
    const value = filters[name]
    if (value !== undefined && value !== null && value !== '') out[name] = value
  }
  return out
}

/** The line of a host in the selector: "ws-01 · 1,204 processes". */
export const hostLine = (item) =>
  `${item.host || '(no host name)'} · ${number(item.processes)} ${item.processes === 1 ? 'process' : 'processes'}`

/**
 * A small cache of the answers asked per process (the ancestors of the rows of a flat list): the oldest
 * entry goes when it holds more than `size`. `get` and `has` do not touch the order; `set` does.
 */
export function createCache(size = 300) {
  const held = new Map()
  return {
    has: (key) => held.has(key),
    get: (key) => held.get(key),
    set(key, value) {
      held.delete(key)
      held.set(key, value)
      while (held.size > size) held.delete(held.keys().next().value)
    },
    get size() {
      return held.size
    },
  }
}

/**
 * The state that shows a process in its place in the tree ("Show in the tree"): the tree answer of the process
 * (`ancestors`, root first, and `node`) seeds one chain, root to process, every ancestor open. The lists are
 * `partial`: "Show all" on one of them loads the siblings the chain skipped.
 */
export function seedFromTree(answer) {
  const chain = [...(answer.ancestors ?? []), answer.node]
  const nodes = { [ROOTS]: { ...freshNode(), items: [chain[0]], partial: true, loaded: true } }
  const open = new Set()
  chain.slice(0, -1).forEach((process, index) => {
    open.add(process.id)
    nodes[process.id] = { ...freshNode(), items: [chain[index + 1]], partial: true, loaded: true }
  })
  return { nodes, open }
}
