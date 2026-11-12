/*
 * Network Analysis helpers (pure, unit-tested): the isolated browser's
 * request log as DevTools shows it, and Wireshark's protocol tree and bytes
 * as sharkd returns them.
 */

// DevTools' type filters and the Playwright resource types each covers.
export const REQUEST_TYPES = [
  { id: 'all', label: 'All' },
  { id: 'fetch', label: 'Fetch/XHR', types: ['fetch', 'xhr', 'eventsource'] },
  { id: 'doc', label: 'Doc', types: ['document'] },
  { id: 'css', label: 'CSS', types: ['stylesheet'] },
  { id: 'js', label: 'JS', types: ['script'] },
  { id: 'font', label: 'Font', types: ['font'] },
  { id: 'img', label: 'Img', types: ['image'] },
  { id: 'media', label: 'Media', types: ['media'] },
  { id: 'ws', label: 'WS', types: ['websocket'] },
  { id: 'other', label: 'Other' },
]

const NAMED_TYPES = new Set(REQUEST_TYPES.flatMap((t) => t.types ?? []))

/** Entries matching the type filter, the text and the toggles (blocked/held only, POST only). */
export function filterRequests(entries, { type = 'all', text = '', refused = false, posts = false } = {}) {
  const group = REQUEST_TYPES.find((t) => t.id === type)
  const needle = text.trim().toLowerCase()
  return entries.filter((e) => {
    if (group?.types && !group.types.includes(e.resourceType)) return false
    if (type === 'other' && NAMED_TYPES.has(e.resourceType)) return false
    if (refused && !['blocked', 'held', 'failed'].includes(e.state)) return false
    if (posts && ['GET', 'HEAD', 'OPTIONS'].includes(e.method)) return false
    return !needle || (e.url ?? '').toLowerCase().includes(needle)
  })
}

/** The last path segment (DevTools' "Name" column). */
export function requestName(url) {
  try {
    const parsed = new URL(url)
    const last = parsed.pathname.split('/').filter(Boolean).pop()
    return (last || parsed.host) + parsed.search
  } catch {
    return url ?? ''
  }
}

/** The status shown in the list: the HTTP status, or why there is none. */
export function requestStatus(entry) {
  if (entry.state === 'held') return { text: 'held', tone: 'high' }
  if (entry.state === 'blocked') return { text: 'blocked', tone: 'high' }
  if (entry.state === 'failed') return { text: 'failed', tone: 'med' }
  if (entry.state === 'pending') return { text: 'pending', tone: 'muted' }
  const status = entry.response?.status
  if (!status) return { text: '—', tone: 'muted' }
  return { text: String(status), tone: status >= 400 ? 'high' : status >= 300 ? 'med' : 'ok' }
}

export function formatBytesShort(n) {
  if (n === undefined || n === null) return '—'
  if (n < 1024) return `${n} B`
  if (n < 1048576) return `${(n / 1024).toFixed(1)} kB`
  return `${(n / 1048576).toFixed(1)} MB`
}

export function formatMs(ms) {
  if (ms === undefined || ms === null || ms < 0) return '—'
  return ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`
}

/**
 * The waterfall bar of an entry: offset and width in % of the session span.
 * Entries without timings get a thin mark at their start.
 */
export function waterfall(entry, start, span) {
  const total = entry.timing?.total > 0 ? entry.timing.total : 0
  const offset = span > 0 ? ((entry.startedAt - start) / span) * 100 : 0
  const width = span > 0 ? Math.max(0.5, (total / span) * 100) : 0.5
  return { offset: Math.min(99.5, Math.max(0, offset)), width: Math.min(100 - Math.max(0, offset), width) }
}

/** The span of a list of entries: { start, span } in ms. */
export function timeSpan(entries) {
  if (!entries.length) return { start: 0, span: 0 }
  const start = Math.min(...entries.map((e) => e.startedAt))
  const end = Math.max(...entries.map((e) => e.startedAt + Math.max(0, e.timing?.total ?? 0)))
  return { start, span: Math.max(1, end - start) }
}

/** base64 → bytes (Uint8Array). */
export function fromBase64(text) {
  if (!text) return new Uint8Array()
  const raw = atob(text)
  return Uint8Array.from(raw, (c) => c.charCodeAt(0))
}

/** base64 → text (UTF-8, invalid sequences replaced). */
export function base64Text(text) {
  return new TextDecoder('utf-8', { fatal: false }).decode(fromBase64(text))
}

const TEXT_TYPES =
  /^(text\/|application\/(json|javascript|x-javascript|xml|x-www-form-urlencoded|ld\+json|xhtml)|image\/svg)/i

/** True when a body of this MIME type reads as text. */
export function isText(mime) {
  return TEXT_TYPES.test(mime ?? '')
}

/** A form-encoded or JSON request body as [[name, value]] pairs, else null. */
export function payloadFields(body, contentType = '') {
  if (!body) return null
  const text = base64Text(body)
  if (/application\/x-www-form-urlencoded/i.test(contentType) || /^[\w.%-]+=[^&]*(&[\w.%-]+=[^&]*)*$/.test(text)) {
    return [...new URLSearchParams(text).entries()]
  }
  if (/json/i.test(contentType) || /^\s*[{[]/.test(text)) {
    try {
      const value = JSON.parse(text)
      if (value && typeof value === 'object' && !Array.isArray(value))
        return Object.entries(value).map(([k, v]) => [k, typeof v === 'string' ? v : JSON.stringify(v)])
    } catch {
      return null
    }
  }
  return null
}

export function header(pairs, name) {
  const lower = name.toLowerCase()
  return (pairs ?? []).find((p) => String(p[0]).toLowerCase() === lower)?.[1] ?? ''
}

// --------------------------------------------------------------------------- //
// Wireshark (sharkd)                                                           //
// --------------------------------------------------------------------------- //

/** A sharkd colour ("e4ffc7") as a CSS colour, or undefined. */
export const hexColor = (value) => (value && /^[0-9a-f]{6}$/i.test(value) ? `#${value}` : undefined)

/**
 * The protocol tree with a stable path per node ("0.2.1"), for expansion state
 * and selection. Each node: { path, label, filter, field, range: [start, end] | null, children }.
 */
export function normalizeTree(nodes, prefix = '') {
  return (nodes ?? []).map((node, index) => {
    const path = prefix ? `${prefix}.${index}` : String(index)
    const range = Array.isArray(node.h) ? [node.h[0], node.h[0] + node.h[1]] : null
    return {
      path,
      label: node.l ?? '',
      filter: node.f ?? '',
      field: node.fn ?? '',
      severity: node.s ?? '',
      source: node.ds ?? 0,
      range,
      children: normalizeTree(node.n, path),
    }
  })
}

/** The first node of a field in the tree (depth first), or null. */
export function findField(nodes, field) {
  for (const node of nodes ?? []) {
    if (node.field === field) return node
    const found = findField(node.children, field)
    if (found) return found
  }
  return null
}

/** The value of a field from its filter ("tcp.stream == 3" → "3"). */
export function fieldValue(node) {
  const match = /==\s*(.+)$/.exec(node?.filter ?? '')
  return match ? match[1].replace(/^"|"$/g, '') : null
}

/** What can be followed from a packet's tree: { kind, filter } or null. */
export function followTarget(tree) {
  const http = findField(tree, 'http')
  const tls = findField(tree, 'tls')
  const tcp = fieldValue(findField(tree, 'tcp.stream'))
  if (tcp !== null) {
    const kind = http ? 'HTTP' : tls ? 'TLS' : 'TCP'
    return { kind, filter: `tcp.stream eq ${tcp}` }
  }
  const udp = fieldValue(findField(tree, 'udp.stream'))
  if (udp !== null) return { kind: 'UDP', filter: `udp.stream eq ${udp}` }
  return null
}

/** The byte ranges to highlight in the hex view for a selected tree node. */
export function highlight(node) {
  return node?.range ? { start: node.range[0], end: node.range[1] } : null
}

const captureName = (capture) => (capture.kind === 'browser' ? capture.label || capture.fileName : capture.fileName)

/** What toggleFlag() expects for a capture as a whole (the timeline and the capture list flag the same key). */
export function captureFlaggable(capture) {
  return {
    key: `capture:${capture.id}`,
    browserId: 'network',
    section: 'network',
    eventType: 'network',
    title: captureName(capture),
    url: '',
    time: capture.first ?? Date.parse(capture.createdAt),
  }
}

/**
 * Timeline events of the network captures: each capture at its first packet
 * (its upload when unknown), each held submission (high) and each periodic
 * connection (medium), on top of the SOC rules.
 */
export function networkEvents(captures = [], engine) {
  const out = []
  for (const capture of captures) {
    const name = captureName(capture)
    const time = capture.first ?? Date.parse(capture.createdAt)
    const base = { sourceType: 'network', sourceLabel: 'Network', eventType: 'network' }
    const flaggable = (key, title, url, at) => ({
      key,
      browserId: 'network',
      section: 'network',
      eventType: 'network',
      title,
      url,
      time: at,
    })
    out.push({
      ...base,
      id: `capture:${capture.id}`,
      time,
      label: name,
      detail: `${capture.kind === 'browser' ? 'isolated browser session' : 'capture'} · ${capture.packets ?? 0} packets`,
      soc: engine.analyze({ kind: 'network', title: name, time }),
      flaggable: captureFlaggable(capture),
    })
    for (const held of capture.held ?? []) {
      const title = `${held.method} ${held.url} (held, not sent)`
      const soc = engine.analyze({ kind: 'network', title, url: held.url, time: held.time })
      out.push({
        ...base,
        id: `held:${capture.id}:${held.id}`,
        time: held.time,
        label: title,
        detail: `submission held by Nik · ${name}`,
        soc: { ...soc, severity: 'high', isFlagged: true },
        flaggable: flaggable(`held:${capture.id}:${held.id}`, title, held.url, held.time),
      })
    }
    for (const beacon of capture.beacons ?? []) {
      const at = beacon.first ? beacon.first * 1000 : time
      const title = `Beacon to ${beacon.destination}:${beacon.port} every ${beacon.interval} s (${beacon.count}×)`
      const soc = engine.analyze({ kind: 'network', title, time: at })
      out.push({
        ...base,
        id: `beacon:${capture.id}:${beacon.destination}:${beacon.port}`,
        time: at,
        label: title,
        detail: name,
        soc: { ...soc, severity: soc.severity === 'high' ? 'high' : 'medium', isFlagged: true },
        flaggable: flaggable(
          `beacon:${capture.id}:${beacon.destination}:${beacon.port}`,
          title,
          beacon.destination,
          at,
        ),
      })
    }
  }
  return out
}

/** Time formats of the packet list (the worker fills the Time column). */
export const TIME_FORMATS = [
  { id: 'relative', label: 'Seconds since start' },
  { id: 'absolute', label: 'Date and time (UTC)' },
  { id: 'delta', label: 'Since previous packet' },
]

/*
 * Column sorting of the Network Analysis tables (packets, requests, objects).
 * A header cycles: ascending, descending, back to the capture's own order.
 */

/** The next sort after a click on `key`: asc, desc, then none. */
export function nextSort(sort, key) {
  if (sort?.key !== key) return { key, dir: 'asc' }
  return sort.dir === 'asc' ? { key, dir: 'desc' } : null
}

/** Numbers by value, text in natural order ("10.0.0.2" before "10.0.0.10"); empty values last. */
export function compareCells(a, b) {
  const emptyA = a === null || a === undefined || a === ''
  const emptyB = b === null || b === undefined || b === ''
  if (emptyA || emptyB) return emptyA === emptyB ? 0 : emptyA ? 1 : -1
  const na = typeof a === 'number' ? a : Number(a)
  const nb = typeof b === 'number' ? b : Number(b)
  if (Number.isFinite(na) && Number.isFinite(nb)) return na - nb
  return String(a).localeCompare(String(b), 'en', { numeric: true, sensitivity: 'base' })
}

/** A sorted copy of `rows` (stable; empty values stay last in both directions), or `rows` itself without a sort. */
export function sortRows(rows, sort, accessor) {
  if (!sort) return rows
  const sign = sort.dir === 'desc' ? -1 : 1
  return rows
    .map((row, index) => ({ row, index, value: accessor(row, sort.key) }))
    .sort((x, y) => {
      const emptyX = x.value === null || x.value === undefined || x.value === ''
      const emptyY = y.value === null || y.value === undefined || y.value === ''
      if (emptyX !== emptyY) return emptyX ? 1 : -1
      return sign * compareCells(x.value, y.value) || x.index - y.index
    })
    .map((item) => item.row)
}

/** What each column of the request log sorts by. */
export function requestSortValue(entry, key) {
  switch (key) {
    case 'name':
      return requestName(entry.url)
    case 'method':
      return entry.method
    case 'status':
      return entry.response?.status ?? requestStatus(entry).text
    case 'type':
      return entry.resourceType
    case 'size':
      return entry.response?.bodySize
    case 'time':
      return entry.timing?.total
    case 'start':
      return entry.startedAt
    default:
      return null
  }
}
