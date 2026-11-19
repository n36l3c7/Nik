/*
 * ============================================================================
 * DASHBOARDS — what a widget asks, how its answer is drawn, where it sits
 * ============================================================================
 *
 * Pure functions: the address of the page, the request a widget sends to
 * /api/query/aggregate, the shape a chart draws from its answer, numbers as
 * people read them, and the grid of 12 columns widgets are moved on. The
 * server checks a widget again when a dashboard is saved (app/dashboards.py).
 */

export const DASHBOARDS_ROOT = '/dashboards'

export const isDashboardsPath = (pathname) => /^\/dashboards(\/|$)/.test(String(pathname ?? ''))

/** `{ id }` of a /dashboards address (id null for the page alone), or null. */
export function dashboardsFromPath(pathname) {
  const path = String(pathname ?? '').split('?')[0]
  if (!isDashboardsPath(path)) return null
  const [, , raw] = path.replace(/\/+$/, '').split('/')
  try {
    return { id: raw ? decodeURIComponent(raw) : null }
  } catch {
    return { id: null }
  }
}

export const dashboardsPath = (id = null) => (id ? `${DASHBOARDS_ROOT}/${encodeURIComponent(id)}` : DASHBOARDS_ROOT)

// ---------------------------------------------------------------------------
// Widgets
// ---------------------------------------------------------------------------
export const COLUMNS = 12
export const ROW_PX = 80
export const GAP_PX = 12
export const NARROW_PX = 860 // below this the grid is one column, in reading order
export const MAX_HEIGHT = 12

/** The kinds of widget: how many groups each takes, and its size when it is added. */
export const TYPES = [
  { id: 'number', label: 'Number', hint: 'One figure, with its change against the period before', groups: [0, 0], w: 3, h: 2 },
  { id: 'trend', label: 'Trend line', hint: 'A count or a measure over time', groups: [1, 2], w: 6, h: 3 },
  { id: 'bar', label: 'Bars', hint: 'One bar for each value of a field', groups: [1, 1], w: 6, h: 3 },
  { id: 'stacked_bar', label: 'Stacked bars', hint: 'Bars split by a second field', groups: [2, 2], w: 6, h: 3 },
  { id: 'pie', label: 'Donut', hint: 'The parts of a whole', groups: [1, 1], w: 4, h: 3 },
  { id: 'top', label: 'Top values', hint: 'The most frequent values of a field, as a list', groups: [1, 1], w: 4, h: 3 },
  { id: 'table', label: 'Table', hint: 'The rows themselves, with the columns you choose', groups: [0, 0], w: 6, h: 4 },
  { id: 'duration', label: 'Duration', hint: 'The time between two dates, or of an SLA timer', groups: [0, 1], w: 3, h: 2 },
  { id: 'gauge', label: 'Gauge', hint: 'A figure against a target', groups: [0, 0], w: 3, h: 2 },
  { id: 'text', label: 'Text', hint: 'A note in Markdown', groups: null, w: 4, h: 2 },
  { id: 'storage', label: 'Storage', hint: 'How full the file store is, and with what', groups: null, w: 4, h: 3 },
  { id: 'fetch', label: 'Fetch health', hint: 'How each connection that fetches goes', groups: null, w: 6, h: 3 },
] // prettier-ignore

export const typeOf = (id) => TYPES.find((type) => type.id === id) ?? null
export const asks = (widget) => Boolean(typeOf(widget?.type)?.groups)

export const ENTITIES = [
  { id: 'incidents', label: 'Incidents', time: 'created' },
  { id: 'artifacts', label: 'Artifacts', time: 'created' },
  { id: 'indicators', label: 'Indicators', time: 'firstSeen' },
  { id: 'tasks', label: 'Tasks', time: 'created' },
  { id: 'runs', label: 'Runs of playbooks', time: 'started' },
  { id: 'approvals', label: 'Approvals', time: 'asked' },
  { id: 'audit', label: 'Audit log', time: 'at' },
]

export const entityOf = (id) => ENTITIES.find((entity) => entity.id === id) ?? null

export const RANGES = [
  { id: '24h', label: 'Last 24 hours' },
  { id: '7d', label: 'Last 7 days' },
  { id: '30d', label: 'Last 30 days' },
  { id: '90d', label: 'Last 90 days' },
  { id: '1y', label: 'Last year' },
  { id: 'all', label: 'All time' },
]

export const rangeLabel = (id) => RANGES.find((range) => range.id === id)?.label ?? `Last ${id}`

export const REFRESH = [
  { id: 0, label: 'No refresh' },
  { id: 60, label: 'Every minute' },
  { id: 300, label: 'Every 5 minutes' },
  { id: 900, label: 'Every 15 minutes' },
]

export const FUNCTIONS = [
  { id: 'count', label: 'Count' },
  { id: 'avg', label: 'Mean' },
  { id: 'median', label: 'Median' },
  { id: 'p90', label: '90th percentile' },
  { id: 'sum', label: 'Sum' },
  { id: 'min', label: 'Minimum' },
  { id: 'max', label: 'Maximum' },
]

export const BUCKETS = ['hour', 'day', 'week', 'month', 'year']

/** `created@day` as `{ field, bucket }`. */
export function parseGroup(text) {
  const [field, bucket = ''] = String(text ?? '').split('@')
  return { field, bucket }
}

export const groupText = ({ field, bucket }) => (bucket ? `${field}@${bucket}` : field)

/** `median:duration(created,closed)` as `{ fn, field, from, to }` (field for a number, from/to for a duration). */
export function parseMeasure(text) {
  const [fn, ...rest] = String(text || 'count').split(':')
  const what = rest.join(':')
  const between = /^duration\(\s*([\w.]+)\s*,\s*([\w.]+)\s*\)$/.exec(what)
  if (between) return { fn, field: '', from: between[1], to: between[2] }
  return { fn: fn || 'count', field: what, from: '', to: '' }
}

export function measureText({ fn, field, from, to }) {
  if (!fn || fn === 'count') return 'count'
  if (from) return `${fn}:duration(${from},${to || 'now'})`
  return field ? `${fn}:${field}` : 'count'
}

/** Two queries that must both hold. */
export function bothQueries(first, second) {
  const a = String(first ?? '').trim()
  const b = String(second ?? '').trim()
  if (!a || !b) return a || b
  return `(${a}) (${b})`
}

/** The query a widget asks: its own, narrowed by the filter of the dashboard when it is of the same entity. */
export function widgetQuery(widget, board) {
  const narrowed =
    board?.filter && board.filterEntity === widget.entity && !widget.options?.ignoreFilter ? board.filter : ''
  return bothQueries(widget.query, narrowed)
}

/** What a widget sends to POST /api/query/aggregate (null for one that asks nothing, and for a table). */
export function aggregateRequest(widget, board, range) {
  if (!asks(widget) || widget.type === 'table') return null
  const options = widget.options ?? {}
  const within = options.ignoreRange || !range || range === 'all' ? null : range
  const body = {
    entity: widget.entity,
    query: widgetQuery(widget, board),
    groupBy: widget.groupBy ?? [],
    measure: widget.measure || 'count',
    limit: options.limit ?? (widget.type === 'pie' ? 8 : 10),
  }
  if (widget.type === 'stacked_bar' || widget.type === 'trend') body.limit = 500
  if (within) {
    body.timeField = options.timeField || entityOf(widget.entity)?.time
    body.timeRange = within
    if (options.compare) body.compare = 'previous'
  }
  return body
}

/** What a table widget sends to POST /api/query: the rows, newest first. */
export function rowsRequest(widget, board, range) {
  const options = widget.options ?? {}
  let query = widgetQuery(widget, board)
  const field = options.timeField || entityOf(widget.entity)?.time
  if (range && range !== 'all' && !options.ignoreRange && field) {
    query = bothQueries(query, `${field}:>=now-${range === '1y' ? '52w' : range}`)
  }
  return { entity: widget.entity, query, limit: options.limit ?? 10, offset: 0 }
}

/** A widget of a type, with what it needs to be valid, at the end of the grid. */
export function newWidget(type, id) {
  const meta = typeOf(type) ?? TYPES[0]
  const widget = { id, title: '', type: meta.id, options: {}, x: 0, y: 10_000, w: meta.w, h: meta.h }
  if (!meta.groups) return widget
  const groups = { trend: ['created@day'], stacked_bar: ['created@day', 'severity'] }[meta.id]
  return {
    ...widget,
    entity: 'incidents',
    query: '',
    groupBy: groups ?? (meta.groups[0] ? ['severity'] : []),
    measure: meta.id === 'duration' ? 'median:duration(created,closed)' : 'count',
    options:
      meta.id === 'gauge' ? { target: 10 } : meta.id === 'table' ? { columns: ['name', 'severity', 'status'] } : {},
  }
}

// ---------------------------------------------------------------------------
// Numbers as people read them
// ---------------------------------------------------------------------------
/** 1284 → "1,284"; 12940 → "12.9K"; 4200000 → "4.2M". */
export function compact(value) {
  if (value == null || Number.isNaN(Number(value))) return '—'
  const number = Number(value)
  const size = Math.abs(number)
  if (size >= 1e9) return `${trim(number / 1e9)}B`
  if (size >= 1e6) return `${trim(number / 1e6)}M`
  if (size >= 1e4) return `${trim(number / 1e3)}K`
  if (Number.isInteger(number)) return number.toLocaleString('en-US')
  return trim(number, size < 10 ? 2 : 1)
}

function trim(number, digits = 1) {
  return String(Number(number.toFixed(digits)))
}

/** Seconds as the two largest units that matter: "45s", "12m", "2h 5m", "3d 4h". */
export function duration(seconds) {
  if (seconds == null || Number.isNaN(Number(seconds))) return '—'
  let left = Math.round(Math.abs(Number(seconds)))
  if (left < 60) return `${left}s`
  const units = [
    ['d', 86400],
    ['h', 3600],
    ['m', 60],
  ]
  const parts = []
  for (const [name, size] of units) {
    const count = Math.floor(left / size)
    left -= count * size
    if (count || parts.length) parts.push([count, name])
    if (parts.length === 2) break
  }
  return parts
    .filter(([count], index) => count || index === 0)
    .map(([count, name]) => `${count}${name}`)
    .join(' ')
}

export function bytes(value) {
  if (value == null || Number.isNaN(Number(value))) return '—'
  let number = Number(value)
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let unit = 0
  while (Math.abs(number) >= 1024 && unit < units.length - 1) {
    number /= 1024
    unit += 1
  }
  return `${trim(number, number < 10 && unit ? 1 : 0)} ${units[unit]}`
}

/** How a widget's figures are written: what it says, or a duration when its measure is one. */
export function formatOf(widget) {
  const chosen = widget?.options?.format
  if (chosen) return chosen
  const measure = String(widget?.measure ?? '')
  if (measure.includes('duration(') || /:timeTo/.test(measure) || widget?.type === 'duration') {
    return measure === 'count' ? 'number' : 'duration'
  }
  return 'number'
}

export function formatValue(value, format = 'number') {
  if (value == null) return '—'
  if (format === 'duration') return duration(value)
  if (format === 'bytes') return bytes(value)
  if (format === 'percent') return `${trim(Number(value), 1)}%`
  return compact(value)
}

/** The change against the period before: `{ text, direction: 'up' | 'down' | 'same' }`, or null. */
export function change(total, previous, format = 'number') {
  if (total == null || previous == null) return null
  const difference = Number(total) - Number(previous)
  const direction = difference > 0 ? 'up' : difference < 0 ? 'down' : 'same'
  if (direction === 'same') return { text: 'no change', direction }
  const sign = difference > 0 ? '+' : '−'
  const amount = formatValue(Math.abs(difference), format)
  const share = Number(previous) ? ` (${sign}${Math.round((Math.abs(difference) / Math.abs(previous)) * 100)}%)` : ''
  return { text: `${sign}${amount}${share}`, direction }
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

/** A stretch of time as it is named on an axis: "17 Nov", "Nov 2026", "17 Nov 08:00", "2026". */
export function bucketLabel(key, bucket) {
  const text = String(key ?? '')
  if (!text) return '(none)'
  const [year, month, rest = ''] = text.split('-')
  const name = MONTHS[Number(month) - 1] ?? month
  if (bucket === 'year') return year
  if (bucket === 'month') return `${name} ${year}`
  const day = Number(rest.slice(0, 2))
  if (bucket === 'hour') return `${day} ${name} ${rest.slice(3, 5)}:00`
  return `${day} ${name}`
}

/** The name of a group value: a stretch of time, or the value, or "(none)". */
export function keyLabel(key, column) {
  if (column?.bucket) return bucketLabel(key, column.bucket)
  return key === '' || key == null ? '(none)' : String(key)
}

// ---------------------------------------------------------------------------
// What a chart draws
// ---------------------------------------------------------------------------
/** One group: `[{ key, label, value }]`, in the order the server gave. */
export function categories(result) {
  const column = result?.columns?.[0]
  return (result?.rows ?? []).map(([key, value]) => ({ key, label: keyLabel(key, column), value }))
}

export const MAX_SERIES = 8

/**
 * Two groups as the series of a chart: `{ x: [{ key, label }], series: [{ key, label, values, total }] }`.
 * The first group is the axis, the second the series. Past eight series the smallest are folded into
 * "Other" when the measure can be added up (a count or a sum); otherwise they are left out and
 * `dropped` says how many.
 */
export function seriesOf(result) {
  const [first, second, measure] = result?.columns ?? []
  const rows = result?.rows ?? []
  const xKeys = []
  const byKey = new Map()
  for (const [x, name, value] of rows) {
    if (!xKeys.includes(x)) xKeys.push(x)
    if (!byKey.has(name)) byKey.set(name, new Map())
    byKey.get(name).set(x, value)
  }
  if (first?.bucket) xKeys.sort()
  let series = [...byKey.entries()].map(([key, values]) => {
    const list = xKeys.map((x) => values.get(x) ?? null)
    return { key, label: keyLabel(key, second), values: list, total: list.reduce((sum, v) => sum + (v ?? 0), 0) }
  })
  // The order of a field that has one (severity) is kept; otherwise the largest first, so colours stay put.
  if (second?.kind !== 'ordered') series.sort((a, b) => b.total - a.total || String(a.key).localeCompare(String(b.key)))
  let dropped = 0
  if (series.length > MAX_SERIES) {
    const adds = /^(count|sum)/.test(measure?.name ?? 'count')
    const rest = series.slice(MAX_SERIES - 1)
    series = series.slice(0, MAX_SERIES - 1)
    if (adds) {
      const values = xKeys.map((_, index) => rest.reduce((sum, item) => sum + (item.values[index] ?? 0), 0))
      series.push({ key: '\u0000other', label: 'Other', values, total: values.reduce((sum, v) => sum + v, 0) })
    } else dropped = rest.length
  }
  return { x: xKeys.map((key) => ({ key, label: keyLabel(key, first) })), series, dropped }
}

/** Round ticks from zero to a little above the largest value: `[0, 5, 10, 15]`. */
export function ticks(max, count = 4) {
  const top = Number(max) > 0 ? Number(max) : 1
  const rough = top / count
  const power = 10 ** Math.floor(Math.log10(rough))
  const step = [1, 2, 2.5, 5, 10].map((m) => m * power).find((size) => size >= rough) ?? rough
  const out = []
  for (let value = 0; value < top + step - 1e-9; value += step) out.push(Number(value.toFixed(6)))
  return out
}

/** Ticks for something that is counted: whole numbers only (never "0.5 incidents"). */
export function wholeTicks(max, count = 4) {
  const top = Math.max(1, Math.ceil(Number(max) || 0))
  const found = ticks(top, Math.min(count, top)).filter(Number.isInteger)
  return found.length > 1 ? found : [0, top]
}

/** Ticks for seconds, on round minutes, hours or days. */
export function durationTicks(max, count = 4) {
  const top = Number(max) > 0 ? Number(max) : 60
  const unit = top >= 2 * 86400 ? 86400 : top >= 2 * 3600 ? 3600 : top >= 120 ? 60 : 1
  return ticks(top / unit, count).map((value) => value * unit)
}

/** The query of the objects behind one value of a chart: the widget's, and each group at its value. */
export function drillQuery(widget, board, columns, keys) {
  const parts = keys.map((key, index) => {
    const column = columns[index]
    if (!column || key === '\u0000other') return ''
    const value = String(key ?? '')
    if (column.bucket) {
      if (!value) return `${column.name}:""`
      if (column.bucket === 'day' || column.bucket === 'month' || column.bucket === 'year') {
        return `${column.name}:${value}`
      }
      const start = column.bucket === 'hour' ? `${value}:00:00` : `${value}T00:00:00`
      const span = column.bucket === 'hour' ? 3600e3 : 7 * 86400e3
      const end = new Date(Date.parse(`${start}Z`) + span).toISOString().slice(0, 19)
      return `${column.name}:>="${start}" ${column.name}:<"${end}"`
    }
    return `${column.name}:"${value.replace(/(["\\])/g, '\\$1')}"`
  })
  return parts.filter(Boolean).reduce((query, part) => bothQueries(query, part), widgetQuery(widget, board))
}

// ---------------------------------------------------------------------------
// The grid
// ---------------------------------------------------------------------------
const overlaps = (a, b) => a.x < b.x + b.w && b.x < a.x + a.w && a.y < b.y + b.h && b.y < a.y + a.h

const clamp = (value, low, high) => Math.max(low, Math.min(high, Math.round(Number(value) || 0)))

/** A widget kept inside the 12 columns. */
export function bounded(widget) {
  const w = clamp(widget.w, 1, COLUMNS)
  return {
    ...widget,
    w,
    h: clamp(widget.h, 1, MAX_HEIGHT),
    x: clamp(widget.x, 0, COLUMNS - w),
    y: clamp(widget.y, 0, 10_000),
  }
}

/**
 * No two widgets on the same cell and no hole above one: in reading order, each is moved up to the
 * highest row where it fits. `first` names a widget that keeps its place when two want the same one
 * (the one being dragged).
 */
export function compactGrid(widgets, first = null) {
  const ordered = widgets.map(bounded).sort((a, b) => a.y - b.y || (b.id === first) - (a.id === first) || a.x - b.x)
  const placed = []
  for (const widget of ordered) {
    let y = 0
    for (;;) {
      const under = placed.filter((other) => overlaps({ ...widget, y }, other)).map((other) => other.y + other.h)
      if (!under.length) break
      y = Math.max(...under)
    }
    placed.push({ ...widget, y })
  }
  const byId = new Map(placed.map((widget) => [widget.id, widget]))
  return widgets.map((widget) => byId.get(widget.id))
}

/** The grid after one widget is moved or resized: it takes the place, the others make room. */
export function arrange(widgets, id, patch) {
  const next = widgets.map((widget) => (widget.id === id ? bounded({ ...widget, ...patch }) : widget))
  return compactGrid(next, id)
}

/** The widgets in reading order: top-left first (the order of the one-column layout). */
export const readingOrder = (widgets) => [...widgets].sort((a, b) => a.y - b.y || a.x - b.x)

export const gridHeight = (widgets) => widgets.reduce((rows, widget) => Math.max(rows, widget.y + widget.h), 0)

/** What an arrow key does to a widget in edit mode: move it, or resize it with Shift. */
export function keyStep(key, shift) {
  const step = { ArrowLeft: [-1, 0], ArrowRight: [1, 0], ArrowUp: [0, -1], ArrowDown: [0, 1] }[key]
  if (!step) return null
  return shift ? { dw: step[0], dh: step[1] } : { dx: step[0], dy: step[1] }
}

/** Who sees a dashboard, in a few words. */
export function sharingText(board) {
  if (board?.builtin) return 'Shipped with Nik'
  const shared = board?.sharedWith ?? {}
  if (shared.everyone) return 'Shared with everyone'
  const names = [...(shared.roles ?? []).map((role) => `role ${role}`), ...(shared.users ?? [])]
  return names.length ? `Shared with ${names.join(', ')}` : 'Only you'
}

// The categorical colours of a chart, in a fixed order (validated on the panel surface for
// colour-blind separation and contrast). A series keeps its colour: it is never cycled past eight.
export const SERIES_COLORS = ['#3987e5', '#d95926', '#199e70', '#c98500', '#d55181', '#0ca30c', '#9085e9', '#e66767']
export const OTHER_COLOR = '#6e7681'

export const seriesColor = (index, key) =>
  key === '\u0000other' ? OTHER_COLOR : SERIES_COLORS[index % SERIES_COLORS.length]

// Which dashboard opens at sign-in, when the person chose one (kept in this browser).
export const LANDING_KEY = 'nik.landing'

export function landingDashboard() {
  try {
    return localStorage.getItem(LANDING_KEY) || null
  } catch {
    return null
  }
}
