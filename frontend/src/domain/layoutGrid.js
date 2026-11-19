/*
 * The Summary of an incident as a grid (5.3): what a type of incident puts on
 * the first page of its incidents, placed like the widgets of a dashboard.
 *
 * A layout keeps, beside its sections of fields and the order of its tabs,
 *
 *   grid: [{ id, kind, x, y, w, h, title?, section?, text?, playbooks? }]
 *
 * on the twelve columns of the dashboards (domain/dashboards.js: rows of
 * 80 px). A type that has no grid, which is every type made before 5.3, gets
 * `defaultGrid`: the details of the incident, the numbers of its evidence,
 * its sections of fields in their order, then its flags and notes: what the
 * Summary showed, in the same order.
 */
import { COLUMNS, MAX_HEIGHT, gridHeight } from './dashboards.js'

export const GRID_MAX = 30
export const NOTE_MAX = 2000
export const PLAYBOOKS_MAX = 8

/**
 * The kinds of widget, in the order the editor offers them. `w` and `h` are
 * the size a new one takes; `once` kinds are on a page one time at most.
 */
export const WIDGET_KINDS = [
  {
    id: 'facts',
    label: 'Incident details',
    w: 7,
    h: 3,
    once: true,
    hint: 'Name, ticket, severity, status, owner, host: with the button that edits them.',
  },
  {
    id: 'section',
    label: 'A section of fields',
    w: 12,
    h: 3,
    hint: 'One of the sections of this type, with its fields.',
  },
  {
    id: 'stats',
    label: 'Numbers of the evidence',
    w: 5,
    h: 3,
    once: true,
    hint: 'How many events, commands, artifacts, flags and notes.',
  },
  {
    id: 'timeline',
    label: 'Flags and notes',
    w: 12,
    h: 6,
    once: true,
    hint: 'What was flagged and written, in order of time.',
  },
  { id: 'timers', label: 'Timers', w: 4, h: 3, once: true, hint: 'The timers of the SLA of this type.' },
  {
    id: 'evidence',
    label: 'Evidence',
    w: 4,
    h: 5,
    once: true,
    hint: 'The files of the incident: each opens in the Evidence tab.',
  },
  {
    id: 'war_room',
    label: 'War Room',
    w: 6,
    h: 6,
    once: true,
    hint: 'The stream of the incident and its command line.',
  },
  { id: 'work_plan', label: 'Work plan', w: 6, h: 6, once: true, hint: 'The tasks and the steps of the playbooks.' },
  { id: 'indicators', label: 'Indicators', w: 12, h: 6, once: true, hint: 'The indicators found in the evidence.' },
  {
    id: 'playbooks',
    label: 'Playbook buttons',
    w: 4,
    h: 2,
    hint: 'Buttons that run the playbooks you choose on the incident.',
  },
  { id: 'note', label: 'A text', w: 4, h: 2, hint: 'A text of your own: what to check first, who to call.' },
]

export const kindOf = (id) => WIDGET_KINDS.find((kind) => kind.id === id) ?? null

const list = (value) => (Array.isArray(value) ? value : [])
const whole = (value, fallback) => (Number.isFinite(Number(value)) ? Math.round(Number(value)) : fallback)
const clamp = (value, min, max) => Math.max(min, Math.min(max, value))

/** The fields "Edit the incident" changes: the details show them, a section does not show them twice. */
export const DETAIL_FIELDS = ['name', 'ticket', 'host', 'username', 'os', 'severity', 'status', 'owner']

/**
 * The rows a section of fields needs: its title, then a line for each field it
 * shows (two a line when it has two columns).
 */
export function sectionHeight(section) {
  const shown = list(section?.fields).filter((name) => !DETAIL_FIELDS.includes(name))
  const lines = Math.ceil(shown.length / (section?.columns === 2 ? 2 : 1))
  return clamp(Math.ceil((56 + lines * 28) / 80), 2, MAX_HEIGHT)
}

/** The sections a grid can show: every one but the side panel. */
export const gridSections = (layout) => list(layout?.sections).filter((section) => !section.key)

/**
 * The page of a type that never arranged one: the details and the numbers
 * side by side, the sections one under the other, the flags and notes last.
 */
export function defaultGrid(layout) {
  const grid = [
    { id: 'facts', kind: 'facts', x: 0, y: 0, w: 7, h: 3 },
    { id: 'stats', kind: 'stats', x: 7, y: 0, w: 5, h: 3 },
  ]
  let y = 3
  for (const section of gridSections(layout)) {
    const h = sectionHeight(section)
    grid.push({ id: `section-${section.id}`, kind: 'section', section: section.id, x: 0, y, w: COLUMNS, h })
    y += h
  }
  grid.push({ id: 'timeline', kind: 'timeline', x: 0, y, w: COLUMNS, h: 6 })
  return grid
}

/**
 * A grid as it is kept and drawn: the widgets of a kind there is, inside the
 * twelve columns, a section widget only for a section the layout has, a kind
 * that is there once kept once. Never throws: what cannot be drawn is left out.
 */
export function cleanGrid(grid, layout) {
  const sections = new Set(gridSections(layout).map((section) => section.id))
  const ids = new Set()
  const once = new Set()
  const out = []
  for (const raw of list(grid).slice(0, GRID_MAX)) {
    const kind = kindOf(raw?.kind)
    if (!kind) continue
    if (kind.once && once.has(kind.id)) continue
    if (kind.id === 'section' && !sections.has(raw.section)) continue
    let id = String(raw.id ?? '').slice(0, 40) || `${kind.id}-${out.length + 1}`
    while (ids.has(id)) id = `${id}-${out.length + 1}`
    ids.add(id)
    once.add(kind.id)
    const w = clamp(whole(raw.w, kind.w), 1, COLUMNS)
    const widget = {
      id,
      kind: kind.id,
      x: clamp(whole(raw.x, 0), 0, COLUMNS - w),
      y: Math.max(0, whole(raw.y, 0)),
      w,
      h: clamp(whole(raw.h, kind.h), 1, MAX_HEIGHT),
    }
    const title = String(raw.title ?? '')
      .trim()
      .slice(0, 80)
    if (title) widget.title = title
    if (kind.id === 'section') widget.section = raw.section
    if (kind.id === 'note') widget.text = String(raw.text ?? '').slice(0, NOTE_MAX)
    if (kind.id === 'playbooks') {
      widget.playbooks = [...new Set(list(raw.playbooks).map(String).filter(Boolean))].slice(0, PLAYBOOKS_MAX)
    }
    out.push(widget)
  }
  return out
}

/** The grid of a type: the one it keeps, or the one made from its sections. `custom` says which. */
export function gridOf(type) {
  const layout = type?.layout ?? null
  const kept = Array.isArray(layout?.grid) ? cleanGrid(layout.grid, layout) : []
  return kept.length > 0 ? { grid: kept, custom: true } : { grid: defaultGrid(layout), custom: false }
}

/** What a widget is called on the page: its own title, the title of its section, or its kind. */
export function widgetTitle(widget, layout) {
  if (widget?.title) return widget.title
  if (widget?.kind === 'section') {
    return gridSections(layout).find((section) => section.id === widget.section)?.title ?? 'Section'
  }
  return kindOf(widget?.kind)?.label ?? 'Widget'
}

/** Whether a kind can still be added to a grid (a `once` kind that is there cannot). */
export const canAdd = (grid, kindId) => {
  const kind = kindOf(kindId)
  if (!kind || list(grid).length >= GRID_MAX) return false
  return !(kind.once && list(grid).some((widget) => widget.kind === kind.id))
}

/** `grid` with a new widget of a kind under everything else. Unchanged when it cannot be added. */
export function addWidget(grid, kindId, extras = {}) {
  const all = list(grid)
  const kind = kindOf(kindId)
  if (!canAdd(all, kindId)) return all
  let number = all.length + 1
  while (all.some((widget) => widget.id === `${kind.id}-${number}`)) number += 1
  const widget = { id: `${kind.id}-${number}`, kind: kind.id, x: 0, y: gridHeight(all), w: kind.w, h: kind.h }
  if (kind.id === 'note') widget.text = ''
  if (kind.id === 'playbooks') widget.playbooks = []
  return [...all, { ...widget, ...extras }]
}

/** The sections no widget of the grid shows yet: what "A section of fields" can still be added for. */
export function freeSections(grid, layout) {
  const shown = new Set(
    list(grid)
      .filter((widget) => widget.kind === 'section')
      .map((widget) => widget.section),
  )
  return gridSections(layout).filter((section) => !shown.has(section.id))
}

/** The grid as the type keeps it: for the editor's kinds of widget, what each needs and no more. */
export const gridForSaving = (grid, layout) => cleanGrid(grid, layout)
