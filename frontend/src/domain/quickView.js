/*
 * The quick view of the incident list (6.2): the panel a click on a row
 * opens over the right side of the list.
 *
 * What it shows is decided by the type of the incident: a layout keeps
 *
 *   quick: [{ kind, section?, text? }]
 *
 * one block under the other, in one narrow column. A type that has none,
 * which is every type made before 6.2, gets `defaultBlocks`: the details of
 * the incident, its first section of fields, the numbers of its evidence and
 * the last lines of its War Room.
 */
import { NOTE_MAX, gridSections } from './layoutGrid.js'
import { span } from './timers.js'
import { authorLabel, entryLine } from './warRoom.js'

export const QUICK_MAX = 12

/** The kinds of block, in the order the editor of a type offers them. `once` kinds are there one time at most. */
export const QUICK_KINDS = [
  { id: 'facts', label: 'Details', once: true },
  { id: 'section', label: 'A section of fields' },
  { id: 'stats', label: 'Numbers of the evidence', once: true },
  { id: 'timers', label: 'Timers', once: true },
  { id: 'last', label: 'Last in the War Room', once: true },
  { id: 'linked', label: 'Linked incidents', once: true },
  { id: 'note', label: 'A text' },
]

const kindOf = (id) => QUICK_KINDS.find((kind) => kind.id === id) ?? null
const list = (value) => (Array.isArray(value) ? value : [])

/** What the quick view of a type that never arranged one shows. */
export function defaultBlocks(type) {
  const [first] = gridSections(type?.layout)
  return [
    { id: 'facts', kind: 'facts' },
    ...(first ? [{ id: `section-${first.id}`, kind: 'section', section: first.id }] : []),
    { id: 'stats', kind: 'stats' },
    { id: 'last', kind: 'last' },
  ]
}

/**
 * The blocks of the quick view of a type, as they are drawn: those its
 * layout keeps, each of a kind there is, a section block only for a section
 * the layout has (and once), a kind that is there once kept once; or the
 * default ones when that leaves nothing. Each has an `id` to tell it from the
 * others. Never throws: what cannot be drawn is left out.
 */
export function quickBlocks(type) {
  const layout = type?.layout ?? null
  const sections = new Set(gridSections(layout).map((section) => section.id))
  const seen = new Set()
  const blocks = []
  for (const raw of list(layout?.quick)) {
    if (blocks.length >= QUICK_MAX) break
    const kind = kindOf(raw?.kind)
    if (!kind) continue
    if (kind.id === 'section') {
      if (!sections.has(raw.section) || seen.has(`section-${raw.section}`)) continue
      seen.add(`section-${raw.section}`)
      blocks.push({ id: `section-${raw.section}`, kind: 'section', section: raw.section })
    } else if (kind.id === 'note') {
      const text = String(raw.text ?? '').slice(0, NOTE_MAX)
      if (!text.trim()) continue
      blocks.push({ id: `note-${blocks.length + 1}`, kind: 'note', text })
    } else {
      if (seen.has(kind.id)) continue
      seen.add(kind.id)
      blocks.push({ id: kind.id, kind: kind.id })
    }
  }
  return blocks.length > 0 ? blocks : defaultBlocks(type)
}

/** What a block is called above what it shows ('' for a text, which says what it is itself). */
export function blockTitle(block, layout) {
  if (block?.kind === 'note') return ''
  if (block?.kind === 'section') {
    return gridSections(layout).find((section) => section.id === block.section)?.title ?? 'Section'
  }
  return kindOf(block?.kind)?.label ?? ''
}

/**
 * The SLA timer the header of the quick view shows: among those that run
 * against a time, the one that is over it by the most, or else the one with
 * the least left. `{ label, text, late }`, or null when none runs.
 */
export function nearestTimer(timers) {
  const running = list(timers).filter((timer) => timer?.state === 'running' && timer.dueS)
  if (running.length === 0) return null
  const left = (timer) => Number(timer.remainingS ?? timer.dueS - timer.elapsedS)
  const nearest = running.reduce((best, timer) => (left(timer) < left(best) ? timer : best))
  const late = Boolean(nearest.breached) || left(nearest) <= 0
  return {
    label: nearest.label,
    text: late ? `SLA ${span(-left(nearest))} over` : `SLA ${span(left(nearest))} left`,
    late,
  }
}

/** The numbers of the evidence (GET /api/incidents/<id>/quick, `counts`) with what each is called, in order. */
export function countFigures(counts) {
  const of = (key) => (Number.isFinite(counts?.[key]) ? counts[key] : 0)
  return [
    ['Browser events', of('browserEvents')],
    ['Commands', of('commands')],
    ['Endpoint artifacts', of('endpointArtifacts')],
    ['Flagged', of('flagged')],
    ['Bookmarks', of('bookmarks')],
    ['Notes', of('notes')],
  ]
}

/** The last entries of the War Room as lines of the quick view, newest first: `{ id, at, who, text, tone }`. */
export function lastLines(entries, limit = 3) {
  return list(entries)
    .slice(-limit)
    .reverse()
    .map((entry) => {
      const line = entryLine(entry)
      return {
        id: entry.id,
        at: entry.at,
        who: authorLabel(entry.author),
        text: [line.title, line.text].filter(Boolean).join(': '),
        tone: line.tone,
      }
    })
}
