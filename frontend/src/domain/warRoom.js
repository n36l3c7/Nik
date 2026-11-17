/*
 * The War Room of an incident (GET /api/incidents/<id>/war-room) as the
 * screen reads it: what a line says, what the inspector draws of a result.
 */

/** The chips of the stream, in order. */
export const FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'notes', label: 'Notes' },
  { id: 'commands', label: 'Commands' },
  { id: 'automation', label: 'Automation' },
  { id: 'evidence', label: 'Evidence' },
]

export const EVIDENCE = 'evidence'

const isFlat = (value) => value === null || ['string', 'number', 'boolean'].includes(typeof value)
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Who wrote an entry, as it is shown: a person, the engine, a connector. */
export function authorLabel(author) {
  const text = String(author ?? '')
  if (text === 'nik-automation') return 'automation'
  if (text.startsWith('connector:')) return text.slice(10)
  return text || 'nik'
}

/**
 * What a line of the stream says: `{ title, text, tone }`. `tone` is
 * 'note' | 'ok' | 'error' | 'ask' | 'command' | 'system'.
 */
export function entryLine(entry) {
  const body = entry?.body ?? {}
  switch (entry?.kind) {
    case 'note':
      return { title: '', text: String(body.text ?? ''), tone: 'note' }
    case 'command':
      return {
        title: String(body.line ?? ''),
        text: body.status === 'refused' ? String(body.error ?? '') : '',
        tone: 'command',
      }
    case 'result':
      return {
        title: String(body.title ?? body.what ?? 'A step'),
        text: body.playbook && !body.adhoc ? `playbook ${body.playbook}` : String(body.what ?? ''),
        tone: 'ok',
      }
    case 'error':
      return {
        title: String(body.title ?? body.what ?? 'A step'),
        text: String(body.error ?? 'It failed'),
        tone: 'error',
      }
    case 'approval': {
      const said =
        body.answer === 'approved' ? 'approved' : body.answer === 'refused' ? 'refused' : 'not answered in time'
      return {
        title: String(body.question ?? 'An approval'),
        text: body.comment ? `${said}: ${body.comment}` : said,
        tone: body.answer === 'approved' ? 'ok' : 'ask',
      }
    }
    case 'task': {
      const title = String(body.title ?? 'A task')
      if (body.state === 'asked') return { title, text: `a task for ${body.for ?? 'anyone'}`, tone: 'ask' }
      if (body.state === 'given') return { title, text: `given to ${body.for ?? 'anyone'}`, tone: 'ask' }
      if (body.state === 'skipped') {
        return { title, text: body.comment ? `skipped: ${body.comment}` : 'skipped', tone: 'system' }
      }
      const said = [body.answer, body.comment].filter(Boolean).join(' · ')
      return { title, text: said ? `done: ${said}` : 'done', tone: 'ok' }
    }
    default:
      return { title: '', text: String(body.text ?? body.title ?? ''), tone: 'system' }
  }
}

/**
 * A result as a table, when it is one: a list of objects whose values are
 * all plain (texts, numbers, yes/no). `{ columns, rows }`, or null. An object
 * with exactly one such list (the usual shape of a command's result) is read
 * as that list.
 */
export function asTable(value) {
  let items = value
  if (isObject(value)) {
    const lists = Object.values(value).filter((item) => Array.isArray(item) && item.length > 0 && item.every(isObject))
    if (lists.length !== 1) return null
    ;[items] = lists
  }
  if (!Array.isArray(items) || items.length === 0 || !items.every(isObject)) return null
  if (!items.every((item) => Object.values(item).every(isFlat))) return null
  const columns = []
  for (const item of items) for (const key of Object.keys(item)) if (!columns.includes(key)) columns.push(key)
  if (columns.length === 0 || columns.length > 12) return null
  return { columns, rows: items }
}

/** What a step wrote to the context, from the line its log keeps. */
export function contextWrites(log) {
  const line = String(log ?? '')
    .split('\n')
    .find((item) => item.startsWith('[nik] written to the context: '))
  if (!line) return []
  return line
    .slice('[nik] written to the context: '.length)
    .split(', ')
    .map((item) => item.trim())
    .filter(Boolean)
}

/** A cell of a result table. */
export function cell(value) {
  if (value === null || value === undefined) return ''
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  return String(value)
}

/** Whether an entry can be opened in the inspector with more than it shows in the stream. */
export const hasDetail = (entry) => Boolean(entry?.stepId) || entry?.kind !== 'note'

/** The entries with their answers under them: a command first, then what it gave. */
export function threaded(entries) {
  const list = Array.isArray(entries) ? entries : []
  const ids = new Set(list.map((entry) => entry.id))
  const children = new Map()
  for (const entry of list) {
    if (entry.parentId && ids.has(entry.parentId)) {
      children.set(entry.parentId, [...(children.get(entry.parentId) ?? []), entry])
    }
  }
  return list
    .filter((entry) => !(entry.parentId && ids.has(entry.parentId)))
    .flatMap((entry) => [
      { ...entry, depth: 0 },
      ...(children.get(entry.id) ?? []).map((child) => ({ ...child, depth: 1 })),
    ])
}
