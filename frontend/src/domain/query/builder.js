/*
 * A query as rows of a builder, and back.
 *
 * The value that is kept is always the text. The builder shows a text it can
 * represent: conditions joined by one of and / or, with at most one level of
 * groups. For anything else `toModel` gives null and the interface says
 * "edit as text".
 *
 *   model  = { join: 'and' | 'or', rows: (row | group)[] }
 *   group  = { join, rows: row[] }
 *   row    = { field, op, value, value2 }
 *            field '' is "any text"; op is one of OPS below; value2 is the
 *            upper end of `between`.
 */

import { tryParse } from './parse.js'
import { fieldOf, writeValue } from './complete.js'

export const OPS = [
  { id: '=', label: 'is', text: '' },
  { id: '!', label: 'is not', text: '!' },
  { id: '>', label: 'after / more than', text: '>' },
  { id: '>=', label: 'from / at least', text: '>=' },
  { id: '<', label: 'before / less than', text: '<' },
  { id: '<=', label: 'until / at most', text: '<=' },
  { id: 'between', label: 'between', text: '' },
  { id: 'empty', label: 'is empty', text: '' },
  { id: 'filled', label: 'holds something', text: '' },
]

const COMPARED = new Set(['number', 'date', 'ordered'])

/** The operators a field of this kind takes ("any text" and text fields: contains or not). */
export function opsFor(kind) {
  if (!kind) return OPS.filter((op) => op.id === '=' || op.id === '!')
  return OPS.filter((op) => COMPARED.has(kind) || !['>', '>=', '<', '<=', 'between'].includes(op.id)).filter(
    (op) => kind !== 'bool' || op.id === '=' || op.id === '!',
  )
}

/** How "is" reads for a kind of field. */
export function opLabel(op, kind) {
  if (!kind || kind === 'text') {
    if (op.id === '=') return 'contains'
    if (op.id === '!') return 'does not contain'
  }
  if (kind === 'tags') {
    if (op.id === '=') return 'has'
    if (op.id === '!') return 'has not'
  }
  return op.label
}

export const emptyRow = (field = '') => ({ field, op: '=', value: '', value2: '' })
export const emptyModel = () => ({ join: 'and', rows: [] })

/* ---- tree → model ---- */

/** A value as the builder edits it; null when it cannot be written back the same. */
function editable(value) {
  if (value === null) return ''
  // A wildcard next to something that needs quotes cannot be written: quotes make the star literal.
  if (value.pattern && /[\s()"]/.test(value.text)) return null
  // A star that was written literally (quoted or escaped) would come back as a wildcard.
  if (!value.pattern && /[*?]/.test(value.text)) return null
  return value.text
}

/** Text typed in a row, written as a value: wildcards stay wildcards unless the value needs quotes. */
function written(text) {
  if (text === '') return '""'
  return /[\s()"\\]/.test(text) ? writeValue(text) : text
}

const isAny = (value) => !value.quoted && value.pattern?.length === 1 && value.pattern[0].wild === '*'
const isEmpty = (value) => value.quoted && value.text === ''

function rowOf(node, negated = false) {
  if (node.not) return negated ? null : rowOf(node.not, true)
  if (node.and || node.or) return null
  if (node.range) {
    if (negated) return null
    const [low, high] = node.range.map(editable)
    if (low === null || high === null) return null
    return { field: node.field, op: 'between', value: low, value2: high }
  }
  if (node.field !== undefined) {
    if (isAny(node.value) || isEmpty(node.value)) {
      if (node.op !== '=' && node.op !== '!') return null
      const filled = isAny(node.value) === (node.op === '=') // field:* and field:!"" are "filled"
      return { field: node.field, op: filled !== negated ? 'filled' : 'empty', value: '', value2: '' }
    }
    const value = editable(node.value)
    if (value === null) return null
    if (negated && node.op !== '=' && node.op !== '!') return null
    const op = negated ? (node.op === '=' ? '!' : '=') : node.op
    return { field: node.field, op, value, value2: '' }
  }
  const value = editable(node.text)
  if (value === null) return null
  return { field: '', op: negated ? '!' : '=', value, value2: '' }
}

function groupOf(node) {
  const join = node.and ? 'and' : 'or'
  const rows = (node.and ?? node.or).map((item) => rowOf(item))
  return rows.includes(null) ? null : { join, rows }
}

/**
 * The model of a query text, or null when the builder cannot show it (it
 * cannot be read, or it nests deeper than one level of groups).
 */
export function toModel(text) {
  const { tree, error } = tryParse(text)
  if (error) return null
  if (tree === null) return emptyModel()
  if (!tree.and && !tree.or) {
    const row = rowOf(tree)
    return row ? { join: 'and', rows: [row] } : null
  }
  const join = tree.and ? 'and' : 'or'
  const rows = (tree.and ?? tree.or).map((item) => (item.and || item.or ? groupOf(item) : rowOf(item)))
  return rows.includes(null) ? null : { join, rows }
}

/* ---- model → text ---- */

/** A row is written only when it says something. */
export function isComplete(row) {
  if (row.op === 'empty' || row.op === 'filled') return Boolean(row.field)
  if (row.op === 'between') return Boolean(row.field) && (row.value !== '' || row.value2 !== '')
  return row.value !== ''
}

function rowText(row) {
  if (!isComplete(row)) return ''
  if (!row.field) return (row.op === '!' ? '-' : '') + written(row.value)
  if (row.op === 'empty') return `${row.field}:""`
  if (row.op === 'filled') return `${row.field}:*`
  if (row.op === 'between') {
    const end = (value) => (value === '' ? '*' : written(value))
    return `${row.field}:[${end(row.value)} TO ${end(row.value2)}]`
  }
  // "Is not" is written before the field.
  if (row.op === '!') return `!${row.field}:${written(row.value)}`
  const op = OPS.find((candidate) => candidate.id === row.op)?.text ?? ''
  return `${row.field}:${op}${written(row.value)}`
}

const joinText = (parts, join) => parts.filter(Boolean).join(join === 'or' ? ' or ' : ' ')

/** The query text of a model. Rows that are not filled in yet are left out. */
export function toText(model) {
  const parts = model.rows.map((item) => {
    if (!item.rows) return rowText(item)
    const inner = item.rows.map(rowText).filter(Boolean)
    if (inner.length === 0) return ''
    return inner.length === 1 ? inner[0] : `(${joinText(inner, item.join)})`
  })
  return joinText(parts, model.join)
}

/* ---- one condition of a query, for the filters that write it ---- */

const namesOf = (schema, field) => {
  const spec = fieldOf(schema, field)
  return new Set((spec ? [spec.name, ...spec.aliases] : [field]).map((name) => name.toLowerCase()))
}

const isField = (item, names) => !item.rows && names.has(String(item.field).toLowerCase())

/**
 * The condition a query holds on a field at its top level, as text
 * (`status:open`, `verdict:>=suspicious`), or '' when it holds none. Null
 * when the builder cannot read the query.
 */
export function conditionOn(text, field, schema = null) {
  const model = toModel(text)
  if (model === null) return null
  if (model.join === 'or' && model.rows.length > 1) return ''
  const names = namesOf(schema, field)
  const found = model.rows.find((item) => isField(item, names))
  return found ? rowText(found) : ''
}

/**
 * The query with its condition on a field replaced by `condition` (a piece of
 * query text; '' takes it away). A query the builder cannot show, or one
 * whose top level is a list of alternatives, is kept as it is written and the
 * condition is added to the whole.
 */
export function withCondition(text, field, condition, schema = null) {
  const source = String(text ?? '').trim()
  const piece = String(condition ?? '').trim()
  const model = toModel(source)
  if (model === null || (model.join === 'or' && model.rows.length > 1)) {
    if (!piece) return source
    return source ? `(${source}) ${piece}` : piece
  }
  const names = namesOf(schema, field)
  const kept = model.rows.filter((item) => !isField(item, names))
  return joinText([toText({ join: 'and', rows: kept }), piece], 'and')
}
