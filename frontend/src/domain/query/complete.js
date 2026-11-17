/*
 * What to offer while a query is typed: the fields of the entity at the start
 * of a condition, the values of a field after its colon. The schema is what
 * GET /api/query/schema returns for the entity.
 */

import { tokenAt, tokenize } from './tokenize.js'

const DATE_VALUES = [
  { value: 'today', detail: 'the whole day' },
  { value: 'yesterday', detail: 'the day before' },
  { value: 'now-24h', detail: '24 hours ago' },
  { value: 'now-7d', detail: '7 days ago' },
  { value: 'now-30d', detail: '30 days ago' },
]
const BOOL_VALUES = [{ value: 'true' }, { value: 'false' }]
const MAX_ITEMS = 12

/** The field of a schema by its name or one of its other names (case does not matter). */
export function fieldOf(schema, name) {
  const wanted = String(name ?? '').toLowerCase()
  return (
    schema?.fields?.find(
      (field) => field.name.toLowerCase() === wanted || field.aliases.some((alias) => alias.toLowerCase() === wanted),
    ) ?? null
  )
}

/** Candidates that start with the prefix first, then those that hold it. */
function rank(items, prefix, key) {
  const wanted = prefix.toLowerCase()
  if (!wanted) return items
  const starts = items.filter((item) => key(item).toLowerCase().startsWith(wanted))
  const holds = items.filter((item) => !starts.includes(item) && key(item).toLowerCase().includes(wanted))
  return [...starts, ...holds]
}

function valuesOf(field) {
  if (field.kind === 'bool') return BOOL_VALUES
  if (field.kind === 'date') return DATE_VALUES
  return field.values.map((value) => ({ value }))
}

/** A value as it must be written: quoted when it holds a space or a character the grammar reads. */
export function writeValue(value) {
  const text = String(value)
  if (text !== '' && !/[\s()"*?\\]/.test(text)) return text
  return `"${text.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`
}

/**
 * @param {string} text    the query
 * @param {number} caret   where the caret is
 * @param {object} schema  one entity of GET /api/query/schema
 * @param {{ force?: boolean }} [options]  `force`: asked for (Ctrl+Space), so an empty word lists every field
 * @returns {{ from: number, to: number, items: { label, insert, detail, kind }[] } | null}
 *   Replace `text.slice(from, to)` with an item's `insert`.
 */
export function completions(text, caret, schema, { force = false } = {}) {
  if (!schema) return null
  const source = String(text ?? '')
  const tokens = tokenize(source)
  const token = tokenAt(tokens, caret)

  // After "field:": its values.
  if (token && (token.type === 'value' || token.type === 'op') && token.field) {
    const field = fieldOf(schema, token.field)
    if (!field) return null
    const from = token.type === 'op' ? token.end : token.start
    const to = token.type === 'op' ? token.end : token.end
    const typed = token.type === 'value' ? source.slice(token.start, caret).replace(/^"/, '') : ''
    const exact = valuesOf(field).some((item) => item.value === typed)
    const items = rank(valuesOf(field), typed, (item) => item.value)
      .filter(() => !exact || force)
      .slice(0, MAX_ITEMS)
      .map((item) => ({ label: item.value, insert: writeValue(item.value), detail: item.detail ?? '', kind: 'value' }))
    return items.length ? { from, to, items } : null
  }

  // At the start of a condition: the fields.
  const word = token && token.type === 'text' ? token : null
  if (token && !word) return null
  const prefix = word ? source.slice(word.start, caret) : ''
  if (!prefix && !force) return null
  if (word && caret < word.end) return null // the caret is inside a word: nothing is cut in two
  const names = schema.fields.flatMap((field) => [
    { name: field.name, field },
    ...field.aliases
      .filter((alias) => prefix && alias.toLowerCase().startsWith(prefix.toLowerCase()))
      .map((alias) => ({ name: alias, field })),
  ])
  const seen = new Set()
  const items = rank(names, prefix, (item) => item.name)
    .filter((item) => (seen.has(item.field.name) ? false : seen.add(item.field.name)))
    .slice(0, MAX_ITEMS)
    .map((item) => ({
      label: item.name,
      insert: `${item.name}:`,
      detail: item.field.description,
      kind: 'field',
    }))
  if (items.length === 0) return null
  return { from: word ? word.start : caret, to: word ? word.end : caret, items }
}

/** The text and the caret after an item is taken. A field stays open for its value. */
export function applyCompletion(text, completion, item) {
  const source = String(text ?? '')
  const tail = source.slice(completion.to)
  const space = item.kind === 'value' && !/^\s/.test(tail) ? ' ' : ''
  const next = source.slice(0, completion.from) + item.insert + space + tail
  return { text: next, caret: completion.from + item.insert.length + space.length }
}
