/*
 * Classifiers and mappers (/api/mappers, /api/classifiers) as their editor
 * reads them: the rows of the rules table, the rules a table gives back, a
 * sample read from what was pasted, and what a value looks like in a cell.
 */

export const ANY_TYPE = '*'

export const OPERATORS = [
  { id: 'eq', label: 'is' },
  { id: 'ne', label: 'is not' },
  { id: 'contains', label: 'contains' },
  { id: 'matches', label: 'matches the pattern' },
  { id: 'gt', label: 'is more than' },
  { id: 'gte', label: 'is at least' },
  { id: 'lt', label: 'is less than' },
  { id: 'lte', label: 'is at most' },
  { id: 'in', label: 'is one of' },
  { id: 'exists', label: 'is there' },
  { id: 'empty', label: 'is empty' },
]
const UNARY = new Set(['exists', 'empty'])

const text = (value) =>
  typeof value === 'string' ? value : value === null || value === undefined ? '' : JSON.stringify(value)

/** What a rule reads, as the text of its input: a template as it is, anything else as JSON. */
export const fromToText = text

/** What was typed for a rule: JSON when it reads as an object or a list, else the text. */
export function textToFrom(typed) {
  const value = String(typed ?? '').trim()
  if (/^[[{]/.test(value)) {
    try {
      return JSON.parse(value)
    } catch {
      return value
    }
  }
  return value
}

/**
 * The rows of an incoming mapper: one for each field Nik's side offers, in
 * the order of the table (those the type needs, then those that are mapped,
 * then the rest), each `{ name, label, type, required, from, authoritative,
 * group }` with `group` 'required' | 'mapped' | 'rest'.
 */
export function incomingRows(targets, rules) {
  const byName = Object.fromEntries((rules ?? []).map((rule) => [rule.to, rule]))
  const rows = (targets?.fields ?? []).map((field) => {
    const rule = byName[field.name]
    return {
      name: field.name,
      label: field.label,
      type: field.type,
      required: Boolean(field.required),
      from: rule ? text(rule.from) : '',
      authoritative: Boolean(rule?.authoritative),
      group: field.required ? 'required' : rule ? 'mapped' : 'rest',
    }
  })
  const order = { required: 0, mapped: 1, rest: 2 }
  return rows.sort((a, b) => order[a.group] - order[b.group])
}

/** The rules that write somewhere else than a field: context paths, `ext` fields. */
export function extraRows(targets, rules) {
  const fields = new Set((targets?.fields ?? []).map((field) => field.name))
  return (rules ?? []).filter((rule) => !fields.has(rule.to)).map((rule) => ({ to: rule.to, from: text(rule.from) }))
}

/** The rules a table of an incoming mapper gives back: the rows that read something. */
export function incomingRules(rows, extras) {
  const rules = (rows ?? [])
    .filter((row) => String(row.from ?? '').trim())
    .map((row) => ({ to: row.name, from: textToFrom(row.from), authoritative: Boolean(row.authoritative) }))
  for (const extra of extras ?? []) {
    if (String(extra.to ?? '').trim() && String(extra.from ?? '').trim()) {
      rules.push({ to: String(extra.to).trim(), from: textToFrom(extra.from), authoritative: false })
    }
  }
  return rules
}

/**
 * The rows of an outgoing mapper: the names the product takes (its schema)
 * and those the saved rules write besides, each `{ to, from, known }`.
 */
export function outgoingRows(schema, rules) {
  const byName = Object.fromEntries((rules ?? []).map((rule) => [rule.to, rule]))
  const names = (schema?.outgoing ?? []).map((field) => field.name)
  const rows = names.map((name) => ({ to: name, from: text(byName[name]?.from), known: true }))
  for (const rule of rules ?? []) {
    if (!names.includes(rule.to)) rows.push({ to: rule.to, from: text(rule.from), known: false })
  }
  return rows
}

export const outgoingRules = (rows) =>
  (rows ?? [])
    .filter((row) => String(row.to ?? '').trim() && String(row.from ?? '').trim())
    .map((row) => ({ to: String(row.to).trim(), from: textToFrom(row.from) }))

/** A field of the product put into an expression: an empty one becomes it, another has it added. */
export function withField(expression, name, root = 'item') {
  const path = String(name)
    .split('.')
    .map((part) => (/^[A-Za-z_][A-Za-z0-9_]*$/.test(part) ? `.${part}` : `[${JSON.stringify(part)}]`))
    .join('')
  const piece = `{{ ${root}${path} }}`
  const current = String(expression ?? '')
  return current.trim() ? `${current} ${piece}` : piece
}

/** A sample read from what was pasted: `{ item, problem }`. */
export function parseSample(pasted) {
  const value = String(pasted ?? '').trim()
  if (!value) return { item: null, problem: null }
  try {
    const item = JSON.parse(value)
    // A list of items was pasted: the first is the sample.
    return { item: Array.isArray(item) ? (item[0] ?? null) : item, problem: null }
  } catch (failure) {
    return { item: null, problem: `Not valid JSON: ${failure.message}` }
  }
}

/** A value as a cell shows it. */
export function cellText(value) {
  if (value === undefined || value === null || value === '') return ''
  if (typeof value === 'boolean') return value ? 'yes' : 'no'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

/** The fields of an item, by their dotted names, for the picker when the connector names none. */
export function fieldsOfSample(item, limit = 200) {
  const found = []
  const walk = (value, path) => {
    if (found.length >= limit) return
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      for (const [key, inner] of Object.entries(value)) walk(inner, path ? `${path}.${key}` : key)
    } else if (path) {
      found.push({ name: path, type: Array.isArray(value) ? 'list' : typeof value === 'number' ? 'number' : 'text' })
    }
  }
  walk(item, '')
  return found
}

/* ---------------------------------------------------------------- classifier */

/**
 * The rules of a classifier as rows: `{ left, op, right, type, kept }`. A
 * rule of one comparison is edited in the table; one of several is `kept`
 * as it is (written through the API) and shown as text.
 */
export function classifierRows(rules) {
  return (rules ?? []).map((rule) => {
    const group = rule.when?.all ?? rule.when?.any ?? []
    if (group.length === 1) {
      const [one] = group
      return { left: text(one.left), op: one.op, right: text(one.right), type: rule.type, kept: null }
    }
    return { left: '', op: 'eq', right: '', type: rule.type, kept: rule.when }
  })
}

const typed = (value) => {
  const trimmed = String(value ?? '').trim()
  if (/^-?\d+(\.\d+)?$/.test(trimmed)) return Number(trimmed)
  if (trimmed === 'true') return true
  if (trimmed === 'false') return false
  return trimmed
}

/** What PUT /api/classifiers/<id> takes as `rules`, from the rows; rows that compare nothing are left out. */
export function classifierRules(rows) {
  return (rows ?? [])
    .filter((row) => row.type && (row.kept || String(row.left ?? '').trim()))
    .map((row) =>
      row.kept
        ? { when: row.kept, type: row.type }
        : {
            when: {
              all: [
                UNARY.has(row.op)
                  ? { left: row.left.trim(), op: row.op }
                  : {
                      left: row.left.trim(),
                      op: row.op,
                      right: row.op === 'matches' ? String(row.right) : typed(row.right),
                    },
              ],
            },
            type: row.type,
          },
    )
}

export const isUnary = (op) => UNARY.has(op)

/** A condition of several comparisons, in a few words. */
export function conditionText(when) {
  const key = when?.any ? 'any' : 'all'
  const group = when?.[key] ?? []
  return `${key} of ${group.length}: ${group.map((item) => `${text(item.left)} ${item.op} ${text(item.right)}`.trim()).join('; ')}`
}
