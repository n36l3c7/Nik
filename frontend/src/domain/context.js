/*
 * The context of an incident (GET /api/incidents/<id>/context) as a tree to
 * read: what `{{ incident.… }}` and `{{ context.… }}` hold, with the path of
 * every value as a playbook writes it and who set it last.
 *
 * The common schema of the context is the server's (`schema` of the answer):
 * entities with fixed keys, the same whatever product a value came from.
 */

/** What an expression of a playbook reads from the incident, for the pickers of the canvas. */
export const INCIDENT_FIELDS = [
  ['id', 'text', 'Its id'],
  ['name', 'text', 'Its name'],
  ['type', 'text', 'The id of its type'],
  ['status', 'text', 'open, in_progress or closed'],
  ['severity', 'text', 'low, medium, high or critical'],
  ['owner', 'text', 'Who has it'],
  ['ticket', 'text', 'The ticket id'],
  ['host', 'text', 'The host'],
  ['username', 'text', 'The user'],
  ['tlp', 'text', 'Its TLP'],
  ['category', 'text', 'Its category'],
  ['tags', 'list', 'Its tags'],
  ['labels', 'list', 'Its tags, by the name of their field'],
  ['affected_hosts', 'list', 'The hosts it affects'],
  ['affected_users', 'list', 'The users it affects'],
  ['details', 'text', 'Its details'],
  ['occurred', 'text', 'When it occurred'],
].map(([name, type, description]) => ({ name, type, description }))

/** The entities of the common schema, for the pickers of the canvas (their first item). */
export const CONTEXT_FIELDS = [
  ['File', 'The files Nik analysed, and those commands found'],
  ['Mail', 'The e-mails'],
  ['URL', 'The addresses'],
  ['IP', 'IP addresses'],
  ['Domain', 'Domains'],
  ['Host', 'Hosts'],
  ['Account', 'Accounts'],
  ['Ticket', 'Tickets in other systems'],
  ['Alert', 'Alerts of other systems'],
  ['Process', 'Processes'],
  ['Rule', 'Rules that matched'],
].map(([name, description]) => ({ name, type: 'list', description }))

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/**
 * A key between quotes as the expressions of a playbook read one: a backslash before a
 * backslash and before a quote, `\n` and `\t` for a new line and a tab, everything else as
 * it is. (Not JSON: the expressions know no `\u00e9`, and read `\r` as the letter r.)
 */
function quoted(key) {
  const inside = key.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n').replace(/\t/g, '\\t')
  return `"${inside}"`
}

/** A step of a path as an expression writes it: `.name`, `["a key"]` or `[0]`. */
function step(key) {
  if (typeof key === 'number') return `[${key}]`
  return /^[A-Za-z_][A-Za-z0-9_]*$/.test(key) ? `.${key}` : `[${quoted(key)}]`
}

/** `context.Ticket[0].Number` from its steps. */
export const pathOf = (root, keys) => root + keys.map(step).join('')

/** The same path as a playbook writes it, and as the War Room's command line does. */
export const asExpression = (path) => `{{ ${path} }}`
export const asReference = (path) => `\${${path}}`

/** What tells an item of an entity apart, as the provenance names it: `Ticket:<key>`. */
export function itemKey(schema, entity, item) {
  const keys = schema?.[entity]?.key ?? []
  if (!keys.length || !isObject(item)) return null
  const parts = keys.map((key) => item[key])
  if (parts.some((part) => part === undefined || part === null || part === '')) return null
  return `${entity}:${parts.join('+')}`
}

/**
 * Who set a value last: `{ source, at }` or null. `keys` are the steps under
 * `context` (an entity, an index…): an item of an entity and everything in
 * it share the provenance of the item; so does a key under `ext`.
 */
export function provenanceOf(answer, keys) {
  const [first, second, third] = keys
  const known = answer?.provenance ?? {}
  if (first === 'ext') {
    return typeof second === 'string' && typeof third === 'string' ? (known[`ext.${second}.${third}`] ?? null) : null
  }
  if (typeof second !== 'number') return null
  const key = itemKey(answer?.schema, first, answer?.context?.[first]?.[second])
  return key ? (known[key] ?? null) : null
}

/** "Nik's analysis", "the connector servicenow", "anna", "a playbook run". */
export function sourceLabel(source) {
  const text = String(source ?? '')
  if (text === 'nik') return "Nik's analysis"
  if (text.startsWith('connector:')) return `the connector ${text.slice(10)}`
  if (text.startsWith('user:')) return text.slice(5)
  if (text.startsWith('run:')) return 'a playbook run'
  return text || 'unknown'
}

/** The id of the run that set a value, when one did. */
export const runOf = (source) => (String(source ?? '').startsWith('run:') ? String(source).slice(4) : null)

/**
 * The tree as rows to draw: `{ id, root, keys, depth, label, value, leaf, count }`
 * in reading order. `open` is the set of ids whose children are shown.
 * A query keeps the rows whose path or value holds it, with what leads to
 * them, and opens everything on the way.
 */
export function rows(answer, open, query = '') {
  const words = query.trim().toLowerCase()
  const out = []
  const walk = (root, keys, value, depth, label) => {
    const id = pathOf(root, keys)
    const leaf = !isObject(value) && !Array.isArray(value)
    const row = {
      id,
      root,
      keys,
      depth,
      label,
      leaf,
      value: leaf ? value : undefined,
      count: leaf ? 0 : Array.isArray(value) ? value.length : Object.keys(value).length,
      list: Array.isArray(value),
    }
    if (leaf) {
      const text = `${id} ${typeof value === 'string' ? value : JSON.stringify(value)}`.toLowerCase()
      if (!words || text.includes(words)) out.push(row)
      return
    }
    const at = out.length
    out.push(row)
    const shown = words ? true : open.has(id)
    if (shown) {
      const entries = Array.isArray(value) ? value.map((item, index) => [index, item]) : Object.entries(value)
      for (const [key, child] of entries) walk(root, [...keys, key], child, depth + 1, String(key))
    }
    // A branch that holds nothing the query asks for is not shown, unless its own path matches.
    if (words && out.length === at + 1 && !id.toLowerCase().includes(words)) out.pop()
  }
  walk('incident', [], answer?.incident ?? {}, 0, 'incident')
  walk('context', [], answer?.context ?? {}, 0, 'context')
  return out
}

/** The ids open at first: the two roots and the entities, so that what there is shows at a glance. */
export function openAtFirst(answer) {
  return new Set(['incident', 'context', ...Object.keys(answer?.context ?? {}).map((key) => pathOf('context', [key]))])
}

/** A value on one line. */
export function shown(value) {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'string') return value
  return JSON.stringify(value)
}

/** What a row of the tree holds: the value at its steps, a branch with everything under it. */
export function valueAt(answer, root, keys) {
  let value = answer?.[root]
  for (const key of keys) {
    if (value === null || value === undefined) return undefined
    value = value[key]
  }
  return value
}

/**
 * A value as it is copied: a text as it is, whole however long; a number, true, false and
 * null as they are written; an object or a list as JSON on several lines.
 */
export function copied(value) {
  if (value === undefined) return ''
  if (typeof value === 'string') return value
  if (value === null || typeof value !== 'object') return String(value)
  return JSON.stringify(value, null, 2)
}

/**
 * Where the keyboard goes from a row of the tree: `{ focus }` the id of the row to go to, or
 * `{ toggle }` the id of the branch to open or close. Up and down move by a row, Home and End
 * to the ends; right opens a closed branch, then steps into it; left closes an open branch,
 * and from anything else goes to what holds it.
 */
export function treeKey(list, open, id, key) {
  const at = list.findIndex((row) => row.id === id)
  if (at < 0) return {}
  const row = list[at]
  if (key === 'ArrowDown') return at + 1 < list.length ? { focus: list[at + 1].id } : {}
  if (key === 'ArrowUp') return at > 0 ? { focus: list[at - 1].id } : {}
  if (key === 'Home') return { focus: list[0].id }
  if (key === 'End') return { focus: list[list.length - 1].id }
  if (key === 'ArrowRight') {
    if (row.leaf) return {}
    if (!open.has(row.id)) return { toggle: row.id }
    return list[at + 1]?.depth > row.depth ? { focus: list[at + 1].id } : {}
  }
  if (key === 'ArrowLeft') {
    if (!row.leaf && open.has(row.id)) return { toggle: row.id }
    for (let index = at - 1; index >= 0; index -= 1) {
      if (list[index].depth < row.depth) return { focus: list[index].id }
    }
  }
  return {}
}
