/*
 * The {{ }} language of playbooks, as the server reads it
 * (backend/app/automation/expressions.py). Both parsers read the same
 * vectors: backend/tests/data/expressions.json.
 *
 *   template := (text | "{{" expr "}}")*
 *   expr     := path ( "|" filter )*
 *   path     := name ( "." name | "[" index "]" )*
 *   index    := integer | "*" | string
 *   filter   := name [ "(" arg ("," arg)* ")" ]
 *
 * Only paths and filters: no arithmetic, no comparisons, no code. The canvas
 * uses this to say where an expression is wrong while it is typed, to list
 * what a node reads, and to rewrite expressions when a node is renamed. The
 * server decides: what runs is what its own parser reads.
 */

export const MAX_TEMPLATE = 20_000
export const MAX_EXPRESSIONS = 200

export class ExpressionError extends Error {
  constructor(position, message) {
    super(message)
    this.name = 'ExpressionError'
    this.position = position
  }
}

export const MISSING = Symbol('MISSING')
export const STAR = Symbol('*')

const NAME = /[A-Za-z_][A-Za-z0-9_]*/y
const NUMBER = /-?\d+(?:\.\d+)?/y
const INTEGER = /-?\d+/y
const SPACE = ' \t\r\n'

function matchAt(pattern, text, index) {
  pattern.lastIndex = index
  const found = pattern.exec(text)
  return found ? found[0] : null
}

class Reader {
  constructor(text, i) {
    this.text = text
    this.i = i
  }

  skip() {
    while (this.i < this.text.length && SPACE.includes(this.text[this.i])) this.i += 1
  }

  peek(count = 1) {
    return this.text.slice(this.i, this.i + count)
  }

  fail(message, at = this.i) {
    throw new ExpressionError(at, message)
  }

  name() {
    const found = matchAt(NAME, this.text, this.i)
    if (!found) this.fail('A name is expected here')
    this.i += found.length
    return found
  }

  string() {
    const quote = this.text[this.i]
    const start = this.i
    this.i += 1
    let out = ''
    while (this.i < this.text.length) {
      const char = this.text[this.i]
      if (char === '\\' && this.i + 1 < this.text.length) {
        const next = this.text[this.i + 1]
        out += next === 'n' ? '\n' : next === 't' ? '\t' : next
        this.i += 2
      } else if (char === quote) {
        this.i += 1
        return out
      } else {
        out += char
        this.i += 1
      }
    }
    return this.fail('A quote is not closed', start)
  }

  literal() {
    if (this.peek() === '"' || this.peek() === "'") return this.string()
    const number = matchAt(NUMBER, this.text, this.i)
    if (number) {
      this.i += number.length
      return Number(number)
    }
    for (const [word, value] of [
      ['true', true],
      ['false', false],
      ['null', null],
    ]) {
      if (this.text.startsWith(word, this.i) && !/[A-Za-z_]/.test(this.text[this.i + word.length] ?? '')) {
        this.i += word.length
        return value
      }
    }
    return this.fail('A text in quotes, a number, true, false or null is expected here')
  }

  path() {
    const root = this.name()
    const steps = []
    for (;;) {
      if (this.peek() === '.') {
        this.i += 1
        steps.push(this.name())
      } else if (this.peek() === '[') {
        this.i += 1
        this.skip()
        if (this.peek() === '*') {
          this.i += 1
          steps.push(STAR)
        } else if (this.peek() === '"' || this.peek() === "'") {
          steps.push(this.string())
        } else {
          const index = matchAt(INTEGER, this.text, this.i)
          if (!index) this.fail('A number, * or a text in quotes is expected between the brackets')
          this.i += index.length
          steps.push(Number(index))
        }
        this.skip()
        if (this.peek() !== ']') this.fail('A bracket is not closed: add ]')
        this.i += 1
      } else {
        return { root, steps }
      }
    }
  }

  filter() {
    const at = this.i
    const name = this.name()
    if (!Object.hasOwn(FILTERS, name)) this.fail(`There is no filter "${name}"`, at)
    const args = []
    const named = []
    if (this.peek() === '(') {
      this.i += 1
      this.skip()
      while (this.peek() !== ')') {
        const key = matchAt(NAME, this.text, this.i)
        const rest = key ? this.text.slice(this.i + key.length).replace(/^[ \t\r\n]+/, '') : ''
        if (key && rest.startsWith('=') && !['true', 'false', 'null'].includes(key)) {
          this.i += key.length
          this.skip()
          this.i += 1 // =
          this.skip()
          named.push([key, this.literal()])
        } else {
          args.push(this.literal())
        }
        this.skip()
        if (this.peek() === ',') {
          this.i += 1
          this.skip()
        } else if (this.peek() !== ')') {
          this.fail('A comma or a closing parenthesis is expected here')
        }
      }
      this.i += 1
    }
    return { name, args, named, position: at }
  }

  expression(start) {
    this.skip()
    const rootAt = this.i
    const { root, steps } = this.path()
    const filters = []
    this.skip()
    while (this.peek() === '|') {
      this.i += 1
      this.skip()
      filters.push(this.filter())
      this.skip()
    }
    if (this.peek(2) !== '}}') {
      this.fail(this.i >= this.text.length ? 'The expression is not closed: add }}' : '}} is expected here')
    }
    this.i += 2
    return { root, rootAt, steps, filters, position: start, end: this.i }
  }
}

/** A template as its parts: text (strings) and expressions (objects). Throws ExpressionError. */
export function parse(template) {
  const text = String(template ?? '')
  if (text.length > MAX_TEMPLATE) {
    throw new ExpressionError(MAX_TEMPLATE, `The text is longer than ${MAX_TEMPLATE} characters`)
  }
  const parts = []
  let i = 0
  let count = 0
  for (;;) {
    const start = text.indexOf('{{', i)
    if (start === -1) {
      if (i < text.length) parts.push(text.slice(i))
      return parts
    }
    if (start > i) parts.push(text.slice(i, start))
    count += 1
    if (count > MAX_EXPRESSIONS)
      throw new ExpressionError(start, `More than ${MAX_EXPRESSIONS} expressions in one text`)
    const expr = new Reader(text, start + 2).expression(start)
    parts.push(expr)
    i = expr.end
  }
}

/** What is wrong with a text as a template: `{ position, message }`, or null. */
export function problemOf(template) {
  if (typeof template !== 'string' || !template.includes('{{')) return null
  try {
    parse(template)
    return null
  } catch (error) {
    if (error instanceof ExpressionError) return { position: error.position, message: error.message }
    throw error
  }
}

/**
 * The root names the expressions of a value (a text, or a structure of
 * texts) read: `[{ name, position }]`. Throws ExpressionError on a text that
 * cannot be read.
 */
export function references(value) {
  if (typeof value === 'string') {
    if (!value.includes('{{')) return []
    return parse(value)
      .filter((part) => typeof part !== 'string')
      .map((part) => ({ name: part.root, position: part.position }))
  }
  if (Array.isArray(value)) return value.flatMap(references)
  if (value && typeof value === 'object') return Object.values(value).flatMap(references)
  return []
}

/** `value` with every expression that reads `from` reading `to` instead (texts that cannot be read are left). */
export function renameRoot(value, from, to) {
  if (typeof value === 'string') {
    if (!value.includes('{{')) return value
    let parts
    try {
      parts = parse(value)
    } catch {
      return value
    }
    let out = value
    for (const part of parts.filter((item) => typeof item !== 'string' && item.root === from).reverse()) {
      out = out.slice(0, part.rootAt) + to + out.slice(part.rootAt + from.length)
    }
    return out
  }
  if (Array.isArray(value)) return value.map((item) => renameRoot(item, from, to))
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, renameRoot(item, from, to)]))
  }
  return value
}

// --------------------------------------------------------------------------- //
// Filters: pure functions of data                                             //
// --------------------------------------------------------------------------- //
const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/** A value as the text a template shows. */
export function text(value) {
  if (value === null || value === undefined || value === MISSING) return ''
  if (typeof value === 'boolean') return value ? 'true' : 'false'
  if (typeof value === 'object') return JSON.stringify(value)
  return String(value)
}

const listed = (value) => (value === null || value === undefined ? [] : Array.isArray(value) ? value : [value])
const fold = (value) => text(value).toLowerCase()

function same(a, b) {
  if (a === b) return true
  if (typeof a === 'boolean' && typeof b === 'number') return Number(a) === b
  if (typeof b === 'boolean' && typeof a === 'number') return Number(b) === a
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return false
  if (Array.isArray(a) !== Array.isArray(b)) return false
  const keysA = Object.keys(a)
  if (keysA.length !== Object.keys(b).length) return false
  return keysA.every((key) => Object.hasOwn(b, key) && same(a[key], b[key]))
}

function fail() {
  throw new TypeError('not applicable')
}

function toFloat(value) {
  if (typeof value === 'number') return value
  if (typeof value === 'boolean') return Number(value)
  if (typeof value === 'string' && /^\s*[+-]?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?\s*$/.test(value)) return Number(value)
  return fail()
}

/** `a.b.0.c` in nested data; MISSING when it leads nowhere. */
export function lookup(data, path) {
  let current = data
  for (const part of String(path).split('.')) {
    if (part === '') continue
    if (isObject(current) && Object.hasOwn(current, part)) current = current[part]
    else if (Array.isArray(current) && /^-*\d+$/.test(part)) {
      const index = Number(part.replace(/^-+/, (signs) => (signs.length ? '-' : '')))
      if (index < -current.length || index >= current.length) return MISSING
      current = current.at(index)
    } else return MISSING
  }
  return current
}

/** The operators of a condition (and of the `where` filter). */
export function compare(left, op, right) {
  if (op === 'exists') return left !== null && left !== undefined && left !== MISSING
  if (op === 'empty') {
    return (
      left === null ||
      left === undefined ||
      left === MISSING ||
      left === '' ||
      (Array.isArray(left) && left.length === 0) ||
      (isObject(left) && Object.keys(left).length === 0)
    )
  }
  const value = left === MISSING || left === undefined ? null : left
  if (op === 'eq' || op === 'ne') {
    const equal = same(value, right) || (fold(value) === fold(right) && (value === null || typeof value !== 'object'))
    return equal === (op === 'eq')
  }
  if (['gt', 'gte', 'lt', 'lte'].includes(op)) {
    let a
    let b
    try {
      a = toFloat(value)
      b = toFloat(right)
    } catch {
      a = text(value)
      b = text(right)
    }
    return { gt: a > b, gte: a >= b, lt: a < b, lte: a <= b }[op]
  }
  if (op === 'contains') {
    if (Array.isArray(value)) return value.some((item) => compare(item, 'eq', right))
    return fold(value).includes(fold(right))
  }
  if (op === 'in') return listed(right).some((item) => compare(value, 'eq', item))
  throw new TypeError(`There is no operator "${op}"`)
}

const falsy = (value) =>
  value === MISSING ||
  value === null ||
  value === false ||
  value === '' ||
  value === 0 ||
  (Array.isArray(value) && value.length === 0) ||
  (isObject(value) && Object.keys(value).length === 0)

function defang(value) {
  if (Array.isArray(value)) return value.map(defang)
  return text(value).replaceAll('http', 'hxxp').replaceAll('://', '[://]').replaceAll('.', '[.]').replaceAll('@', '[@]')
}

const pad = (number, width = 2) => String(number).padStart(width, '0')
const DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday']
const MONTHS = [
  'January',
  'February',
  'March',
  'April',
  'May',
  'June',
  'July',
  'August',
  'September',
  'October',
  'November',
  'December',
]
const ISO = /^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d{1,6})?)?(?:Z|[+-]\d{2}:?\d{2})?)?$/

function date(value, format = '%Y-%m-%d %H:%M') {
  if (typeof format !== 'string' || format.length > 60) fail()
  let moment
  if (typeof value === 'number') moment = new Date(value * 1000)
  else {
    const source = text(value)
    if (!ISO.test(source)) fail()
    const withTime = source.length === 10 ? `${source}T00:00:00` : source.replace(' ', 'T')
    moment = new Date(/(Z|[+-]\d{2}:?\d{2})$/.test(withTime) ? withTime : `${withTime}Z`)
  }
  if (Number.isNaN(moment.getTime())) fail()
  const fields = {
    Y: moment.getUTCFullYear(),
    y: pad(moment.getUTCFullYear() % 100),
    m: pad(moment.getUTCMonth() + 1),
    d: pad(moment.getUTCDate()),
    H: pad(moment.getUTCHours()),
    M: pad(moment.getUTCMinutes()),
    S: pad(moment.getUTCSeconds()),
    A: DAYS[moment.getUTCDay()],
    a: DAYS[moment.getUTCDay()].slice(0, 3),
    B: MONTHS[moment.getUTCMonth()],
    b: MONTHS[moment.getUTCMonth()].slice(0, 3),
    Z: 'UTC',
    z: '+0000',
    '%': '%',
  }
  return format.replace(/%(.)/g, (whole, letter) => (Object.hasOwn(fields, letter) ? String(fields[letter]) : whole))
}

function sorted(value) {
  const items = [...listed(value)]
  const numbers = items.every((item) => typeof item === 'number' || typeof item === 'boolean')
  const strings = items.every((item) => typeof item === 'string')
  if (numbers) return items.sort((a, b) => Number(a) - Number(b))
  if (strings) return items.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0))
  return items.sort((a, b) => (text(a) < text(b) ? -1 : text(a) > text(b) ? 1 : 0))
}

function unique(value) {
  const seen = []
  for (const item of listed(value)) if (!seen.some((kept) => same(kept, item))) seen.push(item)
  return seen
}

function mapped(value, named) {
  const pairs = named.filter(([key]) => key !== 'else')
  const fallback = named.find(([key]) => key === 'else')
  for (const [key, result] of pairs) if (fold(value) === key.toLowerCase()) return result
  return fallback ? fallback[1] : value
}

function toInt(value) {
  const number = toFloat(value)
  if (!Number.isFinite(number)) fail()
  return Math.trunc(number)
}

const length = (value) =>
  typeof value === 'string'
    ? [...value].length
    : Array.isArray(value)
      ? value.length
      : isObject(value)
        ? Object.keys(value).length
        : 0

/*
 * Each filter: how many arguments it takes besides the value (`[least, most]`)
 * and the function. `named: true` lets it take name=value pairs (only "map").
 * `default` is handled by the evaluator: it is the one that takes a missing value.
 */
const FILTERS = {
  default: { args: [0, 1], run: null },
  length: { args: [0, 0], run: length },
  join: { args: [0, 1], run: (v, sep = ', ') => listed(v).map(text).join(text(sep)) },
  lower: { args: [0, 0], run: (v) => text(v).toLowerCase() },
  upper: { args: [0, 0], run: (v) => text(v).toUpperCase() },
  trim: { args: [0, 0], run: (v) => text(v).trim() },
  first: { args: [0, 0], run: (v) => listed(v)[0] ?? null },
  last: { args: [0, 0], run: (v) => listed(v).at(-1) ?? null },
  unique: { args: [0, 0], run: unique },
  sort: { args: [0, 0], run: sorted },
  json: { args: [0, 0], run: (v) => JSON.stringify(v) },
  defang: { args: [0, 0], run: defang },
  date: { args: [0, 1], run: date },
  get: {
    args: [1, 1],
    run: (v, path) => {
      const found = lookup(v, path)
      return found === MISSING ? null : found
    },
  },
  map: { args: [0, 0], named: true, run: (v, named) => mapped(v, named) },
  split: {
    args: [0, 1],
    run: (v, sep = ',') =>
      text(v)
        .split(text(sep) || ',')
        .map((part) => part.trim())
        .filter(Boolean),
  },
  replace: {
    args: [1, 2],
    run: (v, old, fresh = '') => (text(old) ? text(v).replaceAll(text(old), text(fresh)) : fail()),
  },
  add: {
    args: [0, 1],
    run: (v, amount = 1) => (typeof v === 'number' && typeof amount === 'number' ? v + amount : fail()),
  },
  int: { args: [0, 0], run: toInt },
  float: { args: [0, 0], run: toFloat },
  bool: { args: [0, 0], run: (v) => !falsy(v) && !['false', 'no', '0', 'off'].includes(text(v).toLowerCase()) },
  keys: { args: [0, 0], run: (v) => (isObject(v) ? Object.keys(v) : []) },
  values: { args: [0, 0], run: (v) => (isObject(v) ? Object.values(v) : []) },
  where: {
    args: [1, 3],
    run: (v, key, op = null, wanted = null) =>
      op === null
        ? listed(v).filter((item) => !falsy(lookup(item, key)))
        : listed(v).filter((item) => compare(lookup(item, key), op, wanted)),
  },
  pluck: {
    args: [1, 1],
    run: (v, key) =>
      listed(v).map((item) => {
        const found = lookup(item, key)
        return found === MISSING ? null : found
      }),
  },
}

/** The filters there are, for the editor's hints. */
export const FILTER_NAMES = Object.keys(FILTERS)

// --------------------------------------------------------------------------- //
// Evaluating                                                                  //
// --------------------------------------------------------------------------- //
function walk(data, steps) {
  let current = data
  for (let index = 0; index < steps.length; index += 1) {
    const step = steps[index]
    if (step === STAR) {
      if (!Array.isArray(current)) return MISSING
      const rest = steps.slice(index + 1)
      const out = []
      for (const item of current) {
        const found = walk(item, rest)
        if (found === MISSING) continue
        // One level is flattened: the tags of every item are one list of tags.
        if (Array.isArray(found)) out.push(...found)
        else out.push(found)
      }
      return out
    }
    if (typeof step === 'number') {
      if (!Array.isArray(current) || step < -current.length || step >= current.length) return MISSING
      current = current.at(step)
    } else if (isObject(current) && Object.hasOwn(current, step)) current = current[step]
    else return MISSING
  }
  return current
}

/** The path of an expression as it is written. */
export function pathText(expr) {
  let out = expr.root
  for (const step of expr.steps) {
    if (typeof step === 'string' && /^[A-Za-z_][A-Za-z0-9_]*$/.test(step)) out += `.${step}`
    else out += `[${step === STAR ? '*' : JSON.stringify(step)}]`
  }
  return out
}

function apply(filter, data) {
  const spec = FILTERS[filter.name]
  const [least, most] = spec.args
  if (filter.args.length < least || filter.args.length > most) fail()
  if (filter.named.length && !spec.named) fail()
  return spec.named ? spec.run(data, filter.named) : spec.run(data, ...filter.args)
}

function evaluate(expr, scope) {
  if (!Object.hasOwn(scope, expr.root)) {
    throw new ExpressionError(expr.position, `"${expr.root}" is not a name that can be read here`)
  }
  let data = walk(scope[expr.root], expr.steps)
  for (const filter of expr.filters) {
    if (filter.name === 'default') {
      if (data === MISSING || data === null) data = filter.args.length ? filter.args[0] : ''
      continue
    }
    if (data === MISSING) break
    try {
      data = apply(filter, data)
    } catch (error) {
      if (error instanceof ExpressionError) throw error
      throw new ExpressionError(filter.position, `The filter "${filter.name}" cannot be applied to this value`)
    }
  }
  if (data === MISSING) {
    throw new ExpressionError(
      expr.position,
      `There is nothing at ${pathText(expr)}: add | default(…) if it may be absent`,
    )
  }
  return data
}

/**
 * A text with its expressions replaced by what `scope` (name → data) holds.
 * Exactly one expression and nothing else keeps the type of what it names.
 */
export function renderText(template, scope) {
  const source = String(template ?? '')
  if (!source.includes('{{')) return source
  const parts = parse(source)
  if (parts.length === 1 && typeof parts[0] !== 'string') return evaluate(parts[0], scope)
  return parts.map((part) => (typeof part === 'string' ? part : text(evaluate(part, scope)))).join('')
}

/** A structure with every text in it rendered. */
export function render(value, scope) {
  if (typeof value === 'string') return renderText(value, scope)
  if (Array.isArray(value)) return value.map((item) => render(item, scope))
  if (isObject(value)) return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, render(item, scope)]))
  return value
}
