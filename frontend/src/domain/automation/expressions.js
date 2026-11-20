/*
 * The {{ }} language of playbooks, as the server reads it
 * (backend/app/automation/expressions.py). Both parsers read the same
 * vectors: backend/tests/data/expressions.json.
 *
 *   template := (text | "{{" expr "}}")*
 *   expr     := and ( "or" and )*
 *   and      := not ( "and" not )*
 *   not      := "not" not | compared
 *   compared := joined [ ("==" | "!=" | "<" | "<=" | ">" | ">=" | "in" | "not" "in") joined ]
 *   joined   := sum ( "~" sum )*
 *   sum      := product ( ("+" | "-") product )*
 *   product  := signed ( ("*" | "/") signed )*
 *   signed   := "-" signed | piped
 *   piped    := value ( "|" filter )*
 *   value    := path | string | number | true | false | null
 *             | "[" [ expr ("," expr)* ] "]" | "(" expr ")" | function "(" expr ("," expr)* ")"
 *   path     := name ( "." name | "[" index "]" )*
 *   index    := integer | "*" | string
 *   filter   := name [ "(" arg ("," arg)* ")" ]
 *   arg      := expr | name "=" expr
 *
 * Paths, filters, comparisons, and / or / not, in, the four operations on
 * numbers, ~ to join texts, lists and four functions (if, first_of, min,
 * max): no code. The canvas uses this to say where an expression is wrong
 * while it is typed, to list what a node reads, and to rewrite expressions
 * when a node is renamed. The server decides: what runs is what its own
 * parser reads.
 */

export const MAX_TEMPLATE = 20_000
export const MAX_EXPRESSIONS = 200
const MAX_STRING = 1_000_000
const MAX_NODES = 200 // the parts of one expression: values, operators, filters' arguments
const MAX_NESTING = 40 // parentheses, lists and arguments inside one another
const MAX_NUMBER = 1e15 // beyond it the two parsers would not count alike
const MAX_COMPARED = 1_000_000 // items of one list times items of the other, for the filters that compare them all

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

const WORDS = { true: true, false: false, null: null }
const COMPARISONS = [
  ['==', 'eq'],
  ['!=', 'ne'],
  ['<=', 'lte'],
  ['>=', 'gte'],
  ['<', 'lt'],
  ['>', 'gt'],
]
// What a name followed by a parenthesis may be, and how many values each takes.
const FUNCTIONS = { if: [2, 3], first_of: [1, 40], min: [1, 40], max: [1, 40] }
const ARITY = {
  if: 'if takes a condition, the value when it holds and, if wanted, the value when it does not',
  first_of: 'first_of takes one value at least',
  min: 'min takes one value at least',
  max: 'max takes one value at least',
}
// One of these where a value is expected, by where it is: the wording of before there were operators is kept.
const A_NAME = 'A name is expected here'
const A_LITERAL = 'A text in quotes, a number, true, false or null is expected here'

function matchAt(pattern, text, index) {
  pattern.lastIndex = index
  const found = pattern.exec(text)
  return found ? found[0] : null
}

class Reader {
  constructor(text, i) {
    this.text = text
    this.i = i
    this.depth = 0
    this.nodes = 0
    this.paths = []
  }

  skip() {
    while (this.i < this.text.length && SPACE.includes(this.text[this.i])) this.i += 1
  }

  peek(count = 1) {
    return this.text.slice(this.i, this.i + count)
  }

  fail(message, at = this.i) {
    throw new ExpressionError(at ?? this.i, message)
  }

  name() {
    const found = matchAt(NAME, this.text, this.i)
    if (!found) this.fail(A_NAME)
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

  // ------------------------------------------------------------ operators --
  /** Whether the word `wanted` is next (after spaces), as a whole word; nothing is consumed. */
  word(wanted) {
    let at = this.i
    while (at < this.text.length && SPACE.includes(this.text[at])) at += 1
    return matchAt(NAME, this.text, at) === wanted
  }

  /** Consume the word `wanted` and give where it was. */
  take(wanted) {
    this.skip()
    const at = this.i
    this.i += wanted.length
    return at
  }

  /** Count what an expression is made of: its evaluation walks every part, so there is a most. */
  made(node) {
    this.nodes += 1
    if (this.nodes > MAX_NODES) this.fail('The expression is too long: compute it in several steps')
    return node
  }

  deeper() {
    this.depth += 1
    if (this.depth > MAX_NESTING) this.fail('The expression nests too deep')
  }

  either(message) {
    let left = this.both(message)
    while (this.word('or')) {
      const at = this.take('or')
      this.skip()
      left = this.made({ type: 'binary', op: 'or', left, right: this.both(A_NAME), position: at })
    }
    return left
  }

  both(message) {
    let left = this.negation(message)
    while (this.word('and')) {
      const at = this.take('and')
      this.skip()
      left = this.made({ type: 'binary', op: 'and', left, right: this.negation(A_NAME), position: at })
    }
    return left
  }

  negation(message) {
    // "not" is the operator unless it is the start of a path (a node may be called "not").
    if (this.word('not') && !['.', '['].includes(this.text.slice(this.i + 3, this.i + 4))) {
      const at = this.take('not')
      this.skip()
      this.deeper()
      const node = this.made({ type: 'unary', op: 'not', operand: this.negation(A_NAME), position: at })
      this.depth -= 1
      return node
    }
    return this.comparison(message)
  }

  comparison(message) {
    const left = this.joined(message)
    this.skip()
    const at = this.i
    const sign = COMPARISONS.find(([symbol]) => this.peek(symbol.length) === symbol)
    let op
    if (sign) {
      op = sign[1]
      this.i += sign[0].length
    } else if (this.word('in')) {
      this.take('in')
      op = 'in'
    } else if (this.word('not')) {
      this.take('not')
      if (!this.word('in')) {
        this.i = at
        return left
      }
      this.take('in')
      op = 'not_in'
    } else {
      return left
    }
    this.skip()
    return this.made({ type: 'binary', op, left, right: this.joined(A_NAME), position: at })
  }

  /** One level of operators that go from left to right: `signs` between what `next` reads. */
  chain(message, signs, next) {
    let left = next.call(this, message)
    for (;;) {
      this.skip()
      if (!signs.includes(this.peek()) || this.peek() === '') return left
      const at = this.i
      this.i += 1
      this.skip()
      left = this.made({ type: 'binary', op: this.text[at], left, right: next.call(this, A_NAME), position: at })
    }
  }

  joined(message) {
    return this.chain(message, ['~'], this.summed)
  }

  summed(message) {
    return this.chain(message, ['+', '-'], this.multiplied)
  }

  multiplied(message) {
    return this.chain(message, ['*', '/'], this.signed)
  }

  signed(message) {
    if (this.peek() === '-' && matchAt(NUMBER, this.text, this.i) === null) {
      const at = this.i
      this.i += 1
      this.skip()
      this.deeper()
      const node = this.made({ type: 'unary', op: 'neg', operand: this.signed(A_NAME), position: at })
      this.depth -= 1
      return node
    }
    return this.piped(message)
  }

  /** A value and the filters that follow it: a filter applies to what is just before it. */
  piped(message) {
    const operand = this.primary(message)
    const filters = []
    for (;;) {
      this.skip()
      if (this.peek() !== '|') break
      this.i += 1
      this.skip()
      filters.push(this.filter())
    }
    return filters.length ? this.made({ type: 'piped', operand, filters }) : operand
  }

  primary(message) {
    const char = this.peek()
    if (char === '(') {
      const start = this.i
      this.i += 1
      this.skip()
      this.deeper()
      const node = this.either(A_NAME)
      this.depth -= 1
      this.skip()
      if (this.peek() !== ')') {
        this.fail('A parenthesis is not closed: add )', this.i >= this.text.length ? start : this.i)
      }
      this.i += 1
      return node
    }
    if (char === '[') {
      this.i += 1
      this.skip()
      this.deeper()
      const items = []
      while (this.peek() !== ']') {
        items.push(this.either(A_LITERAL))
        this.skip()
        if (this.peek() === ',') {
          this.i += 1
          this.skip()
        } else if (this.peek() !== ']') {
          this.fail('A comma or a closing bracket is expected here')
        }
      }
      this.i += 1
      this.depth -= 1
      return this.made({ type: 'list', items })
    }
    if (char === '"' || char === "'") return this.made({ type: 'literal', value: this.string() })
    const number = matchAt(NUMBER, this.text, this.i)
    if (number) {
      this.i += number.length
      return this.made({ type: 'literal', value: Number(number) })
    }
    const word = matchAt(NAME, this.text, this.i)
    if (!word) this.fail(message)
    const after = this.text.slice(this.i + word.length, this.i + word.length + 1)
    if (Object.hasOwn(WORDS, word) && after !== '.' && after !== '[') {
      this.i += word.length
      return this.made({ type: 'literal', value: WORDS[word] })
    }
    if (after === '(') return this.call(word)
    const at = this.i
    const { root, steps } = this.path()
    const node = { type: 'path', root, rootAt: at, steps, position: at }
    this.paths.push(node)
    return this.made(node)
  }

  /** What is between the parentheses of a filter or of a function, the opening one being next. */
  arguments(named) {
    this.i += 1
    this.skip()
    this.deeper()
    const args = []
    while (this.peek() !== ')') {
      const key = matchAt(NAME, this.text, this.i)
      const rest = key ? this.text.slice(this.i + key.length).replace(/^[ \t\r\n]+/, '') : ''
      if (named && key && rest.startsWith('=') && !rest.startsWith('==') && !Object.hasOwn(WORDS, key)) {
        this.i += key.length
        this.skip()
        this.i += 1 // =
        this.skip()
        named.push([key, this.either(A_LITERAL)])
      } else {
        args.push(this.either(A_LITERAL))
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
    this.depth -= 1
    return args
  }

  call(name) {
    const at = this.i
    if (!Object.hasOwn(FUNCTIONS, name)) this.fail(`There is no function "${name}"`, at)
    this.i += name.length
    const args = this.arguments(null)
    const [least, most] = FUNCTIONS[name]
    if (args.length < least || args.length > most) this.fail(ARITY[name], at)
    return this.made({ type: 'call', name, args, position: at })
  }

  filter() {
    const at = this.i
    const name = this.name()
    if (!Object.hasOwn(FILTERS, name)) this.fail(`There is no filter "${name}"`, at)
    const named = []
    const args = this.peek() === '(' ? this.arguments(named) : []
    return { name, args, named, position: at }
  }

  expression(start) {
    this.skip()
    const node = this.either(A_NAME)
    this.skip()
    if (this.peek(2) !== '}}') {
      this.fail(this.i >= this.text.length ? 'The expression is not closed: add }}' : '}} is expected here')
    }
    this.i += 2
    // When the expression is one path (with or without filters), what it reads is said as before.
    const one = node.type === 'piped' ? node.operand : node
    const path = one.type === 'path' ? one : null
    return {
      node,
      paths: this.paths,
      root: path ? path.root : '',
      rootAt: path ? path.rootAt : -1,
      steps: path ? path.steps : [],
      filters: node.type === 'piped' ? node.filters : [],
      position: start,
      end: this.i,
    }
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
 * texts) read, one for each path: `[{ name, position }]`, the position being
 * that of the expression. Throws ExpressionError on a text that cannot be read.
 */
export function references(value) {
  if (typeof value === 'string') {
    if (!value.includes('{{')) return []
    return parse(value)
      .filter((part) => typeof part !== 'string')
      .flatMap((part) => part.paths.map((path) => ({ name: path.root, position: part.position })))
  }
  if (Array.isArray(value)) return value.flatMap(references)
  if (value && typeof value === 'object') return Object.values(value).flatMap(references)
  return []
}

/** `value` with every path that reads `from` reading `to` instead (texts that cannot be read are left). */
export function renameRoot(value, from, to) {
  if (typeof value === 'string') {
    if (!value.includes('{{')) return value
    let parts
    try {
      parts = parse(value)
    } catch {
      return value
    }
    const places = parts
      .filter((item) => typeof item !== 'string')
      .flatMap((item) => item.paths)
      .filter((path) => path.root === from)
      .map((path) => path.rootAt)
      .sort((a, b) => b - a)
    let out = value
    for (const at of places) out = out.slice(0, at) + to + out.slice(at + from.length)
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

/** A moment as it is written: a number of seconds since 1970, or an ISO 8601 text (UTC when it names no zone). */
function moment(value) {
  let found
  if (typeof value === 'number') found = new Date(value * 1000)
  else {
    const source = text(value)
    if (!ISO.test(source)) fail()
    const withTime = source.length === 10 ? `${source}T00:00:00` : source.replace(' ', 'T')
    found = new Date(/(Z|[+-]\d{2}:?\d{2})$/.test(withTime) ? withTime : `${withTime}Z`)
  }
  if (Number.isNaN(found.getTime())) fail()
  return found
}

function date(value, format = '%Y-%m-%d %H:%M') {
  if (typeof format !== 'string' || format.length > 60) fail()
  const at = moment(value)
  const fields = {
    Y: at.getUTCFullYear(),
    y: pad(at.getUTCFullYear() % 100),
    m: pad(at.getUTCMonth() + 1),
    d: pad(at.getUTCDate()),
    H: pad(at.getUTCHours()),
    M: pad(at.getUTCMinutes()),
    S: pad(at.getUTCSeconds()),
    A: DAYS[at.getUTCDay()],
    a: DAYS[at.getUTCDay()].slice(0, 3),
    B: MONTHS[at.getUTCMonth()],
    b: MONTHS[at.getUTCMonth()].slice(0, 3),
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

function mapped(value, named, flat = []) {
  if (flat.length % 2) fail()
  const pairs = named.filter(([key]) => key !== 'else')
  const fallback = named.find(([key]) => key === 'else')
  // What is not a name is given as pairs, one after the other: map('1', 'open', '2', 'closed').
  for (let at = 0; at < flat.length; at += 2) if (fold(value) === text(flat[at]).toLowerCase()) return flat[at + 1]
  for (const [key, result] of pairs) if (fold(value) === key.toLowerCase()) return result
  return fallback ? fallback[1] : value
}

function toInt(value) {
  const number = toFloat(value)
  if (!Number.isFinite(number)) fail()
  return Math.trunc(number)
}

const SEVERITY_WORDS = {
  informational: 'low',
  info: 'low',
  none: 'low',
  low: 'low',
  minor: 'low',
  trivial: 'low',
  lowest: 'low',
  medium: 'medium',
  moderate: 'medium',
  warning: 'medium',
  normal: 'medium',
  high: 'high',
  major: 'high',
  important: 'high',
  critical: 'critical',
  severe: 'critical',
  highest: 'critical',
  blocker: 'critical',
  urgent: 'critical',
  fatal: 'critical',
}

/** A severity of another product as Nik's (the server's `_severity`): words, 1 to 5, 0 to 100. */
function severity(value, scale = '') {
  const word = text(value).trim().toLowerCase()
  if (!word) return ''
  if (Object.hasOwn(SEVERITY_WORDS, word)) return SEVERITY_WORDS[word]
  const first = word.split(' ')[0].replace(/^[p-]+|[p-]+$/g, '')
  if (!/^[+-]?(\d+\.?\d*|\.\d+)(e[+-]?\d+)?$/.test(first)) return ''
  const number = Number(first)
  if (!Number.isFinite(number) || number < 0) return ''
  const inverse = text(scale).trim().toLowerCase() === 'inverse'
  if (number <= 5) {
    // As Python rounds: a half goes to the even number.
    const floor = Math.floor(number)
    const rounded = number - floor === 0.5 ? (floor % 2 === 0 ? floor : floor + 1) : Math.round(number)
    const step = Math.max(1, Math.min(5, rounded || 1))
    const up = ['low', 'low', 'medium', 'high', 'critical']
    const down = ['critical', 'high', 'medium', 'low', 'low']
    return (inverse ? down : up)[step - 1]
  }
  return number < 25 ? 'low' : number < 50 ? 'medium' : number < 75 ? 'high' : 'critical'
}

/** The part of a text a pattern finds, or a group of it; '' when it finds none. */
function regexExtract(value, pattern, group = 0) {
  const source = text(pattern)
  if (!source || source.length > 500) fail()
  let found
  try {
    // The server's patterns are Python's: a named group is (?P<name>…) there, (?<name>…) here.
    found = new RegExp(source.replace(/\(\?P</g, '(?<')).exec(text(value).slice(0, 100_000))
  } catch {
    fail()
  }
  if (!found) return ''
  const part = typeof group === 'string' ? found.groups?.[group] : found[Math.trunc(Number(group))]
  if (typeof group === 'string' ? !found.groups || !(group in found.groups) : !(Math.trunc(Number(group)) in found))
    fail()
  return part ?? ''
}

const length = (value) =>
  typeof value === 'string'
    ? [...value].length
    : Array.isArray(value)
      ? value.length
      : isObject(value)
        ? Object.keys(value).length
        : 0

// --------------------------------------------------------------------------- //
// Counting and deciding (6.5): as the server computes them, number for number  //
// --------------------------------------------------------------------------- //
const numeric = (value) => (typeof value === 'number' ? value : fail())

/** A number that was computed: never beyond what the two parsers count alike. */
function tidy(number) {
  if (!Number.isFinite(number) || Math.abs(number) > MAX_NUMBER) fail()
  return number === 0 ? 0 : number
}

/** `in`: an item of a list, a part of a text, a key of an object. */
function contained(left, right) {
  if (typeof right === 'string') return right.toLowerCase().includes(fold(left))
  if (isObject(right)) return Object.hasOwn(right, text(left))
  return listed(right).some((item) => compare(left, 'eq', item))
}

/** To so many decimals, a half away from zero (2.5 is 3, -2.5 is -3). */
function round(value, digits = 0) {
  const number = numeric(value)
  if (!Number.isInteger(digits) || digits < 0 || digits > 10) fail()
  const scale = 10 ** digits
  const out = Math.floor(Math.abs(number) * scale + 0.5) / scale
  return tidy(number < 0 ? -out : out)
}

const numbers = (value) => listed(value).map(numeric)
const total = (value) => tidy(numbers(value).reduce((sum, item) => sum + item, 0))
const smallest = (value) => numbers(value).reduce((kept, item) => (kept === null || item < kept ? item : kept), null)
const largest = (value) => numbers(value).reduce((kept, item) => (kept === null || item > kept ? item : kept), null)

function percent(value, whole, digits = 0) {
  const part = numeric(value)
  return numeric(whole) === 0 ? 0 : round((part * 100) / whole, digits)
}

function both(value, other) {
  const left = listed(value)
  const right = listed(other)
  if (left.length * right.length > MAX_COMPARED) fail()
  return [left, right]
}

function intersect(value, other) {
  const [left, right] = both(value, other)
  return left.filter((item) => right.some((wanted) => compare(item, 'eq', wanted)))
}

function without(value, other) {
  const [left, right] = both(value, other)
  return left.filter((item) => !right.some((wanted) => compare(item, 'eq', wanted)))
}

/** The items of the list, then those of the other that it does not have already. */
function union(value, other) {
  const [left, right] = both(value, other)
  return [...left, ...right.filter((item) => !left.some((have) => compare(item, 'eq', have)))]
}

function hasAll(value, other) {
  const [left, right] = both(value, other)
  return right.every((wanted) => left.some((item) => compare(item, 'eq', wanted)))
}

/** A count with its noun: "1 report", "2 reports". A list counts as its length. */
function plural(value, one, many = null) {
  const number = Array.isArray(value) ? value.length : isObject(value) ? Object.keys(value).length : numeric(value)
  const noun = number === 1 ? text(one) : many === null ? `${text(one)}s` : text(many)
  return `${text(number)} ${noun}`
}

function limit(value, count) {
  if (!Number.isInteger(count) || count < 0) fail()
  return Array.isArray(value) ? value.slice(0, count) : [...text(value)].slice(0, count).join('')
}

const fieldOf = (item, path) => {
  const value = lookup(item, text(path))
  return value === MISSING ? null : value
}

/** Each item as a new object: pick(name='attributes.name', id='id'). One object gives one object. */
function pick(value, named, flat = []) {
  if (!named.length || flat.length) fail()
  const shaped = (item) => Object.fromEntries(named.map(([key, path]) => [key, fieldOf(item, path)]))
  return Array.isArray(value) ? value.map(shaped) : shaped(value)
}

/** The items in the order of one of their fields: numbers as numbers, anything else as text. */
function sortBy(value, key, order = 'asc') {
  if (!['asc', 'desc'].includes(text(order))) fail()
  const items = listed(value)
  let keys = items.map((item) => fieldOf(item, key))
  if (!keys.every((item) => typeof item === 'number')) keys = keys.map(text)
  const ordered = (a, b) => (keys[a] < keys[b] ? -1 : keys[a] > keys[b] ? 1 : 0)
  return items
    .map((_item, at) => at)
    .sort(text(order) === 'desc' ? (a, b) => ordered(b, a) : ordered)
    .map((at) => items[at])
}

const SHA_K = [
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98,
  0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8,
  0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819,
  0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
  0xc67178f2,
]

/** The SHA-256 of a text (its UTF-8 bytes), in hexadecimal: the preview cannot wait for the browser's own. */
function sha256(value) {
  const bytes = [...new TextEncoder().encode(text(value))]
  const bits = bytes.length * 8
  bytes.push(0x80)
  while (bytes.length % 64 !== 56) bytes.push(0)
  for (let shift = 56; shift >= 0; shift -= 8) bytes.push(Math.floor(bits / 2 ** shift) & 0xff)
  const hash = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
  const rotate = (word, by) => (word >>> by) | (word << (32 - by))
  const words = new Array(64)
  for (let block = 0; block < bytes.length; block += 64) {
    for (let at = 0; at < 64; at += 1) {
      if (at < 16) {
        const from = block + at * 4
        words[at] = (bytes[from] << 24) | (bytes[from + 1] << 16) | (bytes[from + 2] << 8) | bytes[from + 3] | 0
      } else {
        const a = words[at - 15]
        const b = words[at - 2]
        const low = rotate(a, 7) ^ rotate(a, 18) ^ (a >>> 3)
        const high = rotate(b, 17) ^ rotate(b, 19) ^ (b >>> 10)
        words[at] = (words[at - 16] + low + words[at - 7] + high) | 0
      }
    }
    let [a, b, c, d, e, f, g, h] = hash
    for (let at = 0; at < 64; at += 1) {
      const first =
        (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) + ((e & f) ^ (~e & g)) + SHA_K[at] + words[at]) | 0
      const second = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) | 0
      h = g
      g = f
      f = e
      e = (d + first) | 0
      d = c
      c = b
      b = a
      a = (first + second) | 0
    }
    const mixed = [a, b, c, d, e, f, g, h]
    for (let at = 0; at < 8; at += 1) hash[at] = (hash[at] + mixed[at]) | 0
  }
  return hash.map((word) => (word >>> 0).toString(16).padStart(8, '0')).join('')
}

const UNITS = { second: 1, minute: 60, hour: 3600, day: 86_400, week: 604_800 }

function unit(name) {
  const key = text(name).trim().toLowerCase().replace(/s$/, '')
  return Object.hasOwn(UNITS, key) ? UNITS[key] : fail()
}

function dateAdd(value, amount, name = 'days') {
  const seconds = Math.floor(moment(value).getTime() / 1000 + numeric(amount) * unit(name))
  const later = new Date(seconds * 1000)
  if (Number.isNaN(later.getTime()) || later.getUTCFullYear() < 1 || later.getUTCFullYear() > 9999) fail()
  return date(seconds, '%Y-%m-%dT%H:%M:%SZ')
}

/*
 * Each filter: how many arguments it takes besides the value (`[least, most]`)
 * and the function. `named: true` lets it take name=value pairs ("map" and "pick").
 * `default` is handled by the evaluator: it is the one that takes a missing value.
 */
const FILTERS = {
  default: { args: [0, 1], run: null },
  // Whether the value is in a list by its name: only the server holds the lists, so a preview says no.
  in_list: { args: [1, 1], run: () => false },
  severity: { args: [0, 1], run: severity },
  regex_extract: { args: [1, 2], run: regexExtract },
  // As the server writes them: everything but letters, digits and -._~ percent-encoded.
  urlencode: {
    args: [0, 0],
    run: (v) =>
      encodeURIComponent(text(v)).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`),
  },
  base64url: {
    args: [0, 0],
    run: (v) => {
      const bytes = new TextEncoder().encode(text(v))
      let binary = ''
      for (const byte of bytes) binary += String.fromCharCode(byte)
      return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
    },
  },
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
  map: { args: [0, 60], named: true, run: (v, named, flat) => mapped(v, named, flat) },
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
  round: { args: [0, 1], run: round },
  abs: { args: [0, 0], run: (v) => Math.abs(numeric(v)) },
  sum: { args: [0, 0], run: total },
  min: { args: [0, 0], run: smallest },
  max: { args: [0, 0], run: largest },
  percent: { args: [1, 2], run: percent },
  count: {
    args: [0, 3],
    run: (v, key = null, op = null, wanted = null) =>
      key === null ? listed(v).length : FILTERS.where.run(v, key, op, wanted).length,
  },
  intersect: { args: [1, 1], run: intersect },
  without: { args: [1, 1], run: without },
  union: { args: [1, 1], run: union },
  has_any: { args: [1, 1], run: (v, other) => intersect(v, other).length > 0 },
  has_all: { args: [1, 1], run: hasAll },
  plural: { args: [1, 2], run: plural },
  starts_with: { args: [1, 1], run: (v, start) => fold(v).startsWith(fold(start)) },
  ends_with: { args: [1, 1], run: (v, end) => fold(v).endsWith(fold(end)) },
  limit: { args: [1, 1], run: limit },
  entries: {
    args: [0, 0],
    run: (v) => (isObject(v) ? Object.entries(v).map(([key, value]) => ({ key, value })) : []),
  },
  pick: { args: [0, 0], named: true, run: pick },
  sort_by: { args: [1, 2], run: sortBy },
  sha256: { args: [0, 0], run: sha256 },
  timestamp: { args: [0, 0], run: (v) => Math.floor(moment(v).getTime() / 1000) },
  date_add: { args: [1, 2], run: dateAdd },
  date_diff: {
    args: [1, 2],
    run: (v, other, name = 'days') =>
      Math.trunc((moment(v).getTime() - moment(other).getTime()) / 1000 / unit(name)) || 0,
  },
}

/** The filters there are, for the editor's hints. */
export const FILTER_NAMES = Object.keys(FILTERS)

/** The functions there are: a name followed by a parenthesis is one of them. */
export const FUNCTION_NAMES = Object.keys(FUNCTIONS)

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

function apply(filter, data, args, named) {
  const spec = FILTERS[filter.name]
  const [least, most] = spec.args
  if (args.length < least || args.length > most) fail()
  if (named.length && !spec.named) fail()
  return spec.named ? spec.run(data, named, args) : spec.run(data, ...args)
}

/** `value`, unless it is a path that led nowhere and nothing took its place. */
function present(value, node, expr) {
  if (value === MISSING) {
    const path = node.type === 'piped' ? node.operand : node
    throw new ExpressionError(
      expr.position,
      `There is nothing at ${pathText(path)}: add | default(…) if it may be absent`,
    )
  }
  return value
}

/**
 * What a part of an expression gives. A path that leads nowhere gives MISSING, which only
 * `default`, `first_of` and the condition of `if` accept: everything else asks `present`.
 */
function compute(node, scope, expr) {
  const strict = (part) => present(compute(part, scope, expr), part, expr)
  switch (node.type) {
    case 'literal':
      return node.value
    case 'path':
      if (!Object.hasOwn(scope, node.root)) {
        throw new ExpressionError(expr.position, `"${node.root}" is not a name that can be read here`)
      }
      return walk(scope[node.root], node.steps)
    case 'piped': {
      let data = compute(node.operand, scope, expr)
      for (const filter of node.filters) {
        if (filter.name === 'default') {
          // Read only when it is needed: the other value may be absent too.
          if (data === MISSING || data === null) data = filter.args.length ? strict(filter.args[0]) : ''
          continue
        }
        if (data === MISSING) break
        const args = filter.args.map(strict)
        const named = filter.named.map(([key, arg]) => [key, strict(arg)])
        try {
          data = apply(filter, data, args, named)
        } catch (error) {
          if (error instanceof ExpressionError) throw error
          throw new ExpressionError(filter.position, `The filter "${filter.name}" cannot be applied to this value`)
        }
      }
      return data
    }
    case 'list':
      return node.items.map(strict)
    case 'unary': {
      const value = strict(node.operand)
      if (node.op === 'not') return falsy(value)
      if (typeof value !== 'number') {
        throw new ExpressionError(node.position, 'Only a number has an opposite: use | int or | float on a text')
      }
      return value === 0 ? 0 : -value
    }
    case 'call': {
      if (node.name === 'if') {
        const chosen = !falsy(compute(node.args[0], scope, expr)) ? node.args[1] : node.args[2]
        return chosen === undefined ? null : strict(chosen)
      }
      if (node.name === 'first_of') {
        for (const arg of node.args) {
          const value = compute(arg, scope, expr)
          if (!compare(value, 'empty', null)) return value
        }
        return null
      }
      const values = node.args.map(strict)
      try {
        return (node.name === 'min' ? smallest : largest)(values.length === 1 ? values[0] : values)
      } catch {
        throw new ExpressionError(node.position, `${node.name} takes numbers`)
      }
    }
    default:
  }
  const left = strict(node.left)
  if (node.op === 'or' || node.op === 'and') {
    // As a person reads it: the right side is not looked at when the left one decides.
    return !falsy(left) === (node.op === 'or') ? left : strict(node.right)
  }
  const right = strict(node.right)
  if (node.op === 'in' || node.op === 'not_in') return contained(left, right) === (node.op === 'in')
  if (node.op === '~') {
    const joined = text(left) + text(right)
    if (joined.length > MAX_STRING) throw new ExpressionError(node.position, 'The text this gives is too long')
    return joined
  }
  if (['+', '-', '*', '/'].includes(node.op)) {
    if (typeof left !== 'number' || typeof right !== 'number') {
      throw new ExpressionError(
        node.position,
        `"${node.op}" takes two numbers: use | int or | float on a text, ~ to join texts`,
      )
    }
    if (node.op === '/' && right === 0) throw new ExpressionError(node.position, 'A number cannot be divided by zero')
    const result =
      node.op === '+' ? left + right : node.op === '-' ? left - right : node.op === '*' ? left * right : left / right
    if (!Number.isFinite(result) || Math.abs(result) > MAX_NUMBER) {
      throw new ExpressionError(node.position, 'The number this gives is too large')
    }
    return result
  }
  return compare(left, node.op, right)
}

function evaluate(expr, scope) {
  return present(compute(expr.node, scope, expr), expr.node, expr)
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
