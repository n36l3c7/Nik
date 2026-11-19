/*
 * The query language: text to a tree.
 *
 *   !status:closed severity:>=high owner:"" category IN (malware, "data loss")
 *
 * The twin of backend/app/query/parser.py: the same grammar, the same tree
 * (as plain data), the same error codes and positions. Both are checked
 * against backend/tests/data/query_vectors.json. The server decides what a
 * query means; this copy is what lets the interface colour it, complete it,
 * show it as rows of a builder and say what is wrong while it is typed.
 *
 *   query   := or
 *   or      := and ( "or" and )*
 *   and     := unary ( ["and"] unary )*
 *   unary   := ( "not" | "-" | "!" ) unary | group | term
 *   group   := "(" query ")"
 *   term    := field ":" [op] value | field ":" range | field list | value
 *   op      := ">=" | "<=" | ">" | "<" | "!"
 *   range   := "[" value " TO " value "]"
 *   list    := [ "not" ] "in" "(" value ( [","] value )* ")"
 *
 * "Is not" is written before the field (`!status:closed`); `status:!closed`,
 * the writing before 5.0, is still read and `modern()` rewrites it. A list
 * stands for the conditions it shortens: the tree holds those.
 */

export const MAX_LENGTH = 2000
export const MAX_DEPTH = 20
export const MAX_TERMS = 200

export const MESSAGES = {
  too_long: `The query is longer than ${MAX_LENGTH} characters`,
  too_deep: `The query nests more than ${MAX_DEPTH} levels`,
  too_many_terms: `The query has more than ${MAX_TERMS} conditions`,
  unclosed_quote: 'A quote is not closed: add the closing "',
  unclosed_group: 'A parenthesis is not closed: add the closing )',
  unexpected_close: 'A closing parenthesis has no opening one',
  empty_group: 'The parentheses hold nothing',
  missing_value: 'A value is expected after the colon',
  bad_range: 'A range is written [from TO to]',
  old_not: '"Is not" is written before the field: !status:closed',
  bad_list: 'A list is written IN (a, b, c)',
  dangling_operator: 'A condition is expected here',
}

export class QueryError extends Error {
  constructor(code, position) {
    super(MESSAGES[code])
    this.code = code
    this.position = position
  }
}

const SPACE = ' \t\r\n'
const OPS = ['>=', '<=', '>', '<', '!']
// What a backslash takes literally in a bare value; before anything else it is itself.
const ESCAPED = '*?()" '
const NAME = /[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/y

/**
 * `field IN (` and `field NOT IN (`, read after the name of a field: where its
 * words are (`not` is -1 when it is not there) and where the values start, or
 * null when what follows the name is not a list. Read a character at a time,
 * like the rest: no expression runs over what a person typed.
 *
 * @returns {{ not: number, in: number, paren: number, end: number, negated: boolean } | null}
 */
export function listOpening(text, at) {
  const spaces = (i) => {
    while (i < text.length && SPACE.includes(text[i])) i += 1
    return i
  }
  let i = spaces(at)
  if (i === at) return null
  let not = -1
  if (text.slice(i, i + 3).toLowerCase() === 'not') {
    const after = spaces(i + 3)
    if (after === i + 3) return null
    not = i
    i = after
  }
  if (text.slice(i, i + 2).toLowerCase() !== 'in') return null
  const word = i
  i = spaces(i + 2)
  if (text[i] !== '(') return null
  return { not, in: word, paren: i, end: i + 1, negated: not !== -1 }
}

const isSpace = (char) => char !== '' && SPACE.includes(char)

/** A value as plain data: `{ text, quoted }`, plus `pattern` when it holds wildcards. */
function valueOf(parts, quoted) {
  const text = parts.map((part) => (typeof part === 'string' ? part : part.wild)).join('')
  const value = { text, quoted }
  if (parts.some((part) => typeof part !== 'string')) value.pattern = parts
  return value
}

const isAny = (value) => !value.quoted && value.pattern?.length === 1 && value.pattern[0].wild === '*'

class Reader {
  constructor(text) {
    this.text = text
    this.i = 0
    this.terms = 0
    // Where "is not" is written as before 5.0 (`field:!value`): [start of the condition, its "!"].
    this.old = []
  }

  skip() {
    while (this.i < this.text.length && SPACE.includes(this.text[this.i])) this.i += 1
  }

  peek() {
    return this.i < this.text.length ? this.text[this.i] : ''
  }

  /** The connective at the cursor (`and`, `or`, `not`), or ''. */
  keyword() {
    for (const word of ['and', 'or', 'not']) {
      const end = this.i + word.length
      if (
        this.text.slice(this.i, end).toLowerCase() === word &&
        (end >= this.text.length || (SPACE + '()').includes(this.text[end]))
      ) {
        return word
      }
    }
    return ''
  }

  counted() {
    this.terms += 1
    if (this.terms > MAX_TERMS) throw new QueryError('too_many_terms', this.i)
  }

  ends() {
    return !this.peek() || this.peek() === ')' || ['and', 'or'].includes(this.keyword())
  }

  query(depth) {
    const nodes = [this.conjunction(depth)]
    for (;;) {
      this.skip()
      if (this.keyword() !== 'or') break
      const at = this.i
      this.i += 2
      this.skip()
      if (this.ends()) throw new QueryError('dangling_operator', at)
      nodes.push(this.conjunction(depth))
    }
    return nodes.length === 1 ? nodes[0] : { or: nodes }
  }

  conjunction(depth) {
    const nodes = []
    for (;;) {
      this.skip()
      if (!this.peek() || this.peek() === ')') break
      const word = this.keyword()
      if (word === 'or') {
        if (nodes.length === 0) throw new QueryError('dangling_operator', this.i)
        break
      }
      if (word === 'and') {
        const at = this.i
        this.i += 3
        this.skip()
        if (nodes.length === 0 || this.ends()) throw new QueryError('dangling_operator', at)
      }
      nodes.push(this.unary(depth))
    }
    if (nodes.length === 0) throw new QueryError('dangling_operator', this.i)
    return nodes.length === 1 ? nodes[0] : { and: nodes }
  }

  unary(depth) {
    if (depth > MAX_DEPTH) throw new QueryError('too_deep', this.i)
    if (this.keyword() === 'not') {
      const at = this.i
      this.i += 3
      this.skip()
      if (this.ends()) throw new QueryError('dangling_operator', at)
      return { not: this.unary(depth + 1) }
    }
    const next = this.i + 1 < this.text.length ? this.text[this.i + 1] : ''
    if (this.peek() === '-' && next !== '' && !isSpace(next) && next !== ')') {
      this.i += 1
      return { not: this.unary(depth + 1) }
    }
    if (this.peek() === '!' && next !== '' && !isSpace(next) && next !== ')') {
      const at = this.i
      this.i += 1
      const node = this.unary(depth + 1)
      // "Is not", empty fields included: one condition, not the negation of one.
      if (node.field && node.op === '=') return { ...node, op: '!', position: at }
      return { not: node }
    }
    if (this.peek() === '(') {
      const at = this.i
      this.i += 1
      this.skip()
      if (this.peek() === ')') throw new QueryError('empty_group', at)
      if (!this.peek()) throw new QueryError('unclosed_group', at)
      const node = this.query(depth + 1)
      this.skip()
      if (this.peek() !== ')') throw new QueryError('unclosed_group', at)
      this.i += 1
      return node
    }
    return this.term()
  }

  term() {
    const start = this.i
    this.counted()
    if (this.peek() === '"') return { text: this.quoted(), position: start }
    NAME.lastIndex = this.i
    const name = NAME.exec(this.text)
    if (name && this.text[NAME.lastIndex] === ':') {
      this.i = NAME.lastIndex + 1
      let op = '='
      for (const candidate of OPS) {
        if (this.text.startsWith(candidate, this.i)) {
          op = candidate
          if (op === '!') this.old.push([start, this.i])
          this.i += candidate.length
          break
        }
      }
      if (this.peek() === '[') {
        if (op !== '=') throw new QueryError('bad_range', this.i)
        return { field: name[0], range: this.range(), position: start }
      }
      const at = this.i
      const value = this.peek() === '"' ? this.quoted() : this.bare()
      if (!value.quoted && value.text === '' && !value.pattern) throw new QueryError('missing_value', at)
      return { field: name[0], op, value, position: start }
    }
    if (name) {
      const listed = listOpening(this.text, NAME.lastIndex)
      if (listed) return this.listed(name[0], start, listed.end, listed.negated)
    }
    return { text: this.bare(), position: start }
  }

  /** `field IN (a, b)`: the conditions it stands for, one for each value. */
  listed(field, start, opened, negated) {
    this.i = opened
    const terms = []
    for (;;) {
      while (this.peek() && (SPACE.includes(this.peek()) || this.peek() === ',')) this.i += 1
      if (!this.peek()) throw new QueryError('bad_list', start)
      if (this.peek() === ')') {
        this.i += 1
        break
      }
      if (terms.length > 0) this.counted()
      const value = this.peek() === '"' ? this.quoted() : this.bare(',')
      terms.push({ field, op: negated ? '!' : '=', value, position: start })
    }
    if (terms.length === 0) throw new QueryError('bad_list', start)
    if (terms.length === 1) return terms[0]
    return negated ? { and: terms } : { or: terms }
  }

  quoted() {
    const start = this.i
    this.i += 1
    let out = ''
    while (this.i < this.text.length) {
      const char = this.text[this.i]
      if (char === '\\' && this.i + 1 < this.text.length && '"\\'.includes(this.text[this.i + 1])) {
        out += this.text[this.i + 1]
        this.i += 2
      } else if (char === '"') {
        this.i += 1
        return { text: out, quoted: true }
      } else {
        out += char
        this.i += 1
      }
    }
    throw new QueryError('unclosed_quote', start)
  }

  /** Characters up to a space or the parenthesis that closes the group. */
  bare(stop = '') {
    const parts = []
    let run = ''
    let opened = 0
    const flush = () => {
      if (run) parts.push(run)
      run = ''
    }
    while (this.i < this.text.length) {
      const char = this.text[this.i]
      if (SPACE.includes(char) || (stop && stop.includes(char))) break
      if (char === ')') {
        if (opened === 0) break
        opened -= 1
      } else if (char === '(') {
        opened += 1
      }
      if (char === '\\' && this.i + 1 < this.text.length && ESCAPED.includes(this.text[this.i + 1])) {
        run += this.text[this.i + 1]
        this.i += 2
        continue
      }
      if (char === '*' || char === '?') {
        flush()
        // A run of stars is one star.
        const last = parts[parts.length - 1]
        if (!(char === '*' && last && typeof last !== 'string' && last.wild === '*')) parts.push({ wild: char })
      } else {
        run += char
      }
      this.i += 1
    }
    flush()
    return valueOf(parts, false)
  }

  range() {
    const start = this.i
    this.i += 1 // [
    const ends = []
    for (const index of [0, 1]) {
      this.skip()
      if (!this.peek() || this.peek() === ']') throw new QueryError('bad_range', start)
      const value = this.peek() === '"' ? this.quoted() : this.bare(']')
      ends.push(isAny(value) ? null : value)
      if (index === 0) {
        this.skip()
        const after = this.text.slice(this.i + 2, this.i + 3)
        if (this.text.slice(this.i, this.i + 2).toLowerCase() !== 'to' || (after !== ' ' && after !== '\t')) {
          throw new QueryError('bad_range', start)
        }
        this.i += 2
      }
    }
    this.skip()
    if (this.peek() !== ']') throw new QueryError('bad_range', start)
    this.i += 1
    return ends
  }
}

/**
 * The tree of a query; null for an empty one (it matches everything).
 * Throws QueryError with the position of what cannot be read.
 */
export function parse(text) {
  const { tree, reader } = read(text ?? '')
  // The writing before 5.0 (`status:!closed`): refused since 6.0, at its "!".
  if (reader.old.length) throw new QueryError('old_not', Math.min(...reader.old.map(([, bang]) => bang)))
  return tree
}

function read(source) {
  if (source.length > MAX_LENGTH) throw new QueryError('too_long', MAX_LENGTH)
  const reader = new Reader(source)
  reader.skip()
  if (!reader.peek()) return { tree: null, reader }
  const tree = reader.query(0)
  reader.skip()
  if (reader.peek() === ')') throw new QueryError('unexpected_close', reader.i)
  return { tree, reader }
}

/**
 * A query in today's writing: `status:!closed` becomes `!status:closed`. The
 * tree is the same. A query that cannot be read is given back as it is.
 */
export function modern(text) {
  let source = text ?? ''
  let old
  try {
    old = read(source).reader.old
  } catch (error) {
    if (!(error instanceof QueryError)) throw error
    return source
  }
  for (const [start, bang] of [...old].sort((a, b) => b[0] - a[0])) {
    source = `${source.slice(0, start)}!${source.slice(start, bang)}${source.slice(bang + 1)}`
  }
  return source
}

/** `{ tree }` or `{ error: { code, position, message } }`, without throwing. */
export function tryParse(text) {
  try {
    return { tree: parse(text), error: null }
  } catch (error) {
    if (!(error instanceof QueryError)) throw error
    return { tree: null, error: { code: error.code, position: error.position, message: error.message } }
  }
}
