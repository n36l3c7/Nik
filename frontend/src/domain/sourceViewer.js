/*
 * What the viewer of a source says and draws (components/evidence/SourceViewer.jsx): the pages of the
 * original, its bytes as a dump, the XML of a record as tokens, the place a record has in its file.
 * Nothing here builds HTML: tokens and lines are data, the component draws them as text.
 */

import { hexOffset } from './sourceFiles.js'

export const PAGE_BYTES = 65536
const ROW = 16

/**
 * An offset as typed: `0x1A00` or `1A00h` is hex, anything else must be a decimal number. Underscores and
 * spaces are ignored. A whole number, or null.
 */
export function parseOffset(text) {
  const clean = String(text ?? '')
    .trim()
    .replace(/[\s_,]/g, '')
  let value = null
  if (/^0x[0-9a-f]+$/i.test(clean)) value = Number.parseInt(clean.slice(2), 16)
  else if (/^[0-9a-f]+h$/i.test(clean)) value = Number.parseInt(clean.slice(0, -1), 16)
  else if (/^[0-9]+$/.test(clean)) value = Number.parseInt(clean, 10)
  return Number.isSafeInteger(value) && value >= 0 ? value : null
}

/** Where the page that shows `offset` starts: on a row of the dump, and inside the file. */
export function pageStartFor(offset, size) {
  const last = Math.max(0, size - 1)
  return Math.floor(Math.min(Math.max(0, offset), last) / ROW) * ROW
}

/** The page after and the page before `start`: null where there is none. */
export function neighbours(start, size, length = PAGE_BYTES) {
  return {
    previous: start > 0 ? Math.max(0, start - length) : null,
    next: start + length < size ? start + length : null,
  }
}

/** "0x00010000-0x0001FFFF of 68,157,440 bytes" for the page that was read (`got` bytes from `start`). */
export function pageText(start, got, size) {
  if (got === 0) return `Nothing at ${hexOffset(start)}: the file has ${size.toLocaleString('en-US')} bytes`
  return `${hexOffset(start)}–${hexOffset(start + got - 1)} of ${size.toLocaleString('en-US')} bytes`
}

/**
 * Bytes as lines of 16: the offset, the bytes in hex and the printable characters. `hex` is what
 * `GET .../page?as=hex` sends (two lower-case digits a byte), `base` the offset of its first byte.
 */
export function hexDump(hex, base = 0) {
  const bytes = []
  for (let i = 0; i + 1 < hex.length; i += 2) bytes.push(Number.parseInt(hex.slice(i, i + 2), 16))
  const width = base + bytes.length > 0xffffffff ? 16 : 8
  const lines = []
  for (let at = 0; at < bytes.length; at += ROW) {
    const row = bytes.slice(at, at + ROW)
    const cells = row.map((byte) => byte.toString(16).padStart(2, '0'))
    const left = cells.slice(0, 8).join(' ')
    const right = cells.slice(8).join(' ')
    const ascii = row.map((byte) => (byte >= 0x20 && byte < 0x7f ? String.fromCharCode(byte) : '.')).join('')
    lines.push(
      `${(base + at).toString(16).toUpperCase().padStart(width, '0')}  ${left.padEnd(23)}  ${right.padEnd(23)}  ${ascii}`,
    )
  }
  return lines.join('\n')
}

/**
 * The text of an XML document as tokens `{ type, text }`: `tag` (`<Event`, `>`, `</Event>`), `attr`, `value`,
 * `comment`, `text` and `plain` (the spaces and the `=` inside a tag). Joined, the tokens are the source
 * again. It does not parse: a document that is broken still gets coloured as far as it goes.
 */
export function tokenizeXml(source) {
  const tokens = []
  const push = (type, text) => {
    if (!text) return
    const last = tokens[tokens.length - 1]
    if (last && last.type === type && type !== 'tag') last.text += text
    else tokens.push({ type, text })
  }
  const NAME = /[\w:.-]+/y
  const START = /<[?/!]?[\w:.-]*/y
  const END = /[/?]?>/y
  const QUOTED = /"[^"]*"?|'[^']*'?/y
  const SPACE = /\s+/y
  const n = source.length
  let i = 0
  while (i < n) {
    if (source[i] !== '<') {
      const next = source.indexOf('<', i)
      const end = next === -1 ? n : next
      push('text', source.slice(i, end))
      i = end
      continue
    }
    if (source.startsWith('<!--', i)) {
      const close = source.indexOf('-->', i + 4)
      const end = close === -1 ? n : close + 3
      push('comment', source.slice(i, end))
      i = end
      continue
    }
    if (source.startsWith('<![CDATA[', i)) {
      const close = source.indexOf(']]>', i + 9)
      const end = close === -1 ? n : close + 3
      push('text', source.slice(i, end))
      i = end
      continue
    }
    START.lastIndex = i
    const start = START.exec(source)
    push('tag', start[0])
    i += start[0].length
    // Inside the tag, up to its end.
    while (i < n) {
      END.lastIndex = i
      const end = END.exec(source)
      if (end) {
        push('tag', end[0])
        i += end[0].length
        break
      }
      QUOTED.lastIndex = i
      const quoted = QUOTED.exec(source)
      if (quoted) {
        push('value', quoted[0])
        i += quoted[0].length
        continue
      }
      NAME.lastIndex = i
      const name = NAME.exec(source)
      if (name) {
        push('attr', name[0])
        i += name[0].length
        continue
      }
      SPACE.lastIndex = i
      const space = SPACE.exec(source)
      const length = space ? space[0].length : 1
      push('plain', source.slice(i, i + length))
      i += length
    }
  }
  return tokens
}

/** The lines of a `text` answer of the worker, each with its number and whether the record is on it. */
export function numberedLines(text, first = 1, highlight = null) {
  const [from, to] = Array.isArray(highlight) && highlight.length === 2 ? highlight : [null, null]
  return String(text ?? '')
    .split('\n')
    .map((line, index) => {
      const number = first + index
      return { number, text: line, on: from !== null && number >= from && number <= to }
    })
}

/** The place a record has in its file, from the `where` of the worker's answer: "offset 0x00D6A200 · 1,184 bytes · record 27460". */
export function whereLine(where) {
  if (!where || typeof where !== 'object') return ''
  const parts = []
  if (Number.isInteger(where.offset)) parts.push(`offset ${hexOffset(where.offset)}`)
  if (Number.isInteger(where.length)) parts.push(`${where.length.toLocaleString('en-US')} bytes`)
  for (const [name, value] of Object.entries(where)) {
    if (name === 'offset' || name === 'length' || value === null || value === undefined || typeof value === 'object')
      continue
    parts.push(`${name} ${value}`)
  }
  return parts.join(' · ')
}

/**
 * The fields of a record as `[name, text]` rows: the pairs it was given, or an object (`data` of the API)
 * flattened one level; an object or a list inside is written as JSON. Empty values are left out.
 */
export function fieldRows(fields) {
  const entries = Array.isArray(fields) ? fields : Object.entries(fields ?? {})
  const rows = []
  for (const [name, value] of entries) {
    if (value === null || value === undefined || value === '') continue
    rows.push([String(name), typeof value === 'object' ? JSON.stringify(value) : String(value)])
  }
  return rows
}

/** The sentence for a view that could not be had: by the status the server answered. */
export function viewProblem(error) {
  if (error?.status === 404) return 'This record has no original to show'
  if (error?.status === 503) return 'The forensics worker is not available, so the original cannot be shown now'
  return error?.message || 'The original could not be shown'
}

/** The text a Copy button copies for a `view` answer. */
export function copyTextOf(answer) {
  if (!answer) return ''
  if (answer.kind === 'fields') return (answer.rows ?? []).map(([name, value]) => `${name}: ${value}`).join('\n')
  return String(answer.text ?? '')
}

/** How many matches one search asks for (the API's default is 100, its ceiling 200). */
export const FIND_LIMIT = 100

const ENCODING_NAMES = { 'utf-8': 'UTF-8', 'utf-16le': 'UTF-16', hex: 'bytes' }

/** One match of the whole-file search as a line: "0x000012A0 · UTF-16 · 24 bytes". */
export function matchLine(match) {
  const name = ENCODING_NAMES[match.encoding] ?? match.encoding ?? ''
  return [hexOffset(match.offset), name, `${match.length} byte${match.length === 1 ? '' : 's'}`]
    .filter(Boolean)
    .join(' · ')
}

/**
 * What to tell under a search answer (`{ matches, next, cut }`). `more` is where "Next matches" goes on from.
 * A search is cut either because it found `limit` matches (then there are more, and nothing else to say) or
 * because the worker's clock ran out before the end of the file: that one gets a sentence of its own.
 */
export function findSummary(answer, limit = FIND_LIMIT) {
  const matches = answer?.matches ?? []
  const more = Number.isInteger(answer?.next) ? answer.next : null
  const timedOut = Boolean(answer?.cut) && matches.length < limit
  const sentence = timedOut
    ? `The search stopped at its time limit, at ${hexOffset(more ?? 0)}: "Next matches" goes on from there.`
    : matches.length === 0
      ? 'Not found in this file.'
      : more !== null
        ? `${matches.length} matches shown, there are more.`
        : `${matches.length} match${matches.length === 1 ? '' : 'es'}.`
  return { matches, more, timedOut, note: sentence }
}

/** Where, in the text of a page, a match lies: `[from, to)` in characters, from the bytes it covers. */
export function charRange(text, pageOffset, matchOffset, matchLength) {
  const from = matchOffset - pageOffset
  const to = from + matchLength
  if (to <= 0 || matchLength <= 0) return null
  const encoder = new TextEncoder()
  let bytes = 0
  let start = null
  let end = null
  let index = 0
  for (const char of text) {
    const size = char === '�' ? 1 : encoder.encode(char).length // a broken byte shows as one replacement
    if (start === null && bytes + size > from) start = index
    bytes += size
    index += char.length
    if (start !== null && bytes >= to) {
      end = index
      break
    }
  }
  if (start === null) return null
  return { from: start, to: end ?? index }
}

/** The rows (of 16 bytes) of a hex dump that start at `pageOffset` and hold bytes of the match: `[first, last]`. */
export function markedRows(pageOffset, matchOffset, matchLength) {
  const first = Math.max(0, Math.floor((matchOffset - pageOffset) / ROW))
  const last = Math.floor((matchOffset + Math.max(1, matchLength) - 1 - pageOffset) / ROW)
  return last < 0 ? null : [first, last]
}
