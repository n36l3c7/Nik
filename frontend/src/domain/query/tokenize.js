/*
 * A query as coloured pieces. Unlike parse(), this never refuses: whatever is
 * typed, half-written or wrong, is cut into tokens that cover the whole text,
 * so the input can be coloured while it is edited.
 *
 * Token types: space, paren, keyword (and / or / not / in), not (the leading
 * - or !), field, op (the colon and the comparison after it), value, range,
 * text (a value on its own), and quote for a quoted value or text. The values
 * of a list (`field IN (a, b)`) are value tokens of that field.
 */

import { listOpening } from './parse.js'

const SPACE = ' \t\r\n'
const OPS = ['>=', '<=', '>', '<', '!']
const NAME = /[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*/y

function keywordAt(text, i) {
  for (const word of ['and', 'or', 'not']) {
    const end = i + word.length
    if (text.slice(i, end).toLowerCase() === word && (end >= text.length || (SPACE + '()').includes(text[end]))) {
      return word
    }
  }
  return ''
}

/** The end of a quoted run starting at `i` (the text's end when it is not closed). */
function quoteEnd(text, i) {
  let j = i + 1
  while (j < text.length) {
    if (text[j] === '\\' && j + 1 < text.length) j += 2
    else if (text[j] === '"') return j + 1
    else j += 1
  }
  return text.length
}

/** The end of a bare run starting at `i`: a space, or the parenthesis that closes the group. */
function bareEnd(text, i) {
  let j = i
  let opened = 0
  while (j < text.length) {
    const char = text[j]
    if (SPACE.includes(char)) break
    if (char === '\\' && j + 1 < text.length && !SPACE.includes(text[j + 1])) {
      j += 2
      continue
    }
    if (char === ')') {
      if (opened === 0) break
      opened -= 1
    } else if (char === '(') {
      opened += 1
    }
    j += 1
  }
  return j
}

/**
 * @param {string} text
 * @returns {{ type: string, start: number, end: number, text: string, field?: string }[]}
 *   `field` is set on the op, value and range tokens of a `field:value` term.
 */
export function tokenize(text) {
  const source = String(text ?? '')
  const tokens = []
  const push = (type, start, end, extra) => {
    if (end > start) tokens.push({ type, start, end, text: source.slice(start, end), ...extra })
  }
  let i = 0
  while (i < source.length) {
    const char = source[i]
    if (SPACE.includes(char)) {
      let j = i
      while (j < source.length && SPACE.includes(source[j])) j += 1
      push('space', i, j)
      i = j
      continue
    }
    if (char === '(' || char === ')') {
      push('paren', i, i + 1)
      i += 1
      continue
    }
    const word = keywordAt(source, i)
    if (word) {
      push('keyword', i, i + word.length)
      i += word.length
      continue
    }
    if (
      (char === '-' || char === '!') &&
      i + 1 < source.length &&
      !SPACE.includes(source[i + 1]) &&
      source[i + 1] !== ')'
    ) {
      push('not', i, i + 1)
      i += 1
      continue
    }
    if (char === '"') {
      const end = quoteEnd(source, i)
      push('quote', i, end)
      i = end
      continue
    }
    NAME.lastIndex = i
    const name = NAME.exec(source)
    if (name && source[NAME.lastIndex] === ':') {
      const field = name[0]
      push('field', i, NAME.lastIndex)
      let j = NAME.lastIndex + 1
      for (const op of OPS) {
        if (source.startsWith(op, j)) {
          j += op.length
          break
        }
      }
      push('op', NAME.lastIndex, j, { field })
      if (source[j] === '[') {
        const close = source.indexOf(']', j)
        const end = close === -1 ? source.length : close + 1
        push('range', j, end, { field })
        i = end
      } else if (source[j] === '"') {
        const end = quoteEnd(source, j)
        push('value', j, end, { field })
        i = end
      } else {
        const end = bareEnd(source, j)
        push('value', j, end, { field })
        i = end
      }
      continue
    }
    if (name) {
      const listed = listOpening(source, NAME.lastIndex)
      if (listed) {
        const field = name[0]
        push('field', i, NAME.lastIndex)
        // The words between the name and the parenthesis, and the spaces around them.
        let j = NAME.lastIndex
        for (const [at, length] of [
          [listed.not, 3],
          [listed.in, 2],
        ]) {
          if (at === -1) continue
          push('space', j, at)
          push('keyword', at, at + length)
          j = at + length
        }
        push('space', j, listed.paren)
        j = listed.paren
        push('paren', j, j + 1)
        j += 1
        // The values, up to the parenthesis that closes the list (or the end, while it is typed).
        while (j < source.length && source[j] !== ')') {
          if (SPACE.includes(source[j]) || source[j] === ',') {
            let k = j
            while (k < source.length && (SPACE.includes(source[k]) || source[k] === ',')) k += 1
            push('space', j, k)
            j = k
          } else if (source[j] === '"') {
            const end = quoteEnd(source, j)
            push('value', j, end, { field })
            j = end
          } else {
            let k = j
            while (k < source.length && !SPACE.includes(source[k]) && source[k] !== ',' && source[k] !== ')') {
              k += source[k] === '\\' && k + 1 < source.length ? 2 : 1
            }
            push('value', j, Math.min(k, source.length), { field })
            j = Math.min(k, source.length)
          }
        }
        i = j
        continue
      }
    }
    const end = Math.max(bareEnd(source, i), i + 1)
    push('text', i, end)
    i = end
  }
  return tokens
}

/** The token the caret is in or right after (a space counts only when the caret is inside it). */
export function tokenAt(tokens, caret) {
  return tokens.find((token) => token.start < caret && caret <= token.end && token.type !== 'space') ?? null
}
