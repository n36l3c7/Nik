/*
 * A small Markdown, read into a tree the screen draws as elements (never as
 * HTML): the instructions of a task are written by whoever builds a playbook
 * and read by someone else, so nothing in them is ever run or injected.
 *
 *   blocks   paragraphs, # headings (three levels), - and 1. lists, ``` code
 *   inline   **bold**, *italic*, `code`, [text](https://…)
 *
 * A link is kept only when it is http, https or mailto; anything else stays
 * as the text it was written as.
 */

const SAFE_LINK = /^(https?:\/\/|mailto:)/i
const INLINE = /(`[^`\n]+`)|(\*\*[^*\n]+\*\*)|(\*[^*\n]+\*)|(\[[^\]\n]+\]\([^)\s]+\))/g

/** The inline parts of a line: `[{ type: 'text'|'code'|'bold'|'italic'|'link', text, href? }]`. */
export function inline(text) {
  const source = String(text ?? '')
  const parts = []
  let at = 0
  for (const found of source.matchAll(INLINE)) {
    if (found.index > at) parts.push({ type: 'text', text: source.slice(at, found.index) })
    const piece = found[0]
    if (found[1]) parts.push({ type: 'code', text: piece.slice(1, -1) })
    else if (found[2]) parts.push({ type: 'bold', text: piece.slice(2, -2) })
    else if (found[3]) parts.push({ type: 'italic', text: piece.slice(1, -1) })
    else {
      const close = piece.indexOf('](')
      const href = piece.slice(close + 2, -1)
      if (SAFE_LINK.test(href)) parts.push({ type: 'link', text: piece.slice(1, close), href })
      else parts.push({ type: 'text', text: piece })
    }
    at = found.index + piece.length
  }
  if (at < source.length) parts.push({ type: 'text', text: source.slice(at) })
  return parts
}

/**
 * The blocks of a text:
 * `{ type: 'heading', level, parts } | { type: 'paragraph', parts } |
 *  { type: 'list', ordered, items: parts[] } | { type: 'code', text }`.
 */
export function blocks(text) {
  const lines = String(text ?? '')
    .replace(/\r\n?/g, '\n')
    .split('\n')
  const out = []
  let paragraph = []
  const flush = () => {
    if (paragraph.length) out.push({ type: 'paragraph', parts: inline(paragraph.join(' ')) })
    paragraph = []
  }
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (line.trim().startsWith('```')) {
      flush()
      const code = []
      index += 1
      while (index < lines.length && !lines[index].trim().startsWith('```')) {
        code.push(lines[index])
        index += 1
      }
      out.push({ type: 'code', text: code.join('\n') })
      continue
    }
    const heading = /^(#{1,3})\s+(.*)$/.exec(line)
    if (heading) {
      flush()
      out.push({ type: 'heading', level: heading[1].length, parts: inline(heading[2].trim()) })
      continue
    }
    const item = /^\s*(?:([-*])|(\d+)[.)])\s+(.*)$/.exec(line)
    if (item) {
      flush()
      const ordered = Boolean(item[2])
      const last = out[out.length - 1]
      if (last?.type === 'list' && last.ordered === ordered) last.items.push(inline(item[3]))
      else out.push({ type: 'list', ordered, items: [inline(item[3])] })
      continue
    }
    if (!line.trim()) {
      flush()
      continue
    }
    paragraph.push(line.trim())
  }
  flush()
  return out
}
