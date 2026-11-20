/*
 * What is under the pointer when the right-click menu is asked for, read from
 * the page: selected text, a text field, a link, a cell of a table or a line
 * of text. domain/contextMenu.js decides what the menu holds from it.
 */

import { fieldAt } from './textField.js'

// What holds one piece of text a person may want whole.
const LINES = 'li, dd, dt, pre, p, h1, h2, h3, h4, h5, h6, blockquote, figcaption, [role="listitem"]'
// Controls: their text is a label, not something read.
const CONTROLS =
  'button, [role="button"], [role="tab"], [role="option"], [role="menuitem"], select, summary, nav, label'

/** How many steps out from `from` the element `to` is; 0 when they are the same. */
export function depthOf(from, to) {
  let steps = 0
  for (let node = from; node instanceof Element; node = node.parentElement) {
    if (node === to) return steps
    steps += 1
  }
  // Not around it on the page (drawn elsewhere by its component): the outermost thing.
  return Number.MAX_SAFE_INTEGER
}

const clean = (text) =>
  String(text ?? '')
    .replace(/[ \t\xa0]+/g, ' ')
    .replace(/ ?\n ?/g, '\n')
    .trim()

/** The selected text, when the pointer is on it (or when the keyboard asked: there is no pointer). */
function selectionUnder(event, keyboard) {
  const selection = window.getSelection?.()
  if (!selection || selection.isCollapsed || selection.rangeCount === 0) return ''
  const text = selection.toString()
  if (!text.trim()) return ''
  if (keyboard) return text
  const { clientX: x, clientY: y } = event
  const on = [...selection.getRangeAt(0).getClientRects()].some(
    (box) => x >= box.left - 2 && x <= box.right + 2 && y >= box.top - 2 && y <= box.bottom + 2,
  )
  return on ? text : ''
}

/**
 * @param {MouseEvent} event  the `contextmenu` event
 * @param {{ keyboard?: boolean }} how  the menu key asked, not the pointer
 * @returns {{
 *   target: Element | null, inMenu: boolean, selection: string,
 *   field: object | null, link: object | null, text: object | null,
 *   things: { kind: string, depth: number }[],
 * }}
 */
export function underPointer(event, { keyboard = false } = {}) {
  const target = event.target instanceof Element ? event.target : (event.target?.parentElement ?? null)
  const none = { target, inMenu: false, selection: '', field: null, link: null, text: null, things: [] }
  if (!target) return none
  if (target.closest('[data-nik-menu]')) return { ...none, inMenu: true }

  const things = []
  const field = fieldAt(target)
  if (field) things.push({ kind: 'field', depth: depthOf(target, field.element) })

  const anchor = target.closest('a[href]')
  const link = anchor
    ? {
        element: anchor,
        // As written for an address made in the browser, whole otherwise.
        href: anchor.href,
        download: anchor.hasAttribute('download'),
        newTab: anchor.target === '_blank',
      }
    : null
  if (link) things.push({ kind: 'link', depth: depthOf(target, anchor) })

  let text = null
  const cell = target.closest('td, th')
  const row = cell?.closest('tr')
  if (cell && row) {
    text = {
      element: cell,
      cell: clean(cell.innerText),
      row: [...row.cells]
        .map((one) => clean(one.innerText).replace(/\n/g, ' '))
        .join('\t')
        .trim(),
    }
  } else if (!target.closest(CONTROLS)) {
    const line = target.closest(LINES)
    if (line) text = { element: line, text: clean(line.innerText) }
  }
  if (text) things.push({ kind: 'text', depth: depthOf(target, text.element) })

  return { target, inMenu: false, selection: selectionUnder(event, keyboard), field, link, text, things }
}

/**
 * True when a dialog stands between `inner` and `outer`: what is around a
 * dialog has nothing to say about a right-click inside it.
 */
export function behindDialog(outer, inner) {
  if (!(outer instanceof Element) || !(inner instanceof Element)) return false
  const dialog = inner.closest('[role="dialog"]')
  return Boolean(dialog && dialog !== outer && outer.contains(dialog))
}
