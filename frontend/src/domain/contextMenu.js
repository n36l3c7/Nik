/*
 * What Nik's right-click menu holds, by what is under the pointer.
 *
 * A right-click anywhere opens Nik's menu, never the browser's. The menu is
 * made of sections, from the innermost thing under the pointer outward:
 *
 *   selection  text that is selected: copy it, and look it up when it is an
 *              address or an indicator
 *   field      a text field: undo, redo, cut, copy, paste, select all
 *   object     a row, a card, a file, a node: the actions its page gives it
 *   link       a link: open, open in a new tab, copy the address
 *   text       a cell of a table or a line of text nothing else claims: copy it
 *   page       what the page adds for itself (New incident…, Refresh)
 *   general    always last: search, the shortcuts, back, the address of the page
 *
 * This is the part that can be checked without a browser: which sections there
 * are and in which order, and the entries of the sections that do not belong to
 * a page. lib/underPointer.js reads the page to say what is under the pointer;
 * context/ContextMenuContext.jsx listens and shows the menu;
 * components/menu/ambientMenu.js gives each entry what it runs.
 */

import { recognise } from './pasted.js'

/** The types of <input> that hold text a person edits. */
const TEXT_TYPES = new Set(['', 'text', 'search', 'url', 'tel', 'password', 'email', 'number'])
/** Those whose selection a page cannot read (the browser keeps it to itself). */
const UNRANGED = new Set(['email', 'number'])

/**
 * What kind of text field an element is, or null when it is not one (a
 * checkbox, a button, a list of choices).
 *
 * @param {{ tag?: string, type?: string, editable?: boolean, editor?: boolean }} element
 * @returns {{ kind: 'editor' | 'input' | 'editable', secret: boolean, ranged: boolean } | null}
 */
export function fieldKind({ tag = '', type = '', editable = false, editor = false } = {}) {
  const name = String(tag).toUpperCase()
  const kind = String(type ?? '').toLowerCase()
  if (editor) return { kind: 'editor', secret: false, ranged: true }
  if (name === 'TEXTAREA') return { kind: 'input', secret: false, ranged: true }
  if (name === 'INPUT' && TEXT_TYPES.has(kind)) {
    return { kind: 'input', secret: kind === 'password', ranged: !UNRANGED.has(kind) }
  }
  if (editable) return { kind: 'editable', secret: false, ranged: true }
  return null
}

// When two things are the same element, the more specific one comes first.
const RANK = { field: 0, object: 1, link: 2, text: 3 }

/**
 * The sections of the menu, in order.
 *
 * @param {{
 *   inMenu?: boolean,       // the pointer is on the menu itself: nothing new opens
 *   selection?: boolean,    // selected text is under the pointer
 *   things?: { kind: 'field' | 'object' | 'link' | 'text', depth: number }[],
 *                           // what was found from the pointer outward; `depth` counts the steps out
 *   page?: boolean,         // the page adds entries of its own
 * }} under
 * @returns {('selection' | 'field' | 'object' | 'link' | 'text' | 'page' | 'general')[]}
 */
export function menuSections({ inMenu = false, selection = false, things = [], page = false } = {}) {
  if (inMenu) return []
  const has = (kind) => things.some((thing) => thing.kind === kind)
  const field = has('field')
  const kept = things
    // A field copies its own text, and an object says what is worth copying of it.
    .filter((thing) => thing.kind !== 'text' || (!field && !has('object')))
    .map((thing, index) => ({ ...thing, index }))
    .sort((a, b) => a.depth - b.depth || RANK[a.kind] - RANK[b.kind] || a.index - b.index)
    .map((thing) => thing.kind)
  const sections = [
    // In a field the selection is the field's: its Copy is the one shown.
    ...(selection && !field ? ['selection'] : []),
    ...kept.filter((kind, index) => kept.indexOf(kind) === index),
    ...(page ? ['page'] : []),
    'general',
  ]
  return sections
}

const entry = (id, label, { hint = null, why = null } = {}) => ({
  id,
  label,
  ...(hint ? { hint } : {}),
  // An entry that cannot be done stays in the menu, and says why when it is pointed at.
  ...(why ? { disabled: true, title: why } : {}),
})

const READ_ONLY = 'This field is read-only'
const SECRET = 'A password is not copied'

/**
 * The entries of a text field.
 *
 * @param {{
 *   readOnly?: boolean, secret?: boolean,
 *   ranged?: boolean,        // false: the browser does not say what is selected, the whole value is taken
 *   hasSelection?: boolean, empty?: boolean,
 *   history?: { canUndo: boolean, canRedo: boolean } | null,   // an editor that keeps its own undo
 * }} field
 */
export function fieldItems({
  readOnly = false,
  secret = false,
  ranged = true,
  hasSelection = false,
  empty = false,
  history = null,
} = {}) {
  const nothing = ranged ? (hasSelection ? null : 'Nothing is selected') : empty ? 'The field is empty' : null
  const whole = !ranged && !empty ? 'The whole value' : null
  const copy = entry('copy', 'Copy', { hint: 'ctrl c', why: secret ? SECRET : nothing })
  const cut = entry('cut', 'Cut', { hint: 'ctrl x', why: readOnly ? READ_ONLY : secret ? SECRET : nothing })
  return [
    ...(history && !readOnly
      ? [
          entry('undo', 'Undo', { hint: 'ctrl z', why: history.canUndo ? null : 'Nothing to undo' }),
          entry('redo', 'Redo', { hint: 'ctrl shift z', why: history.canRedo ? null : 'Nothing to redo' }),
          'separator',
        ]
      : []),
    whole && !cut.disabled ? { ...cut, title: whole } : cut,
    whole && !copy.disabled ? { ...copy, title: whole } : copy,
    entry('paste', 'Paste', { hint: 'ctrl v', why: readOnly ? READ_ONLY : null }),
    entry('selectAll', 'Select all', { hint: 'ctrl a', why: empty ? 'The field is empty' : null }),
  ]
}

/**
 * What Nik offers for a piece of text that is an address or an indicator, as
 * it does for text that is pasted: where it was seen, the search, the
 * Indicators. Nothing when the text is not one, or the account cannot read.
 */
export function lookupItems(text, { canRead = false, canWrite = false } = {}) {
  const match = canRead ? recognise(text) : null
  if (!match) return []
  return [
    { ...entry('whereSeen', 'Where else was this seen?'), match },
    { ...entry('searchFor', 'Search for it', { hint: 'ctrl k' }), match },
    ...(canWrite ? [{ ...entry('addIndicator', 'Add to the Indicators…'), match }] : []),
  ]
}

/** The entries of selected text. */
export function selectionItems(text, rights = {}) {
  if (!String(text ?? '').trim()) return []
  return [entry('copySelection', 'Copy', { hint: 'ctrl c' }), ...lookupItems(text, rights)]
}

/** A line of text is copied whole up to this length; past it, the person selects what they want. */
export const TEXT_LIMIT = 4000

/**
 * The entries of a cell of a table, or of a line of text, that nothing else
 * claims.
 *
 * @param {{ cell?: string, row?: string, text?: string }} found  `cell` and `row` in a table, `text` elsewhere
 */
export function textItems({ cell = '', row = '', text = '' } = {}, rights = {}) {
  const fits = (value) => Boolean(value) && value.length <= TEXT_LIMIT
  if (fits(cell) || fits(row)) {
    return [
      ...(fits(cell) ? [entry('copyCell', 'Copy this cell')] : []),
      // A row of one cell is that cell.
      ...(fits(row) && row !== cell ? [entry('copyRow', 'Copy this row')] : []),
      ...(fits(cell) ? lookupItems(cell, rights) : []),
    ]
  }
  if (!fits(text)) return []
  return [entry('copyText', 'Copy this text'), ...lookupItems(text, rights)]
}

/**
 * The entries of a link. An address outside Nik opens in a new tab, as its
 * click does, and never in place of Nik; a link that downloads a file
 * downloads it. Only real links come here: an address found in evidence is
 * never one in Nik, so nothing here makes it clickable.
 *
 * @param {{ href: string, download?: boolean, newTab?: boolean }} link
 * @param {string} origin  the address of this Nik
 */
export function linkItems({ href = '', download = false, newTab = false } = {}, origin = '') {
  let url
  try {
    url = new URL(href, origin || undefined)
  } catch {
    return []
  }
  const web = url.protocol === 'http:' || url.protocol === 'https:'
  // A file made in the browser (blob:, data:) has no address worth copying.
  const address = web ? [entry('copyLink', 'Copy the address')] : []
  if (download || !web) return [entry('followLink', 'Download'), ...address]
  if (url.origin !== origin) return [entry('openLinkTab', 'Open in a new tab'), ...address]
  return [...(newTab ? [] : [entry('followLink', 'Open')]), entry('openLinkTab', 'Open in a new tab'), ...address]
}

/**
 * The general section, the same on every page: last in every menu, and the
 * whole menu where nothing else is under the pointer.
 *
 * @param {{
 *   signedIn?: boolean, canRead?: boolean,
 *   canGoBack?: boolean,    // the browser has a page before this one
 *   shortcuts?: boolean,    // the list of shortcuts can be opened from here
 * }} state
 */
export function generalItems({ signedIn = false, canRead = false, canGoBack = true, shortcuts = true } = {}) {
  return [
    ...(signedIn && canRead ? [entry('search', 'Search…', { hint: 'ctrl k' })] : []),
    ...(signedIn && shortcuts ? [entry('shortcuts', 'Keyboard shortcuts', { hint: '?' })] : []),
    entry('back', 'Back', { hint: 'alt ←', why: canGoBack ? null : 'There is no page before this one' }),
    entry('copyAddress', 'Copy the address of this page'),
  ]
}

/** True for the key that asks for the menu of what has the focus: the menu key, or Shift + F10. */
export function isMenuKey({ key, shiftKey = false, ctrlKey = false, altKey = false, metaKey = false } = {}) {
  if (ctrlKey || altKey || metaKey) return false
  return key === 'ContextMenu' || (key === 'F10' && shiftKey)
}

/**
 * Where the menu opens when the keyboard asks for it: on the element that has
 * the focus, inside the window. `box` is its place on screen, or null when
 * nothing has the focus (the menu then opens near the top of the page).
 */
export function keyboardPoint(box, viewport) {
  if (!box || (box.width === 0 && box.height === 0)) {
    return { x: Math.round(viewport.width / 2), y: Math.round(viewport.height / 3) }
  }
  const within = (value, max) => Math.max(8, Math.min(value, max - 8))
  return {
    x: Math.round(within(box.left + Math.min(box.width / 2, 24), viewport.width)),
    y: Math.round(within(box.top + Math.min(box.height / 2, 24), viewport.height)),
  }
}
