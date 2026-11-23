/*
 * The selection of a list: which rows are ticked, and how a click, a
 * shift-click, the checkbox of the heading and the keyboard change it.
 *
 * One model for every list that can be selected from (the incidents, the
 * artifacts, the indicators). A selection is either rows named one by one
 * (`ids`), or **everything the filter keeps** (`all`): then no id is held
 * here, and the server works out which they are from the filter itself.
 *
 *   { ids: Set<string>, anchor: string | null, all: boolean, filter: string, cleared: boolean }
 *
 * `anchor` is the row a range starts from: the last one that was clicked.
 * `filter` is what the list was filtered by when the rows were ticked: a
 * selection lives inside one filter, across its pages and whatever the
 * order. When the filter changes the selection is emptied, and `cleared`
 * says so until something is ticked again, so the screen can say it too.
 */

/** Nothing selected, in a list filtered by `filter`. */
export function emptySelection(filter = '') {
  return { ids: new Set(), anchor: null, all: false, filter, cleared: false }
}

/** How many are selected; `total` is what the filter keeps (the count when everything is). */
export function selectedCount(selection, total = 0) {
  return selection.all ? total : selection.ids.size
}

export const isSelected = (selection, id) => selection.all || selection.ids.has(id)

const withIds = (selection, ids, anchor) => ({ ...selection, ids, anchor, all: false, cleared: false })

/** A click on the checkbox of a row: ticked becomes unticked, and it is where the next range starts. */
export function toggle(selection, id) {
  // From "everything", unticking one row cannot be said to the server: the rows named one by one
  // start again from this click.
  const ids = new Set(selection.all ? [] : selection.ids)
  if (ids.has(id)) ids.delete(id)
  else ids.add(id)
  return withIds(selection, ids, id)
}

/**
 * A shift-click: every row from the anchor to this one, in the order they are on screen, is
 * ticked. Without an anchor on screen it is a plain click.
 */
export function selectRange(selection, order, id) {
  const from = order.indexOf(selection.anchor)
  const to = order.indexOf(id)
  if (selection.all || from < 0 || to < 0) return toggle(selection, id)
  const ids = new Set(selection.ids)
  for (const row of order.slice(Math.min(from, to), Math.max(from, to) + 1)) ids.add(row)
  // The anchor stays: a second shift-click draws another range from the same row.
  return withIds(selection, ids, selection.anchor)
}

/** A click on a checkbox, with or without Shift. */
export const click = (selection, order, id, shift = false) =>
  shift ? selectRange(selection, order, id) : toggle(selection, id)

/** What the checkbox of the heading shows for the rows of the page: 'none', 'some' or 'all'. */
export function pageState(selection, pageIds) {
  if (pageIds.length === 0) return 'none'
  if (selection.all) return 'all'
  const ticked = pageIds.filter((id) => selection.ids.has(id)).length
  return ticked === 0 ? 'none' : ticked === pageIds.length ? 'all' : 'some'
}

/** The checkbox of the heading: a page that is all ticked is unticked, any other is ticked whole. */
export function togglePage(selection, pageIds) {
  const ids = new Set(selection.all ? [] : selection.ids)
  if (pageState(selection, pageIds) === 'all') for (const id of pageIds) ids.delete(id)
  else for (const id of pageIds) ids.add(id)
  return withIds(selection, ids, null)
}

/**
 * Whether "Select all N that match" is offered: the page is all ticked, and the filter keeps
 * more than what is ticked.
 */
export function offersAll(selection, pageIds, total) {
  return !selection.all && pageState(selection, pageIds) === 'all' && total > selection.ids.size
}

/** Everything the filter keeps. */
export const selectAll = (selection) => ({ ...selection, ids: new Set(), anchor: null, all: true, cleared: false })

export const clear = (selection) => emptySelection(selection.filter)

/**
 * The selection for a list filtered by `filter`: the same one while the filter is the same; an
 * empty one, marked `cleared` when something was ticked, once it changed.
 */
export function forFilter(selection, filter) {
  if (selection.filter === filter) return selection
  const had = selection.all || selection.ids.size > 0
  return { ...emptySelection(filter), cleared: had }
}

/**
 * The selection without the rows the list does not hold any more (`known`: the ids it holds, all
 * of them, not only the page; null when the list does not know them all). A row that left the
 * list, because it was changed elsewhere or the answer to the filter came, is never acted on.
 */
export function within(selection, known) {
  if (!known || selection.all) return selection
  const ids = [...selection.ids].filter((id) => known.has(id))
  if (ids.length === selection.ids.size) return selection
  return { ...selection, ids: new Set(ids), anchor: known.has(selection.anchor) ? selection.anchor : null }
}

/** What is said when a change of the filter emptied the selection. */
export const CLEARED = 'The filter changed: the selection was cleared.'

/**
 * A key pressed on a row of the list. Returns `{ selection, focus }` when the key is one of the
 * selection's (`focus`: the row the focus goes to, when it moves), null when it is not:
 *
 *   Space              tick or untick the row
 *   Shift + ↓ / ↑      tick the next row too, and go there
 *   Ctrl/⌘ + A         tick the page
 *   Escape             untick everything (only when something is ticked)
 */
export function onKey(selection, order, focused, event) {
  const { key, shiftKey, ctrlKey, metaKey, altKey } = event
  if (altKey) return null
  if ((ctrlKey || metaKey) && (key === 'a' || key === 'A')) {
    const ids = new Set(selection.all ? [] : selection.ids)
    for (const id of order) ids.add(id)
    return { selection: withIds(selection, ids, selection.anchor), focus: null }
  }
  if (ctrlKey || metaKey) return null
  if (key === 'Escape') {
    return selection.all || selection.ids.size > 0 ? { selection: clear(selection), focus: null } : null
  }
  if (focused === null || focused === undefined) return null
  if (key === ' ' && !shiftKey) return { selection: toggle(selection, focused), focus: null }
  if (shiftKey && (key === 'ArrowDown' || key === 'ArrowUp')) {
    const at = order.indexOf(focused)
    const next = order[at + (key === 'ArrowDown' ? 1 : -1)]
    if (at < 0 || next === undefined) return { selection, focus: null }
    const ids = new Set(selection.all ? [] : selection.ids)
    ids.add(focused)
    ids.add(next)
    return { selection: withIds(selection, ids, selection.anchor ?? focused), focus: next }
  }
  return null
}

/**
 * What a bulk request names: the rows one by one, or the filter (`query`, in the words the
 * server reads for this list) when everything it keeps is selected.
 */
export function selectionBody(selection, query) {
  return selection.all ? { query } : { ids: [...selection.ids] }
}

/** "12 selected", "All 1,284 that match are selected". */
export function selectionText(selection, total) {
  const count = selectedCount(selection, total)
  return selection.all
    ? `All ${count.toLocaleString('en-US')} that match are selected`
    : `${count.toLocaleString('en-US')} selected`
}
