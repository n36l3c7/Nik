import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  CLEARED,
  clear,
  click,
  emptySelection,
  forFilter,
  isSelected,
  offersAll,
  onKey,
  pageState,
  selectAll,
  selectRange,
  selectedCount,
  selectionBody,
  selectionText,
  toggle,
  togglePage,
  within,
} from './selection.js'

const PAGE = ['a', 'b', 'c', 'd', 'e']
const ids = (selection) => [...selection.ids].sort()
const key = (name, more = {}) => ({
  key: name,
  shiftKey: false,
  ctrlKey: false,
  metaKey: false,
  altKey: false,
  ...more,
})

test('a click ticks a row and another click unticks it', () => {
  let selection = toggle(emptySelection(), 'b')
  assert.deepEqual(ids(selection), ['b'])
  assert.equal(selection.anchor, 'b')
  assert.equal(isSelected(selection, 'b'), true)
  selection = toggle(selection, 'b')
  assert.deepEqual(ids(selection), [])
  assert.equal(selectedCount(selection, 40), 0)
})

test('a shift-click ticks the range from the last click, in the order on screen', () => {
  let selection = click(emptySelection(), PAGE, 'b')
  selection = click(selection, PAGE, 'd', true)
  assert.deepEqual(ids(selection), ['b', 'c', 'd'])
  // Upwards too, and from the same anchor: what was ticked stays.
  selection = click(selection, PAGE, 'a', true)
  assert.deepEqual(ids(selection), ['a', 'b', 'c', 'd'])
  assert.equal(selection.anchor, 'b')
  // In another order of the list the range is the one of that order.
  const sorted = ['e', 'd', 'c', 'b', 'a']
  assert.deepEqual(ids(selectRange(toggle(emptySelection(), 'e'), sorted, 'c')), ['c', 'd', 'e'])
})

test('a shift-click without an anchor on screen is a plain click', () => {
  assert.deepEqual(ids(selectRange(emptySelection(), PAGE, 'c')), ['c'])
  const elsewhere = toggle(emptySelection(), 'z')
  assert.deepEqual(ids(selectRange(elsewhere, PAGE, 'c')), ['c', 'z'])
})

test('the checkbox of the heading has three states and ticks or unticks the page', () => {
  let selection = emptySelection()
  assert.equal(pageState(selection, PAGE), 'none')
  assert.equal(pageState(selection, []), 'none')
  selection = toggle(selection, 'a')
  assert.equal(pageState(selection, PAGE), 'some')
  selection = togglePage(selection, PAGE)
  assert.equal(pageState(selection, PAGE), 'all')
  assert.deepEqual(ids(selection), PAGE)
  selection = togglePage(selection, PAGE)
  assert.deepEqual(ids(selection), [])
})

test('the selection survives paging: another page adds to it and is unticked alone', () => {
  let selection = togglePage(emptySelection(), PAGE)
  const next = ['f', 'g']
  assert.equal(pageState(selection, next), 'none')
  selection = togglePage(selection, next)
  assert.equal(selectedCount(selection, 100), 7)
  selection = togglePage(selection, next)
  assert.deepEqual(ids(selection), PAGE)
})

test('"select all that match" is offered when the page is all ticked and there is more', () => {
  let selection = togglePage(emptySelection(), PAGE)
  assert.equal(offersAll(selection, PAGE, 5), false)
  assert.equal(offersAll(selection, PAGE, 1284), true)
  assert.equal(offersAll(toggle(selection, 'a'), PAGE, 1284), false)
  selection = selectAll(selection)
  assert.equal(offersAll(selection, PAGE, 1284), false)
  assert.equal(selectedCount(selection, 1284), 1284)
  assert.equal(isSelected(selection, 'not-on-this-page'), true)
  assert.equal(pageState(selection, PAGE), 'all')
  assert.equal(selectionText(selection, 1284), 'All 1,284 that match are selected')
  assert.equal(selectionText(togglePage(emptySelection(), PAGE), 1284), '5 selected')
})

test('everything is said to the server by the filter, rows by their ids', () => {
  const query = { q: 'status:open' }
  assert.deepEqual(selectionBody(selectAll(emptySelection()), query), { query })
  assert.deepEqual(selectionBody(toggle(emptySelection(), 'a'), query), { ids: ['a'] })
})

test('from "everything", a click starts again from the rows named one by one', () => {
  const selection = toggle(selectAll(emptySelection()), 'c')
  assert.equal(selection.all, false)
  assert.deepEqual(ids(selection), ['c'])
  assert.deepEqual(ids(togglePage(selectAll(emptySelection()), PAGE)), [])
})

test('the selection is emptied when the filter changes, and says so once', () => {
  let selection = toggle(emptySelection('status:open'), 'a')
  assert.equal(forFilter(selection, 'status:open'), selection)
  selection = forFilter(selection, 'status:closed')
  assert.deepEqual(ids(selection), [])
  assert.equal(selection.cleared, true)
  assert.equal(selection.filter, 'status:closed')
  assert.match(CLEARED, /cleared/)
  // Ticking again takes the sentence away; a filter that changes with nothing ticked says nothing.
  assert.equal(toggle(selection, 'b').cleared, false)
  assert.equal(forFilter(emptySelection('x'), 'y').cleared, false)
  assert.equal(forFilter(selectAll(emptySelection('x')), 'y').all, false)
  assert.equal(clear(toggle(emptySelection('x'), 'a')).filter, 'x')
})

test('the keyboard: space, shift and the arrows, select the page, escape', () => {
  let selection = emptySelection()
  let done = onKey(selection, PAGE, 'b', key(' '))
  assert.deepEqual(ids(done.selection), ['b'])
  // Shift + down ticks the row and the next one, and goes there; again extends.
  done = onKey(done.selection, PAGE, 'b', key('ArrowDown', { shiftKey: true }))
  assert.deepEqual(ids(done.selection), ['b', 'c'])
  assert.equal(done.focus, 'c')
  done = onKey(done.selection, PAGE, 'c', key('ArrowDown', { shiftKey: true }))
  assert.deepEqual(ids(done.selection), ['b', 'c', 'd'])
  done = onKey(done.selection, PAGE, 'b', key('ArrowUp', { shiftKey: true }))
  assert.deepEqual(ids(done.selection), ['a', 'b', 'c', 'd'])
  assert.equal(done.focus, 'a')
  // At the end of the page there is nowhere to go.
  assert.equal(onKey(done.selection, PAGE, 'e', key('ArrowDown', { shiftKey: true })).focus, null)
  selection = onKey(emptySelection(), PAGE, 'a', key('a', { ctrlKey: true })).selection
  assert.deepEqual(ids(selection), PAGE)
  assert.deepEqual(ids(onKey(emptySelection(), PAGE, null, key('A', { metaKey: true })).selection), PAGE)
  assert.deepEqual(ids(onKey(selection, PAGE, 'a', key('Escape')).selection), [])
})

test("keys that are not the selection's are left to the list", () => {
  const selection = emptySelection()
  assert.equal(onKey(selection, PAGE, 'a', key('Escape')), null) // nothing ticked: Escape is somebody else's
  assert.equal(onKey(selection, PAGE, 'a', key('ArrowDown')), null)
  assert.equal(onKey(selection, PAGE, 'a', key('Enter')), null)
  assert.equal(onKey(selection, PAGE, null, key(' ')), null)
  assert.equal(onKey(selection, PAGE, 'a', key('a', { ctrlKey: true, altKey: true })), null)
  assert.equal(onKey(selection, PAGE, 'a', key('c', { ctrlKey: true })), null)
})

test('a ticked row the list does not hold any more is not selected, nor acted on', () => {
  // The heading ticked the rows of the old filter; the answer to the new one keeps only two.
  let selection = togglePage(emptySelection('type:malware'), PAGE)
  selection = within(selection, new Set(['b', 'd']))
  assert.deepEqual(ids(selection), ['b', 'd'])
  assert.equal(selection.anchor, null)
  assert.deepEqual(selectionBody(selection, { q: 'type:malware' }), { ids: ['b', 'd'] })
  // The same list: the very same selection, so nothing is drawn again for it.
  assert.equal(within(selection, new Set(PAGE)), selection)
  // A list that does not know all its rows, and everything that matches, are left as they are.
  assert.equal(within(selection, null), selection)
  const all = selectAll(selection)
  assert.equal(within(all, new Set()), all)
})
