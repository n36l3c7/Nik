import { useCallback, useEffect, useMemo, useState } from 'react'
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
  selectedCount,
  selectionBody,
  togglePage,
} from '../../domain/selection.js'

/*
 * The selection of a list, for the component that draws it (domain/selection.js
 * has the rules; <SelectBox> is the checkbox, <BulkBar> what appears when
 * something is ticked).
 *
 *   const picked = useSelection({ filter, pageIds, total })
 *   <SelectBox … checked={picked.has(row.id)} onPick={(event) => picked.pick(row.id, event)} />
 *   <tr onKeyDown={(event) => picked.key(event, row.id)} aria-selected={picked.has(row.id)}>
 *
 * `filter` is a string that changes when what the list keeps changes (the
 * query, the list that is open): the selection lives inside one filter, and
 * is emptied when it changes. `pageIds` are the rows on screen, in their
 * order; `total` is how many the filter keeps in all.
 *
 * The selection is the state of the component that holds it: leaving the
 * page forgets it, and it is never carried to another list.
 */
export function useSelection({ filter = '', pageIds, total }) {
  const [held, setHeld] = useState(() => emptySelection(filter))
  // The filter changed: nothing of the old selection is acted on, even before the effect below runs.
  const selection = useMemo(() => forFilter(held, filter), [held, filter])
  useEffect(() => setHeld((current) => forFilter(current, filter)), [filter])

  const has = useCallback((id) => isSelected(selection, id), [selection])
  const pick = useCallback(
    (id, event) => setHeld((current) => click(forFilter(current, filter), pageIds, id, Boolean(event?.shiftKey))),
    [filter, pageIds],
  )
  const pickPage = useCallback(
    () => setHeld((current) => togglePage(forFilter(current, filter), pageIds)),
    [filter, pageIds],
  )
  const pickAll = useCallback(() => setHeld((current) => selectAll(forFilter(current, filter))), [filter])
  const reset = useCallback(() => setHeld((current) => clear(current)), [])
  /**
   * A key pressed on a row (`focused`: its id) or on the list (`focused` null). Returns the id of
   * the row the focus goes to, null when the key was taken and the focus stays, undefined when
   * the key is not the selection's. The event is marked as taken.
   */
  const key = useCallback(
    (event, focused = null) => {
      const done = onKey(selection, pageIds, focused, event)
      if (!done) return undefined
      event.preventDefault()
      event.stopPropagation()
      setHeld(done.selection)
      return done.focus
    },
    [selection, pageIds],
  )

  return {
    selection,
    count: selectedCount(selection, total),
    all: selection.all,
    has,
    pick,
    pickPage,
    pickAll,
    reset,
    key,
    page: pageState(selection, pageIds),
    offersAll: offersAll(selection, pageIds, total),
    total,
    notice: selection.cleared ? CLEARED : '',
    /** What a bulk request names: the ids, or `query` when everything the filter keeps is selected. */
    body: (query) => selectionBody(selection, query),
    ids: () => [...selection.ids],
  }
}
