import { useCallback, useEffect, useRef } from 'react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'

/**
 * What a page adds to every right-click menu opened on it, before the general
 * section: the things the page itself does (New incident…, Refresh).
 *
 *   const pageMenu = usePageMenu(() => [{ label: 'Refresh', icon: RefreshCw, onSelect: load }])
 *   <div onContextMenu={pageMenu}>
 *
 * The entries are asked for when the menu opens. They are things the page
 * already does with a button; one that cannot be done now is given `disabled`
 * and a `title` that says why.
 */
export function usePageMenu(entries) {
  const { openMenu } = useContextMenu()
  const latest = useRef(entries)
  latest.current = entries
  return useCallback((event) => openMenu(event, { page: true, items: latest.current() ?? [] }), [openMenu])
}

/**
 * What the application lends the sections of the menu that belong to no page
 * (components/menu/ambientMenu.js): who is signed in and what they may do, how
 * the search and the list of shortcuts open, how an indicator is looked up
 * and added. Called once, by App.
 */
export function useAmbientMenu(app) {
  const { lend } = useContextMenu()
  // Lent again at every render: the menu reads it when it opens.
  useEffect(() => {
    lend(app)
  })
  useEffect(() => () => lend(null), [lend])
}
