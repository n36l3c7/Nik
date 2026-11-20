import { useCallback, useRef } from 'react'
import {
  Bug,
  ClipboardPaste,
  Copy,
  CopyPlus,
  LayoutGrid,
  Maximize,
  PanelRight,
  Plus,
  Redo2,
  Scissors,
  SquareDashed,
  Trash2,
  Undo2,
  Unlink,
} from 'lucide-react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { editorMenu } from '../../domain/automation/editorMenu.js'

const ICONS = {
  open: PanelRight,
  debug: Bug,
  duplicate: CopyPlus,
  copy: Copy,
  cut: Scissors,
  paste: ClipboardPaste,
  disconnect: Unlink,
  remove: Trash2,
  removeLine: Trash2,
  add: Plus,
  selectAll: SquareDashed,
  fit: Maximize,
  tidy: LayoutGrid,
  undo: Undo2,
  redo: Redo2,
}

/**
 * The right-click menu of the playbook editor:
 *
 *   const onMenu = useEditorMenu(stateOf, actions)
 *   <Canvas onMenu={onMenu} />
 *
 * `stateOf()` gives what the menu depends on when it opens (the graph, why
 * nothing can be changed, what was copied: see domain/automation/editorMenu.js,
 * which decides the entries). `actions` has a function for each entry, by its
 * id, called with what was right-clicked and with the view of the canvas.
 */
export function useEditorMenu(stateOf, actions) {
  const { openMenu } = useContextMenu()
  // Read when the menu opens: the page gives new functions at every render.
  const latest = useRef(null)
  latest.current = { stateOf, actions }
  return useCallback(
    (event, target, view) => {
      const now = latest.current
      const menu = editorMenu(target, now.stateOf())
      const items = menu.items.map((item) =>
        item === 'separator'
          ? item
          : { ...item, icon: ICONS[item.id], onSelect: () => now.actions[item.id]?.(target, view) },
      )
      // Asked for by the menu key, the canvas opens it itself: the general section ends it all the same.
      return openMenu(event, { title: menu.title, items, general: true })
    },
    [openMenu],
  )
}
