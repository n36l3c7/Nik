import { useCallback } from 'react'
import { Braces, Copy, Link2 } from 'lucide-react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { objectMenuItems } from '../../domain/menus.js'

const ICONS = { link: Link2, copy: Copy, json: Braces }

/**
 * The right-click menu of an object of Nik that is not a row of evidence (a
 * playbook, a script, a run, a task, a dashboard, an entry of the War Room):
 *
 *   const menu = useObjectMenu()
 *   <tr onContextMenu={(event) => menu(event, { title, actions, link, copy, record, danger })}>
 *
 * See domain/menus.js for the sections. Rows of evidence, indicators and
 * artifacts use useItemMenu (useRowMenu.js), which adds flags and the rest.
 */
export function useObjectMenu() {
  const { openMenu } = useContextMenu()
  const { showToast } = useToast()

  return useCallback(
    (event, spec) => {
      const copyText = async (what, text) => {
        let done = true
        try {
          await navigator.clipboard.writeText(text)
        } catch {
          done = false
        }
        showToast({ message: done ? `${what} copied.` : 'The browser refused to copy.' })
      }
      const items = objectMenuItems(spec, { copyText, origin: window.location.origin, icons: ICONS })
      return openMenu(event, { title: spec.title ?? '', items })
    },
    [openMenu, showToast],
  )
}
