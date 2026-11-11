import { useEffect, useRef } from 'react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { isTypingTarget } from '../../domain/search.js'
import { SHORTCUTS, shortcutFor, shortcutMessage } from '../../domain/shortcuts.js'
import { Modal } from '../ui/index.js'

/*
 * ============================================================================
 * KEYBOARD SHORTCUTS — F flags, C comments, ? lists them
 * ============================================================================
 *
 * F and C act on the row under the pointer, or on the focused element when the
 * analyst last moved with Tab or the arrows, through that row's right-click
 * menu (ContextMenuContext.runShortcut). They are off while typing and while a
 * dialog or a menu is open. The search shortcuts (Ctrl K, /) live in App.
 *
 * @param {{ open: boolean, onOpenChange: (open: boolean) => void }} props the "?" list
 */
export default function KeyboardShortcuts({ open, onOpenChange }) {
  const { runShortcut } = useContextMenu()
  const { showToast } = useToast()
  // Where the pointer is, and whether the keyboard moved last.
  const pointer = useRef({ x: -1, y: -1, keyboard: false })

  useEffect(() => {
    const onMove = (event) => {
      pointer.current = { x: event.clientX, y: event.clientY, keyboard: false }
    }
    const target = () => {
      const { x, y, keyboard } = pointer.current
      const focused = document.activeElement
      if (keyboard && focused && focused !== document.body) return focused
      return x >= 0 ? document.elementFromPoint(x, y) : null
    }
    const onKeyDown = (event) => {
      if (event.key === 'Tab' || event.key.startsWith('Arrow')) pointer.current.keyboard = true
      const kind = shortcutFor(event)
      if (!kind || isTypingTarget(event.target)) return
      if (document.querySelector('[role="dialog"], [role="menu"]')) return
      if (kind === 'help') {
        event.preventDefault()
        onOpenChange(true)
        return
      }
      const ran = runShortcut(kind, target())
      if (!ran) {
        showToast({ message: `Nothing to ${kind === 'flag' ? 'flag' : 'comment on'} under the pointer.` })
        return
      }
      event.preventDefault()
      const message = shortcutMessage(kind, ran.label, ran.title)
      if (message) showToast({ message })
    }
    window.addEventListener('mousemove', onMove, { passive: true })
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [runShortcut, showToast, onOpenChange])

  return (
    <Modal open={open} onClose={() => onOpenChange(false)} title="Keyboard shortcuts">
      <dl className="grid grid-cols-[auto_1fr] items-baseline gap-x-5 gap-y-2.5 text-sm">
        {SHORTCUTS.map((row) => (
          <div key={row.does} className="contents">
            <dt className="flex flex-wrap gap-1.5">
              {row.keys.map((key) => (
                <kbd
                  key={key}
                  className="whitespace-nowrap border border-line bg-canvas px-1.5 py-0.5 font-mono text-[11px] text-fg"
                >
                  {key}
                </kbd>
              ))}
            </dt>
            <dd className="text-fg-muted">{row.does}</dd>
          </div>
        ))}
      </dl>
    </Modal>
  )
}
