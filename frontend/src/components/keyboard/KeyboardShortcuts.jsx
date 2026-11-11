import { useEffect, useRef } from 'react'
import { useContextMenu } from '../../context/ContextMenuContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { isTypingTarget } from '../../domain/search.js'
import { SHORTCUTS, shortcutFor, shortcutMessage } from '../../domain/shortcuts.js'
import { hasModalLayer } from '../../lib/layers.js'
import { useStoredBoolean } from '../../lib/useStoredBoolean.js'
import { Modal } from '../ui/index.js'

/*
 * ============================================================================
 * KEYBOARD SHORTCUTS — F flags, C comments, ? lists them
 * ============================================================================
 *
 * F and C act on the row under the pointer, or on the focused row when the
 * analyst last moved with Tab, through that row's right-click menu
 * (ContextMenuContext.runShortcut). They are off while typing and while a
 * dialog or a menu is open, and can be turned off altogether in the list (the
 * choice is kept in this browser). The search shortcuts (Ctrl K, /) live in App.
 *
 * @param {{ open: boolean, onOpenChange: (open: boolean) => void }} props the "?" list
 */
export default function KeyboardShortcuts({ open, onOpenChange }) {
  const { runShortcut } = useContextMenu()
  const { showToast } = useToast()
  // Single keys can be switched off: they clash with dictation and with some assistive tools.
  const [enabled, setEnabled] = useStoredBoolean('nik.shortcuts.single-key', true)
  // Where the pointer is, and whether the keyboard moved last.
  const pointer = useRef({ x: -1, y: -1, keyboard: false })

  useEffect(() => {
    const onMove = (event) => {
      pointer.current = { x: event.clientX, y: event.clientY, keyboard: false }
    }
    /** The focused row first when Tab moved last, then whatever is under the pointer. */
    const targets = () => {
      const { x, y, keyboard } = pointer.current
      const focused = document.activeElement
      const under = x >= 0 ? document.elementFromPoint(x, y) : null
      return keyboard && focused && focused !== document.body ? [focused, under] : [under]
    }
    const onKeyDown = (event) => {
      // Tab moves the focus to a row; the arrows only scroll, the pointer still says which row.
      if (event.key === 'Tab') pointer.current.keyboard = true
      const kind = shortcutFor(event)
      if (!kind || !enabled || isTypingTarget(event.target)) return
      if (hasModalLayer() || document.querySelector('[role="menu"]')) return
      if (kind === 'help') {
        event.preventDefault()
        onOpenChange(true)
        return
      }
      const ran = targets().reduce((done, element) => done ?? runShortcut(kind, element), null)
      if (!ran) {
        showToast({ message: `Nothing to ${kind === 'flag' ? 'flag' : 'comment on'} under the pointer.` })
        return
      }
      event.preventDefault()
      const message = shortcutMessage(kind, ran.label, ran.title)
      // A flag removed takes its comments with it: one key brings it back.
      const undo = typeof ran.result?.undo === 'function' ? ran.result.undo : null
      if (message) showToast({ message, action: undo ? { label: 'Undo', run: undo } : undefined })
    }
    window.addEventListener('mousemove', onMove, { passive: true })
    window.addEventListener('keydown', onKeyDown)
    return () => {
      window.removeEventListener('mousemove', onMove)
      window.removeEventListener('keydown', onKeyDown)
    }
  }, [runShortcut, showToast, onOpenChange, enabled])

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
      <label className="mt-4 flex items-start gap-2 border-t border-line pt-3 text-sm text-fg">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(event) => setEnabled(event.target.checked)}
          className="mt-0.5 accent-[var(--color-accent)]"
        />
        <span>
          Single-key shortcuts (F, C, ?)
          <span className="block text-xs text-fg-muted">
            Turn them off if you dictate, or if they clash with the keys of an assistive tool. The menu and the keyboard
            button in the header still do the same. Kept in this browser.
          </span>
        </span>
      </label>
    </Modal>
  )
}
