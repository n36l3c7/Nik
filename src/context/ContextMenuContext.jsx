import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { Button, Modal } from '../components/ui/index.js'

/*
 * ============================================================================
 * RIGHT-CLICK MENU — one menu for the whole app
 * ============================================================================
 *
 * A component opts in with
 *   onContextMenu={(event) => openMenu(event, { title, items })}
 * where items are { label, icon?, hint?, onSelect, disabled?, indent? } or
 * 'separator'. Everything else keeps the browser's own menu, and so do text
 * fields, selected text and Shift + right-click, so copy/paste still works.
 * Arrow keys move, Enter runs, Esc closes.
 *
 * askText({ title, label, placeholder, confirm }) asks for a line of text in a
 * small dialog (e.g. a flag comment) and resolves to the text or null.
 */

const ContextMenuContext = createContext(null)

const MENU_WIDTH = 260

/** True when the browser's own menu should open instead of ours. */
export function wantsNativeMenu(event) {
  if (event.shiftKey) return true
  const target = event.target
  const tag = target?.tagName
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || target?.isContentEditable) return true
  const selection = window.getSelection?.()
  return Boolean(selection && !selection.isCollapsed && selection.toString().trim())
}

function Menu({ menu, onClose }) {
  const ref = useRef(null)
  const [position, setPosition] = useState({ left: menu.x, top: menu.y })
  const actionable = menu.items
    .map((item, i) => (item !== 'separator' && !item.disabled ? i : -1))
    .filter((i) => i >= 0)
  const [cursor, setCursor] = useState(actionable[0] ?? -1)

  useLayoutEffect(() => {
    const box = ref.current?.getBoundingClientRect()
    if (!box) return
    setPosition({
      left: Math.max(8, Math.min(menu.x, window.innerWidth - box.width - 8)),
      top: Math.max(8, Math.min(menu.y, window.innerHeight - box.height - 8)),
    })
    ref.current.focus()
  }, [menu])

  const run = (item) => {
    onClose()
    item.onSelect?.()
  }

  const onKeyDown = (event) => {
    const at = actionable.indexOf(cursor)
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setCursor(actionable[(at + 1) % actionable.length])
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setCursor(actionable[(at - 1 + actionable.length) % actionable.length])
    } else if (event.key === 'Enter' && cursor >= 0) {
      event.preventDefault()
      run(menu.items[cursor])
    } else if (event.key === 'Escape' || event.key === 'Tab') {
      event.preventDefault()
      onClose()
    }
  }

  return (
    <div
      ref={ref}
      role="menu"
      tabIndex={-1}
      aria-label={menu.title || 'Actions'}
      onKeyDown={onKeyDown}
      onContextMenu={(e) => e.preventDefault()}
      style={{ left: position.left, top: position.top, width: MENU_WIDTH }}
      className="fixed z-[70] border border-line bg-raised py-1 text-[13px] text-fg shadow-2xl focus:outline-none"
    >
      {menu.title && (
        <div
          className="mb-1 truncate border-b border-line px-3 pb-1.5 pt-1 font-mono text-[11px] text-fg-subtle"
          title={menu.title}
        >
          {menu.title}
        </div>
      )}
      {menu.items.map((item, i) => {
        if (item === 'separator') return <div key={`sep-${i}`} className="my-1 h-px bg-line" role="separator" />
        const Icon = item.icon
        return (
          <div
            key={item.label}
            role="menuitem"
            aria-disabled={item.disabled || undefined}
            onMouseEnter={() => !item.disabled && setCursor(i)}
            onClick={() => !item.disabled && run(item)}
            className={[
              'flex cursor-default items-center gap-2.5 py-1.5 pr-3',
              item.indent ? 'pl-9 text-fg-muted' : 'pl-3',
              item.disabled ? 'opacity-40' : '',
              cursor === i ? 'bg-accent-soft' : '',
            ].join(' ')}
          >
            {Icon && <Icon className="h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden="true" />}
            <span className="min-w-0 flex-1 truncate">{item.label}</span>
            {item.hint && <span className="shrink-0 font-mono text-[11px] text-fg-subtle">{item.hint}</span>}
          </div>
        )
      })}
    </div>
  )
}

function TextPrompt({ prompt, onDone }) {
  const [text, setText] = useState('')
  const submit = (event) => {
    event.preventDefault()
    onDone(text.trim() || null)
  }
  return (
    <Modal
      open
      onClose={() => onDone(null)}
      title={prompt.title}
      footer={
        <>
          <Button variant="secondary" onClick={() => onDone(null)}>
            Cancel
          </Button>
          <Button type="submit" form="text-prompt" disabled={!text.trim()}>
            {prompt.confirm ?? 'Save'}
          </Button>
        </>
      }
    >
      <form id="text-prompt" onSubmit={submit} className="space-y-2">
        <label htmlFor="text-prompt-input" className="block font-mono text-xs text-fg-muted">
          {prompt.label}
        </label>
        <textarea
          id="text-prompt-input"
          autoFocus
          rows={3}
          value={text}
          onChange={(e) => setText(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) submit(e)
          }}
          placeholder={prompt.placeholder}
          className="w-full border border-line bg-canvas px-3 py-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
      </form>
    </Modal>
  )
}

export function ContextMenuProvider({ children }) {
  const [menu, setMenu] = useState(null)
  const [prompt, setPrompt] = useState(null)
  const close = useCallback(() => setMenu(null), [])

  const openMenu = useCallback((event, { title = '', items = [] }) => {
    if (wantsNativeMenu(event)) return false
    const visible = items.filter(Boolean)
    if (visible.length === 0) return false
    event.preventDefault()
    event.stopPropagation()
    setMenu({ x: event.clientX, y: event.clientY, title, items: visible })
    return true
  }, [])

  const askText = useCallback((options) => new Promise((resolve) => setPrompt({ ...options, resolve })), [])

  useEffect(() => {
    if (!menu) return undefined
    const onPointer = (event) => {
      if (!event.target.closest?.('[role="menu"]')) close()
    }
    window.addEventListener('pointerdown', onPointer, true)
    window.addEventListener('resize', close)
    window.addEventListener('scroll', close, true)
    window.addEventListener('blur', close)
    return () => {
      window.removeEventListener('pointerdown', onPointer, true)
      window.removeEventListener('resize', close)
      window.removeEventListener('scroll', close, true)
      window.removeEventListener('blur', close)
    }
  }, [menu, close])

  const value = useMemo(() => ({ openMenu, askText }), [openMenu, askText])
  return (
    <ContextMenuContext.Provider value={value}>
      {children}
      {menu && <Menu menu={menu} onClose={close} />}
      {prompt && (
        <TextPrompt
          prompt={prompt}
          onDone={(text) => {
            prompt.resolve(text)
            setPrompt(null)
          }}
        />
      )}
    </ContextMenuContext.Provider>
  )
}

/** `{ openMenu(event, { title, items }), askText(options) }` */
export function useContextMenu() {
  const ctx = useContext(ContextMenuContext)
  if (!ctx) throw new Error('useContextMenu must be used inside <ContextMenuProvider>')
  return ctx
}
