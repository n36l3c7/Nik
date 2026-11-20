import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { Button, Modal } from '../components/ui/index.js'
import { ambientItems } from '../components/menu/ambientMenu.js'
import { isMenuKey, keyboardPoint, menuSections } from '../domain/contextMenu.js'
import { joinSections } from '../domain/menus.js'
import { useLayer } from '../lib/layers.js'
import { behindDialog, depthOf, underPointer } from '../lib/underPointer.js'
import { useToast } from './ToastContext.jsx'

/*
 * ============================================================================
 * RIGHT-CLICK MENU — one menu for the whole app, and never the browser's
 * ============================================================================
 *
 * The rule is kept here, in one place: a `contextmenu` event anywhere in the
 * app is stopped before the browser shows its menu, and Nik's opens instead.
 * No page has to do anything for that, and no key brings the browser's back.
 *
 * What the menu holds is collected while the event travels from what is under
 * the pointer outward (domain/contextMenu.js has the order of the sections):
 *
 *  - an object says what it offers with
 *      onContextMenu={(event) => openMenu(event, { title, items })}
 *    where items are { label, icon?, hint?, shortcut?, onSelect, disabled?,
 *    title?, indent? } or 'separator' (`title` is said when the item is pointed
 *    at: why it is disabled). The innermost object is the one of the menu;
 *  - a page adds entries of its own with `page: true` (usePageMenu);
 *  - selected text, a text field, a link, a cell or a line of text are found
 *    on the page itself (lib/underPointer.js), and the general section ends
 *    every menu (components/menu/ambientMenu.js).
 *
 * The menu key and Shift + F10 ask for the same menu on what has the focus.
 * Arrow keys move, Enter runs, Esc closes. An item whose onSelect returns
 * `{ message, undo }` (a flag removed with its comments) gets a toast with Undo.
 *
 * openMenu() called outside a right-click (a button that opens a menu under
 * itself) shows its items as they are; `general: true` adds the general
 * section to them.
 *
 * runShortcut(kind, element) runs, without showing the menu, the item with that
 * `shortcut` ('flag', 'comment') of the menu `element` would open on right-click:
 * a key acts on a row exactly as its menu does. It resolves to { label, title,
 * result } of the item that ran (`result` is what its onSelect returned), or
 * null when the element offers none. It asks the element the way a right-click
 * would, with a `contextmenu` event of its own making: an onContextMenu that
 * does anything else than open a menu must ignore it (isShortcutProbe).
 *
 * askText({ title, label, placeholder, confirm }) asks for a line of text in a
 * small dialog (e.g. a flag comment) and resolves to the text or null.
 */

const ContextMenuContext = createContext(null)

const MENU_WIDTH = 260

/**
 * True for a `contextmenu` event that is not a right-click: the one
 * runShortcut dispatches to find a row's menu, and the one the menu key
 * makes. A handler with an effect of its own, such as applying a filter,
 * returns at once on it.
 */
export function isShortcutProbe(event) {
  return (event?.nativeEvent ?? event)?.isTrusted === false
}

function Menu({ menu, onClose, onResult }) {
  const ref = useRef(null)
  const [position, setPosition] = useState({ left: menu.x, top: menu.y })
  const actionable = menu.items
    .map((item, i) => (item !== 'separator' && !item.disabled ? i : -1))
    .filter((i) => i >= 0)
  const [cursor, setCursor] = useState(actionable[0] ?? -1)
  // Escape closes the menu and nothing under it; the focus returns to the row.
  useLayer(ref, { open: true, onClose, trap: false })

  useLayoutEffect(() => {
    const box = ref.current?.getBoundingClientRect()
    if (!box) return
    setPosition({
      left: Math.max(8, Math.min(menu.x, window.innerWidth - box.width - 8)),
      top: Math.max(8, Math.min(menu.y, window.innerHeight - box.height - 8)),
    })
    // The focus is taken by the layer (useLayer), which first notes what had it, to give it back.
  }, [menu])

  const run = (item) => {
    onClose()
    onResult(item.onSelect?.())
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
    } else if (event.key === 'Tab') {
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
      aria-activedescendant={cursor >= 0 ? `nik-menu-item-${cursor}` : undefined}
      data-nik-menu=""
      onKeyDown={onKeyDown}
      // The press of a choice takes nothing away: the selected text and the focus stay as they are.
      onMouseDown={(event) => event.preventDefault()}
      style={{ left: position.left, top: position.top, width: MENU_WIDTH }}
      className="fixed z-[70] max-h-[calc(100vh-16px)] overflow-y-auto border border-line bg-raised py-1 text-[13px] text-fg shadow-2xl focus:outline-none"
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
            key={`${i}-${item.label}`}
            id={`nik-menu-item-${i}`}
            role="menuitem"
            aria-disabled={item.disabled || undefined}
            title={item.title || undefined}
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
  const { showToast } = useToast()
  /** What an item returned: when it can be undone, say so and offer it. */
  const offerUndo = useCallback(
    (result) => {
      if (typeof result?.undo !== 'function') return
      showToast({ message: result.message || 'Done.', action: { label: 'Undo', run: result.undo } })
    },
    [showToast],
  )
  // Set while runShortcut dispatches its event: openMenu then runs an item instead of showing the menu.
  const shortcutRef = useRef(null)

  // What the application lends the sections that belong to no page (useAmbientMenu).
  const app = useRef({})
  const lend = useCallback((lent) => {
    app.current = lent ?? {}
  }, [])
  const say = useCallback((message) => showToast({ message }), [showToast])
  const general = useCallback(() => ambientItems('general', {}, app.current, say), [say])

  // The right-click being answered: what the elements it passes through offer.
  const asked = useRef(null)

  const openMenu = useCallback(
    (event, { title = '', items = [], page = false, general: withGeneral = false }) => {
      const native = event?.nativeEvent ?? event
      const pending = shortcutRef.current
      if (pending) {
        const item = items.find((entry) => entry?.shortcut === pending.kind && !entry.disabled)
        // None here: the event goes on to the elements around, as a right-click would.
        if (!item) return false
        event.preventDefault()
        event.stopPropagation()
        pending.ran = { label: item.label, title, result: item.onSelect?.() }
        return true
      }
      const visible = items.filter(Boolean)
      if (visible.length === 0) return false
      const collecting = asked.current
      if (collecting && collecting.event === native) {
        const at = event.currentTarget instanceof Element ? event.currentTarget : native.target
        // What is around a dialog has nothing to say about a right-click inside it.
        if (behindDialog(at, native.target)) return false
        if (page) collecting.pages.push(visible)
        // The innermost object is the one the menu is about.
        else if (!collecting.object) collecting.object = { title, items: visible, at }
        return true
      }
      // Asked for by a button, or by a key the page handles itself: shown at once.
      setMenu({
        at: Date.now(),
        x: event.clientX,
        y: event.clientY,
        title,
        items: withGeneral ? joinSections([visible, general()]) : visible,
      })
      return true
    },
    [general],
  )

  // The rule: no `contextmenu` event shows the browser's menu, and each one opens Nik's.
  useEffect(() => {
    const finish = (event) => {
      const collecting = asked.current
      if (!collecting || collecting.event !== event) return
      asked.current = null
      const under = underPointer(event, { keyboard: collecting.keyboard })
      const { object, pages } = collecting
      const kinds = menuSections({
        inMenu: under.inMenu,
        selection: Boolean(under.selection),
        things: [...under.things, ...(object ? [{ kind: 'object', depth: depthOf(under.target, object.at) }] : [])],
        page: pages.length > 0,
      })
      const items = joinSections(
        kinds.flatMap((kind) => {
          if (kind === 'object') return [object.items]
          if (kind === 'page') return pages
          return [ambientItems(kind, under, app.current, say)]
        }),
      )
      if (items.length > 0)
        setMenu({ at: event.timeStamp, x: event.clientX, y: event.clientY, title: object?.title ?? '', items })
    }
    const onAsk = (event) => {
      event.preventDefault()
      // A key looking for a row's item (runShortcut): nothing is shown.
      if (shortcutRef.current) return
      asked.current = { event, object: null, pages: [], keyboard: Boolean(event.nikKeyboard) }
      // Should something on the way stop the event, the menu still opens.
      setTimeout(() => finish(event), 0)
    }
    // The menu key and Shift + F10: the menu of what has the focus, where it is.
    const onKey = (event) => {
      if (!isMenuKey(event) || event.defaultPrevented) return
      event.preventDefault()
      const focused = document.activeElement instanceof Element ? document.activeElement : document.body
      if (focused.closest('[data-nik-menu]')) return
      const nothing = focused === document.body || focused === document.documentElement
      const point = keyboardPoint(nothing ? null : focused.getBoundingClientRect(), {
        width: window.innerWidth,
        height: window.innerHeight,
      })
      const made = new MouseEvent('contextmenu', {
        bubbles: true,
        cancelable: true,
        clientX: point.x,
        clientY: point.y,
      })
      made.nikKeyboard = true
      focused.dispatchEvent(made)
    }
    window.addEventListener('contextmenu', onAsk, true)
    window.addEventListener('contextmenu', finish)
    window.addEventListener('keydown', onKey)
    return () => {
      window.removeEventListener('contextmenu', onAsk, true)
      window.removeEventListener('contextmenu', finish)
      window.removeEventListener('keydown', onKey)
    }
  }, [say])

  const runShortcut = useCallback((kind, element) => {
    if (!element?.isConnected) return null
    const box = element.getBoundingClientRect()
    const pending = { kind, ran: null }
    shortcutRef.current = pending
    try {
      element.dispatchEvent(
        new MouseEvent('contextmenu', {
          bubbles: true,
          cancelable: true,
          clientX: box.left + box.width / 2,
          clientY: box.top + box.height / 2,
        }),
      )
    } finally {
      shortcutRef.current = null
    }
    return pending.ran
  }, [])

  const askText = useCallback((options) => new Promise((resolve) => setPrompt({ ...options, resolve })), [])

  useEffect(() => {
    if (!menu) return undefined
    const onPointer = (event) => {
      if (!event.target.closest?.('[data-nik-menu]')) close()
    }
    // The analyst scrolling closes the menu (it would no longer point at its
    // row). A `scroll` event is not used: the browser also fires it when a list
    // above reloads and the page re-anchors, which would close the menu at once.
    window.addEventListener('pointerdown', onPointer, true)
    window.addEventListener('wheel', onPointer, { capture: true, passive: true })
    window.addEventListener('touchmove', onPointer, { capture: true, passive: true })
    window.addEventListener('resize', close)
    window.addEventListener('blur', close)
    return () => {
      window.removeEventListener('pointerdown', onPointer, true)
      window.removeEventListener('wheel', onPointer, true)
      window.removeEventListener('touchmove', onPointer, true)
      window.removeEventListener('resize', close)
      window.removeEventListener('blur', close)
    }
  }, [menu, close])

  const value = useMemo(() => ({ openMenu, askText, runShortcut, lend }), [openMenu, askText, runShortcut, lend])
  return (
    <ContextMenuContext.Provider value={value}>
      {children}
      {/* A menu asked for while one is open is a new menu: it starts on its own first entry. */}
      {menu && <Menu key={menu.at} menu={menu} onClose={close} onResult={offerUndo} />}
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

/** `{ openMenu(event, { title, items, page?, general? }), askText(options), runShortcut(kind, element), lend(app) }` */
export function useContextMenu() {
  const ctx = useContext(ContextMenuContext)
  if (!ctx) throw new Error('useContextMenu must be used inside <ContextMenuProvider>')
  return ctx
}
