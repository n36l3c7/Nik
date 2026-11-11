import { useEffect, useRef } from 'react'

/*
 * ============================================================================
 * LAYERS — what a dialog or a menu owes the keyboard
 * ============================================================================
 *
 * Dialogs open over dialogs (a confirmation inside Settings, the right-click
 * menu inside a dialog). They register here, in opening order, and only the
 * top one is spoken to:
 *
 *  - Escape closes the top layer, and nothing under it;
 *  - Tab stays inside the top layer (a modal dialog), going round from its
 *    last control to its first;
 *  - opening moves the focus into the layer, closing gives it back to what
 *    had it, so a keyboard user is where they were.
 *
 * useLayer(ref, { open, onClose, trap }) is all a component needs.
 */

const stack = []

const FOCUSABLE = [
  'a[href]',
  'button:not([disabled])',
  'input:not([disabled]):not([type="hidden"])',
  'select:not([disabled])',
  'textarea:not([disabled])',
  '[tabindex]:not([tabindex="-1"])',
].join(',')

/** The controls of `node` the Tab key stops on, in order. */
export function focusables(node) {
  return [...(node?.querySelectorAll(FOCUSABLE) ?? [])].filter(
    (element) => element.getClientRects().length > 0 && !element.closest('[inert]'),
  )
}

/** Where Tab goes from `active` inside `items`, or null when the browser's own move is right. */
export function nextInTrap(items, active, backwards) {
  if (items.length === 0) return null
  const index = items.indexOf(active)
  if (index === -1) return backwards ? items[items.length - 1] : items[0]
  if (backwards && index === 0) return items[items.length - 1]
  if (!backwards && index === items.length - 1) return items[0]
  return null
}

function onKeyDown(event) {
  const top = stack[stack.length - 1]
  if (!top) return
  if (event.key === 'Escape') {
    // The top layer only: a dialog under it stays open.
    event.stopPropagation()
    event.preventDefault()
    top.close()
    return
  }
  if (event.key !== 'Tab' || !top.trap) return
  const node = top.element()
  if (!node) return
  const target = nextInTrap(focusables(node), document.activeElement, event.shiftKey)
  if (target) {
    event.preventDefault()
    target.focus()
  } else if (!node.contains(document.activeElement)) {
    event.preventDefault()
    node.focus()
  }
}

/** True while a modal dialog is open (the single-key shortcuts stand down). */
export function hasModalLayer() {
  return stack.some((layer) => layer.trap)
}

/**
 * Register `ref`'s element as the top layer while `open`.
 * @param {{ current: HTMLElement | null }} ref
 * @param {{ open: boolean, onClose: () => void, trap?: boolean }} options
 *   `trap` keeps Tab inside (a modal dialog); a menu passes false.
 */
export function useLayer(ref, { open, onClose, trap = true }) {
  const closeRef = useRef(onClose)
  closeRef.current = onClose
  useEffect(() => {
    if (!open) return undefined
    const previous = document.activeElement
    const layer = { element: () => ref.current, close: () => closeRef.current?.(), trap }
    stack.push(layer)
    // Capture: before the page's own shortcuts see the key.
    if (stack.length === 1) window.addEventListener('keydown', onKeyDown, true)
    const node = ref.current
    // Unless a field inside asked for the focus itself (autoFocus).
    if (node && !node.contains(document.activeElement)) (focusables(node)[0] ?? node).focus({ preventScroll: true })
    return () => {
      stack.splice(stack.indexOf(layer), 1)
      if (stack.length === 0) window.removeEventListener('keydown', onKeyDown, true)
      if (previous instanceof HTMLElement && previous.isConnected) previous.focus({ preventScroll: true })
    }
  }, [open, ref, trap])
}
