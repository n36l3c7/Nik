import { useCallback, useEffect, useState } from 'react'
import { clampWidth, paneKey, readWidth, stepWidth } from '../../domain/panes.js'

/*
 * ============================================================================
 * RESIZABLE SIDE PANELS
 * ============================================================================
 *
 * Every side panel of Nik can be made wider or narrower the same way: a thin
 * handle on the edge it shares with the page. Drag it, or focus it and use the
 * arrow keys (Shift for a larger step, Home and End for the limits); a
 * double-click or Enter puts the width back. The width is remembered for each
 * panel, in this browser.
 *
 *   const pane = useResizablePane('automation.library', { initial: 220, min: 180, max: 420 })
 *   <aside style={pane.style} className="w-full md:w-[var(--pane-w)]">…</aside>
 *   <ResizeHandle {...pane.handle} label="Resize the node library" className="hidden md:block" />
 *
 * `edge` says which edge of the panel the handle is on: 'right' for a panel on
 * the left of the page (the default), 'left' for one on the right.
 */

/**
 * @param {string} name   which panel (the key its width is remembered under)
 * @param {{ initial: number, min?: number, max?: number, edge?: 'left' | 'right' }} options
 */
export function useResizablePane(name, { initial, min = 180, max = 640, edge = 'right' }) {
  const limits = useCallback(() => ({ min, max, viewport: window.innerWidth }), [min, max])
  const [width, setWidth] = useState(() =>
    clampWidth(readWidth(localStorage, name) ?? initial, { min, max, viewport: window.innerWidth }),
  )

  const set = useCallback(
    (next) => {
      const clamped = clampWidth(next, limits())
      setWidth(clamped)
      try {
        localStorage.setItem(paneKey(name), String(clamped))
      } catch {
        // The width still applies to this visit.
      }
    },
    [name, limits],
  )
  const reset = useCallback(() => {
    setWidth(clampWidth(initial, limits()))
    try {
      localStorage.removeItem(paneKey(name))
    } catch {
      // Nothing was remembered.
    }
  }, [name, initial, limits])

  // A window made smaller takes the panel with it.
  useEffect(() => {
    const onResize = () => setWidth((current) => clampWidth(current, limits()))
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [limits])

  return {
    width,
    style: { '--pane-w': `${width}px` },
    handle: { width, min, max, edge, onWidth: set, onReset: reset },
  }
}

/**
 * @param {{
 *   label: string, width: number, min: number, max: number, edge?: 'left' | 'right',
 *   onWidth: (width: number) => void, onReset: () => void, className?: string,
 * }} props
 */
export default function ResizeHandle({ label, width, min, max, edge = 'right', onWidth, onReset, className = '' }) {
  const sign = edge === 'right' ? 1 : -1

  const onPointerDown = (event) => {
    if (event.button !== 0) return
    event.preventDefault()
    const startX = event.clientX
    const startWidth = width
    const move = (moved) => onWidth(startWidth + sign * (moved.clientX - startX))
    const up = () => {
      window.removeEventListener('pointermove', move)
      window.removeEventListener('pointerup', up)
      window.removeEventListener('pointercancel', up)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }
    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    window.addEventListener('pointermove', move)
    window.addEventListener('pointerup', up)
    window.addEventListener('pointercancel', up)
  }

  const onKeyDown = (event) => {
    if (event.key === 'Enter') {
      event.preventDefault()
      onReset()
      return
    }
    const next = stepWidth(width, event.key, { min, max, edge, large: event.shiftKey })
    if (next === null) return
    event.preventDefault()
    onWidth(next)
  }

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      aria-label={label}
      aria-valuenow={Math.round(width)}
      aria-valuemin={min}
      aria-valuemax={max}
      tabIndex={0}
      title="Drag to resize · arrow keys · double-click to reset"
      onPointerDown={onPointerDown}
      onDoubleClick={onReset}
      onKeyDown={onKeyDown}
      className={`group relative z-10 w-1 shrink-0 cursor-col-resize bg-transparent hover:bg-accent/30 focus-visible:bg-accent focus-visible:outline-none ${className}`}
    >
      {/* A wider strip to grab than the line that is drawn. */}
      <span className="absolute inset-y-0 -left-1 -right-1" />
    </div>
  )
}
