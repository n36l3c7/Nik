/*
 * The width of a side panel: its limits, where it is remembered, and what a
 * key does to it. The component is components/ui/ResizeHandle.jsx.
 */

/** A panel never takes more than this share of the window. */
export const VIEWPORT_SHARE = 0.6
export const STEP = 16
export const LARGE_STEP = 64

/** Where the width of a panel is remembered in the browser. */
export const paneKey = (name) => `nik.pane.${name}`

/** A width inside the panel's limits and the window's. */
export function clampWidth(width, { min, max, viewport = Infinity }) {
  const ceiling = Math.max(min, Math.min(max, Math.floor(viewport * VIEWPORT_SHARE)))
  const number = Number(width)
  if (!Number.isFinite(number)) return min
  return Math.round(Math.min(Math.max(number, min), ceiling))
}

/**
 * The width remembered for a panel, or null. `legacyKey` is where a release
 * before 5.0 kept it (the list of incidents had its own key).
 */
export function readWidth(storage, name, legacyKey = null) {
  for (const key of [paneKey(name), legacyKey]) {
    if (!key) continue
    let stored
    try {
      stored = storage.getItem(key)
    } catch {
      return null
    }
    const number = Number(stored)
    if (stored !== null && Number.isFinite(number) && number > 0) return number
  }
  return null
}

/**
 * The width after a key on the handle, or null when the key is not one of its
 * keys. The arrow that points away from the panel makes it wider: for a panel
 * with its handle on the right that is ArrowRight, on the left ArrowLeft.
 */
export function stepWidth(width, key, { min, max, edge = 'right', large = false }) {
  const step = large ? LARGE_STEP : STEP
  const wider = edge === 'right' ? 'ArrowRight' : 'ArrowLeft'
  const narrower = edge === 'right' ? 'ArrowLeft' : 'ArrowRight'
  if (key === wider) return Math.min(max, width + step)
  if (key === narrower) return Math.max(min, width - step)
  if (key === 'Home') return min
  if (key === 'End') return max
  return null
}
