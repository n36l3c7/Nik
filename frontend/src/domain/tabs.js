/*
 * The keyboard of a row of tabs (components/ui/Tabs.jsx): one tab is a Tab stop (the selected one),
 * the arrow keys move between the others, Home and End go to the ends. A disabled tab is skipped.
 */

/** The index a key moves to from `current`, or null when the key is not one of the row's. */
export function tabTarget(key, current, items) {
  const open = items.map((item, index) => (item.disabled ? -1 : index)).filter((index) => index >= 0)
  if (open.length === 0) return null
  if (key === 'Home') return open[0]
  if (key === 'End') return open[open.length - 1]
  if (key !== 'ArrowRight' && key !== 'ArrowLeft') return null
  const at = open.indexOf(current)
  if (at === -1) return key === 'ArrowRight' ? open[0] : open[open.length - 1]
  const step = key === 'ArrowRight' ? 1 : -1
  return open[(at + step + open.length) % open.length]
}

/** The index of the tab that is a Tab stop: the selected one, else the first that is not disabled. */
export function tabStop(value, items) {
  const selected = items.findIndex((item) => item.id === value && !item.disabled)
  return selected >= 0 ? selected : items.findIndex((item) => !item.disabled)
}
