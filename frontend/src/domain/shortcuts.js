/*
 * Keyboard shortcuts.
 *
 * F and C act on "the row": the one under the pointer, or the focused one when
 * the analyst last moved with the keyboard. They run the item of the row's
 * right-click menu that carries the same `shortcut`, so every list that has
 * the menu has the shortcuts.
 */

/** The shortcuts listed by "?", in order. `keys` are alternatives. */
export const SHORTCUTS = [
  { keys: ['F'], does: 'Flag the row under the pointer, or remove its flag' },
  { keys: ['C'], does: 'Comment on the row under the pointer (it is flagged too)' },
  { keys: ['Ctrl K', '/'], does: 'Search incidents, indicators, samples and events' },
  { keys: ['Ctrl V'], does: 'Paste a file, an address or an indicator to analyse it' },
  { keys: ['Right-click'], does: 'Every action of a row or an item' },
  { keys: ['Shift + right-click'], does: "The browser's own menu" },
  { keys: ['↑', '↓', 'Enter'], does: 'Move in a menu and run the action' },
  { keys: ['Esc'], does: 'Close a menu or a dialog' },
  { keys: ['?'], does: 'This list' },
]

const KEYS = { f: 'flag', c: 'comment', '?': 'help' }

/**
 * The action a key press asks for ('flag' | 'comment' | 'help'), or null:
 * a plain key, with no Ctrl, Cmd or Alt, so copy and the browser's own
 * shortcuts are left alone.
 */
export function shortcutFor({ key, ctrlKey = false, metaKey = false, altKey = false, repeat = false } = {}) {
  if (ctrlKey || metaKey || altKey || repeat || typeof key !== 'string') return null
  return KEYS[key.toLowerCase()] ?? null
}

/** What the toast says after a shortcut ran the menu item with this label. */
export function shortcutMessage(kind, label, title = '') {
  if (kind !== 'flag') return ''
  const what = title ? `: ${title.length > 60 ? `${title.slice(0, 60)}…` : title}` : '.'
  return label === 'Remove the flag' ? `Flag removed${what}` : `Flagged${what}`
}
