/*
 * The right-click menu of an object that is not a row of evidence: a playbook,
 * a script, a run, a task, a dashboard, an entry of the War Room. The same
 * sections in the same order everywhere:
 *
 *   actions   what the object offers (Open, Run…)
 *   copy      its link, then what else is worth copying (a name, an id), then
 *             the object as JSON
 *   danger    last, after a rule (Delete)
 *
 * The hook that opens it is components/menu/useObjectMenu.js; this is the part
 * that can be checked without a browser.
 */

/** Sections joined by a rule, without the empty ones and what is not an item. */
export function joinSections(sections) {
  const out = []
  for (const section of sections) {
    const items = (section ?? []).filter(Boolean)
    if (items.length === 0) continue
    if (out.length > 0) out.push('separator')
    out.push(...items)
  }
  return out
}

/** A path of Nik as a whole address, to be pasted elsewhere. */
export function absoluteLink(path, origin) {
  if (!path) return ''
  return new URL(path, origin).href
}

/**
 * The items of an object's menu. `copyText(what, text)` is what an item calls
 * to copy; `origin` is the address of this Nik.
 *
 * @param {{
 *   actions?: object[], link?: string | null, copy?: { label: string, text: string }[],
 *   record?: object | null, danger?: object[],
 * }} spec
 */
export function objectMenuItems(spec, { copyText, origin, icons = {} }) {
  const { actions = [], link = null, copy = [], record = null, danger = [] } = spec
  const copies = [
    link && {
      label: 'Copy link',
      icon: icons.link,
      onSelect: () => copyText('Link', absoluteLink(link, origin)),
    },
    ...copy
      .filter((entry) => entry && entry.text !== '' && entry.text !== null && entry.text !== undefined)
      .map((entry) => ({
        label: entry.label,
        icon: icons.copy,
        onSelect: () => copyText(entry.label.replace(/^Copy (the |its )?/i, ''), String(entry.text)),
      })),
    record && {
      label: 'Copy as JSON',
      icon: icons.json,
      onSelect: () => copyText('JSON', JSON.stringify(record, null, 2)),
    },
  ]
  return joinSections([actions, copies, danger])
}
