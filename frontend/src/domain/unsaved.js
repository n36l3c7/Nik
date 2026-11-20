/*
 * What is being edited and has not been saved: the list the application keeps
 * so that nothing is lost without asking (lib/unsaved.js holds it, this file
 * is its arithmetic).
 *
 * An editing surface (a form, an editor, a dialog) enters the list while it
 * holds changes that are not saved, with:
 *
 *   id     its own key
 *   what   what it is, as the question names it: "The playbook"
 *   name   the name of the thing, when it has one: "Phishing triage"
 *   path   the address shown when it began to hold changes
 *   stays  optional: (path) => true for the addresses it stays on screen at
 *          (the tabs of one form each have an address)
 *   save   optional: saves it; rejects, or resolves false, when it could not
 *   sent   optional: true for what saves itself and is sent on the way out (the
 *          canvas of a playbook between two saves): leaving it inside the
 *          application loses nothing and asks nothing; only the browser's tab
 *          closing could lose it, and the browser asks then
 */

// An indicator's page is drawn over what is open: nothing under it is left.
const OVER_WHAT_IS_OPEN = /^\/ioc\//

// Settings, the Automations and My tasks are drawn over the incident, the artifact or the Indicators
// page too: what is being written there is on screen again when they are left.
const OVER_THE_MAIN_AREA = /^\/(settings|automation|tasks)(\/|$)/
const IN_THE_MAIN_AREA = /^\/(incident|artifact|iocs)(\/|$)/

const pathOnly = (path) => String(path ?? '').split('?')[0]

/** The list with `entry` in it (in place of the one with the same id). */
export function withEntry(entries, entry) {
  return [...entries.filter((item) => item.id !== entry.id), entry]
}

/** The list without the entry `id`. */
export function withoutEntry(entries, id) {
  return entries.filter((item) => item.id !== id)
}

/** True when `entry` is still on screen at the address `path`. */
export function staysAt(entry, path) {
  if (OVER_WHAT_IS_OPEN.test(pathOnly(path))) return true
  if (typeof entry.stays === 'function') return Boolean(entry.stays(pathOnly(path)))
  if (IN_THE_MAIN_AREA.test(pathOnly(entry.path)) && OVER_THE_MAIN_AREA.test(pathOnly(path))) return true
  return pathOnly(entry.path) === pathOnly(path)
}

/**
 * What a move would lose. With `only` (an id) the move leaves that surface
 * alone (its dialog is closed); with `path` it is a change of address, and
 * what stays on screen there is not lost; with neither, everything is.
 * `except` (an id) is the surface that makes the move itself, as it is saved.
 * `here` (an address) is for a move inside one screen (another item of its
 * list is chosen): what began to be edited at that address is lost, and what
 * waits under the screen, on the incident it is drawn over, is not.
 */
export function lostBy(entries, { path = null, only = null, except = null, here = null } = {}) {
  if (only !== null) return entries.filter((entry) => entry.id === only)
  const others = entries.filter((entry) => entry.id !== except && !entry.sent)
  if (here !== null) return others.filter((entry) => pathOnly(entry.path) === pathOnly(here))
  if (path === null) return others
  return others.filter((entry) => !staysAt(entry, path))
}

/** "The playbook Phishing triage has changes that are not saved." in its parts: the name is set apart. */
export function sentenceOf(entry) {
  const what = String(entry.what || 'This form').trim()
  const name = String(entry.name ?? '').trim()
  return { before: name ? `${what} ` : what, name, after: ' has changes that are not saved.' }
}

/** The same as one text (for a title, a list read aloud). */
export function sentenceText(entry) {
  const { before, name, after } = sentenceOf(entry)
  return `${before}${name}${after}`
}

/** "Save and leave" is offered when every surface that would be lost can be saved from here. */
export function canSaveAll(entries) {
  return entries.length > 0 && entries.every((entry) => typeof entry.save === 'function')
}

/**
 * Save every entry, one after the other, stopping at the first that fails.
 * Resolves with null when all were saved, with what to tell the person otherwise.
 */
export async function saveAll(entries) {
  for (const entry of entries) {
    try {
      const done = await entry.save()
      if (done === false) return `${sentenceOf(entry).before}${sentenceOf(entry).name}`.trim() + ' was not saved.'
    } catch (error) {
      return error?.message ? `It was not saved: ${error.message}` : 'It was not saved.'
    }
  }
  return null
}
