import { useEffect, useId, useMemo, useRef, useSyncExternalStore } from 'react'
import { lostBy, saveAll, withEntry, withoutEntry } from '../domain/unsaved.js'
import { currentPath, freely, setLeaveGuard } from './location.js'

/*
 * ============================================================================
 * UNSAVED CHANGES — nothing is lost without asking
 * ============================================================================
 *
 * One list for the whole application of what is being edited and has not been
 * saved (domain/unsaved.js says what an entry is). A form, an editor or a
 * dialog enters it with
 *
 *   const unsaved = useUnsavedChanges(dirty, { what, name, save, stays })
 *
 * and is in it only while `dirty` is true. Whoever takes the person somewhere
 * else asks first:
 *
 *   leave(action)            everything unsaved would be lost (an entry of the
 *                            rail, another tab of the incident, signing out)
 *   leaveHere(action)        what is edited on this screen would be (another
 *                            item of its list is chosen by the screen itself)
 *   unsaved.leave(action)    this surface alone would be (its dialog is closed,
 *                            another item of its list is chosen)
 *   unsaved.leaveOthers(action)  everything but this surface, which is being
 *                            saved (what it creates takes the place of what is open)
 *
 * `action` runs at once when nothing would be lost; otherwise after the person
 * chose "Leave without saving" or "Save and leave" in the one dialog that asks
 * (components/ui/UnsavedDialog.jsx). A change of address needs no call: every
 * one passes through lib/location.js, which asks here, Back and Forward
 * included. Closing or reloading the browser's tab is the browser's own
 * question (`beforeunload`), listened to only while the list is not empty.
 *
 * A form that is sent and then takes the person somewhere (a new playbook
 * opens in its editor, a scanned address opens as an artifact) is still in
 * the list at that instant: it leaves it when the screen is drawn again. So
 * the question is not asked on the spot: the move waits a moment, and is
 * simply made if by then nothing it would lose is left.
 */

// How long a move that would lose something waits before the question: time for a form that has
// just been sent to close and leave the list.
const SETTLE_MS = 40

let entries = []
// The question on screen: { lost, go, saving, error }, or null.
let asking = null
// A move that waits to know whether it loses anything (see above).
let settling = false
// What the person agreed to leave: not asked about again by what follows from the same answer (a move
// made of several steps, one of them after a request to the server), until they act again.
let released = new Set()
const stillHeld = () => (released.size ? entries.filter((entry) => !released.has(entry.id)) : entries)

function release(lost) {
  released = new Set(lost.map((entry) => entry.id))
  if (typeof window === 'undefined') return
  const forget = () => {
    released = new Set()
    window.removeEventListener('pointerdown', forget, true)
    window.removeEventListener('keydown', forget, true)
  }
  window.addEventListener('pointerdown', forget, true)
  window.addEventListener('keydown', forget, true)
}
const listeners = new Set()

const emit = () => listeners.forEach((listener) => listener())
const subscribe = (listener) => {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function beforeUnload(event) {
  event.preventDefault()
  event.returnValue = ''
}

function setEntries(next) {
  const had = entries.length > 0
  entries = next
  if (typeof window !== 'undefined' && had !== entries.length > 0) {
    if (entries.length > 0) window.addEventListener('beforeunload', beforeUnload)
    else window.removeEventListener('beforeunload', beforeUnload)
  }
  emit()
}

/**
 * Whether the move `what` describes may be made at once; when not, `go` is kept: it is made after the
 * person agreed, or by itself when what it would have lost was saved in the meantime.
 */
function free(what, go) {
  if (lostBy(stillHeld(), what).length === 0) return true
  // One question at a time: a second move while one waits or is asked about is dropped.
  if (asking || settling) return false
  settling = true
  setTimeout(() => {
    settling = false
    const lost = lostBy(stillHeld(), what)
    if (lost.length === 0) {
      freely(go)
      return
    }
    asking = { lost, go, saving: false, error: null }
    emit()
  }, SETTLE_MS)
  return false
}

/** Do `action`, after asking when it would lose something that is not saved. */
export function leave(action, { path = null, only = null, except = null, here = null } = {}) {
  if (free({ path, only, except, here }, action)) action()
}

/** Do `action`, after asking when what is being edited on the screen shown would be lost. */
export const leaveHere = (action) => leave(action, { here: currentPath() })

/** The person's answer to the question: 'stay', 'leave' or 'save'. */
export async function answer(choice) {
  const question = asking
  if (!question || question.saving) return
  if (choice === 'stay') {
    asking = null
    emit()
    return
  }
  if (choice === 'save') {
    asking = { ...question, saving: true, error: null }
    emit()
    const error = await saveAll(question.lost)
    if (error) {
      asking = { ...question, saving: false, error }
      emit()
      return
    }
  }
  asking = null
  emit()
  release(question.lost)
  freely(question.go)
}

// A change of address, asked by lib/location.js.
setLeaveGuard((path, go) => !free({ path }, go))

/**
 * Enter the list while `dirty`.
 * @param {boolean} dirty  true while what is on screen differs from what was loaded
 * @param {{ what?: string, name?: string, save?: () => Promise<unknown>, stays?: (path: string) => boolean,
 *   sent?: boolean }} options  (domain/unsaved.js says what each is)
 * @returns {{ leave: (action: () => void) => void, leaveOthers: (action: () => void) => void }}
 *   `leave` asks about this surface alone before `action` (its dialog is closed); `leaveOthers` about
 *   every other one (this one is being saved, and what it makes takes the place of what is open)
 */
export function useUnsavedChanges(dirty, { what, name, save, stays, sent = false } = {}) {
  const id = useId()
  const latest = useRef({})
  latest.current = { what, name, save, stays }
  const canSave = typeof save === 'function'
  const canStay = typeof stays === 'function'
  useEffect(() => {
    if (!dirty) return undefined
    setEntries(
      withEntry(entries, {
        id,
        sent,
        path: currentPath(),
        get what() {
          return latest.current.what
        },
        get name() {
          return latest.current.name
        },
        save: canSave ? () => latest.current.save?.() : undefined,
        stays: canStay ? (path) => latest.current.stays?.(path) : undefined,
      }),
    )
    return () => setEntries(withoutEntry(entries, id))
  }, [dirty, id, canSave, canStay, sent])
  return useMemo(
    () => ({
      leave: (action) => leave(action, { only: id }),
      leaveOthers: (action) => leave(action, { except: id }),
    }),
    [id],
  )
}

const getAsking = () => asking
const getEntries = () => entries

/** The question on screen, for the dialog that asks it. */
export const useLeaveQuestion = () => useSyncExternalStore(subscribe, getAsking, getAsking)

/** Everything that is not saved, for who must say so (the session that ended). */
export const useUnsavedList = () => useSyncExternalStore(subscribe, getEntries, getEntries)
