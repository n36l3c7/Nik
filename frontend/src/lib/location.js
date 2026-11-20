/*
 * The address bar as the one source of truth for what the main area shows.
 *
 * Several contexts own a part of the address: the active incident
 * (/incident/<id>), an artifact on its own (/artifact/<id>), the Indicators page
 * (/iocs…), an indicator's page (/ioc/<type>), the Settings page
 * (/settings/<group>/<section>) and the Automations area (/automation/…).
 * Each derives its state from
 * the address. The browser tells them about Back and Forward (`popstate`) but
 * not about the app's own pushState, so a change made by one context used to
 * leave the others showing what they showed before: the address changed and
 * the page did not, until a reload.
 *
 * setPath() changes the address and announces it; onLocationChange()
 * listens to both that announcement and Back/Forward.
 */

const LOCATION_EVENT = 'nik:location'

/*
 * Nothing unsaved is lost without asking (lib/unsaved.js). Every change of
 * address passes here, so here is where the question is asked: the guard is
 * given the address being gone to and how to go there, and answers true when
 * it keeps the move for itself (it goes once the person has agreed).
 *
 * Back and Forward have moved already when the browser says so. Each entry of
 * the history carries its position (`nik` in its state): the move is undone,
 * the question asked, and the move made again if the person leaves.
 */
let guard = null
// While a move the person agreed to, or one that only follows the screen, is carried out.
let free = false
// The position of the entry on screen, and what the next `popstate` is when it is our own doing.
let position = 0
let own = null // 'undo' | 'redo'

const isBrowser = typeof window !== 'undefined'
const positionOf = (state) => (state && typeof state.nik === 'number' ? state.nik : null)

if (isBrowser) {
  const here = positionOf(window.history.state)
  if (here === null) window.history.replaceState({ ...window.history.state, nik: 0 }, '')
  else position = here
  window.addEventListener('popstate', () => {
    const to = positionOf(window.history.state)
    if (own === 'undo') {
      // Back where the person was: nothing moved for the application.
      own = null
      return
    }
    if (own === 'redo') {
      own = null
    } else if (to !== null && to !== position && !free && guard) {
      const delta = to - position
      const go = () => {
        own = 'redo'
        window.history.go(delta)
      }
      if (guard(currentPath(), go)) {
        own = 'undo'
        window.history.go(-delta)
        return
      }
    }
    if (to === null) {
      // An entry the application did not number (a link to a place in the page, a state written by
      // hand): it takes the position of the one before it, so a move across it is never undone wrongly.
      window.history.replaceState({ ...window.history.state, nik: position }, '')
    } else {
      position = to
    }
    window.dispatchEvent(new Event(LOCATION_EVENT))
  })
}

/** Who is asked before the address changes: `(path, go) => true` when it keeps the move for itself. */
export function setLeaveGuard(next) {
  guard = next
}

/** Carry out `action` without asking: the person agreed already, or the address only follows the screen. */
export function freely(action) {
  const was = free
  free = true
  try {
    return action()
  } finally {
    free = was
  }
}

/** The path and query the address bar shows. */
export function currentPath() {
  return typeof window === 'undefined' ? '/' : window.location.pathname + window.location.search
}

/**
 * Go to `path` (a path, with its query if any). `replace` rewrites the
 * current history entry instead of adding one. Returns false when the address
 * is that one already, and when the move waits for the person's answer about
 * what is not saved.
 */
export function setPath(path, { replace = false, state = {} } = {}) {
  if (typeof window === 'undefined' || currentPath() === path) return false
  if (!free && guard?.(path, () => freely(() => setPath(path, { replace, state })))) return false
  if (replace) {
    window.history.replaceState({ ...state, nik: position }, '', path)
  } else {
    position += 1
    window.history.pushState({ ...state, nik: position }, '', path)
  }
  window.dispatchEvent(new Event(LOCATION_EVENT))
  return true
}

/** Call `handler` whenever the address changes, by the app or by Back/Forward. */
export function onLocationChange(handler) {
  window.addEventListener(LOCATION_EVENT, handler)
  return () => window.removeEventListener(LOCATION_EVENT, handler)
}

/**
 * An indicator's page, the Settings page, the Automations area and My tasks are drawn over whatever is open:
 * the incident, the artifact or the library under them stays as it is, and is
 * there again when they are left.
 */
export const isOverlayPage = (pathname) => /^\/(ioc|settings|automation|tasks|dashboards)(\/|$)/.test(pathname)
