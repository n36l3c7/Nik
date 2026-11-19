/*
 * The address bar as the one source of truth for what the main area shows.
 *
 * Several contexts own a part of the address: the active incident
 * (/incident/<id>), an artifact on its own (/artifact/<id>), the IoC library
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

/** The path and query the address bar shows. */
export function currentPath() {
  return typeof window === 'undefined' ? '/' : window.location.pathname + window.location.search
}

/**
 * Go to `path` (a path, with its query if any). `replace` rewrites the
 * current history entry instead of adding one. Returns false when the address
 * is that one already.
 */
export function setPath(path, { replace = false, state = {} } = {}) {
  if (typeof window === 'undefined' || currentPath() === path) return false
  if (replace) window.history.replaceState(state, '', path)
  else window.history.pushState(state, '', path)
  window.dispatchEvent(new Event(LOCATION_EVENT))
  return true
}

/** Call `handler` whenever the address changes, by the app or by Back/Forward. */
export function onLocationChange(handler) {
  window.addEventListener('popstate', handler)
  window.addEventListener(LOCATION_EVENT, handler)
  return () => {
    window.removeEventListener('popstate', handler)
    window.removeEventListener(LOCATION_EVENT, handler)
  }
}

/**
 * An indicator's page, the Settings page, the Automations area and My tasks are drawn over whatever is open:
 * the incident, the artifact or the library under them stays as it is, and is
 * there again when they are left.
 */
export const isOverlayPage = (pathname) => /^\/(ioc|settings|automation|tasks|dashboards)(\/|$)/.test(pathname)
