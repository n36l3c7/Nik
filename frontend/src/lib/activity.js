import { isBackground, needsKeepAlive } from '../domain/signin.js'

/*
 * Whether the person is there.
 *
 * A session ends when nobody used it for a while, and the page itself must
 * not count as somebody: its lists refresh, its counts are asked again, for
 * as long as the tab is open. So the page watches what the person does (a
 * key, a click, the wheel, a touch) and services/api.js asks here, for every
 * request, whether the person did something just before: if not, the request
 * says it is the page's own (`X-Nik-Background`) and the server does not
 * count it as use. Nothing has to be marked where a request is made, and a
 * poll added tomorrow is covered like the ones of today.
 *
 * The other way round, somebody who works for a long time without any request
 * being sent (a long note being typed) is using the session: when they do
 * something and the server was not told for a while, `keepAlive` tells it.
 */

// Opening the page is the person's doing.
let lastInteraction = Date.now()
let lastForeground = 0
let keepAlive = null
let keepAliveEvery = 60_000
const listeners = new Set()

/** Whether a request sent now is the page's own rather than the person's. */
export function requestIsBackground(now = Date.now()) {
  return isBackground(lastInteraction, now)
}

/** A request of the person was sent: the server counts the session as used from now. */
export function noteForeground(now = Date.now()) {
  lastForeground = now
  listeners.forEach((listener) => listener(now))
}

/** Be told of every request of the person (the clock of the session follows them). Returns how to stop. */
export function onForeground(listener) {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

/**
 * What tells the server the person is there when no request of theirs did for `everyMs`
 * (null: nobody is signed in, nothing is told).
 */
export function setKeepAlive(tell, everyMs = 60_000) {
  keepAlive = tell
  keepAliveEvery = everyMs
}

function interacted() {
  const now = Date.now()
  lastInteraction = now
  if (keepAlive && needsKeepAlive(lastForeground, now, keepAliveEvery)) {
    lastForeground = now
    keepAlive()
  }
}

if (typeof window !== 'undefined') {
  for (const type of ['pointerdown', 'keydown', 'wheel', 'touchstart']) {
    window.addEventListener(type, interacted, { capture: true, passive: true })
  }
}
