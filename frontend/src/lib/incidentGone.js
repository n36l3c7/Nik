/*
 * An incident deleted while it is open in another window.
 *
 * Every request about it then answers 404 "Incident not found", from whichever poll, save or click is the
 * first to ask: a dozen places, not all of them awaited with a catch. The API client (services/api.js) says
 * so here, once, for any of them; the app (App.jsx) takes the incident out of what it holds, goes back to the
 * list of incidents and says so in a toast. The error those requests throw is marked `incidentGone`, and the
 * page does not report as uncaught what was dealt with in one place.
 */

export const INCIDENT_GONE = 'Incident not found'

const PATH = /^\/incidents\/([^/?#]+)/

/** The id of the incident an answer says is gone, or null: a 404 with that sentence to a request about one. */
export function goneIncidentOf(status, detail, path) {
  if (status !== 404 || detail !== INCIDENT_GONE) return null
  const match = PATH.exec(path || '')
  if (!match) return null
  try {
    return decodeURIComponent(match[1])
  } catch {
    return null
  }
}

let handler = null

/** Register what happens when an incident is found gone (null: nothing). */
export function onIncidentGone(next) {
  handler = next
}

/** Called by the API client for each failed request. Returns whether the answer was that of a gone incident. */
export function reportIncidentGone(status, detail, path) {
  const id = goneIncidentOf(status, detail, path)
  if (id) handler?.(id)
  return Boolean(id)
}

/** An `unhandledrejection` listener that leaves alone the rejections of requests about a gone incident. */
export function ignoreGoneRejections(event) {
  if (event?.reason?.incidentGone) event.preventDefault()
}
