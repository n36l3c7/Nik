/*
 * Which collection the dialog of its members is open on. A file dropped anywhere, "Import a collection…" and
 * the row of the Collections block all open it, and it is drawn once, by the app: this holds what to show
 * (`{ incidentId, sourceId }`, or null) and tells whoever listens.
 */
let open = null
const listeners = new Set()

export const openCollection = (incidentId, sourceId) => {
  open = incidentId && sourceId ? { incidentId, sourceId } : null
  listeners.forEach((listener) => listener())
}

export const closeCollection = () => openCollection(null, null)

export const collectionOpen = () => open

export const subscribeCollection = (listener) => {
  listeners.add(listener)
  return () => listeners.delete(listener)
}
