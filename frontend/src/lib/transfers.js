import { cutText, wasCut, withTransfer, withoutTransfer } from '../domain/transfers.js'

/*
 * The transfers in flight that have no place of their own on the screen: a
 * file dropped anywhere that is being uploaded, an export being prepared from
 * a menu, a pack being fetched. They are shown in a tray at the foot of the
 * window (components/ui/Wait.jsx, <Transfers />) until they end.
 *
 *   const artifact = await transfer(`Uploading ${file.name}`, (onProgress) =>
 *     upload('/samples', file, { onProgress }))
 *
 * `work` is given what to call with `{ sent, total }` or `{ received, total }`
 * as the bytes pass; without a call the tray shows the (o.o) wait and the
 * sentence. The promise of `work` is returned as it is: errors are the
 * caller's to show.
 */

let list = []
let next = 1
const listeners = new Set()

const set = (changed) => {
  list = changed
  listeners.forEach((listener) => listener())
}

export const subscribeTransfers = (listener) => {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export const transfersNow = () => list

// What each transfer that was cut waits for: the person says "send again" or lets it go.
const decisions = new Map()

/** Try again a transfer the tray shows as cut. */
export const retryTransfer = (id) => decisions.get(id)?.(true)

/** Let go of a transfer the tray shows as cut: its error goes to who started it. */
export const dismissTransfer = (id) => decisions.get(id)?.(false)

/**
 * Show a transfer in the tray while `work` goes.
 *
 * A transfer the server went away under (a restart, an upgrade: `wasCut`) does not vanish and
 * does not hang: it stays in the tray with a sentence, "Try again" and "Dismiss". Tried again,
 * `work` is called anew and the promise goes on as if nothing had happened; dismissed, the error
 * is the caller's to show, as any other.
 *
 * @template T
 * @param {string} label  what is happening, without the final "…": "Uploading invoice.eml"
 * @param {(onProgress: (progress: object) => void) => Promise<T>} work
 * @returns {Promise<T>}
 */
export async function transfer(label, work) {
  const id = next++
  set(withTransfer(list, { id, label }))
  try {
    for (;;) {
      try {
        return await work((progress) => set(withTransfer(list, { id, ...progress })))
      } catch (error) {
        if (!wasCut(error)) throw error
        set(withTransfer(list, { id, failed: cutText(label), sent: 0, received: 0, total: 0 }))
        const again = await new Promise((resolve) => decisions.set(id, resolve))
        decisions.delete(id)
        if (!again) throw error
        set(withTransfer(list, { id, failed: '' }))
      }
    }
  } finally {
    decisions.delete(id)
    set(withoutTransfer(list, id))
  }
}
