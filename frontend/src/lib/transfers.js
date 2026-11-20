import { withTransfer, withoutTransfer } from '../domain/transfers.js'

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

/**
 * Show a transfer in the tray while `work` goes.
 * @template T
 * @param {string} label  what is happening, without the final "…": "Uploading invoice.eml"
 * @param {(onProgress: (progress: object) => void) => Promise<T>} work
 * @returns {Promise<T>}
 */
export async function transfer(label, work) {
  const id = next++
  set(withTransfer(list, { id, label }))
  try {
    return await work((progress) => set(withTransfer(list, { id, ...progress })))
  } finally {
    set(withoutTransfer(list, id))
  }
}
