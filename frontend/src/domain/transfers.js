/*
 * What a transfer says of itself while it goes: a file going up, one coming
 * down, something the server is preparing.
 *
 * The rule the whole application follows (components/ui/Wait.jsx draws it):
 * a transfer whose size is known shows a bar with how much of it is done; one
 * whose size is not known shows the (o.o) wait with a sentence that says what
 * is happening. Nothing waits behind a button that only goes grey.
 */

/** How much is done, 0 to 100, or null when the size is not known. `done` is `sent` or `received`. */
export function percentOf(progress) {
  const done = Number(progress?.sent ?? progress?.received ?? 0)
  const total = Number(progress?.total ?? 0)
  if (!Number.isFinite(total) || total <= 0 || !Number.isFinite(done)) return null
  return Math.max(0, Math.min(100, Math.round((done / total) * 100)))
}

/** A size as a person reads it: "812 B", "4.2 KB", "13.0 MB", "1.25 GB". */
export function sizeText(bytes) {
  const size = Math.max(0, Number(bytes) || 0)
  if (size < 1024) return `${Math.round(size)} B`
  if (size < 1024 ** 2) return `${(size / 1024).toFixed(1)} KB`
  if (size < 1024 ** 3) return `${(size / 1024 ** 2).toFixed(1)} MB`
  return `${(size / 1024 ** 3).toFixed(2)} GB`
}

/** "4.2 MB of 13.0 MB" when the size is known, "4.2 MB" when only what passed is, '' when nothing is. */
export function amountText(progress) {
  const done = Number(progress?.sent ?? progress?.received ?? 0)
  const total = Number(progress?.total ?? 0)
  if (total > 0) return `${sizeText(Math.min(done, total))} of ${sizeText(total)}`
  return done > 0 ? sizeText(done) : ''
}

/** The list of transfers with one added, changed (by its id) or taken away: what the tray shows. */
export function withTransfer(list, item) {
  return list.some((entry) => entry.id === item.id)
    ? list.map((entry) => (entry.id === item.id ? { ...entry, ...item } : entry))
    : [...list, item]
}

export const withoutTransfer = (list, id) => list.filter((entry) => entry.id !== id)
