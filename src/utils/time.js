/*
 * Timestamp conversion and formatting utilities.
 *
 * Chrome/Chromium store timestamps in "WebKit time": microseconds elapsed
 * since January 1st, 1601 (Windows epoch). The conversion to Unix epoch (ms)
 * is:  ms = webkit_us / 1000 - 11644473600000
 * (equivalent to the SQL query: visit_time/1000000 - 11644473600 seconds).
 */

/** Offset between the 1601 epoch (WebKit/Windows) and the 1970 epoch (Unix), in milliseconds. */
export const WEBKIT_EPOCH_OFFSET_MS = 11644473600000

/**
 * Converts a WebKit timestamp (microseconds since 1601, number or string,
 * such as `visits.visit_time` or `date_added` of Chrome/Chromium Bookmarks)
 * to Unix epoch ms. Returns null for missing or non-numeric values.
 */
export function webkitToMs(webkitMicroseconds) {
  const us = Number(webkitMicroseconds)
  if (!Number.isFinite(us) || us <= 0) return null
  return Math.round(us / 1000) - WEBKIT_EPOCH_OFFSET_MS
}

/**
 * Converts a Firefox "PRTime" timestamp (microseconds since 1970, such as
 * `moz_historyvisits.visit_date` or `moz_bookmarks.dateAdded`) to Unix epoch ms.
 * Unlike Chrome, Firefox does NOT use the 1601 epoch: just divide by 1000.
 * Returns null for missing or non-numeric values.
 */
export function firefoxToMs(prTimeMicroseconds) {
  const us = Number(prTimeMicroseconds)
  if (!Number.isFinite(us) || us <= 0) return null
  return Math.round(us / 1000)
}

/**
 * Interprets an "arbitrary" time value coming from CSV/JSON exports of
 * forensic tools and normalizes it to Unix epoch ms:
 *  - number > 1e14  => WebKit microseconds
 *  - number > 1e11  => already Unix ms
 *  - number > 1e8   => Unix seconds
 *  - string         => parsed as a date (ISO or "YYYY-MM-DD HH:MM:SS")
 */
export function anyToMs(value) {
  if (value === null || value === undefined || value === '') return null
  const n = Number(value)
  if (Number.isFinite(n)) {
    if (n > 1e14) return webkitToMs(n)
    if (n > 1e11) return Math.round(n)
    if (n > 1e8) return Math.round(n * 1000)
    return null
  }
  const parsed = Date.parse(String(value).replace(' ', 'T'))
  return Number.isFinite(parsed) ? parsed : null
}

/** Formats a timestamp (ms) as a readable date + time in the en-GB locale. */
export function formatDateTime(ms) {
  if (!Number.isFinite(ms)) return '—'
  return new Date(ms).toLocaleString('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

/** Formats a timestamp (ms) as a date only. */
export function formatDate(ms) {
  if (!Number.isFinite(ms)) return '—'
  return new Date(ms).toLocaleDateString('en-GB', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
  })
}

/** Local hour (0-23) of a timestamp, or null if invalid. */
export function hourOf(ms) {
  return Number.isFinite(ms) ? new Date(ms).getHours() : null
}

/** Short relative date/time for the incident list (e.g. "2 h ago"). */
export function formatRelative(isoString) {
  const ms = Date.parse(isoString)
  if (!Number.isFinite(ms)) return ''
  const diff = Date.now() - ms
  const minutes = Math.round(diff / 60000)
  if (minutes < 1) return 'now'
  if (minutes < 60) return `${minutes} min ago`
  const hours = Math.round(minutes / 60)
  if (hours < 24) return `${hours} h ago`
  const days = Math.round(hours / 24)
  if (days < 30) return `${days} d ago`
  return formatDate(ms)
}
