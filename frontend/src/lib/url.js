/*
 * URL utilities: the domain of a URL and a shortened URL for tables.
 */

/** Extracts the hostname (without "www.") from a URL. Returns null if invalid. */
export function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '') || null
  } catch {
    return null
  }
}

/** Truncates a string (long URLs in tables) adding "…". */
export function truncate(text, maxLength = 80) {
  if (!text) return ''
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text
}
