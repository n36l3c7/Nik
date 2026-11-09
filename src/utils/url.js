/*
 * URL analysis utilities: domain extraction, search queries,
 * rankings for the Browser Forensics tab widgets.
 */

/** Parsed URL, or null when the string is not a valid absolute URL. */
function parseUrl(url) {
  try {
    return new URL(url)
  } catch {
    return null
  }
}

function domainOf(parsed) {
  return parsed.hostname.replace(/^www\./, '') || null
}

/** Extracts the hostname (without "www.") from a URL. Returns null if invalid. */
export function extractDomain(url) {
  const parsed = parseUrl(url)
  return parsed ? domainOf(parsed) : null
}

/*
 * Recognized search engines: pairs [hostname test, query parameter].
 * Extensible by adding an entry (e.g. ['baidu.com', 'wd']).
 */
const SEARCH_ENGINES = [
  { hostIncludes: 'google.', param: 'q' },
  { hostIncludes: 'bing.com', param: 'q' },
  { hostIncludes: 'duckduckgo.com', param: 'q' },
  { hostIncludes: 'search.yahoo.', param: 'p' },
  { hostIncludes: 'ecosia.org', param: 'q' },
]

/**
 * If the URL is a search on a known engine, returns the query typed by the
 * user (decoded), otherwise null.
 * E.g. https://www.google.com/search?q=how+to+bypass+av → "how to bypass av"
 */
export function extractSearchQuery(url) {
  const parsed = parseUrl(url)
  return parsed ? searchQueryOf(parsed) : null
}

function searchQueryOf(parsed) {
  const engine = SEARCH_ENGINES.find((e) => parsed.hostname.includes(e.hostIncludes))
  if (!engine) return null
  const query = parsed.searchParams.get(engine.param)
  return query?.trim() ? query.trim() : null
}

/**
 * Domain and search query of a URL from a single parse: what buildEvents()
 * stores on every history event. Parsing is the expensive part, so the two
 * are not extracted separately there.
 * @returns {{ domain: string|null, searchQuery: string|null }}
 */
export function analyzeUrl(url) {
  const parsed = parseUrl(url)
  if (!parsed) return { domain: null, searchQuery: null }
  return { domain: domainOf(parsed), searchQuery: searchQueryOf(parsed) }
}

/**
 * Domain of a history entry or event. Events from buildEvents() carry the
 * domain already parsed (`domain`), so the URL is not parsed a second time;
 * raw history entries fall back to parsing.
 */
export function entryDomain(entry) {
  return entry.domain !== undefined ? entry.domain : extractDomain(entry.url)
}

/** Search query of an entry or event, see entryDomain(). */
export function entrySearchQuery(entry) {
  return entry.searchQuery !== undefined ? entry.searchQuery : extractSearchQuery(entry.url)
}

/**
 * Top N most visited domains in an array of history entries or events
 * (each entry = one visit). Returns [{ domain, count }] sorted desc.
 */
export function topDomains(historyEntries, n = 5) {
  const counts = new Map()
  for (const entry of historyEntries) {
    const domain = entryDomain(entry)
    if (!domain) continue
    counts.set(domain, (counts.get(domain) ?? 0) + 1)
  }
  return [...counts.entries()]
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n)
}

/**
 * Top N most frequent search queries extracted from the history URLs (entries
 * or events). Returns [{ query, count }] sorted desc.
 */
export function topSearchQueries(historyEntries, n = 5) {
  const counts = new Map()
  for (const entry of historyEntries) {
    const query = entrySearchQuery(entry)
    if (!query) continue
    const key = query.toLowerCase()
    const existing = counts.get(key)
    if (existing) existing.count += 1
    else counts.set(key, { query, count: 1 })
  }
  return [...counts.values()].sort((a, b) => b.count - a.count).slice(0, n)
}

/** Truncates a string (long URLs in tables) adding "…". */
export function truncate(text, maxLength = 80) {
  if (!text) return ''
  return text.length > maxLength ? `${text.slice(0, maxLength - 1)}…` : text
}
