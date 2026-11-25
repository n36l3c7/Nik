/*
 * ============================================================================
 * GLOBAL SEARCH — the Ctrl/Cmd+K palette
 * ============================================================================
 *
 * The palette mixes two sources:
 *   - the server (GET /api/search): incidents, indicators from every incident
 *     and samples — what no single browser holds;
 *   - the open incident, already in memory: the events of its document (mail,
 *     samples, captures, addresses), notes and samples, searched here with
 *     searchIncident(). Host records (browser, commands, endpoint, event logs)
 *     are NOT indexed here: they live on the server and are never loaded whole;
 *     the palette gets an "Evidence" group from the server in a later stage.
 * A query starting with ">" lists actions instead (go to a tab, new
 * incident, settings…), filtered with matchActions().
 */

const norm = (text) => String(text ?? '').toLowerCase()

/** True when typing in this element should not open the palette with "/". */
export function isTypingTarget(element) {
  if (!element) return false
  const tag = element.tagName
  return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || Boolean(element.isContentEditable)
}

/** The tab that shows a timeline event of the given source type. */
export function tabForSource(sourceType) {
  return { sample: 'malware', mail: 'mail', network: 'network' }[sourceType] ?? 'timeline'
}

/**
 * Search the open incident: `events` is buildTimelineEvents() output (newest
 * first), `incident` the document (for its notes and samples). Every word of
 * the query must appear (in any order).
 * @returns {{ events: Array, notes: Array, samples: Array }}
 */
export function searchIncident({ incident, events = [], query, limit = 8 }) {
  const words = norm(query).split(/\s+/).filter(Boolean)
  const empty = { events: [], notes: [], samples: [] }
  if (!incident || words.length === 0) return empty
  const hit = (...fields) => {
    const haystack = norm(fields.filter(Boolean).join(' '))
    return words.every((word) => haystack.includes(word))
  }
  const found = { events: [], notes: [], samples: [] }
  for (const event of events) {
    if (found.events.length >= limit) break
    if (hit(event.label, event.detail, event.sourceLabel)) found.events.push(event)
  }
  for (const note of incident.notes ?? []) {
    if (found.notes.length >= limit) break
    if (hit(note.text, note.author)) found.notes.push(note)
  }
  for (const sample of incident.data?.malware?.samples ?? []) {
    if (found.samples.length >= limit) break
    if (hit(sample.fileName, sample.sha256, sample.md5, sample.sha1, sample.type?.label)) found.samples.push(sample)
  }
  return found
}

/** Actions whose label contains every word typed after ">". */
export function matchActions(actions, query) {
  const words = norm(query.replace(/^>\s*/, '')).split(/\s+/).filter(Boolean)
  return actions.filter((action) => {
    const haystack = norm(`${action.label} ${action.keywords ?? ''}`)
    return words.every((word) => haystack.includes(word))
  })
}

/**
 * The summary of a record of the server's Evidence group, cut to `max` characters around the first place the words are,
 * and split in segments `{ text, hit }` so the words can be marked. The server matches the typed text as it is (any
 * case), so that is looked for first; words are marked one by one only when the text as a whole is not there.
 */
export function markWords(summary, query, max = 140) {
  const text = String(summary ?? '').replace(/\s+/g, ' ')
  const lower = text.toLowerCase()
  const typed = norm(query).trim()
  const ranges = []
  const find = (needle) => {
    for (let at = lower.indexOf(needle); at >= 0 && needle; at = lower.indexOf(needle, at + needle.length)) {
      ranges.push([at, at + needle.length])
    }
  }
  find(typed)
  if (ranges.length === 0) for (const word of typed.split(/\s+/)) if (word.length >= 2) find(word)
  ranges.sort((a, b) => a[0] - b[0])
  const merged = []
  for (const range of ranges) {
    const last = merged[merged.length - 1]
    if (last && range[0] <= last[1]) last[1] = Math.max(last[1], range[1])
    else merged.push([...range])
  }
  // A window around the first hit, with an ellipsis where the text was cut.
  let start = 0
  if (text.length > max) start = Math.max(0, Math.min((merged[0]?.[0] ?? 0) - 40, text.length - max))
  const end = Math.min(text.length, start + max)
  const pieces = []
  let at = start
  for (const [from, to] of merged) {
    if (to <= start || from >= end) continue
    const a = Math.max(from, start)
    const b = Math.min(to, end)
    if (a > at) pieces.push({ text: text.slice(at, a), hit: false })
    pieces.push({ text: text.slice(a, b), hit: true })
    at = b
  }
  if (at < end) pieces.push({ text: text.slice(at, end), hit: false })
  if (start > 0) pieces.unshift({ text: '…', hit: false })
  if (end < text.length) pieces.push({ text: '…', hit: false })
  return pieces
}

/**
 * What choosing a record of the Evidence group asks of the app: the tab of its section (`eventlogs` for event
 * logs and for the logs of Linux and macOS; the Evidence page when the section is none of the pages) and the
 * request the page reads once: the record to open in the Source viewer.
 */
export function evidenceTarget(hit, tabOf) {
  return {
    tab: tabOf(hit.section) ?? 'evidence',
    request: {
      record: {
        id: hit.recordId,
        incidentId: hit.incidentId,
        sourceId: hit.sourceId,
        fileName: hit.source ?? '',
      },
    },
  }
}
