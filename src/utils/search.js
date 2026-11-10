/*
 * ============================================================================
 * GLOBAL SEARCH — the Ctrl/Cmd+K palette
 * ============================================================================
 *
 * The palette mixes two sources:
 *   - the server (GET /api/search): incidents, indicators from every incident
 *     and samples — what no single browser holds;
 *   - the open incident, already in memory: its timeline events, notes and
 *     samples, searched here with searchIncident().
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
  return (
    { browser: 'browser', command: 'commands', endpoint: 'endpoint', eventlog: 'eventlogs', sample: 'malware' }[
      sourceType
    ] ?? 'timeline'
  )
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
