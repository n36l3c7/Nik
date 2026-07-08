/*
 * ============================================================================
 * SUPER-TIMELINE AGGREGATION
 * ============================================================================
 *
 * Merges every TIMESTAMPED event of an incident — browser history/downloads,
 * shell commands, and endpoint artifacts — into a single chronological stream.
 * Entries without a usable timestamp are deliberately left out (a timeline row
 * with no time is meaningless).
 *
 * Each timeline event carries:
 *   { id, time, sourceType, sourceLabel, eventType, label, detail, soc,
 *     flaggable }
 * where `flaggable` is the exact payload toggleFlag() expects, so a row can be
 * flagged/unflagged straight from the timeline.
 */

import { BROWSERS } from '../config/browsers.js'
import { SHELLS } from '../config/shells.js'
import { ARTIFACT_CATEGORIES } from '../config/artifacts.js'
import { buildEvents } from './events.js'
import { buildCommandEvents } from './commands.js'
import { buildArtifactEvents, combineCategoryRecords } from './artifacts.js'
import { extractDomain, truncate } from './url.js'

/** Source-type metadata: badge color used by the timeline UI. */
export const TIMELINE_SOURCE_META = {
  browser: { label: 'Browser', color: 'cyan' },
  command: { label: 'Command', color: 'violet' },
  endpoint: { label: 'Endpoint', color: 'emerald' },
}

function hasTime(event) {
  return Number.isFinite(event.time)
}

/**
 * Build the merged, time-sorted (desc) timeline for an incident.
 * @param {object} incident
 * @param {object} engine SOC engine from useSocEngine()
 * @returns Array of timeline events (only those with a timestamp)
 */
export function buildTimelineEvents(incident, engine) {
  const out = []
  const data = incident?.data ?? {}

  /* ---- Browser history + downloads (per browser) ---- */
  const browsers = data.browser?.browsers ?? {}
  for (const browser of BROWSERS) {
    const bd = browsers[browser.id]
    if (!bd) continue
    const { allEvents } = buildEvents({
      history: bd.history ?? [],
      downloads: bd.downloads ?? [],
      engine,
    })
    for (const event of allEvents) {
      if (!hasTime(event)) continue
      const isDownload = event.kind === 'download'
      out.push({
        id: event.id,
        time: event.time,
        sourceType: 'browser',
        sourceLabel: browser.label,
        eventType: event.eventType,
        label: isDownload ? event.fileName : event.title || event.url || '(no title)',
        detail: isDownload
          ? `from ${extractDomain(event.referrer || event.url) || '—'}`
          : extractDomain(event.url) || truncate(event.url, 60),
        soc: event.soc,
        flaggable: {
          key: event.id,
          browserId: browser.id,
          section: 'events',
          eventType: event.eventType,
          title: event.title || event.fileName || '',
          url: event.url || '',
          time: event.time,
        },
      })
    }
  }

  /* ---- Shell commands (per shell) ---- */
  const shells = data.commands?.shells ?? {}
  for (const shell of SHELLS) {
    const sd = shells[shell.id]
    if (!sd?.commands?.length) continue
    const events = buildCommandEvents({ commands: sd.commands, engine })
    for (const event of events) {
      if (!hasTime(event)) continue
      out.push({
        id: event.id,
        time: event.time,
        sourceType: 'command',
        sourceLabel: shell.label,
        eventType: 'command',
        label: event.command,
        detail: '',
        soc: event.soc,
        flaggable: {
          key: event.id,
          browserId: shell.id,
          section: 'commands',
          eventType: 'command',
          title: event.command,
          url: '',
          time: event.time,
        },
      })
    }
  }

  /* ---- Endpoint artifacts (per category) ---- */
  const categories = data.endpoint?.categories ?? {}
  for (const category of ARTIFACT_CATEGORIES) {
    const combined = combineCategoryRecords(category, categories[category.id])
    if (combined.length === 0) continue
    const events = buildArtifactEvents({ records: combined, category, engine })
    const [, secondCol] = category.columns
    for (const event of events) {
      if (!hasTime(event)) continue
      out.push({
        id: event.id,
        time: event.time,
        sourceType: 'endpoint',
        sourceLabel: category.label,
        eventType: category.id,
        label: event.fields?.[category.primaryField] || '',
        detail: secondCol ? event.fields?.[secondCol.key] || '' : '',
        soc: event.soc,
        flaggable: {
          key: event.id,
          browserId: category.id,
          section: `endpoint:${category.id}`,
          eventType: category.id,
          title: event.fields?.[category.primaryField] || '',
          url: '',
          time: event.time,
        },
      })
    }
  }

  out.sort((a, b) => b.time - a.time)
  return out
}
