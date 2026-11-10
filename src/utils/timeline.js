/*
 * ============================================================================
 * SUPER-TIMELINE AGGREGATION
 * ============================================================================
 *
 * Merges every TIMESTAMPED event of an incident — browser history/downloads,
 * shell commands, endpoint artifacts, Windows event logs and sample imports —
 * into a single chronological stream.
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
import { profileLabel } from './browserProfiles.js'
import { sampleEvents } from './malware.js'
import { mailEvents } from './mail.js'
import { networkEvents } from './network.js'
import { buildEventLogEvents } from './eventLogs.js'

/** Source-type metadata: badge color used by the timeline UI. */
export const TIMELINE_SOURCE_META = {
  browser: { label: 'Browser', color: 'cyan' },
  command: { label: 'Command', color: 'violet' },
  endpoint: { label: 'Endpoint', color: 'emerald' },
  eventlog: { label: 'Event log', color: 'amber' },
  sample: { label: 'Sample', color: 'red' },
  mail: { label: 'E-mail', color: 'cyan' },
  network: { label: 'Network', color: 'violet' },
}

function hasTime(event) {
  return Number.isFinite(event.time)
}

/** Timeline events of one browser profile (history + downloads). */
function browserProfileEvents(browser, slot, profile, engine) {
  const sourceLabel = profileLabel(browser.label, slot, profile)
  const { allEvents } = buildEvents({
    history: profile.history ?? [],
    downloads: profile.downloads ?? [],
    engine,
  })
  return allEvents.filter(hasTime).map((event) => {
    const isDownload = event.kind === 'download'
    return {
      id: event.id,
      time: event.time,
      sourceType: 'browser',
      sourceLabel,
      eventType: event.eventType,
      label: isDownload ? event.fileName : event.title || event.url || '(no title)',
      detail: isDownload
        ? `from ${extractDomain(event.referrer || event.url) || '—'}`
        : event.domain || truncate(event.url, 60),
      soc: event.soc,
      flaggable: {
        key: event.id,
        browserId: browser.id,
        profileId: profile.id,
        profileName: profile.name,
        section: 'events',
        eventType: event.eventType,
        title: event.title || event.fileName || '',
        url: event.url || '',
        time: event.time,
      },
    }
  })
}

/**
 * Build the merged, time-sorted (desc) timeline for an incident.
 * It takes `incident.data` rather than the incident: flags, notes and
 * metadata do not affect the timeline, so callers can memoize on `data`
 * alone and a flag toggle does not rebuild it.
 * @param {object} data `incident.data`
 * @param {object} engine SOC engine from useSocEngine()
 * @returns Array of timeline events (only those with a timestamp)
 */
export function buildTimelineEvents(data = {}, engine) {
  const out = []

  /* ---- Browser history + downloads (per browser, per profile) ---- */
  const browsers = data.browser?.browsers ?? {}
  for (const browser of BROWSERS) {
    const slot = browsers[browser.id]
    for (const profile of Object.values(slot?.profiles ?? {})) {
      out.push(...browserProfileEvents(browser, slot, profile, engine))
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

  /* ---- Windows event logs (per channel) ---- */
  for (const event of buildEventLogEvents({ channels: data.eventlogs?.channels ?? {}, engine })) {
    if (!hasTime(event)) continue
    out.push({
      id: event.id,
      time: event.time,
      sourceType: 'eventlog',
      sourceLabel: event.channelLabel,
      eventType: 'eventlog',
      label: `${event.eventId} ${event.label}`,
      detail: event.summary,
      soc: event.soc,
      flaggable: {
        key: event.id,
        browserId: event.channelLabel,
        section: 'eventlogs',
        eventType: 'eventlog',
        title: event.title,
        url: '',
        time: event.time,
      },
    })
  }

  /* ---- Malware samples (import time) ---- */
  for (const event of sampleEvents(data.malware?.samples ?? [], engine)) {
    if (hasTime(event)) out.push(event)
  }

  /* ---- E-mails (time sent, else import time) ---- */
  /* ---- Network captures: the capture, held submissions, beacons ---- */
  for (const event of networkEvents(data.network?.captures ?? [], engine)) {
    if (hasTime(event)) out.push(event)
  }

  for (const event of mailEvents(data.mail?.messages ?? [], engine)) {
    if (hasTime(event)) out.push(event)
  }

  out.sort((a, b) => b.time - a.time)
  return out
}

/**
 * The last `limit` timeline events as `tail -f` lines: oldest first, newest at
 * the bottom. `events` is buildTimelineEvents() output (newest first).
 * @returns {Array<{ id, time, source, sourceLabel, label, severity, flagged }>}
 */
export function tailLines(events, flags = {}, limit = 50) {
  return events
    .slice(0, limit)
    .reverse()
    .map((event) => ({
      id: event.id,
      time: event.time,
      source: event.sourceType,
      sourceLabel: event.sourceLabel,
      label: event.label,
      severity: event.soc?.severity ?? null,
      flagged: Boolean(flags[event.id]),
    }))
}
