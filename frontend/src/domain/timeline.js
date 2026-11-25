/*
 * ============================================================================
 * TIMELINE: the events of the document, and the host records of the server
 * ============================================================================
 *
 * Two streams make the timeline (7.0):
 *   - the events of the DOCUMENT (samples, e-mails, captures, scanned addresses): timestamped entries
 *     built here from `incident.data`, as before;
 *   - the HOST RECORDS (browser, commands, endpoint, event logs): they are never loaded whole, the
 *     Timeline asks the server for a page of them (`evidence.records`, order time) and for their density
 *     (`evidence.histogram`). The pure helpers for that side are at the end of this file.
 *
 * Each document event carries:
 *   { id, time, sourceType, sourceLabel, eventType, label, detail, soc, flaggable }
 * where `flaggable` is the exact payload toggleFlag() expects.
 */

import { sampleEvents } from './malware.js'
import { mailEvents } from './mail.js'
import { networkEvents } from './network.js'
import { urlEvents } from './urlscan.js'

/** Source-type metadata: badge color used by the timeline UI. */
export const TIMELINE_SOURCE_META = {
  sample: { label: 'Sample', color: 'red' },
  mail: { label: 'E-mail', color: 'cyan' },
  network: { label: 'Network', color: 'violet' },
}

/** The kinds of host records (the `kind` of a record) as the timeline names and colours them. */
export const HOST_KIND_META = {
  browser: { label: 'Browser', color: 'cyan', tab: 'browser' },
  commands: { label: 'Command', color: 'violet', tab: 'commands' },
  endpoint: { label: 'Endpoint', color: 'emerald', tab: 'endpoint' },
  eventlog: { label: 'Event log', color: 'amber', tab: 'eventlogs' },
  syslog: { label: 'Linux/macOS log', color: 'amber', tab: 'eventlogs' },
  disk: { label: 'Disk', color: 'slate', tab: 'disk' },
}

/**
 * The kinds the Timeline shows until the person asks for more: a disk holds millions of $MFT and $J records
 * that would bury everything else, so the Kind filter switches them on.
 */
export const KINDS_OFF_BY_DEFAULT = ['disk']

function hasTime(event) {
  return Number.isFinite(event.time)
}

/**
 * The time-sorted (desc) events of the document of an incident, those with a timestamp only.
 * It takes `incident.data` rather than the incident: flags, notes and metadata do not affect
 * the timeline, so callers can memoize on `data` alone.
 * @param {object} data `incident.data`
 * @param {object} engine SOC engine from useSocEngine()
 */
export function buildTimelineEvents(data = {}, engine) {
  const out = []
  for (const event of sampleEvents(data.malware?.samples ?? [], engine)) if (hasTime(event)) out.push(event)
  for (const event of networkEvents(data.network?.captures ?? [], engine)) if (hasTime(event)) out.push(event)
  for (const event of mailEvents(data.mail?.messages ?? [], engine)) if (hasTime(event)) out.push(event)
  for (const event of urlEvents(data.urls?.scans ?? [], engine)) if (hasTime(event)) out.push(event)
  out.sort((a, b) => b.time - a.time)
  return out
}

/**
 * The density of the timeline: the server's buckets of host records (`histogram.buckets`, `{ t, count }`
 * from `histogram.from`, each `histogram.width` ms wide) and the events of the document, on one grid of at
 * most `max` bars. `{ from, width, bars: [{ t, host, docs }], peak }`; `bars` is empty with nothing dated.
 */
export function density(histogram, events = [], max = 120) {
  const points = []
  for (const bucket of histogram?.buckets ?? []) points.push({ t: bucket.t, host: bucket.count, docs: 0 })
  for (const event of events) if (hasTime(event)) points.push({ t: event.time, host: 0, docs: 1 })
  if (points.length === 0) return { from: null, width: 0, bars: [], peak: 0 }
  const from = Math.min(...points.map((point) => point.t))
  const to = Math.max(...points.map((point) => point.t), (histogram?.to ?? 0) || 0)
  const span = Math.max(1, to - from + 1)
  const width = Math.max(Number(histogram?.width) || 1, Math.ceil(span / max))
  const held = new Map()
  for (const point of points) {
    const index = Math.floor((point.t - from) / width)
    const bar = held.get(index) ?? { t: from + index * width, host: 0, docs: 0 }
    bar.host += point.host
    bar.docs += point.docs
    held.set(index, bar)
  }
  const bars = [...held.entries()].sort((a, b) => a[0] - b[0]).map(([, bar]) => bar)
  return { from, width, bars, peak: Math.max(...bars.map((bar) => bar.host + bar.docs)) }
}

/** What a record says in a line: its summary, else its kind and type. */
export const recordLabel = (record) =>
  record?.summary || [record?.kind, record?.type].filter(Boolean).join(' ') || '(no summary)'

/** ms -> the value of an `<input type="datetime-local">` (local time, to the minute); '' for no time. */
export function toLocalInput(ms) {
  if (!Number.isFinite(ms)) return ''
  const date = new Date(ms)
  const pad = (n) => String(n).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`
}

/** The value of an `<input type="datetime-local">` -> ms; null for an empty or a bad one. */
export function fromLocalInput(text) {
  if (!text) return null
  const ms = new Date(text).getTime()
  return Number.isFinite(ms) ? ms : null
}
