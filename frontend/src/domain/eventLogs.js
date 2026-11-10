/*
 * ============================================================================
 * WINDOWS EVENT LOG MODEL — Event Logs tab
 * ============================================================================
 *
 * Incident data: `data.eventlogs.channels[<channel name>] = { events, meta }`.
 * A stored event (written by the server for .evtx files, by
 * parseEventLogJson() for the collection script's JSON):
 *   { id, time, eventId, channel, provider, computer, recordId, level, data,
 *     recovered? }
 * `meta`: { fileName, format: 'evtx'|'json', importedAt, rows, total,
 *           kept, dropped, recovered, first, last, gaps: [[start, end]], sha256? }
 *
 * buildEventLogEvents() enriches events for the UI with the catalog label,
 * category, summary and the SOC verdict: the user keywords, the command-line
 * ruleset for command lines and script blocks, and the event-log ruleset
 * (DEFAULT_EVENTLOG_RULES), some of which look at groups of events.
 */

import { DEFAULT_EVENTLOG_RULES } from '../config/detectionRules.js'
import { EVENT_CATEGORIES, HUMAN_LOGON_TYPES, getChannel, getEventDefinition } from '../config/eventLogs.js'
import { isOutsideBusinessHours } from './soc.js'

export const MAX_EVENTS_PER_CHANNEL = 20_000
const MAX_VALUE = 8_000
const GAP_MS = 6 * 3600 * 1000
const MAX_GAPS = 20
const DROP_VALUES = new Set(['', '-', '%%1793', '%%1794', '{00000000-0000-0000-0000-000000000000}'])

const RULES = Object.fromEntries(DEFAULT_EVENTLOG_RULES.map((rule) => [rule.id, rule]))

/* ------------------------------------------------------------------------ */
/* JSON import (collection script)                                           */
/* ------------------------------------------------------------------------ */

/** ISO string, `/Date(ms)/` (PowerShell 5.1) or `{ value, DateTime }` → ms. */
function toMs(value) {
  if (value == null) return null
  if (typeof value === 'object') return toMs(value.value ?? value.DateTime)
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  const legacy = /\/Date\((-?\d+)/.exec(value)
  if (legacy) return Number(legacy[1])
  const ms = Date.parse(value)
  return Number.isFinite(ms) ? ms : null
}

function cleanValue(value) {
  if (value == null) return null
  const text = (typeof value === 'object' ? JSON.stringify(value) : String(value)).trim()
  if (DROP_VALUES.has(text)) return null
  return text.length > MAX_VALUE ? `${text.slice(0, MAX_VALUE)} […]` : text
}

function cleanData(raw) {
  const out = {}
  if (Array.isArray(raw)) {
    // `Get-WinEvent | ConvertTo-Json` keeps the unnamed Properties: [{ Value }].
    raw.forEach((item, index) => {
      const text = cleanValue(item && typeof item === 'object' && 'Value' in item ? item.Value : item)
      if (text != null) out[`Data${index + 1}`] = text
    })
    return out
  }
  for (const [key, value] of Object.entries(raw ?? {})) {
    const text = cleanValue(value)
    if (text != null) out[key] = text
  }
  return out
}

/** The longest silences of at least 6 h between consecutive times. */
export function silentPeriods(times) {
  const ordered = times.filter(Number.isFinite).sort((a, b) => a - b)
  const gaps = []
  for (let i = 1; i < ordered.length; i += 1) {
    if (ordered[i] - ordered[i - 1] >= GAP_MS) gaps.push([ordered[i - 1], ordered[i]])
  }
  return gaps
    .sort((a, b) => b[1] - b[0] - (a[1] - a[0]))
    .slice(0, MAX_GAPS)
    .sort((a, b) => a[0] - b[0])
}

/**
 * Parse the collection script's JSON (or a plain `Get-WinEvent | ConvertTo-Json`
 * export) into `{ [channel]: { events, meta } }`, curated ids only.
 * @throws Error when the text is not a JSON event export.
 */
export function parseEventLogJson(text, fileName = 'nik-eventlogs.json') {
  let doc
  try {
    doc = JSON.parse(String(text).replace(/^\uFEFF/, ''))
  } catch {
    throw new Error('Not a JSON file. Run the collection script and import the nik-eventlogs.json it writes.')
  }
  const rawEvents = Array.isArray(doc) ? doc : Array.isArray(doc?.events) ? doc.events : doc?.Id ? [doc] : null
  if (!rawEvents) throw new Error('No events in this file: expected the nik-eventlogs.json written by the script.')
  const logs = new Map((Array.isArray(doc?.logs) ? doc.logs : []).map((log) => [String(log.name).toLowerCase(), log]))

  const channels = new Map()
  const slotFor = (name) => {
    if (!channels.has(name)) channels.set(name, { events: new Map(), seen: 0 })
    return channels.get(name)
  }
  for (const raw of rawEvents) {
    if (!raw || typeof raw !== 'object') continue
    const channelRaw = String(raw.LogName ?? raw.Channel ?? '').trim()
    const definition = getChannel(channelRaw)
    const eventId = Number(raw.Id ?? raw.EventID ?? raw.EventId)
    if (!definition || !Number.isInteger(eventId)) continue
    const slot = slotFor(definition.name)
    slot.seen += 1
    if (!definition.events[eventId]) continue
    const recordId = raw.RecordId ?? raw.EventRecordID ?? `${slot.seen}`
    const data = cleanData(raw.Data ?? raw.Properties)
    const message = cleanValue(raw.Message)
    if (message && Object.keys(data).length === 0) data.Message = message
    const id = `evt:${definition.name}:${recordId}`
    slot.events.set(id, {
      id,
      time: toMs(raw.TimeCreated ?? raw.TimeCreatedUtc),
      eventId,
      channel: definition.name,
      provider: String(raw.ProviderName ?? raw.Provider ?? ''),
      computer: String(raw.MachineName ?? raw.Computer ?? doc?.host ?? ''),
      recordId: Number.isFinite(Number(recordId)) ? Number(recordId) : recordId,
      level: raw.Level ?? null,
      data,
    })
  }
  if (channels.size === 0) throw new Error('No Windows event-log channel Nik knows in this file.')

  const importedAt = new Date().toISOString()
  const out = {}
  for (const [name, slot] of channels) {
    const events = [...slot.events.values()].sort((a, b) => (b.time ?? 0) - (a.time ?? 0))
    const kept = events.slice(0, MAX_EVENTS_PER_CHANNEL)
    const times = events.map((e) => e.time).filter(Number.isFinite)
    const log = logs.get(name.toLowerCase())
    out[name] = {
      events: kept,
      meta: {
        fileName,
        format: 'json',
        importedAt,
        rows: kept.length,
        total: Number.isFinite(Number(log?.total)) ? Number(log.total) : slot.seen,
        kept: kept.length,
        dropped: events.length - kept.length,
        recovered: 0,
        first: toMs(log?.first) ?? (times.length ? Math.min(...times) : null),
        last: toMs(log?.last) ?? (times.length ? Math.max(...times) : null),
        // Only the curated events are in the export: silences are approximate.
        gaps: silentPeriods(times),
        gapsFromCurated: true,
      },
    }
  }
  return out
}

/* ------------------------------------------------------------------------ */
/* Enrichment + SOC rules                                                    */
/* ------------------------------------------------------------------------ */

const SUSPICIOUS_PS =
  /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{20,}|frombase64string|downloadstring|downloadfile|net\.webclient|invoke-webrequest|\biwr\s|invoke-expression|\biex\b|start-bitstransfer|-w(indowstyle)?\s+h(idden)?\b|amsiutils|amsiinitfailed|reflection\.assembly\]::load/i
const SERVICE_USER_PATH =
  /\\users\\|\\appdata\\|\\temp\\|\\windows\\tasks\\|\\perflogs\\|\\programdata\\(?!microsoft\\)|\bcmd(\.exe)?\s+\/[ck]\b|powershell|mshta|rundll32|%comspec%/i
const PRIVILEGED_GROUP =
  /administrators|domain admins|enterprise admins|schema admins|remote desktop users|backup operators/i
const PRIVILEGED_SIDS = new Set(['S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-551'])

/** The command line or script text of an event, for the command ruleset. */
function commandText(event) {
  const d = event.data ?? {}
  switch (`${event.category}:${event.eventId}`) {
    case 'process:4688':
    case 'process:1':
      return d.CommandLine || d.NewProcessName || d.Image || ''
    case 'powershell:4104':
      return d.ScriptBlockText || ''
    case 'powershell:4103':
      return d.Payload || ''
    case 'powershell:400':
    case 'powershell:800':
      return Object.values(d).join(' ')
    default:
      return ''
  }
}

const isRdpLogon = (event) =>
  (event.eventId === 4624 && event.data?.LogonType === '10') ||
  (event.category === 'rdp' && [21, 25, 1149].includes(event.eventId))

/** True for events a person is behind (logons, RDP, account changes, …). */
function isHumanEvent(event) {
  if (['account', 'process', 'powershell', 'rdp', 'task', 'service', 'defender', 'log'].includes(event.category)) {
    return true
  }
  if ([4624, 4625, 4634].includes(event.eventId)) return HUMAN_LOGON_TYPES.has(event.data?.LogonType)
  return event.eventId === 4648 || event.eventId === 4647
}

/** Rules that look at one event. */
function singleEventRules(event, businessHours) {
  const d = event.data ?? {}
  const hits = []
  const { eventId } = event
  if ((event.channel === 'Security' && eventId === 1102) || (event.channel === 'System' && eventId === 104)) {
    hits.push('evt-log-cleared')
  }
  if (event.channel === 'Security' && eventId === 4719) hits.push('evt-audit-policy')
  if ((event.channel === 'System' && eventId === 7045) || (event.channel === 'Security' && eventId === 4697)) {
    const image = d.ImagePath || d.ServiceFileName || ''
    hits.push(SERVICE_USER_PATH.test(image) ? 'evt-service-user-path' : 'evt-service-installed')
  }
  if ((event.category === 'powershell' || event.category === 'process') && SUSPICIOUS_PS.test(commandText(event))) {
    hits.push('evt-ps-suspicious')
  }
  if (isRdpLogon(event) && isOutsideBusinessHours(event.time, businessHours)) hits.push('evt-rdp-off-hours')
  if (event.channel === 'Security' && (eventId === 4720 || eventId === 4722)) hits.push('evt-account-created')
  if (event.channel === 'Security' && [4728, 4732, 4756].includes(eventId)) {
    if (PRIVILEGED_GROUP.test(d.TargetUserName ?? '') || PRIVILEGED_SIDS.has(d.TargetSid)) hits.push('evt-admin-group')
  }
  if (event.category === 'defender') hits.push('evt-defender')
  if ((event.channel === 'Security' && eventId === 4698) || (event.category === 'task' && eventId === 106)) {
    hits.push('evt-task-created')
  }
  return hits
}

const BRUTE_WINDOW = 10 * 60 * 1000
const BRUTE_THRESHOLD = 10
const AFTER_WINDOW = 30 * 60 * 1000
const AFTER_THRESHOLD = 5

const sourceOf = (d) => (d?.IpAddress && d.IpAddress !== '-' ? d.IpAddress : d?.WorkstationName || '')

/**
 * Rules over groups of logons: brute force (bursts of 4625 per account or
 * source) and a success right after many failures. Returns Map(id → [rule ids]).
 */
export function groupRules(events) {
  const hits = new Map()
  const add = (id, rule) => {
    const list = hits.get(id) ?? []
    if (!list.includes(rule)) list.push(rule)
    hits.set(id, list)
  }
  const failures = events
    .filter((e) => e.channel === 'Security' && e.eventId === 4625 && Number.isFinite(e.time))
    .sort((a, b) => a.time - b.time)
  const groups = new Map()
  for (const event of failures) {
    for (const key of [`u:${(event.data?.TargetUserName ?? '').toLowerCase()}`, `s:${sourceOf(event.data)}`]) {
      if (key.length <= 2) continue
      if (!groups.has(key)) groups.set(key, [])
      groups.get(key).push(event)
    }
  }
  // Sliding window over each group: every event of a dense burst is marked.
  for (const list of groups.values()) {
    let start = 0
    for (let end = 0; end < list.length; end += 1) {
      while (list[end].time - list[start].time > BRUTE_WINDOW) start += 1
      if (end - start + 1 >= BRUTE_THRESHOLD) {
        for (let i = start; i <= end; i += 1) add(list[i].id, 'evt-bruteforce')
      }
    }
  }
  const successes = events.filter((e) => e.channel === 'Security' && e.eventId === 4624 && Number.isFinite(e.time))
  for (const event of successes) {
    const keys = [`u:${(event.data?.TargetUserName ?? '').toLowerCase()}`, `s:${sourceOf(event.data)}`]
    for (const key of keys) {
      if (key.length <= 2) continue
      const recent = (groups.get(key) ?? []).filter((f) => f.time <= event.time && event.time - f.time <= AFTER_WINDOW)
      if (recent.length >= AFTER_THRESHOLD) add(event.id, 'evt-logon-after-failures')
    }
  }
  return hits
}

/**
 * Enrich the stored events of every channel for the UI and the timeline.
 * @param {{ channels?: object, engine: object }} args
 * @returns Array sorted by time desc.
 */
export function buildEventLogEvents({ channels = {}, engine }) {
  const base = []
  for (const [name, slot] of Object.entries(channels)) {
    const channel = getChannel(name)
    for (const raw of slot?.events ?? []) {
      const definition = getEventDefinition(name, raw.eventId)
      const data = raw.data ?? {}
      const category = definition?.category ?? 'system'
      const summary = definition ? definition.summary(data) : ''
      const user = definition?.user ? definition.user(data) : data.TargetUserName || data.SubjectUserName || ''
      base.push({
        ...raw,
        kind: 'eventlog',
        eventType: 'eventlog',
        time: Number.isFinite(raw.time) ? raw.time : null,
        channelLabel: channel?.short ?? name,
        label: definition?.label ?? `Event ${raw.eventId}`,
        category,
        categoryLabel: EVENT_CATEGORIES[category]?.label ?? category,
        summary,
        user: user === '?' ? '' : user,
        title: `${raw.eventId} ${definition?.label ?? ''} — ${summary}`,
        _search: [raw.eventId, definition?.label, summary, user, raw.computer, ...Object.values(data)]
          .filter(Boolean)
          .join(' '),
      })
    }
  }
  const grouped = groupRules(base)
  const { businessHours } = engine
  for (const event of base) {
    const command = commandText(event)
    const verdict = engine.analyze({
      kind: command ? 'command' : 'eventlog',
      title: command || event.title,
      time: event.time,
    })
    const ruleIds = [...singleEventRules(event, businessHours), ...(grouped.get(event.id) ?? [])]
    const keywordMatches = [...verdict.keywordMatches, ...ruleIds.map((id) => RULES[id]).filter(Boolean)]
    // Machine activity (service logons, boots…) is not judged by the clock.
    const isAnomalousTime = verdict.isAnomalousTime && isHumanEvent(event)
    let severity = null
    if (keywordMatches.some((rule) => rule.severity === 'high')) severity = 'high'
    else if (keywordMatches.length > 0 || isAnomalousTime) severity = 'medium'
    event.soc = { keywordMatches, isAnomalousTime, severity, isFlagged: severity !== null }
  }
  return base.sort((a, b) => (b.time ?? -Infinity) - (a.time ?? -Infinity))
}

/* ------------------------------------------------------------------------ */
/* Logon sessions + coverage                                                 */
/* ------------------------------------------------------------------------ */

const MACHINE_ACCOUNT = /\$$|^(system|local service|network service|anonymous logon)$|^(dwm|umfd)-\d+$/i

/**
 * Pair logons (4624) with their logoff (4634/4647) and admin privileges
 * (4672) by logon id. Service logons and machine accounts are left out.
 * @returns Array of { id, user, logonType, source, start, end, durationMs,
 *          elevated, computer, logonId, severity } sorted by start desc.
 */
export function logonSessions(events) {
  const ends = new Map()
  const elevated = new Set()
  for (const event of events) {
    if (event.channel !== 'Security') continue
    const key = `${event.computer}|${event.data?.TargetLogonId}`
    if (event.eventId === 4634 || event.eventId === 4647) {
      const known = ends.get(key)
      if (!known || (event.time ?? 0) < known) ends.set(key, event.time)
    }
    if (event.eventId === 4672) elevated.add(`${event.computer}|${event.data?.SubjectLogonId}`)
  }
  const sessions = []
  for (const event of events) {
    if (event.channel !== 'Security' || event.eventId !== 4624) continue
    const d = event.data ?? {}
    if (d.LogonType === '5' || MACHINE_ACCOUNT.test(d.TargetUserName ?? '')) continue
    const key = `${event.computer}|${d.TargetLogonId}`
    const end = ends.get(key)
    const ended = Number.isFinite(end) && end >= (event.time ?? 0) ? end : null
    sessions.push({
      id: event.id,
      user: d.TargetDomainName ? `${d.TargetDomainName}\\${d.TargetUserName}` : (d.TargetUserName ?? '?'),
      logonType: d.LogonType ?? '',
      source: sourceOf(d),
      start: event.time,
      end: ended,
      durationMs: ended != null && event.time != null ? ended - event.time : null,
      elevated: elevated.has(key),
      computer: event.computer,
      logonId: d.TargetLogonId ?? '',
      severity: event.soc?.severity ?? null,
    })
  }
  return sessions.sort((a, b) => (b.start ?? 0) - (a.start ?? 0))
}

/**
 * One row per channel for the coverage chart: the log's span, its silences
 * and the moments it was cleared. Also returns the overall [min, max].
 */
export function coverage(channels = {}, events = []) {
  const cleared = new Map()
  for (const event of events) {
    if (event.soc?.keywordMatches?.some((rule) => rule.id === 'evt-log-cleared')) {
      // 104 names the cleared channel; 1102 is the Security log itself.
      const target = getChannel(event.data?.Channel)?.name ?? (event.eventId === 1102 ? 'Security' : event.channel)
      if (!cleared.has(target)) cleared.set(target, [])
      cleared.get(target).push(event.time)
    }
  }
  const rows = Object.entries(channels)
    .map(([name, slot]) => {
      const meta = slot?.meta ?? {}
      return {
        name,
        label: getChannel(name)?.short ?? name,
        first: meta.first ?? null,
        last: meta.last ?? null,
        total: meta.total ?? slot?.events?.length ?? 0,
        kept: slot?.events?.length ?? 0,
        gaps: Array.isArray(meta.gaps) ? meta.gaps : [],
        approximate: Boolean(meta.gapsFromCurated),
        cleared: (cleared.get(name) ?? []).filter(Number.isFinite),
      }
    })
    .sort((a, b) => a.label.localeCompare(b.label))
  const bounds = rows.flatMap((row) => [row.first, row.last, ...row.cleared]).filter(Number.isFinite)
  return {
    rows,
    min: bounds.length ? Math.min(...bounds) : null,
    max: bounds.length ? Math.max(...bounds) : null,
  }
}
