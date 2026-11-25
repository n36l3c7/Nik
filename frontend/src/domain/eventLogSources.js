/*
 * What the Event Logs page knows about its sources (the files of `kind` eventlog): which channels a
 * file holds, what the page expects, and the coverage of each file from its first and last record.
 * The API gives each file its `channels` (the first has most records). Only a file not read yet has
 * none, and then its name is the guess (Windows writes `Microsoft-Windows-X%4Operational.evtx`).
 */

import { EVENT_CHANNELS, getChannel } from '../config/eventLogs.js'

export const EVENTLOG_KIND = 'eventlog'

// What an analyst is asked for first; the other channels still show once a file of them is added.
const EXPECTED_KEYS = [
  'security',
  'system',
  'microsoft-windows-powershell/operational',
  'microsoft-windows-sysmon/operational',
]

export const EXPECTED_CHANNELS = EVENT_CHANNELS.filter((channel) => EXPECTED_KEYS.includes(channel.key)).map(
  (channel) => ({
    key: channel.key,
    label: channel.short,
    hint: `C:\\Windows\\System32\\winevt\\Logs\\${channel.file}`,
  }),
)

/** The name of an .evtx file as a channel name: `%4` is `/`, no extension. */
const stem = (fileName) =>
  String(fileName ?? '')
    .replace(/^.*[\\/]/, '')
    .replace(/\.evtx$/i, '')
    .replace(/%4/g, '/')
    .toLowerCase()

/** The catalog channel an .evtx file holds, from its name; null for a file that is not one of them. */
export function channelOfFile(fileName) {
  return getChannel(stem(fileName))
}

/** The channels of a source, the main one first: the API's, else the guess from the file name. */
export function channelsOf(source) {
  if (Array.isArray(source?.channels) && source.channels.length > 0) return source.channels.map(String)
  const guess = channelOfFile(source?.fileName)
  return guess ? [guess.name] : []
}

/** The keys of the expected channels a source holds, the main one first (`match` of SourceFiles). */
export function matchSource(source) {
  return channelsOf(source)
    .map((name) => getChannel(name)?.key)
    .filter((key) => key && EXPECTED_KEYS.includes(key))
}

/** The channels of a source as text, the short names where the catalog has them: "Security, System". */
export const channelsLabel = (source) =>
  channelsOf(source)
    .map((name) => getChannel(name)?.short ?? name)
    .join(', ')

/** The name a source goes by in the coverage chart: its channels, else its file name. */
export const sourceLabel = (source) => channelsLabel(source) || source.fileName || source.source || '?'

/**
 * The rows of the coverage chart: one per source that has a time span, `{ name, label, first, last, kept }`,
 * and the overall `min` and `max`. Sources still being read or without records have no span and are left out.
 */
export function coverageRows(sources = []) {
  const rows = sources
    .filter((source) => Number.isFinite(source.firstTs) && Number.isFinite(source.lastTs))
    .map((source) => ({
      name: source.id,
      label: sourceLabel(source),
      first: source.firstTs,
      last: source.lastTs,
      kept: source.kept ?? 0,
    }))
    .sort((a, b) => a.label.localeCompare(b.label) || a.first - b.first)
  return {
    rows,
    min: rows.length ? Math.min(...rows.map((row) => row.first)) : null,
    max: rows.length ? Math.max(...rows.map((row) => row.last)) : null,
  }
}

/** The source of a record, from the list of sources: the shape the viewer takes. */
export function sourceOfRecord(record, sources = []) {
  const found = sources.find((source) => source.id === record?.sourceId)
  return found ? { id: found.id, fileName: found.fileName, sha256: found.sha256, size: found.size } : null
}

/** The record before and after the one with `id` in the rows on screen: null at the ends. */
export function neighbourRecords(rows, id) {
  const at = rows.findIndex((row) => row.id === id)
  if (at < 0) return { previous: null, next: null }
  return { previous: rows[at - 1] ?? null, next: rows[at + 1] ?? null }
}

const LEVEL_NAMES = ['LogAlways', 'Critical', 'Error', 'Warning', 'Information', 'Verbose']

/**
 * The Windows level of an event, from its own `data.level` (ask for it with `fields`): "Warning".
 * The value is a number or its text; anything else is shown as it is.
 */
export function levelText(value) {
  if (value === undefined || value === null || value === '') return ''
  const number = Number(value)
  return Number.isInteger(number) && LEVEL_NAMES[number] ? LEVEL_NAMES[number] : String(value)
}

/** The flag of a record as the page shows it: a mark the person just made wins over the page's copy. */
export const flaggedOf = (record, overrides = {}) => overrides[record.key] ?? record.flagged
