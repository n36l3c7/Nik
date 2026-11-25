/*
 * What the table of the source files of a page says (components/evidence/SourceFiles.jsx): the shape
 * of a source is the one of browse.source_of (backend/app/evidence/browse.py) and of its parse report
 * (`report.reasons`, `report.notes`, `report.ended`, evidence/parse.py).
 */

import { amountText } from './transfers.js'

const number = (n) => n.toLocaleString('en-US')

export const isReading = (source) => source.state === 'queued' || source.state === 'parsing'

/** Whether anything is being read: only then does the table ask the server again by itself. */
export const needsPolling = (sources) => sources.some(isReading)

/**
 * The pill of the Read column: `{ label, color }` (Badge colours) and the longer sentence in `title`.
 * A file that was listed by an import and is not here has no original; one imported before 7.0 has no
 * report; a file read in part says how many records it lost.
 */
export function readPill(source) {
  if (source.legacy)
    return { label: 'imported before 7.0', color: 'slate', title: 'Import the file again to have its report' }
  if (source.state === 'absent') {
    return {
      label: 'original absent',
      color: 'slate',
      title: 'The file is listed by an import and is not on this server',
    }
  }
  if (source.state === 'queued') return { label: 'queued', color: 'cyan', title: 'Waiting for the worker' }
  if (source.state === 'parsing') {
    const progress = source.work?.progress
    return {
      label: progress ? `reading · ${progress}` : 'reading',
      color: 'cyan',
      title: 'The worker is reading the file',
    }
  }
  if (source.state === 'failed' || source.read === 'failed') {
    return { label: 'failed', color: 'red', title: source.error || 'The file could not be read' }
  }
  if (source.read === 'partial') {
    const lost = source.skipped > 0 ? ` · ${number(source.skipped)} skipped` : ''
    const seen = source.seen ? ' · seen' : ''
    return {
      label: `read in part${lost}${seen}`,
      color: source.seen ? 'slate' : 'amber',
      title: source.seen ? `Seen by ${source.seen.by}` : 'Open the report to see what was not read',
    }
  }
  if (source.read === 'complete')
    return { label: 'complete', color: 'emerald', title: 'Every record of the file was read' }
  return { label: source.read || source.state || 'unknown', color: 'slate', title: '' }
}

/** "48,190 / 48,213": kept and in the file; just what was kept when the file does not say, "—" for none. */
export function keptText(source) {
  if (source.legacy || source.state === 'absent' || isReading(source)) return '—'
  if (source.kept === null || source.kept === undefined) return '—'
  if (source.inFile === null || source.inFile === undefined) return number(source.kept)
  return `${number(source.kept)} / ${number(source.inFile)}`
}

/**
 * How many entries of a file that was read whole are not records of their own (an `$MFT` entry without a name, a
 * continuation, a damaged one are "in file" and not records), or 0. Duplicates are told apart: they have their own
 * number. A collection counts its members, not records.
 */
export function notRecords(source) {
  if (!source || source.read !== 'complete' || source.kind === 'collection' || source.legacy) return 0
  if (!Number.isInteger(source.kept) || !Number.isInteger(source.inFile)) return 0
  return Math.max(0, source.inFile - source.kept - (source.duplicates > 0 ? source.duplicates : 0))
}

/** The sentence under the count of a row that has some: "6 in the file are not records of their own: see the report". */
export function notRecordsText(source, see = 'the report') {
  const n = notRecords(source)
  if (n === 0) return ''
  return `${number(n)} in the file ${n === 1 ? 'is not a record' : 'are not records'} of their own: see ${see}`
}

/** The first characters of a SHA-256, as the table shows them. */
export const shortHash = (sha256, length = 12) => (sha256 ? sha256.slice(0, length) : '')

/** An offset as the viewer writes it: `0x00D6A200`. */
export const hexOffset = (offset, width = 8) =>
  `0x${Math.max(0, offset).toString(16).toUpperCase().padStart(width, '0')}`

/**
 * The expected sources a page has none of, in their order. `match(source)` gives the `key` of the
 * expected source a file satisfies (null for a file that is none of them), or the list of them for a
 * file that holds several (an export of event logs with more than one channel). `satisfied` are the keys that
 * are there without a file of their own (the records of a registry hive).
 */
const keysOf = (found) => (Array.isArray(found) ? found : [found]).filter(Boolean)

export function missingExpected(expected = [], sources = [], match = () => null, satisfied = []) {
  const present = new Set([...sources.flatMap((source) => keysOf(match(source))), ...satisfied])
  return expected.filter((item) => !present.has(item.key))
}

/** The expected entry a source satisfies (the first, for a file that satisfies several), or null. */
export const expectedOf = (source, expected = [], match = () => null) => {
  const [key] = keysOf(match(source))
  return key ? (expected.find((item) => item.key === key) ?? null) : null
}

/** Whether the file can be read again: the server has its original and it is not being read. */
export const canReadAgain = (source) => !source.legacy && (source.state === 'done' || source.state === 'failed')

/** Whether the viewer can be offered: an original is (or may be) kept. The server answers for the rest. */
export const canView = (source) => !source.legacy && source.state !== 'absent' && Boolean(source.sha256)

/** A file read in part that nobody acknowledged yet. */
export const canAcknowledge = (source) => source.read === 'partial' && source.state === 'done' && !source.seen

/**
 * Whether the file an upload ended with was in the incident already: the server gives back the row it
 * has (same SHA-256, section and source), so the row is known by the table, or older than the upload.
 */
export function alreadyImported(source, knownIds, startedAt) {
  if (!source) return false
  if (knownIds.has(source.id)) return true
  const created = Date.parse(source.createdAt)
  return Number.isFinite(created) && created < startedAt
}

/** "0x1A00 (4,096 bytes)" or "0x1A00": where in the file something was skipped. */
export function whereText(example) {
  if (!example || example.offset === null || example.offset === undefined) return ''
  const at = hexOffset(example.offset, 4)
  return Number.isInteger(example.length) && example.length > 0 ? `${at} (${number(example.length)} bytes)` : at
}

/**
 * The table of skip reasons of a report: `{ reason, records, where, detail }`, the largest loss first.
 * `records` is what was lost (the count of skips when the worker did not say how many).
 */
export function reasonRows(report) {
  const reasons = report?.reasons ?? {}
  return Object.entries(reasons)
    .map(([reason, held]) => {
      const examples = held.examples ?? []
      const first = examples[0]
      const more = (held.count ?? 0) - examples.length
      const where = [whereText(first), more > 0 ? `+ ${number(more)} more` : ''].filter(Boolean).join(' ')
      return {
        reason,
        records: held.lost > 0 ? held.lost : (held.count ?? 0),
        skips: held.count ?? 0,
        where,
        detail: first?.detail ?? '',
      }
    })
    .sort((a, b) => b.records - a.records || a.reason.localeCompare(b.reason))
}

/** The notes of a report: `{ reason, count, detail }`, the most frequent first. */
export function noteRows(report) {
  return Object.entries(report?.notes ?? {})
    .map(([reason, held]) => ({ reason, count: held.count ?? 0, detail: held.detail ?? '' }))
    .sort((a, b) => b.count - a.count || a.reason.localeCompare(b.reason))
}

/** What the row of a file being uploaded says: its state in a sentence. */
export function uploadText(item) {
  if (item.error) return item.error
  if (item.state === 'queued') return 'Waiting for its turn'
  if (item.state === 'sending') return `Sending · ${amountText({ sent: item.sent, total: item.total })}`
  if (item.state === 'keeping') return 'The server is checking and keeping the file'
  if (item.state === 'cancelled') return 'Cancelled'
  if (item.state === 'done') return item.already ? 'Already imported' : 'Added: the worker is reading it'
  return ''
}

/** The parsers that, from their version 2, also write the processes and the logons of the log (the worker's NAME and VERSION). */
const PROCESS_PARSERS = ['evtx', 'eventlog-json', 'syslog', 'plaso']
const PROCESS_PARSER_VERSION = 2

/**
 * Whether a file was read by a parser that did not yet extract processes and logons (an event log, a Linux or
 * macOS log or a Plaso export read before 7.0 stage 7): reading it again fills the Processes and Logons pages.
 * A file imported before 7.0 has no original to read again and is not this.
 */
export const readBeforeProcesses = (source) =>
  !source.legacy &&
  source.state === 'done' &&
  PROCESS_PARSERS.includes(source.parser) &&
  Number(source.parserVersion) < PROCESS_PARSER_VERSION
