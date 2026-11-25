/*
 * What the Event Logs page knows about the logs of Linux and macOS (section `syslog`, parser syslog.py):
 * the sources it expects for a system with where to find the file, the channels and types a record has,
 * and which types are the "events that matter". On Windows the page keeps its own (domain/eventLogSources.js).
 * The worker names a source `linux.auth`, `linux.journal`, `linux.audit` or `macos.unifiedlog`; a record's
 * `channel` is auth, journal, audit or unifiedlog and its `type` says what it is.
 */

export const SYSLOG_KIND = 'syslog'

export const SYSLOG_SOURCES = [
  {
    key: 'auth',
    source: 'linux.auth',
    os: 'linux',
    label: 'Auth log',
    channel: 'auth',
    hint: '/var/log/auth.log (Debian, Ubuntu) or /var/log/secure (RHEL, Fedora), and their rotated copies; unpack a .gz first. The lines carry no year: Nik takes it from the file’s date and says which year it assumed.',
  },
  {
    key: 'journal',
    source: 'linux.journal',
    os: 'linux',
    label: 'Journal',
    channel: 'journal',
    hint: 'journalctl -o json --since "2026-11-01" > journal.json (one object per line; not json-pretty).',
  },
  {
    key: 'audit',
    source: 'linux.audit',
    os: 'linux',
    label: 'Audit log',
    channel: 'audit',
    hint: '/var/log/audit/audit.log (root only), copied as it is.',
  },
  {
    key: 'unifiedlog',
    source: 'macos.unifiedlog',
    os: 'macos',
    label: 'Unified log',
    channel: 'unifiedlog',
    hint: 'sudo log show --style ndjson --last 7d > unified.ndjson (or --archive system.logarchive).',
  },
]

/** The sources of a system, or of both when the incident names none. */
export const syslogSourcesFor = (os) => SYSLOG_SOURCES.filter((item) => !os || item.os === os)

/** The sources of the page as SourceFiles' `expected`: `{ key, label, hint }`. */
export const expectedSyslog = (os) => syslogSourcesFor(os).map(({ key, label, hint }) => ({ key, label, hint }))

/** `match` of SourceFiles: the key of the expected source a file is. */
export const matchSyslogSource = (source) => SYSLOG_SOURCES.find((item) => item.source === source?.source)?.key ?? null

/** The page title of the sources table. */
export const syslogTitle = (os) =>
  os === 'linux' ? 'Sources — Linux logs' : os === 'macos' ? 'Sources — macOS logs' : 'Sources — Linux and macOS logs'

/** What the page shows: the Windows logs, or those of Linux and macOS (both when the incident says no system). */
export function logFamilies(os) {
  if (os === 'windows') return { windows: true, syslog: false }
  if (os === 'linux' || os === 'macos') return { windows: false, syslog: true }
  return { windows: true, syslog: true }
}

/** The types of record that matter ("Events that matter" of these logs). */
export const SYSLOG_MATTER_TYPES = ['logon', 'logon_failed', 'sudo', 'account', 'process']

/** The `type` filter of "Events that matter": the API takes a comma-separated list. */
export const SYSLOG_MATTER_FILTER = SYSLOG_MATTER_TYPES.join(',')

export const TYPE_LABELS = {
  logon: 'Logon',
  logon_failed: 'Failed logon',
  sudo: 'sudo',
  account: 'Account',
  session: 'Session',
  process: 'Process',
  audit: 'Audit',
  log: 'Log',
}

export const typeLabel = (type) => TYPE_LABELS[type] ?? type ?? ''

export const CHANNEL_LABELS = { auth: 'auth', journal: 'journal', audit: 'audit', unifiedlog: 'unified log' }

export const channelLabel = (channel) => CHANNEL_LABELS[channel] ?? channel ?? ''

/** The keys of `data` the table asks for (`program`, the command line of an exec and the address). */
export const SYSLOG_FIELDS = ['program', 'CommandLine', 'command', 'source_ip', 'message']

/** What the "Message / command" column holds: the command of a process or sudo, else the message, else the summary. */
export function messageOf(row) {
  const data = row?.data ?? {}
  return String(data.CommandLine || data.command || data.message || row?.summary || '')
}

/** The program of a record (sshd, sudo, a process name). */
export const programOf = (row) => String(row?.data?.program ?? '')

/** The address a record came from, when it says one. */
export const addressOf = (row) => String(row?.data?.source_ip ?? '')
