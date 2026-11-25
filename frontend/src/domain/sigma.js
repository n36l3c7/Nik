/*
 * The Sigma rules screen (Settings → Sigma rules): the filters of the list and what the API is asked,
 * the line above it, the starter text of a new rule, where an error of the worker sits in the text, and
 * how a "Try on an incident" answer is put in words. Pure functions; the screen is
 * components/settings/sections/SigmaRulesSection.jsx.
 */
import { generateId } from '../lib/id.js'

export const PAGE_LIMIT_MAX = 500

/** The names of the filters of `GET /sigma/rules`, as the table keeps them (`q` is its search box). */
export const RULE_FILTERS = [
  'q',
  'pack',
  'level',
  'status',
  'enabled',
  'supported',
  'product',
  'category',
  'service',
  'kind',
]

const WRITTEN_HERE = '-'

export const STATUS_OPTIONS = [
  { value: '', label: 'Any status' },
  { value: 'stable', label: 'stable' },
  { value: 'test', label: 'test' },
  { value: 'experimental', label: 'experimental' },
  { value: 'deprecated', label: 'deprecated' },
  { value: 'unsupported', label: 'unsupported' },
]

export const KIND_OPTIONS = [
  { value: '', label: 'Rules and correlations' },
  { value: 'rule', label: 'Rules' },
  { value: 'correlation', label: 'Correlations' },
]

export const ENABLED_OPTIONS = [
  { value: '', label: 'On and off' },
  { value: 'true', label: 'On' },
  { value: 'false', label: 'Off' },
]

export const SUPPORTED_OPTIONS = [
  { value: '', label: 'Run and not run' },
  { value: 'true', label: 'Nik can run' },
  { value: 'false', label: 'Nik cannot run' },
]

/** Where a record of "Try on an incident" can come from: the sections of host evidence. */
export const TRY_KINDS = [
  { value: '', label: 'Every section' },
  { value: 'eventlog', label: 'Event logs' },
  { value: 'endpoint', label: 'Endpoint artifacts' },
  { value: 'browser', label: 'Browser forensics' },
  { value: 'commands', label: 'Command history' },
]

const empty = (value) => value === undefined || value === null || value === ''

/** The filters of the table as the API takes them: what is empty left out, `enabled`/`supported` as booleans. */
export function ruleFilters(filters = {}) {
  const kept = {}
  for (const name of RULE_FILTERS) {
    const value = filters[name]
    if (empty(value) || value === false) continue
    if (name === 'enabled' || name === 'supported') kept[name] = value === true || value === 'true'
    else if (name === 'level') kept[name] = Number(value)
    else kept[name] = String(value)
  }
  return kept
}

/** The query of one page: offset and limit from the cursor and the page size (the cursor is the offset). */
export function listParams({ filters = {}, order = 'title', cursor = '', limit = 100 } = {}) {
  const offset = Math.max(0, Number.parseInt(cursor, 10) || 0)
  return { ...ruleFilters(filters), order, limit: Math.min(limit, PAGE_LIMIT_MAX), offset }
}

/** What a page gives a ServerTable: the next cursor is the next offset while there is more. */
export function pageOf(answer) {
  const next = answer.offset + answer.rules.length
  return { items: answer.rules, next: next < answer.total ? String(next) : null, total: answer.total }
}

/** The body of a bulk switch: the chosen ids, or the filters when "all that match" was ticked. */
export function bulkBody(enabled, scope) {
  if (scope?.all) return { enabled, filters: ruleFilters(scope.filters ?? {}) }
  return { enabled, ids: scope?.ids ?? [] }
}

/** What a bulk switch did, in a sentence. */
export function bulkText(enabled, { matched = 0, changed = 0 } = {}) {
  const verb = enabled ? 'on' : 'off'
  if (matched === 0) return 'No rule matched.'
  const left = matched - changed
  const kept = left > 0 ? ` ${left.toLocaleString('en-US')} left as they were.` : ''
  return `${changed.toLocaleString('en-US')} of ${matched.toLocaleString('en-US')} rules switched ${verb}.${kept}`
}

/**
 * The line over the list: "2,731 rules · 214 on · 12 Nik cannot run · 3 critical, 40 high · engine 1".
 * `summary` is `GET /sigma/rules/summary`.
 */
export function summaryLine(summary) {
  if (!summary) return ''
  const number = (n) => Number(n || 0).toLocaleString('en-US')
  const parts = [`${number(summary.total)} ${summary.total === 1 ? 'rule' : 'rules'}`, `${number(summary.enabled)} on`]
  const unsupported = Math.max(0, (summary.total ?? 0) - (summary.supported ?? 0))
  if (unsupported > 0) parts.push(`${number(unsupported)} Nik cannot run`)
  if (summary.unchecked > 0) parts.push(`${number(summary.unchecked)} not checked yet`)
  const names = ['critical', 'high', 'medium', 'low', 'informational']
  const levels = names
    .map((name, index) => [name, Number(summary.byLevel?.[5 - index] ?? 0)])
    .filter(([, n]) => n > 0)
    .map(([name, n]) => `${number(n)} ${name}`)
  if (levels.length) parts.push(levels.join(', '))
  if (summary.engine) parts.push(`engine ${summary.engine}`)
  return parts.join(' · ')
}

/** The choices of the pack filter: every pack of the summary, then the rules written here. */
export function packOptions(summary) {
  const packs = (summary?.packs ?? []).filter((pack) => pack.id !== '')
  return [
    { value: '', label: 'Any pack' },
    { value: WRITTEN_HERE, label: 'Written here' },
    ...packs.map((pack) => ({ value: pack.id, label: pack.name || pack.id })),
  ]
}

/** The choices of a filter made of the values the summary counted (products), plus the one in force. */
export function productOptions(summary, current = '') {
  const names = Object.keys(summary?.products ?? {}).filter(Boolean)
  if (current && !names.includes(current)) names.push(current)
  return [{ value: '', label: 'Any product' }, ...names.sort().map((name) => ({ value: name, label: name }))]
}

/** What a pack says of a rule: "Written here", "Nik", or the pack's name. */
export function packLabel(rule, summary) {
  if (!rule.pack) return 'Written here'
  const named = (summary?.packs ?? []).find((pack) => pack.id === rule.pack)
  return named?.name || (rule.pack === 'nik' ? 'Nik' : rule.pack)
}

/** The log source of a rule as one word: "windows / process_creation". */
export function logSourceText(rule) {
  return [rule?.product, rule?.category || rule?.service].filter(Boolean).join(' / ') || '—'
}

/** Today as Sigma writes a date: 2026/11/25. */
export function sigmaDate(now = new Date()) {
  const two = (n) => String(n).padStart(2, '0')
  return `${now.getFullYear()}/${two(now.getMonth() + 1)}/${two(now.getDate())}`
}

/** The text a new rule starts from: valid, with a fresh id, to be changed. */
export function starterRule({ id = generateId(), now = new Date() } = {}) {
  return `title: Name what this rule finds
id: ${id}
status: experimental
description: What the rule looks for, and why it matters.
author: Your name
date: ${sigmaDate(now)}
tags:
    - attack.execution
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'suspicious-tool'
    condition: selection
falsepositives:
    - Say what else can look like this
level: medium
`
}

/**
 * Where an error sits in the text: the offsets `{ from, to }` of the position the worker named
 * (`line` and `column` count from 1; a column of 0 or none is the whole line). The range ends with the line.
 */
export function positionOf(text, line, column = 0) {
  const lines = String(text ?? '').split('\n')
  const at = Math.min(Math.max(1, Number(line) || 1), lines.length)
  let start = 0
  for (let i = 0; i < at - 1; i += 1) start += lines[i].length + 1
  const length = lines[at - 1].length
  const from = start + Math.min(Math.max(0, (Number(column) || 1) - 1), length)
  return { from, to: Math.max(from, start + length) }
}

/** An error as one line of the list under the editor: "Line 12: a rule needs an id". */
export const errorText = (error) => `Line ${error.line ?? 1}: ${error.message}`

/** Errors as the API gives them, or none for a failure that is not about the text. */
export const errorsOf = (failure) =>
  Array.isArray(failure?.data?.errors) && failure.data.errors.length > 0 ? failure.data.errors : []

/** The rule a text is about, for the beside-the-editor card: the first rule of the answer of `/validate`. */
export const firstRule = (answer) => answer?.rules?.[0] ?? null

/** True when the text is another one than the one saved (line ends and a final newline do not count). */
export const changedText = (a, b) => String(a ?? '').trimEnd() !== String(b ?? '').trimEnd()

/** The cause the run stopped, in words: the answer of `/try` says `cutReason` records or time. */
export function cutText(result) {
  if (!result?.cut) return ''
  if (result.cutReason === 'time') {
    return `The run stopped after ${result.limits?.seconds ?? 60} seconds: the records after the last one scanned were not read.`
  }
  return `The run stopped at ${Number(result.limits?.records ?? result.scanned ?? 0).toLocaleString('en-US')} records: the later ones were not read. Narrow it to one section.`
}

/** "Scanned 4,310 records, 2 matches." for the answer of `/try`. */
export function tryText(result) {
  if (!result) return ''
  const scanned = Number(result.scanned ?? 0).toLocaleString('en-US')
  const count = Number(result.matchCount ?? 0)
  return `Scanned ${scanned} ${result.scanned === 1 ? 'record' : 'records'}: ${count.toLocaleString('en-US')} ${count === 1 ? 'match' : 'matches'}.`
}

/** The matches of a try, as shown: at most `limit` of them and how many are left out. */
export function shownMatches(result, limit = 200) {
  const all = result?.matches ?? []
  return {
    items: all.slice(0, limit),
    more: Math.max(0, (result?.matchCount ?? all.length) - Math.min(all.length, limit)),
  }
}

/** The address that opens an incident (the app has no address for one record). */
export const incidentHref = (incidentId) => `/incident/${encodeURIComponent(incidentId)}`
