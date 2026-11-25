/*
 * The Evidence tab of an incident (5.3): its files and what was parsed from
 * the machine, as one list at the side of the page.
 *
 * The analysis tabs of 4.x (Mail, Malware, Network, URL, Endpoint, Event
 * logs, Browser, Commands) are still what opens a file: they are *kinds* of
 * evidence now (`evidence: true` in config/tabs.js), listed here instead of
 * on the tab bar. An address that names one (`mail`, `malware`…) still
 * works: it is the Evidence tab, on that kind.
 */

const list = (value) => (Array.isArray(value) ? value : [])

/** A tab that is gone, and where what it showed is now. */
export const TAB_ALIASES = { automation: 'work_plan' }

export const EVIDENCE_TAB = 'evidence'

/**
 * The kinds that show the paths and the collection commands of ONE operating
 * system: what was collected on the machine. An incident may name no system
 * (5.3); since 6.2 these kinds ask for it before they show anything, instead
 * of showing the paths of Windows as if it were said.
 */
export const SYSTEM_KINDS = ['endpoint', 'eventlogs', 'browser', 'commands']

/** Whether a kind of evidence cannot be shown yet: it needs the system, and the incident has none (`os` is ''). */
export const asksSystem = (kindId, os) => SYSTEM_KINDS.includes(kindId) && !os

/**
 * The groups the Evidence tab may open by itself: without a system, not the
 * kinds that would ask for one. Nobody is asked a question for a page they
 * did not choose.
 */
export const openedAlone = (groups, os) =>
  os ? list(groups) : list(groups).filter((group) => !SYSTEM_KINDS.includes(group.id))

/**
 * What the page shows for the tab that was asked: `{ bar, kind }`. `bar` is
 * the tab of the bar that is lit, `kind` the kind of evidence on screen (null
 * outside Evidence, or for the list alone). A tab that is not there (hidden by
 * the type, not this account's) falls back to the first of the bar.
 */
export function resolveTab(tabs, asked) {
  const all = list(tabs)
  const id = TAB_ALIASES[asked] ?? asked
  const bar = all.filter((tab) => !tab.evidence)
  const found = all.find((tab) => tab.id === id)
  const evidence = bar.find((tab) => tab.id === EVIDENCE_TAB) ?? null
  if (found?.evidence) return evidence ? { bar: evidence, kind: found } : { bar: bar[0] ?? null, kind: null }
  return { bar: found ?? bar[0] ?? null, kind: null }
}

/**
 * The section of the server a tab of host evidence reads (`kind` of a source and of a record). The
 * counts of these kinds come from `evidence.summary`, not from the document.
 */
export const SERVER_KIND = { endpoint: 'endpoint', eventlogs: 'eventlog', browser: 'browser', commands: 'commands' }

const NO_COUNTS = { sources: 0, records: 0, partial: 0, failed: 0, parsing: 0, absent: 0 }

/** What the summary holds of a tab of host evidence (zeros while it is not read, or for another kind). */
export function hostCounts(summary, tabId) {
  const server = SERVER_KIND[tabId]
  return server ? { ...NO_COUNTS, ...(summary?.kinds?.[server] ?? {}) } : NO_COUNTS
}

/** The files of each kind that has files of its own: `{ key, name, detail }`. */
const ITEMS = {
  mail: (data) =>
    list(data?.messages).map((message) => ({
      key: message.sha256,
      name: message.subject || message.fileName || 'An e-mail',
      detail: message.from || message.fileName || '',
      verdict: message.verdict ?? null,
    })),
  malware: (data) =>
    list(data?.samples).map((sample) => ({
      key: sample.sha256,
      name: sample.fileName || sample.sha256,
      detail: sample.type || '',
      verdict: sample.verdict ?? null,
    })),
  network: (data) =>
    list(data?.captures).map((capture) => ({
      key: capture.id,
      name: capture.fileName || 'A capture',
      detail: capture.kind === 'browser' ? 'browser session' : 'capture',
      verdict: null,
    })),
  urls: (data) =>
    list(data?.scans).map((scan) => ({
      key: scan.id,
      name: scan.host || scan.url || 'An address',
      detail: scan.url || '',
      verdict: scan.verdict ?? null,
    })),
}

/**
 * The side list of the Evidence tab: one group for each kind, in the order
 * given, with its files (`items`, for the kinds that have files) or the number
 * of records the server holds for it (`count`, from `summary`; `partial` is how
 * many of its files were read in part and not looked at). `query` keeps the files
 * whose name or detail holds it, and the kinds whose label does.
 */
export function evidenceGroups(kinds, incident, summary = null, query = '') {
  const data = incident?.data ?? {}
  const wanted = String(query ?? '')
    .trim()
    .toLowerCase()
  const groups = []
  for (const kind of list(kinds)) {
    const own = data[kind.dataKey]
    const make = ITEMS[kind.id]
    let items = make ? make(own) : null
    const host = hostCounts(summary, kind.id)
    const count = items ? items.length : host.records
    if (wanted) {
      const named = kind.label.toLowerCase().includes(wanted)
      if (items) {
        const kept = items.filter((item) => `${item.name} ${item.detail}`.toLowerCase().includes(wanted))
        if (!named && kept.length === 0) continue
        if (!named) items = kept
      } else if (!named) continue
    }
    groups.push({
      id: kind.id,
      label: kind.label,
      icon: kind.icon,
      files: Boolean(make),
      items: items ?? [],
      count,
      partial: host.partial,
      failed: host.failed,
      parsing: host.parsing,
    })
  }
  return groups
}

/** The first file there is: what the tab opens on when nothing was chosen. */
export function firstFile(groups) {
  for (const group of list(groups)) if (group.items.length > 0) return { kind: group.id, key: group.items[0].key }
  const filled = list(groups).find((group) => group.count > 0 || group.partial > 0)
  return filled ? { kind: filled.id, key: null } : null
}

/** The pill of the header: how many files were read in part and not looked at; '' when none. */
export function partialPill(summary) {
  const count = Number(summary?.partialUnseen) || 0
  if (count <= 0) return ''
  return `${count} ${count === 1 ? 'file' : 'files'} read in part`
}

/**
 * The first file read in part and not acknowledged, among the sources the server listed
 * (`evidence.sources`): where the pill of the header leads. Null when there is none.
 */
export function firstPartialSource(sources) {
  return list(sources).find((source) => source?.read === 'partial' && !source.seen && source.state === 'done') ?? null
}

/** The tab (id) that shows a section of the server: `eventlog` -> `eventlogs`. */
export function tabOfKind(serverKind) {
  return Object.keys(SERVER_KIND).find((tab) => SERVER_KIND[tab] === serverKind) ?? null
}
