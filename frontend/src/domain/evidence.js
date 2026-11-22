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

const browserCount = (data) => {
  let count = 0
  for (const browser of Object.values(data?.browsers ?? {})) {
    for (const profile of Object.values(browser?.profiles ?? {})) {
      count += list(profile?.history).length + list(profile?.downloads).length + list(profile?.bookmarks).length
    }
  }
  return count
}
const commandCount = (data) =>
  Object.values(data?.shells ?? {}).reduce((sum, shell) => sum + list(shell?.commands).length, 0)
const endpointCount = (data) =>
  Object.values(data?.categories ?? {}).reduce(
    (sum, category) =>
      sum + Object.values(category?.sources ?? {}).reduce((inner, source) => inner + list(source?.records).length, 0),
    0,
  )
const eventCount = (data) =>
  Object.values(data?.channels ?? {}).reduce((sum, channel) => sum + list(channel?.events).length, 0)

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

/** What the kinds without files of their own hold, as a number of records. */
const COUNTS = { browser: browserCount, commands: commandCount, endpoint: endpointCount, eventlogs: eventCount }

/**
 * The side list of the Evidence tab: one group for each kind, in the order
 * given, with its files (`items`, for the kinds that have files) or the number
 * of records it holds (`count`). `query` keeps the files whose name or detail
 * holds it, and the kinds whose label does.
 */
export function evidenceGroups(kinds, incident, query = '') {
  const data = incident?.data ?? {}
  const wanted = String(query ?? '')
    .trim()
    .toLowerCase()
  const groups = []
  for (const kind of list(kinds)) {
    const own = data[kind.dataKey]
    const make = ITEMS[kind.id]
    let items = make ? make(own) : null
    const count = items ? items.length : (COUNTS[kind.id]?.(own) ?? 0)
    if (wanted) {
      const named = kind.label.toLowerCase().includes(wanted)
      if (items) {
        const kept = items.filter((item) => `${item.name} ${item.detail}`.toLowerCase().includes(wanted))
        if (!named && kept.length === 0) continue
        if (!named) items = kept
      } else if (!named) continue
    }
    groups.push({ id: kind.id, label: kind.label, icon: kind.icon, files: Boolean(make), items: items ?? [], count })
  }
  return groups
}

/** The first file there is: what the tab opens on when nothing was chosen. */
export function firstFile(groups) {
  for (const group of list(groups)) if (group.items.length > 0) return { kind: group.id, key: group.items[0].key }
  const filled = list(groups).find((group) => group.count > 0)
  return filled ? { kind: filled.id, key: null } : null
}
