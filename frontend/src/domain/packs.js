/*
 * Content packs, as the interface reasons about them: what the plan of an
 * import says and whether it can be applied, a difference as lines, and the
 * identity of a pack that is being made. The server decides everything
 * again (app/packs.py).
 */

export const ACTIONS = {
  add: { label: 'add', color: 'emerald', hint: 'Nothing with this name is here.' },
  update: { label: 'update', color: 'cyan', hint: 'It is here and differs.' },
  same: { label: 'same', color: 'slate', hint: 'It is here exactly as the pack has it.' },
  conflict: { label: 'conflict', color: 'red', hint: 'It cannot be applied as it is.' },
}

export const actionBadge = (action) => ACTIONS[action] ?? { label: action, color: 'slate', hint: '' }

export const itemKey = (item) => `${item.kind}/${item.name}`

/** "3 to add, 1 to update, 2 the same, 1 in conflict". */
export function planSummary(counts = {}) {
  const parts = [
    counts.add ? `${counts.add} to add` : '',
    counts.update ? `${counts.update} to update` : '',
    counts.same ? `${counts.same} the same` : '',
    counts.conflict ? `${counts.conflict} in conflict` : '',
  ].filter(Boolean)
  return parts.join(', ') || 'It holds nothing'
}

/** The items that are left out to begin with: a conflict cannot be applied, so it starts skipped. */
export const initialSkips = (plan) =>
  new Set((plan?.items ?? []).filter((item) => item.action === 'conflict').map(itemKey))

/**
 * Whether the plan can be applied with these items skipped: `{ ok, why, changes }`. A conflict that is
 * not skipped stops everything; so does what the pack requires and is not there.
 */
export function importable(plan, skipped) {
  if (!plan) return { ok: false, why: '', changes: 0 }
  if (plan.problems?.length) return { ok: false, why: plan.problems[0], changes: 0 }
  const kept = plan.items.filter((item) => !skipped.has(itemKey(item)))
  const blocking = kept.filter((item) => item.action === 'conflict')
  if (blocking.length) {
    return { ok: false, why: `${blocking[0].label} "${blocking[0].name}" conflicts: leave it out to go on`, changes: 0 }
  }
  const changes = kept.filter((item) => item.action === 'add' || item.action === 'update').length
  if (!kept.length) return { ok: false, why: 'Everything is left out', changes }
  return { ok: true, why: '', changes }
}

/** What POST /api/packs/import takes for the items that are left out. */
export const choicesOf = (skipped) => Object.fromEntries([...skipped].map((key) => [key, 'skip']))

/** A unified difference as lines to draw: `{ kind: 'add' | 'del' | 'hunk' | 'same', text }`, headers left out. */
export function diffLines(diff) {
  return String(diff ?? '')
    .split('\n')
    .filter((line) => !line.startsWith('--- ') && !line.startsWith('+++ '))
    .map((line) => {
      if (line.startsWith('@@')) return { kind: 'hunk', text: line }
      if (line.startsWith('+')) return { kind: 'add', text: line }
      if (line.startsWith('-')) return { kind: 'del', text: line }
      return { kind: 'same', text: line }
    })
}

/** An id for a pack from its name: "Acme SOC!" → "acme-soc". */
export function idFromName(name) {
  const found = String(name ?? '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 49)
  return /^[a-z]/.test(found) ? found : found ? `pack-${found}`.slice(0, 49) : ''
}

/** What is wrong with the identity of a pack being made, or null. */
export function packProblem({ id, name, version }, chosen = 1) {
  if (!String(name ?? '').trim()) return 'A pack needs a name'
  if (!/^[a-z][a-z0-9-]{1,48}$/.test(id ?? '')) {
    return 'Its id is a lower-case letter, then lower-case letters, digits or -'
  }
  if (!/^\d{1,5}\.\d{1,5}\.\d{1,5}$/.test(version ?? '')) return 'Its version is three numbers: 1.0.0'
  if (!chosen) return 'Choose one item at least'
  return null
}

/** Items by kind, in the order given: `[{ kind, label, items }]`. */
export function byKind(items) {
  const groups = []
  for (const item of items ?? []) {
    let group = groups.find((entry) => entry.kind === item.kind)
    if (!group) {
      group = { kind: item.kind, label: item.label ?? item.kind, items: [] }
      groups.push(group)
    }
    group.items.push(item)
  }
  return groups
}

/** "Field" → "Fields", "Pre-processing rule" → "Pre-processing rules", "Incident type" → "Incident types". */
export const plural = (label, count) => (count === 1 ? label : `${label}s`)

/** What a pack is, in a line: "12 items · installed by admin on 2026-11-19". */
export function packLine(pack) {
  const count = pack?.items?.length ?? 0
  const missing = (pack?.items ?? []).filter((item) => !item.there).length
  const parts = [`${count} ${count === 1 ? 'item' : 'items'}`]
  if (missing) parts.push(`${missing} no longer here`)
  if (pack?.builtin) parts.push('part of Nik')
  else if (pack?.updatedBy) parts.push(`installed by ${pack.updatedBy} on ${String(pack.updatedAt ?? '').slice(0, 10)}`)
  return parts.join(' · ')
}

// --------------------------------------------------------------------------- //
// The catalogue (GET /api/packs/catalogue) beside what is installed            //
// --------------------------------------------------------------------------- //

/** The id of the pack that is Nik itself. */
export const NIK_PACK = 'nik'

const KIND_WORDS = {
  playbooks: 'playbook',
  scripts: 'script',
  incident_types: 'type',
  fields: 'field',
  mappers: 'mapper',
  lists: 'list',
  dashboards: 'dashboard',
  preprocess_rules: 'pre-processing rule',
}

/** How many of each kind a pack holds, counted from the items of an installed one. */
export function contentsOf(items) {
  const found = {}
  for (const item of items ?? []) found[item.kind] = (found[item.kind] ?? 0) + 1
  return found
}

/** "connector (41 commands, 3 premium) · 1 type · 2 playbooks": what a pack holds, in a line. */
export function contentsLine(contents = {}, premium = 0) {
  const parts = []
  const connectors = contents.connectors ?? 0
  if (connectors) {
    const commands = contents.commands
      ? ` (${contents.commands} ${contents.commands === 1 ? 'command' : 'commands'}${premium ? `, ${premium} premium` : ''})`
      : ''
    parts.push(`${connectors === 1 ? 'connector' : `${connectors} connectors`}${commands}`)
  }
  for (const [kind, word] of Object.entries(KIND_WORDS)) {
    const count = contents[kind] ?? 0
    if (count) parts.push(`${count} ${count === 1 ? word : `${word}s`}`)
  }
  return parts.join(' · ') || 'Nothing yet'
}

/**
 * One card for each pack there is: those of the catalogue, each with what is true of it here, and those
 * that are installed and are not in the catalogue (Nik's own, one that came as a file). `state` is
 * `installed`, `update` (a newer version is in the catalogue), `available`, or `later` (for a later Nik).
 */
export function packCards(catalogue, installed) {
  const here = new Map((installed ?? []).map((pack) => [pack.id, pack]))
  const cards = []
  for (const entry of catalogue?.packs ?? []) {
    const pack = here.get(entry.id) ?? null
    here.delete(entry.id)
    cards.push({
      id: entry.id,
      name: entry.name,
      vendor: entry.vendor || 'Other',
      category: entry.category ?? '',
      description: entry.description ?? '',
      version: entry.version,
      installed: pack?.version ?? null,
      state: entry.update ? 'update' : pack ? 'installed' : entry.needsNik ? 'later' : 'available',
      needsNik: entry.needsNik ?? '',
      contents: entry.contents ?? {},
      premium: entry.premium ?? 0,
      logo: entry.logo ? 'catalogue' : pack?.hasLogo ? 'pack' : null,
      requires: entry.requires ?? [],
      builtin: false,
      inCatalogue: true,
      pack,
    })
  }
  for (const pack of here.values()) {
    cards.push({
      id: pack.id,
      name: pack.name,
      vendor: pack.builtin ? 'Nik' : pack.vendor || 'Other',
      category: pack.category ?? '',
      description: pack.description ?? '',
      version: pack.version,
      installed: pack.version,
      state: 'installed',
      needsNik: '',
      contents: contentsOf(pack.items),
      premium: 0,
      logo: pack.hasLogo ? 'pack' : null,
      requires: pack.requires ?? [],
      builtin: Boolean(pack.builtin),
      inCatalogue: false,
      pack,
    })
  }
  return cards
}

/** The numbers on the three filters: `{ all, installed, updates }`. */
export const cardCounts = (cards) => ({
  all: cards.length,
  installed: cards.filter((card) => card.installed).length,
  updates: cards.filter((card) => card.state === 'update').length,
})

/** The cards a filter (`all`, `installed`, `updates`) and what was typed keep. */
export function filterCards(cards, show = 'all', query = '') {
  const wanted = String(query ?? '')
    .trim()
    .toLowerCase()
  return cards.filter((card) => {
    if (show === 'installed' && !card.installed) return false
    if (show === 'updates' && card.state !== 'update') return false
    if (!wanted) return true
    return `${card.name} ${card.vendor} ${card.category} ${card.description} ${card.id}`.toLowerCase().includes(wanted)
  })
}

/** Cards by vendor: Nik first, then the vendors by name, "Other" last. `[{ vendor, cards }]`. */
export function byVendor(cards) {
  const groups = new Map()
  for (const card of cards) {
    if (!groups.has(card.vendor)) groups.set(card.vendor, [])
    groups.get(card.vendor).push(card)
  }
  const rank = (vendor) => (vendor === 'Nik' ? 0 : vendor === 'Other' ? 2 : 1)
  return [...groups.entries()]
    .sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b))
    .map(([vendor, held]) => ({ vendor, cards: held.sort((a, b) => a.name.localeCompare(b.name)) }))
}

/** Where a pack that is installed came from, in words. */
export const SOURCES = {
  nik: 'part of Nik',
  catalogue: 'from the catalogue',
  file: 'from a file',
  folder: 'from the folder of packs',
  'nik-5': 'came with Nik before 6.0',
}

/** What uninstalling would do, counted: `{ remove, keep, gone }`. */
export function uninstallCounts(items) {
  const found = { remove: 0, keep: 0, gone: 0 }
  for (const item of items ?? []) if (item.action in found) found[item.action] += 1
  return found
}
