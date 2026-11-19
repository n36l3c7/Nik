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
