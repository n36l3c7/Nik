/*
 * What the rules found in host evidence: the levels, their names and colours, and the small words the
 * pages write about them. Levels are the Sigma ones, 1 to 5, everywhere (the API gives the number, and
 * the name where it shows one). Every page that draws a detection takes its look from here.
 */

/** Level 1 to 5, lowest first. `color` is a Badge colour (components/ui/Badge.jsx). */
export const LEVELS = [
  { level: 1, name: 'informational', label: 'Informational', color: 'slate' },
  { level: 2, name: 'low', label: 'Low', color: 'cyan' },
  { level: 3, name: 'medium', label: 'Medium', color: 'amber' },
  { level: 4, name: 'high', label: 'High', color: 'red' },
  { level: 5, name: 'critical', label: 'Critical', color: 'red' },
]

const BY_LEVEL = new Map(LEVELS.map((item) => [item.level, item]))
const BY_NAME = new Map(LEVELS.map((item) => [item.name, item]))

/** The level of a number (1 to 5) or a name ("high"), or null for anything else. */
export function levelOf(value) {
  if (typeof value === 'string' && BY_NAME.has(value.trim().toLowerCase()))
    return BY_NAME.get(value.trim().toLowerCase())
  const number = Number(value)
  return value !== null && value !== '' && BY_LEVEL.has(number) ? BY_LEVEL.get(number) : null
}

/** "high" for 4; '' when it is no level. */
export const levelName = (value) => levelOf(value)?.name ?? ''

/** "High" for 4; '' when it is no level. */
export const levelLabel = (value) => levelOf(value)?.label ?? ''

/** The Badge colour of a level; slate when it is no level. */
export const levelColor = (value) => levelOf(value)?.color ?? 'slate'

/** Level 3 and up: what the War Room hears about and what a playbook usually starts on. */
export const NOTABLE_LEVEL = 3

/** The choices of the "Level" filter: nothing, then each level and the ones above it. */
export const LEVEL_FILTER_OPTIONS = [
  { value: '', label: 'Any' },
  ...LEVELS.map((item) => ({ value: String(item.level), label: item.level === 5 ? item.label : `${item.label}+` })),
]

/** What a filter on a minimum level says as a chip: "level ≥ high". */
export const minLevelText = (value) => (levelName(value) ? `at least ${levelName(value)}` : String(value ?? ''))

/** The count of detections a summary carries per level (`{"1": n, ...}`) as `[{ level, name, count }]`, highest first. */
export function levelCounts(byLevel = {}) {
  return [...LEVELS]
    .reverse()
    .map((item) => ({ ...item, count: Number(byLevel?.[item.level] ?? byLevel?.[String(item.level)] ?? 0) || 0 }))
}

/** How many detections in all. */
export const totalOf = (byLevel = {}) => levelCounts(byLevel).reduce((sum, item) => sum + item.count, 0)

/** "2 critical, 5 high, 7 medium": the levels that have any, highest first; '' for none. */
export function levelsText(byLevel = {}) {
  return levelCounts(byLevel)
    .filter((item) => item.count > 0)
    .map((item) => `${item.count.toLocaleString('en-US')} ${item.name}`)
    .join(', ')
}

/** The stat card tone of a count by level: red for high and critical, amber for medium, plain otherwise. */
export function detectionTone(byLevel = {}) {
  const counts = Object.fromEntries(levelCounts(byLevel).map((item) => [item.level, item.count]))
  if (counts[5] + counts[4] > 0) return 'danger'
  if (counts[3] > 0) return 'warn'
  return 'default'
}

/**
 * The part of a parse report that speaks of detections: `{ total, byLevel, rules }`, or null when the
 * file was read without rules (the key is missing). A file read with rules and no match has `total: 0`.
 */
export function reportDetections(report) {
  const found = report?.detections
  if (!found || typeof found !== 'object') return null
  const total = Number(found.total) || 0
  return { total, byLevel: found.byLevel ?? {}, rules: Array.isArray(found.rules) ? found.rules : [] }
}

/** An ATT&CK tag as a short word: "attack.t1059.001" is "T1059.001", "attack.execution" is "execution". */
export function tagText(tag) {
  const text = String(tag ?? '').replace(/^attack\./i, '')
  return /^t\d{4}(\.\d{3})?$/i.test(text) ? text.toUpperCase() : text
}

/** The address of the ATT&CK page of a technique tag, or '' for a tag that is no technique. */
export function tagUrl(tag) {
  const text = tagText(tag)
  const match = /^T(\d{4})(?:\.(\d{3}))?$/.exec(text)
  if (!match) return ''
  return `https://attack.mitre.org/techniques/T${match[1]}${match[2] ? `/${match[2]}` : ''}/`
}

/** The tags of a rule that are ATT&CK ones first, each once, as short words. */
export function tagChips(tags = []) {
  const shown = [...new Set((tags ?? []).map(tagText).filter(Boolean))]
  return shown.sort((a, b) => Number(/^T\d/.test(b)) - Number(/^T\d/.test(a)))
}

/** What the chip of the rule filter says after "rule = ": the title of the rule, or its id when the title is not known. */
export const ruleChipValue = (ruleId, titles = {}) => titles[ruleId] || String(ruleId)

/** The hosts of a rule row: "HL-WS014 and 2 more". */
export function hostsText(rule) {
  const shown = (rule?.hosts ?? []).filter(Boolean)
  const more = Math.max(0, (Number(rule?.hostCount) || shown.length) - shown.length)
  if (shown.length === 0) return ''
  const head = shown.slice(0, 3).join(', ')
  const rest = more + Math.max(0, shown.length - 3)
  return rest > 0 ? `${head} and ${rest} more` : head
}

/** The detections of every section of a `/summary` answer, added level by level: `{ "1": n, ... }`. */
export function summedByLevel(summary, kinds = null) {
  const total = {}
  for (const [kind, entry] of Object.entries(summary?.kinds ?? {})) {
    if (kinds && !kinds.includes(kind)) continue
    for (const [level, count] of Object.entries(entry?.detections ?? {})) total[level] = (total[level] ?? 0) + count
  }
  return total
}

/** Rules at or above a level (the "Detection" select of the Detections tab keeps the rules of that level and up). */
export const rulesAtLeast = (rules, level) => {
  const least = Number(level) || 0
  return (rules ?? []).filter((rule) => rule.level >= least)
}
