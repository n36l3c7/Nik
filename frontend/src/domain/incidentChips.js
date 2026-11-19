/*
 * The quick chips of the incident list ("Add: Type, Severity, Status, Owner,
 * Opened, Field…"): each writes one condition into the query, and shows the
 * one the query holds. The value that is kept is always the text of the
 * query; the chips read it and write it with the builder
 * (domain/query/builder.js), like the status picker and "mine" before them.
 */
import { conditionOn, toText, withCondition } from './query/builder.js'
import { writeValue } from './query/complete.js'
import { SEVERITIES, STATUSES } from './incidentName.js'

/** The chips, in order: what each is called and the field of the query it writes. */
export const CHIPS = [
  { id: 'type', label: 'Type', field: 'type' },
  { id: 'severity', label: 'Severity', field: 'severity' },
  { id: 'status', label: 'Status', field: 'status' },
  { id: 'owner', label: 'Owner', field: 'owner' },
  { id: 'created', label: 'Opened', field: 'created' },
]

const list = (value) => (Array.isArray(value) ? value : [])

/**
 * What a chip offers: `{ label, condition }`, the condition as text of the
 * query. `types` are the incident types, `assignees` the accounts an incident
 * can be given to, `me` the account that is signed in.
 */
export function chipChoices(chipId, { types = [], assignees = [], me = '' } = {}) {
  switch (chipId) {
    case 'type':
      return list(types).map((type) => ({ label: type.name, condition: `type:${writeValue(type.name)}` }))
    case 'severity':
      return [
        ...[...SEVERITIES].reverse().map((item) => ({ label: item.label, condition: `severity:${item.value}` })),
        { label: 'high or more', condition: 'severity:>=high' },
        { label: 'medium or more', condition: 'severity:>=medium' },
        { label: 'not set', condition: 'severity:""' },
      ]
    case 'status':
      return [
        ...STATUSES.map((item) => ({ label: item.label, condition: `status:${item.value}` })),
        { label: 'not closed', condition: '!status:closed' },
      ]
    case 'owner': {
      const others = list(assignees).filter((name) => name && name.toLowerCase() !== me.toLowerCase())
      return [
        ...(me ? [{ label: `me (${me})`, condition: `owner:${writeValue(me)}` }] : []),
        { label: 'nobody', condition: 'owner:""' },
        ...others.map((name) => ({ label: name, condition: `owner:${writeValue(name)}` })),
      ]
    }
    case 'created':
      return [
        { label: 'today', condition: 'created:today' },
        { label: 'since yesterday', condition: 'created:>=yesterday' },
        { label: 'last 7 days', condition: 'created:>=now-7d' },
        { label: 'last 30 days', condition: 'created:>=now-30d' },
      ]
    default:
      return []
  }
}

const chipOf = (chipId) => CHIPS.find((chip) => chip.id === chipId) ?? null

/**
 * The condition a query holds on the field of a chip, as text ('' for none;
 * null when the builder cannot read the query, and the chip then only adds).
 */
export function chipCondition(query, chipId, schema = null) {
  const chip = chipOf(chipId)
  return chip ? conditionOn(query, chip.field, schema) : ''
}

/**
 * The query after a choice of a chip: its condition replaces the one the
 * query held on that field; choosing the one it holds already, or '' ("any"),
 * takes it away.
 */
export function applyChip(query, chipId, condition, schema = null) {
  const chip = chipOf(chipId)
  if (!chip) return String(query ?? '')
  const held = conditionOn(query, chip.field, schema)
  return withCondition(query, chip.field, held === condition ? '' : condition, schema)
}

/** The fields "Field…" offers: every field of the entity, those of the chips last. */
export function otherFields(schema) {
  const chipped = new Set(CHIPS.map((chip) => chip.field))
  const all = list(schema?.fields)
  return [...all.filter((field) => !chipped.has(field.name)), ...all.filter((field) => chipped.has(field.name))]
}

/** The text of one condition built as a row of the builder (`{ field, op, value, value2 }`); '' until it says something. */
export const rowCondition = (row) => toText({ join: 'and', rows: [row] })

/** The query with a condition built in "Field…" written into it, in place of the one it held on that field. */
export function addCondition(query, row, schema = null) {
  const piece = rowCondition(row)
  return piece ? withCondition(query, row.field, piece, schema) : String(query ?? '')
}
