/*
 * The field registry and the incident types, as the screens use them
 * (GET /api/fields, GET /api/incident-types): what a type of field is
 * called, how a value is shown and typed, and the edits of a type's layout.
 *
 * A layout is `{ sections: [{ id, title, key, columns, fields: [names] }],
 * tabs: [ids], hidden: [ids] }`, with the grid of its Summary
 * (domain/layoutGrid.js) and, since 6.2, its pages, its close form and its
 * quick view (domain/typePages.js). Every edit here returns a new layout and
 * leaves the one it was given as it was.
 */
import { DETAIL_FIELDS } from './layoutGrid.js'
import { statusLabel } from './incidentName.js'
import { layoutForSaving } from './typePages.js'
import { storedTimer } from './timers.js'

export const UNCLASSIFIED = 'unclassified'

export const FIELD_TYPES = {
  text: 'Text',
  long_text: 'Long text',
  number: 'Number',
  bool: 'Yes / no',
  date: 'Date',
  choice: 'One of a list',
  multi_choice: 'Several of a list',
  user: 'An account',
  role: 'A role',
  url: 'Address (URL)',
  tags: 'Tags',
  indicator: 'Indicator',
  list: 'Table',
  timer: 'Timer',
  json: 'JSON',
}

const list = (value) => (Array.isArray(value) ? value : [])
const isEmpty = (value) =>
  value === null ||
  value === undefined ||
  value === '' ||
  (Array.isArray(value) && value.length === 0) ||
  (typeof value === 'object' && !Array.isArray(value) && Object.keys(value).length === 0)

/** name → field, from the list the API gives. */
export const byName = (fields) => Object.fromEntries(list(fields).map((field) => [field.name, field]))

/** A machine name from a label: "Business unit" → "business_unit". */
export function nameFromLabel(label) {
  const base = String(label ?? '')
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .slice(0, 41)
  if (!base) return ''
  return /^[a-z]/.test(base) ? base : `f_${base}`.slice(0, 41)
}

/** Why a machine name cannot be used (null when it can). */
export function nameProblem(name, fields) {
  if (!/^[a-z][a-z0-9_]{1,40}$/.test(String(name ?? ''))) {
    return 'A lower-case letter, then lower-case letters, digits or _ (2 to 41 characters)'
  }
  if (list(fields).some((field) => field.name === name)) return 'There is a field with this name already'
  return null
}

/** What a field holds, as a line of text ("" when it holds nothing). */
export function formatValue(field, value) {
  if (isEmpty(value) && value !== false && value !== 0) return ''
  switch (field?.type) {
    case 'bool':
      return value ? 'yes' : 'no'
    case 'choice':
      // The status is stored as a word of the program (in_progress): it is shown as the list shows it.
      return field.name === 'status' ? statusLabel(value) : String(value)
    case 'timer':
      // Started and stopped, never typed: what it holds in a few words (the side panel reads the clock).
      return storedTimer(value)
    case 'date': {
      const ms = Date.parse(value)
      if (!Number.isFinite(ms)) return String(value)
      return new Date(ms).toISOString().replace('T', ' ').slice(0, 16) + ' UTC'
    }
    case 'multi_choice':
    case 'tags':
      return list(value).join(', ')
    case 'indicator':
      return value?.value ? `${value.value} (${value.type})` : ''
    case 'list':
      return `${list(value).length} row${list(value).length === 1 ? '' : 's'}`
    case 'json':
      return JSON.stringify(value)
    default:
      return String(value)
  }
}

/** The value a form starts from: what an input of that type shows. */
export function toInput(field, value) {
  if (isEmpty(value) && value !== false && value !== 0) {
    if (field?.type === 'list') return []
    return field?.type === 'bool' ? '' : ''
  }
  switch (field?.type) {
    case 'bool':
      return value ? 'true' : 'false'
    case 'date':
    case 'timer': {
      // What <input type="datetime-local"> takes, in UTC.
      const ms = Date.parse(value)
      return Number.isFinite(ms) ? new Date(ms).toISOString().slice(0, 16) : ''
    }
    case 'multi_choice':
      return list(value)
    case 'tags':
      return list(value).join(', ')
    case 'indicator':
      return value?.value ?? ''
    case 'list':
      return list(value)
    case 'json':
      return JSON.stringify(value, null, 2)
    default:
      return String(value)
  }
}

/**
 * What is sent for what was typed: `null` for nothing. Throws an Error with a
 * sentence when what was typed cannot be a value of the field.
 */
export function fromInput(field, typed) {
  const label = field?.label ?? field?.name ?? 'The field'
  if (typed === null || typed === undefined) return null
  if (field?.type === 'list') return list(typed).length ? list(typed) : null
  if (field?.type === 'multi_choice') return list(typed).length ? list(typed) : null
  const text = typeof typed === 'string' ? typed.trim() : typed
  if (text === '') return null
  switch (field?.type) {
    case 'number': {
      const number = Number(text)
      if (!Number.isFinite(number)) throw new Error(`${label} is a number`)
      return number
    }
    case 'bool':
      return text === true || text === 'true'
    case 'date':
    case 'timer': {
      // Typed in UTC, as it is shown.
      const ms = Date.parse(/[zZ]|[+-]\d\d:?\d\d$/.test(String(text)) ? text : `${text}Z`)
      if (!Number.isFinite(ms)) throw new Error(`${label} is a date`)
      return new Date(ms).toISOString().replace('.000Z', 'Z')
    }
    case 'tags':
      return [
        ...new Set(
          String(text)
            .split(',')
            .map((part) => part.trim())
            .filter(Boolean),
        ),
      ]
    case 'indicator': {
      const value = String(text)
      return { type: indicatorKind(value), value }
    }
    case 'json':
      try {
        return JSON.parse(text)
      } catch {
        throw new Error(`${label} is not valid JSON`)
      }
    default:
      return String(text)
  }
}

/** A guess of what kind of indicator a typed value is; the server checks it. */
export function indicatorKind(value) {
  const text = String(value).trim()
  if (/^https?:\/\//i.test(text)) return 'url'
  if (/^[^@\s]+@[^@\s]+$/.test(text)) return 'email'
  if (/^[0-9a-f]{64}$/i.test(text)) return 'sha256'
  if (/^[0-9a-f]{40}$/i.test(text)) return 'sha1'
  if (/^[0-9a-f]{32}$/i.test(text)) return 'md5'
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(text) || text.includes(':')) return 'ip'
  return 'domain'
}

// --------------------------------------------------------------------------- //
// Types                                                                       //
// --------------------------------------------------------------------------- //

/** The type of an incident among those the API gave (Unclassified when it has none, or one that is gone). */
export function typeOf(types, incident) {
  const all = list(types)
  return (
    all.find((type) => type.id === (incident?.type || UNCLASSIFIED)) ??
    all.find((type) => type.id === UNCLASSIFIED) ??
    null
  )
}

/** The fields of a type's Summary that are in no section: what the side list offers to add. */
export function unplaced(type, fields) {
  const placed = new Set(list(type?.layout?.sections).flatMap((section) => list(section.fields)))
  return list(fields).filter((field) => field.appliesTo === 'incident' && !placed.has(field.name))
}

/** What every value of an incident is: the system fields the document holds, and its own `fields`. */
export function valuesOf(incident) {
  if (!incident) return {}
  const system = {
    id: incident.id,
    name: incident.name,
    type: incident.type || UNCLASSIFIED,
    status: incident.status || 'open',
    severity: incident.severity,
    owner: incident.assignee,
    ticket: incident.ticketId,
    host: incident.host,
    username: incident.username,
    os: incident.os,
    created: incident.createdAt,
    modified: incident.updatedAt,
  }
  const values = { ...system, ...(incident.fields ?? {}) }
  return Object.fromEntries(Object.entries(values).filter(([, value]) => !isEmpty(value) || value === false))
}

// --------------------------------------------------------------------------- //
// Editing a layout                                                            //
// --------------------------------------------------------------------------- //
const sectionsOf = (layout) =>
  list(layout?.sections).map((section) => ({ ...section, fields: [...list(section.fields)] }))
const withSections = (layout, sections) => ({ tabs: [], hidden: [], ...layout, sections })

/** A section id that is not taken. */
function freeId(sections) {
  let number = sections.length + 1
  while (sections.some((section) => section.id === `s${number}`)) number += 1
  return `s${number}`
}

export function addSection(layout, title = 'New section') {
  const sections = sectionsOf(layout)
  return withSections(layout, [...sections, { id: freeId(sections), title, key: false, columns: 2, fields: [] }])
}

/** Remove a section; its fields go back to the side list. */
export function removeSection(layout, id) {
  return withSections(
    layout,
    sectionsOf(layout).filter((section) => section.id !== id),
  )
}

export function updateSection(layout, id, changes) {
  let sections = sectionsOf(layout).map((section) => (section.id === id ? { ...section, ...changes } : section))
  // One side panel at most: making a section the panel takes it from the other.
  if (changes.key) sections = sections.map((section) => (section.id === id ? section : { ...section, key: false }))
  return withSections(layout, sections)
}

export function moveSection(layout, id, by) {
  const sections = sectionsOf(layout)
  const from = sections.findIndex((section) => section.id === id)
  const to = from + by
  if (from < 0 || to < 0 || to >= sections.length) return layout
  const [moved] = sections.splice(from, 1)
  sections.splice(to, 0, moved)
  return withSections(layout, sections)
}

/**
 * Put a field in a section, at `index` (the end when left out). It leaves
 * the section it was in: a field is in one place.
 */
export function placeField(layout, name, sectionId, index = null) {
  const sections = sectionsOf(layout).map((section) => ({
    ...section,
    fields: section.fields.filter((field) => field !== name),
  }))
  const target = sections.find((section) => section.id === sectionId)
  if (!target) return layout
  const at = index === null || index > target.fields.length ? target.fields.length : Math.max(0, index)
  target.fields.splice(at, 0, name)
  return withSections(layout, sections)
}

/** Take a field out of every section. */
export function unplaceField(layout, name) {
  return withSections(
    layout,
    sectionsOf(layout).map((section) => ({ ...section, fields: section.fields.filter((field) => field !== name) })),
  )
}

/** Move a field up or down; past the edge of its section it goes to the next one. */
export function moveField(layout, name, by) {
  const sections = sectionsOf(layout)
  const at = sections.findIndex((section) => section.fields.includes(name))
  if (at < 0) return layout
  const index = sections[at].fields.indexOf(name)
  const to = index + by
  if (to >= 0 && to < sections[at].fields.length) {
    sections[at].fields.splice(index, 1)
    sections[at].fields.splice(to, 0, name)
    return withSections(layout, sections)
  }
  const neighbour = sections[at + (by < 0 ? -1 : 1)]
  if (!neighbour) return layout
  sections[at].fields.splice(index, 1)
  if (by < 0) neighbour.fields.push(name)
  else neighbour.fields.unshift(name)
  return withSections(layout, sections)
}

/** The fields of the type with a field's flags changed (added to the type when it was not on it). */
export function setFieldFlags(typeFields, name, flags) {
  const current = list(typeFields)
  const found = current.find((item) => item.name === name)
  if (!found) return [...current, { name, required: false, requiredOnClose: false, ...flags }]
  return current.map((item) => (item.name === name ? { ...item, ...flags } : item))
}

/** What PUT /api/incident-types/<id> takes of a type as the builder holds it. */
export function typePayload(type) {
  return {
    name: String(type.name ?? '').trim(),
    description: type.description ?? '',
    colour: type.colour ?? 'slate',
    fields: list(type.fields).map((item) => ({
      name: item.name,
      required: Boolean(item.required),
      requiredOnClose: Boolean(item.requiredOnClose),
    })),
    // What names a section or a page that was taken away goes with it: the server would refuse it.
    layout: layoutForSaving(type.layout),
    closeReasons: list(type.closeReasons)
      .map((reason) => String(reason).trim())
      .filter(Boolean),
  }
}

// --------------------------------------------------------------------------- //
// The incident page                                                           //
// --------------------------------------------------------------------------- //

/** The fields "Edit the incident" changes (the Summary's own form until 5.3): a section does not show them twice. */
export const IN_SUMMARY_FORM = DETAIL_FIELDS

/**
 * The tabs of an incident page, as its type's layout orders them: those the
 * layout names first, in its order, then the others as they come; the hidden
 * ones left out. The Summary is always there.
 */
export function orderTabs(tabs, layout) {
  const all = list(tabs)
  const hidden = new Set(list(layout?.hidden).filter((id) => id !== 'summary'))
  const named = list(layout?.tabs)
    .map((id) => all.find((tab) => tab.id === id))
    .filter(Boolean)
  const rest = all.filter((tab) => !named.includes(tab))
  return [...named, ...rest].filter((tab) => !hidden.has(tab.id))
}

/** The section of a type that is the side panel of the incident page (null when it has none). */
export const panelSection = (type) => list(type?.layout?.sections).find((section) => section.key) ?? null

/**
 * The sections the Summary shows: every one but the side panel, each with the
 * fields that exist and that the Summary's own form does not already edit.
 * A section left with no field is not shown.
 */
export function summarySections(type, fields) {
  const known = byName(fields)
  return list(type?.layout?.sections)
    .filter((section) => !section.key)
    .map((section) => ({
      ...section,
      fields: list(section.fields).filter((name) => known[name] && !IN_SUMMARY_FORM.includes(name)),
    }))
    .filter((section) => section.fields.length > 0)
}

/** Whether a field of a type must hold a value (`required` on the type). */
export const isRequired = (type, name) => list(type?.fields).some((item) => item.name === name && item.required)

/**
 * What a form of fields sends: the values that changed, `null` for one that
 * was emptied. Throws (a sentence) for a value that cannot be one, or a
 * required field left empty.
 */
export function changesOf(type, fields, typed, values) {
  const changes = {}
  for (const field of list(fields)) {
    if (field.writable === false) continue
    const next = fromInput(field, typed[field.name])
    if (next === null && isRequired(type, field.name)) throw new Error(`${field.label} is required`)
    const before = values?.[field.name]
    const same = JSON.stringify(next ?? null) === JSON.stringify(isEmpty(before) && before !== false ? null : before)
    if (!same) changes[field.name] = next
  }
  return changes
}
