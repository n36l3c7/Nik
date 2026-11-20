/*
 * The tags of an incident: the rules of a tag, the tags in use, and the
 * conditions on tags a query holds.
 *
 * An incident's tags are its field `labels` of the registry (that is its name
 * where it is stored, and in the API); a person reads "Tags", the light row
 * of the list carries them as `tags`, and a query asks `tag:<value>`.
 *
 * A tag is what it is on an indicator and on an artifact: lower case, a
 * letter or a digit, then letters, digits and . _ : -, 40 characters at most;
 * once on an incident, 12 at most. The server holds to the same rules
 * (backend/app/incident_tags.py) and has the last word.
 */
import { toModel, toText } from './query/builder.js'
import { fieldOf, writeValue } from './query/complete.js'

export const TAGS_FIELD = 'labels'
export const TAGS_MAX = 12
export const TAG_RULE = 'A tag is a letter or a digit, then letters, digits and . _ : - (40 characters at most).'

const TAG = /^[a-z0-9][a-z0-9._:-]{0,39}$/
const list = (value) => (Array.isArray(value) ? value : [])
const same = (a, b) => String(a).toLowerCase() === String(b).toLowerCase()

/**
 * What was typed, as a tag: `{ tag, error }`. Capitals become lower case, a #
 * in front is dropped, the spaces inside become "-". Nothing typed is no tag
 * and no error.
 */
export function cleanTag(text) {
  const tag = String(text ?? '')
    .trim()
    .split(/\s+/)
    .join('-')
    .toLowerCase()
    .replace(/^#+/, '')
  if (!tag) return { tag: '', error: null }
  return TAG.test(tag) ? { tag, error: null } : { tag: '', error: TAG_RULE }
}

/**
 * The tags with what was typed added: `{ tags, error }`. A tag the incident
 * has already changes nothing (`tags` is then the list that was given).
 */
export function addTag(tags, text) {
  const held = list(tags)
  const { tag, error } = cleanTag(text)
  if (error) return { tags: held, error }
  if (!tag || held.some((item) => same(item, tag))) return { tags: held, error: null }
  if (held.length >= TAGS_MAX) return { tags: held, error: `An incident holds ${TAGS_MAX} tags at most.` }
  return { tags: [...held, tag], error: null }
}

/** The tags without one of them (case does not matter). */
export const removeTag = (tags, tag) => list(tags).filter((item) => !same(item, tag))

/**
 * The tags the incidents of the list carry, with how many incidents carry
 * each: `[{ tag, count }]`, the most used first, then by name. Two writings
 * of a tag that differ only by their capitals are one tag, shown as it was
 * first met.
 */
export function tagsInUse(rows) {
  const found = new Map()
  for (const row of list(rows)) {
    const seen = new Set()
    for (const tag of list(row?.tags)) {
      const key = String(tag).toLowerCase()
      if (!key || seen.has(key)) continue
      seen.add(key)
      const held = found.get(key)
      if (held) held.count += 1
      else found.set(key, { tag: String(tag), count: 1 })
    }
  }
  return [...found.values()].sort((a, b) => b.count - a.count || a.tag.localeCompare(b.tag))
}

/**
 * The tags to offer while one is typed: those in use the incident does not
 * have, the ones that start with what was typed first, then those that hold it.
 */
export function suggestTags(inUse, held, typed, max = 8) {
  const wanted = cleanTag(typed).tag || String(typed ?? '').trim().toLowerCase().replace(/^#+/, '')
  const free = list(inUse)
    .map((item) => item.tag)
    .filter((tag) => !list(held).some((item) => same(item, tag)))
  if (!wanted) return free.slice(0, max)
  const starts = free.filter((tag) => tag.toLowerCase().startsWith(wanted))
  const holds = free.filter((tag) => !starts.includes(tag) && tag.toLowerCase().includes(wanted))
  return [...starts, ...holds].slice(0, max)
}

/**
 * The tags a cell of the list has room for: `{ shown, more }`. At most `max`
 * of them and `chars` characters together; the first one is always shown.
 */
export function fitTags(tags, { max = 3, chars = 28 } = {}) {
  const all = list(tags).map(String)
  const shown = []
  let used = 0
  for (const tag of all) {
    if (shown.length >= max || (shown.length > 0 && used + tag.length > chars)) break
    shown.push(tag)
    used += tag.length
  }
  return { shown, more: all.length - shown.length }
}

/* ---- tag: in a query ---- */

/** The name the tags are asked by: `tag`, or `labels` where a field of the installation is called `tag`. */
export function tagField(schema) {
  const spec = schema ? fieldOf(schema, 'tag') : null
  return !schema || spec?.name === TAGS_FIELD ? 'tag' : TAGS_FIELD
}

/** The condition of a query that keeps the incidents with a tag. */
export const tagCondition = (tag, schema = null) => `${tagField(schema)}:${writeValue(tag)}`

function tagNames(schema) {
  const spec = schema ? fieldOf(schema, TAGS_FIELD) : null
  return new Set((spec ? [spec.name, ...spec.aliases] : [TAGS_FIELD, 'tag', 'tags']).map((name) => name.toLowerCase()))
}

const isTagRow = (item, names) => !item.rows && item.op === '=' && names.has(String(item.field).toLowerCase())

/**
 * The tags a query asks for at its top level, where every condition must
 * hold: `tag:phish tag:vip` asks for both. Null when the builder cannot read
 * the query; none when its top level is a list of alternatives.
 */
export function tagsInQuery(query, schema = null) {
  const model = toModel(query)
  if (model === null) return null
  if (model.join === 'or' && model.rows.length > 1) return []
  const names = tagNames(schema)
  return model.rows.filter((item) => isTagRow(item, names) && item.value !== '').map((item) => item.value)
}

/** The query with a tag asked for as well: it narrows what the query keeps. One it asks already changes nothing. */
export function withTag(query, tag, schema = null) {
  const source = String(query ?? '').trim()
  const held = tagsInQuery(source, schema)
  if (held?.some((item) => same(item, tag))) return source
  const piece = tagCondition(tag, schema)
  const model = toModel(source)
  // A query the builder does not rewrite is kept as it is written, and the condition added to the whole.
  if (model === null || (model.join === 'or' && model.rows.length > 1)) return source ? `(${source}) ${piece}` : piece
  return source ? `${source} ${piece}` : piece
}

/** The query without its condition on a tag (the other tags it asks for stay). */
export function withoutTag(query, tag, schema = null) {
  const source = String(query ?? '').trim()
  const model = toModel(source)
  if (model === null || (model.join === 'or' && model.rows.length > 1)) return source
  const names = tagNames(schema)
  const rows = model.rows.filter((item) => !(isTagRow(item, names) && same(item.value, tag)))
  return rows.length === model.rows.length ? source : toText({ join: 'and', rows })
}

/** A choice of the Tag chip: the tag is asked for, or no longer when the query asked for it. */
export function toggleTag(query, tag, schema = null) {
  const held = tagsInQuery(query, schema)
  return held?.some((item) => same(item, tag)) ? withoutTag(query, tag, schema) : withTag(query, tag, schema)
}

/** The query without any of its conditions on a tag. */
export function withoutTags(query, schema = null) {
  return list(tagsInQuery(query, schema)).reduce((text, tag) => withoutTag(text, tag, schema), String(query ?? '').trim())
}
