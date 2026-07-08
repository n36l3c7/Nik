/*
 * ============================================================================
 * ENDPOINT ARTIFACT EVENT MODEL
 * ============================================================================
 *
 * Endpoint records are enriched into the same event shape used elsewhere
 * (`eventType`, `time`, `soc`), so flagging, the SOC engine and the super
 * timeline treat them identically to browser and command events.
 *
 * A category's data is per-source ({ sources: { key: { records, meta } } });
 * `combineCategoryRecords` flattens it into one list, tagging each record with
 * the source that produced it so the table can show provenance.
 */

import { sourceNameByKey } from '../config/artifacts.js'

/** Flatten a category's per-source records into one list tagged by source. */
export function combineCategoryRecords(category, categoryData) {
  const names = sourceNameByKey(category)
  const sources = categoryData?.sources ?? {}
  const out = []
  for (const [key, slot] of Object.entries(sources)) {
    const sourceName = names[key] ?? key
    for (const record of slot?.records ?? []) out.push({ ...record, _sourceName: sourceName })
  }
  return out
}

/**
 * Enriches combined records with `kind`, `eventType`, `time`, `sourceName` and
 * `soc`. The keyword haystack is built from the category's `detectFields`;
 * `kind: 'endpoint'` selects the artifact ruleset.
 * @returns Array sorted by time desc (records without a time sink last).
 */
export function buildArtifactEvents({ records = [], category, engine }) {
  const events = records.map((record) => {
    const fields = record.fields ?? {}
    const haystack = (category.detectFields ?? [])
      .map((key) => fields[key] ?? '')
      .filter(Boolean)
      .join(' ')
    const event = {
      ...record,
      kind: 'endpoint',
      categoryId: category.id,
      eventType: category.id,
      sourceName: record._sourceName ?? '',
      time: Number.isFinite(record.time) ? record.time : null,
      title: fields[category.primaryField] ?? '',
      // Flat haystack for the DataTable search (it only reads top-level keys).
      _search: [...Object.values(fields).filter(Boolean), record._sourceName]
        .filter(Boolean)
        .join(' '),
    }
    event.soc = engine.analyze({ kind: 'endpoint', title: haystack, time: event.time })
    return event
  })
  return events.sort((a, b) => (b.time ?? -Infinity) - (a.time ?? -Infinity))
}
