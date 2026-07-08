/*
 * ============================================================================
 * ENDPOINT ARTIFACT EVENT MODEL
 * ============================================================================
 *
 * Endpoint records are enriched into the same event shape used elsewhere
 * (`eventType`, `time`, `soc`), so flagging, the SOC engine and the super
 * timeline treat them identically to browser and command events.
 */

/**
 * Enriches a category's records with `kind`, `eventType`, `time` and `soc`.
 * The keyword haystack is built from the category's `detectFields` and passed
 * to the engine as `title`; `kind: 'endpoint'` selects the artifact ruleset.
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
      time: Number.isFinite(record.time) ? record.time : null,
      title: fields[category.primaryField] ?? '',
      // Flat haystack for the DataTable search (it only reads top-level keys).
      _search: Object.values(fields).filter(Boolean).join(' '),
    }
    event.soc = engine.analyze({ kind: 'endpoint', title: haystack, time: event.time })
    return event
  })
  return events.sort((a, b) => (b.time ?? -Infinity) - (a.time ?? -Infinity))
}
