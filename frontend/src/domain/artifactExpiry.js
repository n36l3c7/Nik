/*
 * The optional expiry of an artifact, as the interface says it. Nothing has
 * a date unless someone sets one; the server decides when an artifact goes
 * (app/artifact_expiry.py).
 */

/** The ways to set an expiry without typing a date. `days: null` is "never". */
export const EXPIRY_CHOICES = [
  { label: 'In 30 days', days: 30 },
  { label: 'In 90 days', days: 90 },
  { label: 'In 1 year', days: 365 },
  { label: 'Never', days: null },
]

/** The day `days` from now, as the server takes it (YYYY-MM-DD, UTC). */
export function expiryDate(days, now = Date.now()) {
  return new Date(now + days * 86_400_000).toISOString().slice(0, 10)
}

/** "kept: no expiry", "expires tomorrow", "expires in 6 days (2026-11-25)". */
export function expiryText(artifact) {
  if (!artifact?.expiresAt) return 'kept: no expiry'
  const left = artifact.expiresInDays
  if (left == null) return `expires on ${artifact.expiresAt}`
  if (left <= 0) return `expires today (${artifact.expiresAt})`
  if (left === 1) return `expires tomorrow (${artifact.expiresAt})`
  return `expires in ${left} days (${artifact.expiresAt})`
}

/** "12 artifacts (3.4 GB) have no date and are kept until someone deletes them." */
export function undatedText(undated, formatBytes) {
  const count = undated?.count ?? 0
  if (!count) return 'Every artifact has a date.'
  return `${count} ${count === 1 ? 'artifact has' : 'artifacts have'} no date (${formatBytes(undated.bytes)}) and ${
    count === 1 ? 'is' : 'are'
  } kept until someone deletes ${count === 1 ? 'it' : 'them'}.`
}

/** What the export dialog is asked for: the artifacts, how much their files weigh, how many are mailboxes. */
export function exportRequest(artifacts) {
  const rows = artifacts ?? []
  return {
    mode: 'export',
    ids: rows.map((artifact) => artifact.id),
    label: rows[0]?.name ?? '',
    bytes: rows.reduce((sum, artifact) => sum + (Number(artifact.size) || 0), 0),
    mailboxes: rows.filter((artifact) => artifact.kind === 'mailbox').length,
  }
}
