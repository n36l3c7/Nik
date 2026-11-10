/*
 * Threat-intelligence answers (GET /api/enrichment, the IOCs tab's
 * `reputation`): verdict colours and the types a provider can be asked about.
 */

export const VERDICT_META = {
  malicious: { label: 'malicious', color: 'red' },
  suspicious: { label: 'suspicious', color: 'amber' },
  harmless: { label: 'harmless', color: 'emerald' },
  unknown: { label: 'unknown', color: 'slate' },
}

export const verdictMeta = (verdict) => VERDICT_META[verdict] ?? VERDICT_META.unknown

/** Types that can be sent to providers (e-mail addresses never are). */
export const LOOKUP_TYPES = new Set(['ip', 'domain', 'url', 'md5', 'sha1', 'sha256'])

/** Sort key for the IOCs table: malicious first, never checked last. */
export function reputationRank(reputation) {
  if (!reputation) return 0
  const order = { malicious: 4, suspicious: 3, harmless: 1, unknown: 2 }
  return (order[reputation.verdict] ?? 0) * 100 + (reputation.flagged ?? 0)
}

/** "VirusTotal, AbuseIPDB" for the types a provider takes. */
export function typeGroups(types = []) {
  const groups = []
  if (types.includes('ip')) groups.push('IP')
  if (types.includes('domain')) groups.push('domain')
  if (types.includes('url')) groups.push('URL')
  if (types.some((t) => ['md5', 'sha1', 'sha256'].includes(t))) groups.push('hash')
  return groups.join(' · ')
}
