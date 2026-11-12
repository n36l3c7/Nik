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
  return (order[reputation.verdict] ?? 0) * 1000 + (reputation.score ?? 0) * 5 + (reputation.flagged ?? 0)
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

/*
 * The indicator's page: its address, the weighted score, expiry.
 */

/** The permalink of an indicator: /ioc/<type>?v=<value>. */
export function iocPath(type, value) {
  return `/ioc/${encodeURIComponent(type)}?v=${encodeURIComponent(value)}`
}

const IOC_PATH_TYPES = new Set(['ip', 'domain', 'url', 'email', 'md5', 'sha1', 'sha256'])

/** `{ type, value }` from a location shaped like iocPath(), or null. */
export function iocFromLocation({ pathname = '', search = '' } = {}) {
  const match = pathname.match(/^\/ioc\/([a-z0-9]+)\/?$/)
  if (!match || !IOC_PATH_TYPES.has(match[1])) return null
  const value = new URLSearchParams(search).get('v')
  return value ? { type: match[1], value: value.slice(0, 1024) } : null
}

/** Shares of the verdicts for the bar under the score: [{ verdict, share, count }]. */
export function verdictShares(counts = {}) {
  const order = ['malicious', 'suspicious', 'harmless', 'unknown']
  const total = order.reduce((sum, v) => sum + (counts[v] ?? 0), 0)
  if (!total) return []
  return order
    .filter((v) => counts[v] > 0)
    .map((verdict) => ({ verdict, count: counts[verdict], share: (counts[verdict] / total) * 100 }))
}

/** "3 malicious · 2 suspicious · 1 unknown". */
export function countsLine(counts = {}) {
  return verdictShares(counts)
    .map((s) => `${s.count} ${s.verdict}`)
    .join(' · ')
}

/** "30 days", "6 months", "1 year": a retention in days, as people say it. */
export function retentionLabel(days) {
  if (days % 365 === 0) return `${days / 365} year${days === 365 ? '' : 's'}`
  if (days >= 60 && days % 30 === 0) return `${days / 30} months`
  return `${days} day${days === 1 ? '' : 's'}`
}

/** A provider's verdicts over time, oldest first, without repeats: what changed. */
export function verdictChanges(history = []) {
  const out = []
  for (const entry of [...history].reverse()) {
    if (!out.length || out[out.length - 1].verdict !== entry.verdict) out.push(entry)
  }
  return out
}

// ---- an indicator and the artifact that is its analysis ---------------------

/** Types Nik can analyse itself: an address it can visit, a file it may hold. */
export const ANALYSABLE = new Set(['url', 'domain', 'sha256', 'sha1', 'md5'])

/** The address the isolated browser visits for an indicator, or null. */
export function addressOf(type, value) {
  if (type === 'url') return String(value)
  if (type === 'domain') return `https://${value}/`
  return null
}

/** "phishing 82", "suspicious", "high": an artifact's verdict as a short label. */
export function analysisLabel(artifact) {
  if (!artifact) return ''
  if (artifact.status && !['done', ''].includes(artifact.status)) return artifact.status
  const verdict = artifact.verdict || (artifact.kind === 'url' ? 'clean' : 'no rule match')
  return artifact.score != null && artifact.kind !== 'file' ? `${verdict} ${artifact.score}` : verdict
}

export function analysisColor(artifact) {
  const verdict = String(artifact?.verdict ?? '')
  if (['phishing', 'high', 'malicious'].includes(verdict)) return 'red'
  if (['suspicious', 'medium'].includes(verdict)) return 'amber'
  return 'slate'
}

/**
 * What the right-click menu offers to analyse an indicator, from what is known
 * of it (`analysis` of GET /api/enrichment, or undefined when not asked yet):
 * `[{ id: 'open' | 'analyse' | 'rescan', label, hint }]`.
 */
export function analysisActions(type, value, analysis) {
  if (!ANALYSABLE.has(type)) return []
  const artifact = analysis?.artifacts?.[0] ?? null
  const address = addressOf(type, value)
  if (artifact) {
    const open = { id: 'open', label: 'Open the analysis', hint: analysisLabel(artifact), artifact }
    return artifact.kind === 'url' && type === 'url' ? [open, { id: 'rescan', label: 'Scan again', artifact }] : [open]
  }
  if (!address || analysis?.canAnalyse === false) return []
  return [
    {
      id: 'analyse',
      label: type === 'url' ? 'Analyse URL' : 'Analyse as URL',
      hint: type === 'url' ? 'isolated browser' : address,
      address,
    },
  ]
}
