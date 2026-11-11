/*
 * ============================================================================
 * ARTIFACTS — files, e-mails, captures and URLs analysed on their own
 * ============================================================================
 *
 * Pure helpers over the artifact summaries of GET /api/artifacts
 * ({ id, kind, ref, name, verdict, score, detail, size, tags, createdAt,
 * createdBy, incidents }). An artifact exists without an incident and can be
 * linked to incidents later (backend/app/artifacts.py).
 */

export const ARTIFACT_KINDS = [
  { id: 'file', label: 'file', plural: 'files', tab: 'malware', uploadPath: '/artifacts/files' },
  { id: 'mail', label: 'mail', plural: 'e-mails', tab: 'mail', uploadPath: '/artifacts/mails' },
  { id: 'pcap', label: 'pcap', plural: 'captures', tab: 'network', uploadPath: '/artifacts/captures' },
  // A URL is not uploaded: it is scanned (POST /artifacts/urls).
  { id: 'url', label: 'url', plural: 'addresses', tab: 'urls', uploadPath: null },
]

const BY_ID = Object.fromEntries(ARTIFACT_KINDS.map((kind) => [kind.id, kind]))
const BY_TAB = Object.fromEntries(ARTIFACT_KINDS.map((kind) => [kind.tab, kind]))

export const artifactKind = (id) => BY_ID[id] ?? null

/** The artifact kind a dropped file becomes, from its analysis tab; null for host evidence. */
export const kindForTab = (tab) => (BY_TAB[tab]?.uploadPath ? BY_TAB[tab].id : null)

/** Where the artifact's analysis is read from. */
export function artifactId(kind, ref) {
  return `${kind}-${ref}`
}

/* ---- Verdict ---- */

const VERDICTS = {
  high: { label: 'high', color: 'red' },
  phishing: { label: 'phishing', color: 'red' },
  medium: { label: 'medium', color: 'amber' },
  suspicious: { label: 'suspicious', color: 'amber' },
  clean: { label: 'clean', color: 'slate' },
}

/**
 * The badge of an artifact: `{ label, color }`. A file without detections
 * says so instead of "clean" (no detection is not a clean bill); a capture
 * has no verdict (null).
 */
export function verdictBadge(artifact) {
  const known = VERDICTS[artifact?.verdict]
  if (known) return artifact.score != null ? { ...known, label: `${known.label} · ${artifact.score}` } : known
  if (artifact?.kind === 'file') return { label: 'no detection', color: 'slate' }
  return null
}

/* ---- Tags ---- */

const TAG_RE = /^[a-z0-9][a-z0-9._:-]{0,39}$/
export const TAGS_MAX = 12

/** Tags typed in one field ("emotet, campaign:q4"): lower case, valid, distinct, 12 at most. */
export function parseTags(text) {
  const out = []
  for (const piece of String(text ?? '').split(/[\s,;]+/)) {
    const tag = piece.trim().toLowerCase()
    if (TAG_RE.test(tag) && !out.includes(tag)) out.push(tag)
  }
  return out.slice(0, TAGS_MAX)
}

/* ---- Permalink (/artifact/<id>) ---- */

const PATH_RE = /^\/artifact\/((?:file|mail)-[0-9a-f]{64}|(?:pcap|url)-[0-9a-f]{32})$/

export const artifactPath = (id) => `/artifact/${id}`

export function artifactIdFromPath(pathname) {
  return PATH_RE.exec(String(pathname ?? ''))?.[1] ?? null
}

/* ---- The analysis tabs, reused for one artifact ---- */

/**
 * The reference an analysis tab expects (what an incident keeps for a sample,
 * a message or a capture), built from the artifact's summary.
 */
export function artifactReference(artifact) {
  const base = { importedAt: artifact.createdAt, importedBy: artifact.createdBy, size: artifact.size }
  if (artifact.kind === 'file') {
    return { ...base, sha256: artifact.ref, fileName: artifact.name, type: { id: '', label: artifact.detail } }
  }
  if (artifact.kind === 'mail') {
    return {
      ...base,
      sha256: artifact.ref,
      fileName: artifact.name,
      subject: artifact.name,
      from: artifact.detail,
      verdict: artifact.verdict,
      score: artifact.score ?? 0,
    }
  }
  if (artifact.kind === 'url') {
    // The summary's name is the address without its scheme; the scan itself has the exact one.
    const scanned = Boolean(artifact.verdict)
    return {
      id: artifact.ref,
      url: `https://${artifact.name}`,
      status: scanned ? 'done' : ['queued', 'running', 'error'].includes(artifact.detail) ? artifact.detail : 'done',
      verdict: artifact.verdict,
      score: artifact.score ?? 0,
      createdAt: artifact.createdAt,
      createdBy: artifact.createdBy,
    }
  }
  return { id: artifact.ref, kind: 'pcap', fileName: artifact.name, size: artifact.size, status: 'indexing' }
}

/**
 * A stand-in for the incident an analysis tab receives, holding only this
 * artifact: no id (nothing is saved to an incident) and no flags.
 * `reference` overrides the one built from the summary (a capture's live state).
 */
export function standaloneIncident(artifact, reference = null) {
  const ref = reference ?? artifactReference(artifact)
  const data = {
    malware: { samples: artifact.kind === 'file' ? [ref] : [] },
    mail: { messages: artifact.kind === 'mail' ? [ref] : [] },
    network: { captures: artifact.kind === 'pcap' ? [ref] : [] },
    urls: { scans: artifact.kind === 'url' ? [ref] : [] },
  }
  return { id: null, standalone: true, name: artifact.name, flags: {}, data }
}

/* ---- Lists ---- */

/** "2 min ago · m.rossi"-style second line of a row, without the time (the caller formats it). */
export function artifactMeta(artifact) {
  const linked = artifact.incidents?.length
    ? artifact.incidents.length === 1
      ? artifact.incidents[0].name
      : `${artifact.incidents.length} incidents`
    : null
  return [artifact.kind, artifact.detail, linked ?? artifact.createdBy].filter(Boolean).join(' · ')
}
