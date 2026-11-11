/*
 * URL Analysis helpers (pure, unit-tested): the state and verdict of a scan,
 * recognising a URL (or another indicator) in pasted text, and the timeline
 * events of an incident's scanned addresses.
 *
 * A scan is what GET /api/urls/{id} returns, or the light reference an
 * incident keeps under `data.urls.scans` ({ id, url, host, status, verdict,
 * score, scannedAt }); see backend/app/urlscan.py.
 */

const VERDICTS = {
  phishing: { label: 'phishing', color: 'red' },
  suspicious: { label: 'suspicious', color: 'amber' },
  clean: { label: 'clean', color: 'slate' },
}

export const isScanning = (scan) => scan?.status === 'queued' || scan?.status === 'running'

/** `{ label, color }` for the badge of a scan: its verdict, or its state while there is none. */
export function scanBadge(scan) {
  if (isScanning(scan)) return { label: 'scanning…', color: 'cyan' }
  if (scan?.status === 'error') return { label: 'not visited', color: 'amber' }
  const verdict = VERDICTS[scan?.verdict]
  return verdict
    ? { ...verdict, label: `${verdict.label} · ${scan.score ?? 0}` }
    : { label: 'no verdict', color: 'slate' }
}

/** `host/path` of an address, without the scheme and the query. */
export function displayUrl(url) {
  try {
    const parsed = new URL(url)
    return `${parsed.host}${parsed.pathname === '/' ? '' : parsed.pathname}`
  } catch {
    return String(url ?? '')
  }
}

/**
 * The address a piece of text holds, as Nik would scan it, or null. Defanged
 * text is understood (`hxxps://evil[.]top/x`); a bare host needs a dot and a
 * known-looking top-level label, so ordinary words are not taken for one.
 */
export function urlFromText(text) {
  const raw = String(text ?? '').trim()
  if (!raw || raw.length > 2000 || /\s/.test(raw)) return null
  const fanged = raw
    .replace(/\[\.\]|\(\.\)/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/^hxxp/i, 'http')
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(fanged) ? fanged : `https://${fanged}`
  let parsed
  try {
    parsed = new URL(candidate)
  } catch {
    return null
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return null
  const host = parsed.hostname
  if (!/^(?:[a-z0-9-]+\.)+[a-z]{2,}$/i.test(host) && !/^\d{1,3}(?:\.\d{1,3}){3}$/.test(host)) return null
  // A bare word with a dot ("file.txt", "v1.2") is an address only with a scheme or a path.
  if (candidate !== fanged && !fanged.includes('/') && !/\.(?:[a-z]{2,6})$/i.test(host)) return null
  return parsed.href
}

/** What toggleFlag() expects for a scanned address (the timeline and the address list flag the same key). */
export function scanFlaggable(scan) {
  const time = Date.parse(scan.scannedAt ?? scan.importedAt ?? scan.createdAt ?? '')
  return {
    key: `url:${scan.id}`,
    browserId: 'network',
    section: 'urls',
    eventType: 'network',
    title: displayUrl(scan.url),
    url: scan.url,
    time: Number.isFinite(time) ? time : null,
  }
}

/** Timeline events of the incident's scanned addresses: one per finished scan, at its scan time. */
export function urlEvents(scans = [], engine) {
  const out = []
  for (const scan of scans) {
    const time = Date.parse(scan.scannedAt ?? scan.importedAt ?? '')
    if (!Number.isFinite(time) || scan.status !== 'done') continue
    const label = displayUrl(scan.url)
    const soc = engine.analyze({ kind: 'network', title: label, url: scan.url, time })
    const severity = scan.verdict === 'phishing' ? 'high' : scan.verdict === 'suspicious' ? 'medium' : soc.severity
    out.push({
      id: `url:${scan.id}`,
      time,
      sourceType: 'network',
      sourceLabel: 'URL scan',
      eventType: 'network',
      label,
      detail: `address scanned · ${scanBadge(scan).label}`,
      soc: { ...soc, severity, isFlagged: Boolean(severity) },
      flaggable: scanFlaggable(scan),
    })
  }
  return out
}
