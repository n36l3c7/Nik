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

// ---- scripts of a scanned page (result.scripts) ------------------------------

const SCRIPT_RANK = { high: 3, medium: 2, low: 1 }

/** The scripts with their place in `result.scripts` (`index`), worst first. */
export function sortScripts(scripts = []) {
  return scripts
    .map((script, index) => ({ ...script, index, findings: script.findings ?? [], iocs: script.iocs ?? [] }))
    .sort(
      (a, b) =>
        (SCRIPT_RANK[b.severity] ?? 0) - (SCRIPT_RANK[a.severity] ?? 0) ||
        b.findings.length - a.findings.length ||
        Number(Boolean(a.library)) - Number(Boolean(b.library)) ||
        a.index - b.index,
    )
}

/** What the list calls a script: the end of its address, or "inline #n". */
export function scriptName(script) {
  if (script.kind === 'inline') return script.name || 'inline'
  try {
    const { pathname, search } = new URL(script.url)
    return `${pathname}${search}`.slice(0, 120) || script.url
  } catch {
    return script.url || 'script'
  }
}

/** The badge of a script in the list. */
export function scriptBadge(script) {
  const count = script.findings?.length ?? 0
  if (count > 0) {
    const color = script.severity === 'high' ? 'red' : script.severity === 'medium' ? 'amber' : 'slate'
    return { color, label: `${count} ${count === 1 ? 'finding' : 'findings'}` }
  }
  if (script.library) return { color: 'emerald', label: 'known library' }
  return { color: 'slate', label: 'clean' }
}

export function scriptStats(scripts = []) {
  const flagged = scripts.filter((script) => (script.findings?.length ?? 0) > 0)
  return {
    total: scripts.length,
    external: scripts.filter((script) => script.kind === 'external').length,
    inline: scripts.filter((script) => script.kind === 'inline').length,
    flagged: flagged.length,
    high: flagged.filter((script) => script.severity === 'high').length,
    obfuscated: scripts.filter((script) => (script.obfuscation ?? 0) >= 25).length,
    hosts: new Set(scripts.filter((script) => script.thirdParty).map((script) => script.host)).size,
  }
}

/**
 * The code cut where the findings matched: `[{ text, finding? }]`, in order.
 * Overlapping matches keep the first; a finding with no range (the whole
 * script is obfuscated) marks nothing.
 */
export function codeSegments(code, findings = []) {
  const text = String(code ?? '')
  const ranges = findings
    .filter((finding) => finding.end > finding.start && finding.start < text.length)
    .sort((a, b) => a.start - b.start)
  const out = []
  let cursor = 0
  for (const range of ranges) {
    if (range.start < cursor) continue
    if (range.start > cursor) out.push({ text: text.slice(cursor, range.start) })
    const end = Math.min(range.end, text.length)
    out.push({ text: text.slice(range.start, end), finding: range.id })
    cursor = end
  }
  if (cursor < text.length || out.length === 0) out.push({ text: text.slice(cursor) })
  return out
}

/** Minified code: few, very long lines. */
export function looksMinified(code) {
  const text = String(code ?? '')
  if (text.length < 400) return false
  const lines = text.split('\n').length
  return text.length / lines > 200
}

/**
 * The segments of codeSegments() laid out to be read: a line per statement,
 * blocks indented. Only white space outside strings, template literals and
 * comments is changed, so the code means the same and each mark stays on the
 * text it was on. A layout aid, not a parser: a regular expression holding a
 * quote can throw the rest of its line off.
 */
export function beautifySegments(segments = []) {
  const out = []
  let piece = ''
  let indent = 0
  let parens = 0 // open "(" in the current block: a ";" inside them (for (;;)) ends no statement
  const outer = [] // the count of each enclosing block
  let quote = null // ' " ` while inside a string
  let escaped = false
  let comment = null // 'line' | 'block'
  let lineStart = true
  let previous = ''
  const pad = () => '  '.repeat(Math.max(0, indent))
  const emit = (text) => {
    if (lineStart && text.trim()) {
      piece += pad()
      lineStart = false
    }
    piece += text
  }
  const newline = () => {
    if (lineStart) return
    piece = piece.replace(/[ \t]+$/, '')
    piece += '\n'
    lineStart = true
  }
  const all = segments.map((segment) => segment.text).join('')
  let position = 0
  for (const segment of segments) {
    piece = ''
    for (const char of segment.text) {
      const next = all[position + 1] ?? ''
      position += 1
      if (comment === 'line') {
        if (char === '\n') {
          comment = null
          newline()
        } else emit(char)
      } else if (comment === 'block') {
        emit(char === '\n' ? ' ' : char)
        if (char === '/' && previous === '*') comment = null
      } else if (quote) {
        emit(char)
        if (escaped) escaped = false
        else if (char === '\\') escaped = true
        else if (char === quote) quote = null
      } else if (char === '"' || char === "'" || char === '`') {
        quote = char
        emit(char)
      } else if (char === '/' && next === '/') {
        comment = 'line'
        emit(char)
      } else if (char === '/' && next === '*') {
        comment = 'block'
        emit(char)
      } else if (char === '{') {
        emit(char)
        indent += 1
        outer.push(parens)
        parens = 0
        newline()
      } else if (char === '}') {
        newline()
        indent -= 1
        parens = outer.pop() ?? 0
        emit(char)
        if (![';', ',', ')', '.', '('].includes(next)) newline()
      } else if (char === ';') {
        emit(char)
        if (parens === 0) newline()
      } else if (char === '(' || char === ')') {
        parens = Math.max(0, parens + (char === '(' ? 1 : -1))
        emit(char)
      } else if (char === '\n' || char === '\r') {
        newline()
      } else if (char === ' ' || char === '\t') {
        if (!lineStart && !piece.endsWith(' ')) emit(' ')
      } else emit(char)
      previous = char
    }
    if (piece) out.push(segment.finding ? { text: piece, finding: segment.finding } : { text: piece })
  }
  return out
}
