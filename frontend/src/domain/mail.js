import { anyToMs } from '../lib/time.js'
import { sameAddress, stripRemoteCss } from './links.js'

/*
 * Mail Analysis helpers (pure, unit-tested): verdict and result colours, the
 * sandboxed document the HTML body is shown in, the rows of the hex view and
 * the timeline events.
 */

export const VERDICTS = {
  phishing: { label: 'phishing', color: 'red', tone: 'danger' },
  suspicious: { label: 'suspicious', color: 'amber', tone: 'warn' },
  clean: { label: 'no strong signs', color: 'emerald', tone: 'ok' },
}

export const verdictMeta = (verdict) => VERDICTS[verdict] ?? VERDICTS.clean

/** Badge colour of an SPF / DKIM / DMARC result. */
export function resultColor(result) {
  if (result === 'pass') return 'emerald'
  if (['fail', 'softfail', 'permerror'].includes(result)) return 'red'
  if (['neutral', 'temperror', 'policy'].includes(result)) return 'amber'
  return 'slate'
}

/**
 * The result an analyst should read for one method: Nik's own DNS check when
 * it gave an answer, else what a (trusted) receiving server wrote.
 * Returns { result, source: 'nik' | 'server' | 'header' | null, detail }.
 */
export function authResult(auth, method) {
  const verified = auth?.verified?.[method]
  if (verified && !['none', 'temperror', undefined].includes(verified.result))
    return { result: verified.result, source: 'nik', detail: verified.detail ?? '' }
  const reported = auth?.reported?.summary?.[method]
  if (reported)
    return { result: reported.result, source: reported.trusted ? 'server' : 'header', detail: reported.detail }
  if (verified) return { result: verified.result, source: 'nik', detail: verified.detail ?? '' }
  return { result: 'none', source: null, detail: '' }
}

// Every network request is refused: no scripts, frames, fonts, forms or
// remote images. Loading images allows https/http images only.
export function frameCsp(loadImages) {
  const images = loadImages ? 'data: https: http:' : 'data:'
  return `default-src 'none'; img-src ${images}; style-src 'unsafe-inline'; font-src data:; form-action 'none'; base-uri 'none'`
}

const escapeAttr = (value) => String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;')

/**
 * The full document for the sandboxed frame. `body` is the server-sanitised
 * HTML, already stripped of link targets by the caller (see neutraliseLinks).
 */
export function frameDocument(body, { loadImages = false } = {}) {
  return (
    '<!doctype html><html><head><meta charset="utf-8">' +
    `<meta http-equiv="Content-Security-Policy" content="${escapeAttr(frameCsp(loadImages))}">` +
    '<style>html{background:#fff;color:#111;font:14px/1.45 Arial,sans-serif}body{margin:12px}' +
    'img[data-nik-blocked]{outline:1px dashed #8c959f;min-width:24px;min-height:16px}' +
    'a[data-nik-href]{color:#0b57d0;text-decoration:underline;cursor:help}</style>' +
    `</head><body>${body}</body></html>`
  )
}

/**
 * Nothing in the frame leads anywhere or calls out. A sandboxed frame may
 * still navigate itself, so every way to do it is removed: a link's target
 * moves to a tooltip, forms lose their action, `<base>` and `<meta
 * http-equiv>` (a refresh is a redirect) go. Remote images are marked as
 * blocked, or removed when they are tracking pixels and the analyst chose to
 * load the others; remote references in CSS are always removed, since a
 * background image is a tracking pixel by another name. Uses the browser's
 * DOMParser, which runs nothing.
 */
export function neutraliseLinks(html, { loadImages = false, tracking = [] } = {}) {
  const doc = new DOMParser().parseFromString(`<body>${html ?? ''}</body>`, 'text/html')
  for (const anchor of doc.querySelectorAll('a[href], area[href]')) {
    const href = anchor.getAttribute('href')
    anchor.removeAttribute('href')
    anchor.removeAttribute('target')
    anchor.setAttribute('data-nik-href', href)
    anchor.setAttribute('title', `Link to ${href} (not followed)`)
  }
  for (const form of doc.querySelectorAll('form')) form.removeAttribute('action')
  for (const button of doc.querySelectorAll('[formaction]')) button.removeAttribute('formaction')
  for (const element of doc.querySelectorAll('base, meta[http-equiv], link')) element.remove()
  for (const element of doc.querySelectorAll('[style]')) {
    element.setAttribute('style', stripRemoteCss(element.getAttribute('style')))
  }
  for (const sheet of doc.querySelectorAll('style')) sheet.textContent = stripRemoteCss(sheet.textContent)
  for (const element of doc.querySelectorAll('[background]')) element.removeAttribute('background')
  const pixels = [...tracking]
  for (const image of doc.querySelectorAll('img[src]')) {
    const src = image.getAttribute('src')
    if (/^data:/i.test(src)) continue
    if (!loadImages) {
      // No request at all (the frame's policy would refuse it anyway).
      image.removeAttribute('src')
      image.setAttribute('data-nik-blocked', '')
      image.setAttribute('title', src)
      image.setAttribute('alt', image.getAttribute('alt') || 'remote image (not loaded)')
    } else if (pixels.some((pixel) => sameAddress(src, pixel))) {
      image.remove()
    }
  }
  return doc.body.innerHTML
}

/** Rows of a hex dump: [{ offset, hex: ['4d', …], ascii }], 16 bytes each. */
export function hexRows(bytes, start = 0, width = 16) {
  const rows = []
  for (let i = 0; i < bytes.length; i += width) {
    const slice = Array.from(bytes.slice(i, i + width))
    rows.push({
      offset: start + i,
      hex: slice.map((b) => b.toString(16).padStart(2, '0')),
      ascii: slice.map((b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : '.')).join(''),
    })
  }
  return rows
}

export const formatOffset = (n) => n.toString(16).padStart(8, '0')

/** "4 s", "2 min", "3 h": the delay between two hops. */
export function formatDelay(ms) {
  if (ms === null || ms === undefined) return ''
  const sign = ms < 0 ? '−' : ''
  const abs = Math.abs(ms)
  if (abs < 60_000) return `${sign}${Math.round(abs / 1000)} s`
  if (abs < 3_600_000) return `${sign}${Math.round(abs / 60_000)} min`
  return `${sign}${(abs / 3_600_000).toFixed(1)} h`
}

/** What toggleFlag() expects for a message as a whole (the timeline and the message list flag the same key). */
export function mailFlaggable(message) {
  return {
    key: `mail:${message.sha256}`,
    browserId: 'mail',
    section: 'mail',
    eventType: 'mail',
    title: message.subject || message.fileName || message.sha256,
    url: message.from ?? '',
    time: message.date ?? anyToMs(message.importedAt),
  }
}

/**
 * Timeline events of the analysed e-mails: one per message, at the time it was
 * sent (its import time when the Date header is missing). A phishing verdict
 * is high, a suspicious one medium, on top of the SOC rules.
 */
export function mailEvents(messages = [], engine) {
  return messages.map((message) => {
    const time = message.date ?? anyToMs(message.importedAt)
    const label = message.subject || message.fileName || message.sha256
    const soc = engine.analyze({ kind: 'mail', title: label, url: message.from ?? '', time })
    const severity =
      message.verdict === 'phishing'
        ? 'high'
        : message.verdict === 'suspicious' && soc.severity !== 'high'
          ? 'medium'
          : soc.severity
    return {
      id: `mail:${message.sha256}`,
      time,
      sourceType: 'mail',
      sourceLabel: 'E-mail',
      eventType: 'mail',
      label,
      detail: `${message.from ?? '?'} · ${verdictMeta(message.verdict).label} (${message.score ?? 0})`,
      soc: { ...soc, severity, isFlagged: severity !== null },
      flaggable: mailFlaggable(message),
    }
  })
}

const OFFICE_EXT = new Set(
  'doc docx docm dot dotx dotm rtf odt ott xls xlsx xlsm xlsb xlt xltx xltm ods csv ppt pptx pptm pps ppsx ppsm pot potx odp'.split(
    ' ',
  ),
)
const IMAGE_EXT = new Set('png jpg jpeg gif bmp tif tiff webp'.split(' '))
const HTML_EXT = new Set('html htm shtml xhtml svg'.split(' '))

/** How an attachment can be previewed: 'document', 'html' or null (mirrors backend previews.kind). */
export function previewKind(item) {
  if (!item?.size) return null
  const ext = item.extension ?? ''
  if (HTML_EXT.has(ext)) return 'html'
  if (['pdf', 'rtf', 'png', 'jpeg', 'gif'].includes(item.type?.id) || ext === 'pdf') return 'document'
  if (OFFICE_EXT.has(ext) || IMAGE_EXT.has(ext)) return 'document'
  return null
}

/** Page coordinates of a click on a screenshot drawn at another size. */
export function toPagePoint(clientX, clientY, rect, width, height) {
  const x = Math.round(((clientX - rect.left) * width) / rect.width)
  const y = Math.round(((clientY - rect.top) * height) / rect.height)
  return { x: Math.min(width, Math.max(0, x)), y: Math.min(height, Math.max(0, y)) }
}

// What the worker accepts for the size of a page (see workers/browser/nik_browser.py).
const VIEWPORT = { minWidth: 640, minHeight: 400, maxWidth: 2560, maxHeight: 1600 }

/**
 * The page size to ask the isolated browser for, given the space the window
 * has for it: that space, within the worker's limits, in steps of 8 pixels so
 * a window being dragged does not ask for a new size at every pixel.
 */
export function browserViewport(spaceWidth, spaceHeight) {
  const step = (value) => Math.floor((Number(value) || 0) / 8) * 8
  return {
    width: Math.min(VIEWPORT.maxWidth, Math.max(VIEWPORT.minWidth, step(spaceWidth))),
    height: Math.min(VIEWPORT.maxHeight, Math.max(VIEWPORT.minHeight, step(spaceHeight))),
  }
}

/**
 * The size to draw a `width` x `height` picture at inside a space: its own
 * size when it fits, scaled down (never up, never distorted) when it does not.
 */
export function fitInside(width, height, spaceWidth, spaceHeight) {
  // Two pixels for the frame's border.
  const scale = Math.min(1, (spaceWidth - 2) / width, (spaceHeight - 2) / height)
  if (!(scale > 0)) return { width, height }
  return { width: Math.floor(width * scale), height: Math.floor(height * scale) }
}

// Keys replayed as key presses (the worker accepts these); the rest is typed text.
export const BROWSER_KEYS = new Set([
  'Enter',
  'Tab',
  'Backspace',
  'Delete',
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
  'Home',
  'End',
  'PageUp',
  'PageDown',
])
