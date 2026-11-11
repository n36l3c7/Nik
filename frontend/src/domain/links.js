import { defang } from './iocs.js'

/*
 * Addresses that come from the evidence, and the CSS of hostile HTML.
 * Pure helpers behind EvidenceLink and the sandboxed previews.
 */

/**
 * What can be done with an address found in the evidence.
 * @returns {{ href: string|null, scheme: string, defanged: string }} `href` is
 *   set only for an http(s) address: nothing else is ever opened (a bookmark
 *   can hold `javascript:`, `data:` or `file:`).
 */
export function evidenceAddress(url) {
  const text = String(url ?? '').trim()
  const scheme = (/^([a-z][a-z0-9+.-]*):/i.exec(text)?.[1] ?? '').toLowerCase()
  let href = null
  if (scheme === 'http' || scheme === 'https') {
    try {
      href = new URL(text).href
    } catch {
      href = null
    }
  }
  return { href, scheme, defanged: defang(text) }
}

/**
 * CSS with every remote reference removed: `url(...)` that is not a `data:`
 * image, and `@import`. A style attribute or a style sheet is the one place
 * left where a message can make the reader's browser call home (a tracking
 * "pixel" as a background image) once images are allowed.
 */
export function stripRemoteCss(css) {
  return String(css ?? '')
    .replace(/@import\b[^;]*;?/gi, '')
    .replace(/url\(\s*(['"]?)\s*(?!data:)[^)]*\)/gi, 'none')
}

/** True when two image addresses are the same one, however the HTML spelled it. */
export function sameAddress(a, b) {
  const normal = (value) => {
    const text = String(value ?? '').trim()
    return text.startsWith('//') ? `https:${text}` : text
  }
  return normal(a) === normal(b)
}
