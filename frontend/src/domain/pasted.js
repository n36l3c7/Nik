/*
 * Text pasted or dragged onto the app: is it something Nik can act on?
 *
 * recognise() answers for one short piece of text: an address to scan, or an
 * indicator (hash, IP address, domain, e-mail address) to search and check.
 * Defanged text is understood (`hxxps://evil[.]top`, `1.2.3[.]4`). Anything
 * else (sentences, several lines, long text) is not for Nik: null.
 */

import { guessIocType } from './iocs.js'
import { urlFromText } from './urlscan.js'

const MAX_LENGTH = 2000

export const PASTED_LABELS = {
  url: 'URL',
  domain: 'domain',
  ip: 'IP address',
  sha256: 'SHA-256',
  sha1: 'SHA-1',
  md5: 'MD5',
  email: 'e-mail address',
}

/** Undo the usual defanging: hxxp, [.] (.) [:] [at] [@]. */
export function refang(text) {
  return String(text ?? '')
    .trim()
    .replace(/\[\.\]|\(\.\)|\{\.\}/g, '.')
    .replace(/\[:\]/g, ':')
    .replace(/\[at\]|\[@\]/gi, '@')
    .replace(/^hxxp/i, 'http')
}

/**
 * @returns {{ kind: string, value: string, url: string | null, defanged: boolean } | null}
 *   `kind`: url | domain | ip | sha256 | sha1 | md5 | email; `value`: the
 *   indicator as Nik reads it; `url`: the address to scan (for a URL, and for
 *   a domain, which can be visited too); `defanged`: the text was not written
 *   plainly.
 */
export function recognise(text) {
  const raw = String(text ?? '').trim()
  if (!raw || raw.length > MAX_LENGTH || /\s/.test(raw)) return null
  const plain = refang(raw)
  const defanged = plain !== raw
  // An address needs its scheme or a path: a bare "example.com" is a domain.
  if (/^https?:\/\//i.test(plain) || (plain.includes('/') && !plain.includes('@'))) {
    const url = urlFromText(plain)
    return url ? { kind: 'url', value: url, url, defanged } : null
  }
  const kind = guessIocType(plain)
  if (!kind || kind === 'url') return null
  const value = ['sha256', 'sha1', 'md5', 'domain', 'email'].includes(kind) ? plain.toLowerCase() : plain
  return { kind, value, url: kind === 'domain' ? `https://${value}/` : null, defanged }
}
