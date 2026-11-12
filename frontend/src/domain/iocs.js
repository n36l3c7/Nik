/*
 * ============================================================================
 * INDICATORS OF COMPROMISE — labels and helpers for the IOCs tab
 * ============================================================================
 *
 * The server indexes every indicator of every incident (backend/app/iocs.py)
 * and answers "where else was this seen?". This module names the types and
 * the sources it reports, and guesses the type of a bare value so any table
 * can offer the lookup.
 */

import { BROWSERS } from '../config/browsers.js'
import { SHELLS } from '../config/shells.js'
import { ARTIFACT_CATEGORIES } from '../config/artifacts.js'
import { getChannel } from '../config/eventLogs.js'

export const IOC_TYPES = {
  ip: { label: 'IP address', short: 'IP', color: 'cyan' },
  domain: { label: 'Domain', short: 'domain', color: 'violet' },
  url: { label: 'URL', short: 'URL', color: 'amber' },
  email: { label: 'E-mail', short: 'e-mail', color: 'slate' },
  md5: { label: 'MD5', short: 'MD5', color: 'emerald' },
  sha1: { label: 'SHA-1', short: 'SHA-1', color: 'emerald' },
  sha256: { label: 'SHA-256', short: 'SHA-256', color: 'emerald' },
}

const label = (list, id) => list.find((item) => item.id === id)?.label ?? id

/** The flag key of an indicator, whatever tab shows it. */
export const indicatorFlagKey = (type, value) => `ioc:${type}:${value}`

/**
 * What toggleFlag() expects for an indicator flagged by hand: no time of its
 * own (the report lists it among the indicators, not on the timeline).
 */
export function indicatorFlaggable(type, value) {
  return {
    key: indicatorFlagKey(type, value),
    browserId: 'ioc',
    section: 'iocs',
    eventType: type,
    title: String(value),
    url: type === 'url' ? String(value) : '',
    time: null,
  }
}

/** "browser:chrome" → "Browser · Chrome", "eventlog:Security" → "Event log · Security"… */
export function sourceLabel(source) {
  const [kind, ...rest] = String(source ?? '').split(':')
  const id = rest.join(':')
  switch (kind) {
    case 'browser':
      return `Browser · ${label(BROWSERS, id)}`
    case 'commands':
      return `Commands · ${label(SHELLS, id)}`
    case 'endpoint':
      return `Endpoint · ${label(ARTIFACT_CATEGORIES, id)}`
    case 'eventlog':
      return `Event log · ${getChannel(id)?.short ?? id}`
    case 'sample':
      return `Sample · ${id}`
    case 'mail':
      return `Mail · ${id}`
    case 'network':
      return `Network · ${id}`
    case 'url':
      return `URL scan · ${id}`
    default:
      return String(source ?? '')
  }
}

const IPV4 = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
const IPV6 = /^[0-9a-f]*:[0-9a-f:]+$/i

/** The indicator type of a bare value, or null when it is none of them. */
export function guessIocType(value) {
  const text = String(value ?? '').trim()
  if (!text || text.length > 1024) return null
  if (IPV4.test(text) || (IPV6.test(text) && text.includes(':'))) return 'ip'
  if (/^(?:https?|ftp):\/\//i.test(text)) return 'url'
  if (/^[^\s@]+@[a-z0-9.-]+\.[a-z]{2,}$/i.test(text)) return 'email'
  if (/^[a-f0-9]{64}$/i.test(text)) return 'sha256'
  if (/^[a-f0-9]{40}$/i.test(text)) return 'sha1'
  if (/^[a-f0-9]{32}$/i.test(text)) return 'md5'
  if (/^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(text)) return 'domain'
  return null
}

const parentDomains = (host) => {
  const labels = String(host).toLowerCase().replace(/\.$/, '').split('.')
  const out = []
  for (let i = 0; i < labels.length - 1; i += 1) out.push(labels.slice(i).join('.'))
  return out
}

const hostOf = (url) => {
  try {
    return new URL(url).hostname
  } catch {
    return ''
  }
}

/**
 * Allowlist entries an analyst can choose for an indicator, narrowest first:
 * `[{ entry, label }]`. A domain entry also covers its subdomains, URLs and
 * e-mail addresses on it (see Allowlist in backend/app/iocs.py).
 */
export function allowlistOptions(type, value) {
  const v = String(value ?? '').trim()
  if (!v) return []
  const domains = (host) =>
    parentDomains(host).map((d, i) => ({
      entry: d,
      label: i === 0 ? `${d} and its subdomains` : `the whole domain ${d}`,
    }))
  switch (type) {
    case 'url':
      return [{ entry: v, label: 'this exact URL' }, ...domains(hostOf(v))]
    case 'domain':
      return domains(v)
    case 'email':
      return [{ entry: v.toLowerCase(), label: 'this address' }, ...domains(v.split('@').pop())]
    case 'ip': {
      // IPv6: the exact address only (a prefix needs the expanded form).
      if (v.includes(':')) return [{ entry: v, label: 'this address' }]
      const net = `${v.split('.').slice(0, 3).join('.')}.0/24`
      return [
        { entry: v, label: 'this address' },
        { entry: net, label: `the network ${net}` },
      ]
    }
    default:
      return [{ entry: v.toLowerCase(), label: 'this value' }]
  }
}

/** A value made safe to paste in a ticket or a chat: hxxps[:]//evil[.]top */
export function defang(value) {
  return String(value ?? '')
    .replace(/^http/i, 'hxxp')
    .replace(/^ftp/i, 'fxp')
    .replace('://', '[:]//')
    .replace(/@/g, '[@]')
    .replace(/\./g, '[.]')
}

// ---- indicators inside a line of text ---------------------------------------

/** An address on the internet: not private, loopback, link-local, CGNAT, multicast or reserved. */
export function isPublicIp(value) {
  const text = String(value ?? '')
  if (IPV4.test(text)) {
    const [a, b] = text.split('.').map(Number)
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false
    if (a === 172 && b >= 16 && b <= 31) return false
    if (a === 192 && b === 168) return false
    if (a === 169 && b === 254) return false
    if (a === 100 && b >= 64 && b <= 127) return false
    return true
  }
  if (IPV6.test(text) && text.includes(':')) {
    const lower = text.toLowerCase()
    return !(lower === '::' || lower === '::1' || /^(fe[89ab]|f[cd]|ff)/.test(lower))
  }
  return false
}

// What a host name is not: a file, a version, a protocol field.
const NOT_A_TLD = new Set(
  (
    'php html htm js css json xml txt exe dll bin dat zip rar gz tar png jpg jpeg gif svg ico bmp webp pdf doc docx ' +
    'xls xlsx ppt pptx asp aspx jsp cgi log tmp bak cfg conf ini sys bat cmd ps vbs sh py rb pl so lib pem crt key ' +
    'woff woff2 ttf eot mp3 mp4 avi mov wav map min src dst len seq ack win request response local lan internal corp home'
  ).split(' '),
)
const TOKEN =
  /\b(?:https?|ftp|wss?):\/\/[^\s"'<>]+|\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b|\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b|\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi

/**
 * A line of text cut where it holds indicators: `[{ text, type? }]`, in order.
 * Public addresses, URLs, hashes and host names get a type; private addresses
 * and everything else stay plain text. `hint` names what the whole line is
 * when the caller knows (a protocol field): 'ip', 'domain' or 'url'.
 */
export function indicatorSegments(text, hint = null) {
  const line = String(text ?? '')
  const out = []
  const push = (piece, type) => {
    if (!piece) return
    const last = out[out.length - 1]
    if (!type && last && !last.type) last.text += piece
    else out.push(type ? { text: piece, type } : { text: piece })
  }
  let cursor = 0
  for (const match of line.matchAll(TOKEN)) {
    let token = match[0]
    // Punctuation that ends a sentence or closes a bracket is not part of an address.
    token = token.replace(/[.,;:)\]}'"]+$/, '')
    if (!token) continue
    const start = match.index
    // A token glued to "/" or "@" on its left is a path segment or the host of an e-mail address.
    const before = line[start - 1] ?? ''
    let type = guessIocType(token)
    // "Chrome/130.0.0.0" is a version, not an address.
    if (type === 'ip' && (!isPublicIp(token) || before === '/')) type = null
    if (type === 'domain') {
      const tld = token.slice(token.lastIndexOf('.') + 1).toLowerCase()
      if (NOT_A_TLD.has(tld) || /^\d+$/.test(tld) || before === '/' || before === '@' || before === '\\') type = null
      else if (hint !== 'domain' && !/[a-z]/i.test(token.split('.')[0])) type = null
    }
    if (type === 'url') {
      try {
        const host = new URL(token).hostname
        if (IPV4.test(host) ? !isPublicIp(host) : !host.includes('.')) type = null
      } catch {
        type = null
      }
    }
    push(line.slice(cursor, start), null)
    push(token, type)
    cursor = start + token.length
  }
  push(line.slice(cursor), null)
  return out
}
