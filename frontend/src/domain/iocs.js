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
