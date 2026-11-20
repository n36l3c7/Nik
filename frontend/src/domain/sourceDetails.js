/*
 * What a source of threat intelligence said about an indicator, shaped for
 * the indicator's page.
 *
 * An answer is the outputs of the reputation command of the source's
 * connector, as the command gives them (`data` of GET /api/enrichment, with
 * `_command` naming the command: "virustotal.get-ip-report"). The server
 * renames nothing and knows no vendor: a list comes as the vendor sends it,
 * a date in the vendor's own format. What the page shows of each is decided
 * here: how many rows, which columns, dates as one kind of number.
 *
 * Everything is defensive: an output may be missing, or of another type than
 * expected, when a connector file changes.
 */

export const ROWS_SHOWN = 10

/** The id of the connector that answered ("virustotal"), from `_command`; '' when the answer names none. */
export function sourceOf(data) {
  const command = typeof data?._command === 'string' ? data._command : ''
  return command.split('.')[0] ?? ''
}

/** The command that answered, without its connector ("get-ip-report"). */
export function commandOf(data) {
  const command = typeof data?._command === 'string' ? data._command : ''
  return command.includes('.') ? command.slice(command.indexOf('.') + 1) : ''
}

const list = (value) => (Array.isArray(value) ? value : [])
const text = (value, limit = 300) =>
  value === null || value === undefined || value === '' ? '' : String(value).slice(0, limit)

/**
 * A moment as Unix milliseconds, from what vendors send: seconds or
 * milliseconds as a number, ISO 8601, or "2026-01-31 10:00:00 UTC" (abuse.ch,
 * read as UTC also when it does not say so). null for anything else.
 */
export function toMs(value) {
  if (typeof value === 'number' && Number.isFinite(value) && value > 0) return value < 1e11 ? value * 1000 : value
  if (typeof value !== 'string' || !value.trim()) return null
  let cleaned = value.trim().replace(/ UTC$/, '')
  if (/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}/.test(cleaned)) cleaned = cleaned.replace(' ', 'T')
  if (/^\d{4}-\d{2}-\d{2}T[\d:.]+$/.test(cleaned)) cleaned += 'Z'
  const parsed = Date.parse(cleaned)
  return Number.isNaN(parsed) ? null : parsed
}

// The categories of an AbuseIPDB report, as www.abuseipdb.com/categories names them.
const ABUSE_CATEGORIES = {
  1: 'DNS Compromise',
  2: 'DNS Poisoning',
  3: 'Fraud Orders',
  4: 'DDoS Attack',
  5: 'FTP Brute-Force',
  6: 'Ping of Death',
  7: 'Phishing',
  8: 'Fraud VoIP',
  9: 'Open Proxy',
  10: 'Web Spam',
  11: 'Email Spam',
  12: 'Blog Spam',
  13: 'VPN IP',
  14: 'Port Scan',
  15: 'Hacking',
  16: 'SQL Injection',
  17: 'Spoofing',
  18: 'Brute-Force',
  19: 'Bad Web Bot',
  20: 'Exploited Host',
  21: 'Web App Attack',
  22: 'SSH',
  23: 'IoT Targeted',
}

/** AbuseIPDB: the latest reports, with the names of their categories. */
export function abuseReports(reports) {
  return list(reports)
    .slice(0, ROWS_SHOWN)
    .map((report) => ({
      date: toMs(report?.reportedAt),
      categories: list(report?.categories).map((id) => ABUSE_CATEGORIES[id] ?? String(id)),
      comment: text(report?.comment),
      country: report?.reporterCountryCode ?? null,
    }))
}

/** VirusTotal: the vendors listed, those that flag the value or all of them. */
export function vtEngines(data, all = false) {
  const rows = all && list(data?.all_engines).length ? list(data.all_engines) : list(data?.engines)
  return rows
    .filter((row) => row && row.engine)
    .map((row) => ({ engine: String(row.engine), category: row.category ?? '', result: text(row.result, 120) }))
}

/** OTX: the pulses the value is in, each with the address of its page. */
export function otxPulses(details) {
  return list(details)
    .slice(0, ROWS_SHOWN)
    .map((pulse) => ({
      name: text(pulse?.name, 200),
      author: pulse?.author ?? null,
      modified: toMs(pulse?.modified),
      tags: list(pulse?.tags).slice(0, 6),
      link: pulse?.id ? `https://otx.alienvault.com/pulse/${encodeURIComponent(pulse.id)}` : '',
    }))
}

/** OTX: why it vouches for the value ("whitelisted domain"), as short lines. */
export function otxValidation(validation) {
  return list(validation)
    .map((entry) => text(entry?.message ?? entry?.name, 120))
    .filter(Boolean)
    .slice(0, 5)
}

/** ThreatFox: the indicators that match, newest as the service lists them. */
export function threatfoxIocs(iocs) {
  return list(iocs)
    .slice(0, ROWS_SHOWN)
    .map((entry) => ({
      ioc: text(entry?.ioc),
      threat: entry?.threat_type_desc || entry?.threat_type || null,
      malware: entry?.malware_printable ?? null,
      confidence: entry?.confidence_level ?? null,
      firstSeen: toMs(entry?.first_seen),
      link: entry?.id ? `https://threatfox.abuse.ch/ioc/${encodeURIComponent(entry.id)}/` : '',
    }))
}

/** URLhaus: the files a malware URL served. */
export function urlhausPayloads(payloads) {
  return list(payloads)
    .slice(0, ROWS_SHOWN)
    .map((payload) => ({
      sha256: payload?.response_sha256 ?? null,
      fileType: payload?.file_type ?? null,
      signature: payload?.signature ?? null,
      firstSeen: toMs(payload?.firstseen),
    }))
}

/** URLhaus: the malware URLs on a host, or that served a file. */
export function urlhausUrls(urls) {
  return list(urls)
    .slice(0, ROWS_SHOWN)
    .map((entry) => ({
      url: text(entry?.url, 500),
      status: entry?.url_status ?? null,
      threat: entry?.threat ?? null,
      added: toMs(entry?.date_added ?? entry?.firstseen),
    }))
}

/** urlscan.io: the public scans, either shape of the verdict read. */
export function urlscanScans(scans) {
  return list(scans)
    .slice(0, ROWS_SHOWN)
    .map((scan) => {
      const page = scan?.page ?? {}
      const verdicts = scan?.verdicts ?? {}
      return {
        time: toMs(scan?.task?.time),
        url: text(page.url, 500),
        ip: page.ip ?? null,
        country: page.country ?? null,
        title: text(page.title, 160),
        malicious: Boolean(verdicts.malicious || verdicts.overall?.malicious),
        result: scan?._id ? `https://urlscan.io/result/${encodeURIComponent(scan._id)}/` : '',
      }
    })
}

const spaced = (value) =>
  String(value ?? '')
    .replaceAll('_', ' ')
    .toLowerCase()

/** Google Safe Browsing: the lists the address is on. */
export function safeBrowsingMatches(matches) {
  return list(matches)
    .slice(0, ROWS_SHOWN)
    .map((match) => ({
      threat: spaced(match?.threatType),
      platform: spaced(match?.platformType),
      url: text(match?.threat?.url, 500),
    }))
}

/** "203.0.113.0 – 203.0.113.255", or the CIDRs when the registry gives them. */
export function networkRange(data) {
  const cidrs = list(data?.cidrs)
    .map((cidr) => (cidr?.v4prefix ?? cidr?.v6prefix) && `${cidr.v4prefix ?? cidr.v6prefix}/${cidr.length}`)
    .filter(Boolean)
  if (cidrs.length) return cidrs.slice(0, 4).join(', ')
  if (data?.start_address && data?.end_address) return `${data.start_address} – ${data.end_address}`
  return data?.start_address ?? null
}

/**
 * Days since the domain was registered, when a registry says it is a young
 * one (its answer flags the value and gives an age); else null.
 */
export function youngDomainDays(results = []) {
  const found = list(results).find(
    (result) =>
      result?.status === 'done' &&
      ['suspicious', 'malicious'].includes(result.verdict) &&
      typeof result.data?.age_days === 'number',
  )
  return found ? found.data.age_days : null
}

const label = (name) => name.replaceAll('_', ' ')

/**
 * An answer of a connector this page has no layout for, as rows: every
 * output that is a plain value, short lists as one line, longer things as a
 * count (the JSON download has them whole). `[[label, text]]`.
 */
export function genericFacts(data) {
  const rows = []
  for (const [name, value] of Object.entries(data ?? {})) {
    if (name.startsWith('_') || value === null || value === undefined || value === '') continue
    if (typeof value === 'boolean') rows.push([label(name), value ? 'yes' : 'no'])
    else if (typeof value === 'number' || typeof value === 'string') rows.push([label(name), text(value, 500)])
    else if (Array.isArray(value)) {
      if (!value.length) continue
      const plain = value.every((item) => ['string', 'number'].includes(typeof item))
      rows.push([
        label(name),
        plain && value.length <= 20
          ? value.join(', ').slice(0, 500)
          : `${value.length} ${value.length === 1 ? 'entry' : 'entries'}`,
      ])
    }
  }
  return rows
}

/** "reports: the first 100 of 2 400" for each list the server cut, as one line; '' when none was. */
export function cutNote(data) {
  const cut = data?._cut && typeof data._cut === 'object' ? Object.entries(data._cut) : []
  if (!cut.length) return ''
  const parts = cut.map(([name, total]) => `${label(name)} (${total})`)
  return `Longer than the page shows, whole in the JSON download: ${parts.join(', ')}.`
}
