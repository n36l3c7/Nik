/*
 * ============================================================================
 * SOC DETECTION RULES — FACTORY DEFAULTS
 * ============================================================================
 *
 * These are the factory defaults. At runtime the rules are managed by
 * SettingsContext (src/context/SettingsContext.jsx), which starts from these
 * values but lets the user add/edit/remove keywords and change the business
 * hours from the platform Settings.
 *
 * Each keyword rule:
 *  - id:          unique rule identifier
 *  - label:       short name shown on UI badges
 *  - pattern:     source of a (case-insensitive) RegExp applied to URL + title
 *                 (+ file name). Use \\b (word boundary) for short keywords that
 *                 risk false positives (e.g. "tor" inside "tutorial").
 *  - severity:    'high' (red) | 'medium' (amber)
 *  - description: explanation shown in the tooltip / detail
 *
 * To change the factory defaults edit this array; for runtime changes use the
 * Settings UI. See README.md § "Extend the detection rules".
 */

export const DEFAULT_SUSPICIOUS_KEYWORDS = [
  {
    id: 'pastebin',
    label: 'pastebin',
    pattern: 'pastebin',
    severity: 'medium',
    description:
      'Text sharing service, often used for data exfiltration or payload delivery.',
  },
  {
    id: 'mega-nz',
    label: 'mega.nz',
    pattern: 'mega\\.nz',
    severity: 'medium',
    description:
      'Encrypted cloud storage, a frequent channel for exfiltration or downloading unauthorized tools.',
  },
  {
    id: 'onion',
    label: '.onion / darkweb',
    pattern: '\\.onion\\b|darkweb|dark[-_ ]web',
    severity: 'high',
    description: 'Tor network domain (hidden service): dark web access.',
  },
  {
    id: 'exploit',
    label: 'exploit',
    pattern: 'exploit',
    severity: 'high',
    description: 'Searching for or downloading exploits / offensive code (e.g. exploit-db).',
  },
  {
    id: 'bypass',
    label: 'bypass',
    pattern: 'bypass',
    severity: 'medium',
    description: 'Attempt to evade security controls (AV, UAC, filters…).',
  },
  {
    id: 'tor',
    label: 'tor',
    pattern: '\\btor\\b|torproject',
    severity: 'medium',
    description: 'Reference to the Tor network / Tor Browser (traffic anonymization).',
  },
  {
    id: 'malware',
    label: 'malware',
    pattern: 'malware|ransomware|trojan|keylogger',
    severity: 'high',
    description: 'Explicit reference to malware or malicious families.',
  },
  {
    id: 'cracking',
    label: 'crack/keygen',
    pattern: '\\bcrack(ed|ing)?\\b|keygen|warez',
    severity: 'medium',
    description: 'Pirated software: a common infection vector on corporate endpoints.',
  },
  {
    id: 'anon-sharing',
    label: 'anonymous file sharing',
    pattern: 'anonfiles|temp[-_ ]?mail|transfer\\.sh|gofile\\.io',
    severity: 'medium',
    description: 'Anonymous file sharing / disposable email services, possible exfiltration.',
  },
]

/*
 * BUSINESS HOURS.
 *
 * Events that occur OUTSIDE this window are highlighted as a temporal anomaly
 * ("outside business hours"). The window is [startHour, endHour) in local
 * hours; `flagWeekends: true` marks ALL weekend events (Saturday/Sunday) as
 * anomalous regardless of the hour.
 *
 * Editable at runtime from the platform Settings.
 */
export const DEFAULT_BUSINESS_HOURS = {
  startHour: 8, // start of business hours (inclusive)
  endHour: 18, // end of business hours (exclusive)
  flagWeekends: true, // if true, weekends are always "outside hours"
}
