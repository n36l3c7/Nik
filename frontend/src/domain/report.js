/*
 * Incident report options and the detections the app sends with a report
 * request (the server builds the HTML/PDF: backend/app/report.py).
 */

export const REPORT_SECTIONS = [
  { id: 'summary', label: 'Executive summary and key facts' },
  { id: 'timeline', label: 'Flagged events' },
  { id: 'attack', label: 'MITRE ATT&CK techniques' },
  { id: 'iocs', label: 'Indicators of compromise' },
  { id: 'samples', label: 'Malware samples' },
  { id: 'mails', label: 'E-mails' },
  { id: 'network', label: 'Network captures' },
  { id: 'eventlogs', label: 'Windows event logs' },
  { id: 'notes', label: 'Analyst notes' },
  { id: 'evidence', label: 'Evidence appendix (files and SHA-256)' },
]

export const TLP_OPTIONS = [
  { value: 'clear', label: 'TLP:CLEAR' },
  { value: 'green', label: 'TLP:GREEN' },
  { value: 'amber', label: 'TLP:AMBER' },
  { value: 'amber+strict', label: 'TLP:AMBER+STRICT' },
  { value: 'red', label: 'TLP:RED' },
]

export const LANGUAGE_OPTIONS = [
  { value: 'en', label: 'English' },
  { value: 'it', label: 'Italiano' },
]

/** Saved report settings of an incident, with the defaults filled in. */
export function reportSettings(incident) {
  const saved = incident?.report ?? {}
  return {
    lang: LANGUAGE_OPTIONS.some((o) => o.value === saved.lang) ? saved.lang : 'en',
    tlp: TLP_OPTIONS.some((o) => o.value === saved.tlp) ? saved.tlp : 'amber',
    sections: Array.isArray(saved.sections) ? saved.sections : REPORT_SECTIONS.map((s) => s.id),
    executiveSummary: typeof saved.executiveSummary === 'string' ? saved.executiveSummary : '',
  }
}

/**
 * The SOC rule hits of an incident, from buildTimelineEvents() output:
 * `[{ id, label, severity, count, attack }]`, most frequent first.
 */
export function reportDetections(events) {
  const byRule = new Map()
  for (const event of events) {
    for (const rule of event.soc?.keywordMatches ?? []) {
      const known = byRule.get(rule.id)
      if (known) known.count += 1
      else {
        byRule.set(rule.id, {
          id: rule.id,
          label: rule.label,
          severity: rule.severity,
          count: 1,
          attack: Array.isArray(rule.attack) ? rule.attack : [],
        })
      }
    }
  }
  return [...byRule.values()].sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
}
