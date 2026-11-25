/*
 * Incident report options (the server builds the HTML/PDF: backend/app/report.py; the rule matches in it
 * are read there from its tables).
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
    // 'flagged': only what the analysts flagged (the default); 'all': everything in the incident.
    scope: saved.scope === 'all' ? 'all' : 'flagged',
  }
}
