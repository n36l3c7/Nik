/*
 * ============================================================================
 * MALWARE SAMPLE KEYWORDS AND BUSINESS HOURS — FACTORY DEFAULTS
 * ============================================================================
 *
 * What is left of the client-side detection (7.0): the keywords the Malware
 * Analysis tab looks for in the strings and indicators of a sample, and the
 * business hours the settings start from. The rules that read host evidence
 * (event logs, browser, commands, endpoint artifacts) are Sigma rules now,
 * run by the server (Settings > Rule sets > Sigma rules).
 *
 * Each keyword rule:
 *  - id:          unique rule identifier
 *  - label:       short name shown on UI badges
 *  - pattern:     source of a (case-insensitive) RegExp
 *  - severity:    'high' (red) | 'medium' (amber)
 *  - description: explanation shown in the tooltip / detail
 *  - attack:      MITRE ATT&CK technique ids the rule points to
 */

/*
 * Applied by the "Malware Analysis" tab to the strings and indicators
 * extracted from a sample: process injection and anti-debug APIs, persistence
 * locations, command-and-control patterns, encoded PowerShell and throwaway
 * TLDs. Matched case-insensitively against the string or indicator value.
 */
export const DEFAULT_MALWARE_KEYWORDS = [
  {
    id: 'mal-injection',
    label: 'process injection',
    pattern:
      'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext|NtUnmapViewOfSection',
    severity: 'high',
    attack: ['T1055'],
    description: 'Windows APIs used to run code inside another process.',
  },
  {
    id: 'mal-anti-debug',
    label: 'anti-analysis',
    pattern: 'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|sbiedll|vboxservice|vmtoolsd',
    severity: 'medium',
    attack: ['T1622'],
    description: 'Debugger or sandbox detection.',
  },
  {
    id: 'mal-run-key',
    label: 'persistence',
    pattern: 'CurrentVersion\\\\(Run|RunOnce|Explorer\\\\Shell Folders)|schtasks|CreateService|\\\\Startup\\\\',
    severity: 'medium',
    attack: ['T1547.001'],
    description: 'Run keys, scheduled tasks, services or startup folders.',
  },
  {
    id: 'mal-c2-path',
    label: 'c2 pattern',
    pattern:
      '/(gate|panel|bot|cmd|task|beacon|checkin|c2)\\.php|/api/v\\d/(bot|client)s?/|User-Agent: Mozilla/4\\.0 \\(compatible; MSIE',
    severity: 'high',
    attack: ['T1071.001'],
    description: 'URL paths and headers typical of command-and-control traffic.',
  },
  {
    id: 'mal-encoded-ps',
    label: 'encoded powershell',
    pattern: 'powershell[^\\n]*(-enc|-e |-encodedcommand|frombase64string|-nop|-w hidden)',
    severity: 'high',
    attack: ['T1059.001', 'T1027'],
    description: 'PowerShell launched with an encoded or hidden payload.',
  },
  {
    id: 'mal-throwaway-tld',
    label: 'throwaway tld',
    pattern: '\\.(top|xyz|tk|ml|ga|cf|gq|pw|cc|su|click|buzz|monster)(/|$|\\s)',
    severity: 'medium',
    description: 'Domains on TLDs favoured by disposable malware infrastructure.',
  },
  {
    id: 'mal-crypto',
    label: 'ransomware hints',
    pattern:
      'CryptEncrypt|BCryptEncrypt|vssadmin[^\\n]*delete shadows|wbadmin delete|your files have been encrypted|decrypt',
    severity: 'high',
    attack: ['T1486'],
    description: 'File encryption APIs, shadow-copy deletion or ransom-note wording.',
  },
  {
    id: 'mal-recon',
    label: 'recon & credentials',
    pattern: 'GetAsyncKeyState|mimikatz|sekurlsa|lsass|CreateToolhelp32Snapshot|NetUserAdd|\\\\SAM\\b',
    severity: 'high',
    attack: ['T1082', 'T1003'],
    description: 'Keylogging, credential dumping or host enumeration.',
  },
]

export const DEFAULT_BUSINESS_HOURS = {
  startHour: 8, // start of business hours (inclusive)
  endHour: 18, // end of business hours (exclusive)
  flagWeekends: true, // if true, weekends are always "outside hours"
  tz: 'UTC', // IANA name of the zone the hours are told in (the server's rules and timers use it)
}
