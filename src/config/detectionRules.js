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
 * COMMAND-LINE DETECTION RULES — FACTORY DEFAULTS.
 *
 * Applied by the "Command History" tab on top of the user-editable keyword
 * rules above (which also run against commands, so custom keywords added in
 * the Settings cover both browsers and shells). These defaults target
 * shell/PowerShell tradecraft rather than web navigation. Same shape as the
 * keyword rules; matched case-insensitively against the command line.
 */
export const DEFAULT_COMMAND_KEYWORDS = [
  {
    id: 'cmd-download-exec',
    label: 'download → execute',
    pattern: '(curl|wget)[^|;&]*\\|\\s*(ba|z|da)?sh\\b|iwr\\b.*\\|\\s*iex|iex\\s*\\(.*(iwr|downloadstring)',
    severity: 'high',
    description: 'Remote content downloaded and piped straight into a shell interpreter.',
  },
  {
    id: 'cmd-encoded',
    label: 'encoded payload',
    pattern: 'base64\\s+(-d|--decode)|frombase64string|-encodedcommand|\\s-enc\\s|certutil.*-decode',
    severity: 'high',
    description: 'Base64/encoded payload decoding, a common obfuscation step.',
  },
  {
    id: 'cmd-reverse-shell',
    label: 'reverse shell',
    pattern: '\\bnc(at)?\\b[^|]*\\s-e\\s|/dev/tcp/|bash\\s+-i\\s+>&|mkfifo\\s+/tmp|socat\\b.*exec',
    severity: 'high',
    description: 'Classic reverse/bind shell one-liners (netcat -e, /dev/tcp, socat exec…).',
  },
  {
    id: 'cmd-history-tampering',
    label: 'history tampering',
    pattern: 'history\\s+-c|unset\\s+histfile|histsize=0|histfilesize=0|clear-history|rm\\s+[^|;&]*_history',
    severity: 'high',
    description: 'Attempt to clear or disable the shell history (anti-forensics).',
  },
  {
    id: 'cmd-cred-access',
    label: 'credential access',
    pattern: '/etc/shadow|mimikatz|lazagne|secretsdump|hashdump|ntds\\.dit|lsass|procdump[^|;&]*lsass',
    severity: 'high',
    description: 'Access to credential stores (shadow file, LSASS, NTDS) or dumping tools.',
  },
  {
    id: 'cmd-defense-evasion',
    label: 'defense evasion',
    pattern: 'set-mppreference|amsi(utils|\\.dll)|setenforce\\s+0|systemctl\\s+(stop|disable)\\s+(falcon|sentinel|cb|auditd)|auditctl\\s+-e\\s*0',
    severity: 'high',
    description: 'Disabling AV/EDR/auditing (Defender, SELinux, auditd, EDR services).',
  },
  {
    id: 'cmd-priv-escalation',
    label: 'privilege escalation',
    pattern: 'sudo\\s+su\\b|chmod\\s+\\+s\\b|chmod\\s+4755|/etc/sudoers|pkexec\\b',
    severity: 'medium',
    description: 'Privilege escalation attempts (setuid bits, sudoers edits, pkexec).',
  },
  {
    id: 'cmd-persistence',
    label: 'persistence',
    pattern: 'crontab\\s+-|authorized_keys|systemctl\\s+enable|schtasks\\b|reg\\s+add\\b[^|;&]*\\\\run|launchctl\\s+(load|bootstrap)',
    severity: 'medium',
    description: 'Persistence mechanisms: cron, SSH keys, services, Run keys, LaunchAgents.',
  },
  {
    id: 'cmd-recon',
    label: 'recon / scanning',
    pattern: '\\bnmap\\b|masscan|whoami\\s*/priv|net\\s+group\\s+.domain|smbclient\\b|bloodhound|sharphound',
    severity: 'medium',
    description: 'Network/AD reconnaissance and scanning tools.',
  },
  {
    id: 'cmd-exfil',
    label: 'exfiltration',
    pattern: '\\brclone\\b|curl\\s+(-T|--upload-file)|tar\\b[^|;&]*\\|\\s*ssh|scp\\s+[^|;&]*@',
    severity: 'medium',
    description: 'Bulk data transfer toward remote hosts (rclone, scp, curl upload, tar over ssh).',
  },
  {
    id: 'cmd-destructive',
    label: 'destructive',
    pattern: 'rm\\s+-rf\\s+(/|~)(\\s|$)|mkfs\\.|dd\\s+if=[^|;&]*of=/dev/(sd|nvme|vd)|vssadmin\\s+delete\\s+shadows',
    severity: 'high',
    description: 'Destructive commands: filesystem wipe, shadow-copy deletion (ransomware pattern).',
  },
]

/*
 * ENDPOINT ARTIFACT DETECTION RULES — FACTORY DEFAULTS.
 *
 * Applied by the "Endpoint Artifacts" tab (program execution, persistence,
 * file access, removable devices) on top of the shared keyword rules. These
 * target file-system / registry tradecraft: execution from temp or user-writable
 * paths, living-off-the-land binaries, script droppers, suspicious persistence
 * locations. Matched case-insensitively against the artifact's path/name/detail
 * fields. Same shape as the keyword rules.
 */
export const DEFAULT_ARTIFACT_KEYWORDS = [
  {
    id: 'art-temp-exec',
    label: 'runs from temp',
    pattern:
      '\\\\(temp|tmp|windows\\\\temp)\\\\[^\\\\]*\\.(exe|dll|ps1|bat|cmd|scr|js|vbs)|/tmp/[^/]*\\.(sh|elf|py)|/dev/shm/',
    severity: 'high',
    description: 'Executable or script running from a temporary directory — classic malware staging.',
  },
  {
    id: 'art-user-writable-exec',
    label: 'runs from user path',
    pattern:
      '\\\\(users\\\\[^\\\\]+\\\\(appdata|downloads|desktop|documents))\\\\[^\\\\]*\\.(exe|dll|ps1|scr|js|vbs)|/home/[^/]+/(downloads|\\.cache)/[^/]*\\.(sh|elf)',
    severity: 'medium',
    description: 'Execution from a user-writable location (AppData/Downloads/Desktop) rather than Program Files.',
  },
  {
    id: 'art-lolbin',
    label: 'LOLBin',
    pattern:
      '\\b(mshta|rundll32|regsvr32|certutil|bitsadmin|wmic|cscript|wscript|installutil|msbuild|hh|forfiles)\\.exe\\b',
    severity: 'medium',
    description: 'Living-off-the-land binary frequently abused for execution or download.',
  },
  {
    id: 'art-double-ext',
    label: 'double extension',
    pattern: '\\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\\s*\\.(exe|scr|js|vbs|bat|cmd|lnk)\\b',
    severity: 'high',
    description: 'Double-extension file masquerading as a document — a common phishing lure.',
  },
  {
    id: 'art-suspicious-task',
    label: 'suspicious persistence',
    pattern:
      'currentversion\\\\run|\\\\tasks\\\\|authorized_keys|/etc/cron|launchagents|launchdaemons|\\.service\\b|rc\\.local',
    severity: 'medium',
    description: 'Common persistence location (Run key, scheduled task, cron, systemd, LaunchAgent, SSH keys).',
  },
  {
    id: 'art-suspicious-name',
    label: 'suspicious name',
    pattern:
      '\\b(mimikatz|psexec|procdump|lazagne|rubeus|cobalt|meterpreter|beacon|nc\\.exe|ncat|winpeas|linpeas|svch0st|scvhost)\\b',
    severity: 'high',
    description: 'File or process name matching a known offensive tool or a masquerading system name.',
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
