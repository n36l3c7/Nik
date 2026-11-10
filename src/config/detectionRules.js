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
    description: 'Text sharing service, often used for data exfiltration or payload delivery.',
  },
  {
    id: 'mega-nz',
    label: 'mega.nz',
    pattern: 'mega\\.nz',
    severity: 'medium',
    description: 'Encrypted cloud storage, a frequent channel for exfiltration or downloading unauthorized tools.',
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
    pattern:
      'set-mppreference|amsi(utils|\\.dll)|setenforce\\s+0|systemctl\\s+(stop|disable)\\s+(falcon|sentinel|cb|auditd)|auditctl\\s+-e\\s*0',
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
    pattern:
      'crontab\\s+-|authorized_keys|systemctl\\s+enable|schtasks\\b|reg\\s+add\\b[^|;&]*\\\\run|launchctl\\s+(load|bootstrap)',
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
/*
 * MALWARE SAMPLE DETECTION RULES — FACTORY DEFAULTS.
 *
 * Applied by the "Malware Analysis" tab to the strings and indicators
 * extracted from a sample, on top of the shared keyword rules: process
 * injection and anti-debug APIs, persistence locations, command-and-control
 * patterns, encoded PowerShell and throwaway TLDs. Same shape as the keyword
 * rules; matched case-insensitively against the string or indicator value.
 */
export const DEFAULT_MALWARE_KEYWORDS = [
  {
    id: 'mal-injection',
    label: 'process injection',
    pattern:
      'VirtualAllocEx|WriteProcessMemory|CreateRemoteThread|NtCreateThreadEx|QueueUserAPC|SetThreadContext|NtUnmapViewOfSection',
    severity: 'high',
    description: 'Windows APIs used to run code inside another process.',
  },
  {
    id: 'mal-anti-debug',
    label: 'anti-analysis',
    pattern: 'IsDebuggerPresent|CheckRemoteDebuggerPresent|NtQueryInformationProcess|sbiedll|vboxservice|vmtoolsd',
    severity: 'medium',
    description: 'Debugger or sandbox detection.',
  },
  {
    id: 'mal-run-key',
    label: 'persistence',
    pattern: 'CurrentVersion\\\\(Run|RunOnce|Explorer\\\\Shell Folders)|schtasks|CreateService|\\\\Startup\\\\',
    severity: 'medium',
    description: 'Run keys, scheduled tasks, services or startup folders.',
  },
  {
    id: 'mal-c2-path',
    label: 'c2 pattern',
    pattern:
      '/(gate|panel|bot|cmd|task|beacon|checkin|c2)\\.php|/api/v\\d/(bot|client)s?/|User-Agent: Mozilla/4\\.0 \\(compatible; MSIE',
    severity: 'high',
    description: 'URL paths and headers typical of command-and-control traffic.',
  },
  {
    id: 'mal-encoded-ps',
    label: 'encoded powershell',
    pattern: 'powershell[^\\n]*(-enc|-e |-encodedcommand|frombase64string|-nop|-w hidden)',
    severity: 'high',
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
    description: 'File encryption APIs, shadow-copy deletion or ransom-note wording.',
  },
  {
    id: 'mal-recon',
    label: 'recon & credentials',
    pattern: 'GetAsyncKeyState|mimikatz|sekurlsa|lsass|CreateToolhelp32Snapshot|NetUserAdd|\\\\SAM\\b',
    severity: 'high',
    description: 'Keylogging, credential dumping or host enumeration.',
  },
]

/*
 * Windows event-log ruleset. Unlike the keyword rulesets these rules look at
 * the event id and its fields (or at groups of events, for brute force), so
 * the logic lives in utils/eventLogs.js; this list names them for the badges
 * and the Settings reference. Process command lines and PowerShell script
 * blocks also go through the command-line ruleset above.
 */
export const DEFAULT_EVENTLOG_RULES = [
  {
    id: 'evt-log-cleared',
    label: 'log cleared',
    severity: 'high',
    description: 'The Security audit log (1102) or another event log (104) was cleared: anti-forensics.',
  },
  {
    id: 'evt-audit-policy',
    label: 'audit policy changed',
    severity: 'medium',
    description: 'The audit policy was changed (4719); attackers turn auditing off to hide their tracks.',
  },
  {
    id: 'evt-service-user-path',
    label: 'service from user path',
    severity: 'high',
    description:
      'A service was installed (7045/4697) whose binary lives in a user-writable folder or runs a shell, as remote-execution tools and malware do.',
  },
  {
    id: 'evt-service-installed',
    label: 'service installed',
    severity: 'medium',
    description: 'A new service was installed (7045/4697): a common persistence and lateral-movement step.',
  },
  {
    id: 'evt-ps-suspicious',
    label: 'suspicious PowerShell',
    severity: 'high',
    description:
      'Encoded command, download cradle, Invoke-Expression, hidden window or AMSI tampering in a PowerShell script block, pipeline or command line.',
  },
  {
    id: 'evt-bruteforce',
    label: 'brute force',
    severity: 'high',
    description: '10 or more failed logons (4625) for the same account or from the same source within 10 minutes.',
  },
  {
    id: 'evt-logon-after-failures',
    label: 'logon after failures',
    severity: 'high',
    description:
      'A successful logon (4624) for an account or from a source with 5 or more failed logons in the previous 30 minutes.',
  },
  {
    id: 'evt-rdp-off-hours',
    label: 'RDP outside hours',
    severity: 'high',
    description: 'A remote desktop logon (4624 type 10, 21, 25, 1149) outside the configured business hours.',
  },
  {
    id: 'evt-account-created',
    label: 'account created',
    severity: 'medium',
    description: 'A local or domain account was created or enabled (4720/4722).',
  },
  {
    id: 'evt-admin-group',
    label: 'added to admins',
    severity: 'high',
    description:
      'An account was added to a privileged group (Administrators, Domain/Enterprise Admins, Remote Desktop Users, Backup Operators).',
  },
  {
    id: 'evt-defender',
    label: 'Defender alert',
    severity: 'high',
    description: 'Microsoft Defender detected malware (1116/1117) or real-time protection was turned off (5001).',
  },
  {
    id: 'evt-task-created',
    label: 'task created',
    severity: 'medium',
    description: 'A scheduled task was created (4698/106): a common persistence mechanism.',
  },
]

export const DEFAULT_BUSINESS_HOURS = {
  startHour: 8, // start of business hours (inclusive)
  endHour: 18, // end of business hours (exclusive)
  flagWeekends: true, // if true, weekends are always "outside hours"
}
