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
