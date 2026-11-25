/*
 * ============================================================================
 * FILE ROUTING — where a file dropped anywhere in the app belongs
 * ============================================================================
 *
 * detectFileRoute() looks at a file's name and its first bytes (never its
 * extension alone for executables) and proposes the tab and the source that
 * import it. The drop dialog shows the proposal and lets the analyst change
 * it; a file Nik cannot place gets no proposal and the dialog asks.
 *
 * Route: { tab, label, params } where params depend on the tab:
 *   host      { }                           (host evidence: the server recognises the file, or says why not)
 *   browser   { engine, source, browser? }  (Chromium files: the browser is asked; chosen by hand in the dialog)
 *   commands  { shell }                     (the same)
 *   endpoint  { }                           (category and source are asked; the same)
 *   eventlogs { kind: 'evtx' | 'json' }     (the same)
 *   malware   { }
 *   mail      { }                           (.eml, Outlook .msg)
 *   network   { }                           (pcap, pcapng)
 */

export const HEAD_BYTES = 512

/** The tab of a file of host evidence the app does not place by guessing: `kind: "auto"` asks the server. */
export const HOST_TAB = 'host'
const HOST = (label) => ({ tab: HOST_TAB, label, params: {} })

const text = (bytes) => new TextDecoder('latin1').decode(bytes)

const startsWith = (bytes, signature) => signature.every((byte, i) => bytes[i] === byte)

const MAGIC = {
  mz: [0x4d, 0x5a],
  elf: [0x7f, 0x45, 0x4c, 0x46],
  pdf: [0x25, 0x50, 0x44, 0x46],
  ole: [0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1],
  zip: [0x50, 0x4b, 0x03, 0x04],
  sqlite: [...'SQLite format 3'].map((c) => c.charCodeAt(0)).concat(0),
  evtx: [...'ElfFile'].map((c) => c.charCodeAt(0)).concat(0),
  bplist: [...'bplist00'].map((c) => c.charCodeAt(0)),
  pcapng: [0x0a, 0x0d, 0x0d, 0x0a],
}
// pcap in both byte orders, microsecond and nanosecond resolution.
const PCAP = [
  [0xd4, 0xc3, 0xb2, 0xa1],
  [0xa1, 0xb2, 0xc3, 0xd4],
  [0x4d, 0x3c, 0xb2, 0xa1],
  [0xa1, 0xb2, 0x3c, 0x4d],
]
const MACHO = [
  [0xfe, 0xed, 0xfa, 0xce],
  [0xfe, 0xed, 0xfa, 0xcf],
  [0xce, 0xfa, 0xed, 0xfe],
  [0xcf, 0xfa, 0xed, 0xfe],
  [0xca, 0xfe, 0xba, 0xbe],
]

// Files that run or carry code even without an executable header.
const ACTIVE_EXTENSIONS =
  /\.(js|jse|vbs|vbe|wsf|hta|ps1|psm1|bat|cmd|scr|lnk|iso|img|vhd|vhdx|jar|apk|dmg|pkg|msi|one|chm|cpl|docm|xlsm|pptm|dotm|rtf|7z|rar|zip|gz|tgz)$/i

// An RFC 5322 message saved without the .eml extension starts with headers.
const MAIL_HEADERS =
  /^(?:received|return-path|delivered-to|x-[\w-]+|from|message-id|mime-version|date|subject|to|arc-seal|dkim-signature|authentication-results):/i

const SHELL_FILES = [
  [/(^|[\\/])\.?bash_history$/i, 'bash'],
  [/(^|[\\/])\.?zsh_history$/i, 'zsh'],
  [/(^|[\\/])fish_history$/i, 'fish'],
  [/consolehost_history\.txt$/i, 'powershell'],
]

// What only host evidence is called: a hive, a prefetch file, a $MFT, the logs of Linux, a disk image to be turned
// into something Nik reads (the server answers with how). A zip and a shortcut are NOT here: a zip is how samples
// arrive (password "infected") and a shortcut is a common phishing payload, so anywhere outside a page of host
// evidence they stay samples. A collection is imported on purpose ("Import a collection…", the Collections block
// of the Evidence page, or "Host evidence (Nik recognises it)" in the Add-a-file dialog).
const HOST_NAMES = [
  [/(^|[\\/])(\$?mft|\$j|\$usnjrnl_\$j|c_\$extend_\$usnjrnl_\$j)$/i, '$MFT or $J of an NTFS volume'],
  [/(^|[\\/])ntuser\.dat$/i, 'Registry hive (NTUSER.DAT)'],
  [/\.hve$/i, 'Registry hive'],
  [/(^|[\\/])(system|software|sam|security|default|usrclass\.dat)$/i, 'Registry hive'],
  [/(^|[\\/])srudb\.dat$/i, 'SRUM database (SRUDB.dat)'],
  [/\.pf$/i, 'Prefetch file'],
  [/\.(automatic|custom)destinations-ms$/i, 'Jump list'],
  [/(^|[\\/])(auth\.log|secure|audit\.log)(\.\d+)?$/i, 'Linux log'],
  [/\.(vhd|vhdx|vmdk|e01|aff4?|dd|raw|plaso)$/i, 'Disk image or forensic container'],
  [/(^|[\\/])plaso\.(jsonl|csv)$/i, 'Plaso export (psort)'],
]

/**
 * @param {{ name: string, head: Uint8Array }} file name and first bytes
 * @returns {{ tab: string, label: string, params: object } | null}
 */
export function detectFileRoute({ name = '', head = new Uint8Array() }) {
  const base = String(name).split(/[\\/]/).pop()
  const lower = base.toLowerCase()

  if (startsWith(head, MAGIC.evtx)) return HOST('Windows event log')

  if (startsWith(head, MAGIC.sqlite)) {
    if (lower === 'places.sqlite') return HOST('Firefox places database')
    if (lower === 'history.db') return HOST('Safari history')
    if (lower === 'history') return HOST('Chromium history')
    if (lower === 'shortcuts') return HOST('Chromium shortcuts')
  }
  if (lower === 'bookmarks' && head[0] === 0x7b) return HOST('Chromium bookmarks')
  if (lower === 'downloads.plist' || lower === 'bookmarks.plist') {
    return HOST(`Safari ${lower.startsWith('downloads') ? 'downloads' : 'bookmarks'}`)
  }

  for (const [pattern] of SHELL_FILES) {
    if (pattern.test(base)) return HOST('Shell history')
  }

  if (startsWith(head, MAGIC.pcapng)) return { tab: 'network', label: 'Packet capture (pcapng)', params: {} }
  if (PCAP.some((sig) => startsWith(head, sig))) return { tab: 'network', label: 'Packet capture (pcap)', params: {} }
  if (/\.(pcap|pcapng|cap)(\.gz)?$/.test(lower) && startsWith(head, [0x1f, 0x8b]))
    return { tab: 'network', label: 'Packet capture (gzip)', params: {} }

  if (startsWith(head, MAGIC.ole) && lower.endsWith('.msg'))
    return { tab: 'mail', label: 'Outlook message (.msg)', params: {} }
  if (lower.endsWith('.eml') || (!lower.includes('.') && MAIL_HEADERS.test(text(head).trimStart())))
    return { tab: 'mail', label: 'E-mail (.eml)', params: {} }

  if (lower.endsWith('.json') && text(head).includes('nik-eventlogs')) return HOST('Event logs (collection script)')

  // Host evidence by its name, before the executables and the archives.
  for (const [pattern, label] of HOST_NAMES) {
    if (pattern.test(base) && !startsWith(head, MAGIC.mz) && !startsWith(head, MAGIC.elf)) return HOST(label)
  }

  if (startsWith(head, MAGIC.mz)) return { tab: 'malware', label: 'Windows executable (PE)', params: {} }
  if (startsWith(head, MAGIC.elf)) return { tab: 'malware', label: 'Linux executable (ELF)', params: {} }
  if (MACHO.some((sig) => startsWith(head, sig)))
    return { tab: 'malware', label: 'macOS executable (Mach-O)', params: {} }
  if (startsWith(head, MAGIC.pdf)) return { tab: 'malware', label: 'PDF document', params: {} }
  if (startsWith(head, MAGIC.ole) && !lower.endsWith('.msg'))
    return { tab: 'malware', label: 'Office document (OLE)', params: {} }
  if (ACTIVE_EXTENSIONS.test(lower)) return { tab: 'malware', label: 'Script, archive or active document', params: {} }

  if (lower.endsWith('.csv')) return HOST('Tool export (CSV)')
  return null
}

/** Read the first bytes of a File/Blob for detectFileRoute(). */
export async function readHead(file, length = HEAD_BYTES) {
  try {
    return new Uint8Array(await file.slice(0, length).arrayBuffer())
  } catch {
    return new Uint8Array()
  }
}
