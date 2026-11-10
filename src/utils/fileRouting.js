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
 *   browser   { engine, source, browser? }  (Chromium files: the browser is asked)
 *   commands  { shell }
 *   endpoint  { }                           (category and source are asked)
 *   eventlogs { kind: 'evtx' | 'json' }
 *   malware   { }
 */

export const HEAD_BYTES = 512

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
}
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

const SHELL_FILES = [
  [/(^|[\\/])\.?bash_history$/i, 'bash'],
  [/(^|[\\/])\.?zsh_history$/i, 'zsh'],
  [/(^|[\\/])fish_history$/i, 'fish'],
  [/consolehost_history\.txt$/i, 'powershell'],
]

/**
 * @param {{ name: string, head: Uint8Array }} file name and first bytes
 * @returns {{ tab: string, label: string, params: object } | null}
 */
export function detectFileRoute({ name = '', head = new Uint8Array() }) {
  const base = String(name).split(/[\\/]/).pop()
  const lower = base.toLowerCase()

  if (startsWith(head, MAGIC.evtx)) return { tab: 'eventlogs', label: 'Windows event log', params: { kind: 'evtx' } }

  if (startsWith(head, MAGIC.sqlite)) {
    if (lower === 'places.sqlite')
      return {
        tab: 'browser',
        label: 'Firefox places database',
        params: { engine: 'firefox', source: 'places', browser: 'firefox' },
      }
    if (lower === 'history.db')
      return {
        tab: 'browser',
        label: 'Safari history',
        params: { engine: 'safari', source: 'history', browser: 'safari' },
      }
    if (lower === 'history')
      return { tab: 'browser', label: 'Chromium history', params: { engine: 'chromium', source: 'history' } }
    if (lower === 'shortcuts')
      return { tab: 'browser', label: 'Chromium shortcuts', params: { engine: 'chromium', source: 'shortcuts' } }
  }
  if (lower === 'bookmarks' && head[0] === 0x7b)
    return { tab: 'browser', label: 'Chromium bookmarks', params: { engine: 'chromium', source: 'bookmarks' } }
  if (lower === 'downloads.plist' || lower === 'bookmarks.plist') {
    const source = lower.startsWith('downloads') ? 'downloads' : 'bookmarks'
    return { tab: 'browser', label: `Safari ${source}`, params: { engine: 'safari', source, browser: 'safari' } }
  }

  for (const [pattern, shell] of SHELL_FILES) {
    if (pattern.test(base)) return { tab: 'commands', label: 'Shell history', params: { shell } }
  }

  if (lower.endsWith('.json') && text(head).includes('nik-eventlogs'))
    return { tab: 'eventlogs', label: 'Event logs (collection script)', params: { kind: 'json' } }

  if (startsWith(head, MAGIC.mz)) return { tab: 'malware', label: 'Windows executable (PE)', params: {} }
  if (startsWith(head, MAGIC.elf)) return { tab: 'malware', label: 'Linux executable (ELF)', params: {} }
  if (MACHO.some((sig) => startsWith(head, sig)))
    return { tab: 'malware', label: 'macOS executable (Mach-O)', params: {} }
  if (startsWith(head, MAGIC.pdf)) return { tab: 'malware', label: 'PDF document', params: {} }
  if (startsWith(head, MAGIC.ole) && !lower.endsWith('.msg'))
    return { tab: 'malware', label: 'Office document (OLE)', params: {} }
  if (ACTIVE_EXTENSIONS.test(lower)) return { tab: 'malware', label: 'Script, archive or active document', params: {} }

  if (lower.endsWith('.csv')) return { tab: 'endpoint', label: 'Tool export (CSV)', params: {} }
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
