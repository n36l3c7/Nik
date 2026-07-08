/*
 * ============================================================================
 * ENDPOINT ARTIFACT PARSERS — existing files (in-browser) + tool CSV/JSON
 * ============================================================================
 *
 * Each endpoint source is imported by one of two mechanisms, declared on the
 * source (config/artifacts.js):
 *
 *   - mode 'file'   → the analyst uploads the EXISTING raw file from the host
 *                     and it is parsed here, in the browser, with a dedicated
 *                     custom parser (no third-party tools). Text/XML/log/SQLite.
 *   - mode 'script' → the analyst runs a fully-custom native script (shown in
 *                     the tab), which writes a CSV; that CSV is imported with
 *                     the lenient CSV/JSON mapper.
 *
 * Every parser returns records shaped by the category's fields:
 *   { records: [{ id, time, fields: {...} }], format }
 */

import Papa from 'papaparse'
import { generateId } from '../utils/id.js'
import { anyToMs } from '../utils/time.js'

const asText = (value) => (value === null || value === undefined ? '' : String(value).trim())

function baseName(path) {
  const parts = String(path ?? '').split(/[\\/]/).filter(Boolean)
  return parts.length ? parts[parts.length - 1] : String(path ?? '')
}

/* ------------------------------------------------------------------------ */
/* Lenient CSV / JSON (script output, or any tool export)                     */
/* ------------------------------------------------------------------------ */

function normalizeRow(row) {
  const out = {}
  for (const [key, value] of Object.entries(row ?? {})) {
    out[String(key).trim().toLowerCase().replace(/[\s_-]+/g, '')] = value
  }
  return out
}

function pick(normalizedRow, aliases) {
  for (const alias of aliases) {
    const key = alias.toLowerCase().replace(/[\s_-]+/g, '')
    const value = normalizedRow[key]
    if (value !== undefined && value !== null && String(value).trim() !== '') return value
  }
  return null
}

function mapDelimitedRows(rows, category) {
  const records = []
  for (const raw of rows) {
    if (!raw || typeof raw !== 'object') continue
    const row = normalizeRow(raw)
    const fields = {}
    for (const [fieldKey, aliases] of Object.entries(category.fields)) {
      fields[fieldKey] = asText(pick(row, aliases))
    }
    if (!fields[category.primaryField]) continue
    records.push({ id: generateId(), time: anyToMs(pick(row, category.timeAliases)), fields })
  }
  return records
}

function parseCsvJson(text, category) {
  const trimmed = text.trimStart()
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    let parsed
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = null
    }
    const rows = Array.isArray(parsed)
      ? parsed
      : Array.isArray(parsed?.records)
        ? parsed.records
        : Array.isArray(parsed?.rows)
          ? parsed.rows
          : Array.isArray(parsed?.data)
            ? parsed.data
            : null
    if (rows) {
      const records = mapDelimitedRows(rows, category)
      if (records.length > 0) return { records, format: 'json' }
    }
  }
  const result = Papa.parse(text.trim(), { header: true, skipEmptyLines: true })
  if (Array.isArray(result.data) && result.data.length > 0) {
    const records = mapDelimitedRows(result.data, category)
    if (records.length > 0) return { records, format: 'csv' }
  }
  throw new Error(
    `Could not map any records: a column for "${category.primaryField}" is required ` +
      '(CSV with a header row, or a JSON array).',
  )
}

/* ------------------------------------------------------------------------ */
/* File-mode parsers (existing raw files → records)                           */
/* ------------------------------------------------------------------------ */

/** GTK `recently-used.xbel` (File Access) — an XML list of file:// bookmarks. */
function parseXbel(text, category) {
  const doc = new DOMParser().parseFromString(text, 'application/xml')
  if (doc.querySelector('parsererror')) throw new Error('Not a valid XBEL/XML file.')
  const records = []
  for (const b of doc.querySelectorAll('bookmark')) {
    const href = b.getAttribute('href') || ''
    if (!href) continue
    let target = href
    try {
      target = decodeURIComponent(href.replace(/^file:\/*/i, '/'))
    } catch {
      /* keep raw href */
    }
    const when = b.getAttribute('modified') || b.getAttribute('visited') || b.getAttribute('added')
    records.push({
      id: generateId(),
      time: anyToMs(when),
      fields: { name: baseName(target), target, kind: 'recently-used' },
    })
  }
  if (records.length === 0) throw new Error('No bookmarks found in the XBEL file.')
  return { records, format: 'xbel' }
}

/**
 * Plain-text config files (authorized_keys / cron / rc). Each non-comment,
 * non-empty line becomes one record; the record's kind is fixed by the source.
 */
function parseConfigLines(text, category, source) {
  const kind = source.recordKind || 'config'
  const label = source.recordName || kind
  const records = []
  let lineNo = 0
  for (const raw of text.split('\n')) {
    lineNo += 1
    const line = raw.replace(/\r$/, '').trim()
    if (!line || line.startsWith('#')) continue
    records.push({
      id: generateId(),
      time: null,
      fields: { name: label, kind, command: line, location: source.name },
    })
  }
  if (records.length === 0) throw new Error('No entries found (only comments or blank lines).')
  return { records, format: 'text' }
}

/** A macOS LaunchAgent/LaunchDaemon XML plist (Persistence). */
function parsePlist(text, category, source) {
  const doc = new DOMParser().parseFromString(text, 'application/xml')
  if (doc.querySelector('parsererror')) {
    throw new Error('Not a valid XML plist (binary plists must be converted with `plutil -convert xml1`).')
  }
  const dict = doc.querySelector('plist > dict')
  if (!dict) throw new Error('No <dict> found in the plist.')
  // Walk the top-level dict as alternating <key>/<value> siblings.
  const kids = Array.from(dict.children)
  const map = {}
  for (let i = 0; i < kids.length - 1; i += 2) {
    if (kids[i].tagName !== 'key') continue
    map[kids[i].textContent.trim()] = kids[i + 1]
  }
  const label = map.Label?.textContent?.trim() || baseName(source.name)
  let command = ''
  if (map.ProgramArguments?.tagName === 'array') {
    command = Array.from(map.ProgramArguments.querySelectorAll('string'))
      .map((s) => s.textContent.trim())
      .join(' ')
  } else if (map.Program) {
    command = map.Program.textContent.trim()
  }
  return {
    records: [
      {
        id: generateId(),
        time: null,
        fields: { name: label, kind: 'LaunchAgent', command, location: source.name },
      },
    ],
    format: 'plist',
  }
}

/** Windows `setupapi.dev.log` (USB) — device-install sections with timestamps. */
function parseSetupapi(text, category) {
  const records = []
  let pendingDevice = null
  for (const raw of text.split('\n')) {
    const line = raw.replace(/\r$/, '')
    const header = line.match(/\[Device Install[^\]]*-\s*(USBSTOR\\[^\]]+|USB\\VID_[^\]]+)\]/i)
    if (header) {
      pendingDevice = header[1].trim()
      continue
    }
    if (pendingDevice) {
      const ts = line.match(/Section start\s+([\d/]+\s+[\d:.]+)/)
      const serial = pendingDevice.split('\\').pop() || ''
      records.push({
        id: generateId(),
        time: ts ? anyToMs(ts[1].replace(/\//g, '-')) : null,
        fields: { device: pendingDevice, serial, vendor: '', connection: 'setupapi' },
      })
      pendingDevice = null
    }
  }
  if (records.length === 0) throw new Error('No USB device-install sections found in the log.')
  return { records, format: 'setupapi' }
}

/** macOS `knowledgeC.db` (Program Execution) — app-usage rows via sql.js. */
async function parseKnowledgeC(arrayBuffer, category) {
  // Lazy: pulls in sql.js (WASM) only when a KnowledgeC file is actually parsed.
  const { getSql } = await import('./sqliteParser.js')
  const SQL = await getSql()
  let db
  try {
    db = new SQL.Database(new Uint8Array(arrayBuffer))
  } catch {
    throw new Error('Unable to open the file as a SQLite database.')
  }
  try {
    const res = db.exec(
      "SELECT ZVALUESTRING AS app, ZSTARTDATE AS start FROM ZOBJECT " +
        "WHERE ZSTREAMNAME = '/app/usage' AND ZVALUESTRING IS NOT NULL ORDER BY ZSTARTDATE DESC",
    )
    if (!res.length) throw new Error('No /app/usage rows found (is this a knowledgeC.db?).')
    const { columns, values } = res[0]
    const ai = columns.indexOf('app')
    const si = columns.indexOf('start')
    // ZSTARTDATE is Mac absolute time: seconds since 2001-01-01 UTC.
    const MAC_EPOCH = 978307200
    const records = values.map((row) => ({
      id: generateId(),
      time: Number.isFinite(row[si]) ? Math.round((row[si] + MAC_EPOCH) * 1000) : null,
      fields: { name: row[ai], path: row[ai], runCount: '', source: 'KnowledgeC' },
    }))
    return { records, format: 'sqlite' }
  } finally {
    db.close()
  }
}

/* ------------------------------------------------------------------------ */
/* Dispatch                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Imports a file for a given category source.
 * @param {File} file
 * @param {object} category registry entry (config/artifacts.js)
 * @param {object} source the source within the category being imported
 * @returns {Promise<{ records: Array, format: string }>}
 */
export async function parseArtifactImport(file, category, source) {
  // SQLite parser needs the raw bytes; everything else is text.
  if (source.parser === 'knowledgec') {
    return parseKnowledgeC(await file.arrayBuffer(), category)
  }

  const text = await file.text()
  if (!text.trim()) throw new Error('The file is empty.')

  switch (source.parser) {
    case 'xbel':
      return parseXbel(text, category)
    case 'configlines':
      return parseConfigLines(text, category, source)
    case 'plist':
      return parsePlist(text, category, source)
    case 'setupapi':
      return parseSetupapi(text, category)
    default:
      // Script-mode sources (and any tool export) go through CSV/JSON.
      return parseCsvJson(text, category)
  }
}
