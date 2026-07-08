/*
 * ============================================================================
 * PARSING DISPATCHER — single entry point for uploaded files
 * ============================================================================
 *
 * `parseBrowserSource(file, engine, source)` automatically recognizes the
 * format (SQLite / JSON / CSV) and returns the ARTIFACTS PRODUCED by the source
 * (a source can produce more than one: Chrome's History contains both the
 * browsing history and the downloads; Firefox's places.sqlite contains
 * history, bookmarks and downloads).
 *
 * Return: { produced: { history?, downloads?, bookmarks?, shortcuts? }, format }
 *
 * The JSON/CSV field mapping is deliberately "lenient": forensic tools use
 * different column names, so for each field we accept several aliases.
 */

import Papa from 'papaparse'
import { generateId } from '../utils/id.js'
import { anyToMs, webkitToMs } from '../utils/time.js'
import { parseSqliteSource, fileNameFromPath } from './sqliteParser.js'

/* ------------------------------------------------------------------------ */
/* Format recognition                                                         */
/* ------------------------------------------------------------------------ */

// Header of a SQLite file: the string "SQLite format 3" (15 characters)
// followed by a NULL byte (0x00), for a total of 16 bytes.
const SQLITE_MAGIC = 'SQLite format 3'

/** True if the buffer starts with the SQLite magic number (15 chars + 0x00). */
export function isSqliteBuffer(arrayBuffer) {
  if (!arrayBuffer || arrayBuffer.byteLength < 16) return false
  const bytes = new Uint8Array(arrayBuffer, 0, 16)
  for (let i = 0; i < SQLITE_MAGIC.length; i++) {
    if (bytes[i] !== SQLITE_MAGIC.charCodeAt(i)) return false
  }
  return bytes[15] === 0x00 // the 16th byte must be the null terminator
}

/* ------------------------------------------------------------------------ */
/* Lenient mapping helpers                                                    */
/* ------------------------------------------------------------------------ */

function normalizeRow(row) {
  const normalized = {}
  for (const [key, value] of Object.entries(row ?? {})) {
    normalized[String(key).trim().toLowerCase()] = value
  }
  return normalized
}

function pick(normalizedRow, aliases) {
  for (const alias of aliases) {
    const value = normalizedRow[alias]
    if (value !== undefined && value !== null && value !== '') return value
  }
  return null
}

const asText = (value) => (value === null || value === undefined ? '' : String(value).trim())

function asCount(value, fallback = 0) {
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : fallback
}

function extractRowsArray(parsed, containerKeys) {
  if (Array.isArray(parsed)) return parsed
  if (parsed && typeof parsed === 'object') {
    for (const key of containerKeys) {
      if (Array.isArray(parsed[key])) return parsed[key]
    }
  }
  return null
}

/* ------------------------------------------------------------------------ */
/* HISTORY mapping                                                            */
/* ------------------------------------------------------------------------ */

// Aliases keep both English and Italian column names so exports from
// localized forensic tools are still recognized.
const HISTORY_ALIASES = {
  url: ['url'],
  title: ['title', 'titolo'],
  visitCount: ['visit_count', 'visitcount', 'visits'],
  visitTime: ['visit_time', 'visittime', 'data_leggibile', 'date', 'timestamp', 'data'],
}

function mapHistoryRows(rows) {
  const entries = []
  for (const raw of rows) {
    const row = normalizeRow(raw)
    const url = asText(pick(row, HISTORY_ALIASES.url))
    if (!url) continue
    entries.push({
      id: generateId(),
      url,
      title: asText(pick(row, HISTORY_ALIASES.title)),
      visitCount: asCount(pick(row, HISTORY_ALIASES.visitCount)),
      visitTime: anyToMs(pick(row, HISTORY_ALIASES.visitTime)),
      visitId: null,
      fromVisitId: null,
      isRedirect: false,
    })
  }
  return entries
}

/* ------------------------------------------------------------------------ */
/* BOOKMARKS mapping (native Chrome JSON + flat export)                       */
/* ------------------------------------------------------------------------ */

const CHROME_ROOT_LABELS = {
  bookmark_bar: 'Bookmarks bar',
  other: 'Other bookmarks',
  synced: 'Synced bookmarks',
}

function walkBookmarkNode(node, folderPath, out) {
  if (!node || typeof node !== 'object') return
  if (node.type === 'url' && node.url) {
    out.push({
      id: generateId(),
      name: asText(node.name) || '(unnamed)',
      url: node.url,
      folder: folderPath || null,
      dateAdded: webkitToMs(Number(node.date_added)),
    })
    return
  }
  if (Array.isArray(node.children)) {
    const name = asText(node.name)
    const path = name ? (folderPath ? `${folderPath} > ${name}` : name) : folderPath
    for (const child of node.children) walkBookmarkNode(child, path, out)
  }
}

function mapChromeBookmarks(parsed) {
  const out = []
  for (const [rootKey, rootNode] of Object.entries(parsed.roots)) {
    if (!rootNode || typeof rootNode !== 'object') continue
    const rootLabel = CHROME_ROOT_LABELS[rootKey] ?? asText(rootNode.name) ?? rootKey
    if (Array.isArray(rootNode.children)) {
      for (const child of rootNode.children) walkBookmarkNode(child, rootLabel, out)
    }
  }
  return out
}

// Aliases keep both English and Italian column names (see HISTORY_ALIASES).
const BOOKMARK_ALIASES = {
  name: ['name', 'nome', 'title', 'titolo'],
  url: ['url'],
  folder: ['folder', 'cartella'],
  dateAdded: ['date_added', 'dateadded', 'data', 'date', 'timestamp'],
}

function mapBookmarkRows(rows) {
  const entries = []
  for (const raw of rows) {
    const row = normalizeRow(raw)
    const url = asText(pick(row, BOOKMARK_ALIASES.url))
    if (!url) continue
    const folder = asText(pick(row, BOOKMARK_ALIASES.folder))
    entries.push({
      id: generateId(),
      name: asText(pick(row, BOOKMARK_ALIASES.name)) || '(unnamed)',
      url,
      folder: folder || null,
      dateAdded: anyToMs(pick(row, BOOKMARK_ALIASES.dateAdded)),
    })
  }
  return entries
}

/* ------------------------------------------------------------------------ */
/* SHORTCUTS mapping                                                          */
/* ------------------------------------------------------------------------ */

// Aliases keep both English and Italian column names (see HISTORY_ALIASES).
const SHORTCUT_ALIASES = {
  text: ['text', 'testo'],
  url: ['url'],
  title: ['contents', 'title', 'titolo'],
  lastAccessTime: ['last_access_time', 'lastaccesstime'],
  hits: ['number_of_hits', 'hits'],
}

function mapShortcutRows(rows) {
  const entries = []
  for (const raw of rows) {
    const row = normalizeRow(raw)
    const url = asText(pick(row, SHORTCUT_ALIASES.url))
    if (!url) continue
    entries.push({
      id: generateId(),
      text: asText(pick(row, SHORTCUT_ALIASES.text)),
      url,
      title: asText(pick(row, SHORTCUT_ALIASES.title)),
      lastAccessTime: anyToMs(pick(row, SHORTCUT_ALIASES.lastAccessTime)),
      hits: asCount(pick(row, SHORTCUT_ALIASES.hits)),
    })
  }
  return entries
}

/* ------------------------------------------------------------------------ */
/* DOWNLOADS mapping                                                          */
/* ------------------------------------------------------------------------ */

// Aliases keep both English and Italian column names (see HISTORY_ALIASES).
const DOWNLOAD_ALIASES = {
  fileName: ['file_name', 'filename', 'nome_file', 'name', 'nome', 'target_path', 'file'],
  url: ['url', 'source', 'source_url', 'from', 'download_url'],
  referrer: ['referrer', 'referer', 'tab_url', 'site', 'sito'],
  startTime: ['start_time', 'starttime', 'date', 'data', 'timestamp', 'downloaded_at'],
  totalBytes: ['total_bytes', 'size', 'bytes', 'dimensione'],
}

function mapDownloadRows(rows) {
  const entries = []
  for (const raw of rows) {
    const row = normalizeRow(raw)
    const rawName = asText(pick(row, DOWNLOAD_ALIASES.fileName))
    const url = asText(pick(row, DOWNLOAD_ALIASES.url))
    const referrer = asText(pick(row, DOWNLOAD_ALIASES.referrer))
    if (!rawName && !url) continue // at least a file name or URL is required
    entries.push({
      id: generateId(),
      fileName: fileNameFromPath(rawName) || rawName || fileNameFromPath(url) || '(unknown)',
      targetPath: rawName,
      url,
      referrer: referrer || url,
      startTime: anyToMs(pick(row, DOWNLOAD_ALIASES.startTime)),
      endTime: null,
      totalBytes: asCount(pick(row, DOWNLOAD_ALIASES.totalBytes)),
      receivedBytes: 0,
      mimeType: '',
      state: 1,
    })
  }
  return entries
}

/* ------------------------------------------------------------------------ */
/* Mapping a text document onto the source                                    */
/* ------------------------------------------------------------------------ */

// "Primary" artifact produced by a source for text imports (JSON/CSV): the
// order in `produces` puts the main artifact first.
function primaryArtifact(source) {
  return source.produces?.[0] ?? 'history'
}

function mapTextDocument(source, parsedJson, csvRows) {
  const kind = primaryArtifact(source)

  // Native Chrome bookmarks: recognizable by the "roots" key.
  if (
    source.produces?.includes('bookmarks') &&
    parsedJson &&
    typeof parsedJson === 'object' &&
    !Array.isArray(parsedJson) &&
    parsedJson.roots &&
    typeof parsedJson.roots === 'object'
  ) {
    return { bookmarks: mapChromeBookmarks(parsedJson) }
  }

  // Extract the rows array (from a container JSON or an already-parsed CSV).
  const rows =
    csvRows ??
    extractRowsArray(parsedJson, ['history', 'bookmarks', 'shortcuts', 'downloads', 'entries', 'rows', 'data', 'items', 'records'])

  if (!Array.isArray(rows)) {
    throw new Error(
      'Unrecognized JSON format: expected an array of objects (export from forensic tools).',
    )
  }

  if (kind === 'bookmarks') return { bookmarks: mapBookmarkRows(rows) }
  if (kind === 'shortcuts') return { shortcuts: mapShortcutRows(rows) }
  if (kind === 'downloads') return { downloads: mapDownloadRows(rows) }
  return { history: mapHistoryRows(rows) }
}

/* ------------------------------------------------------------------------ */
/* Main API                                                                   */
/* ------------------------------------------------------------------------ */

/**
 * Parses a file uploaded for a browser source.
 * @param {File} file selected/dragged file
 * @param {'chromium'|'firefox'} engine browser engine
 * @param {object} source source definition (from config/browsers.js): { key, produces, label }
 * @returns {Promise<{ produced: object, format: 'sqlite'|'json'|'csv' }>}
 * @throws {Error} a clear message understandable by the analyst
 */
export async function parseBrowserSource(file, engine, source) {
  if (!file) throw new Error('No file selected.')
  const buffer = await file.arrayBuffer()
  if (buffer.byteLength === 0) throw new Error('The file is empty.')

  /* --- 1. Binary SQLite file --- */
  if (isSqliteBuffer(buffer)) {
    if (engine === 'chromium' && source.key === 'bookmarks') {
      throw new Error(
        'This is a SQLite database, but Chrome Bookmarks are a JSON file: select the "Bookmarks" file (without extension) from the profile folder.',
      )
    }
    const produced = await parseSqliteSource(buffer, engine, source.key)
    const totalRows = Object.values(produced).reduce(
      (sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0),
      0,
    )
    if (totalRows === 0) {
      throw new Error('The database was read but contains no entries for this source.')
    }
    return { produced, format: 'sqlite' }
  }

  /* --- 2. Text file: JSON or CSV --- */
  const text = new TextDecoder('utf-8').decode(buffer)

  let parsedJson = null
  let isJson = false
  try {
    parsedJson = JSON.parse(text)
    isJson = true
  } catch {
    /* not JSON: try CSV */
  }

  let produced
  let format
  if (isJson) {
    produced = mapTextDocument(source, parsedJson, null)
    format = 'json'
  } else {
    const result = Papa.parse(text, { header: true, skipEmptyLines: true })
    if (!Array.isArray(result.data) || result.data.length === 0) {
      throw new Error(
        'Unrecognized format: the file is neither SQLite, JSON, nor a CSV with a column header.',
      )
    }
    produced = mapTextDocument(source, null, result.data)
    format = 'csv'
  }

  const totalRows = Object.values(produced).reduce(
    (sum, arr) => sum + (Array.isArray(arr) ? arr.length : 0),
    0,
  )
  if (totalRows === 0) {
    throw new Error(
      `No valid entries found in the file for "${source.label}": check the fields (at least "url").`,
    )
  }
  return { produced, format }
}
