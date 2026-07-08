/*
 * ============================================================================
 * CLIENT-SIDE SQLITE PARSER — native browser artifacts
 * ============================================================================
 *
 * Two schema families:
 *  - CHROMIUM (Chrome/Edge/Brave/Opera): `History` file (urls/visits/downloads),
 *    `Shortcuts` (omni_box_shortcuts). Timestamps in "WebKit time" (µs since 1601).
 *  - FIREFOX: single `places.sqlite` file (moz_places/moz_historyvisits/
 *    moz_bookmarks/moz_annos). Timestamps in "PRTime" (µs since 1970).
 *
 * sql.js (SQLite in WebAssembly) opens the databases ENTIRELY in the browser:
 * no byte leaves the analyst's machine. The module and the .wasm are loaded
 * LAZILY (only on the first parse).
 */

import wasmUrl from 'sql.js/dist/sql-wasm.wasm?url'
import { webkitToMs, firefoxToMs } from '../utils/time.js'
import { generateId } from '../utils/id.js'

let sqlPromise = null

/** Lazily initializes sql.js and always returns the same instance. */
export async function getSql() {
  if (!sqlPromise) {
    sqlPromise = import('sql.js').then((m) =>
      (m.default ?? m)({ locateFile: () => wasmUrl }),
    )
  }
  return sqlPromise
}

/** Opens an ArrayBuffer as an in-memory SQLite database. */
async function openDatabase(arrayBuffer) {
  const SQL = await getSql()
  try {
    return new SQL.Database(new Uint8Array(arrayBuffer))
  } catch {
    throw new Error(
      'Unable to open the file as a SQLite database: it may be corrupted or truncated.',
    )
  }
}

/** True if the database contains ALL the given tables. */
function hasTables(db, tableNames) {
  const placeholders = tableNames.map(() => '?').join(', ')
  const stmt = db.prepare(
    `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN (${placeholders})`,
  )
  try {
    stmt.bind(tableNames)
    stmt.step()
    return stmt.get()[0] === tableNames.length
  } finally {
    stmt.free()
  }
}

/** Runs a query and returns the rows as an array of {column: value} objects. */
function queryRows(db, sql) {
  const result = db.exec(sql)
  if (!result.length) return []
  const { columns, values } = result[0]
  return values.map((row) =>
    Object.fromEntries(columns.map((col, i) => [col, row[i]])),
  )
}

/** Like queryRows but does not throw if the query fails (missing table/column). */
function tryQueryRows(db, sql) {
  try {
    return queryRows(db, sql)
  } catch {
    return []
  }
}

/* ------------------------------------------------------------------------ */
/* Common helpers                                                             */
/* ------------------------------------------------------------------------ */

// Redirect bits in Chromium's `transition` column.
const CHROMIUM_REDIRECT_MASK = 0x40000000 | 0x80000000 // CLIENT | SERVER redirect

/** Extracts the file name from a Windows/Unix path or from a file:// URI. */
export function fileNameFromPath(path) {
  if (!path) return ''
  let value = String(path)
  if (value.startsWith('file:')) {
    try {
      value = decodeURIComponent(value.replace(/^file:\/*/i, ''))
    } catch {
      /* leave the raw value */
    }
  }
  value = value.split(/[?#]/)[0] // remove any query/fragment
  const parts = value.split(/[\\/]/).filter(Boolean)
  return parts.length ? parts[parts.length - 1] : value
}

/* ======================================================================== */
/* CHROMIUM                                                                  */
/* ======================================================================== */

/**
 * Parses the browsing history from a Chromium `History` file.
 * Each row of `visits` is a visit; the JOIN with `urls` reconstructs the
 * timeline. The visit id, the origin visit (`from_visit`) and the redirect
 * flag are also extracted, useful to reconstruct the chains.
 */
export function parseChromiumHistory(db) {
  const rows = queryRows(
    db,
    `SELECT u.url AS url, u.title AS title, u.visit_count AS visit_count,
            v.id AS visit_id, v.from_visit AS from_visit,
            v.transition AS transition, v.visit_time AS visit_time
     FROM urls AS u INNER JOIN visits AS v ON u.id = v.url
     ORDER BY v.visit_time DESC`,
  )
  return rows.map((row) => {
    const transition = Number(row.transition) || 0
    return {
      id: generateId(),
      url: row.url ?? '',
      title: row.title ?? '',
      visitCount: row.visit_count ?? 0,
      visitTime: webkitToMs(row.visit_time),
      visitId: row.visit_id ?? null,
      fromVisitId: row.from_visit || null, // 0 = no origin
      isRedirect: (transition & CHROMIUM_REDIRECT_MASK) !== 0,
    }
  })
}

/**
 * Parses the downloads from a Chromium `History` file (tables `downloads` and
 * `downloads_url_chain`). Uses SELECT * to tolerate schema differences
 * between browser versions.
 */
export function parseChromiumDownloads(db) {
  if (!hasTables(db, ['downloads'])) return []

  // URLs of the download redirect chain: the last one is the file URL.
  const chainByDownload = new Map()
  for (const row of tryQueryRows(
    db,
    'SELECT id, url, chain_index FROM downloads_url_chain ORDER BY id, chain_index',
  )) {
    chainByDownload.set(row.id, row.url) // the last one overwrites → highest index
  }

  const rows = tryQueryRows(db, 'SELECT * FROM downloads ORDER BY start_time DESC')
  return rows.map((row) => {
    const targetPath = row.target_path ?? row.current_path ?? ''
    const fileUrl = chainByDownload.get(row.id) ?? row.tab_url ?? ''
    // "from which site": referrer or the page that started the download, with fallback.
    const site = row.referrer || row.tab_url || row.site_url || fileUrl || ''
    return {
      id: generateId(),
      fileName: fileNameFromPath(targetPath) || fileNameFromPath(fileUrl) || '(unknown)',
      targetPath,
      url: fileUrl, // direct file URL
      referrer: site, // originating page/site
      startTime: webkitToMs(row.start_time),
      endTime: webkitToMs(row.end_time),
      totalBytes: Number(row.total_bytes) || 0,
      receivedBytes: Number(row.received_bytes) || 0,
      mimeType: row.mime_type ?? '',
      state: Number(row.state) || 0,
    }
  })
}

/** Parses the Shortcuts (omnibox) from a Chromium `Shortcuts` file. */
export function parseChromiumShortcuts(db) {
  if (!hasTables(db, ['omni_box_shortcuts'])) {
    throw new Error(
      'The database does not contain the expected table (omni_box_shortcuts): it does not look like a Chrome Shortcuts file.',
    )
  }
  const rows = queryRows(
    db,
    `SELECT text, url, contents, last_access_time, number_of_hits
     FROM omni_box_shortcuts ORDER BY last_access_time DESC`,
  )
  return rows.map((row) => ({
    id: generateId(),
    text: row.text ?? '',
    url: row.url ?? '',
    title: row.contents ?? '',
    lastAccessTime: webkitToMs(row.last_access_time),
    hits: row.number_of_hits ?? 0,
  }))
}

/* ======================================================================== */
/* FIREFOX (places.sqlite)                                                   */
/* ======================================================================== */

// Firefox visit types (moz_historyvisits.visit_type) that are relevant.
const FIREFOX_REDIRECT_TYPES = new Set([5, 6]) // REDIRECT_PERMANENT / TEMPORARY

/** History from places.sqlite (moz_places + moz_historyvisits). */
export function parseFirefoxHistory(db) {
  const rows = queryRows(
    db,
    `SELECT p.url AS url, p.title AS title, p.visit_count AS visit_count,
            v.id AS visit_id, v.from_visit AS from_visit,
            v.visit_type AS visit_type, v.visit_date AS visit_date
     FROM moz_places AS p INNER JOIN moz_historyvisits AS v ON v.place_id = p.id
     ORDER BY v.visit_date DESC`,
  )
  return rows.map((row) => ({
    id: generateId(),
    url: row.url ?? '',
    title: row.title ?? '',
    visitCount: row.visit_count ?? 0,
    visitTime: firefoxToMs(row.visit_date),
    visitId: row.visit_id ?? null,
    fromVisitId: row.from_visit || null,
    isRedirect: FIREFOX_REDIRECT_TYPES.has(Number(row.visit_type)),
  }))
}

// English labels for the Firefox bookmark roots (by guid).
// The technical root `root________` is mapped to an empty string so it does
// NOT appear in the paths (e.g. "Bookmarks Toolbar > Work", not
// "Bookmarks > Bookmarks Toolbar > Work").
const FIREFOX_ROOT_LABELS = {
  root________: '',
  menu________: 'Bookmarks Menu',
  toolbar_____: 'Bookmarks Toolbar',
  unfiled_____: 'Other Bookmarks',
  mobile______: 'Mobile Bookmarks',
  tags________: 'Tags',
}

/** Bookmarks from places.sqlite (moz_bookmarks + moz_places), with folder path. */
export function parseFirefoxBookmarks(db) {
  if (!hasTables(db, ['moz_bookmarks', 'moz_places'])) return []

  // Map of all nodes to reconstruct the folder path.
  const nodes = new Map()
  for (const row of tryQueryRows(
    db,
    'SELECT id, parent, title, type, guid FROM moz_bookmarks',
  )) {
    nodes.set(row.id, row)
  }

  /** Reconstructs "Bookmarks Toolbar > Work" by climbing the parent chain. */
  function folderPath(parentId) {
    const parts = []
    let current = nodes.get(parentId)
    let guard = 0
    while (current && guard < 50) {
      const label = FIREFOX_ROOT_LABELS[current.guid] ?? (current.title || '')
      if (label) parts.unshift(label)
      if (!current.parent || current.parent === current.id) break
      current = nodes.get(current.parent)
      guard += 1
    }
    return parts.join(' > ') || null
  }

  /**
   * True if the node descends from the TAGS root (guid `tags________`). In
   * Firefox, tags are type=1 entries under that root and duplicate the URL of
   * the real bookmark: they must be excluded from the bookmark list.
   */
  function isUnderTags(parentId) {
    let current = nodes.get(parentId)
    let guard = 0
    while (current && guard < 50) {
      if (current.guid === 'tags________') return true
      if (!current.parent || current.parent === current.id) break
      current = nodes.get(current.parent)
      guard += 1
    }
    return false
  }

  const rows = queryRows(
    db,
    `SELECT b.id AS id, b.title AS title, b.dateAdded AS date_added,
            b.parent AS parent, p.url AS url
     FROM moz_bookmarks AS b INNER JOIN moz_places AS p ON p.id = b.fk
     WHERE b.type = 1
     ORDER BY b.dateAdded DESC`,
  )
  return rows
    .filter((row) => !isUnderTags(row.parent)) // exclude tags (they are not bookmarks)
    .map((row) => ({
      id: generateId(),
      name: row.title || '(unnamed)',
      url: row.url ?? '',
      folder: folderPath(row.parent),
      dateAdded: firefoxToMs(row.date_added),
    }))
}

/**
 * Downloads from places.sqlite. Firefox (since 2019) stores them as
 * annotations on moz_places: `downloads/destinationFileURI` (path of the
 * saved file) and `downloads/metaData` (JSON with state, endTime and fileSize).
 * The download source is the place URL; the destination is the downloaded file.
 */
export function parseFirefoxDownloads(db) {
  if (!hasTables(db, ['moz_annos', 'moz_anno_attributes', 'moz_places'])) return []

  // Join the destination annotation with the metadata one (same place).
  const rows = tryQueryRows(
    db,
    `SELECT p.url AS source_url, p.title AS title,
            dest.content AS dest, dest.dateAdded AS date_added,
            meta.content AS meta_json, p.last_visit_date AS last_visit
     FROM moz_annos AS dest
     JOIN moz_places AS p ON p.id = dest.place_id
     JOIN moz_anno_attributes AS a_dest
       ON a_dest.id = dest.anno_attribute_id
      AND a_dest.name = 'downloads/destinationFileURI'
     LEFT JOIN moz_anno_attributes AS a_meta ON a_meta.name = 'downloads/metaData'
     LEFT JOIN moz_annos AS meta
       ON meta.place_id = dest.place_id AND meta.anno_attribute_id = a_meta.id
     ORDER BY dest.dateAdded DESC`,
  )
  return rows.map((row) => {
    // downloads/metaData is a JSON: { state, deleted, endTime (ms), fileSize }
    let fileSize = 0
    let endTime = null
    let state = 1
    if (row.meta_json) {
      try {
        const meta = JSON.parse(row.meta_json)
        fileSize = Number(meta.fileSize) || 0
        endTime = Number(meta.endTime) || null // already in Unix ms
        if (typeof meta.state === 'number') state = meta.state
      } catch {
        /* unreadable metaData: defaults are used */
      }
    }
    return {
      id: generateId(),
      fileName: fileNameFromPath(row.dest) || '(unknown)',
      targetPath: row.dest ?? '',
      url: row.source_url ?? '', // in Firefox the place is the download source
      referrer: row.source_url ?? '',
      startTime: firefoxToMs(row.date_added) ?? firefoxToMs(row.last_visit),
      endTime,
      totalBytes: fileSize,
      receivedBytes: fileSize,
      mimeType: '',
      state,
    }
  })
}

/* ======================================================================== */
/* Dispatch by engine                                                        */
/* ======================================================================== */

/**
 * Opens a SQLite file and extracts the artifacts required by the source.
 * @param {ArrayBuffer} arrayBuffer file content
 * @param {'chromium'|'firefox'} engine browser engine
 * @param {string} sourceKey source key (history/shortcuts/places)
 * @returns {Promise<object>} map { history?, downloads?, bookmarks?, shortcuts? }
 */
export async function parseSqliteSource(arrayBuffer, engine, sourceKey) {
  const db = await openDatabase(arrayBuffer)
  try {
    if (engine === 'firefox') {
      if (!hasTables(db, ['moz_places'])) {
        throw new Error(
          'The database does not contain the expected tables (moz_places): it does not look like a Firefox places.sqlite file.',
        )
      }
      return {
        history: parseFirefoxHistory(db),
        bookmarks: parseFirefoxBookmarks(db),
        downloads: parseFirefoxDownloads(db),
      }
    }

    // --- Chromium ---
    if (sourceKey === 'shortcuts') {
      return { shortcuts: parseChromiumShortcuts(db) }
    }
    // 'history' source (default): history + downloads
    if (!hasTables(db, ['urls', 'visits'])) {
      throw new Error(
        'The database does not contain the expected tables (urls/visits): it does not look like a Chrome History file.',
      )
    }
    return {
      history: parseChromiumHistory(db),
      downloads: parseChromiumDownloads(db),
    }
  } finally {
    db.close()
  }
}
