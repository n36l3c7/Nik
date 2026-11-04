/*
 * ============================================================================
 * SAFARI PLIST ARTIFACTS — Downloads.plist and Bookmarks.plist
 * ============================================================================
 *
 * Maps decoded Safari property lists (see plistParser.js) onto the normalized
 * shapes every browser shares (`downloads`, `bookmarks`). Safari's history is
 * a SQLite database instead (History.db), parsed in sqliteParser.js.
 *
 * Downloads.plist: { DownloadHistory: [ { DownloadEntryURL, DownloadEntryPath,
 *   DownloadEntryDateAddedKey, DownloadEntryDateFinishedKey,
 *   DownloadEntryProgressBytesSoFar, DownloadEntryProgressTotalToLoad, … } ] }
 *
 * Bookmarks.plist: a tree of nodes with `WebBookmarkType` — `…List` (folder
 * with `Title` and `Children`), `…Leaf` (bookmark with `URLString` and
 * `URIDictionary.title`) and `…Proxy` (the built-in History entry, skipped).
 * Reading List items are leaves under the `com.apple.ReadingList` folder and
 * carry `ReadingList.DateAdded`; regular bookmarks store no creation date.
 */

import { generateId } from '../utils/id.js'
import { fileNameFromPath } from '../utils/path.js'

// Display labels of Safari's built-in top-level folders.
const SAFARI_ROOT_LABELS = {
  BookmarksBar: 'Favorites',
  BookmarksMenu: 'Bookmarks Menu',
  'com.apple.ReadingList': 'Reading List',
}

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Unix ms of a plist date (Date), or null. */
function dateToMs(value) {
  if (!(value instanceof Date)) return null
  const ms = value.getTime()
  return Number.isFinite(ms) ? ms : null
}

/** Non-negative byte count from a plist number (or BigInt), else 0. */
function asBytes(value) {
  const n = Number(value)
  return Number.isFinite(n) && n >= 0 ? Math.round(n) : 0
}

const asText = (value) => (typeof value === 'string' ? value.trim() : '')

/**
 * Downloads from a decoded Downloads.plist.
 * Safari keeps no referrer: the file URL is used as the originating site.
 * `state` follows the Chromium convention used across Nik: 1 = complete,
 * 4 = interrupted (no finish date).
 */
export function mapSafariDownloads(plist) {
  const entries = isObject(plist) ? plist.DownloadHistory : null
  if (!Array.isArray(entries)) {
    throw new Error('Not a Safari Downloads.plist: the "DownloadHistory" list is missing.')
  }
  return entries.filter(isObject).map((entry) => {
    const url = asText(entry.DownloadEntryURL)
    const targetPath = asText(entry.DownloadEntryPath)
    const endTime = dateToMs(entry.DownloadEntryDateFinishedKey)
    return {
      id: generateId(),
      fileName: fileNameFromPath(targetPath) || fileNameFromPath(url) || '(unknown)',
      targetPath,
      url,
      referrer: url,
      startTime: dateToMs(entry.DownloadEntryDateAddedKey) ?? endTime,
      endTime,
      totalBytes: asBytes(entry.DownloadEntryProgressTotalToLoad),
      receivedBytes: asBytes(entry.DownloadEntryProgressBytesSoFar),
      mimeType: '',
      state: endTime !== null ? 1 : 4,
    }
  })
}

/** Bookmarks (including Reading List items) from a decoded Bookmarks.plist. */
export function mapSafariBookmarks(plist) {
  if (!isObject(plist) || !Array.isArray(plist.Children)) {
    throw new Error('Not a Safari Bookmarks.plist: the root bookmark list is missing.')
  }
  const out = []
  const walk = (node, folderPath, depth) => {
    if (!isObject(node) || depth > 100) return
    if (node.WebBookmarkType === 'WebBookmarkTypeLeaf') {
      const url = asText(node.URLString)
      if (!url) return
      out.push({
        id: generateId(),
        name: asText(node.URIDictionary?.title) || asText(node.Title) || '(unnamed)',
        url,
        folder: folderPath || null,
        dateAdded: dateToMs(node.ReadingList?.DateAdded),
      })
      return
    }
    if (node.WebBookmarkType !== 'WebBookmarkTypeList' || !Array.isArray(node.Children)) return
    const title = asText(node.Title)
    const label = SAFARI_ROOT_LABELS[title] ?? title
    const path = label ? (folderPath ? `${folderPath} > ${label}` : label) : folderPath
    for (const child of node.Children) walk(child, path, depth + 1)
  }
  for (const child of plist.Children) walk(child, '', 0)
  return out
}
