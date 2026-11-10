import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { parsePlist } from './plistParser.js'
import { mapSafariBookmarks, mapSafariDownloads } from './safariParser.js'

function plistFixture(name) {
  const bytes = readFileSync(new URL(`./__fixtures__/${name}`, import.meta.url))
  return parsePlist(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength))
}

const withoutIds = (rows) => rows.map(({ id, ...rest }) => (assert.ok(id), rest))

test('maps Downloads.plist entries onto the shared download shape', () => {
  const downloads = withoutIds(mapSafariDownloads(plistFixture('safari-downloads.bplist')))
  assert.deepEqual(downloads, [
    {
      fileName: 'payload.dmg',
      targetPath: '/Users/jdoe/Downloads/payload.dmg',
      url: 'https://evil.example/payload.dmg',
      referrer: 'https://evil.example/payload.dmg',
      startTime: Date.UTC(2026, 10, 2, 2, 14),
      endTime: Date.UTC(2026, 10, 2, 2, 15),
      totalBytes: 1048576,
      receivedBytes: 1048576,
      mimeType: '',
      state: 1,
    },
    {
      fileName: 'report.pdf',
      targetPath: '',
      url: 'https://example.com/files/report.pdf?dl=1',
      referrer: 'https://example.com/files/report.pdf?dl=1',
      startTime: Date.UTC(2026, 10, 3, 9, 0),
      endTime: null,
      totalBytes: 4096,
      receivedBytes: 512,
      mimeType: '',
      state: 4,
    },
  ])
})

test('maps Bookmarks.plist leaves with folder paths, skipping proxies', () => {
  const bookmarks = withoutIds(mapSafariBookmarks(plistFixture('safari-bookmarks.bplist')))
  assert.deepEqual(bookmarks, [
    { name: 'Intranet', url: 'https://intranet.company.local/', folder: 'Favorites', dateAdded: null },
    { name: '(unnamed)', url: 'https://pastebin.com/u/anon0x', folder: 'Favorites > Tools', dateAdded: null },
    {
      name: 'Download Tor Browser',
      url: 'https://www.torproject.org/download/',
      folder: 'Reading List',
      dateAdded: Date.UTC(2026, 10, 1, 23, 5),
    },
  ])
})

test('rejects plists that are not the expected Safari file', () => {
  const bookmarks = plistFixture('safari-bookmarks.bplist')
  const downloads = plistFixture('safari-downloads.bplist')
  assert.throws(() => mapSafariDownloads(bookmarks), /Not a Safari Downloads\.plist/)
  assert.throws(() => mapSafariBookmarks(downloads), /Not a Safari Bookmarks\.plist/)
})
