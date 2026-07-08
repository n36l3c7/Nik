import { Chrome, Compass, Database, Flame, Globe, Shield, Bookmark, Zap } from 'lucide-react'

/*
 * ============================================================================
 * BROWSER REGISTRY — the only file to edit to add a browser
 * ============================================================================
 *
 * The "Browser Forensics" tab shows a sub-tab for each browser listed here.
 * Each browser declares:
 *  - id / label / icon:  identity and entry in the sub-tab bar
 *  - engine:             'chromium' | 'firefox' — determines the parsers used
 *  - accent:             accent color of the sub-tab (Tailwind classes)
 *  - profilePaths:       path of the profile PER OS (windows/macos/linux) for
 *                        the "where to find the files" note, driven by the
 *                        incident's host OS
 *  - artifacts:          which analysis sections to show
 *                        ('history' | 'downloads' | 'bookmarks' | 'shortcuts')
 *  - sources:            the FILES the user uploads. Each source produces one
 *                        or more artifacts (e.g. Chrome's History contains both
 *                        the browsing history and the downloads; Firefox's
 *                        places.sqlite contains history, bookmarks and downloads).
 *
 * Source:
 *  { key, label, icon, accept, produces: string[], paths, hint }
 *   - key:      unique key within the browser (also used for metadata/removal)
 *   - produces: artifacts populated by parsing this file
 *   - paths:    typical path of the file per OS (shown in the note)
 *   - hint:     short description of the file
 */

/** Append `fileName` to every per-OS base path (joiner inferred per path). */
function joinPaths(bases, fileName) {
  const paths = {}
  for (const [os, base] of Object.entries(bases)) {
    paths[os] = base + fileName
  }
  return paths
}

/* ---- Chromium-based browsers (Chrome, Edge, Brave, Opera) ---------------- */
// They all share Chrome's SQLite schema (urls/visits/downloads) and the JSON
// format of the Bookmarks, so they reuse the same sources.
function chromiumSources(bases) {
  return [
    {
      key: 'history',
      label: 'History',
      icon: Database,
      accept: '', // Chrome's files have no extension
      produces: ['history', 'downloads'],
      paths: joinPaths(bases, 'History'),
      hint: "SQLite database 'History': contains browsing history AND downloads. Copy the file (without extension).",
    },
    {
      key: 'bookmarks',
      label: 'Bookmarks',
      icon: Bookmark,
      accept: '.json,.csv',
      produces: ['bookmarks'],
      paths: joinPaths(bases, 'Bookmarks'),
      hint: "JSON file 'Bookmarks' (without extension) or a JSON/CSV export.",
    },
    {
      key: 'shortcuts',
      label: 'Shortcuts',
      icon: Zap,
      accept: '',
      produces: ['shortcuts'],
      paths: joinPaths(bases, 'Shortcuts'),
      hint: "SQLite database 'Shortcuts': shortcuts typed in the omnibox.",
    },
  ]
}

/* ---- Firefox ------------------------------------------------------------- */
// Firefox uses a single `places.sqlite` database (moz_* schema) that gathers
// history, bookmarks and downloads; Shortcuts do not exist.
function firefoxSources(bases) {
  return [
    {
      key: 'places',
      label: 'places.sqlite',
      icon: Database,
      accept: '', // may have a .sqlite extension: we do not restrict
      produces: ['history', 'bookmarks', 'downloads'],
      paths: joinPaths(bases, 'places.sqlite'),
      hint: 'Firefox SQLite database: history, bookmarks and downloads together.',
    },
  ]
}

/* Per-OS profile directories for each browser. */
const CHROME_PROFILES = {
  windows: '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\',
  macos: '~/Library/Application Support/Google/Chrome/Default/',
  linux: '~/.config/google-chrome/Default/',
}
const FIREFOX_PROFILES = {
  windows: '%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>.default-release\\',
  macos: '~/Library/Application Support/Firefox/Profiles/<profile>.default-release/',
  linux: '~/.mozilla/firefox/<profile>.default-release/',
}
const EDGE_PROFILES = {
  windows: '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\',
  macos: '~/Library/Application Support/Microsoft Edge/Default/',
  linux: '~/.config/microsoft-edge/Default/',
}
const BRAVE_PROFILES = {
  windows: '%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',
  macos: '~/Library/Application Support/BraveSoftware/Brave-Browser/Default/',
  linux: '~/.config/BraveSoftware/Brave-Browser/Default/',
}
const OPERA_PROFILES = {
  windows: '%APPDATA%\\Opera Software\\Opera Stable\\',
  macos: '~/Library/Application Support/com.operasoftware.Opera/',
  linux: '~/.config/opera/',
}

export const BROWSERS = [
  {
    id: 'chrome',
    label: 'Chrome',
    icon: Chrome,
    engine: 'chromium',
    accent: 'text-amber-500',
    profilePaths: CHROME_PROFILES,
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources(CHROME_PROFILES),
  },
  {
    id: 'firefox',
    label: 'Firefox',
    icon: Flame,
    engine: 'firefox',
    accent: 'text-orange-500',
    profilePaths: FIREFOX_PROFILES,
    artifacts: ['history', 'downloads', 'bookmarks'],
    sources: firefoxSources(FIREFOX_PROFILES),
  },
  {
    id: 'edge',
    label: 'Edge',
    icon: Globe,
    engine: 'chromium',
    accent: 'text-sky-500',
    profilePaths: EDGE_PROFILES,
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources(EDGE_PROFILES),
  },
  {
    id: 'brave',
    label: 'Brave',
    icon: Shield,
    engine: 'chromium',
    accent: 'text-orange-600',
    profilePaths: BRAVE_PROFILES,
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources(BRAVE_PROFILES),
  },
  {
    id: 'opera',
    label: 'Opera',
    icon: Compass,
    engine: 'chromium',
    accent: 'text-red-500',
    profilePaths: OPERA_PROFILES,
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources(OPERA_PROFILES),
  },
]

/** Path of a source file for a given OS (windows fallback for legacy data). */
export function sourcePathFor(source, osId) {
  return source.paths?.[osId] ?? source.paths?.windows ?? ''
}

/** All supported artifacts (keys of a browser's data arrays). */
export const BROWSER_ARTIFACT_KEYS = ['history', 'downloads', 'bookmarks', 'shortcuts']

/** Returns the definition of a browser from its id. */
export function getBrowserById(browserId) {
  return BROWSERS.find((b) => b.id === browserId) ?? null
}

/** Initial data structure for a single browser (empty arrays + null meta). */
export function buildDefaultBrowserData(browser) {
  const meta = {}
  for (const source of browser.sources) meta[source.key] = null
  return {
    history: [],
    downloads: [],
    bookmarks: [],
    shortcuts: [],
    meta,
  }
}

/** Map { [browserId]: browserData } with all browsers initialized empty. */
export function buildDefaultBrowsersMap() {
  const map = {}
  for (const browser of BROWSERS) map[browser.id] = buildDefaultBrowserData(browser)
  return map
}
