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
 *  - profilePath:        path of the profile on Windows (for the "where to
 *                        find the files" note)
 *  - artifacts:          which analysis sections to show
 *                        ('history' | 'downloads' | 'bookmarks' | 'shortcuts')
 *  - sources:            the FILES the user uploads. Each source produces one
 *                        or more artifacts (e.g. Chrome's History contains both
 *                        the browsing history and the downloads; Firefox's
 *                        places.sqlite contains history, bookmarks and downloads).
 *
 * Source:
 *  { key, label, icon, accept, produces: string[], path, hint }
 *   - key:      unique key within the browser (also used for metadata/removal)
 *   - produces: artifacts populated by parsing this file
 *   - path:     typical path of the file (shown in the note)
 *   - hint:     short description of the file
 */

/* ---- Chromium-based browsers (Chrome, Edge, Brave, Opera) ---------------- */
// They all share Chrome's SQLite schema (urls/visits/downloads) and the JSON
// format of the Bookmarks, so they reuse the same sources.
function chromiumSources(base) {
  return [
    {
      key: 'history',
      label: 'History',
      icon: Database,
      accept: '', // Chrome's files have no extension
      produces: ['history', 'downloads'],
      path: base + 'History',
      hint: "SQLite database 'History': contains browsing history AND downloads. Copy the file (without extension).",
    },
    {
      key: 'bookmarks',
      label: 'Bookmarks',
      icon: Bookmark,
      accept: '.json,.csv',
      produces: ['bookmarks'],
      path: base + 'Bookmarks',
      hint: "JSON file 'Bookmarks' (without extension) or a JSON/CSV export.",
    },
    {
      key: 'shortcuts',
      label: 'Shortcuts',
      icon: Zap,
      accept: '',
      produces: ['shortcuts'],
      path: base + 'Shortcuts',
      hint: "SQLite database 'Shortcuts': shortcuts typed in the omnibox.",
    },
  ]
}

/* ---- Firefox ------------------------------------------------------------- */
// Firefox uses a single `places.sqlite` database (moz_* schema) that gathers
// history, bookmarks and downloads; Shortcuts do not exist.
function firefoxSources(base) {
  return [
    {
      key: 'places',
      label: 'places.sqlite',
      icon: Database,
      accept: '', // may have a .sqlite extension: we do not restrict
      produces: ['history', 'bookmarks', 'downloads'],
      path: base + 'places.sqlite',
      hint: 'Firefox SQLite database: history, bookmarks and downloads together.',
    },
  ]
}

export const BROWSERS = [
  {
    id: 'chrome',
    label: 'Chrome',
    icon: Chrome,
    engine: 'chromium',
    accent: 'text-amber-500',
    profilePath: '%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\',
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources('%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\'),
  },
  {
    id: 'firefox',
    label: 'Firefox',
    icon: Flame,
    engine: 'firefox',
    accent: 'text-orange-500',
    profilePath: '%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>.default-release\\',
    artifacts: ['history', 'downloads', 'bookmarks'],
    sources: firefoxSources('%APPDATA%\\Mozilla\\Firefox\\Profiles\\<profile>.default-release\\'),
  },
  {
    id: 'edge',
    label: 'Edge',
    icon: Globe,
    engine: 'chromium',
    accent: 'text-sky-500',
    profilePath: '%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\',
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources('%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\'),
  },
  {
    id: 'brave',
    label: 'Brave',
    icon: Shield,
    engine: 'chromium',
    accent: 'text-orange-600',
    profilePath: '%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\',
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources('%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\'),
  },
  {
    id: 'opera',
    label: 'Opera',
    icon: Compass,
    engine: 'chromium',
    accent: 'text-red-500',
    profilePath: '%APPDATA%\\Opera Software\\Opera Stable\\',
    artifacts: ['history', 'downloads', 'bookmarks', 'shortcuts'],
    sources: chromiumSources('%APPDATA%\\Opera Software\\Opera Stable\\'),
  },
]

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
