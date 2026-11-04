/*
 * ============================================================================
 * BROWSER PROFILES — pure helpers over `data.browser.browsers[id]`
 * ============================================================================
 *
 * Each browser holds several profiles (Chrome "Default", "Profile 1", …):
 *
 *   { activeProfile: '<profileId>',
 *     profiles: { '<profileId>': { id, name, createdAt, history, downloads,
 *                                  bookmarks, shortcuts, meta } } }
 *
 * Profiles are keyed by a stable id (renaming does not move data, and a JSON
 * Merge Patch only sends the profile that changed) and displayed in
 * `createdAt` order, because PostgreSQL JSONB does not keep key order.
 *
 * Before 2.0.0 a browser held the artifact arrays directly: such a legacy slot
 * becomes the profile "Default" (id `default`) — the same rule as the backend
 * (`app/browser_profiles.py`) and the 0003 migration.
 */

import {
  DEFAULT_PROFILE_CREATED_AT,
  DEFAULT_PROFILE_ID,
  DEFAULT_PROFILE_NAME,
  buildDefaultBrowserData,
  buildDefaultProfileData,
} from '../config/browsers.js'

const ARTIFACT_KEYS = ['history', 'downloads', 'bookmarks', 'shortcuts']

const isObject = (value) => value !== null && typeof value === 'object' && !Array.isArray(value)

/** Normalize one stored profile (missing arrays/meta become defaults). */
function normalizeProfile(raw, browser, fallback) {
  const base = buildDefaultProfileData(browser, fallback)
  const name = typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : fallback.name
  const profile = {
    ...base,
    id: fallback.id,
    name,
    createdAt: typeof raw.createdAt === 'string' && raw.createdAt ? raw.createdAt : fallback.createdAt,
    meta: { ...base.meta, ...(isObject(raw.meta) ? raw.meta : {}) },
  }
  for (const key of ARTIFACT_KEYS) profile[key] = Array.isArray(raw[key]) ? raw[key] : []
  return profile
}

/**
 * Normalize a stored browser slot, migrating the legacy (pre-2.0.0) shape.
 * Always returns at least one profile and a valid `activeProfile`.
 */
export function normalizeBrowserSlot(raw, browser) {
  if (!isObject(raw)) return buildDefaultBrowserData(browser)

  const defaults = { id: DEFAULT_PROFILE_ID, name: DEFAULT_PROFILE_NAME, createdAt: DEFAULT_PROFILE_CREATED_AT }
  if (!isObject(raw.profiles)) {
    const profile = normalizeProfile(raw, browser, defaults)
    return { activeProfile: profile.id, profiles: { [profile.id]: profile } }
  }

  const profiles = {}
  for (const [id, rawProfile] of Object.entries(raw.profiles)) {
    if (!isObject(rawProfile)) continue
    profiles[id] = normalizeProfile(rawProfile, browser, {
      id,
      name: id === DEFAULT_PROFILE_ID ? DEFAULT_PROFILE_NAME : 'Profile',
      createdAt: DEFAULT_PROFILE_CREATED_AT,
    })
  }
  if (Object.keys(profiles).length === 0) return buildDefaultBrowserData(browser)
  const slot = { activeProfile: raw.activeProfile, profiles }
  return { ...slot, activeProfile: profiles[raw.activeProfile] ? raw.activeProfile : sortedProfiles(slot)[0].id }
}

/** Profiles of a browser slot in display order (creation time, then name). */
export function sortedProfiles(slot) {
  return Object.values(slot?.profiles ?? {}).sort(
    (a, b) => String(a.createdAt).localeCompare(String(b.createdAt)) || a.name.localeCompare(b.name),
  )
}

/** The active profile of a slot (falls back to the first one), or null. */
export function activeProfileOf(slot) {
  return slot?.profiles?.[slot.activeProfile] ?? sortedProfiles(slot)[0] ?? null
}

/** Number of artifact rows in one profile. */
export function profileRowCount(profile) {
  return ARTIFACT_KEYS.reduce((sum, key) => sum + (profile?.[key]?.length ?? 0), 0)
}

/** Total artifact rows of a browser slot, across all its profiles. */
export function browserRowCount(slot) {
  return Object.values(slot?.profiles ?? {}).reduce((sum, p) => sum + profileRowCount(p), 0)
}

/**
 * Validate a profile name for a browser: returns an error message, or null if
 * the name is usable. Names are unique per browser, case-insensitively.
 */
export function profileNameError(slot, name, exceptId = null) {
  const trimmed = String(name ?? '').trim()
  if (!trimmed) return 'Enter a profile name.'
  if (trimmed.length > 60) return 'Use at most 60 characters.'
  const clash = Object.values(slot?.profiles ?? {}).some(
    (p) => p.id !== exceptId && p.name.toLocaleLowerCase() === trimmed.toLocaleLowerCase(),
  )
  return clash ? 'A profile with this name already exists for this browser.' : null
}

/**
 * Display label of a browser profile for timelines and flags. The profile
 * name is shown only when the browser has more than one profile.
 */
export function profileLabel(browserLabel, slot, profile) {
  return Object.keys(slot?.profiles ?? {}).length > 1 && profile ? `${browserLabel} · ${profile.name}` : browserLabel
}

/**
 * Profile of a browser flag, resolved against the incident's current data:
 * `{ name, deleted }`, or null for flags with no profile (shell/endpoint flags
 * and flags placed before 2.0.0). A renamed profile reports its current name.
 */
export function flagProfile(browsers, flag) {
  if (!flag?.profileId) return null
  const profile = browsers?.[flag.browserId]?.profiles?.[flag.profileId]
  if (profile) return { name: profile.name, deleted: false }
  return { name: flag.profileName || 'unknown profile', deleted: true }
}
