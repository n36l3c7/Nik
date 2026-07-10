/*
 * ============================================================================
 * LOCAL PREFERENCES
 * ============================================================================
 *
 * Since v3 all application data — incidents, users, audit log and settings —
 * lives in the backend (PostgreSQL) and is reached through `services/api.js`.
 *
 * The ONLY thing that legitimately stays on the device is the UI theme, a pure
 * per-browser display preference. It is kept in localStorage so a reload does
 * not flash the wrong theme before the app boots.
 */

const LS_KEYS = {
  theme: 'nik:theme',
}

/** Persisted theme: 'dark' | 'light' | null (never set). */
export function loadTheme() {
  const value = localStorage.getItem(LS_KEYS.theme)
  return value === 'dark' || value === 'light' ? value : null
}

export function saveTheme(theme) {
  try {
    localStorage.setItem(LS_KEYS.theme, theme)
  } catch {
    /* non critical — a failed theme write must never break the app */
  }
}
