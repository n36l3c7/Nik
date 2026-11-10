import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api, NOT_MODIFIED } from '../services/api.js'
import { createMergePatch, MERGE_PATCH_CONTENT_TYPE } from '../utils/mergePatch.js'
import { buildDefaultIncidentData } from '../config/tabs.js'
import {
  BROWSERS,
  getBrowserById,
  buildDefaultBrowserData,
  buildDefaultBrowsersMap,
  buildDefaultProfileData,
} from '../config/browsers.js'
import { normalizeBrowserSlot, profileNameError, sortedProfiles } from '../utils/browserProfiles.js'
import { SHELLS, getShellById, buildDefaultShellData, buildDefaultShellsMap } from '../config/shells.js'
import {
  ARTIFACT_CATEGORIES,
  getArtifactCategoryById,
  categorySourceKeys,
  buildDefaultArtifactData,
  buildDefaultArtifactsMap,
} from '../config/artifacts.js'
import { normalizeOs } from '../config/os.js'
import { generateId } from '../utils/id.js'
import { deriveIncidentName, hasIdentity, normalizeSeverity } from '../utils/incidentName.js'
import { useAuth } from './AuthContext.jsx'
import { useAudit } from './AuditContext.jsx'

/*
 * ============================================================================
 * INCIDENT STATE (formerly "projects") — backed by the API
 * ============================================================================
 *
 * An incident represents a forensic case, identified by a host and/or a user.
 *
 * {
 *   id,
 *   ticketId, title,      // ticket of the tracker, short title (both optional)
 *   host, username,       // identity (NOT unique; the id is the DB key)
 *   severity,             // 'low' | 'medium' | 'high' | 'critical' | null — a tag
 *   os,                   // 'windows' | 'macos' | 'linux' — the host OS
 *   name,                 // derived: "[ticket] title" | "[ticket] host - username" …
 *   suspiciousStart,      // Unix ms | null — start of suspicious activity
 *   suspiciousEnd,        // Unix ms | null — end of suspicious activity
 *   createdAt, updatedAt, createdBy,
 *   data: { summary, browser, commands, endpoint, malware, eventlogs, network },
 *   flags: { [key]: { key, browserId, profileId?, profileName?, section,
 *                     eventType, title, url, time, flaggedAt, flaggedBy,
 *                     comments: [...] } },
 *   notes: [ { id, text, createdAt, updatedAt, author } ],
 *   report: { lang, tlp, sections, executiveSummary } | null,  // report options
 * }
 *
 * Loading is lazy, so a platform with many large incidents stays responsive:
 *   - after sign-in only the LIGHT list is fetched (GET /incidents?view=summary:
 *     id, name, host, username, os, timestamps — no artifacts);
 *   - an incident's full document is fetched when it is opened
 *     (GET /incidents/{id}) and kept in an in-memory cache for the session;
 *   - reopening a cached incident shows it at once and revalidates it with
 *     `If-None-Match` (304 when unchanged, refreshed when someone else edited it).
 *
 * Every mutation goes through commit(): it updates local state immediately and
 * persists ONLY what changed, as an RFC 7396 JSON Merge Patch computed by
 * diffing the previous and next document (unchanged subtrees share references,
 * so toggling a flag sends the flag, not the artifact arrays):
 *   - createIncident / import     → POST   /incidents        (full doc)
 *   - deleteIncident              → DELETE /incidents/{id}
 *   - every other mutation        → PATCH  /incidents/{id}   (merge patch)
 *   - setActiveBrowser/Shell      → LOCAL ONLY (a view preference; never sent)
 *
 * IMPORTANT: audit() (which triggers a state update in AuditProvider) and
 * commit() are always called from event-handler scope, NEVER inside a
 * state updater — React state updaters must be pure, and StrictMode
 * double-invokes them in dev.
 */

const IncidentContext = createContext(null)

const nowIso = () => new Date().toISOString()

/** Display name derived from host/username. */
export { deriveIncidentName }

/* ---- browser data normalization (per-browser, per-profile + legacy migration) ---- */
function normalizeBrowserData(raw) {
  const fallback = { activeBrowser: BROWSERS[0].id, browsers: buildDefaultBrowsersMap() }
  if (!raw || typeof raw !== 'object') return fallback

  if (raw.browsers && typeof raw.browsers === 'object') {
    const browsers = {}
    for (const browser of BROWSERS) {
      browsers[browser.id] = normalizeBrowserSlot(raw.browsers[browser.id], browser)
    }
    return {
      activeBrowser: getBrowserById(raw.activeBrowser) ? raw.activeBrowser : BROWSERS[0].id,
      browsers,
    }
  }

  // Oldest single-browser shape → Chrome's Default profile.
  if (Array.isArray(raw.history) || Array.isArray(raw.bookmarks) || Array.isArray(raw.shortcuts)) {
    const browsers = buildDefaultBrowsersMap()
    browsers.chrome = normalizeBrowserSlot(
      { history: raw.history, bookmarks: raw.bookmarks, shortcuts: raw.shortcuts, meta: raw.meta },
      getBrowserById('chrome'),
    )
    return { activeBrowser: 'chrome', browsers }
  }

  return fallback
}

/** New `data` with one browser slot replaced by `fn(slot, browser)`. */
function withBrowserSlot(data, browserId, fn) {
  const browser = getBrowserById(browserId) ?? BROWSERS[0]
  const slot = data.browser.browsers[browserId] ?? buildDefaultBrowserData(browser)
  return {
    ...data,
    browser: { ...data.browser, browsers: { ...data.browser.browsers, [browserId]: fn(slot, browser) } },
  }
}

/** New `data` with one profile of a browser replaced by `fn(profile, browser)`. */
function withBrowserProfile(data, browserId, profileId, fn) {
  return withBrowserSlot(data, browserId, (slot, browser) => {
    const profile = slot.profiles[profileId]
    if (!profile) return slot
    return { ...slot, profiles: { ...slot.profiles, [profileId]: fn(profile, browser) } }
  })
}

/* ---- command data normalization (per-shell) ---- */
function normalizeCommandsData(raw) {
  const fallback = { activeShell: SHELLS[0].id, shells: buildDefaultShellsMap() }
  if (!raw || typeof raw !== 'object') return fallback

  const shells = buildDefaultShellsMap()
  if (raw.shells && typeof raw.shells === 'object') {
    for (const shell of SHELLS) {
      const rs = raw.shells[shell.id]
      if (rs && typeof rs === 'object') {
        const def = buildDefaultShellData()
        shells[shell.id] = {
          commands: Array.isArray(rs.commands) ? rs.commands : [],
          meta: { ...def.meta, ...(rs.meta ?? {}) },
        }
      }
    }
  }
  return {
    activeShell: getShellById(raw.activeShell) ? raw.activeShell : SHELLS[0].id,
    shells,
  }
}

/* ---- endpoint artifact data normalization (per-category, per-source) ---- */
function normalizeEndpointData(raw) {
  const categories = buildDefaultArtifactsMap()
  if (!raw || typeof raw !== 'object') return { categories }

  const src = raw.categories && typeof raw.categories === 'object' ? raw.categories : {}
  for (const category of ARTIFACT_CATEGORIES) {
    const rc = src[category.id]
    if (!rc || typeof rc !== 'object' || !rc.sources) continue
    for (const key of categorySourceKeys(category)) {
      const rs = rc.sources[key]
      if (rs && typeof rs === 'object') {
        categories[category.id].sources[key] = {
          records: Array.isArray(rs.records) ? rs.records : [],
          meta: rs.meta ?? null,
        }
      }
    }
  }
  return { categories }
}

/** Normalize a loaded/imported incident (also migrates old "project" shape). */
function normalizeIncident(raw) {
  const defaults = buildDefaultIncidentData()
  const data = {
    ...defaults,
    ...(typeof raw.data === 'object' && raw.data !== null ? raw.data : {}),
  }
  data.browser = normalizeBrowserData(raw.data?.browser)
  data.commands = normalizeCommandsData(raw.data?.commands)
  data.endpoint = normalizeEndpointData(raw.data?.endpoint)

  const identity = {
    ticketId: typeof raw.ticketId === 'string' ? raw.ticketId.trim() : '',
    title: typeof raw.title === 'string' ? raw.title.trim() : '',
    host: typeof raw.host === 'string' ? raw.host.trim() : '',
    username: typeof raw.username === 'string' ? raw.username.trim() : '',
  }
  // With no identity field but an old "name", keep it as the display name.
  const name = hasIdentity(identity)
    ? deriveIncidentName(identity)
    : typeof raw.name === 'string' && raw.name.trim()
      ? raw.name.trim()
      : 'Untitled incident'

  return {
    id: typeof raw.id === 'string' && raw.id ? raw.id : generateId(),
    ...identity,
    severity: normalizeSeverity(raw.severity),
    os: normalizeOs(raw.os),
    name,
    suspiciousStart: Number.isFinite(raw.suspiciousStart) ? raw.suspiciousStart : null,
    suspiciousEnd: Number.isFinite(raw.suspiciousEnd) ? raw.suspiciousEnd : null,
    createdAt: raw.createdAt ?? nowIso(),
    updatedAt: raw.updatedAt ?? nowIso(),
    createdBy: raw.createdBy ?? null,
    data,
    flags: raw.flags && typeof raw.flags === 'object' ? raw.flags : {},
    notes: Array.isArray(raw.notes) ? raw.notes : [],
    // Saved report options (language, TLP, sections, executive summary).
    report: raw.report && typeof raw.report === 'object' ? raw.report : null,
  }
}

function downloadJson(filename, obj) {
  const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const anchor = document.createElement('a')
  anchor.href = url
  anchor.download = filename
  anchor.click()
  URL.revokeObjectURL(url)
}

/* ---- URL <-> active incident (permalink: /incident/<id>) ---- */
// Opening an incident reflects its id in the URL so every incident has a
// shareable, bookmarkable permalink; back/forward navigate between them. nginx
// (and the Vite dev server) serve index.html for these paths (SPA fallback).
const INCIDENT_PATH_RE = /^\/incident\/([^/?#]+)/

/** Read the incident id from the current URL, or null. */
function incidentIdFromUrl() {
  if (typeof window === 'undefined') return null
  const match = window.location.pathname.match(INCIDENT_PATH_RE)
  return match ? decodeURIComponent(match[1]) : null
}

/** Reflect the active incident in the URL (push adds a history entry). */
function syncUrl(incidentId, { replace = false } = {}) {
  if (typeof window === 'undefined') return
  const path = incidentId ? `/incident/${encodeURIComponent(incidentId)}` : '/'
  if (window.location.pathname === path) return
  const state = { incidentId: incidentId ?? null }
  if (replace) window.history.replaceState(state, '', path)
  else window.history.pushState(state, '', path)
}

/** The light listing row of an incident (what `GET /incidents?view=summary` returns). */
function toSummary(incident) {
  return {
    id: incident.id,
    name: incident.name,
    host: incident.host,
    username: incident.username,
    os: incident.os,
    ticketId: incident.ticketId ?? '',
    severity: incident.severity ?? null,
    createdAt: incident.createdAt,
    updatedAt: incident.updatedAt,
  }
}

/** Normalize a summary row from the server (missing fields become defaults). */
function normalizeSummary(raw) {
  const host = typeof raw.host === 'string' ? raw.host.trim() : ''
  const username = typeof raw.username === 'string' ? raw.username.trim() : ''
  const name =
    typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : deriveIncidentName({ host, username })
  return {
    id: raw.id,
    name,
    host,
    username,
    os: normalizeOs(raw.os),
    ticketId: typeof raw.ticketId === 'string' ? raw.ticketId : '',
    severity: normalizeSeverity(raw.severity),
    createdAt: raw.createdAt ?? '',
    updatedAt: raw.updatedAt ?? '',
  }
}

/** ETag the server derives from an incident version (see the backend `_etag`). */
const etagOf = (incident) => `"${incident.updatedAt ?? ''}"`

export function IncidentProvider({ children }) {
  const { currentUser, isAuthenticated } = useAuth()
  const { log } = useAudit()

  // Light listing rows (no artifacts): what the sidebar renders.
  const [incidents, setIncidents] = useState([])
  // Full documents fetched on demand, keyed by id. Never evicted during the
  // session: an incident opened once reopens instantly (revalidated with ETag).
  const [documents, setDocuments] = useState({})
  // Initialize from the URL so a permalink (/incident/<id>) opens directly to
  // the right incident on first load (and survives the sign-in gate).
  const [activeIncidentId, setActiveIncidentId] = useState(incidentIdFromUrl)
  const [loading, setLoading] = useState(true)
  const [activeLoadError, setActiveLoadError] = useState(null)
  // Download progress of the active incident's first fetch: { received, total }
  // in bytes (total null when unknown), or null when nothing is downloading.
  const [activeLoadProgress, setActiveLoadProgress] = useState(null)
  // Bumped by retryActiveIncident() to re-run the on-demand fetch after an error.
  const [reloadToken, setReloadToken] = useState(0)
  const [storageError, setStorageError] = useState(null)

  // Always-current snapshots so event handlers read the latest state without
  // stale-closure issues and without side effects inside a setState updater.
  // `documentsRef` is written eagerly by `commit`, so two mutations in the same
  // tick both build on the latest document.
  const incidentsRef = useRef(incidents)
  incidentsRef.current = incidents
  const documentsRef = useRef(documents)
  const activeIncidentIdRef = useRef(activeIncidentId)
  // POST promises of the incidents created in this session (see whenSaved).
  const savedRef = useRef(new Map())
  activeIncidentIdRef.current = activeIncidentId

  /** Store a full document in the cache (and its summary row in the list). */
  const storeDocument = useCallback((incident, { prepend = false } = {}) => {
    documentsRef.current = { ...documentsRef.current, [incident.id]: incident }
    setDocuments(documentsRef.current)
    const summary = toSummary(incident)
    setIncidents((list) =>
      list.some((row) => row.id === incident.id)
        ? list.map((row) => (row.id === incident.id ? summary : row))
        : prepend
          ? [summary, ...list]
          : [...list, summary],
    )
  }, [])

  const forgetDocument = useCallback((incidentId) => {
    const { [incidentId]: _removed, ...rest } = documentsRef.current
    documentsRef.current = rest
    setDocuments(rest)
  }, [])

  // Browser back/forward: follow the URL to the corresponding incident.
  useEffect(() => {
    const onPopState = () => setActiveIncidentId(incidentIdFromUrl())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  // Load the LIGHT incident list once authenticated; reset on logout. Full
  // documents are fetched one at a time, when an incident is opened.
  // Note: the active id is NOT cleared here, so a permalink opened before
  // sign-in still resolves once the list loads.
  useEffect(() => {
    if (!isAuthenticated) {
      setIncidents([])
      documentsRef.current = {}
      setDocuments({})
      setLoading(true)
      return
    }
    let cancelled = false
    setLoading(true)
    api
      .get('/incidents?view=summary')
      .then((res) => {
        if (cancelled) return
        const list = Array.isArray(res?.incidents) ? res.incidents : []
        const summaries = list.filter((row) => row && row.id).map(normalizeSummary)
        setIncidents(summaries)
        // Drop an invalid permalink (unknown id) so the UI shows a clean state.
        const active = activeIncidentIdRef.current
        if (active && !summaries.some((i) => i.id === active)) {
          setActiveIncidentId(null)
          syncUrl(null, { replace: true })
        }
        setStorageError(null)
      })
      .catch((err) => {
        if (cancelled) return
        setIncidents([])
        setStorageError(err?.message || 'Unable to load incidents.')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => {
      cancelled = true
    }
  }, [isAuthenticated])

  // Fetch the active incident's full document on demand. A cached copy is shown
  // immediately and revalidated in the background with `If-None-Match`, so an
  // unchanged incident costs a tiny 304 and a changed one is refreshed. Switching
  // to another incident aborts the pending request.
  useEffect(() => {
    if (loading || !activeIncidentId) return
    const cached = documentsRef.current[activeIncidentId]
    const controller = new AbortController()
    setActiveLoadError(null)
    setActiveLoadProgress(null)
    // Progress only matters for a first download (a revalidation is invisible);
    // updates are throttled to every 64 KB to avoid a render per chunk.
    let lastReported = -Infinity
    const onProgress = cached
      ? undefined
      : ({ received, total }) => {
          if (controller.signal.aborted) return
          if (received - lastReported < 65536 && received !== total) return
          lastReported = received
          setActiveLoadProgress({ received, total })
        }
    api
      .get(`/incidents/${encodeURIComponent(activeIncidentId)}`, {
        signal: controller.signal,
        headers: cached ? { 'If-None-Match': etagOf(cached) } : {},
        onProgress,
      })
      .then((res) => {
        if (res === NOT_MODIFIED || !res) return
        // Never overwrite a copy that was edited locally while the request ran.
        const current = documentsRef.current[activeIncidentId]
        if (current && cached && current !== cached) return
        storeDocument(normalizeIncident(res))
      })
      .catch((err) => {
        if (controller.signal.aborted) return
        if (!cached) setActiveLoadError(err?.message || 'Unable to load the incident.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setActiveLoadProgress(null)
      })
    return () => controller.abort()
  }, [activeIncidentId, loading, reloadToken, storeDocument])

  const retryActiveIncident = useCallback(() => {
    setActiveLoadError(null)
    setReloadToken((token) => token + 1)
  }, [])

  const activeIncident = activeIncidentId ? (documents[activeIncidentId] ?? null) : null
  const activeSummary = useMemo(
    () => incidents.find((i) => i.id === activeIncidentId) ?? null,
    [incidents, activeIncidentId],
  )
  const activeLoading = Boolean(activeSummary && !activeIncident && !activeLoadError)

  const actor = currentUser?.username ?? 'system'

  /** Record an audit entry. Call ONLY from event-handler scope. */
  const audit = useCallback(
    (action, details, incident) =>
      log({
        actor,
        action,
        target: incident?.name ?? null,
        details,
        incidentId: incident?.id ?? null,
        incidentName: incident?.name ?? null,
      }),
    [actor, log],
  )

  /** Find a loaded incident document by id from the live snapshot. */
  const find = (id) => documentsRef.current[id] ?? null

  /**
   * Persist the difference between two versions of an incident as an RFC 7396
   * JSON Merge Patch: only the changed subtrees reach the server, never the
   * whole artifact blob. Fire-and-forget: local state is already updated; API
   * errors are surfaced via `storageError`.
   */
  const persist = useCallback((incidentId, prev, next) => {
    const patch = createMergePatch(prev, next)
    if (Object.keys(patch).length === 0) return
    api
      .patch(`/incidents/${encodeURIComponent(incidentId)}`, patch, {
        contentType: MERGE_PATCH_CONTENT_TYPE,
      })
      .then(() => setStorageError(null))
      .catch((err) => setStorageError(err?.message || 'Unable to save changes to the server.'))
  }, [])

  /**
   * Apply `updater` to a loaded incident, update local state immediately and
   * (unless `local`) persist the change. Call ONLY from event-handler scope.
   */
  const commit = useCallback(
    (incidentId, updater, { local = false } = {}) => {
      const prev = documentsRef.current[incidentId]
      if (!prev) return null
      const next = updater(prev)
      storeDocument(next)
      if (!local) persist(incidentId, prev, next)
      return next
    },
    [persist, storeDocument],
  )

  /* ---- incident CRUD ---- */

  const createIncident = useCallback(
    ({ ticketId, title, host, username, os, severity } = {}) => {
      const now = nowIso()
      const identity = {
        ticketId: (ticketId ?? '').trim(),
        title: (title ?? '').trim(),
        host: (host ?? '').trim(),
        username: (username ?? '').trim(),
      }
      const incident = {
        id: generateId(),
        ...identity,
        os: normalizeOs(os),
        severity: normalizeSeverity(severity),
        name: deriveIncidentName(identity),
        suspiciousStart: null,
        suspiciousEnd: null,
        createdAt: now,
        updatedAt: now,
        createdBy: actor,
        data: buildDefaultIncidentData(),
        flags: {},
        notes: [],
      }
      storeDocument(incident, { prepend: true })
      setActiveIncidentId(incident.id)
      syncUrl(incident.id)
      audit('incident.create', `Created incident "${incident.name}"`, incident)
      // Persist the full document; the server stamps its own createdBy.
      const saved = api
        .post('/incidents', incident)
        .then(() => {
          setStorageError(null)
          return true
        })
        .catch((err) => {
          setStorageError(err?.message || 'Unable to create the incident on the server.')
          return false
        })
      savedRef.current.set(incident.id, saved)
      return incident
    },
    [actor, audit, storeDocument],
  )

  /**
   * Resolves once a just-created incident is on the server (true) or failed
   * (false); immediately for any other incident. Server-side imports into a
   * new incident (samples, .evtx) wait for it.
   */
  const whenSaved = useCallback((incidentId) => savedRef.current.get(incidentId) ?? Promise.resolve(true), [])

  /** Update incident identity/time attributes; recompute the display name. */
  const updateIncidentMeta = useCallback(
    (incidentId, patch) => {
      const prev = find(incidentId)
      if (!prev) return
      const pick = (key) => (patch[key] !== undefined ? String(patch[key] ?? '').trim() : (prev[key] ?? ''))
      const identity = {
        ticketId: pick('ticketId'),
        title: pick('title'),
        host: pick('host'),
        username: pick('username'),
      }
      const os = patch.os !== undefined ? normalizeOs(patch.os) : prev.os
      const updatedAt = nowIso()
      const next = {
        ...prev,
        ...identity,
        os,
        severity: patch.severity !== undefined ? normalizeSeverity(patch.severity) : (prev.severity ?? null),
        name: hasIdentity(identity) ? deriveIncidentName(identity) : prev.name,
        suspiciousStart: patch.suspiciousStart !== undefined ? patch.suspiciousStart : prev.suspiciousStart,
        suspiciousEnd: patch.suspiciousEnd !== undefined ? patch.suspiciousEnd : prev.suspiciousEnd,
        updatedAt,
      }
      commit(incidentId, () => next)
      audit('incident.update', `Updated attributes of "${next.name}"`, next)
    },
    [audit, commit],
  )

  const deleteIncident = useCallback(
    (incidentId) => {
      const target = incidentsRef.current.find((i) => i.id === incidentId) ?? null
      const remaining = incidentsRef.current.filter((i) => i.id !== incidentId)
      setIncidents(remaining)
      forgetDocument(incidentId)
      // If the deleted incident was open, fall back to the newest remaining one
      // (or none) and update the permalink to match.
      if (activeIncidentIdRef.current === incidentId) {
        const next = remaining[0]?.id ?? null
        setActiveIncidentId(next)
        syncUrl(next, { replace: true })
      }
      if (target) audit('incident.delete', `Deleted incident "${target.name}"`, target)
      api
        .del(`/incidents/${incidentId}`)
        .then(() => setStorageError(null))
        .catch((err) => setStorageError(err?.message || 'Unable to delete the incident on the server.'))
    },
    [audit, forgetDocument],
  )

  const selectIncident = useCallback((incidentId) => {
    setActiveIncidentId(incidentId)
    syncUrl(incidentId)
  }, [])

  /* ---- generic tab data ---- */

  const updateTabData = useCallback(
    (incidentId, dataKey, patch) => {
      const prev = find(incidentId)
      if (!prev) return
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        [dataKey]: { ...(prev.data?.[dataKey] ?? {}), ...patch },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
    },
    [commit],
  )

  const clearTabData = useCallback(
    (incidentId, dataKey) => {
      const prev = find(incidentId)
      if (!prev) return
      const defaults = buildDefaultIncidentData()
      const updatedAt = nowIso()
      const data = { ...prev.data, [dataKey]: defaults[dataKey] ?? {} }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
    },
    [commit],
  )

  /* ---- per-browser, per-profile data ---- */

  /** Shallow-merge `patch` into ONE profile of a browser (e.g. after an upload). */
  const updateBrowserData = useCallback(
    (incidentId, browserId, profileId, patch, auditInfo) => {
      const prev = find(incidentId)
      if (!prev) return
      const updatedAt = nowIso()
      const data = withBrowserProfile(prev.data, browserId, profileId, (profile) => ({
        ...profile,
        ...patch,
      }))
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      if (auditInfo) audit(auditInfo.action, auditInfo.details, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  // View preference only: update the active browser locally and DO NOT call the
  // API (avoids re-sending the large `data` blob just to change a tab).
  const setActiveBrowser = useCallback(
    (incidentId, browserId) => {
      commit(
        incidentId,
        (i) => ({ ...i, data: { ...i.data, browser: { ...i.data.browser, activeBrowser: browserId } } }),
        { local: true },
      )
    },
    [commit],
  )

  // View preference only, like setActiveBrowser: never sent on its own.
  const setActiveProfile = useCallback(
    (incidentId, browserId, profileId) => {
      commit(
        incidentId,
        (i) => ({ ...i, data: withBrowserSlot(i.data, browserId, (slot) => ({ ...slot, activeProfile: profileId })) }),
        { local: true },
      )
    },
    [commit],
  )

  /** Create a profile in a browser and make it active. Returns its id, or null. */
  const addBrowserProfile = useCallback(
    (incidentId, browserId, name) => {
      const prev = find(incidentId)
      if (!prev) return null
      const slot = prev.data.browser.browsers[browserId]
      if (profileNameError(slot, name)) return null
      const browser = getBrowserById(browserId) ?? BROWSERS[0]
      const profile = buildDefaultProfileData(browser, { id: generateId(), name: name.trim(), createdAt: nowIso() })
      const updatedAt = nowIso()
      const data = withBrowserSlot(prev.data, browserId, (current) => ({
        ...current,
        activeProfile: profile.id,
        profiles: { ...current.profiles, [profile.id]: profile },
      }))
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('browser.profile.add', `Added ${browserId} profile "${profile.name}"`, { ...prev, updatedAt, data })
      return profile.id
    },
    [audit, commit],
  )

  const renameBrowserProfile = useCallback(
    (incidentId, browserId, profileId, name) => {
      const prev = find(incidentId)
      const profile = prev?.data.browser.browsers[browserId]?.profiles[profileId]
      if (!profile || profileNameError(prev.data.browser.browsers[browserId], name, profileId)) return
      const updatedAt = nowIso()
      const newName = name.trim()
      const data = withBrowserProfile(prev.data, browserId, profileId, (p) => ({ ...p, name: newName }))
      // Flags remember the profile name, so they stay readable if it is deleted.
      const flags = { ...prev.flags }
      for (const [key, flag] of Object.entries(flags)) {
        if (flag.browserId === browserId && flag.profileId === profileId) {
          flags[key] = { ...flag, profileName: newName }
        }
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data, flags }))
      audit('browser.profile.rename', `Renamed ${browserId} profile "${profile.name}" to "${newName}"`, {
        ...prev,
        updatedAt,
        data,
      })
    },
    [audit, commit],
  )

  /**
   * Delete a profile and its data (a browser always keeps at least one).
   * Flags on its rows are kept: they are investigative decisions, and the
   * timeline marks them as coming from a deleted profile.
   */
  const deleteBrowserProfile = useCallback(
    (incidentId, browserId, profileId) => {
      const prev = find(incidentId)
      const slot = prev?.data.browser.browsers[browserId]
      const profile = slot?.profiles[profileId]
      if (!profile || Object.keys(slot.profiles).length < 2) return
      const updatedAt = nowIso()
      const data = withBrowserSlot(prev.data, browserId, (current) => {
        const { [profileId]: _deleted, ...profiles } = current.profiles
        const rest = { ...current, profiles }
        return {
          ...rest,
          activeProfile: profiles[current.activeProfile] ? current.activeProfile : sortedProfiles(rest)[0].id,
        }
      })
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('browser.profile.delete', `Deleted ${browserId} profile "${profile.name}" and its data`, {
        ...prev,
        updatedAt,
        data,
      })
    },
    [audit, commit],
  )

  /** Clear ALL data of one profile (the profile itself stays). */
  const clearBrowserData = useCallback(
    (incidentId, browserId, profileId) => {
      const prev = find(incidentId)
      const profile = prev?.data.browser.browsers[browserId]?.profiles[profileId]
      if (!profile) return
      const updatedAt = nowIso()
      const data = withBrowserProfile(prev.data, browserId, profileId, (p, browser) =>
        buildDefaultProfileData(browser, { id: p.id, name: p.name, createdAt: p.createdAt }),
      )
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('browser.clear', `Cleared ${browserId} profile "${profile.name}" data`, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  const removeBrowserSource = useCallback(
    (incidentId, browserId, profileId, sourceKey, producedKeys = []) => {
      const prev = find(incidentId)
      const profile = prev?.data.browser.browsers[browserId]?.profiles[profileId]
      if (!profile) return
      const updatedAt = nowIso()
      const data = withBrowserProfile(prev.data, browserId, profileId, (p) => {
        const cleared = { ...p, meta: { ...p.meta, [sourceKey]: null } }
        for (const key of producedKeys) cleared[key] = []
        return cleared
      })
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('browser.removeFile', `Removed ${browserId} profile "${profile.name}" file (${sourceKey})`, {
        ...prev,
        updatedAt,
        data,
      })
    },
    [audit, commit],
  )

  /* ---- per-shell command data (Command History tab) ---- */

  const updateShellData = useCallback(
    (incidentId, shellId, patch, auditInfo) => {
      const prev = find(incidentId)
      if (!prev) return
      const commands = prev.data.commands
      const current = commands.shells[shellId] ?? buildDefaultShellData()
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        commands: {
          ...commands,
          shells: { ...commands.shells, [shellId]: { ...current, ...patch } },
        },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      if (auditInfo) audit(auditInfo.action, auditInfo.details, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  // View preference only (like setActiveBrowser): never re-sends the data blob.
  const setActiveShell = useCallback(
    (incidentId, shellId) => {
      commit(
        incidentId,
        (i) => ({ ...i, data: { ...i.data, commands: { ...i.data.commands, activeShell: shellId } } }),
        { local: true },
      )
    },
    [commit],
  )

  const clearShellData = useCallback(
    (incidentId, shellId) => {
      const prev = find(incidentId)
      if (!prev) return
      const def = buildDefaultShellData()
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        commands: {
          ...prev.data.commands,
          shells: { ...prev.data.commands.shells, [shellId]: def },
        },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('command.clear', `Cleared ${shellId} command history`, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  /* ---- per-source endpoint artifact data (Endpoint Artifacts tab) ---- */

  /** Replace ONE source's records+meta within a category. */
  const updateArtifactSource = useCallback(
    (incidentId, categoryId, sourceKey, patch, auditInfo) => {
      const prev = find(incidentId)
      if (!prev) return
      const endpoint = prev.data.endpoint
      const cat = endpoint.categories[categoryId] ?? { sources: {} }
      const currentSource = cat.sources[sourceKey] ?? { records: [], meta: null }
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        endpoint: {
          ...endpoint,
          categories: {
            ...endpoint.categories,
            [categoryId]: {
              ...cat,
              sources: { ...cat.sources, [sourceKey]: { ...currentSource, ...patch } },
            },
          },
        },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      if (auditInfo) audit(auditInfo.action, auditInfo.details, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  /** Clear ONE source within a category. */
  const clearArtifactSource = useCallback(
    (incidentId, categoryId, sourceKey) => {
      const prev = find(incidentId)
      if (!prev) return
      const endpoint = prev.data.endpoint
      const cat = endpoint.categories[categoryId] ?? { sources: {} }
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        endpoint: {
          ...endpoint,
          categories: {
            ...endpoint.categories,
            [categoryId]: {
              ...cat,
              sources: { ...cat.sources, [sourceKey]: { records: [], meta: null } },
            },
          },
        },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('endpoint.clearSource', `Cleared ${categoryId}/${sourceKey}`, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  /** Clear ALL sources of a category. */
  const clearArtifactCategory = useCallback(
    (incidentId, categoryId) => {
      const prev = find(incidentId)
      if (!prev) return
      const category = getArtifactCategoryById(categoryId)
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        endpoint: {
          ...prev.data.endpoint,
          categories: {
            ...prev.data.endpoint.categories,
            [categoryId]: category ? buildDefaultArtifactData(category) : { sources: {} },
          },
        },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('endpoint.clear', `Cleared ${categoryId} artifacts`, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  /** Save the incident's report options (a top-level `report` key). */
  const updateReportSettings = useCallback(
    (incidentId, report) => {
      const prev = find(incidentId)
      if (!prev) return
      commit(incidentId, (i) => ({ ...i, updatedAt: nowIso(), report: { ...(i.report ?? {}), ...report } }))
    },
    [commit],
  )

  /* ---- Windows event logs (data.eventlogs.channels) ---- */

  /**
   * Store parsed channels (from the collection script's JSON or demo data),
   * replacing those with the same name. Raw .evtx files are parsed on the
   * server, which writes the incident itself; see reloadActiveIncident.
   */
  const setEventLogChannels = useCallback(
    (incidentId, channels, auditInfo) => {
      const prev = find(incidentId)
      if (!prev) return
      const updatedAt = nowIso()
      const current = prev.data.eventlogs?.channels ?? {}
      const data = { ...prev.data, eventlogs: { ...prev.data.eventlogs, channels: { ...current, ...channels } } }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      if (auditInfo) audit(auditInfo.action, auditInfo.details, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  /** Remove one channel, or every channel when `channel` is null. */
  const clearEventLogs = useCallback(
    (incidentId, channel = null) => {
      const prev = find(incidentId)
      if (!prev) return
      const updatedAt = nowIso()
      const { [channel]: _removed, ...rest } = prev.data.eventlogs?.channels ?? {}
      const data = { ...prev.data, eventlogs: { ...prev.data.eventlogs, channels: channel ? rest : {} } }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('eventlog.clear', channel ? `Cleared event log ${channel}` : 'Cleared all event logs', {
        ...prev,
        updatedAt,
        data,
      })
    },
    [audit, commit],
  )

  /* ---- flagging (mark entries as part of malicious activity) ---- */

  /**
   * Toggle a flag on an entry. `flaggable`:
   *   { key, browserId, section, eventType, title, url, time }
   */
  /* ---- malware samples (the server owns the store; see routers/samples.py) ---- */

  /**
   * Record a sample reference the server already attached to the incident
   * (POST /incidents/{id}/samples wrote it), so the local copy matches
   * without a second PATCH.
   */
  const attachSample = useCallback(
    (incidentId, ref) => {
      const prev = find(incidentId)
      if (!prev) return
      const samples = prev.data.malware?.samples ?? []
      if (samples.some((s) => s.sha256 === ref.sha256)) return
      const data = { ...prev.data, malware: { ...(prev.data.malware ?? {}), samples: [...samples, ref] } }
      commit(incidentId, (i) => ({ ...i, updatedAt: ref.importedAt ?? nowIso(), data }), { local: true })
    },
    [commit],
  )

  /** Detach a sample: the server removes the reference (and the file, when unused). */
  const detachSample = useCallback(
    async (incidentId, sha256) => {
      const prev = find(incidentId)
      if (!prev) return
      await api.del(`/incidents/${encodeURIComponent(incidentId)}/samples/${sha256}`)
      const samples = (prev.data.malware?.samples ?? []).filter((s) => s.sha256 !== sha256)
      const data = { ...prev.data, malware: { ...(prev.data.malware ?? {}), samples } }
      commit(incidentId, (i) => ({ ...i, updatedAt: nowIso(), data }), { local: true })
    },
    [commit],
  )

  const toggleFlag = useCallback(
    (incidentId, flaggable) => {
      const incident = find(incidentId)
      if (!incident) return
      const wasFlagged = Boolean(incident.flags[flaggable.key])
      const flags = { ...incident.flags }
      if (flags[flaggable.key]) {
        delete flags[flaggable.key]
      } else {
        flags[flaggable.key] = {
          ...flaggable,
          flaggedAt: nowIso(),
          flaggedBy: actor,
          comments: [],
        }
      }
      const updatedAt = nowIso()
      commit(incidentId, (i) => ({ ...i, updatedAt, flags }))
      const label = flaggable.title || flaggable.url || flaggable.key
      audit(wasFlagged ? 'flag.remove' : 'flag.add', `${wasFlagged ? 'Unflagged' : 'Flagged'}: ${label}`, incident)
    },
    [actor, audit, commit],
  )

  const addFlagComment = useCallback(
    (incidentId, flagKey, text) => {
      const body = text?.trim()
      if (!body) return
      const incident = find(incidentId)
      if (!incident || !incident.flags[flagKey]) return
      const comment = { id: generateId(), text: body, at: nowIso(), author: actor }
      const flag = incident.flags[flagKey]
      const flags = {
        ...incident.flags,
        [flagKey]: { ...flag, comments: [...(flag.comments ?? []), comment] },
      }
      const updatedAt = nowIso()
      commit(incidentId, (i) => ({ ...i, updatedAt, flags }))
      audit('flag.comment', 'Commented a flagged entry', incident)
    },
    [actor, audit, commit],
  )

  const removeFlagComment = useCallback(
    (incidentId, flagKey, commentId) => {
      const incident = find(incidentId)
      if (!incident || !incident.flags[flagKey]) return
      const flag = incident.flags[flagKey]
      const flags = {
        ...incident.flags,
        [flagKey]: { ...flag, comments: (flag.comments ?? []).filter((c) => c.id !== commentId) },
      }
      const updatedAt = nowIso()
      commit(incidentId, (i) => ({ ...i, updatedAt, flags }))
      audit('flag.comment.remove', 'Removed a comment from a flagged entry', incident)
    },
    [audit, commit],
  )

  /* ---- free-form note blocks (shown on the Summary timeline) ---- */

  const addNote = useCallback(
    (incidentId, text) => {
      const body = text?.trim()
      if (!body) return
      const incident = find(incidentId)
      if (!incident) return
      const note = { id: generateId(), text: body, createdAt: nowIso(), updatedAt: nowIso(), author: actor }
      const notes = [...incident.notes, note]
      const updatedAt = nowIso()
      commit(incidentId, (i) => ({ ...i, updatedAt, notes }))
      audit('note.add', 'Added a note', incident)
    },
    [actor, audit, commit],
  )

  const updateNote = useCallback(
    (incidentId, noteId, text) => {
      const body = text?.trim()
      if (!body) return
      const incident = find(incidentId)
      if (!incident) return
      const notes = incident.notes.map((n) => (n.id === noteId ? { ...n, text: body, updatedAt: nowIso() } : n))
      const updatedAt = nowIso()
      commit(incidentId, (i) => ({ ...i, updatedAt, notes }))
      audit('note.update', 'Edited a note', incident)
    },
    [audit, commit],
  )

  const removeNote = useCallback(
    (incidentId, noteId) => {
      const incident = find(incidentId)
      if (!incident) return
      const notes = incident.notes.filter((n) => n.id !== noteId)
      const updatedAt = nowIso()
      commit(incidentId, (i) => ({ ...i, updatedAt, notes }))
      audit('note.remove', 'Removed a note', incident)
    },
    [audit, commit],
  )

  /* ---- export / import ---- */

  const exportIncident = useCallback(
    async (incidentId) => {
      let incident = find(incidentId)
      if (!incident) {
        // Not opened yet in this session: fetch the full document first.
        try {
          incident = normalizeIncident(await api.get(`/incidents/${encodeURIComponent(incidentId)}`))
        } catch (err) {
          setStorageError(err?.message || 'Unable to load the incident to export it.')
          return
        }
        storeDocument(incident)
      }
      const safeName = incident.name
        .toLowerCase()
        .replace(/[^a-z0-9]+/gi, '-')
        .replace(/^-+|-+$/g, '')
      downloadJson(`nik-${safeName || 'incident'}.json`, {
        app: 'Nik',
        version: 4, // 4 = browser profiles (2.0.0); older versions are still imported
        exportedAt: nowIso(),
        incident,
      })
      audit('incident.export', `Exported incident "${incident.name}"`, incident)
    },
    [audit, storeDocument],
  )

  const importIncidentFromFile = useCallback(
    async (file) => {
      let parsed
      try {
        parsed = JSON.parse(await file.text())
      } catch {
        throw new Error('Invalid file: the content is not JSON.')
      }
      // Accept the v3/v4 envelope, the older "project" envelope, or a bare
      // object; normalizeIncident() converts pre-profile browser data.
      const raw = parsed?.incident ?? parsed?.project ?? parsed
      if (typeof raw?.data !== 'object' || raw?.data === null) {
        throw new Error('Unrecognized file: a Nik export with a "data" field is expected.')
      }
      const incident = normalizeIncident({ ...raw, id: generateId(), updatedAt: nowIso() })
      storeDocument(incident, { prepend: true })
      setActiveIncidentId(incident.id)
      syncUrl(incident.id)
      audit('incident.import', `Imported incident "${incident.name}"`, incident)
      // Persist the imported incident as a new document on the server.
      api
        .post('/incidents', incident)
        .then(() => setStorageError(null))
        .catch((err) => setStorageError(err?.message || 'Unable to save the imported incident.'))
      return incident
    },
    [audit, storeDocument],
  )

  const value = {
    incidents,
    activeIncident,
    activeIncidentId,
    activeSummary,
    activeLoading,
    activeLoadError,
    activeLoadProgress,
    retryActiveIncident,
    setEventLogChannels,
    clearEventLogs,
    updateReportSettings,
    whenSaved,
    loading,
    storageError,
    createIncident,
    updateIncidentMeta,
    deleteIncident,
    selectIncident,
    updateTabData,
    clearTabData,
    updateBrowserData,
    setActiveBrowser,
    setActiveProfile,
    addBrowserProfile,
    renameBrowserProfile,
    deleteBrowserProfile,
    clearBrowserData,
    removeBrowserSource,
    updateShellData,
    setActiveShell,
    clearShellData,
    updateArtifactSource,
    clearArtifactSource,
    clearArtifactCategory,
    attachSample,
    detachSample,
    toggleFlag,
    addFlagComment,
    removeFlagComment,
    addNote,
    updateNote,
    removeNote,
    exportIncident,
    importIncidentFromFile,
  }

  return <IncidentContext.Provider value={value}>{children}</IncidentContext.Provider>
}

export function useIncidents() {
  const ctx = useContext(IncidentContext)
  if (!ctx) throw new Error('useIncidents must be used inside <IncidentProvider>')
  return ctx
}
