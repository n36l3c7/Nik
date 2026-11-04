import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react'
import { api, NOT_MODIFIED } from '../services/api.js'
import { createMergePatch, MERGE_PATCH_CONTENT_TYPE } from '../utils/mergePatch.js'
import { buildDefaultIncidentData } from '../config/tabs.js'
import {
  BROWSERS,
  getBrowserById,
  buildDefaultBrowserData,
  buildDefaultBrowsersMap,
} from '../config/browsers.js'
import {
  SHELLS,
  getShellById,
  buildDefaultShellData,
  buildDefaultShellsMap,
} from '../config/shells.js'
import {
  ARTIFACT_CATEGORIES,
  getArtifactCategoryById,
  categorySourceKeys,
  buildDefaultArtifactData,
  buildDefaultArtifactsMap,
} from '../config/artifacts.js'
import { normalizeOs } from '../config/os.js'
import { generateId } from '../utils/id.js'
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
 *   host, username,       // identity (NOT unique; the id is the DB key)
 *   os,                   // 'windows' | 'macos' | 'linux' — the host OS
 *   name,                 // derived: "host - username" | host | username
 *   suspiciousStart,      // Unix ms | null — start of suspicious activity
 *   suspiciousEnd,        // Unix ms | null — end of suspicious activity
 *   createdAt, updatedAt, createdBy,
 *   data: { summary, browser, commands, endpoint, network },
 *   flags: { [key]: { key, browserId, section, eventType, title, url, time,
 *                     flaggedAt, flaggedBy, comments: [...] } },
 *   notes: [ { id, text, createdAt, updatedAt, author } ],
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
export function deriveIncidentName(host, username) {
  const h = (host ?? '').trim()
  const u = (username ?? '').trim()
  if (h && u) return `${h} - ${u}`
  return h || u || 'Untitled incident'
}

/* ---- browser data normalization (per-browser + legacy migration) ---- */
function normalizeBrowserData(raw) {
  const fallback = { activeBrowser: BROWSERS[0].id, browsers: buildDefaultBrowsersMap() }
  if (!raw || typeof raw !== 'object') return fallback

  if (raw.browsers && typeof raw.browsers === 'object') {
    const browsers = buildDefaultBrowsersMap()
    for (const browser of BROWSERS) {
      const rb = raw.browsers[browser.id]
      if (rb && typeof rb === 'object') {
        const def = buildDefaultBrowserData(browser)
        browsers[browser.id] = {
          history: Array.isArray(rb.history) ? rb.history : [],
          downloads: Array.isArray(rb.downloads) ? rb.downloads : [],
          bookmarks: Array.isArray(rb.bookmarks) ? rb.bookmarks : [],
          shortcuts: Array.isArray(rb.shortcuts) ? rb.shortcuts : [],
          meta: { ...def.meta, ...(rb.meta ?? {}) },
        }
      }
    }
    return {
      activeBrowser: getBrowserById(raw.activeBrowser) ? raw.activeBrowser : BROWSERS[0].id,
      browsers,
    }
  }

  // Legacy single-browser shape → Chrome.
  if (Array.isArray(raw.history) || Array.isArray(raw.bookmarks) || Array.isArray(raw.shortcuts)) {
    const browsers = buildDefaultBrowsersMap()
    browsers.chrome = {
      history: Array.isArray(raw.history) ? raw.history : [],
      downloads: [],
      bookmarks: Array.isArray(raw.bookmarks) ? raw.bookmarks : [],
      shortcuts: Array.isArray(raw.shortcuts) ? raw.shortcuts : [],
      meta: {
        history: raw.meta?.history ?? null,
        bookmarks: raw.meta?.bookmarks ?? null,
        shortcuts: raw.meta?.shortcuts ?? null,
      },
    }
    return { activeBrowser: 'chrome', browsers }
  }

  return fallback
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

  const host = typeof raw.host === 'string' ? raw.host.trim() : ''
  const username = typeof raw.username === 'string' ? raw.username.trim() : ''
  // If no host/username but an old "name" exists, keep it as the display name.
  const name =
    host || username
      ? deriveIncidentName(host, username)
      : typeof raw.name === 'string' && raw.name.trim()
        ? raw.name.trim()
        : 'Untitled incident'

  return {
    id: typeof raw.id === 'string' && raw.id ? raw.id : generateId(),
    host,
    username,
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
    createdAt: incident.createdAt,
    updatedAt: incident.updatedAt,
  }
}

/** Normalize a summary row from the server (missing fields become defaults). */
function normalizeSummary(raw) {
  const host = typeof raw.host === 'string' ? raw.host.trim() : ''
  const username = typeof raw.username === 'string' ? raw.username.trim() : ''
  const name =
    typeof raw.name === 'string' && raw.name.trim()
      ? raw.name.trim()
      : deriveIncidentName(host, username)
  return {
    id: raw.id,
    name,
    host,
    username,
    os: normalizeOs(raw.os),
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
    api
      .get(`/incidents/${encodeURIComponent(activeIncidentId)}`, {
        signal: controller.signal,
        headers: cached ? { 'If-None-Match': etagOf(cached) } : {},
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
    ({ host, username, os } = {}) => {
      const now = nowIso()
      const incident = {
        id: generateId(),
        host: (host ?? '').trim(),
        username: (username ?? '').trim(),
        os: normalizeOs(os),
        name: deriveIncidentName(host, username),
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
      api
        .post('/incidents', incident)
        .then(() => setStorageError(null))
        .catch((err) => setStorageError(err?.message || 'Unable to create the incident on the server.'))
      return incident
    },
    [actor, audit, storeDocument],
  )

  /** Update incident identity/time attributes; recompute the display name. */
  const updateIncidentMeta = useCallback(
    (incidentId, patch) => {
      const prev = find(incidentId)
      if (!prev) return
      const host = patch.host !== undefined ? patch.host.trim() : prev.host
      const username = patch.username !== undefined ? patch.username.trim() : prev.username
      const os = patch.os !== undefined ? normalizeOs(patch.os) : prev.os
      const updatedAt = nowIso()
      const next = {
        ...prev,
        host,
        username,
        os,
        name: host || username ? deriveIncidentName(host, username) : prev.name,
        suspiciousStart:
          patch.suspiciousStart !== undefined ? patch.suspiciousStart : prev.suspiciousStart,
        suspiciousEnd:
          patch.suspiciousEnd !== undefined ? patch.suspiciousEnd : prev.suspiciousEnd,
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

  /* ---- per-browser data ---- */

  const updateBrowserData = useCallback(
    (incidentId, browserId, patch, auditInfo) => {
      const prev = find(incidentId)
      if (!prev) return
      const browser = prev.data.browser
      const current =
        browser.browsers[browserId] ??
        buildDefaultBrowserData(getBrowserById(browserId) ?? BROWSERS[0])
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        browser: {
          ...browser,
          browsers: { ...browser.browsers, [browserId]: { ...current, ...patch } },
        },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      if (auditInfo) audit(auditInfo.action, auditInfo.details, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  // View preference only: update the active browser locally and DO NOT call the
  // API (avoids re-sending the large `data` blob just to change a tab).
  const setActiveBrowser = useCallback(
    (incidentId, browserId) => {
      commit(incidentId, (i) => ({ ...i, data: { ...i.data, browser: { ...i.data.browser, activeBrowser: browserId } } }), { local: true })
    },
    [commit],
  )

  const clearBrowserData = useCallback(
    (incidentId, browserId) => {
      const prev = find(incidentId)
      if (!prev) return
      const def = buildDefaultBrowserData(getBrowserById(browserId) ?? BROWSERS[0])
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        browser: {
          ...prev.data.browser,
          browsers: { ...prev.data.browser.browsers, [browserId]: def },
        },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('browser.clear', `Cleared ${browserId} data`, { ...prev, updatedAt, data })
    },
    [audit, commit],
  )

  const removeBrowserSource = useCallback(
    (incidentId, browserId, sourceKey, producedKeys = []) => {
      const prev = find(incidentId)
      if (!prev) return
      const browsers = prev.data.browser.browsers
      const current = browsers[browserId]
      if (!current) return
      const cleared = { ...current, meta: { ...current.meta, [sourceKey]: null } }
      for (const key of producedKeys) cleared[key] = []
      const updatedAt = nowIso()
      const data = {
        ...prev.data,
        browser: { ...prev.data.browser, browsers: { ...browsers, [browserId]: cleared } },
      }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
      audit('browser.removeFile', `Removed ${browserId} file (${sourceKey})`, {
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
      commit(incidentId, (i) => ({ ...i, data: { ...i.data, commands: { ...i.data.commands, activeShell: shellId } } }), { local: true })
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

  /* ---- flagging (mark entries as part of malicious activity) ---- */

  /**
   * Toggle a flag on an entry. `flaggable`:
   *   { key, browserId, section, eventType, title, url, time }
   */
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
      audit(
        wasFlagged ? 'flag.remove' : 'flag.add',
        `${wasFlagged ? 'Unflagged' : 'Flagged'}: ${label}`,
        incident,
      )
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
      const notes = incident.notes.map((n) =>
        n.id === noteId ? { ...n, text: body, updatedAt: nowIso() } : n,
      )
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
          incident = normalizeIncident(
            await api.get(`/incidents/${encodeURIComponent(incidentId)}`),
          )
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
        version: 3,
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
      // Accept the v3 envelope, the older "project" envelope, or a bare object.
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
    retryActiveIncident,
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
    clearBrowserData,
    removeBrowserSource,
    updateShellData,
    setActiveShell,
    clearShellData,
    updateArtifactSource,
    clearArtifactSource,
    clearArtifactCategory,
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
