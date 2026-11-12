import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api, NOT_MODIFIED } from '../services/api.js'
import { MERGE_PATCH_CONTENT_TYPE } from '../lib/mergePatch.js'
import { createSaveQueue } from '../services/saveQueue.js'
import { buildDefaultIncidentData } from '../config/tabs.js'
import {
  BROWSERS,
  getBrowserById,
  buildDefaultBrowserData,
  buildDefaultBrowsersMap,
  buildDefaultProfileData,
} from '../config/browsers.js'
import { normalizeBrowserSlot, profileNameError, sortedProfiles } from '../domain/browserProfiles.js'
import { SHELLS, getShellById, buildDefaultShellData, buildDefaultShellsMap } from '../config/shells.js'
import {
  ARTIFACT_CATEGORIES,
  getArtifactCategoryById,
  categorySourceKeys,
  buildDefaultArtifactData,
  buildDefaultArtifactsMap,
} from '../config/artifacts.js'
import { normalizeOs } from '../config/os.js'
import { generateId } from '../lib/id.js'
import { deriveIncidentName, hasIdentity, normalizeSeverity, normalizeStatus } from '../domain/incidentName.js'
import { useAuth } from './AuthContext.jsx'
import { onLocationChange, setPath } from '../lib/location.js'
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
 *   status,               // 'open' | 'in_progress' | 'closed' — where the work stands
 *   assignee,             // username of the analyst who has it, or ''
 *   os,                   // 'windows' | 'macos' | 'linux' — the host OS
 *   name,                 // derived: "[ticket] title" | "[ticket] host - username" …
 *   suspiciousStart,      // Unix ms | null — start of suspicious activity
 *   suspiciousEnd,        // Unix ms | null — end of suspicious activity
 *   createdAt, updatedAt, createdBy,
 *   data: { summary, browser, commands, endpoint, malware, mail, eventlogs, network },
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
 * hands the incident to the save queue (services/saveQueue.js), which persists
 * ONLY what changed, as an RFC 7396 JSON Merge Patch computed by diffing the
 * document against the last version the server holds (unchanged subtrees share
 * references, so toggling a flag sends the flag, not the artifact arrays). The
 * queue sends one save at a time with `If-Match`, retries what fails and, when
 * somebody else saved meanwhile (412), merges their version with the local
 * changes instead of overwriting it:
 *   - createIncident / import     → POST   /incidents        (full doc)
 *   - deleteIncident              → DELETE /incidents/{id}
 *   - every other mutation        → PATCH  /incidents/{id}   (merge patch)
 *   - setActiveBrowser/Shell      → LOCAL ONLY (a view preference; never sent)
 *
 * The audit trail is written by the server, from the requests it receives:
 * nothing here reports what it did, except an export (a file built in the
 * browser, which the server never sees).
 *
 * IMPORTANT: commit() is always called from event-handler scope, NEVER inside
 * a state updater — React state updaters must be pure, and StrictMode
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
    status: normalizeStatus(raw.status),
    assignee: typeof raw.assignee === 'string' ? raw.assignee.trim() : '',
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
  // Announced, so an artifact or the IoC library open in the main area leaves it.
  setPath(path, { replace, state: { incidentId: incidentId ?? null } })
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
    status: normalizeStatus(incident.status),
    assignee: incident.assignee ?? '',
    hasMail: (incident.data?.mail?.messages?.length ?? 0) > 0,
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
    status: normalizeStatus(raw.status),
    assignee: typeof raw.assignee === 'string' ? raw.assignee : '',
    hasMail: raw.hasMail === true,
    createdAt: raw.createdAt ?? '',
    updatedAt: raw.updatedAt ?? '',
  }
}

/**
 * A version read from the server, with this client's view preferences (the
 * open browser, profile and shell) kept as they are here: they are never
 * saved, so the server's copy must not move them.
 */
function keepViewPreferences(remote, local) {
  const browser = remote.data.browser
  const mine = local.data?.browser
  const browsers = {}
  for (const [id, slot] of Object.entries(browser.browsers)) {
    const wanted = mine?.browsers?.[id]?.activeProfile
    browsers[id] = wanted && slot.profiles?.[wanted] ? { ...slot, activeProfile: wanted } : slot
  }
  return {
    ...remote,
    data: {
      ...remote.data,
      browser: { ...browser, activeBrowser: mine?.activeBrowser ?? browser.activeBrowser, browsers },
      commands: {
        ...remote.data.commands,
        activeShell: local.data?.commands?.activeShell ?? remote.data.commands.activeShell,
      },
    },
  }
}

const incidentPath = (incidentId) => `/incidents/${encodeURIComponent(incidentId)}`
// A window that regains the focus checks the open incident again, at most this often.
const REVALIDATE_EVERY_MS = 15000

export function IncidentProvider({ children }) {
  const { currentUser, isAuthenticated, sessionExpired } = useAuth()
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
  // A request outside the save queue that failed (create, delete, list).
  const [requestError, setStorageError] = useState(null)
  // What the save queue reports: changes not on the server yet, and why.
  const [saveState, setSaveState] = useState({ pending: false, error: null })
  // Usernames an incident can be assigned to.
  const [assignees, setAssignees] = useState([])
  // Bumped by refreshIncidents(): the accounts changed (a rename moves the assigned incidents).
  const [accountsToken, setAccountsToken] = useState(0)
  useEffect(() => {
    if (!isAuthenticated) return undefined
    let cancelled = false
    api
      .get('/users/names')
      .then((res) => {
        if (!cancelled) setAssignees(Array.isArray(res?.names) ? res.names : [])
      })
      // The fields still work without the list: the assignee is typed by hand.
      .catch(() => {
        if (!cancelled) setAssignees([])
      })
    return () => {
      cancelled = true
    }
  }, [isAuthenticated, accountsToken])

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

  // The save queue: created once, it reads and writes the live snapshot.
  const queueRef = useRef(null)
  if (queueRef.current === null) {
    queueRef.current = createSaveQueue({
      send: async (incidentId, patch, etag) => {
        let next = null
        await api.patch(incidentPath(incidentId), patch, {
          contentType: MERGE_PATCH_CONTENT_TYPE,
          headers: etag ? { 'If-Match': etag } : {},
          onHeaders: (headers) => {
            next = headers.get('ETag')
          },
        })
        return { etag: next }
      },
      load: async (incidentId, etag) => {
        let next = null
        const res = await api.get(incidentPath(incidentId), {
          headers: etag ? { 'If-None-Match': etag } : {},
          onHeaders: (headers) => {
            next = headers.get('ETag')
          },
        })
        return res === NOT_MODIFIED || !res ? null : { doc: normalizeIncident(res), etag: next }
      },
      getLocal: (incidentId) => documentsRef.current[incidentId] ?? null,
      setLocal: (_incidentId, incident) => storeDocument(incident),
      prepare: keepViewPreferences,
      onChange: () => {
        const { pending, error } = queueRef.current.status()
        setSaveState((state) => (state.pending === pending && state.error === error ? state : { pending, error }))
      },
    })
  }
  const queue = queueRef.current

  // Signed in again after the session ended: send what was waiting.
  const wasExpiredRef = useRef(false)
  useEffect(() => {
    if (wasExpiredRef.current && !sessionExpired && isAuthenticated) queue.retry()
    wasExpiredRef.current = sessionExpired
  }, [sessionExpired, isAuthenticated, queue])

  // Closing the tab with changes that are not on the server yet asks first.
  useEffect(() => {
    if (!saveState.pending) return undefined
    const warn = (event) => {
      event.preventDefault()
      event.returnValue = ''
    }
    window.addEventListener('beforeunload', warn)
    return () => window.removeEventListener('beforeunload', warn)
  }, [saveState.pending])

  // Browser back/forward: follow the URL to the corresponding incident.
  useEffect(() => {
    // An artifact's permalink (/artifact/<id>) keeps the active incident as it is.
    const onPopState = () => {
      // An indicator's page (/ioc/…) is drawn over the incident and the library (/iocs…)
      // replaces it in the main area: the active incident stays as it is too.
      if (!/^\/(artifact|iocs?)(\/|$)/.test(window.location.pathname)) setActiveIncidentId(incidentIdFromUrl())
    }
    return onLocationChange(onPopState)
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
      queue.clear()
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
  }, [isAuthenticated, queue])

  // Fetch the active incident's full document on demand. A copy already in the
  // cache is shown immediately and checked in the background by the save queue
  // (`If-None-Match`: an unchanged incident costs a tiny 304, a changed one is
  // merged with what was edited here). Switching to another incident aborts a
  // pending first download.
  const lastCheckRef = useRef(0)
  useEffect(() => {
    if (loading || !activeIncidentId) return undefined
    setActiveLoadError(null)
    setActiveLoadProgress(null)
    lastCheckRef.current = Date.now()
    if (documentsRef.current[activeIncidentId] && queue.isTracked(activeIncidentId)) {
      queue.refresh(activeIncidentId)
      return undefined
    }
    // A document still being created on the server has nothing to download.
    if (documentsRef.current[activeIncidentId]) return undefined
    const controller = new AbortController()
    // Updates are throttled to every 64 KB to avoid a render per chunk.
    let lastReported = -Infinity
    const onProgress = ({ received, total }) => {
      if (controller.signal.aborted) return
      if (received - lastReported < 65536 && received !== total) return
      lastReported = received
      setActiveLoadProgress({ received, total })
    }
    let etag = null
    api
      .get(incidentPath(activeIncidentId), {
        signal: controller.signal,
        onProgress,
        onHeaders: (headers) => {
          etag = headers.get('ETag')
        },
      })
      .then((res) => {
        if (!res || documentsRef.current[activeIncidentId]) return
        const incident = normalizeIncident(res)
        storeDocument(incident)
        queue.track(incident.id, incident, etag)
      })
      .catch((err) => {
        if (controller.signal.aborted) return
        setActiveLoadError(err?.message || 'Unable to load the incident.')
      })
      .finally(() => {
        if (!controller.signal.aborted) setActiveLoadProgress(null)
      })
    return () => controller.abort()
  }, [activeIncidentId, loading, reloadToken, storeDocument, queue])

  // Coming back to the window: somebody may have worked on the incident meanwhile.
  useEffect(() => {
    const onFocus = () => {
      const active = activeIncidentIdRef.current
      if (!active || Date.now() - lastCheckRef.current < REVALIDATE_EVERY_MS) return
      lastCheckRef.current = Date.now()
      queue.refresh(active)
    }
    window.addEventListener('focus', onFocus)
    return () => window.removeEventListener('focus', onFocus)
  }, [queue])

  /**
   * Read the incident list and the assignable accounts again, and check the
   * open incident: an account was renamed, disabled or deleted.
   */
  const refreshIncidents = useCallback(() => {
    setAccountsToken((token) => token + 1)
    api
      .get('/incidents?view=summary')
      .then((res) => {
        const list = Array.isArray(res?.incidents) ? res.incidents : []
        setIncidents(list.filter((row) => row && row.id).map(normalizeSummary))
      })
      .catch((err) => setStorageError(err?.message || 'Unable to load incidents.'))
    if (activeIncidentIdRef.current) queue.refresh(activeIncidentIdRef.current)
  }, [queue])

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

  /** Record an action done in the browser alone (an export). Call ONLY from event-handler scope. */
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
   * Apply `updater` to a loaded incident, update local state immediately and
   * hand it to the save queue. With `local` the change is not sent: it is a
   * view preference, or something the server already wrote itself. Call ONLY
   * from event-handler scope.
   */
  const commit = useCallback(
    (incidentId, updater, { local = false } = {}) => {
      const prev = documentsRef.current[incidentId]
      if (!prev) return null
      const next = updater(prev)
      storeDocument(next)
      if (local) queue.adopt(incidentId, prev, next)
      else queue.touch(incidentId)
      return next
    },
    [queue, storeDocument],
  )

  /**
   * Save a new document (created or imported here) and start tracking it:
   * what was edited while the POST travelled is sent right after it.
   */
  const saveNew = useCallback(
    (incident, failure) => {
      let etag = null
      const saved = api
        .post('/incidents', incident, {
          onHeaders: (headers) => {
            etag = headers.get('ETag')
          },
        })
        .then(() => {
          setStorageError(null)
          queue.track(incident.id, incident, etag)
          queue.touch(incident.id)
          return true
        })
        .catch((err) => {
          setStorageError(err?.message || failure)
          return false
        })
      savedRef.current.set(incident.id, saved)
      return saved
    },
    [queue],
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
        status: 'open',
        assignee: '',
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
      // Persist the full document; the server stamps its own createdBy.
      saveNew(incident, 'Unable to create the incident on the server.')
      return incident
    },
    [actor, saveNew, storeDocument],
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
        status: normalizeStatus(patch.status !== undefined ? patch.status : prev.status),
        assignee: patch.assignee !== undefined ? String(patch.assignee ?? '').trim() : (prev.assignee ?? ''),
        name: hasIdentity(identity) ? deriveIncidentName(identity) : prev.name,
        suspiciousStart: patch.suspiciousStart !== undefined ? patch.suspiciousStart : prev.suspiciousStart,
        suspiciousEnd: patch.suspiciousEnd !== undefined ? patch.suspiciousEnd : prev.suspiciousEnd,
        updatedAt,
      }
      commit(incidentId, () => next)
    },
    [commit],
  )

  /**
   * Set the status and/or the assignee of any incident of the list, loaded
   * or not (the panel's menu works on rows whose document was never opened).
   */
  const setIncidentTriage = useCallback(
    (incidentId, patch) => {
      if (documentsRef.current[incidentId]) {
        updateIncidentMeta(incidentId, patch)
        return
      }
      const row = incidentsRef.current.find((incident) => incident.id === incidentId)
      if (!row) return
      const change = {
        status: normalizeStatus(patch.status !== undefined ? patch.status : row.status),
        assignee: patch.assignee !== undefined ? String(patch.assignee ?? '').trim() : (row.assignee ?? ''),
        updatedAt: nowIso(),
      }
      setIncidents((list) => list.map((item) => (item.id === incidentId ? { ...item, ...change } : item)))
      api
        .patch(incidentPath(incidentId), change, { contentType: MERGE_PATCH_CONTENT_TYPE })
        .then(() => setStorageError(null))
        .catch((err) => setStorageError(err?.message || 'Unable to save changes to the server.'))
    },
    [updateIncidentMeta],
  )

  /** Delete an incident: it leaves the list once the server has deleted it. */
  const deleteIncident = useCallback(
    async (incidentId) => {
      try {
        await api.del(incidentPath(incidentId))
      } catch (err) {
        setStorageError(err?.message || 'Unable to delete the incident on the server.')
        return false
      }
      setStorageError(null)
      queue.forget(incidentId)
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
      return true
    },
    [forgetDocument, queue],
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

  /**
   * Shallow-merge `patch` into ONE profile of a browser (e.g. after an upload).
   * `patch.meta` lists only the sources it changes: it is merged into the
   * profile as it is now, so two files parsed at once do not drop each other.
   */
  const updateBrowserData = useCallback(
    (incidentId, browserId, profileId, patch) => {
      const prev = find(incidentId)
      if (!prev) return
      const updatedAt = nowIso()
      const data = withBrowserProfile(prev.data, browserId, profileId, (profile) => ({
        ...profile,
        ...patch,
        meta: patch.meta ? { ...profile.meta, ...patch.meta } : profile.meta,
      }))
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
    },
    [commit],
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
      return profile.id
    },
    [commit],
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
    },
    [commit],
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
    },
    [commit],
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
    },
    [commit],
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
    },
    [commit],
  )

  /* ---- per-shell command data (Command History tab) ---- */

  const updateShellData = useCallback(
    (incidentId, shellId, patch) => {
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
    },
    [commit],
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
    },
    [commit],
  )

  /* ---- per-source endpoint artifact data (Endpoint Artifacts tab) ---- */

  /** Replace ONE source's records+meta within a category. */
  const updateArtifactSource = useCallback(
    (incidentId, categoryId, sourceKey, patch) => {
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
    },
    [commit],
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
    },
    [commit],
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
    },
    [commit],
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
   * Store parsed channels (from the collection script's JSON),
   * replacing those with the same name. Raw .evtx files are parsed on the
   * server, which writes the incident itself; see reloadActiveIncident.
   */
  const setEventLogChannels = useCallback(
    (incidentId, channels) => {
      const prev = find(incidentId)
      if (!prev) return
      const updatedAt = nowIso()
      const current = prev.data.eventlogs?.channels ?? {}
      const data = { ...prev.data, eventlogs: { ...prev.data.eventlogs, channels: { ...current, ...channels } } }
      commit(incidentId, (i) => ({ ...i, updatedAt, data }))
    },
    [commit],
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
    },
    [commit],
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
      if (!find(incidentId)) return
      await api.del(`${incidentPath(incidentId)}/samples/${sha256}`)
      // Built on the document as it is now: it may have changed while the server answered.
      commit(
        incidentId,
        (i) => ({
          ...i,
          updatedAt: nowIso(),
          data: {
            ...i.data,
            malware: {
              ...(i.data.malware ?? {}),
              samples: (i.data.malware?.samples ?? []).filter((s) => s.sha256 !== sha256),
            },
          },
        }),
        { local: true },
      )
    },
    [commit],
  )

  /** Attach an analysed e-mail's reference (already stored by the server). */
  const attachMail = useCallback(
    (incidentId, ref) => {
      const prev = find(incidentId)
      if (!prev) return
      const messages = prev.data.mail?.messages ?? []
      if (messages.some((m) => m.sha256 === ref.sha256)) return
      const data = { ...prev.data, mail: { ...(prev.data.mail ?? {}), messages: [...messages, ref] } }
      commit(incidentId, (i) => ({ ...i, updatedAt: ref.importedAt ?? nowIso(), data }), { local: true })
    },
    [commit],
  )

  /** Detach an e-mail: the server removes the reference (and the file, when unused). */
  const detachMail = useCallback(
    async (incidentId, sha256) => {
      if (!find(incidentId)) return
      await api.del(`${incidentPath(incidentId)}/mails/${sha256}`)
      commit(
        incidentId,
        (i) => ({
          ...i,
          updatedAt: nowIso(),
          data: {
            ...i.data,
            mail: {
              ...(i.data.mail ?? {}),
              messages: (i.data.mail?.messages ?? []).filter((m) => m.sha256 !== sha256),
            },
          },
        }),
        { local: true },
      )
    },
    [commit],
  )

  /** Add or refresh a network capture's reference (the server already stored it). */
  const putCapture = useCallback(
    (incidentId, ref) => {
      const prev = find(incidentId)
      if (!prev) return
      const captures = prev.data.network?.captures ?? []
      const next = captures.some((c) => c.id === ref.id)
        ? captures.map((c) => (c.id === ref.id ? ref : c))
        : [...captures, ref]
      const data = { ...prev.data, network: { ...(prev.data.network ?? {}), captures: next } }
      commit(incidentId, (i) => ({ ...i, data }), { local: true })
    },
    [commit],
  )

  /** Replace the capture references with the server's list (sessions opened elsewhere, new states). */
  const syncCaptures = useCallback(
    (incidentId, refs) => {
      const prev = find(incidentId)
      if (!prev) return
      const current = prev.data.network?.captures ?? []
      if (JSON.stringify(current) === JSON.stringify(refs)) return
      const data = { ...prev.data, network: { ...(prev.data.network ?? {}), captures: refs } }
      commit(incidentId, (i) => ({ ...i, data }), { local: true })
    },
    [commit],
  )

  /** Remove a network capture: the server deletes its files and analysis. */
  const removeCapture = useCallback(
    async (incidentId, captureId) => {
      if (!find(incidentId)) return
      await api.del(`${incidentPath(incidentId)}/captures/${captureId}`)
      commit(
        incidentId,
        (i) => ({
          ...i,
          updatedAt: nowIso(),
          data: {
            ...i.data,
            network: {
              ...(i.data.network ?? {}),
              captures: (i.data.network?.captures ?? []).filter((c) => c.id !== captureId),
            },
          },
        }),
        { local: true },
      )
    },
    [commit],
  )

  /**
   * Flag an entry, or remove its flag. Removing drops the flag's comments
   * with it, so that case returns `{ message, undo }` for the caller to offer.
   */
  const toggleFlag = useCallback(
    (incidentId, flaggable) => {
      const incident = find(incidentId)
      if (!incident) return null
      const removed = incident.flags[flaggable.key] ?? null
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
      if (!removed) return null
      const comments = removed.comments?.length ?? 0
      return {
        message: comments
          ? `Flag removed, with its ${comments === 1 ? 'comment' : `${comments} comments`}.`
          : 'Flag removed.',
        undo: () =>
          commit(incidentId, (i) =>
            i.flags[removed.key] ? i : { ...i, updatedAt: nowIso(), flags: { ...i.flags, [removed.key]: removed } },
          ),
      }
    },
    [actor, commit],
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
    },
    [actor, commit],
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
    },
    [commit],
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
    },
    [actor, commit],
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
    },
    [commit],
  )

  const removeNote = useCallback(
    (incidentId, noteId) => {
      const incident = find(incidentId)
      if (!incident) return
      const notes = incident.notes.filter((n) => n.id !== noteId)
      const updatedAt = nowIso()
      commit(incidentId, (i) => ({ ...i, updatedAt, notes }))
    },
    [commit],
  )

  /* ---- export / import ---- */

  const exportIncident = useCallback(
    async (incidentId) => {
      let incident = find(incidentId)
      if (!incident) {
        // Not opened yet in this session: fetch the full document first.
        let etag = null
        try {
          incident = normalizeIncident(
            await api.get(incidentPath(incidentId), {
              onHeaders: (headers) => {
                etag = headers.get('ETag')
              },
            }),
          )
        } catch (err) {
          setStorageError(err?.message || 'Unable to load the incident to export it.')
          return
        }
        storeDocument(incident)
        queue.track(incident.id, incident, etag)
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
    [audit, queue, storeDocument],
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
      // Persist the imported incident as a new document on the server.
      saveNew(incident, 'Unable to save the imported incident.')
      return incident
    },
    [saveNew, storeDocument],
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
    refreshIncidents,
    setEventLogChannels,
    clearEventLogs,
    updateReportSettings,
    whenSaved,
    loading,
    // Why the last save or request failed, and whether changes still wait to be saved.
    storageError: saveState.error ?? requestError,
    unsavedChanges: saveState.pending,
    retrySave: queue.retry,
    createIncident,
    updateIncidentMeta,
    setIncidentTriage,
    assignees,
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
    attachMail,
    detachMail,
    putCapture,
    syncCaptures,
    removeCapture,
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
