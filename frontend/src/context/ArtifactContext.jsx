import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api, upload } from '../services/api.js'
import { ARTIFACTS_ROOT, artifactIdFromPath, artifactKind, artifactPath } from '../domain/artifactRegistry.js'
import { freely, isOverlayPage, onLocationChange, setPath } from '../lib/location.js'
import { leave } from '../lib/unsaved.js'
import { useAuth } from './AuthContext.jsx'
import { transfer } from '../lib/transfers.js'

/*
 * ============================================================================
 * ARTIFACT CONTEXT — files, e-mails and captures analysed on their own
 * ============================================================================
 *
 * Holds the artifact list of the sidebar (filtered on the server), the
 * artifact open in the main area (permalink: /artifact/<id>) and the actions
 * on it: start an analysis, link and unlink incidents, tags, delete.
 *
 * The analyses themselves are read by the analysis tabs from /api/samples,
 * /api/mails and /api/captures; this context only knows the registry
 * (GET /api/artifacts).
 */

const ArtifactContext = createContext(null)
const EMPTY_FILTERS = { kind: '', q: '' }
const NO_COUNTS = { file: 0, mail: 0, pcap: 0, url: 0, mailbox: 0 }

const idFromUrl = () => (typeof window === 'undefined' ? null : artifactIdFromPath(window.location.pathname))

export function ArtifactProvider({ children }) {
  const { isAuthenticated: signedIn, can } = useAuth()
  const isAuthenticated = signedIn && can('read')
  const [artifacts, setArtifacts] = useState([])
  const [counts, setCounts] = useState(NO_COUNTS)
  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  // What the server said of the query in `filters.q`, when it could not read it.
  const [queryError, setQueryError] = useState(null)
  const [currentId, setCurrentId] = useState(idFromUrl)
  const [current, setCurrent] = useState(null) // summary + parents + children
  const [currentError, setCurrentError] = useState(null)
  const [version, setVersion] = useState(0) // bumped to reload the list and the open artifact
  const requestRef = useRef(0)

  const refresh = useCallback(() => setVersion((v) => v + 1), [])

  // The list, reloaded when the filters change (the text after a short pause).
  useEffect(() => {
    if (!isAuthenticated) {
      setArtifacts([])
      setCounts(NO_COUNTS)
      return undefined
    }
    const request = ++requestRef.current
    const timer = setTimeout(
      () => {
        const params = new URLSearchParams()
        if (filters.kind) params.set('kind', filters.kind)
        if (filters.q.trim()) params.set('q', filters.q.trim())
        setLoading(true)
        api
          .get(`/artifacts?${params}`)
          .then((res) => {
            if (request !== requestRef.current) return
            setArtifacts(res.artifacts)
            setCounts(res.counts)
            setError(null)
            setQueryError(null)
          })
          .catch((err) => {
            if (request !== requestRef.current) return
            // A query that cannot be read is said next to the input; the list stays.
            if (err.query) setQueryError(err.query)
            else setError(err.message)
          })
          .finally(() => request === requestRef.current && setLoading(false))
      },
      filters.q ? 250 : 0,
    )
    return () => clearTimeout(timer)
  }, [isAuthenticated, filters, version])

  // The open artifact.
  useEffect(() => {
    if (!isAuthenticated || !currentId) {
      setCurrent(null)
      setCurrentError(null)
      return undefined
    }
    let cancelled = false
    api
      .get(`/artifacts/${currentId}`)
      .then((doc) => !cancelled && (setCurrent(doc), setCurrentError(null)))
      .catch((err) => !cancelled && (setCurrent(null), setCurrentError(err.message)))
    return () => {
      cancelled = true
    }
  }, [isAuthenticated, currentId, version])

  // Back and forward move between artifacts and incidents.
  useEffect(() => {
    // The address decides: another page (an incident, the Indicators page) leaves the artifact.
    const onPopState = () => {
      if (!isOverlayPage(window.location.pathname)) setCurrentId(idFromUrl())
    }
    return onLocationChange(onPopState)
  }, [])

  const openArtifact = useCallback((id) => {
    // It takes the place of what is open: what is not saved there is asked about first.
    leave(
      () => {
        setCurrentId(id)
        setPath(artifactPath(id), { state: { artifactId: id } })
      },
      { path: artifactPath(id) },
    )
  }, [])

  /** Leave the artifact view (the caller restores the incident's URL). */
  const closeArtifact = useCallback(() => setCurrentId(null), [])

  /**
   * Close the artifact, as its own Close button does: back to the page of the artifacts, with none
   * open. A move like any other: Back returns to the artifact, and from there to where the person
   * came from (an incident included); what is not saved is asked about first.
   */
  const leaveArtifact = useCallback(() => setPath(ARTIFACTS_ROOT), [])

  /**
   * Upload a file as an artifact of the given kind, optionally linked to an
   * incident at once. Resolves with the artifact's summary.
   */
  const startAnalysis = useCallback(
    async (kind, file, { incidentId = null, onProgress } = {}) => {
      const fields = incidentId ? { incident: incidentId } : {}
      const path = artifactKind(kind).uploadPath
      // Who gives no place of its own to the progress (a file dropped anywhere) gets the tray.
      const artifact = onProgress
        ? await upload(path, file, { fields, onProgress })
        : await transfer(`Uploading ${file.name}`, (report) => upload(path, file, { fields, onProgress: report }))
      refresh()
      return artifact
    },
    [refresh],
  )

  /**
   * Scan an address with the isolated browser, optionally in an incident.
   * Resolves with the scan ({ artifactId, known, status, … }).
   */
  const scanUrl = useCallback(
    async (url, { incidentId = null } = {}) => {
      const scan = await api.post('/artifacts/urls', { url, ...(incidentId ? { incident: incidentId } : {}) })
      refresh()
      return scan
    },
    [refresh],
  )

  /** The artifacts with that digest (a file already analysed), or []. */
  const lookup = useCallback(async (sha256) => {
    if (!sha256) return []
    try {
      return (await api.get(`/artifacts/lookup?sha256=${sha256}`)).artifacts
    } catch {
      return []
    }
  }, [])

  const link = useCallback(
    async (id, incidentId) => {
      const artifact = await api.post(`/artifacts/${id}/links`, { incidentId })
      refresh()
      return artifact
    },
    [refresh],
  )

  /** Analyse a file as an e-mail or as a capture: resolves with the artifact that was made of it. */
  const analyseAs = useCallback(
    async (id, kind) => {
      const artifact = await api.post(`/artifacts/${id}/analyse-as`, { as: kind })
      refresh()
      return artifact
    },
    [refresh],
  )

  const unlink = useCallback(
    async (id, incidentId) => {
      await api.del(`/artifacts/${id}/links/${encodeURIComponent(incidentId)}`)
      refresh()
    },
    [refresh],
  )

  const setTags = useCallback(
    async (id, tags) => {
      const artifact = await api.put(`/artifacts/${id}/tags`, { tags })
      refresh()
      return artifact
    },
    [refresh],
  )

  const setExpiry = useCallback(
    async (id, expiresAt) => {
      const artifact = await api.put(`/artifacts/${id}/expiry`, { expiresAt })
      refresh()
      return artifact
    },
    [refresh],
  )

  const remove = useCallback(
    async (id) => {
      await api.del(`/artifacts/${id}`)
      // Deleted while it was open: its address names nothing any more, and the page of the artifacts
      // takes its place in the history (the address change is what closes it here).
      if (idFromUrl() === id) freely(() => setPath(ARTIFACTS_ROOT, { replace: true }))
      setCurrentId((open) => (open === id ? null : open))
      refresh()
    },
    [refresh],
  )

  const value = useMemo(
    () => ({
      artifacts,
      counts,
      filters,
      setFilters,
      loading,
      error,
      queryError,
      refresh,
      currentId,
      current,
      currentError,
      openArtifact,
      closeArtifact,
      leaveArtifact,
      startAnalysis,
      scanUrl,
      lookup,
      link,
      analyseAs,
      unlink,
      setTags,
      setExpiry,
      remove,
    }),
    [
      artifacts,
      counts,
      filters,
      loading,
      error,
      queryError,
      refresh,
      currentId,
      current,
      currentError,
      openArtifact,
      closeArtifact,
      leaveArtifact,
      startAnalysis,
      scanUrl,
      lookup,
      link,
      analyseAs,
      unlink,
      setTags,
      setExpiry,
      remove,
    ],
  )
  return <ArtifactContext.Provider value={value}>{children}</ArtifactContext.Provider>
}

export function useArtifacts() {
  const ctx = useContext(ArtifactContext)
  if (!ctx) throw new Error('useArtifacts must be used inside <ArtifactProvider>')
  return ctx
}
