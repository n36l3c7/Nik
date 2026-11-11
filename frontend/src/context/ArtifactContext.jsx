import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api, upload } from '../services/api.js'
import { artifactIdFromPath, artifactKind, artifactPath } from '../domain/artifactRegistry.js'
import { useAuth } from './AuthContext.jsx'

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
const EMPTY_FILTERS = { kind: '', q: '', mine: false }
const NO_COUNTS = { file: 0, mail: 0, pcap: 0 }

const idFromUrl = () => (typeof window === 'undefined' ? null : artifactIdFromPath(window.location.pathname))

export function ArtifactProvider({ children }) {
  const { isAuthenticated } = useAuth()
  const [artifacts, setArtifacts] = useState([])
  const [counts, setCounts] = useState(NO_COUNTS)
  const [filters, setFilters] = useState(EMPTY_FILTERS)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
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
        if (filters.mine) params.set('mine', 'true')
        setLoading(true)
        api
          .get(`/artifacts?${params}`)
          .then((res) => {
            if (request !== requestRef.current) return
            setArtifacts(res.artifacts)
            setCounts(res.counts)
            setError(null)
          })
          .catch((err) => request === requestRef.current && setError(err.message))
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
    const onPopState = () => setCurrentId(idFromUrl())
    window.addEventListener('popstate', onPopState)
    return () => window.removeEventListener('popstate', onPopState)
  }, [])

  const openArtifact = useCallback((id) => {
    setCurrentId(id)
    if (window.location.pathname !== artifactPath(id))
      window.history.pushState({ artifactId: id }, '', artifactPath(id))
  }, [])

  /** Leave the artifact view (the caller restores the incident's URL). */
  const closeArtifact = useCallback(() => setCurrentId(null), [])

  /**
   * Upload a file as an artifact of the given kind, optionally linked to an
   * incident at once. Resolves with the artifact's summary.
   */
  const startAnalysis = useCallback(
    async (kind, file, { incidentId = null, onProgress } = {}) => {
      const fields = incidentId ? { incident: incidentId } : {}
      const artifact = await upload(artifactKind(kind).uploadPath, file, { fields, onProgress })
      refresh()
      return artifact
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

  const remove = useCallback(
    async (id) => {
      await api.del(`/artifacts/${id}`)
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
      refresh,
      currentId,
      current,
      currentError,
      openArtifact,
      closeArtifact,
      startAnalysis,
      lookup,
      link,
      unlink,
      setTags,
      remove,
    }),
    [
      artifacts,
      counts,
      filters,
      loading,
      error,
      refresh,
      currentId,
      current,
      currentError,
      openArtifact,
      closeArtifact,
      startAnalysis,
      lookup,
      link,
      unlink,
      setTags,
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
