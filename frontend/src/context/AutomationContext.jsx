import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../services/api.js'
import { useAuth } from './AuthContext.jsx'

/*
 * ============================================================================
 * AUTOMATION — what the whole app knows about it
 * ============================================================================
 *
 * What more than one screen needs:
 *
 *   state      whether automation is on and its worker alive (the banner of
 *              the Automations area, the switch in Settings);
 *   catalog    the library of nodes (the canvas, the inspector, a run);
 *   approvals  the questions that wait for an answer: the count on the rail,
 *              the banner on the incident a run works on, the Approvals
 *              screen. Read when the app opens and again every little while,
 *              while the window is in view;
 *   runRequest "Run a playbook…" asked from anywhere (an incident's menu, a
 *              playbook's page): one dialog, drawn by App.
 *
 * All of it is for an account that may run playbooks; playbooks, runs and
 * scripts are loaded by the pages that show them.
 */

const AutomationContext = createContext(null)

const EMPTY_CATALOG = { nodes: [], events: [], operators: [], ports: {} }
const APPROVALS_EVERY_MS = 20_000

export function AutomationProvider({ children }) {
  const { isAuthenticated, can } = useAuth()
  const allowed = isAuthenticated && can('automation.run')
  const [state, setState] = useState(null) // { enabled, workerAlive }
  const [catalog, setCatalog] = useState(null)
  const catalogRequest = useRef(null)
  const [approvals, setApprovals] = useState([])
  const [waiting, setWaiting] = useState(0)
  const [runRequest, setRunRequest] = useState(null)

  const refreshState = useCallback(async () => {
    if (!allowed) return null
    try {
      const next = await api.get('/automation/state')
      setState(next)
      return next
    } catch {
      return null
    }
  }, [allowed])

  /** The library of nodes, read once; `reload` reads it again (a script got a new version). */
  const loadCatalog = useCallback(
    async ({ reload = false } = {}) => {
      if (!allowed) return EMPTY_CATALOG
      if (!reload && catalogRequest.current) return catalogRequest.current
      const request = api.get('/automation/catalog').then(
        (found) => {
          setCatalog(found)
          return found
        },
        (error) => {
          catalogRequest.current = null
          throw error
        },
      )
      catalogRequest.current = request
      return request
    },
    [allowed],
  )

  /** Read the approvals that wait. Quiet when it fails: the next round asks again. */
  const refreshApprovals = useCallback(async () => {
    if (!allowed) return
    try {
      const found = await api.get('/automation/approvals')
      setApprovals(found.approvals)
      setWaiting(found.waiting)
    } catch {
      /* a session that ended is reported by the API client */
    }
  }, [allowed])

  useEffect(() => {
    if (!allowed) return undefined
    refreshApprovals()
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') refreshApprovals()
    }, APPROVALS_EVERY_MS)
    const onVisible = () => document.visibilityState === 'visible' && refreshApprovals()
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [allowed, refreshApprovals])

  /** Answer an approval ('approved' | 'refused'); throws with the server's sentence when it cannot be. */
  const answerApproval = useCallback(
    async (id, answer, comment = '') => {
      try {
        return await api.post(`/automation/approvals/${encodeURIComponent(id)}`, { answer, comment })
      } finally {
        refreshApprovals()
      }
    },
    [refreshApprovals],
  )

  /**
   * Open "Run a playbook…". `target` may name the incident to run on
   * (`{ incidentId, incidentName }`), the playbook (`{ playbookId }`) and
   * whether a dry run is proposed (`{ dryRun }`).
   */
  const askRun = useCallback((target = {}) => setRunRequest({ ...target }), [])
  const closeRun = useCallback(() => setRunRequest(null), [])

  // Another account signed in: what the last one read is not theirs.
  useEffect(() => {
    if (allowed) return
    setState(null)
    setCatalog(null)
    setApprovals([])
    setWaiting(0)
    setRunRequest(null)
    catalogRequest.current = null
  }, [allowed])

  const value = useMemo(
    () => ({
      allowed,
      state,
      setState,
      refreshState,
      catalog: catalog ?? EMPTY_CATALOG,
      catalogLoaded: catalog !== null,
      loadCatalog,
      approvals,
      waiting,
      refreshApprovals,
      answerApproval,
      runRequest,
      askRun,
      closeRun,
    }),
    [
      allowed,
      state,
      refreshState,
      catalog,
      loadCatalog,
      approvals,
      waiting,
      refreshApprovals,
      answerApproval,
      runRequest,
      askRun,
      closeRun,
    ],
  )
  return <AutomationContext.Provider value={value}>{children}</AutomationContext.Provider>
}

export function useAutomation() {
  const context = useContext(AutomationContext)
  if (!context) throw new Error('useAutomation must be used inside <AutomationProvider>')
  return context
}
