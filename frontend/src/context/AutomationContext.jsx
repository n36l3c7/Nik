import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../services/api.js'
import { useAuth } from './AuthContext.jsx'

/*
 * ============================================================================
 * AUTOMATION — what the whole app knows about it
 * ============================================================================
 *
 * Two things more than one screen needs: whether automation is on and its
 * worker alive (the banner of the Automations area, the switch in Settings),
 * and the library of nodes (the canvas, the inspector, a run). Both are read
 * when first asked for, by an account that may run playbooks; playbooks, runs
 * and scripts are loaded by the pages that show them.
 */

const AutomationContext = createContext(null)

const EMPTY_CATALOG = { nodes: [], events: [], operators: [], ports: {} }

export function AutomationProvider({ children }) {
  const { isAuthenticated, can } = useAuth()
  const allowed = isAuthenticated && can('automation.run')
  const [state, setState] = useState(null) // { enabled, workerAlive }
  const [catalog, setCatalog] = useState(null)
  const catalogRequest = useRef(null)

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

  // Another account signed in: what the last one read is not theirs.
  useEffect(() => {
    if (allowed) return
    setState(null)
    setCatalog(null)
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
    }),
    [allowed, state, refreshState, catalog, loadCatalog],
  )
  return <AutomationContext.Provider value={value}>{children}</AutomationContext.Provider>
}

export function useAutomation() {
  const context = useContext(AutomationContext)
  if (!context) throw new Error('useAutomation must be used inside <AutomationProvider>')
  return context
}
