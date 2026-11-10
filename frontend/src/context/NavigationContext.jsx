import { createContext, useCallback, useContext, useMemo, useState } from 'react'

/*
 * Requests to move around the app, made by components that do not own the
 * tab state (menus, dialogs, the drop handler) and applied by App and the
 * tabs:
 *   - goTo(tab, { search })   App switches tab; the tab reads `search` once;
 *   - openSearch(query)       App opens the search palette with the query;
 *   - importInto(tab, file, params)  App switches tab; the tab imports the file.
 * A tab takes its request with take(tab), which also clears it.
 */

const NavigationContext = createContext(null)

export function NavigationProvider({ children }) {
  const [focus, setFocus] = useState(null) // { tab, at }
  const [search, setSearch] = useState(null) // { query, at }
  const [requests, setRequests] = useState({}) // { [tab]: { search?, file?, params? } }

  const goTo = useCallback((tab, request = {}) => {
    setRequests((prev) => ({ ...prev, [tab]: request }))
    setFocus({ tab, at: Date.now() })
  }, [])
  const importInto = useCallback((tab, file, params = {}) => goTo(tab, { file, params }), [goTo])
  const openSearch = useCallback((query = '') => setSearch({ query, at: Date.now() }), [])
  const clearSearch = useCallback(() => setSearch(null), [])
  const take = useCallback(
    (tab) => {
      const request = requests[tab]
      if (request) setRequests((prev) => ({ ...prev, [tab]: undefined }))
      return request ?? null
    },
    [requests],
  )

  const value = useMemo(
    () => ({ focus, search, requests, goTo, importInto, openSearch, clearSearch, take }),
    [focus, search, requests, goTo, importInto, openSearch, clearSearch, take],
  )
  return <NavigationContext.Provider value={value}>{children}</NavigationContext.Provider>
}

export function useNavigation() {
  const ctx = useContext(NavigationContext)
  if (!ctx) throw new Error('useNavigation must be used inside <NavigationProvider>')
  return ctx
}
