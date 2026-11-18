import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { api } from '../services/api.js'
import { byName } from '../domain/fields.js'
import { useAuth } from './AuthContext.jsx'

/*
 * The field registry and the incident types, for the whole app: the incident
 * page is drawn from them (its side panel, the sections of its Summary, the
 * order of its tabs), and so are the forms that edit fields.
 *
 * Read once an account that reads incidents is signed in; `reload()` after
 * Settings changed a type or a field.
 */

const FieldsContext = createContext(null)

export function FieldsProvider({ children }) {
  const { isAuthenticated, can } = useAuth()
  const allowed = isAuthenticated && can('read')
  const [fields, setFields] = useState([])
  const [types, setTypes] = useState([])
  const [ready, setReady] = useState(false)

  const reload = useCallback(async () => {
    if (!allowed) return
    try {
      const [registry, found] = await Promise.all([api.get('/fields'), api.get('/incident-types')])
      setFields(registry.fields)
      setTypes(found.types)
      setReady(true)
    } catch {
      // The page still works without them: it shows what it always showed.
      setReady(true)
    }
  }, [allowed])

  useEffect(() => {
    if (allowed) reload()
    else {
      setFields([])
      setTypes([])
      setReady(false)
    }
  }, [allowed, reload])

  const value = useMemo(() => ({ fields, types, known: byName(fields), ready, reload }), [fields, types, ready, reload])
  return <FieldsContext.Provider value={value}>{children}</FieldsContext.Provider>
}

export function useFields() {
  const context = useContext(FieldsContext)
  if (!context) throw new Error('useFields must be used inside <FieldsProvider>')
  return context
}
