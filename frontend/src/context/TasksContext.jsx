import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import { api } from '../services/api.js'
import { useAuth } from './AuthContext.jsx'

/*
 * How many tasks wait for the account that is signed in: the count on the
 * rail. Read when the app opens, every little while when the window is in
 * view, and whenever a screen completes, skips, adds or gives a task
 * (`refresh`). The tasks themselves are read by the pages that show them.
 */

const TasksContext = createContext(null)
const EVERY_MS = 30_000
const NONE = { mine: 0, overdue: 0 }

export function TasksProvider({ children }) {
  const { isAuthenticated, can } = useAuth()
  const allowed = isAuthenticated && can('read')
  const [count, setCount] = useState(NONE)
  // Bumped by refresh(): a page that lists tasks reads them again.
  const [version, setVersion] = useState(0)

  const read = useCallback(async () => {
    if (!allowed) return
    try {
      const found = await api.get('/tasks/count')
      setCount({ mine: found.mine ?? 0, overdue: found.overdue ?? 0 })
    } catch {
      /* quiet: the next round asks again */
    }
  }, [allowed])

  const refresh = useCallback(() => {
    setVersion((value) => value + 1)
    return read()
  }, [read])

  useEffect(() => {
    if (!allowed) {
      setCount(NONE)
      return undefined
    }
    read()
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') read()
    }, EVERY_MS)
    const onVisible = () => document.visibilityState === 'visible' && read()
    document.addEventListener('visibilitychange', onVisible)
    return () => {
      clearInterval(timer)
      document.removeEventListener('visibilitychange', onVisible)
    }
  }, [allowed, read])

  const value = useMemo(() => ({ count, version, refresh }), [count, version, refresh])
  return <TasksContext.Provider value={value}>{children}</TasksContext.Provider>
}

export function useTasks() {
  const context = useContext(TasksContext)
  if (!context) throw new Error('useTasks must be used inside <TasksProvider>')
  return context
}
