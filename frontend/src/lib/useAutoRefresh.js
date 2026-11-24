import { useCallback, useEffect, useRef, useState } from 'react'
import { nextAction } from '../domain/autoRefresh.js'

// A refresh due while something blocks it (a dialog drawn elsewhere) is asked again after this long.
const BLOCKED_RETRY_MS = 2000

/**
 * The refresh of a screen, by hand and on a timer.
 *
 *   const { refreshing, lastAt, error, refreshNow } = useAutoRefresh({ refresh, seconds, paused })
 *
 * `refresh` is an async function that brings the screen up to date and rejects when it could not.
 * `refreshNow` runs it once; while it runs a second call is ignored. With `seconds` > 0 the next one
 * starts that long AFTER the last one ended, so a slow server is never hammered. Nothing is asked while
 * the tab is hidden; back in view, an overdue refresh runs once at once. `paused` (a dialog open, an
 * action running) postpones the automatic refresh only; `blocked`, when given, is read before each
 * automatic refresh and postpones it too (for what the screen cannot see). A failed refresh keeps what is
 * on screen and sets `error` (a sentence); the timer goes on, and the next success clears it.
 *
 * @returns {{ refreshing: boolean, lastAt: number | null, error: string | null, refreshNow: () => Promise<void> }}
 */
export function useAutoRefresh({ refresh, seconds, paused = false, blocked = null }) {
  const [state, setState] = useState({ refreshing: false, lastAt: null, error: null, ended: 0 })
  const refreshRef = useRef(refresh)
  const blockedRef = useRef(blocked)
  const runningRef = useRef(false)
  const aliveRef = useRef(true)
  // When the last refresh ended, or the timer was started or its pace changed: what the next one counts from.
  const sinceRef = useRef(null)

  useEffect(() => {
    refreshRef.current = refresh
    blockedRef.current = blocked
  }, [refresh, blocked])
  useEffect(() => {
    aliveRef.current = true
    return () => {
      aliveRef.current = false
    }
  }, [])

  const refreshNow = useCallback(async () => {
    if (runningRef.current) return
    runningRef.current = true
    setState((current) => ({ ...current, refreshing: true }))
    let failure = null
    try {
      await refreshRef.current()
    } catch (caught) {
      failure = caught?.message || 'The screen could not be refreshed.'
    }
    const now = Date.now()
    sinceRef.current = now
    runningRef.current = false
    if (!aliveRef.current) return
    setState((current) => ({
      refreshing: false,
      lastAt: failure ? current.lastAt : now,
      error: failure,
      ended: current.ended + 1,
    }))
  }, [])

  // A new pace counts from now.
  useEffect(() => {
    sinceRef.current = Date.now()
  }, [seconds])

  useEffect(() => {
    let timer = null
    const plan = () => {
      clearTimeout(timer)
      const action = nextAction({
        seconds,
        paused,
        hidden: document.visibilityState === 'hidden',
        refreshing: runningRef.current,
        lastAt: sinceRef.current,
        now: Date.now(),
      })
      if (action.type === 'wait') timer = setTimeout(plan, action.ms)
      else if (action.type === 'refresh') {
        if (blockedRef.current?.()) timer = setTimeout(plan, BLOCKED_RETRY_MS)
        else refreshNow()
      }
    }
    plan()
    document.addEventListener('visibilitychange', plan)
    return () => {
      clearTimeout(timer)
      document.removeEventListener('visibilitychange', plan)
    }
    // `state.ended` restarts the plan when a refresh is over.
  }, [seconds, paused, refreshNow, state.ended])

  return { refreshing: state.refreshing, lastAt: state.lastAt, error: state.error, refreshNow }
}
