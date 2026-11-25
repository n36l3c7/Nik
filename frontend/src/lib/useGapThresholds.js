import { useCallback, useState } from 'react'
import { STORAGE_KEY, readThresholds } from '../domain/gapsBursts.js'

/**
 * The thresholds of the gaps and bursts of the Timeline, kept in this browser: the app has no place on the server
 * for a person's view settings (the lists keep theirs the same way, `nik.table.*`). `[thresholds, change]`;
 * `change` takes the parts to change. When storage is refused the choice lasts for the page only.
 */
export function useGapThresholds() {
  const [held, setHeld] = useState(() => {
    try {
      return readThresholds(localStorage.getItem(STORAGE_KEY))
    } catch {
      return readThresholds(null)
    }
  })
  const change = useCallback((parts) => {
    setHeld((before) => {
      const next = { ...before, ...parts }
      try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(next))
      } catch {
        // Storage refused (private mode, quota): the choice lasts for this page only.
      }
      return next
    })
  }, [])
  return [held, change]
}
