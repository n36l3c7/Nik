import { useCallback, useState } from 'react'

/**
 * A boolean kept in localStorage: a panel the analyst closed stays closed the
 * next time (per browser). `key` is the storage key, `initial` the value when
 * nothing is stored or storage is unavailable.
 *
 * @returns {[boolean, (next: boolean) => void]}
 */
export function useStoredBoolean(key, initial) {
  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(key)
      return stored === null ? initial : stored === '1'
    } catch {
      return initial
    }
  })
  const update = useCallback(
    (next) => {
      setValue(next)
      try {
        localStorage.setItem(key, next ? '1' : '0')
      } catch {
        // Storage refused (private mode, quota): the choice lasts for this page only.
      }
    },
    [key],
  )
  return [value, update]
}
