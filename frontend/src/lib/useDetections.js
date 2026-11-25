import { useEffect, useState } from 'react'
import { evidence } from '../services/api.js'

/*
 * What the rules found in a section of host evidence (`GET …/evidence/detections`): one row for each rule,
 * highest level first, and the counts by level. `kind` is the section; `source` narrows it to one kind of
 * file (a shell, a category); `refresh` is a number the page raises when files were added or read.
 * `enabled: false` (an archived incident has no records) reads nothing.
 */

const NONE = { rules: [], total: 0, detections: 0, byLevel: {} }

/** `{ data, loading, error }`; `data` is `{ rules, total, detections, byLevel }`, empty until the first answer. */
export function useDetections(incidentId, { kind, source = '', refresh = 0, enabled = true } = {}) {
  const [state, setState] = useState({ key: '', data: NONE, error: '' })
  const key = `${incidentId}|${kind}|${source}|${refresh}`
  useEffect(() => {
    if (!incidentId || !enabled) return undefined
    const controller = new AbortController()
    evidence
      .detections(incidentId, { kind, source, signal: controller.signal })
      .then((data) => setState({ key, data, error: '' }))
      .catch((failure) => {
        if (failure?.name !== 'AbortError') setState({ key, data: NONE, error: failure?.message || 'Failed' })
      })
    return () => controller.abort()
  }, [incidentId, kind, source, enabled, key])
  const current = enabled && state.key === key
  return {
    data: enabled && state.key.startsWith(`${incidentId}|${kind}|${source}|`) ? state.data : NONE,
    loading: enabled && !current,
    error: current ? state.error : '',
  }
}
