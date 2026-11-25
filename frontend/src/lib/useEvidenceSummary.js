import { useCallback, useEffect, useState } from 'react'
import { evidence } from '../services/api.js'

/*
 * What the server says each incident holds of host evidence (`GET …/evidence/summary`): per section its
 * files, records, files read in part, failed and being read. One copy per incident, shared by the side
 * list of the Evidence tab, the header, the Summary and the timeline, so the numbers cannot disagree.
 * It is read when a component asks, again each time one mounts (the copy shows meanwhile), whenever
 * a SourceFiles table changes something (`noteEvidenceChanged`), and while a file is being read.
 */

const POLL_MS = 3000
const entries = new Map() // incident id -> { summary, error }
const loading = new Map() // incident id -> AbortController
const listeners = new Set()

const emit = () => listeners.forEach((listener) => listener())

async function load(incidentId) {
  loading.get(incidentId)?.abort()
  const controller = new AbortController()
  loading.set(incidentId, controller)
  try {
    const summary = await evidence.summary(incidentId, { signal: controller.signal, background: true })
    if (controller.signal.aborted) return
    entries.set(incidentId, { summary, error: '' })
  } catch (failure) {
    if (failure?.name === 'AbortError') return
    entries.set(incidentId, { summary: entries.get(incidentId)?.summary ?? null, error: failure?.message || 'Failed' })
  } finally {
    if (loading.get(incidentId) === controller) loading.delete(incidentId)
  }
  emit()
}

/** A file was added, removed, read again or finished being read: read the summary again (if anybody holds it). */
export function noteEvidenceChanged(incidentId) {
  if (incidentId && entries.has(incidentId)) load(incidentId)
}

/** Forget what is held (tests, and a sign-out). */
export function resetEvidenceSummaries() {
  loading.forEach((controller) => controller.abort())
  loading.clear()
  entries.clear()
  emit()
}

/**
 * `{ summary, loading, error, refresh }` for an incident. `summary` is `{ kinds, partialUnseen }` or null
 * until the first answer. `enabled: false` reads nothing (an account that cannot read the incident).
 */
export function useEvidenceSummary(incidentId, { enabled = true } = {}) {
  const [, setVersion] = useState(0)
  useEffect(() => {
    const listener = () => setVersion((version) => version + 1)
    listeners.add(listener)
    return () => {
      listeners.delete(listener)
    }
  }, [])
  useEffect(() => {
    if (incidentId && enabled) load(incidentId)
  }, [incidentId, enabled])

  const entry = incidentId ? entries.get(incidentId) : null
  const reading = Object.values(entry?.summary?.kinds ?? {}).some((kind) => kind.parsing > 0)
  useEffect(() => {
    if (!incidentId || !enabled || !reading) return undefined
    const timer = setTimeout(() => load(incidentId), POLL_MS)
    return () => clearTimeout(timer)
  }, [incidentId, enabled, reading, entry])

  const refresh = useCallback(() => (incidentId ? load(incidentId) : Promise.resolve()), [incidentId])
  return {
    summary: entry?.summary ?? null,
    loading: Boolean(incidentId && enabled && !entry),
    error: entry?.error ?? '',
    refresh,
  }
}
