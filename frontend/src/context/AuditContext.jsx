import { createContext, useCallback, useContext, useMemo, useState } from 'react'
import { api } from '../services/api.js'

/*
 * ============================================================================
 * AUDIT LOG (global, cross-incident) — backed by the API
 * ============================================================================
 *
 * Who did what, when, and on which incident. The log is WRITTEN BY THE SERVER:
 * each request that changes something is recorded where it is handled, so
 * nothing here reports what the app did. The one exception is `log()` for an
 * action that happens in the browser alone (exporting an incident to a file),
 * which the server would never see.
 *
 * The entries are read when the Audit log section opens (`refresh()`), not at
 * sign-in: the log can be thousands of rows and most sessions never look at it.
 * This provider sits ABOVE the auth provider, which calls `clear()` at sign-out.
 *
 * Entry shape (mirrors the server):
 *   { id, at (ISO), actor, action, target, details, incidentId, incidentName }
 */

const AuditContext = createContext(null)

// Keep at most this many entries client-side (newest kept); the server caps too.
const MAX_ENTRIES = 5000

function newId() {
  return crypto.randomUUID?.() ?? `au-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
}

export function AuditProvider({ children }) {
  const [entries, setEntries] = useState([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)

  /** Load the audit log from the server (when the Audit log section opens). */
  const refresh = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await api.get('/audit')
      setEntries(Array.isArray(res?.entries) ? res.entries : [])
    } catch (err) {
      setError(err?.message || 'Unable to load the audit log.')
    } finally {
      setLoading(false)
    }
  }, [])

  /** Forget the entries (at sign-out). */
  const clear = useCallback(() => setEntries([]), [])

  /**
   * Record an action done in the browser alone (`incident.export`; the server
   * refuses any other). Optimistically prepends a temporary entry, then swaps
   * in the server's once it returns. The server sets `id`, `at` and `actor`.
   *
   * @param {{ actor?, action, target?, details?, incidentId?, incidentName? }} e
   */
  const log = useCallback((e) => {
    const temp = {
      id: newId(),
      at: new Date().toISOString(),
      actor: e.actor ?? 'system',
      action: e.action,
      target: e.target ?? null,
      details: e.details ?? '',
      incidentId: e.incidentId ?? null,
      incidentName: e.incidentName ?? null,
    }

    setEntries((prev) => {
      const next = [temp, ...prev]
      return next.length > MAX_ENTRIES ? next.slice(0, MAX_ENTRIES) : next
    })

    // Persist (fire-and-forget). The server ignores any client `actor` and
    // stamps the session username instead.
    api
      .post('/audit', {
        action: e.action,
        target: e.target ?? null,
        details: e.details ?? '',
        incidentId: e.incidentId ?? null,
        incidentName: e.incidentName ?? null,
      })
      .then((saved) => {
        if (saved) setEntries((prev) => prev.map((x) => (x.id === temp.id ? saved : x)))
      })
      .catch(() => {
        // Not recorded: the entry must not stay on screen as if it were.
        setEntries((prev) => prev.filter((x) => x.id !== temp.id))
      })
  }, [])

  /**
   * Clear the whole audit log (admin action), then read it again: the server
   * leaves one entry saying who cleared it. A failure leaves the log as it is.
   */
  const clearAudit = useCallback(async () => {
    try {
      await api.del('/audit')
    } catch (err) {
      setError(err?.message || 'Unable to clear the audit log.')
      return
    }
    await refresh()
  }, [refresh])

  const value = useMemo(
    () => ({ entries, loading, error, log, clearAudit, refresh, clear }),
    [entries, loading, error, log, clearAudit, refresh, clear],
  )
  return <AuditContext.Provider value={value}>{children}</AuditContext.Provider>
}

export function useAudit() {
  const ctx = useContext(AuditContext)
  if (!ctx) throw new Error('useAudit must be used inside <AuditProvider>')
  return ctx
}
