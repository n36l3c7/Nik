import { createContext, useCallback, useContext, useState } from 'react'
import { api } from '../services/api.js'

/*
 * ============================================================================
 * AUDIT LOG (global, cross-incident) — backed by the API
 * ============================================================================
 *
 * Records every meaningful action: who did it, when, exactly what, and on which
 * incident. Entries now live in the backend (`/api/audit`).
 *
 * This provider sits ABOVE the auth provider (so `log()` can receive the actor
 * explicitly, avoiding a circular dependency). Because it cannot read the auth
 * state directly, the auth provider drives it:
 *   - calls `refresh()` after a successful login / on boot with a live session,
 *   - calls `refresh()` again on logout (the request 401s and clears entries).
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
  const [loading, setLoading] = useState(true)

  /**
   * Load the audit log from the server. Used on login/boot and, indirectly, on
   * logout (where the request fails auth and the catch clears local entries).
   */
  const refresh = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get('/audit')
      setEntries(Array.isArray(res?.entries) ? res.entries : [])
    } catch {
      // Not authenticated / server unreachable → show an empty local log.
      setEntries([])
    } finally {
      setLoading(false)
    }
  }, [])

  /**
   * Append an audit entry. Optimistically prepends a temporary entry, then
   * fires POST /audit (fire-and-forget) and swaps in the server's canonical
   * entry once it returns. The server sets `id`, `at` and the real `actor`.
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
        /* keep the optimistic entry; a later refresh() reconciles the log */
      })
  }, [])

  /** Clear the whole audit log (admin action): DELETE on the server, then locally. */
  const clearAudit = useCallback(async () => {
    try {
      await api.del('/audit')
    } catch {
      /* surfaced elsewhere; still clear locally for immediate feedback */
    }
    setEntries([])
  }, [])

  return (
    <AuditContext.Provider value={{ entries, loading, log, clearAudit, refresh }}>
      {children}
    </AuditContext.Provider>
  )
}

export function useAudit() {
  const ctx = useContext(AuditContext)
  if (!ctx) throw new Error('useAudit must be used inside <AuditProvider>')
  return ctx
}
