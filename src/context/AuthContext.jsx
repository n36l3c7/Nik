import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from 'react'
import { api } from '../services/api.js'
import { useAudit } from './AuditContext.jsx'

/*
 * ============================================================================
 * AUTHENTICATION (server-side sessions)
 * ============================================================================
 *
 * Credentials are verified by the backend, which hashes passwords (bcrypt) and
 * issues an httpOnly session cookie (`nik_session`). The client NEVER hashes
 * passwords and never sees the hash — the old crypto.subtle code is gone.
 *
 * User shape (as returned by the API): { id, username, role, createdAt, createdBy }.
 *
 * Boot sequence (on mount):
 *   1. GET /auth/bootstrap → { hasUsers }. This also doubles as the
 *      reachability probe: if it fails, the server is unreachable and App shows
 *      a retry screen.
 *   2. GET /auth/me → the current user if a valid session cookie exists, else a
 *      401 which simply means "not signed in".
 *   `authReady` flips true once both have settled.
 *
 * Flows:
 *  - no users at all    → first-run: create the first (admin) user
 *  - users but no login → login screen
 */

const AuthContext = createContext(null)

const normalizeUsername = (u) => String(u ?? '').trim()

export function AuthProvider({ children }) {
  const { log, refresh: refreshAudit } = useAudit()

  const [users, setUsers] = useState([])
  const [currentUser, setCurrentUser] = useState(null)
  const [hasUsers, setHasUsers] = useState(false)
  const [authReady, setAuthReady] = useState(false)
  // Set only when the boot probe cannot REACH the server (distinct from a 401).
  const [serverError, setServerError] = useState(null)

  // Live snapshot of the current user so callbacks can branch on auth state
  // without being re-created on every change.
  const currentUserRef = useRef(currentUser)
  currentUserRef.current = currentUser

  /** Reload the user list (auth required). Called after login / on demand. */
  const refreshUsers = useCallback(async () => {
    try {
      const res = await api.get('/users')
      setUsers(Array.isArray(res?.users) ? res.users : [])
    } catch {
      // Not authorized (e.g. analyst) or transient error → leave list empty.
      setUsers([])
    }
  }, [])

  /** Refresh the first-run flag (`hasUsers`) from the server. */
  const refreshBootstrap = useCallback(async () => {
    const boot = await api.get('/auth/bootstrap')
    setHasUsers(Boolean(boot?.hasUsers))
  }, [])

  /**
   * Boot probe: bootstrap (also the reachability check) + me. Exposed as
   * `retry` so the "Cannot reach the server" screen can re-run it.
   */
  const boot = useCallback(async () => {
    setAuthReady(false)
    setServerError(null)
    try {
      await refreshBootstrap()
    } catch (err) {
      // bootstrap is public and must always answer; a failure means the API is
      // unreachable → surface the retry screen.
      setServerError(err?.message || 'Cannot reach the server.')
      setAuthReady(true)
      return
    }

    // The server is reachable; a failing /auth/me just means "not signed in".
    try {
      const { user } = await api.get('/auth/me')
      setCurrentUser(user)
      await refreshUsers()
      refreshAudit()
    } catch {
      setCurrentUser(null)
    }
    setAuthReady(true)
  }, [refreshBootstrap, refreshUsers, refreshAudit])

  useEffect(() => {
    boot()
  }, [boot])

  /**
   * Create a user account. Used for first-run (no auth, forced admin server
   * side) and for admin-driven user management. The `actor` second argument is
   * accepted for backward compatibility but ignored — the server attributes the
   * action to the session user.
   * @returns {Promise<{ ok: boolean, error: string|null }>}
   */
  const createUser = useCallback(
    // eslint-disable-next-line no-unused-vars
    async ({ username, password, role = 'analyst' }, _actor) => {
      try {
        await api.post('/users', {
          username: normalizeUsername(username),
          password,
          role,
        })
        // First-run success flips `hasUsers`; a live admin refreshes the list.
        await refreshBootstrap()
        if (currentUserRef.current) await refreshUsers()
        return { ok: true, error: null }
      } catch (err) {
        return { ok: false, error: err?.message || 'Unable to create the user.' }
      }
    },
    [refreshBootstrap, refreshUsers],
  )

  /** Log in with username + password. @returns {Promise<{ok, error}>} */
  const login = useCallback(
    async (username, password) => {
      try {
        const { user } = await api.post('/auth/login', {
          username: normalizeUsername(username),
          password: password ?? '',
        })
        setCurrentUser(user)
        await refreshUsers()
        refreshAudit()
        // Logged after the cookie is set, so the server attributes it correctly.
        log({ actor: user.username, action: 'auth.login', details: 'Signed in' })
        return { ok: true, error: null }
      } catch (err) {
        return { ok: false, error: err?.message || 'Invalid username or password.' }
      }
    },
    [refreshUsers, refreshAudit, log],
  )

  const logout = useCallback(async () => {
    const user = currentUserRef.current
    // Log while the session cookie is still valid.
    if (user) log({ actor: user.username, action: 'auth.logout', details: 'Signed out' })
    try {
      await api.post('/auth/logout')
    } catch {
      /* even if the request fails, drop the local session */
    }
    setCurrentUser(null)
    setUsers([])
    // Reload the audit log — now unauthenticated, so it clears locally.
    refreshAudit()
  }, [log, refreshAudit])

  /** Remove a user (admin action), then reload the list. */
  const deleteUser = useCallback(
    // eslint-disable-next-line no-unused-vars
    async (userId, _actor) => {
      try {
        await api.del(`/users/${userId}`)
        await refreshUsers()
      } catch {
        // Server enforces the rules (last user / self); reload to stay in sync.
        await refreshUsers()
      }
    },
    [refreshUsers],
  )

  const value = {
    users,
    currentUser,
    hasUsers,
    isAuthenticated: currentUser !== null,
    createUser,
    login,
    logout,
    deleteUser,
    refreshUsers,
    authReady,
    // Extra fields (beyond the historical shape) used by App.jsx for the boot
    // "Connecting…" and "Cannot reach the server" screens.
    serverError,
    retry: boot,
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>')
  return ctx
}
