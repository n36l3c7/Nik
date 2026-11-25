import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { api, onRefused, onUnauthorized } from '../services/api.js'
import { can as userCan } from '../domain/permissions.js'
import { clockAfterUse, keepAliveMs, mustEnrol, sessionClock } from '../domain/signin.js'
import { onForeground, setKeepAlive } from '../lib/activity.js'
import { resetQuerySchema } from '../services/querySchema.js'
import { forgetAnswers } from '../services/widgetData.js'
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
 * User shape (as returned by the API): { id, username, roles, permissions, createdAt,
 * createdBy, disabled, secondFactor, secondFactorRequired }. `roles` are the role tags
 * of the account, `permissions` what they grant together; the interface asks
 * `can('<permission>')`, never for a role.
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
 *  - session ended while working (a 401 from any request) → `sessionExpired`:
 *    the app stays on screen with its unsaved changes and asks for the
 *    password again; signing in clears the flag and the saves resume.
 *
 * A second factor: `login` answers `{ ok, secondFactor: true }` when the
 * password was right and a code is asked; `loginCode` sends it. Until then
 * nobody is signed in. An account whose roles ask for a second factor and has
 * none (`mustEnrol`) can do nothing else: found at the sign-in, the app is not
 * shown before the factor is set up (`enrolling`, a page of its own); found
 * later (an administrator just required it), a dialog over the app asks for
 * it, and what was on screen stays.
 *
 * The session's clock (`sessionClock`, domain/signin.js) says when it ends for
 * not being used; components/auth/SessionGuards.jsx warns before it does.
 */

const AuthContext = createContext(null)

const NOT_A_COPY = { copy: false, copyOf: '' }

const serverOf = (answer) => ({
  copy: Boolean(answer?.copy),
  copyOf: typeof answer?.copyOf === 'string' ? answer.copyOf : '',
})

const normalizeUsername = (u) => String(u ?? '').trim()

export function AuthProvider({ children }) {
  const { clear: clearAudit } = useAudit()

  const [users, setUsers] = useState([])
  const [currentUser, setCurrentUser] = useState(null)
  const [hasUsers, setHasUsers] = useState(false)
  const [authReady, setAuthReady] = useState(false)
  // Set only when the boot probe cannot REACH the server (distinct from a 401).
  const [serverError, setServerError] = useState(null)
  // The server answered 401 to a signed-in client: the session is over.
  const [sessionExpired, setSessionExpired] = useState(false)
  // The account had to set its second factor up when it signed in: the app waits behind that.
  const [enrolAtEntry, setEnrolAtEntry] = useState(false)
  // What this server is: { copy, copyOf }. A copy of another server (a restored backup to look at) says so everywhere.
  const [server, setServer] = useState(NOT_A_COPY)
  // A refusal that concerns everything the person does: { code, message } (not on a listed network).
  const [refusal, setRefusal] = useState(null)
  // What a sign-in said besides who it is: { notice, recoveryCodesLeft }, shown once.
  const [signInNote, setSignInNote] = useState(null)
  // When the session ends, on the page's clock. A ref: it moves with every request of the person, and
  // nothing is drawn from it but the warning, which reads it on a timer. Its idle time alone is state.
  const clockRef = useRef(null)
  const [idleMs, setIdleMs] = useState(0)
  const keepClock = useCallback((next) => {
    clockRef.current = next
    setIdleMs(next?.idleMs ?? 0)
  }, [])
  const getSessionClock = useCallback(() => clockRef.current, [])

  // Live snapshot of the current user so callbacks can branch on auth state
  // without being re-created on every change.
  const currentUserRef = useRef(currentUser)
  currentUserRef.current = currentUser

  useEffect(() => {
    onUnauthorized(() => {
      if (currentUserRef.current) setSessionExpired(true)
    })
    return () => onUnauthorized(null)
  }, [])

  /** Ask the server again who is signed in (their roles, their second factor) and how long the session has. */
  const refreshMe = useCallback(async () => {
    try {
      const { user, session, server: where } = await api.get('/auth/me', { background: true })
      currentUserRef.current = user
      setCurrentUser(user)
      setServer(serverOf(where))
      keepClock(sessionClock(session, Date.now()))
      return user
    } catch {
      return null
    }
  }, [keepClock])

  useEffect(() => {
    onRefused((code, message) => {
      const user = currentUserRef.current
      if (!user) return
      // An administrator just made the second factor a must for this account: learn it, once.
      if (code === 'second_factor_required' && !mustEnrol(user)) refreshMe()
      if (code === 'admin_network') setRefusal({ code, message })
    })
    return () => onRefused(null)
  }, [refreshMe])

  // Every request of the person moves the end of the idle time, as the server does.
  useEffect(
    () =>
      onForeground((now) => {
        clockRef.current = clockAfterUse(clockRef.current, now)
      }),
    [],
  )

  /** The state of the session as the server has it now (asking is never "use"); null when it is over. */
  const checkSession = useCallback(async () => {
    try {
      const state = await api.get('/auth/session', { background: true })
      keepClock(sessionClock(state, Date.now()))
      return state
    } catch (err) {
      if (err?.status === 401 && currentUserRef.current) setSessionExpired(true)
      return null
    }
  }, [keepClock])

  /** The person is there: the session counts as used from now. */
  const staySignedIn = useCallback(async () => {
    try {
      keepClock(sessionClock(await api.post('/auth/session/stay', undefined, { background: false }), Date.now()))
      return true
    } catch (err) {
      if (err?.status === 401 && currentUserRef.current) setSessionExpired(true)
      return false
    }
  }, [keepClock])

  // Somebody who works without any request being sent is still using the session: the server is told.
  const signedIn = currentUser !== null && !sessionExpired
  useEffect(() => {
    if (!signedIn || !idleMs) return undefined
    setKeepAlive(() => staySignedIn(), keepAliveMs(idleMs / 1000))
    return () => setKeepAlive(null)
  }, [signedIn, idleMs, staySignedIn])

  /** Reload the user list (auth required). Called after login / on demand. */
  const refreshUsers = useCallback(async () => {
    // Only an admin lists the accounts: nobody else asks.
    if (!userCan(currentUserRef.current, 'admin')) {
      setUsers([])
      return
    }
    try {
      const res = await api.get('/users')
      setUsers(Array.isArray(res?.users) ? res.users : [])
    } catch {
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
      const { user, session, server: where } = await api.get('/auth/me')
      currentUserRef.current = user
      setCurrentUser(user)
      setServer(serverOf(where))
      keepClock(sessionClock(session, Date.now()))
      setEnrolAtEntry(mustEnrol(user))
      if (!mustEnrol(user)) await refreshUsers()
    } catch {
      setCurrentUser(null)
    }
    setAuthReady(true)
  }, [refreshBootstrap, refreshUsers, keepClock])

  useEffect(() => {
    boot()
  }, [boot])

  /**
   * Create a user account. Used for first-run (no auth, forced admin server
   * side) and for admin-driven user management.
   * @returns {Promise<{ ok: boolean, error: string|null }>}
   */
  const createUser = useCallback(
    async ({ username, password, roles = ['analyst'] }) => {
      try {
        await api.post('/users', {
          username: normalizeUsername(username),
          password,
          roles,
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

  /** Somebody is signed in: who, until when, and what the server said besides. */
  const adopt = useCallback(
    async ({ user, session, server: where, notice = null, recoveryCodesLeft = null }) => {
      // Signing in again where one was (the session had ended) keeps the app; a new sign-in waits for the factor.
      const again = currentUserRef.current?.id === user.id
      currentUserRef.current = user
      setCurrentUser(user)
      setServer(serverOf(where))
      keepClock(sessionClock(session, Date.now()))
      setEnrolAtEntry(mustEnrol(user) && !again)
      setRefusal(null)
      setSessionExpired(false)
      if (notice || recoveryCodesLeft !== null) setSignInNote({ notice, recoveryCodesLeft })
      if (!mustEnrol(user)) await refreshUsers()
    },
    [refreshUsers, keepClock],
  )

  /**
   * Log in with username + password.
   * @returns {Promise<{ok, error, secondFactor?: boolean}>} `secondFactor`: the password was right and
   *   the code of the second factor is asked next (`loginCode`); nobody is signed in yet.
   */
  const login = useCallback(
    async (username, password) => {
      try {
        const answer = await api.post('/auth/login', {
          username: normalizeUsername(username),
          password: password ?? '',
        })
        if (answer?.secondFactor) return { ok: true, error: null, secondFactor: true }
        await adopt(answer)
        return { ok: true, error: null }
      } catch (err) {
        return { ok: false, error: err?.message || 'Invalid username or password.' }
      }
    },
    [adopt],
  )

  /**
   * The second step of a sign-in: `{ code }` from the authenticator app, or `{ recoveryCode }`.
   * @returns {Promise<{ok, error, expired?: boolean, wait?: boolean}>} `expired`: the time for the second
   *   step ran out, the password is asked again.
   */
  const loginCode = useCallback(
    async ({ code = null, recoveryCode = null }) => {
      try {
        await adopt(await api.post('/auth/login/code', recoveryCode ? { recoveryCode } : { code }))
        return { ok: true, error: null }
      } catch (err) {
        const expired = err?.status === 401 && /sign in again/.test(err?.message ?? '')
        return { ok: false, error: err?.message || 'Unable to sign in.', expired }
      }
    },
    [adopt],
  )

  const logout = useCallback(async () => {
    try {
      await api.post('/auth/logout')
    } catch {
      /* even if the request fails, drop the local session */
    }
    currentUserRef.current = null
    setCurrentUser(null)
    setSessionExpired(false)
    setEnrolAtEntry(false)
    setRefusal(null)
    setSignInNote(null)
    keepClock(null)
    setUsers([])
    clearAudit()
    resetQuerySchema()
    forgetAnswers()
  }, [clearAudit, keepClock])

  /** Remove a user (admin action), then reload the list. @returns {Promise<{ok, error}>} */
  const deleteUser = useCallback(
    async (userId) => {
      try {
        await api.del(`/users/${encodeURIComponent(userId)}`)
        await refreshUsers()
        return { ok: true, error: null }
      } catch (err) {
        // The server enforces the rules (last admin, own account); reload to stay in sync.
        await refreshUsers()
        return { ok: false, error: err?.message || 'Unable to delete the user.' }
      }
    },
    [refreshUsers],
  )

  /**
   * Change an account (admin action): any of `{ username, roles, password,
   * disabled }`. A change to one's own account updates the signed-in user.
   * @returns {Promise<{ok, error}>}
   */
  const updateUser = useCallback(
    async (userId, changes) => {
      try {
        const { user } = await api.patch(`/users/${encodeURIComponent(userId)}`, changes)
        if (user.id === currentUserRef.current?.id) {
          currentUserRef.current = user
          setCurrentUser(user)
        }
        await refreshUsers()
        return { ok: true, error: null }
      } catch (err) {
        return { ok: false, error: err?.message || 'Unable to change the account.' }
      }
    },
    [refreshUsers],
  )

  /**
   * Change the signed-in user's own password; `proof` is `{ code }` or `{ recoveryCode }` when the
   * account has a second factor. @returns {Promise<{ok, error}>}
   */
  const changePassword = useCallback(async (currentPassword, newPassword, proof = {}) => {
    try {
      await api.put('/users/me/password', { currentPassword, newPassword, ...proof })
      return { ok: true, error: null }
    } catch (err) {
      return { ok: false, error: err?.message || 'Unable to change the password.' }
    }
  }, [])

  /** The second factor was set up: the account is whole again, and the app can show. */
  const enrolled = useCallback(async () => {
    const user = await refreshMe()
    setEnrolAtEntry(false)
    setSignInNote(null) // "your second factor was reset": it is set up again
    if (user && !mustEnrol(user)) await refreshUsers()
  }, [refreshMe, refreshUsers])

  /** Whether the signed-in account holds one of the permissions. */
  const can = useCallback((...wanted) => userCan(currentUser, ...wanted), [currentUser])

  const value = {
    users,
    currentUser,
    can,
    server,
    hasUsers,
    // Signed in, and let in: an account that must set its second factor up first is `enrolling`.
    isAuthenticated: currentUser !== null && !enrolAtEntry,
    enrolling: currentUser !== null && enrolAtEntry,
    mustEnrol: mustEnrol(currentUser),
    sessionExpired,
    refusal,
    signInNote,
    dismissSignInNote: () => setSignInNote(null),
    clearRefusal: () => setRefusal(null),
    getSessionClock,
    checkSession,
    staySignedIn,
    refreshMe,
    enrolled,
    createUser,
    login,
    loginCode,
    logout,
    deleteUser,
    updateUser,
    changePassword,
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
