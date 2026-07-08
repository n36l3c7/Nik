import { useState } from 'react'
import { Shield, UserPlus, AlertCircle, ShieldCheck } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { Button } from '../ui/index.js'

/*
 * ============================================================================
 * FirstRunSetup
 * ============================================================================
 *
 * Shown on first run, when no users exist yet. It creates the very first
 * account which — enforced by `useAuth().createUser` — automatically becomes
 * the administrator. After creation the App shell shows the login screen.
 */

// Shared input styling (matches the design system used across the app).
const INPUT_CLASS =
  'w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 ' +
  'placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ' +
  'dark:border-slate-800 dark:bg-slate-950 dark:text-white dark:placeholder:text-slate-500'

const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300'

/** Brand block: cyan Shield tile + product name + subtitle. */
function BrandHeader() {
  return (
    <div className="mb-5 flex flex-col items-center text-center">
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-600 text-white shadow-sm">
        <Shield className="h-6 w-6" aria-hidden="true" />
      </div>
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">CSAP</h1>
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
        Cyber Security Analysis Platform
      </p>
    </div>
  )
}

export default function FirstRunSetup() {
  const { createUser } = useAuth()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  const handleSubmit = async (event) => {
    event.preventDefault()
    if (submitting) return
    setError(null)

    // Client-side validation before hitting the (async) hashing in createUser.
    if (!username.trim()) {
      setError('Username is required.')
      return
    }
    if (password.length < 8) {
      setError('Password must be at least 8 characters.')
      return
    }
    if (password !== confirm) {
      setError('Passwords do not match.')
      return
    }

    setSubmitting(true)
    const result = await createUser({ username, password })
    if (!result.ok) {
      setError(result.error || 'Unable to create the user.')
      setSubmitting(false)
      return
    }
    // On success `hasUsers` flips to true and the App shell renders the login
    // screen; this component unmounts, so we keep the button disabled.
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 p-4 dark:bg-slate-950">
      <div className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <BrandHeader />

        <div className="mb-5 text-center">
          <h2 className="text-base font-semibold text-slate-900 dark:text-white">
            Create the first user
          </h2>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Set up the account used to access this workstation.
          </p>
        </div>

        {/* Reminder that the first account is always the administrator. */}
        <div className="mb-5 flex items-start gap-2 rounded-lg border border-cyan-200 bg-cyan-50 px-3 py-2 text-xs text-cyan-800 dark:border-cyan-500/30 dark:bg-cyan-500/10 dark:text-cyan-300">
          <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
          <span>This account is created with full administrator rights.</span>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="setup-username" className={LABEL_CLASS}>
              Username
            </label>
            <input
              id="setup-username"
              type="text"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="e.g. analyst"
              autoComplete="username"
              autoFocus
              className={INPUT_CLASS}
            />
          </div>

          <div>
            <label htmlFor="setup-password" className={LABEL_CLASS}>
              Password
            </label>
            <input
              id="setup-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="At least 8 characters"
              autoComplete="new-password"
              className={INPUT_CLASS}
            />
          </div>

          <div>
            <label htmlFor="setup-confirm" className={LABEL_CLASS}>
              Confirm password
            </label>
            <input
              id="setup-confirm"
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              placeholder="Repeat the password"
              autoComplete="new-password"
              className={INPUT_CLASS}
            />
          </div>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-400"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

          <Button
            type="submit"
            icon={UserPlus}
            disabled={submitting}
            className="w-full justify-center"
          >
            {submitting ? 'Creating…' : 'Create admin account'}
          </Button>
        </form>
      </div>
    </div>
  )
}
