import { useState } from 'react'
import { Shield, LogIn, AlertCircle, BookOpen } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { Button } from '../ui/index.js'

/*
 * ============================================================================
 * LoginScreen
 * ============================================================================
 *
 * Full-screen, centered sign-in card shown when at least one user exists but
 * nobody is authenticated yet. Credentials are verified locally through
 * `useAuth().login` (SHA-256 hash comparison, no backend).
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
    <div className="mb-6 flex flex-col items-center text-center">
      <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-600 text-white shadow-sm">
        <Shield className="h-6 w-6" aria-hidden="true" />
      </div>
      <h1 className="text-xl font-semibold text-slate-900 dark:text-white">Nik</h1>
      <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
        Forensic analysis platform
      </p>
    </div>
  )
}

export default function LoginScreen() {
  const { login } = useAuth()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  const handleSubmit = async (event) => {
    event.preventDefault()
    if (submitting) return
    setError(null)
    setSubmitting(true)

    const result = await login(username, password)
    if (!result.ok) {
      // On failure show the error and re-enable the form.
      setError(result.error || 'Unable to sign in.')
      setSubmitting(false)
      return
    }
    // On success the App shell re-renders into the main app and unmounts this
    // screen, so we intentionally keep the button disabled until then.
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-slate-100 p-4 dark:bg-slate-950">
      <div className="w-full max-w-sm rounded-xl border border-slate-200 bg-white p-6 shadow-sm dark:border-slate-800 dark:bg-slate-900">
        <BrandHeader />

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label htmlFor="login-username" className={LABEL_CLASS}>
              Username
            </label>
            <input
              id="login-username"
              type="text"
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="Your username"
              autoComplete="username"
              autoFocus
              className={INPUT_CLASS}
            />
          </div>

          <div>
            <label htmlFor="login-password" className={LABEL_CLASS}>
              Password
            </label>
            <input
              id="login-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="Your password"
              autoComplete="current-password"
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
            icon={LogIn}
            disabled={submitting}
            className="w-full justify-center"
          >
            {submitting ? 'Signing in…' : 'Sign in'}
          </Button>
        </form>

        {/* Public interactive API docs (no login to view; calls need an API key) */}
        <p className="mt-5 border-t border-slate-200 pt-4 text-center text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
          <a
            href="/api/docs"
            className="inline-flex items-center gap-1 font-medium text-cyan-700 hover:underline dark:text-cyan-400"
          >
            <BookOpen className="h-3.5 w-3.5" aria-hidden="true" />
            API documentation
          </a>
        </p>
      </div>
    </div>
  )
}
