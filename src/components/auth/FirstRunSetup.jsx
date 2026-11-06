import { useState } from 'react'
import { UserPlus, AlertCircle, ShieldCheck } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { Button } from '../ui/index.js'
import AuthLayout, { AUTH_INPUT_CLASS, AUTH_LABEL_CLASS } from './AuthLayout.jsx'

/*
 * ============================================================================
 * FirstRunSetup
 * ============================================================================
 *
 * Shown on first run, when no users exist yet. It creates the very first
 * account which — enforced by the backend — automatically becomes the
 * administrator. After creation the App shell shows the login screen.
 */

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
    <AuthLayout title="first run" subtitle="create the first user to start using Nik">
      {/* Reminder that the first account is always the administrator. */}
      <div className="mb-5 flex items-start gap-2 border border-accent-strong bg-accent-soft px-3 py-2 text-xs text-accent-fg">
        <ShieldCheck className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
        <span>This account is created with full administrator rights.</span>
      </div>

      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="setup-username" className={AUTH_LABEL_CLASS}>
            username
          </label>
          <input
            id="setup-username"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="e.g. analyst"
            autoComplete="username"
            autoFocus
            className={AUTH_INPUT_CLASS}
          />
        </div>

        <div>
          <label htmlFor="setup-password" className={AUTH_LABEL_CLASS}>
            password
          </label>
          <input
            id="setup-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="At least 8 characters"
            autoComplete="new-password"
            className={AUTH_INPUT_CLASS}
          />
        </div>

        <div>
          <label htmlFor="setup-confirm" className={AUTH_LABEL_CLASS}>
            confirm password
          </label>
          <input
            id="setup-confirm"
            type="password"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            placeholder="Repeat the password"
            autoComplete="new-password"
            className={AUTH_INPUT_CLASS}
          />
        </div>

        {error && (
          <div
            role="alert"
            className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
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
    </AuthLayout>
  )
}
