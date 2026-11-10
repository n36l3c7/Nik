import { useState } from 'react'
import { LogIn, AlertCircle } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { Button } from '../ui/index.js'
import AuthLayout, { AUTH_INPUT_CLASS, AUTH_LABEL_CLASS } from './AuthLayout.jsx'

/*
 * ============================================================================
 * LoginScreen
 * ============================================================================
 *
 * Sign-in screen shown when at least one user exists but nobody is
 * authenticated yet. Credentials are checked by the backend
 * (`POST /api/auth/login`, via `useAuth().login`), which sets the httpOnly
 * session cookie.
 */

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
    <AuthLayout title="sign in" subtitle="nik login: authenticate to continue">
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <label htmlFor="login-username" className={AUTH_LABEL_CLASS}>
            username
          </label>
          <input
            id="login-username"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            placeholder="Your username"
            autoComplete="username"
            autoFocus
            className={AUTH_INPUT_CLASS}
          />
        </div>

        <div>
          <label htmlFor="login-password" className={AUTH_LABEL_CLASS}>
            password
          </label>
          <input
            id="login-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Your password"
            autoComplete="current-password"
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

        <Button type="submit" icon={LogIn} disabled={submitting} className="w-full justify-center">
          {submitting ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    </AuthLayout>
  )
}
