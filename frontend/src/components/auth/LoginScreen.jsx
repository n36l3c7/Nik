import { useState } from 'react'
import { LogIn, AlertCircle, ShieldCheck } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { isCode } from '../../domain/signin.js'
import { Button } from '../ui/index.js'
import AuthLayout, { AUTH_INPUT_CLASS, AUTH_LABEL_CLASS } from './AuthLayout.jsx'
import { CodeField, RecoveryCodeField } from './SecondFactorParts.jsx'

/*
 * ============================================================================
 * LoginScreen
 * ============================================================================
 *
 * Sign-in screen shown when at least one user exists but nobody is
 * authenticated yet. Credentials are checked by the backend
 * (`POST /api/auth/login`, via `useAuth().login`), which sets the httpOnly
 * session cookie.
 *
 * An account with a second factor gets a second step: the code of its
 * authenticator app, or a recovery code. The right password alone signs
 * nobody in; the server gives the browser a few minutes for the code.
 */

const LINK_CLASS =
  'font-mono text-xs text-link hover:text-link-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function ErrorBox({ children }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
    >
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </div>
  )
}

/** The second step: the code, or a recovery code by its link. */
function CodeStep({ onBack }) {
  const { loginCode } = useAuth()
  const [code, setCode] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
  const [recovery, setRecovery] = useState(false)
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const ready = recovery ? recoveryCode.trim().length >= 8 : isCode(code)

  const submit = async (event) => {
    event.preventDefault()
    if (submitting || !ready) return
    setError(null)
    setSubmitting(true)
    const result = await loginCode(recovery ? { recoveryCode: recoveryCode.trim() } : { code })
    if (result.ok) return // the app takes the place of this screen
    setSubmitting(false)
    setCode('')
    if (result.expired) onBack(result.error)
    else setError(result.error)
  }

  return (
    <form onSubmit={submit} className="space-y-4">
      {recovery ? (
        <RecoveryCodeField
          id="login-recovery-code"
          value={recoveryCode}
          onChange={setRecoveryCode}
          autoFocus
          className={AUTH_INPUT_CLASS}
          labelClassName={AUTH_LABEL_CLASS}
        />
      ) : (
        <CodeField
          id="login-code"
          value={code}
          onChange={setCode}
          label="code from your authenticator app"
          autoFocus
          className={AUTH_INPUT_CLASS}
          labelClassName={AUTH_LABEL_CLASS}
        />
      )}
      {error && <ErrorBox>{error}</ErrorBox>}
      <Button
        waiting={submitting}
        type="submit"
        icon={ShieldCheck}
        disabled={submitting || !ready}
        className="w-full justify-center"
      >
        {submitting ? 'Checking…' : 'Continue'}
      </Button>
      <div className="flex flex-wrap justify-between gap-2">
        <button
          type="button"
          className={LINK_CLASS}
          onClick={() => {
            setRecovery(!recovery)
            setError(null)
          }}
        >
          {recovery ? 'Use a code from the app instead' : 'Use a recovery code instead'}
        </button>
        <button type="button" className={LINK_CLASS} onClick={() => onBack(null)}>
          Start again
        </button>
      </div>
    </form>
  )
}

export default function LoginScreen() {
  const { login } = useAuth()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const [codeAsked, setCodeAsked] = useState(false)

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
    if (result.secondFactor) {
      setPassword('')
      setSubmitting(false)
      setCodeAsked(true)
    }
    // On success the App shell re-renders into the main app and unmounts this
    // screen, so we intentionally keep the button disabled until then.
  }

  if (codeAsked) {
    return (
      <AuthLayout title="second step" subtitle={`nik login: a code for ${username.trim()}`}>
        <CodeStep
          onBack={(reason) => {
            setCodeAsked(false)
            setError(reason)
          }}
        />
      </AuthLayout>
    )
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

        {error && <ErrorBox>{error}</ErrorBox>}

        <Button waiting={submitting} type="submit" icon={LogIn} disabled={submitting} className="w-full justify-center">
          {submitting ? 'Signing in…' : 'Sign in'}
        </Button>
      </form>
    </AuthLayout>
  )
}
