import { useState } from 'react'
import { AlertCircle, LogIn } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { Button, Modal } from '../ui/index.js'
import { isCode } from '../../domain/signin.js'
import { sentenceText } from '../../domain/unsaved.js'
import { CodeField, RecoveryCodeField } from './SecondFactorParts.jsx'

/*
 * Shown over the app when the session ended while it was open (the server
 * answered 401). The app stays as it is underneath, with whatever was not
 * saved yet: signing in again as the same user sends it. Signing out instead
 * gives the changes up, and says so.
 *
 * An account with a second factor is asked for its code here too, after the
 * password: signing in again is a sign-in.
 *
 * Nothing is asked here about what is being edited (lib/unsaved.js): signing
 * in again must not wait on a question, and the forms that were open are
 * still open under this dialog, as they were. `unsaved` is their list, named
 * so that whoever signs out instead knows what goes with it.
 */
const INPUT_CLASS =
  'w-full border border-line bg-canvas px-3 py-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const LABEL_CLASS = 'block text-xs font-medium text-fg-muted'

export default function SessionExpiredDialog({ unsavedChanges: pending = false, unsaved = [] }) {
  const { sessionExpired, currentUser, login, loginCode, logout } = useAuth()
  const [password, setPassword] = useState('')
  const [codeAsked, setCodeAsked] = useState(false)
  const [code, setCode] = useState('')
  const [recoveryCode, setRecoveryCode] = useState('')
  const [recovery, setRecovery] = useState(false)
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  if (!sessionExpired || !currentUser) return null
  const unsavedChanges = pending || unsaved.length > 0
  const ready = !codeAsked ? Boolean(password) : recovery ? recoveryCode.trim().length >= 8 : isCode(code)

  const reset = () => {
    setCodeAsked(false)
    setCode('')
    setRecoveryCode('')
    setRecovery(false)
  }

  const submit = async (event) => {
    event.preventDefault()
    if (submitting || !ready) return
    setError(null)
    setSubmitting(true)
    if (!codeAsked) {
      const result = await login(currentUser.username, password)
      setSubmitting(false)
      setPassword('')
      if (!result.ok) setError(result.error || 'Unable to sign in.')
      else if (result.secondFactor) setCodeAsked(true)
      return
    }
    const result = await loginCode(recovery ? { recoveryCode: recoveryCode.trim() } : { code })
    setSubmitting(false)
    setCode('')
    if (result.ok) {
      reset()
      return
    }
    setError(result.error || 'Unable to sign in.')
    if (result.expired) reset()
  }

  return (
    <Modal
      open
      onClose={() => {}}
      title="Session expired"
      maxWidth="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={logout} disabled={submitting}>
            {unsavedChanges ? 'Sign out and lose the changes' : 'Sign out'}
          </Button>
          <Button type="submit" form="session-expired-form" icon={LogIn} disabled={submitting || !ready}>
            {codeAsked ? 'Continue' : 'Sign in again'}
          </Button>
        </>
      }
    >
      <form id="session-expired-form" onSubmit={submit} className="space-y-3">
        <p className="text-fg-muted">
          {unsavedChanges
            ? 'Your session ended and the last changes are not saved yet. Sign in again to save them: nothing on screen is lost.'
            : 'Your session ended. Sign in again to keep working where you were.'}
        </p>
        {unsaved.length > 0 && (
          <ul aria-label="Not saved yet" className="list-disc space-y-1 pl-5 text-fg-muted">
            {unsaved.map((entry) => (
              <li key={entry.id}>{sentenceText(entry)}</li>
            ))}
          </ul>
        )}
        {!codeAsked && (
          <>
            <label htmlFor="session-expired-password" className={LABEL_CLASS}>
              Password of {currentUser.username}
            </label>
            <input
              id="session-expired-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              autoComplete="current-password"
              autoFocus
              className={INPUT_CLASS}
            />
          </>
        )}
        {codeAsked && (
          <div className="space-y-1.5">
            {recovery ? (
              <RecoveryCodeField
                id="session-expired-recovery-code"
                value={recoveryCode}
                onChange={setRecoveryCode}
                autoFocus
                className={INPUT_CLASS}
                labelClassName={`${LABEL_CLASS} mb-1.5`}
              />
            ) : (
              <CodeField
                id="session-expired-code"
                value={code}
                onChange={setCode}
                autoFocus
                className={INPUT_CLASS}
                labelClassName={`${LABEL_CLASS} mb-1.5`}
              />
            )}
            <button
              type="button"
              onClick={() => {
                setRecovery(!recovery)
                setError(null)
              }}
              className="text-xs text-link hover:text-link-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {recovery ? 'Use a code from the app instead' : 'Use a recovery code instead'}
            </button>
          </div>
        )}
        {error && (
          <div
            role="alert"
            className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg"
          >
            <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
      </form>
    </Modal>
  )
}
