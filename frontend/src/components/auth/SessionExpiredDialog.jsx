import { useState } from 'react'
import { AlertCircle, LogIn } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { Button, Modal } from '../ui/index.js'

/*
 * Shown over the app when the session ended while it was open (the server
 * answered 401). The app stays as it is underneath, with whatever was not
 * saved yet: signing in again as the same user sends it. Signing out instead
 * gives the changes up, and says so.
 */
export default function SessionExpiredDialog({ unsavedChanges = false }) {
  const { sessionExpired, currentUser, login, logout } = useAuth()
  const [password, setPassword] = useState('')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  if (!sessionExpired || !currentUser) return null

  const submit = async (event) => {
    event.preventDefault()
    if (submitting) return
    setError(null)
    setSubmitting(true)
    const result = await login(currentUser.username, password)
    setSubmitting(false)
    setPassword('')
    if (!result.ok) setError(result.error || 'Unable to sign in.')
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
          <Button type="submit" form="session-expired-form" icon={LogIn} disabled={submitting || !password}>
            Sign in again
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
        <label htmlFor="session-expired-password" className="block text-xs font-medium text-fg-muted">
          Password of {currentUser.username}
        </label>
        <input
          id="session-expired-password"
          type="password"
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          autoComplete="current-password"
          autoFocus
          className="w-full border border-line bg-canvas px-3 py-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
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
