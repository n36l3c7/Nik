import { useState } from 'react'
import { AlertCircle, CheckCircle2, KeyRound, UserCog } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { Badge, Button } from '../../ui/index.js'

/*
 * "My account" settings section, for every user: who is signed in, and a
 * form to change one's own password. Changing it ends the account's other
 * sessions; this one goes on.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-fg'

export default function MyAccountSection() {
  const { currentUser, changePassword } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [error, setError] = useState(null)
  const [done, setDone] = useState(false)
  const [saving, setSaving] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    if (saving) return
    setDone(false)
    if (next !== confirm) {
      setError('The new password and its confirmation are not the same.')
      return
    }
    setError(null)
    setSaving(true)
    const result = await changePassword(current, next)
    setSaving(false)
    if (!result.ok) {
      setError(result.error)
      return
    }
    setCurrent('')
    setNext('')
    setConfirm('')
    setDone(true)
  }

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <UserCog className="h-5 w-5 text-accent" />
          <h2 className="text-base font-semibold text-fg">My account</h2>
        </div>
        <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-fg-muted">
          Signed in as <span className="font-medium text-fg">{currentUser?.username}</span>
          <Badge color={currentUser?.role === 'admin' ? 'cyan' : 'slate'}>
            {currentUser?.role === 'admin' ? 'Admin' : 'Analyst'}
          </Badge>
        </p>
      </div>

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Change password</h3>
        <form onSubmit={submit} className="max-w-md space-y-3">
          <div>
            <label htmlFor="own-current-password" className={LABEL_CLASS}>
              Current password
            </label>
            <input
              id="own-current-password"
              type="password"
              value={current}
              onChange={(event) => setCurrent(event.target.value)}
              autoComplete="current-password"
              className={INPUT_CLASS}
            />
          </div>
          <div>
            <label htmlFor="own-new-password" className={LABEL_CLASS}>
              New password
            </label>
            <input
              id="own-new-password"
              type="password"
              value={next}
              onChange={(event) => setNext(event.target.value)}
              placeholder="At least 8 characters"
              autoComplete="new-password"
              className={INPUT_CLASS}
            />
          </div>
          <div>
            <label htmlFor="own-confirm-password" className={LABEL_CLASS}>
              Confirm the new password
            </label>
            <input
              id="own-confirm-password"
              type="password"
              value={confirm}
              onChange={(event) => setConfirm(event.target.value)}
              autoComplete="new-password"
              className={INPUT_CLASS}
            />
          </div>

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}
          {done && (
            <p role="status" className="flex items-center gap-2 text-sm text-fg">
              <CheckCircle2 className="h-4 w-4 text-accent" aria-hidden="true" />
              Password changed. Your other sessions were signed out.
            </p>
          )}

          <Button type="submit" icon={KeyRound} disabled={saving || !current || !next || !confirm}>
            {saving ? 'Changing…' : 'Change password'}
          </Button>
        </form>
      </div>
    </section>
  )
}
