import { useCallback, useEffect, useState } from 'react'
import { AlertCircle, CheckCircle2, KeyRound, RefreshCw, ShieldCheck, ShieldOff, UserCog } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { api } from '../../../services/api.js'
import { rolesOf } from '../../../domain/permissions.js'
import { formatRelative } from '../../../lib/time.js'
import { Badge, Button, Modal, Wait } from '../../ui/index.js'
import { RoleChips } from '../RolePicker.jsx'
import SessionsList from '../SessionsList.jsx'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import {
  CodeOrRecovery,
  ErrorNote,
  IdentityFields,
  NO_PROOF,
  RecoveryCodes,
  SecondFactorSetup,
  proofBody,
  proofComplete,
  useCloseGuard,
} from '../../auth/SecondFactorParts.jsx'

/*
 * "My account" settings section, for every user: who is signed in, the
 * password, the second factor and the open sessions of the account.
 *
 * What changes how the account is protected asks again who it is: the
 * password, and a current code when the account has a second factor (a
 * recovery code is taken in its place). Changing the password, turning the
 * second factor on or off end the account's other sessions; this one goes on.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-fg'
const HEADING_CLASS = 'mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted'

/** A dialog that asks again who it is, then does one thing. `onDone` gets the server's answer. */
function ConfirmIdentityDialog({ title, lead, confirmLabel, busyLabel, danger = false, path, onClose, onDone }) {
  const [proof, setProof] = useState(NO_PROOF)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)

  const submit = async (event) => {
    event.preventDefault()
    if (busy || !proofComplete(proof, true)) return
    setBusy(true)
    setError(null)
    try {
      onDone(await api.post(path, proofBody(proof, true)))
    } catch (failure) {
      setError(failure.message)
      setProof((old) => ({ ...old, code: '' }))
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={title}
      maxWidth="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            waiting={busy}
            variant={danger ? 'danger' : 'primary'}
            type="submit"
            form="confirm-identity-form"
            disabled={busy || !proofComplete(proof, true)}
          >
            {busy ? busyLabel : confirmLabel}
          </Button>
        </>
      }
    >
      <form id="confirm-identity-form" onSubmit={submit} className="space-y-3">
        <div className="space-y-2 text-sm text-fg-muted">{lead}</div>
        <IdentityFields idPrefix="confirm-identity" value={proof} onChange={setProof} hasFactor autoFocus />
        {error && <ErrorNote>{error}</ErrorNote>}
      </form>
    </Modal>
  )
}

/** The second factor of the account: what is on, setting one up, new recovery codes, turning it off. */
function SecondFactor({ state, onChanged }) {
  const { currentUser, refreshMe } = useAuth()
  const [dialog, setDialog] = useState(null) // 'setup' | 'codes' | 'off' | { codes: string[] }
  // Escape and the cross of a dialog that shows recovery codes ask first, while they were not kept.
  const [guard, guarded] = useCloseGuard()
  const closeGuarded = () => guarded(() => setDialog(null))
  const on = state.factors.length > 0
  const changed = async () => {
    await refreshMe()
    await onChanged()
  }

  return (
    <div>
      <h3 className={HEADING_CLASS}>Second factor</h3>
      {on ? (
        <div className="space-y-3">
          <p className="flex flex-wrap items-center gap-2 text-sm text-fg">
            <Badge color="emerald">
              <ShieldCheck className="h-3 w-3" aria-hidden="true" />
              On
            </Badge>
            <span>
              An authenticator app, since {formatRelative(state.factors[0].since)}. Signing in asks for its code after
              your password.
            </span>
          </p>
          <p className={`text-sm ${state.recoveryCodesLeft <= 2 ? 'text-med-fg' : 'text-fg-muted'}`}>
            {state.recoveryCodesLeft === 0
              ? 'No recovery code is left: make new ones, or a lost device locks you out.'
              : `${state.recoveryCodesLeft} recovery code${state.recoveryCodesLeft === 1 ? '' : 's'} left.`}
          </p>
          <div className="flex flex-wrap gap-2">
            <Button variant="secondary" size="sm" icon={RefreshCw} onClick={() => setDialog('codes')}>
              New recovery codes…
            </Button>
            <Button variant="secondary" size="sm" icon={ShieldOff} onClick={() => setDialog('off')}>
              Turn it off…
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-3">
          <p className="max-w-2xl text-sm text-fg-muted">
            With a second factor, signing in asks for a code from an authenticator app on your phone after your
            password: a password that leaked is not enough any more.
            {state.required && ' Administrators must have one.'}
          </p>
          <Button icon={ShieldCheck} onClick={() => setDialog('setup')}>
            Set up a second factor…
          </Button>
        </div>
      )}

      {dialog === 'setup' && (
        <Modal open onClose={closeGuarded} title="Set up a second factor" maxWidth="max-w-2xl">
          <SecondFactorSetup
            username={currentUser.username}
            onEnrolled={changed}
            onDone={() => setDialog(null)}
            onCancel={() => setDialog(null)}
            guard={guard}
          />
        </Modal>
      )}
      {dialog === 'codes' && (
        <ConfirmIdentityDialog
          title="New recovery codes"
          lead={<p>Ten new codes are made, and the ones you have stop working.</p>}
          confirmLabel="Make new codes"
          busyLabel="Making them…"
          path="/auth/second-factor/recovery-codes"
          onClose={() => setDialog(null)}
          onDone={(answer) => {
            setDialog({ codes: answer.recoveryCodes })
            onChanged()
          }}
        />
      )}
      {dialog?.codes && (
        <Modal
          open
          onClose={closeGuarded}
          title="Your new recovery codes"
          maxWidth="max-w-lg"
          footer={<Button onClick={() => setDialog(null)}>Done</Button>}
        >
          <RecoveryCodes codes={dialog.codes} username={currentUser.username} guard={guard} />
        </Modal>
      )}
      {dialog === 'off' && (
        <ConfirmIdentityDialog
          title="Turn the second factor off"
          lead={
            <>
              <p>
                Your account will sign in with its password alone. The recovery codes go with the second factor, and
                your other sessions are signed out.
              </p>
              {state.required && (
                <p className="text-med-fg">
                  Administrators must have a second factor: you will be asked to set one up again at once.
                </p>
              )}
            </>
          }
          confirmLabel="Turn it off"
          busyLabel="Turning it off…"
          danger
          path="/auth/second-factor/off"
          onClose={() => setDialog(null)}
          onDone={() => {
            setDialog(null)
            changed()
          }}
        />
      )}
    </div>
  )
}

export default function MyAccountSection() {
  const { currentUser, changePassword, logout } = useAuth()
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [confirm, setConfirm] = useState('')
  const [proof, setProof] = useState(NO_PROOF)
  const [error, setError] = useState(null)
  const [done, setDone] = useState(false)
  const [saving, setSaving] = useState(false)
  const [factor, setFactor] = useState(null)
  const [factorError, setFactorError] = useState(null)
  // Raised when the sessions changed without the list knowing (a password change ends the others).
  const [sessionsVersion, setSessionsVersion] = useState(0)

  const loadFactor = useCallback(async () => {
    try {
      setFactor(await api.get('/auth/second-factor'))
      setFactorError(null)
    } catch (failure) {
      setFactorError(failure.message)
    }
    setSessionsVersion((version) => version + 1)
  }, [])
  useEffect(() => {
    loadFactor()
  }, [loadFactor])

  const hasFactor = Boolean(factor?.factors.length)
  useUnsavedChanges(Boolean(current || next || confirm), { what: 'The change of your password' })

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
    const code = proofBody({ ...proof, password: current }, hasFactor)
    delete code.password
    const result = await changePassword(current, next, code)
    setSaving(false)
    if (!result.ok) {
      setError(result.error)
      setProof((old) => ({ ...old, code: '' }))
      return
    }
    setCurrent('')
    setNext('')
    setConfirm('')
    setProof(NO_PROOF)
    setDone(true)
    setSessionsVersion((version) => version + 1)
  }

  const loadSessions = useCallback(() => api.get('/auth/sessions'), [])
  const passwordReady = current && next && confirm && proofComplete({ ...proof, password: current }, hasFactor)

  return (
    <section className="space-y-8">
      <div>
        <div className="flex items-center gap-2">
          <UserCog className="h-5 w-5 text-accent" />
          <h2 className="text-base font-semibold text-fg">My account</h2>
        </div>
        <p className="mt-1 flex flex-wrap items-center gap-2 text-sm text-fg-muted">
          Signed in as <span className="font-medium text-fg">{currentUser?.username}</span>
          <RoleChips roles={rolesOf(currentUser)} />
        </p>
      </div>

      <div>
        <h3 className={HEADING_CLASS}>Change password</h3>
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
          {hasFactor && <CodeOrRecovery idPrefix="own-password" value={proof} onChange={setProof} />}

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

          <Button waiting={saving} type="submit" icon={KeyRound} disabled={saving || !passwordReady}>
            {saving ? 'Changing…' : 'Change password'}
          </Button>
        </form>
      </div>

      {factorError && <ErrorNote>{factorError}</ErrorNote>}
      {factor === null && !factorError && <Wait>Reading your second factor…</Wait>}
      {factor && <SecondFactor state={factor} onChanged={loadFactor} />}

      <div>
        <h3 className={HEADING_CLASS}>Sessions</h3>
        <p className="mb-3 max-w-2xl text-sm text-fg-muted">
          Where your account is signed in now. End a session you do not recognise, then change your password.
        </p>
        <SessionsList
          version={sessionsVersion}
          label="Your sessions"
          own
          load={loadSessions}
          end={(session) => (session.current ? logout() : api.del(`/auth/sessions/${encodeURIComponent(session.id)}`))}
          endOthers={() => api.post('/auth/sessions/end-others')}
        />
      </div>
    </section>
  )
}
