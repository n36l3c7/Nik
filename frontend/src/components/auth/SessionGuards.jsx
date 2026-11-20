import { useEffect, useRef, useState } from 'react'
import { Clock, LogOut, ShieldAlert } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { countdown, recoveryCodesLeftText, sessionPhase } from '../../domain/signin.js'
import { Button, Modal } from '../ui/index.js'
import AuthLayout from './AuthLayout.jsx'
import { SecondFactorSetup } from './SecondFactorParts.jsx'

/*
 * What stands between a signed-in person and the app when the server says so:
 *
 *  - the session is about to end for not being used: a warning a minute
 *    before, with "Stay signed in" (when it does end, SessionExpiredDialog
 *    takes over, and what is on screen stays);
 *  - the account must set a second factor up: at the sign-in a page of its
 *    own (RequiredEnrolmentScreen, before the app is shown at all), later a
 *    dialog over the app (an administrator just required it);
 *  - an administrator is not on one of the administrators' networks;
 *  - what the sign-in said once: the second factor was reset, a recovery code
 *    was spent.
 *
 * None of these can be closed with Escape: each ends with its own button.
 */

const TICK_MS = 1000
// The server is not asked more often than this while the end is near.
const ASK_EVERY_MS = 5000
// Without being near any end, the server is asked this often: an administrator may have changed the times.
const REFRESH_EVERY_MS = 5 * 60_000

/** The warning before a session ends, and the checks that lead to it. */
function SessionEnding() {
  const { getSessionClock, checkSession, staySignedIn, sessionExpired } = useAuth()
  const [warning, setWarning] = useState(null) // { reason, left }
  const [busy, setBusy] = useState(false)
  const asked = useRef(0)
  // The person read the warning that cannot be answered (the lifetime is over): it is not shown again.
  const read = useRef(false)

  useEffect(() => {
    if (sessionExpired) {
      setWarning(null)
      return undefined
    }
    const tick = () => {
      const now = Date.now()
      const { phase, reason, left } = sessionPhase(getSessionClock(), now)
      // The server's word, often while the end is near (another tab may have used the session, and
      // when it is over the server is who says so), now and then otherwise (the times may have changed).
      const since = now - asked.current
      const near = phase !== 'fine' && since >= ASK_EVERY_MS
      const routine = phase === 'fine' && since >= REFRESH_EVERY_MS && document.visibilityState === 'visible'
      if (near || routine) {
        asked.current = now
        checkSession()
      }
      if (phase !== 'warn') read.current = false
      const warn = phase === 'warn' && !read.current
      setWarning((shown) => {
        if (!warn) return null
        return shown?.left === left && shown.reason === reason ? shown : { reason, left }
      })
    }
    asked.current = Date.now()
    const timer = setInterval(tick, TICK_MS)
    return () => clearInterval(timer)
  }, [getSessionClock, checkSession, sessionExpired])

  if (!warning || sessionExpired) return null
  const idle = warning.reason === 'idle'

  const stay = async () => {
    setBusy(true)
    await staySignedIn()
    setBusy(false)
    setWarning(null)
  }

  return (
    <Modal
      open
      onClose={() => {}}
      title="Your session is about to end"
      maxWidth="max-w-md"
      footer={
        idle ? (
          <Button waiting={busy} icon={Clock} onClick={stay} disabled={busy}>
            Stay signed in
          </Button>
        ) : (
          <Button
            onClick={() => {
              read.current = true
              setWarning(null)
            }}
          >
            OK
          </Button>
        )
      }
    >
      <div className="space-y-2 text-fg-muted">
        <p>
          {idle
            ? 'Nothing was done here for a while. You will be signed out in '
            : 'This session has lasted as long as one may. It ends in '}
          <span role="timer" className="font-mono text-fg">
            {countdown(warning.left)}
          </span>
          .
        </p>
        <p>
          {idle
            ? 'When a session ends, what is on screen stays: you are asked for your password and go on.'
            : 'Save what you can now. What is on screen stays: you will be asked to sign in again and go on.'}
        </p>
      </div>
    </Modal>
  )
}

/** The second factor became a must while the app was open: it is set up here, over what was on screen. */
function RequiredEnrolmentDialog() {
  const { currentUser, mustEnrol, isAuthenticated, sessionExpired, enrolled, logout } = useAuth()
  // Kept open while the recovery codes are read, though the factor is already on.
  const [open, setOpen] = useState(false)
  useEffect(() => {
    if (mustEnrol && isAuthenticated) setOpen(true)
  }, [mustEnrol, isAuthenticated])
  if (!open || sessionExpired || !currentUser) return null
  return (
    <Modal open onClose={() => {}} title="Set up your second factor" maxWidth="max-w-2xl">
      <div className="space-y-4">
        <p className="text-sm text-fg-muted">
          An administrator now requires a second factor for your role. Nothing else answers until yours is set up; what
          was on screen is still there underneath.
        </p>
        <SecondFactorSetup
          username={currentUser.username}
          onEnrolled={enrolled}
          onDone={() => setOpen(false)}
          doneLabel="Go on"
        />
        {mustEnrol && (
          <div className="border-t border-line pt-3">
            <Button variant="ghost" size="sm" icon={LogOut} onClick={logout}>
              Sign out instead
            </Button>
          </div>
        )}
      </div>
    </Modal>
  )
}

/** An administrator who is not on one of the administrators' networks. */
function NetworkRefusal() {
  const { refusal, clearRefusal, refreshMe, logout, sessionExpired } = useAuth()
  const [busy, setBusy] = useState(false)
  const [again, setAgain] = useState(false)
  if (!refusal || refusal.code !== 'admin_network' || sessionExpired) return null
  const retry = async () => {
    setBusy(true)
    setAgain(false)
    // Answered from a listed network, the refusal is over; otherwise the server says it again.
    const user = await refreshMe()
    setBusy(false)
    if (user) clearRefusal()
    else setAgain(true)
  }
  return (
    <Modal
      open
      onClose={() => {}}
      title="Not from this network"
      maxWidth="max-w-md"
      footer={
        <>
          <Button variant="ghost" icon={LogOut} onClick={logout} disabled={busy}>
            Sign out
          </Button>
          <Button waiting={busy} onClick={retry} disabled={busy}>
            Try again
          </Button>
        </>
      }
    >
      <div className="space-y-2 text-fg-muted">
        <p className="flex items-start gap-2 text-fg">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-high" aria-hidden="true" />
          <span>{refusal.message}</span>
        </p>
        <p>
          Your session is still there: from a listed network it answers again. What is on screen stays, but nothing can
          be saved from here.
        </p>
        {again && <p role="status">Still refused from this address.</p>}
      </div>
    </Modal>
  )
}

/** What the sign-in said once. */
function SignInNote() {
  const { signInNote, dismissSignInNote, mustEnrol, sessionExpired } = useAuth()
  if (!signInNote || sessionExpired) return null
  const { notice, recoveryCodesLeft } = signInNote
  const reset = notice === 'second_factor_reset'
  // An account that is being led to set a factor up is told there; nothing to add.
  if (reset && mustEnrol && recoveryCodesLeft === null) return null
  return (
    <Modal
      open
      onClose={dismissSignInNote}
      title={reset ? 'Your second factor was reset' : 'Recovery code used'}
      maxWidth="max-w-md"
      footer={<Button onClick={dismissSignInNote}>OK</Button>}
    >
      <div className="space-y-2 text-fg-muted">
        {reset && (
          <p>
            Your second factor was taken away by an administrator, or from the server: your account signs in with its
            password alone. Set a second factor up again in Settings → My account.
          </p>
        )}
        {recoveryCodesLeft !== null && <p>{recoveryCodesLeftText(recoveryCodesLeft)}</p>}
      </div>
    </Modal>
  )
}

/** Mounted once, by App, over everything else. */
export default function SessionGuards() {
  return (
    <>
      <SignInNote />
      <RequiredEnrolmentDialog />
      <NetworkRefusal />
      <SessionEnding />
    </>
  )
}

/**
 * The page an account lands on when it signs in and must set its second factor up: the app is not
 * shown, and nothing of it is loaded, before that is done.
 */
export function RequiredEnrolmentScreen() {
  const { currentUser, enrolled, logout, signInNote } = useAuth()
  const [on, setOn] = useState(false)
  return (
    <AuthLayout title="second factor" subtitle={`nik login: ${currentUser.username} must set one up`}>
      <div className="space-y-4">
        {!on && (
          <p className="text-sm text-fg-muted">
            {signInNote?.notice === 'second_factor_reset'
              ? 'Your second factor was reset, and your role requires one. Set it up again to go on.'
              : 'Your role requires a second factor: a code from an authenticator app, asked after your password. Set it up to go on.'}
          </p>
        )}
        <SecondFactorSetup
          username={currentUser.username}
          // The app opens once the recovery codes were read, not before.
          onEnrolled={() => setOn(true)}
          onDone={enrolled}
          doneLabel="Open Nik"
        />
        {!on && (
          <p className="border-t border-line pt-3">
            <button
              type="button"
              onClick={logout}
              className="font-mono text-xs text-link hover:text-link-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              Sign out
            </button>
          </p>
        )}
      </div>
    </AuthLayout>
  )
}
