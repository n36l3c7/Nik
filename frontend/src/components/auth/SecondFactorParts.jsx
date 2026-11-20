import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AlertCircle, Check, Copy, Download, ShieldCheck } from 'lucide-react'
import { api } from '../../services/api.js'
import { cleanCode, groupedSecret, isCode, recoveryCodesFile } from '../../domain/signin.js'
import { qrMatrix, qrPath } from '../../domain/qr.js'
import { copyText, saveBlob } from '../../lib/download.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'
import { Button, Wait } from '../ui/index.js'

/*
 * The pieces every screen of the second factor is made of: the field a code
 * is typed in, the fields that ask again who it is (password, and a code when
 * the account has a factor), the recovery codes shown once, and the set-up
 * itself (the QR code, the secret as text, the first code).
 *
 * The QR code is drawn here (domain/qr.js): the address it carries holds the
 * secret, and goes nowhere.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-fg'

export function ErrorNote({ children }) {
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

/**
 * The six digits of an authenticator app. Takes a paste ("123 456"), the digits of a phone keyboard,
 * and what the browser or the system offers to fill in.
 * @param {{ id: string, value: string, onChange: (code: string) => void, label?: string,
 *   autoFocus?: boolean, className?: string, labelClassName?: string }} props
 */
export function CodeField({
  id,
  value,
  onChange,
  label = 'Code from your authenticator app',
  autoFocus = false,
  className = INPUT_CLASS,
  labelClassName = LABEL_CLASS,
}) {
  return (
    <div>
      <label htmlFor={id} className={labelClassName}>
        {label}
      </label>
      <input
        id={id}
        type="text"
        inputMode="numeric"
        pattern="[0-9]*"
        autoComplete="one-time-code"
        autoCorrect="off"
        spellCheck={false}
        value={value}
        onChange={(event) => onChange(cleanCode(event.target.value))}
        placeholder="6 digits"
        autoFocus={autoFocus}
        className={`${className} font-mono tracking-[0.3em]`}
      />
    </div>
  )
}

/** A recovery code typed in place of the code of the app. */
export function RecoveryCodeField({
  id,
  value,
  onChange,
  autoFocus = false,
  className = INPUT_CLASS,
  labelClassName = LABEL_CLASS,
}) {
  return (
    <div>
      <label htmlFor={id} className={labelClassName}>
        Recovery code
      </label>
      <input
        id={id}
        type="text"
        autoComplete="off"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder="xxxx-xxxx-xxxx-xxxx"
        autoFocus={autoFocus}
        className={`${className} font-mono`}
      />
    </div>
  )
}

/** What the identity fields hold when nothing was typed. */
export const NO_PROOF = { password: '', code: '', recoveryCode: '', recovery: false }

/** Whether the fields hold what the server will ask for. */
export function proofComplete(proof, hasFactor) {
  if (!proof.password) return false
  if (!hasFactor) return true
  return proof.recovery ? proof.recoveryCode.trim().length >= 8 : isCode(proof.code)
}

/** The body the server takes: the password and, with a factor, the code or the recovery code. */
export function proofBody(proof, hasFactor) {
  const body = { password: proof.password }
  if (hasFactor && proof.recovery) body.recoveryCode = proof.recoveryCode.trim()
  if (hasFactor && !proof.recovery) body.code = proof.code
  return body
}

/** The code of the app, or a recovery code in its place by the link under the field. */
export function CodeOrRecovery({ idPrefix, value, onChange }) {
  const set = (changes) => onChange({ ...value, ...changes })
  return (
    <div>
      {value.recovery ? (
        <RecoveryCodeField
          id={`${idPrefix}-recovery`}
          value={value.recoveryCode}
          onChange={(recoveryCode) => set({ recoveryCode })}
        />
      ) : (
        <CodeField id={`${idPrefix}-code`} value={value.code} onChange={(code) => set({ code })} />
      )}
      <button
        type="button"
        onClick={() => set({ recovery: !value.recovery, code: '', recoveryCode: '' })}
        className="mt-1.5 text-xs text-link hover:text-link-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
      >
        {value.recovery ? 'Use a code from the app instead' : 'Use a recovery code instead'}
      </button>
    </div>
  )
}

/**
 * Asking again who it is, before something that changes how the account is protected: the password,
 * and a current code when the account has a second factor (or a recovery code).
 * @param {{ idPrefix: string, value: typeof NO_PROOF, onChange: (next: typeof NO_PROOF) => void,
 *   hasFactor: boolean, passwordLabel?: string, autoFocus?: boolean }} props
 */
export function IdentityFields({
  idPrefix,
  value,
  onChange,
  hasFactor,
  passwordLabel = 'Your password',
  autoFocus = false,
}) {
  const set = (changes) => onChange({ ...value, ...changes })
  return (
    <div className="space-y-3">
      <div>
        <label htmlFor={`${idPrefix}-password`} className={LABEL_CLASS}>
          {passwordLabel}
        </label>
        <input
          id={`${idPrefix}-password`}
          type="password"
          value={value.password}
          onChange={(event) => set({ password: event.target.value })}
          autoComplete="current-password"
          autoFocus={autoFocus}
          className={INPUT_CLASS}
        />
      </div>
      {hasFactor && <CodeOrRecovery idPrefix={idPrefix} value={value} onChange={onChange} />}
    </div>
  )
}

/**
 * The recovery codes, shown this once: the list, Copy and Download. While they are on screen and were
 * neither copied nor downloaded, leaving asks first (they cannot be shown again).
 *
 * `guard` is a ref the dialog that shows them reads before it closes by Escape or its cross:
 * `guard.current(close)` asks when the codes were not kept, and closes otherwise (useCloseGuard).
 * @param {{ codes: string[], username: string, guard?: { current: Function | null } }} props
 */
export function RecoveryCodes({ codes, username, guard = null }) {
  const [kept, setKept] = useState(null) // 'copied' | 'downloaded' | 'refused'
  const unsaved = useUnsavedChanges(kept === null || kept === 'refused', {
    what: 'Your recovery codes',
    sentence: 'Your recovery codes were neither copied nor downloaded, and they are shown only now.',
  })
  useEffect(() => {
    if (!guard) return undefined
    guard.current = unsaved.leave
    return () => {
      guard.current = null
    }
  }, [guard, unsaved])

  const copy = async () => setKept((await copyText(codes.join('\n'))) ? 'copied' : 'refused')
  const download = () => {
    saveBlob(
      new Blob([recoveryCodesFile(codes, username)], { type: 'text/plain' }),
      `nik-recovery-codes-${username}.txt`,
    )
    setKept('downloaded')
  }

  return (
    <div className="space-y-3">
      <p className="text-sm text-fg-muted">
        Each of these codes signs you in once, in place of the code of your app: for the day the device is lost or
        broken. They are shown only now. Keep them where your password is not.
      </p>
      <ul
        aria-label="Recovery codes"
        className="grid grid-cols-2 gap-x-6 gap-y-1 border border-line bg-canvas px-4 py-3 font-mono text-sm text-fg"
      >
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex flex-wrap items-center gap-2">
        <Button variant="secondary" size="sm" icon={Copy} onClick={copy}>
          Copy
        </Button>
        <Button variant="secondary" size="sm" icon={Download} onClick={download}>
          Download
        </Button>
        <span role="status" className="text-xs text-fg-muted">
          {kept === 'copied' && 'Copied.'}
          {kept === 'downloaded' && 'Downloaded.'}
          {kept === 'refused' && 'The browser refused the copy: download them, or write them down.'}
        </span>
      </div>
    </div>
  )
}

/**
 * For a dialog that may hold recovery codes: `[guard, close]`, where `guard` goes to what shows the
 * codes and `close(action)` runs `action` at once, or after asking when codes are on screen and were
 * not kept.
 */
export function useCloseGuard() {
  const guard = useRef(null)
  const close = useCallback((action) => (guard.current ? guard.current(action) : action()), [])
  return [guard, close]
}

/** The QR code of an address, dark on white whatever the theme (a camera reads it). */
export function QrCode({ text, label }) {
  const drawn = useMemo(() => {
    const matrix = qrMatrix(text)
    return matrix ? { size: matrix.length + 8, path: qrPath(matrix) } : null
  }, [text])
  if (!drawn) return null
  return (
    <svg
      role="img"
      aria-label={label}
      viewBox={`0 0 ${drawn.size} ${drawn.size}`}
      shapeRendering="crispEdges"
      className="h-44 w-44 shrink-0 border border-line bg-white"
    >
      <rect width={drawn.size} height={drawn.size} fill="#ffffff" />
      <path d={drawn.path} fill="#000000" />
    </svg>
  )
}

/**
 * Setting an authenticator app up: the server makes a secret, shown as a QR code and as text; a first
 * code from the app turns it on; then the recovery codes are shown, once.
 *
 * @param {{
 *   username: string,
 *   onEnrolled?: () => void,   // the factor is on (the recovery codes are still on screen)
 *   onDone: () => void,        // the person is finished with the recovery codes
 *   onCancel?: () => void,     // offered before the factor is on
 *   guard?: object,            // see RecoveryCodes
 *   doneLabel?: string,
 * }} props
 */
export function SecondFactorSetup({ username, onEnrolled, onDone, onCancel = null, doneLabel = 'Done', guard = null }) {
  const [started, setStarted] = useState(null) // { secret, uri }
  const [error, setError] = useState(null)
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [codes, setCodes] = useState(null)
  const [copied, setCopied] = useState(false)

  // Asked once, however often the effect runs: each asking makes a new secret and ends the one before.
  const asked = useRef(null)
  useEffect(() => {
    let cancelled = false
    asked.current ??= api.post('/auth/second-factor/totp')
    asked.current
      .then((answer) => !cancelled && setStarted(answer))
      .catch((failure) => !cancelled && setError(failure.message))
    return () => {
      cancelled = true
    }
  }, [])

  const confirm = async (event) => {
    event.preventDefault()
    if (busy || !isCode(code)) return
    setBusy(true)
    setError(null)
    try {
      const answer = await api.post('/auth/second-factor/totp/confirm', { code })
      setCodes(answer.recoveryCodes)
      onEnrolled?.()
    } catch (failure) {
      setError(failure.message)
      setCode('')
    }
    setBusy(false)
  }

  if (codes) {
    return (
      <div className="space-y-4">
        <p role="status" className="flex items-center gap-2 text-sm text-fg">
          <ShieldCheck className="h-4 w-4 text-accent" aria-hidden="true" />
          Your second factor is on. From now on, signing in asks for a code from the app.
        </p>
        <RecoveryCodes codes={codes} username={username} guard={guard} />
        <div className="flex justify-end">
          <Button icon={Check} onClick={onDone}>
            {doneLabel}
          </Button>
        </div>
      </div>
    )
  }

  if (!started) {
    return error ? (
      <div className="space-y-3">
        <ErrorNote>{error}</ErrorNote>
        {onCancel && (
          <Button variant="ghost" onClick={onCancel}>
            Close
          </Button>
        )}
      </div>
    ) : (
      <Wait>Making a secret…</Wait>
    )
  }

  return (
    <form onSubmit={confirm} className="space-y-4">
      <ol className="list-decimal space-y-1 pl-5 text-sm text-fg-muted">
        <li>
          Open an authenticator app on your phone (any app that makes six-digit codes that change every 30 seconds).
        </li>
        <li>Scan this code with it, or type the secret in.</li>
        <li>Type the code the app shows.</li>
      </ol>
      <div className="flex flex-wrap items-start gap-4">
        <QrCode text={started.uri} label="QR code to scan with the authenticator app" />
        <div className="min-w-0 flex-1 space-y-2">
          <p className="text-xs font-medium text-fg-muted">Secret, to type in instead of scanning</p>
          <p aria-label="Secret" className="break-all border border-line bg-canvas px-3 py-2 font-mono text-sm text-fg">
            {groupedSecret(started.secret)}
          </p>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="xs"
              icon={Copy}
              onClick={async () => setCopied(await copyText(started.secret))}
            >
              Copy the secret
            </Button>
            <span role="status" className="text-xs text-fg-muted">
              {copied && 'Copied.'}
            </span>
          </div>
          <p className="text-xs text-fg-muted">
            Account {started.account}, issuer {started.issuer}, time based, 6 digits, 30 seconds. It is shown only now.
          </p>
        </div>
      </div>
      <div className="max-w-xs">
        <CodeField id="second-factor-first-code" value={code} onChange={setCode} label="Code the app shows" autoFocus />
      </div>
      {error && <ErrorNote>{error}</ErrorNote>}
      <div className="flex justify-end gap-2">
        {onCancel && (
          <Button variant="ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </Button>
        )}
        <Button waiting={busy} type="submit" icon={ShieldCheck} disabled={busy || !isCode(code)}>
          {busy ? 'Checking…' : 'Turn it on'}
        </Button>
      </div>
    </form>
  )
}
