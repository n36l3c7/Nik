import { useCallback, useEffect, useState } from 'react'
import { AlertTriangle, FileKey2, RefreshCw, Terminal } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { api } from '../../../services/api.js'
import { formatBytes } from '../../../domain/events.js'
import {
  auditSignedLines,
  encryptionStatus,
  planLines,
  restartOnceText,
  restartText,
  rotating,
  rotationPercent,
  rotationStatus,
  sourceText,
} from '../../../domain/keys.js'
import { formatDateTime } from '../../../lib/time.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { ErrorNote, IdentityFields, NO_PROOF, proofBody, proofComplete } from '../../auth/SecondFactorParts.jsx'
import { usePageMenu } from '../../menu/usePageMenu.js'
import { Badge, Button, Modal, TransferBar, Wait } from '../../ui/index.js'

/*
 * System → Keys (admins).
 *
 * Every secret the stack has: where it comes from (a file given to the
 * containers that use it, or the environment), what it protects, which
 * containers hold it. For the two keys that encrypt (the secret key and the
 * store key) and the key that signs the audit log: the fingerprint, since
 * when the key is in use, and changing it. For the audit key also how many
 * entries each key signed, and how many cannot be checked for want of theirs.
 *
 * A key is changed in two places. Here an administrator asks for it, giving
 * the password again (and a code, with a second factor), and sees what will
 * be put under the new key. On the host a command writes the new key where
 * keys are kept: the server cannot write there. Then this page shows the
 * change to its end.
 *
 * No value of a key is ever shown, nor a part of one.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const HEADING = 'font-mono text-[11px] uppercase tracking-wider text-fg-muted'
const when = (iso) => (iso ? formatDateTime(Date.parse(iso)) : '')

function Command({ children }) {
  return (
    <p className="flex items-start gap-2 border border-line bg-canvas px-3 py-2 font-mono text-xs text-fg">
      <Terminal className="mt-0.5 h-3.5 w-3.5 shrink-0 text-fg-muted" aria-hidden="true" />
      <code className="min-w-0 break-all">{children}</code>
    </p>
  )
}

/** Asking for a key to be changed: what it touches, who asks, then what to run on the host. */
function RotateDialog({ entry, hasFactor, onClose, onAsked }) {
  const [plan, setPlan] = useState(null)
  const [proof, setProof] = useState(NO_PROOF)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [asked, setAsked] = useState(entry.request ? { ...entry, command: entry.command } : null)

  useEffect(() => {
    let alive = true
    api
      .get(`/system/keys/${entry.name}/rotation`)
      .then((found) => alive && setPlan(found))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [entry.name])

  const submit = async (event) => {
    event.preventDefault()
    if (busy || !proofComplete(proof, hasFactor)) return
    setBusy(true)
    setError(null)
    try {
      const answer = await api.post(`/system/keys/${entry.name}/rotation`, proofBody(proof, hasFactor))
      setAsked(answer)
      onAsked()
    } catch (failure) {
      setError(failure.message)
      setProof((old) => ({ ...old, code: '' }))
    } finally {
      setBusy(false)
    }
  }
  const withdraw = async () => {
    setBusy(true)
    try {
      await api.del(`/system/keys/${entry.name}/rotation`)
      onAsked()
      onClose()
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }
  // What was typed is a password: leaving the dialog loses nothing worth keeping, and asks nothing.
  const lines = planLines(plan)
  // The key that signs the audit log: nothing is stored under it, so a change moves nothing.
  const audit = entry.name === 'AUDIT_KEY'
  const command = asked?.command ?? plan?.command ?? entry.command

  return (
    <Modal
      open
      onClose={onClose}
      title={`Change the ${entry.label.toLowerCase()}`}
      maxWidth="max-w-xl"
      footer={
        asked ? (
          <>
            <Button variant="ghost" onClick={withdraw} disabled={busy}>
              Withdraw the request
            </Button>
            <Button onClick={onClose}>Done</Button>
          </>
        ) : (
          <>
            <Button variant="ghost" onClick={onClose} disabled={busy}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="form-rotate-key"
              waiting={busy}
              disabled={busy || !plan || !proofComplete(proof, hasFactor)}
            >
              Ask for the change
            </Button>
          </>
        )
      }
    >
      {!asked && (
        <form id="form-rotate-key" onSubmit={submit} className="space-y-3 text-sm text-fg-muted">
          {audit ? (
            <p>
              A new key is made by the server and signs the audit log from the next entry on. Nothing is signed again:
              the entries written so far keep the key that signed them, and that key stays among the keys of the server
              (AUDIT_KEY_PREVIOUS), so that they can still be checked.
            </p>
          ) : (
            <p>
              A new key is made by the server and everything under the key in use is put under it:{' '}
              {entry.name === 'STORE_KEY'
                ? 'the head of each file of the store. The files themselves are not written again.'
                : 'every secret kept in the database, and the snapshots taken before upgrades while no backup passphrase was set.'}
            </p>
          )}
          {!plan && !error && <Wait>Counting what will be put under the new key…</Wait>}
          {plan && (
            <ul
              aria-label={audit ? 'What keeps its key' : 'What will be put under the new key'}
              className="border border-line bg-canvas px-3 py-2"
            >
              {lines.length === 0 && (
                <li>{audit ? 'No entry was signed yet.' : 'Nothing is stored under this key yet.'}</li>
              )}
              {lines.map((line) => (
                <li key={line} className="font-mono text-xs text-fg">
                  {line}
                </li>
              ))}
            </ul>
          )}
          {!audit && (
            <p>
              The server holds both keys until everything was read back under the new one alone; only then is the
              earlier key taken away. Stopped at any moment, the change goes on from where it was.
            </p>
          )}
          {entry.name === 'SECRET_KEY' && plan?.auditKeyDerived && (
            <p>
              The audit log of this server is signed with a key derived from the secret key. Before the earlier secret
              key is taken away, the command writes the key derived from it beside the audit keys (AUDIT_KEY_PREVIOUS):
              the entries signed until now can still be checked afterwards.
            </p>
          )}
          <p>
            It is asked for here and carried out on the server, by who administers it: the new key is written straight
            where the keys are kept and is never shown. {audit ? restartOnceText(plan) : restartText(plan)}
          </p>
          <IdentityFields idPrefix="rotate-key" value={proof} onChange={setProof} hasFactor={hasFactor} autoFocus />
          {error && <ErrorNote>{error}</ErrorNote>}
        </form>
      )}
      {asked && (
        <div className="space-y-3 text-sm text-fg-muted">
          <p role="status" className="text-fg">
            The change was asked for. Within a day, on the server, in the folder of Nik:
          </p>
          <Command>{command}</Command>
          {audit ? (
            <p>
              {restartOnceText(asked.restarts ? asked : plan)} The command keeps the key in use until now among the
              earlier audit keys, and says which key signs once the server answers.
            </p>
          ) : (
            <p>
              {restartText(asked.restarts ? asked : plan)} The command waits for the server to say the change is
              verified, then takes the earlier key away and says where it put it.
            </p>
          )}
          {error && <ErrorNote>{error}</ErrorNote>}
          {audit ? (
            <p>
              Keep a copy of the audit key and of the earlier ones where the copy of the secret key is: a server that is
              restored checks the log that comes back with them.
            </p>
          ) : entry.name === 'SECRET_KEY' ? (
            <p>
              The backups taken before the change hold their secrets under the earlier key: keep it with them, for as
              long as you keep them. Open sessions are not ended.
            </p>
          ) : (
            <p>
              No backup depends on the store key: a backup holds the files themselves, under its own passphrase. Keep a
              copy of the new key away from the server all the same.
            </p>
          )}
        </div>
      )}
    </Modal>
  )
}

/** Setting or changing the backup passphrase, from the place the keys are. */
function PassphraseDialog({ held, onClose, onSaved }) {
  const [first, setFirst] = useState('')
  const [second, setSecond] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const problem =
    first.length < 12
      ? 'At least 12 characters.'
      : first !== second
        ? 'Type the same passphrase twice.'
        : first !== first.trim()
          ? 'It cannot start or end with a space.'
          : null

  const save = async (event) => {
    event?.preventDefault()
    if (problem) return false
    setBusy(true)
    setError(null)
    try {
      await api.put('/backups/passphrase', { passphrase: first })
      onSaved()
      return true
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
      return false
    }
  }
  const unsaved = useUnsavedChanges(Boolean(first || second), {
    what: 'The backup passphrase',
    save: problem ? undefined : () => save(),
  })

  return (
    <Modal
      open
      onClose={() => unsaved.leave(onClose)}
      title={held.set ? 'Change the backup passphrase' : 'Set the backup passphrase'}
      maxWidth="max-w-md"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-keys-passphrase" waiting={busy} disabled={busy || Boolean(problem)}>
            {held.set ? 'Change the passphrase' : 'Set the passphrase'}
          </Button>
        </>
      }
    >
      <form id="form-keys-passphrase" onSubmit={save} className="space-y-3 text-sm text-fg-muted">
        <p>
          Every backup taken from now on is encrypted under it. The backups taken before keep the passphrase they were
          made with: the server remembers the earlier ones to test them, and you need each to restore its backups on
          another host. It is not stored anywhere you can read it back.
        </p>
        <label className="flex flex-col gap-1">
          Passphrase
          <input
            type="password"
            value={first}
            onChange={(event) => setFirst(event.target.value)}
            autoComplete="new-password"
            autoFocus
            className={INPUT}
          />
        </label>
        <label className="flex flex-col gap-1">
          The same, again
          <input
            type="password"
            value={second}
            onChange={(event) => setSecond(event.target.value)}
            autoComplete="new-password"
            className={INPUT}
          />
        </label>
        {(first || second) && problem && <p className="text-xs">{problem}</p>}
        {error && <ErrorNote>{error}</ErrorNote>}
      </form>
    </Modal>
  )
}

function KeyRow({ entry, onRotate }) {
  const source = sourceText(entry)
  const rotation = rotationStatus(entry.rotation)
  const percent = rotationPercent(entry.rotation)
  const running = entry.rotation?.state === 'running'
  const signed = entry.signed ? auditSignedLines(entry.signed) : null
  return (
    <li aria-label={entry.label} className="space-y-1.5 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
        <p className="text-sm font-medium text-fg">{entry.label}</p>
        <code className="font-mono text-xs text-fg-muted">{entry.name}</code>
        <Badge color={source.color} title={source.detail}>
          from {source.text}
        </Badge>
        {rotation.text && <Badge color={rotation.color}>{rotation.text}</Badge>}
        {entry.request && (entry.name === 'AUDIT_KEY' || !entry.rotation?.previousKept) && (
          <Badge color="cyan" title={`By ${entry.request.by}, ${when(entry.request.at)}`}>
            change asked for
          </Badge>
        )}
        {entry.rotates && (
          <span className="ml-auto">
            <Button variant="secondary" size="sm" onClick={() => onRotate(entry)} disabled={running}>
              {entry.request ? 'How to change it…' : 'Rotate…'}
            </Button>
          </span>
        )}
      </div>
      <p className="max-w-prose text-xs text-fg-muted">{entry.protects}</p>
      <p className="text-xs text-fg-muted">
        Held by: <span className="font-mono">{entry.holders.join(', ')}</span>
        {entry.fingerprint && (
          <>
            {' · '}fingerprint <span className="font-mono text-fg">{entry.fingerprint}</span>
          </>
        )}
        {entry.rotatedAt
          ? ` · changed ${when(entry.rotatedAt)}`
          : entry.since
            ? ` · in use since ${when(entry.since)}`
            : ''}
      </p>
      {rotation.detail && (
        <p role="status" className="text-xs text-fg">
          {rotation.detail}
        </p>
      )}
      {running && percent != null && (
        <TransferBar label={`Changing the ${entry.label.toLowerCase()}`} percent={percent} />
      )}
      {signed && signed.lines.length > 0 && (
        <div role="group" aria-label="What each key signed" className="text-xs text-fg-muted">
          {signed.lines.map((line) => (
            <p key={line} className="font-mono">
              {line}
            </p>
          ))}
        </div>
      )}
      {signed?.problem && <ErrorNote>{signed.problem}</ErrorNote>}
      {entry.rotation?.previousKept > 0 && entry.name === 'AUDIT_KEY' && (
        <p className="text-xs text-fg-muted">
          {entry.rotation.previousKept} earlier key{entry.rotation.previousKept === 1 ? '' : 's'} kept
          (AUDIT_KEY_PREVIOUS), for the entries {entry.rotation.previousKept === 1 ? 'it' : 'they'} signed.
        </p>
      )}
      {!entry.rotates && entry.how && <p className="max-w-prose text-xs text-fg-muted">To change it: {entry.how}</p>}
    </li>
  )
}

export default function KeysSection() {
  const { currentUser } = useAuth()
  const [found, setFound] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(true)
  const [dialog, setDialog] = useState(null) // { rotate: entry } | 'passphrase'

  const load = useCallback(async (background = false) => {
    if (!background) setLoading(true)
    try {
      setFound(await api.get('/system/keys', background ? { background: true } : undefined))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    } finally {
      if (!background) setLoading(false)
    }
  }, [])

  useEffect(() => {
    load()
  }, [load])

  const keys = found?.keys ?? []
  const changing = rotating(keys)
  // While a key is being changed the page is read again, so its row follows the change to its end.
  useEffect(() => {
    if (!changing) return undefined
    const timer = setInterval(() => load(true), 3000)
    return () => clearInterval(timer)
  }, [changing, load])

  const pageMenu = usePageMenu(() => [
    {
      label: 'Refresh',
      icon: RefreshCw,
      disabled: loading,
      title: loading ? 'The keys are being read' : undefined,
      onSelect: () => load(),
    },
  ])

  const store = found ? encryptionStatus(found.store, formatBytes, when) : null
  const phrase = found?.backupPassphrase
  const inEnvironment = found?.inEnvironment ?? []

  return (
    <section className="space-y-6" onContextMenu={pageMenu}>
      <div>
        <div className="flex items-center gap-2">
          <FileKey2 className="h-5 w-5 text-accent" aria-hidden="true" />
          <h2 className="text-base font-semibold text-fg">Keys</h2>
        </div>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          The secrets of the server: where each comes from, what it protects, which containers hold it. A value is never
          shown here, nor a part of one: two people check they speak of the same key by its fingerprint.
        </p>
      </div>

      {error && (
        <p role="alert" className="max-w-2xl border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      {!found && !error && <Wait>Reading the keys…</Wait>}

      {found && (
        <div className="max-w-3xl space-y-6">
          {inEnvironment.length > 0 && (
            <div role="note" className="space-y-2 border-l-2 border-med-line bg-med-soft/40 px-3 py-2 text-sm text-fg">
              <p className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-med" aria-hidden="true" />
                <span>
                  The keys of this server are in the environment of its containers (the <code>.env</code> file): whoever
                  can inspect a container reads them, and every process the server starts inherits them. Nik works as
                  before. To put each key in a file that only the containers which use it are given, on the server, in
                  the folder of Nik:
                </span>
              </p>
              <Command>{found.moveCommand}</Command>
              <p className="text-xs text-fg-muted">
                It keeps the <code>.env</code> as it was beside the new one, starts the stack on the files, and puts
                everything back if the server does not answer. The containers restart once.
              </p>
            </div>
          )}

          <div className="space-y-2">
            <div className="flex items-center justify-between gap-3">
              <h3 className={HEADING}>The keys that encrypt and sign</h3>
              <Button variant="secondary" size="sm" icon={RefreshCw} disabled={loading} onClick={() => load()}>
                Refresh
              </Button>
            </div>
            <ul aria-label="Keys that encrypt and sign" className="divide-y divide-line border border-line bg-panel">
              {keys
                .filter((entry) => entry.rotates)
                .map((entry) => (
                  <KeyRow key={entry.name} entry={entry} onRotate={(rotate) => setDialog({ rotate })} />
                ))}
              <li aria-label="Backup passphrase" className="space-y-1.5 px-3 py-2.5">
                <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                  <p className="text-sm font-medium text-fg">Backup passphrase</p>
                  <Badge color={phrase.set ? 'emerald' : 'amber'}>{phrase.set ? 'set' : 'not set'}</Badge>
                  <span className="ml-auto">
                    <Button variant="secondary" size="sm" onClick={() => setDialog('passphrase')}>
                      {phrase.set ? 'Change…' : 'Set…'}
                    </Button>
                  </span>
                </div>
                <p className="max-w-prose text-xs text-fg-muted">
                  Every backup, and the store of files inside it. It is typed by an administrator and kept in the
                  database under the secret key; the server cannot show it again.
                </p>
                <p className="text-xs text-fg-muted">
                  {phrase.setAt ? `Set ${when(phrase.setAt)}` : 'Without it no backup is taken'}
                  {phrase.earlierKept
                    ? ` · ${phrase.earlierKept} earlier passphrase${phrase.earlierKept === 1 ? '' : 's'} remembered, for the backups made with ${phrase.earlierKept === 1 ? 'it' : 'them'}`
                    : ''}
                </p>
              </li>
            </ul>
          </div>

          <div className="space-y-2">
            <h3 className={HEADING}>The store of files</h3>
            <div className="space-y-1 border border-line bg-panel px-3 py-2.5">
              <p className="flex flex-wrap items-center gap-2 text-sm text-fg">
                <Badge color={store.color}>{store.title}</Badge>
                {found.store.keyFingerprint && (
                  <span className="text-xs text-fg-muted">
                    under the store key <span className="font-mono text-fg">{found.store.keyFingerprint}</span>
                  </span>
                )}
              </p>
              {store.lines.map((line) => (
                <p key={line} className="max-w-prose text-xs text-fg-muted">
                  {line}
                </p>
              ))}
              <p className="text-xs text-fg-muted">
                Storage shows the encryption of the store as it goes, and its pause.
              </p>
            </div>
          </div>

          <div className="space-y-2">
            <h3 className={HEADING}>Between the containers</h3>
            <ul aria-label="Passwords and tokens" className="divide-y divide-line border border-line bg-panel">
              {keys
                .filter((entry) => !entry.rotates)
                .map((entry) => (
                  <KeyRow key={entry.name} entry={entry} onRotate={() => {}} />
                ))}
            </ul>
          </div>
        </div>
      )}

      {dialog?.rotate && (
        <RotateDialog
          entry={dialog.rotate}
          hasFactor={Boolean(currentUser?.secondFactor)}
          onClose={() => setDialog(null)}
          onAsked={() => load(true)}
        />
      )}
      {dialog === 'passphrase' && (
        <PassphraseDialog
          held={phrase}
          onClose={() => setDialog(null)}
          onSaved={() => {
            setDialog(null)
            load()
          }}
        />
      )}
    </section>
  )
}
