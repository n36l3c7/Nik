import { useCallback, useEffect, useRef, useState } from 'react'
import {
  AlertTriangle,
  DatabaseBackup,
  Download,
  KeyRound,
  PlugZap,
  RefreshCw,
  ShieldCheck,
  Terminal,
  Trash2,
} from 'lucide-react'
import { api, apiUrl } from '../../../services/api.js'
import {
  EVERY,
  INCLUDE_KEY_WARNING,
  PASSPHRASE_WARNING,
  WEEKDAYS,
  backupStatus,
  backupTitle,
  isBusy,
  restoreSteps,
  scheduleText,
  settingsBody,
  settingsForm,
  settingsProblem,
  sizeText,
  spaceText,
  typedName,
  whereText,
} from '../../../domain/backups.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { formatDateTime, formatRelative } from '../../../lib/time.js'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { usePageMenu } from '../../menu/usePageMenu.js'
import { Badge, Button, EmptyState, Modal, Select, Wait } from '../../ui/index.js'
import ContentExport from './ContentExport.jsx'
import RecoverySection from './RecoverySection.jsx'
import Switch from './Switch.jsx'

/*
 * System → Backup (admins).
 *
 * The server takes its backups by itself: the database and the store of
 * files in one encrypted file, on a schedule, each one tested by restoring it
 * into a scratch database, with a copy sent to another machine. This page is
 * where that is set and watched: what the last good backup is, what is wrong,
 * the schedule and the retention, the passphrase, the destination of the
 * copy, and the list of the backups with what can be done to each.
 *
 * Putting a backup back is not here: it is done on the server, from the
 * command line, with the stack stopped. Each backup shows the command.
 *
 * At the foot, the export of content as one JSON file (what "Full backup"
 * was before 6.7) is kept as it worked, and under it the recovery to a
 * moment (RecoverySection.jsx): the archive of the database log, the base
 * backups and the second host.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const LABEL = 'flex flex-col gap-1 text-sm text-fg-muted'
const when = (iso) => (iso ? formatDateTime(Date.parse(iso)) : '—')

function Alert({ children }) {
  return (
    <p role="alert" className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </p>
  )
}

/** Setting or changing the passphrase: typed twice, never shown again. */
function PassphraseDialog({ settings, onClose, onSaved }) {
  const [first, setFirst] = useState('')
  const [second, setSecond] = useState('')
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const min = settings.passphraseMin ?? 12
  const problem =
    first.length < min
      ? `At least ${min} characters.`
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
      onSaved(await api.put('/backups/passphrase', { passphrase: first }))
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
      title={settings.passphraseSet ? 'Change the backup passphrase' : 'Set the backup passphrase'}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-backup-passphrase" waiting={busy} disabled={busy || Boolean(problem)}>
            {settings.passphraseSet ? 'Change the passphrase' : 'Set the passphrase'}
          </Button>
        </>
      }
    >
      <form id="form-backup-passphrase" onSubmit={save} className="flex flex-col gap-3 text-sm">
        <p className="border border-med-line bg-med-soft px-3 py-2 text-med-fg">{PASSPHRASE_WARNING}</p>
        {settings.passphraseSet && (
          <p className="text-fg-muted">
            The backups already made keep the passphrase they were made with: keep that one too, for as long as they
            exist.
          </p>
        )}
        <label className={LABEL} htmlFor="backup-passphrase">
          Passphrase
          <input
            id="backup-passphrase"
            type="password"
            value={first}
            autoComplete="new-password"
            spellCheck={false}
            onChange={(event) => setFirst(event.target.value)}
            className={INPUT}
          />
        </label>
        <label className={LABEL} htmlFor="backup-passphrase-again">
          The same passphrase again
          <input
            id="backup-passphrase-again"
            type="password"
            value={second}
            autoComplete="new-password"
            spellCheck={false}
            onChange={(event) => setSecond(event.target.value)}
            className={INPUT}
          />
        </label>
        {error && <Alert>{error}</Alert>}
        {problem && !error && (first || second) && <p className="text-xs text-med-fg">{problem}</p>}
      </form>
    </Modal>
  )
}

/** The schedule, the retention, the key and the destination: one form, saved together. */
function SettingsForm({ settings, sends, space, onSaved }) {
  const [form, setForm] = useState(() => settingsForm(settings))
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const [tested, setTested] = useState(null)
  const set = (patch) => setForm((current) => ({ ...current, ...patch }))
  const loaded = JSON.stringify(settingsForm(settings))
  const dirty = JSON.stringify(form) !== loaded
  const problem = settingsProblem(form, settings)
  const room = spaceText(space, form)

  // What the server keeps changed under the form (saved elsewhere): an untouched form follows it.
  const before = useRef(loaded)
  useEffect(() => {
    if (before.current !== loaded) {
      const was = before.current
      before.current = loaded
      setForm((current) => (JSON.stringify(current) === was ? settingsForm(settings) : current))
    }
  }, [loaded, settings])

  const save = async (event) => {
    event?.preventDefault()
    if (problem) return false
    setBusy(true)
    setError(null)
    try {
      const saved = await api.put('/backups/settings', settingsBody(form))
      before.current = JSON.stringify(settingsForm(saved.settings))
      setForm(settingsForm(saved.settings))
      setTested(null)
      onSaved(saved)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  const unsaved = useUnsavedChanges(dirty, {
    what: 'The settings of the backups',
    save: problem ? undefined : () => save(),
  })

  const test = async () => {
    setTesting(true)
    setTested(null)
    try {
      setTested(await api.post('/backups/destination/test'))
    } catch (failure) {
      setTested({ ok: false, message: failure.message })
    } finally {
      setTesting(false)
    }
  }

  const destination = settings.destination ?? {}
  const secretKept = destination.kind === 'sftp' && destination.auth === form.auth && destination.secretSet
  const cannotTest = dirty
    ? 'Save the settings first: the test tries what is saved.'
    : !form.copy
      ? 'No copy off the server is set.'
      : sends === 'off'
        ? 'Copies are sent by the automation worker, which is off on this server.'
        : null

  return (
    <form onSubmit={save} aria-label="Backup settings" className="flex flex-col gap-5">
      <fieldset className="flex flex-col gap-3 border border-line bg-panel p-4">
        <legend className="px-1 font-mono text-xs text-fg-muted">Schedule</legend>
        <div className="flex items-center gap-3 text-sm text-fg">
          <Switch checked={form.enabled} onChange={(enabled) => set({ enabled })} label="Take backups on a schedule" />
          <span>Take backups on a schedule</span>
        </div>
        <div className="flex flex-wrap items-end gap-3">
          <Select
            label="How often"
            value={form.every}
            onChange={(every) => set({ every })}
            options={EVERY}
            disabled={!form.enabled}
          />
          {form.every === 'hours' && (
            <label className={LABEL} htmlFor="backup-hours">
              Hours between two
              <input
                id="backup-hours"
                type="text"
                inputMode="numeric"
                value={form.hours}
                disabled={!form.enabled}
                onChange={(event) => set({ hours: event.target.value })}
                className={`${INPUT} w-24`}
              />
            </label>
          )}
          {form.every === 'week' && (
            <Select
              label="Day"
              value={form.weekday}
              onChange={(weekday) => set({ weekday })}
              options={WEEKDAYS.map((label, index) => ({ value: String(index), label }))}
              disabled={!form.enabled}
            />
          )}
          <label className={LABEL} htmlFor="backup-at">
            {form.every === 'hours' ? 'Counted from' : 'At'}
            <input
              id="backup-at"
              type="text"
              value={form.at}
              placeholder="02:30"
              disabled={!form.enabled}
              onChange={(event) => set({ at: event.target.value })}
              className={`${INPUT} w-24`}
            />
          </label>
          <label className={LABEL} htmlFor="backup-timezone">
            Time zone
            <input
              id="backup-timezone"
              type="text"
              value={form.timezone}
              placeholder="UTC, Europe/Rome"
              spellCheck={false}
              disabled={!form.enabled}
              onChange={(event) => set({ timezone: event.target.value })}
              className={`${INPUT} w-48`}
            />
          </label>
        </div>
        <label className={LABEL} htmlFor="backup-warn">
          Tell the administrators when the last good backup is older than (hours)
          <input
            id="backup-warn"
            type="text"
            inputMode="numeric"
            value={form.warnAfterHours}
            onChange={(event) => set({ warnAfterHours: event.target.value })}
            className={`${INPUT} w-24`}
          />
        </label>
      </fieldset>

      <fieldset className="flex flex-col gap-3 border border-line bg-panel p-4">
        <legend className="px-1 font-mono text-xs text-fg-muted">What is kept</legend>
        <div className="flex flex-wrap items-end gap-3">
          <label className={LABEL} htmlFor="backup-last">
            The latest good backups
            <input
              id="backup-last"
              type="text"
              inputMode="numeric"
              value={form.last}
              onChange={(event) => set({ last: event.target.value })}
              className={`${INPUT} w-24`}
            />
          </label>
          <label className={LABEL} htmlFor="backup-weeks">
            And one a week, for (weeks)
            <input
              id="backup-weeks"
              type="text"
              inputMode="numeric"
              value={form.weeks}
              onChange={(event) => set({ weeks: event.target.value })}
              className={`${INPUT} w-24`}
            />
          </label>
          <label className={LABEL} htmlFor="backup-upgrades">
            Snapshots from before upgrades
            <input
              id="backup-upgrades"
              type="text"
              inputMode="numeric"
              value={form.upgrades}
              onChange={(event) => set({ upgrades: event.target.value })}
              className={`${INPUT} w-24`}
            />
          </label>
        </div>
        <p aria-label="Room the backups take" className="max-w-prose text-sm text-fg">
          {room.now} <span className="text-fg-muted">{room.then}</span>
        </p>
        <p className="max-w-prose text-xs text-fg-muted">
          A backup holds the whole store of files each time, whatever changed since the one before. A backup counts once
          it has passed its restore test. The last good one is never removed, however many came after it and failed. The
          copy off the server follows: what is removed here is removed there.
        </p>
        <label className="flex items-start gap-2 text-sm text-fg">
          <input
            type="checkbox"
            checked={form.includeKey}
            onChange={(event) => set({ includeKey: event.target.checked })}
            className="mt-1 accent-accent"
          />
          <span>
            Include SECRET_KEY inside the encrypted backup
            <span className="block max-w-prose text-xs text-fg-muted">{INCLUDE_KEY_WARNING}</span>
          </span>
        </label>
      </fieldset>

      <fieldset className="flex flex-col gap-3 border border-line bg-panel p-4">
        <legend className="px-1 font-mono text-xs text-fg-muted">The copy off the server</legend>
        <div className="flex items-center gap-3 text-sm text-fg">
          <Switch checked={form.copy} onChange={(copy) => set({ copy })} label="Send a copy to another server" />
          <span>Send a copy of each backup to another server, over SFTP</span>
        </div>
        {form.copy && (
          <>
            <div className="flex flex-wrap items-end gap-3">
              <label className={LABEL} htmlFor="backup-host">
                Host
                <input
                  id="backup-host"
                  type="text"
                  value={form.host}
                  spellCheck={false}
                  placeholder="nik2.example.org"
                  onChange={(event) => set({ host: event.target.value })}
                  className={`${INPUT} w-64`}
                />
              </label>
              <label className={LABEL} htmlFor="backup-port">
                Port
                <input
                  id="backup-port"
                  type="text"
                  inputMode="numeric"
                  value={form.port}
                  onChange={(event) => set({ port: event.target.value })}
                  className={`${INPUT} w-20`}
                />
              </label>
              <label className={LABEL} htmlFor="backup-user">
                Account
                <input
                  id="backup-user"
                  type="text"
                  value={form.user}
                  spellCheck={false}
                  placeholder="nikbackup"
                  onChange={(event) => set({ user: event.target.value })}
                  className={`${INPUT} w-40`}
                />
              </label>
              <label className={LABEL} htmlFor="backup-path">
                Directory
                <input
                  id="backup-path"
                  type="text"
                  value={form.path}
                  spellCheck={false}
                  placeholder="/srv/nik-backups"
                  onChange={(event) => set({ path: event.target.value })}
                  className={`${INPUT} w-64`}
                />
              </label>
            </div>
            <Select
              label="It signs in with"
              value={form.auth}
              onChange={(auth) => set({ auth, secret: '' })}
              options={[
                { value: 'key', label: 'a private key' },
                { value: 'password', label: 'a password' },
              ]}
              className="max-w-xs"
            />
            <label className={LABEL} htmlFor="backup-secret">
              {form.auth === 'key' ? 'Private key' : 'Password'}
              {form.auth === 'key' ? (
                <textarea
                  id="backup-secret"
                  rows={3}
                  value={form.secret}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder={
                    secretKept
                      ? 'stored: paste another to replace it'
                      : '-----BEGIN OPENSSH PRIVATE KEY-----  (or {{ credentials.name }})'
                  }
                  onChange={(event) => set({ secret: event.target.value })}
                  className={INPUT}
                />
              ) : (
                <input
                  id="backup-secret"
                  type="password"
                  value={form.secret}
                  autoComplete="new-password"
                  placeholder={secretKept ? 'stored: type to replace it' : ''}
                  onChange={(event) => set({ secret: event.target.value })}
                  className={INPUT}
                />
              )}
              <span className="text-xs">
                Stored encrypted and never shown again.
                {destination.secretCredential ? ` It is the stored credential ${destination.secretCredential}.` : ''} A
                key made for this alone, with no passphrase of its own; the name of a stored credential can be written
                in its place.
              </span>
            </label>
            <label className={LABEL} htmlFor="backup-hostkey">
              Host key of that server
              <input
                id="backup-hostkey"
                type="text"
                value={form.hostKey}
                spellCheck={false}
                placeholder="ssh-ed25519 AAAA…  or  SHA256:…"
                onChange={(event) => set({ hostKey: event.target.value })}
                className={INPUT}
              />
              <span className="text-xs">
                Nothing is sent to a server that presents another key, or while none is written here. Save, press Test:
                it shows the key the server presents, to compare with the one read on that server itself.
              </span>
            </label>
            <div className="flex flex-wrap items-center gap-3">
              <Button
                variant="secondary"
                size="sm"
                icon={PlugZap}
                waiting={testing}
                disabled={testing || Boolean(cannotTest)}
                title={cannotTest ?? undefined}
                onClick={test}
              >
                Test the destination
              </Button>
              {testing && <Wait inline>Signing in to the destination…</Wait>}
            </div>
            {tested && (
              <div
                role="status"
                className={`border px-3 py-2 text-sm ${
                  tested.ok
                    ? 'border-accent-strong bg-accent-soft text-accent-fg'
                    : 'border-high-line bg-high-soft text-high'
                }`}
              >
                <p>{tested.message}</p>
                {tested.hostKey && (
                  <p className="mt-1 break-all font-mono text-xs">
                    It presents: {tested.hostKey} ({tested.fingerprint})
                  </p>
                )}
              </div>
            )}
          </>
        )}
      </fieldset>

      {error && <Alert>{error}</Alert>}
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" waiting={busy} disabled={busy || !dirty || Boolean(problem)} title={problem ?? undefined}>
          Save the settings
        </Button>
        {dirty && (
          <Button
            variant="secondary"
            disabled={busy}
            onClick={() => unsaved.leave(() => setForm(settingsForm(settings)))}
          >
            Discard
          </Button>
        )}
        {dirty && problem && <p className="text-xs text-med-fg">{problem}</p>}
      </div>
    </form>
  )
}

/** The command that puts a backup back, and what it does. */
function RestoreDialog({ backup, onClose }) {
  const steps = restoreSteps(backup)
  return (
    <Modal
      open
      onClose={onClose}
      title={`How to restore ${backup.id}`}
      footer={<Button onClick={onClose}>Close</Button>}
    >
      <div className="flex flex-col gap-3 text-sm text-fg-muted">
        <p>
          A backup is put back on the server, from the command line, never from this page: a running server is not the
          place to replace its own database.
        </p>
        <pre
          aria-label="Restore command"
          className="overflow-x-auto border border-line bg-canvas px-3 py-2 font-mono text-xs text-fg"
        >
          {steps.command}
        </pre>
        <p>{steps.about}</p>
        <p>
          {backup.summary?.keyFrom === 'secret-key'
            ? 'This one was taken while no passphrase was set: it is encrypted with the SECRET_KEY of this server, and is read with the .env that holds it.'
            : 'It asks for the passphrase this backup was made with. Without it nobody can read the file.'}{' '}
          The deployment guide has the whole procedure, for this server and for a new one.
        </p>
      </div>
    </Modal>
  )
}

/** Deleting a backup: its name is typed; the last good one is asked about once more. */
function DeleteDialog({ backup, onClose, onDeleted }) {
  const [typed, setTyped] = useState('')
  const [sure, setSure] = useState(false)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const ready = typedName(typed, backup) && (!backup.lastGood || sure)

  const remove = async (event) => {
    event?.preventDefault()
    if (!ready) return
    setBusy(true)
    setError(null)
    try {
      const query = `confirm=${encodeURIComponent(backup.id)}${backup.lastGood ? '&lastGood=true' : ''}`
      await api.del(`/backups/${encodeURIComponent(backup.id)}?${query}`)
      onDeleted(backup)
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={`Delete ${backup.id}`}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button
            type="submit"
            form="form-backup-delete"
            variant="danger"
            icon={Trash2}
            waiting={busy}
            disabled={busy || !ready}
          >
            Delete the backup
          </Button>
        </>
      }
    >
      <form id="form-backup-delete" onSubmit={remove} className="flex flex-col gap-3 text-sm text-fg-muted">
        <p>
          Its file is removed from the server now
          {backup.offsiteState === 'copied' ? ', and its copy off the server within a few seconds' : ''}. It cannot be
          taken back.
        </p>
        {backup.lastGood && (
          <label className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-high">
            <input
              type="checkbox"
              checked={sure}
              onChange={(event) => setSure(event.target.checked)}
              className="mt-1 accent-accent"
            />
            <span>
              This is the last good backup: after it there is none that is known to restore. Delete it all the same.
            </span>
          </label>
        )}
        <label className={LABEL} htmlFor="backup-delete-name">
          Type its name to delete it
          <input
            id="backup-delete-name"
            type="text"
            value={typed}
            spellCheck={false}
            autoComplete="off"
            placeholder={backup.id}
            onChange={(event) => setTyped(event.target.value)}
            className={INPUT}
          />
        </label>
        {error && <Alert>{error}</Alert>}
      </form>
    </Modal>
  )
}

export default function BackupSection() {
  const [found, setFound] = useState(null)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [asking, setAsking] = useState(false)
  const [passphrase, setPassphrase] = useState(false)
  const [restoring, setRestoring] = useState(null)
  const [deleting, setDeleting] = useState(null)
  const menu = useObjectMenu()

  const load = useCallback(async () => {
    try {
      setFound(await api.get('/backups'))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const backups = found?.backups ?? []
  const state = found?.state
  const settings = found?.settings
  const working = Boolean(state?.running) || backups.some(isBusy)
  // While the server works on a backup the page is read again, so the row follows it to its end.
  useEffect(() => {
    if (!working) return undefined
    const timer = setInterval(load, 2000)
    return () => clearInterval(timer)
  }, [working, load])

  const act = async (request, said) => {
    setError(null)
    setNotice(null)
    try {
      await request()
      setNotice(said)
      await load()
    } catch (failure) {
      setError(failure.message)
    }
  }
  const backUpNow = async () => {
    setAsking(true)
    await act(() => api.post('/backups/run'), 'A backup was asked for: it starts within a few seconds.')
    setAsking(false)
  }
  const verify = (backup) =>
    act(
      () => api.post(`/backups/${encodeURIComponent(backup.id)}/verify`),
      `The restore test of ${backup.id} was asked for.`,
    )

  const noPassphrase = settings && !settings.passphraseReadable
  const cannotBackUp = noPassphrase
    ? 'Set the backup passphrase first: no backup is written in clear.'
    : working
      ? 'A backup is being taken or tested.'
      : null

  const pageMenu = usePageMenu(() => [
    {
      label: 'Back up now',
      icon: DatabaseBackup,
      disabled: Boolean(cannotBackUp) || asking,
      title: cannotBackUp ?? undefined,
      onSelect: backUpNow,
    },
    { label: 'Refresh', icon: RefreshCw, onSelect: load },
  ])

  const actionsOf = (backup) => {
    const here = backup.state === 'done' && backup.local
    return [
      {
        label: 'Verify now',
        icon: ShieldCheck,
        disabled: !here || isBusy(backup),
        title: here ? undefined : 'Only a backup whose file is on the server can be tested',
        onSelect: () => verify(backup),
      },
      {
        label: 'How to restore…',
        icon: Terminal,
        disabled: backup.state !== 'done',
        onSelect: () => setRestoring(backup),
      },
    ]
  }

  return (
    <section className="flex max-w-5xl flex-col gap-6" onContextMenu={pageMenu}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <DatabaseBackup className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-fg">Backup</h2>
          </div>
          <p className="mt-1 max-w-prose text-sm text-fg-muted">
            Nik takes its own backups: the database and every file of the store in one encrypted file, on a schedule.
            Each one is tested at once by restoring it into a scratch database, and every administrator is told when a
            backup fails, fails that test or is missed. A backup is put back on the server, from the command line.
          </p>
        </div>
        <Button
          icon={DatabaseBackup}
          waiting={asking || working}
          disabled={asking || Boolean(cannotBackUp)}
          title={cannotBackUp ?? undefined}
          onClick={backUpNow}
        >
          Back up now
        </Button>
      </div>

      {error && <Alert>{error}</Alert>}
      <p role="status" className={notice ? 'text-sm text-accent-fg' : 'sr-only'}>
        {notice}
      </p>
      {!found && !error && <Wait>Loading the backups…</Wait>}

      {found && (
        <>
          {state.problems.map((problem) => (
            <Alert key={problem.id}>{problem.text}</Alert>
          ))}
          {noPassphrase && (
            <div className="flex flex-wrap items-center justify-between gap-3 border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg">
              <span>
                {settings.passphraseSet
                  ? 'The backup passphrase cannot be read any more (SECRET_KEY changed): type it again. Until then no backup is taken.'
                  : 'No backup passphrase is set, so no backup is taken. A snapshot taken before an upgrade is encrypted with SECRET_KEY meanwhile.'}
              </span>
            </div>
          )}

          <dl
            aria-label="State of the backups"
            className="grid gap-x-6 gap-y-2 border border-line bg-panel p-4 text-sm sm:grid-cols-2"
          >
            <div>
              <dt className="font-mono text-xs text-fg-muted">Last good backup</dt>
              <dd className="text-fg">
                {state.lastGood
                  ? `${when(state.lastGood.createdAt)} · verified ${formatRelative(state.lastGood.verifiedAt)}`
                  : 'None yet'}
              </dd>
            </div>
            <div>
              <dt className="font-mono text-xs text-fg-muted">Next run</dt>
              <dd className="text-fg">
                {state.nextRun
                  ? when(state.nextRun)
                  : noPassphrase
                    ? 'Not before a passphrase is set'
                    : 'Not scheduled'}
                <span className="block text-xs text-fg-muted">{scheduleText(settings.schedule)}</span>
              </dd>
            </div>
            <div>
              <dt className="font-mono text-xs text-fg-muted">On this server</dt>
              <dd className="break-all font-mono text-xs text-fg">
                {state.directory.path}
                {state.directory.disk && (
                  <span className="block text-fg-muted">
                    {sizeText(state.directory.disk.free)} free of {sizeText(state.directory.disk.total)}. The place is
                    chosen in the deployment (NIK_BACKUP_DIR).
                  </span>
                )}
              </dd>
            </div>
            <div>
              <dt className="font-mono text-xs text-fg-muted">Copy off the server</dt>
              <dd className="break-all text-fg">
                {state.copies || (
                  <span className="text-med-fg">
                    None: a backup kept only on the server it protects is lost with it.
                  </span>
                )}
              </dd>
            </div>
          </dl>

          <div className="flex flex-wrap items-center justify-between gap-3 border border-line bg-panel px-4 py-3 text-sm">
            <p className="max-w-prose text-fg-muted">
              <span className="text-fg">
                {settings.passphraseSet ? 'A backup passphrase is set.' : 'No backup passphrase is set.'}
              </span>{' '}
              Every backup is encrypted under it, and it is asked for again by a restore. It is not SECRET_KEY, and it
              is never shown.
            </p>
            <Button variant="secondary" size="sm" icon={KeyRound} onClick={() => setPassphrase(true)}>
              {settings.passphraseSet ? 'Change the passphrase…' : 'Set the passphrase…'}
            </Button>
          </div>

          <SettingsForm settings={settings} sends={state.sends} space={state.space} onSaved={setFound} />

          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2">
              <h3 className="text-sm font-semibold text-fg">Backups</h3>
              <Badge color="slate">{backups.length}</Badge>
              {working && <Wait inline>The server is working on a backup…</Wait>}
            </div>
            {backups.length === 0 ? (
              <EmptyState
                skull
                title="No backup yet"
                message={
                  noPassphrase
                    ? 'Set the backup passphrase: the server then takes its backups by the schedule, and Back up now takes one at once.'
                    : 'The server takes one at the next run of the schedule. Back up now takes one at once.'
                }
              />
            ) : (
              <div className="overflow-x-auto border border-line">
                <table className="w-full border-collapse text-left text-sm">
                  <caption className="sr-only">Backups</caption>
                  <thead className="bg-panel font-mono text-xs text-fg-muted">
                    <tr>
                      {['Backup', 'Taken', 'Size', 'Where', 'State', 'Nik', ''].map((heading, index) => (
                        <th key={heading || index} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                          {heading || <span className="sr-only">Actions</span>}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {backups.map((backup) => {
                      const status = backupStatus(backup)
                      const actions = actionsOf(backup)
                      return (
                        <tr
                          key={backup.id}
                          onContextMenu={(event) =>
                            menu(event, {
                              title: backup.id,
                              actions,
                              copy: [
                                { label: 'Copy the name', text: backup.id },
                                { label: 'Copy the restore command', text: restoreSteps(backup).command },
                              ],
                              danger: [{ label: 'Delete…', icon: Trash2, onSelect: () => setDeleting(backup) }],
                            })
                          }
                        >
                          <th scope="row" className="border-b border-line-soft px-3 py-2 align-top font-normal">
                            <span className="font-mono text-fg">{backup.id}</span>
                            <span className="block text-xs text-fg-muted">
                              {backupTitle(backup)}
                              {backup.lastGood ? ' · the last good one' : ''}
                            </span>
                          </th>
                          <td className="border-b border-line-soft px-3 py-2 align-top text-xs text-fg-muted">
                            {when(backup.createdAt)}
                            {backup.requestedBy && backup.requestedBy !== 'system' ? (
                              <span className="block">by {backup.requestedBy}</span>
                            ) : null}
                          </td>
                          <td className="border-b border-line-soft px-3 py-2 align-top font-mono text-xs text-fg-muted">
                            {sizeText(backup.size)}
                          </td>
                          <td className="border-b border-line-soft px-3 py-2 align-top text-xs text-fg-muted">
                            {whereText(backup)}
                          </td>
                          <td className="border-b border-line-soft px-3 py-2 align-top text-xs">
                            <Badge color={status.color} title={status.detail || undefined}>
                              {status.text}
                            </Badge>
                            {backup.verifiedAt && backup.verifyState === 'passed' && (
                              <span className="block text-fg-muted">{formatRelative(backup.verifiedAt)}</span>
                            )}
                            {status.color === 'red' && status.detail && (
                              <span className="block max-w-xs text-high-fg">{status.detail}</span>
                            )}
                          </td>
                          <td className="border-b border-line-soft px-3 py-2 align-top font-mono text-xs text-fg-muted">
                            {backup.nikVersion || '—'}
                          </td>
                          <td className="border-b border-line-soft px-2 py-1.5 align-top">
                            <div className="flex justify-end gap-1">
                              <Button
                                size="xs"
                                variant="ghost"
                                icon={ShieldCheck}
                                aria-label={`Verify ${backup.id}`}
                                title={actions[0].title ?? 'Verify now: restore it into a scratch database and compare'}
                                disabled={actions[0].disabled}
                                onClick={() => verify(backup)}
                              />
                              <Button
                                size="xs"
                                variant="ghost"
                                icon={Terminal}
                                aria-label={`How to restore ${backup.id}`}
                                title="How to restore…"
                                disabled={backup.state !== 'done'}
                                onClick={() => setRestoring(backup)}
                              />
                              {backup.state === 'done' && backup.local && (
                                <a
                                  href={apiUrl(`/backups/${encodeURIComponent(backup.id)}/download`)}
                                  download
                                  aria-label={`Download ${backup.id}`}
                                  title="Download the encrypted file"
                                  className="inline-flex h-6 w-6 items-center justify-center text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                                >
                                  <Download className="h-3.5 w-3.5" aria-hidden="true" />
                                </a>
                              )}
                              <Button
                                size="xs"
                                variant="ghost"
                                icon={Trash2}
                                aria-label={`Delete ${backup.id}`}
                                title="Delete…"
                                disabled={backup.state === 'running' || backup.verifyState === 'running'}
                                onClick={() => setDeleting(backup)}
                              />
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            )}
            <p className="max-w-prose text-xs text-fg-muted">
              A backup holds the database and the store of files. It does not hold the .env file (SECRET_KEY, unless
              included above), the TLS certificate and its key, or the Compose overrides: keep those elsewhere.
            </p>
          </div>

          <ContentExport />
          <RecoverySection />
        </>
      )}

      {passphrase && settings && (
        <PassphraseDialog
          settings={settings}
          onClose={() => setPassphrase(false)}
          onSaved={(saved) => {
            setFound(saved)
            setPassphrase(false)
            setNotice('The backup passphrase is set.')
          }}
        />
      )}
      {restoring && <RestoreDialog backup={restoring} onClose={() => setRestoring(null)} />}
      {deleting && (
        <DeleteDialog
          backup={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={(gone) => {
            setDeleting(null)
            setNotice(`${gone.id} was deleted.`)
            load()
          }}
        />
      )}
    </section>
  )
}
