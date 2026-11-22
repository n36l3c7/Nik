import { useCallback, useEffect, useRef, useState } from 'react'
import { AlertTriangle, Copy, DatabaseBackup, History, ShieldCheck } from 'lucide-react'
import { api } from '../../../services/api.js'
import { EVERY, WEEKDAYS } from '../../../domain/backups.js'
import {
  COMMAND_ABOUT,
  NO_ARCHIVE,
  NO_SECOND_HOST,
  PROMOTION_ABOUT,
  archiveState,
  askedText,
  baseCopyText,
  baseStatus,
  checkedText,
  copiesState,
  diskRows,
  estimateText,
  isWorking,
  linkText,
  moment,
  recoveryBody,
  recoveryForm,
  recoveryProblem,
  roleText,
  serviceText,
  shippedText,
  sizeText,
  storeText,
  testState,
  timeoutText,
  waitingText,
  windowText,
} from '../../../domain/recovery.js'
import { useToast } from '../../../context/ToastContext.jsx'
import { copyText } from '../../../lib/download.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { formatDateTime } from '../../../lib/time.js'
import { Badge, Button, Select, Wait } from '../../ui/index.js'
import Switch from './Switch.jsx'

/*
 * Recovery to a moment, at the foot of Settings → Backup (admins).
 *
 * Besides its backups the server archives the log of its database as it is
 * written, and takes a base backup on a schedule: with the two it can be
 * brought back to any moment since the oldest base backup, not only to the
 * hour of a backup. A second host can receive a copy of all of it, and be
 * kept as a standby. This part of the page is where that is watched and set:
 * whether the archive follows, the moments one can go back to and the command
 * that does it, how far behind the second host is, the base backups, the last
 * time a recovery was proven, the room it all takes.
 *
 * Going back to a moment and promoting a standby are not here: each is a
 * command on the host concerned, run by somebody who can see that host.
 *
 * A server without an archive (a development server) says so and shows
 * nothing else.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const LABEL = 'flex flex-col gap-1 text-sm text-fg-muted'
const TERM = 'font-mono text-xs text-fg-muted'
const CELL = 'border-b border-line-soft px-3 py-2 align-top text-xs text-fg-muted'
const when = (ms) => formatDateTime(ms)
// How often the page reads the server again by itself: closely while it works on something.
const WORKING_MS = 3000
const WATCHING_MS = 30000

function Alert({ children }) {
  return (
    <p role="alert" className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </p>
  )
}

/** When the base backups are taken, how far back one can go, what is warned about: one form. */
function SettingsForm({ settings, onSaved }) {
  const [form, setForm] = useState(() => recoveryForm(settings))
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const set = (patch) => setForm((current) => ({ ...current, ...patch }))
  const loaded = JSON.stringify(recoveryForm(settings))
  const body = recoveryBody(form, settings)
  const dirty = Object.keys(body).length > 0
  const problem = recoveryProblem(form)

  // What the server keeps changed under the form (saved elsewhere): an untouched form follows it.
  const before = useRef(loaded)
  useEffect(() => {
    if (before.current !== loaded) {
      const was = before.current
      before.current = loaded
      setForm((current) => (JSON.stringify(current) === was ? recoveryForm(settings) : current))
    }
  }, [loaded, settings])

  const save = async (event) => {
    event?.preventDefault()
    if (problem || !dirty) return false
    setBusy(true)
    setError(null)
    try {
      const saved = await api.put('/recovery/settings', body)
      before.current = JSON.stringify(recoveryForm(saved.settings))
      setForm(recoveryForm(saved.settings))
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
    what: 'The settings of the recovery',
    save: problem ? undefined : () => save(),
  })

  return (
    <form onSubmit={save} aria-label="Recovery settings" className="flex flex-col gap-5">
      <fieldset className="flex flex-col gap-3 border border-line bg-panel p-4">
        <legend className="px-1 font-mono text-xs text-fg-muted">Base backups</legend>
        <div className="flex items-center gap-3 text-sm text-fg">
          <Switch
            checked={form.enabled}
            onChange={(enabled) => set({ enabled })}
            label="Take base backups on a schedule"
          />
          <span>Take base backups on a schedule</span>
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
            <label className={LABEL} htmlFor="recovery-hours">
              Hours between two
              <input
                id="recovery-hours"
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
          <label className={LABEL} htmlFor="recovery-at">
            {form.every === 'hours' ? 'Counted from' : 'At'}
            <input
              id="recovery-at"
              type="text"
              value={form.at}
              placeholder="03:30"
              disabled={!form.enabled}
              onChange={(event) => set({ at: event.target.value })}
              className={`${INPUT} w-24`}
            />
          </label>
          <label className={LABEL} htmlFor="recovery-timezone">
            Time zone
            <input
              id="recovery-timezone"
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
        <label className={LABEL} htmlFor="recovery-keep">
          Days one can go back
          <input
            id="recovery-keep"
            type="text"
            inputMode="numeric"
            value={form.keepDays}
            onChange={(event) => set({ keepDays: event.target.value })}
            className={`${INPUT} w-24`}
          />
          <span className="max-w-prose text-xs">
            The base backups and the log from before those days are removed, and with them the deleted files that were
            kept for a recovery to those days.
          </span>
        </label>
      </fieldset>

      <fieldset className="flex flex-col gap-3 border border-line bg-panel p-4">
        <legend className="px-1 font-mono text-xs text-fg-muted">What is watched</legend>
        <label className={LABEL} htmlFor="recovery-lag">
          Tell the administrators when the second host is more than this many minutes behind
          <input
            id="recovery-lag"
            type="text"
            inputMode="numeric"
            value={form.lagMinutes}
            onChange={(event) => set({ lagMinutes: event.target.value })}
            className={`${INPUT} w-24`}
          />
        </label>
        <label className={LABEL} htmlFor="recovery-test">
          Prove the archive every (hours)
          <input
            id="recovery-test"
            type="text"
            inputMode="numeric"
            value={form.testEveryHours}
            onChange={(event) => set({ testEveryHours: event.target.value })}
            className={`${INPUT} w-24`}
          />
        </label>
        <label className={LABEL} htmlFor="recovery-name">
          Name of this server for the other host
          <input
            id="recovery-name"
            type="text"
            value={form.name}
            spellCheck={false}
            placeholder="the name of the machine, when left empty"
            onChange={(event) => set({ name: event.target.value })}
            className={`${INPUT} max-w-md`}
          />
        </label>
      </fieldset>

      {error && <Alert>{error}</Alert>}
      <div className="flex flex-wrap items-center gap-3">
        <Button type="submit" waiting={busy} disabled={busy || !dirty || Boolean(problem)} title={problem ?? undefined}>
          Save the recovery settings
        </Button>
        {dirty && (
          <Button
            variant="secondary"
            disabled={busy}
            onClick={() => unsaved.leave(() => setForm(recoveryForm(settings)))}
          >
            Discard
          </Button>
        )}
        {dirty && problem && <p className="text-xs text-med-fg">{problem}</p>}
      </div>
    </form>
  )
}

export default function RecoverySection() {
  const { showToast } = useToast()
  // What the server answered, with the moment it did: the ages on the screen are counted from it.
  const [seen, setSeen] = useState(null)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [asking, setAsking] = useState(null)
  const take = useCallback((found) => setSeen({ found, at: Date.now() }), [])

  const load = useCallback(
    async (background = false) => {
      try {
        take(await api.get('/recovery', background ? { background: true } : undefined))
        setError(null)
      } catch (failure) {
        setError(failure.message)
      }
    },
    [take],
  )
  useEffect(() => {
    load()
  }, [load])

  const found = seen?.found
  const available = Boolean(found?.available)
  const working = available && isWorking(found)
  // The page follows the server by itself: the delay of the second host and the last segment are
  // only worth what their age is. A server without an archive has nothing to follow.
  useEffect(() => {
    if (!available) return undefined
    const timer = setInterval(() => load(true), working ? WORKING_MS : WATCHING_MS)
    return () => clearInterval(timer)
  }, [available, working, load])

  const ask = async (what, path, said) => {
    setAsking(what)
    setError(null)
    setNotice(null)
    try {
      take(await api.post(path))
      setNotice(said)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setAsking(null)
    }
  }
  const copy = async (text) =>
    showToast({ message: (await copyText(text)) ? 'The command copied.' : 'The browser refused to copy.' })

  const heading = (
    <div>
      <div className="flex items-center gap-2">
        <History className="h-4 w-4 text-accent" aria-hidden="true" />
        <h3 id="recovery-title" className="text-sm font-semibold text-fg">
          Recovery to a moment
        </h3>
      </div>
    </div>
  )

  if (!found || !available) {
    return (
      <section aria-labelledby="recovery-title" className="flex flex-col gap-4 border-t border-line pt-5">
        {heading}
        {error && <Alert>{error}</Alert>}
        {!found && !error && <Wait>Loading the state of the recovery…</Wait>}
        {found && <p className="max-w-prose text-sm text-fg-muted">{NO_ARCHIVE}</p>}
      </section>
    )
  }

  const { archive, copies, disk, settings } = found
  const role = roleText(found, when)
  const asked = askedText(found.pair?.asked, when)
  const log = archiveState(archive, seen.at)
  const second = copiesState(copies, when)
  const proof = testState(found.test, when)
  const bases = found.bases ?? []
  const taking = bases.some((base) => base.state === 'requested')
  const noBase = !bases.some((base) => base.state === 'done' && base.local)
  const cannotTake = taking ? 'A base backup is being taken.' : null
  const cannotTest = found.test?.running
    ? 'A test is running.'
    : noBase
      ? 'There is no base backup yet to recover from.'
      : null

  return (
    <section aria-labelledby="recovery-title" className="flex flex-col gap-6 border-t border-line pt-5">
      <div>
        {heading}
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          Nik archives the log of its database as it is written and takes a base backup on a schedule. With the two the
          server can be brought back to any moment since the oldest base backup, and a second host can hold a copy of
          all of it, ready to take over. Every administrator is told when the archive stops, when the second host falls
          behind, or when a recovery test fails.
        </p>
      </div>

      {error && <Alert>{error}</Alert>}
      <p role="status" className={notice ? 'text-sm text-accent-fg' : 'sr-only'}>
        {notice}
      </p>
      {(found.problems ?? []).map((problem) => (
        <Alert key={problem.id}>{problem.text}</Alert>
      ))}
      {role.replaced && (
        <Alert>
          {role.text}. A standby was promoted in the place of this server: what is written here from now on is not on
          the server that took over.
        </Alert>
      )}

      <dl
        aria-label="State of the recovery"
        className="grid gap-x-6 gap-y-3 border border-line bg-panel p-4 text-sm sm:grid-cols-2"
      >
        <div>
          <dt className={TERM}>This server</dt>
          <dd className="text-fg">
            <span className={role.replaced ? 'font-semibold text-high-fg' : undefined}>{role.text}</span>
            <span className="block text-xs text-fg-muted">
              Generation {found.pair?.generation ?? 1}
              {found.name ? (
                <>
                  {' · known to the other host as '}
                  <span className="font-mono">{found.name}</span>
                </>
              ) : null}
            </span>
            {asked && <span className="block text-xs text-fg-muted">{asked}</span>}
          </dd>
        </div>
        <div>
          <dt className={TERM}>Archive of the log</dt>
          <dd className="text-fg">
            <Badge color={log.color}>{archive.on ? 'on' : 'off'}</Badge> <span>{log.text}</span>
            {archive.lastWal && (
              <span className="block break-all font-mono text-xs text-fg-muted">
                {archive.lastWal}
                {moment(archive.lastAt) ? ` · ${when(moment(archive.lastAt))}` : ''}
              </span>
            )}
            <span className="block text-xs text-fg-muted">{waitingText(archive)}</span>
            {archive.failedWal && (
              <span className="block text-xs text-high-fg">
                The segment {archive.failedWal} could not be archived
                {moment(archive.failedAt) ? ` on ${when(moment(archive.failedAt))}` : ''}.
              </span>
            )}
            <span className="block max-w-prose text-xs text-fg-muted">{timeoutText(archive.timeout)}</span>
            <span className={`block text-xs ${found.service?.running ? 'text-fg-muted' : 'text-med-fg'}`}>
              {serviceText(found.service)}
            </span>
          </dd>
        </div>
      </dl>

      <div className="flex flex-col gap-2">
        <p aria-label="Moments one can go back to" className="text-sm text-fg">
          {windowText(found.window, when)}
        </p>
        <div className="flex items-stretch gap-2">
          <pre
            aria-label="Command to go back to a moment"
            className="min-w-0 flex-1 overflow-x-auto border border-line bg-canvas px-3 py-2 font-mono text-xs text-fg"
          >
            {found.command}
          </pre>
          <Button variant="secondary" size="sm" icon={Copy} onClick={() => copy(found.command)}>
            Copy the command
          </Button>
        </div>
        <p className="max-w-prose text-xs text-fg-muted">{COMMAND_ABOUT}</p>
      </div>

      <div className="flex flex-col gap-2">
        <h4 className="text-sm font-semibold text-fg">The second host</h4>
        {copies?.on ? (
          <dl
            aria-label="State of the second host"
            className="grid gap-x-6 gap-y-3 border border-line bg-panel p-4 text-sm sm:grid-cols-2"
          >
            <div>
              <dt className={TERM}>Where the copies go</dt>
              <dd className="break-all font-mono text-xs text-fg">{copies.where || '—'}</dd>
            </div>
            <div>
              <dt className={TERM}>How far behind it is</dt>
              <dd className={second.color === 'red' ? 'text-high-fg' : 'text-fg'}>
                {second.text}
                {second.most && <span className="text-fg-muted"> ({second.most})</span>}
              </dd>
            </div>
            <div>
              <dt className={TERM}>Last segment sent</dt>
              <dd className="break-words text-xs text-fg">{shippedText(copies, when)}</dd>
            </div>
            <div>
              <dt className={TERM}>Files of the store</dt>
              <dd className="text-xs text-fg">{storeText(copies.store)}</dd>
            </div>
            <div>
              <dt className={TERM}>The link</dt>
              <dd className={`text-xs ${copies.link?.ok === false ? 'text-high-fg' : 'text-fg'}`}>
                {linkText(copies.link, when)}
              </dd>
            </div>
          </dl>
        ) : (
          <p className="max-w-prose border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg">
            {NO_SECOND_HOST}
          </p>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <h4 className="text-sm font-semibold text-fg">Base backups</h4>
            <Badge color="slate">{bases.length}</Badge>
            {taking && <Wait inline>The server is taking a base backup…</Wait>}
          </div>
          <Button
            variant="secondary"
            size="sm"
            icon={DatabaseBackup}
            waiting={asking === 'base' || taking}
            disabled={Boolean(asking) || Boolean(cannotTake)}
            title={cannotTake ?? undefined}
            onClick={() => ask('base', '/recovery/base', 'A base backup was asked for.')}
          >
            Take a base backup now
          </Button>
        </div>
        {bases.length === 0 ? (
          <p className="border border-line bg-panel px-4 py-3 text-sm text-fg-muted">
            No base backup yet. The server takes one at the next run of its schedule.
          </p>
        ) : (
          <div className="overflow-x-auto border border-line">
            <table className="w-full border-collapse text-left text-sm">
              <caption className="sr-only">Base backups</caption>
              <thead className="bg-panel font-mono text-xs text-fg-muted">
                <tr>
                  {['Base backup', 'Taken', 'Size', 'State', 'Checked against its manifest', 'Its copy'].map(
                    (title) => (
                      <th key={title} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                        {title}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody>
                {bases.map((base) => {
                  const status = baseStatus(base)
                  return (
                    <tr key={base.id}>
                      <th scope="row" className="border-b border-line-soft px-3 py-2 align-top font-normal">
                        <span className="font-mono text-fg">{base.id}</span>
                      </th>
                      <td className={CELL}>
                        {moment(base.createdAt) ? when(moment(base.createdAt)) : '—'}
                        {base.requestedBy && !['system', 'schedule'].includes(base.requestedBy) ? (
                          <span className="block">by {base.requestedBy}</span>
                        ) : null}
                      </td>
                      <td className={`${CELL} font-mono`}>{base.size > 0 ? sizeText(base.size) : '—'}</td>
                      <td className={CELL}>
                        <Badge color={status.color}>{status.text}</Badge>
                        {status.detail && (
                          <span className={`block max-w-xs ${status.color === 'red' ? 'text-high-fg' : ''}`}>
                            {status.detail}
                          </span>
                        )}
                      </td>
                      <td className={CELL}>{checkedText(base)}</td>
                      <td className={`${CELL} break-words`}>{baseCopyText(base, when)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="flex flex-col gap-2">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h4 className="text-sm font-semibold text-fg">Recovery test</h4>
          <Button
            variant="secondary"
            size="sm"
            icon={ShieldCheck}
            waiting={asking === 'test' || Boolean(found.test?.running)}
            disabled={Boolean(asking) || Boolean(cannotTest)}
            title={cannotTest ?? undefined}
            onClick={() => ask('test', '/recovery/test', 'A recovery test was asked for.')}
          >
            Test the recovery now
          </Button>
        </div>
        <div aria-label="State of the recovery test" className="border border-line bg-panel px-4 py-3 text-sm">
          {proof.failed && <p className="text-high-fg">{proof.failed}</p>}
          <p className={proof.color === 'amber' ? 'text-med-fg' : 'text-fg'}>{proof.proven}</p>
          {found.test?.running && (
            <Wait inline className="mt-1">
              A test is running…
            </Wait>
          )}
          <p className="mt-1 max-w-prose text-xs text-fg-muted">
            A test replays the latest base backup and the archive into a scratch server, to a moment a minute before the
            last segment archived. The server itself is not touched.
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        <h4 className="text-sm font-semibold text-fg">Room the archive takes</h4>
        <dl
          aria-label="Room the archive takes"
          className="grid gap-x-6 gap-y-2 border border-line bg-panel p-4 text-sm sm:grid-cols-2"
        >
          {diskRows(disk).map((row) => (
            <div key={row.label}>
              <dt className={TERM}>{row.label}</dt>
              <dd className="text-fg">{row.value}</dd>
            </div>
          ))}
        </dl>
        <p className="max-w-prose text-xs text-fg-muted">{estimateText(disk, settings?.keepDays ?? 2)}</p>
      </div>

      <SettingsForm settings={settings} onSaved={take} />

      <p className="max-w-prose text-xs text-fg-muted">{PROMOTION_ABOUT}</p>
    </section>
  )
}
