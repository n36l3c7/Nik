import { useCallback, useEffect, useRef, useState } from 'react'
import { PlugZap, Send } from 'lucide-react'
import { api } from '../../../services/api.js'
import {
  PROTOCOLS,
  PROTOCOL_NOTES,
  forwardingBody,
  forwardingForm,
  forwardingProblem,
  forwardingStatus,
  levelOptions,
} from '../../../domain/auditChain.js'
import { lastedWords } from '../../../domain/workers.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { formatRelative } from '../../../lib/time.js'
import { Badge, Button, Select, Wait } from '../../ui/index.js'
import Switch from './Switch.jsx'

/*
 * Forwarding of the audit log to a syslog receiver (admins).
 *
 * Every entry is sent as it is written, in order, by the automation worker
 * (the backend has no way out). What is set here is where, how, and how often
 * a checkpoint goes. Changing it is itself an entry of the log, and the
 * receiver that was set before hears of the change before it takes effect.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const LABEL = 'flex flex-col gap-1 text-sm text-fg-muted'

export default function AuditForwardingForm() {
  const [found, setFound] = useState(null)
  const [form, setForm] = useState(() => forwardingForm())
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const [tested, setTested] = useState(null)
  const set = (patch) => setForm((current) => ({ ...current, ...patch }))
  const loaded = useRef(JSON.stringify(forwardingForm()))

  const take = useCallback((answer, keepForm = false) => {
    setFound(answer)
    const fresh = JSON.stringify(forwardingForm(answer.settings))
    // An untouched form follows what the server keeps; one being edited stays as typed.
    setForm((current) => (keepForm && JSON.stringify(current) !== loaded.current ? current : JSON.parse(fresh)))
    loaded.current = fresh
  }, [])

  const load = useCallback(
    async (keepForm = false) => {
      try {
        take(await api.get('/audit/forwarding'), keepForm)
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

  // The backlog and the last error move by themselves: read again while the page is open.
  useEffect(() => {
    const timer = setInterval(() => load(true), 10000)
    return () => clearInterval(timer)
  }, [load])

  const settings = found?.settings ?? {}
  const dirty = found !== null && JSON.stringify(form) !== loaded.current
  const problem = forwardingProblem(form, settings)

  const save = async (event) => {
    event?.preventDefault()
    if (problem) return false
    setBusy(true)
    setError(null)
    try {
      take(await api.put('/audit/forwarding', forwardingBody(form)))
      setTested(null)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }
  const unsaved = useUnsavedChanges(dirty, {
    what: 'The forwarding of the audit log',
    save: problem ? undefined : () => save(),
  })

  const test = async () => {
    setTesting(true)
    setTested(null)
    try {
      setTested(await api.post('/audit/forwarding/test'))
    } catch (failure) {
      setTested({ ok: false, message: failure.message })
    } finally {
      setTesting(false)
    }
  }

  const status = forwardingStatus(found, formatRelative, (seconds) => lastedWords(seconds * 1000))
  const cannotTest = dirty
    ? 'Save the settings first: the test tries what is saved.'
    : !settings.host
      ? 'No receiver is saved.'
      : found?.state?.sends === 'off'
        ? 'The log is sent by the automation worker, which is off on this server.'
        : null
  const keyKept = Boolean(settings.clientKeySet) && Boolean(settings.clientCert)

  return (
    <section aria-label="Forwarding to syslog" className="border border-line bg-panel p-4">
      <div className="flex items-center gap-2">
        <Send className="h-4 w-4 text-accent" aria-hidden="true" />
        <h3 className="text-sm font-semibold text-fg">Forwarding to syslog</h3>
        {found && <Badge color={status.color}>{status.text}</Badge>}
      </div>
      {!found && !error && <Wait inline>Reading the forwarding…</Wait>}
      {found && (
        <p role="status" aria-label="State of the forwarding" className="mt-1 max-w-prose text-sm text-fg-muted">
          {status.detail}
        </p>
      )}

      {found && (
        <form onSubmit={save} aria-label="Forwarding settings" className="mt-4 flex flex-col gap-4">
          <div className="flex items-center gap-3 text-sm text-fg">
            <Switch
              checked={form.enabled}
              onChange={(enabled) => set({ enabled })}
              label="Send the audit log to a syslog receiver"
            />
            <span>Send the audit log to a syslog receiver</span>
          </div>
          <p className="max-w-prose text-xs text-fg-muted">
            Every entry leaves as it is written, as an RFC 5424 message that carries the entry and its place in the
            chain. A receiver that is down makes a backlog here, sent in order when it is back. The receiver may be on a
            private address: the automation worker connects to this host and this port, and to nothing else through it.
          </p>

          <div className="flex flex-wrap items-end gap-3">
            <label className={LABEL} htmlFor="syslog-host">
              Receiver
              <input
                id="syslog-host"
                type="text"
                value={form.host}
                spellCheck={false}
                placeholder="siem.example"
                onChange={(event) => set({ host: event.target.value })}
                className={`${INPUT} w-64`}
              />
            </label>
            <label className={LABEL} htmlFor="syslog-port">
              Port
              <input
                id="syslog-port"
                type="text"
                inputMode="numeric"
                value={form.port}
                onChange={(event) => set({ port: event.target.value })}
                className={`${INPUT} w-24`}
              />
            </label>
            <Select
              label="Protocol"
              value={form.protocol}
              onChange={(protocol) =>
                set({
                  protocol,
                  // The usual port of the protocol, while the port is still the usual one of the other.
                  port: Object.values(found.defaultPorts ?? {})
                    .map(String)
                    .includes(form.port)
                    ? String(found.defaultPorts?.[protocol] ?? form.port)
                    : form.port,
                })
              }
              options={PROTOCOLS}
            />
          </div>
          <p className={`max-w-prose text-xs ${form.protocol === 'tls' ? 'text-fg-muted' : 'text-med-fg'}`}>
            {PROTOCOL_NOTES[form.protocol]}
          </p>

          {form.protocol === 'tls' && (
            <fieldset className="flex flex-col gap-3 border border-line p-3">
              <legend className="px-1 font-mono text-xs text-fg-muted">TLS</legend>
              <label className={LABEL} htmlFor="syslog-ca">
                CA or certificate of the receiver
                <textarea
                  id="syslog-ca"
                  rows={3}
                  value={form.ca}
                  spellCheck={false}
                  placeholder="-----BEGIN CERTIFICATE-----  (left empty: the authorities of the system)"
                  onChange={(event) => set({ ca: event.target.value })}
                  className={INPUT}
                />
                <span className="text-xs">
                  The authority that signed the certificate of the receiver, or that certificate itself: only what is
                  pasted here is then trusted.
                </span>
              </label>
              <div className="flex items-center gap-3 text-sm text-fg">
                <Switch
                  checked={form.verifyName}
                  onChange={(verifyName) => set({ verifyName })}
                  label="Check that the certificate carries the name of the receiver"
                />
                <span>Check that the certificate carries the name of the receiver</span>
              </div>
              <label className={LABEL} htmlFor="syslog-client-cert">
                Client certificate (when the receiver asks for one)
                <textarea
                  id="syslog-client-cert"
                  rows={3}
                  value={form.clientCert}
                  spellCheck={false}
                  placeholder="-----BEGIN CERTIFICATE-----"
                  onChange={(event) => set({ clientCert: event.target.value })}
                  className={INPUT}
                />
              </label>
              {form.clientCert.trim() && (
                <label className={LABEL} htmlFor="syslog-client-key">
                  Key of the client certificate
                  <textarea
                    id="syslog-client-key"
                    rows={3}
                    value={form.clientKey}
                    spellCheck={false}
                    autoComplete="off"
                    placeholder={
                      keyKept
                        ? 'stored: paste another to replace it'
                        : '-----BEGIN PRIVATE KEY-----  (or {{ credentials.name }})'
                    }
                    onChange={(event) => set({ clientKey: event.target.value })}
                    className={INPUT}
                  />
                  <span className="text-xs">
                    Stored encrypted and never shown again.
                    {settings.clientKeyCredential
                      ? ` It is the stored credential ${settings.clientKeyCredential}.`
                      : ''}{' '}
                    The name of a stored credential can be written in its place.
                  </span>
                </label>
              )}
            </fieldset>
          )}

          <fieldset className="flex flex-col gap-3 border border-line p-3">
            <legend className="px-1 font-mono text-xs text-fg-muted">Message</legend>
            <div className="flex flex-wrap items-end gap-3">
              <Select
                label="Facility"
                value={form.facility}
                onChange={(facility) => set({ facility })}
                options={levelOptions(found.facilities)}
              />
              <Select
                label="Severity"
                value={form.severity}
                onChange={(severity) => set({ severity })}
                options={levelOptions(found.severities)}
              />
              <label className={LABEL} htmlFor="syslog-app">
                Application name
                <input
                  id="syslog-app"
                  type="text"
                  value={form.appName}
                  spellCheck={false}
                  onChange={(event) => set({ appName: event.target.value })}
                  className={`${INPUT} w-36`}
                />
              </label>
              <label className={LABEL} htmlFor="syslog-hostname">
                Host name in the messages
                <input
                  id="syslog-hostname"
                  type="text"
                  value={form.hostname}
                  spellCheck={false}
                  onChange={(event) => set({ hostname: event.target.value })}
                  className={`${INPUT} w-52`}
                />
              </label>
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <label className={LABEL} htmlFor="syslog-checkpoint">
                A checkpoint every (minutes)
                <input
                  id="syslog-checkpoint"
                  type="text"
                  inputMode="numeric"
                  value={form.checkpointMinutes}
                  onChange={(event) => set({ checkpointMinutes: event.target.value })}
                  className={`${INPUT} w-24`}
                />
              </label>
              {form.protocol === 'udp' && (
                <label className={LABEL} htmlFor="syslog-datagram">
                  Largest datagram (bytes)
                  <input
                    id="syslog-datagram"
                    type="text"
                    inputMode="numeric"
                    value={form.maxDatagram}
                    onChange={(event) => set({ maxDatagram: event.target.value })}
                    className={`${INPUT} w-28`}
                  />
                </label>
              )}
              <Select
                label="A new receiver gets"
                value={form.startFrom}
                onChange={(startFrom) => set({ startFrom })}
                options={[
                  { value: 'beginning', label: 'the log from its first entry' },
                  { value: 'now', label: 'the log from this change on' },
                ]}
              />
            </div>
            <p className="max-w-prose text-xs text-fg-muted">
              A checkpoint carries the head of the chain and the number of entries, whether anything happened or not: a
              receiver that hears nothing knows the line is cut, and always holds a recent head to check the log
              against.
            </p>
          </fieldset>

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
              Test
            </Button>
            {testing && <Wait inline>Sending a test message to the receiver…</Wait>}
          </div>
          {tested && (
            <p
              role="status"
              aria-label="Result of the test"
              className={`border px-3 py-2 text-sm ${
                tested.ok
                  ? 'border-accent-strong bg-accent-soft text-accent-fg'
                  : 'border-high-line bg-high-soft text-high'
              }`}
            >
              {tested.message}
              {tested.mark ? ` The message is marked ${tested.mark}.` : ''}
            </p>
          )}

          {error && (
            <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
              {error}
            </p>
          )}
          <div className="flex flex-wrap items-center gap-3">
            <Button
              type="submit"
              waiting={busy}
              disabled={busy || !dirty || Boolean(problem)}
              title={problem ?? undefined}
            >
              Save the forwarding
            </Button>
            {dirty && (
              <Button
                variant="secondary"
                disabled={busy}
                onClick={() => unsaved.leave(() => setForm(JSON.parse(loaded.current)))}
              >
                Discard
              </Button>
            )}
            {dirty && problem && <p className="text-xs text-med-fg">{problem}</p>}
          </div>
          <p className="max-w-prose text-xs text-fg-muted">
            A change is itself an entry of the log, and the receiver that was set hears of it before it takes effect:
            turning the forwarding off, or pointing it elsewhere, is the last thing that receiver gets.
          </p>
        </form>
      )}
      {!found && error && (
        <p role="alert" className="mt-3 border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
    </section>
  )
}
