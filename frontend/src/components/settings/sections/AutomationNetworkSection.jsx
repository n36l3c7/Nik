import { useEffect, useState } from 'react'
import { Globe } from 'lucide-react'
import { api } from '../../../services/api.js'
import { Badge, Button } from '../../ui/index.js'
import ListPicker from '../ListPicker.jsx'

/*
 * Automation → Network and data (admins).
 *
 * Two things every playbook shares: the hosts any "listed hosts only"
 * playbook may reach besides its own (a list: this section says which one is
 * read, and Settings → Lists edits it), and the SMTP server the "Send an
 * e-mail" node uses. What one playbook may reach or send beyond that is
 * chosen on the playbook itself (its Settings tab), behind a double check.
 *
 * The SMTP password is write-only: it is stored encrypted and never shown
 * again; leaving the field empty keeps the stored one.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const SECURITY = [
  { value: 'starttls', label: 'STARTTLS (port 587)' },
  { value: 'tls', label: 'TLS from the start (port 465)' },
  { value: 'none', label: 'None (not encrypted)' },
]

export default function AutomationNetworkSection() {
  const [settings, setSettings] = useState(null)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [busy, setBusy] = useState(false)
  const [smtp, setSmtp] = useState(null)
  const [password, setPassword] = useState('')

  const adopt = (found) => {
    setSettings(found)
    setSmtp(found.smtp)
    setPassword('')
  }
  useEffect(() => {
    let alive = true
    api
      .get('/automation/settings')
      .then((found) => alive && adopt(found))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [])

  const save = async (body, done) => {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      adopt(await api.put('/automation/settings', body))
      setNotice(done)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }

  const saveSmtp = (event) => {
    event.preventDefault()
    const body = {
      host: smtp.host,
      port: Number(smtp.port) || 587,
      security: smtp.security,
      username: smtp.username,
      sender: smtp.sender,
      caPem: smtp.caPem,
    }
    if (password) body.password = password
    save({ smtp: body }, smtp.host ? 'The SMTP server is saved.' : 'No SMTP server: the e-mail node cannot send.')
  }

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-accent" aria-hidden="true" />
          <h2 className="text-base font-semibold text-fg">Network and data</h2>
        </div>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          What every playbook shares: the hosts they may all reach, and the server the e-mail node sends through. What
          one playbook may reach or send beyond this is chosen on that playbook, in its Settings tab.
        </p>
      </div>

      {error && (
        <p role="alert" className="max-w-xl border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      {notice && (
        <p
          role="status"
          className="max-w-xl border border-accent-strong bg-accent-soft px-3 py-2 text-sm text-accent-fg"
        >
          {notice}
        </p>
      )}
      {!settings && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading…
        </p>
      )}

      {settings && (
        <>
          <div className="max-w-xl space-y-3">
            <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              Hosts every playbook may reach
            </h3>
            <p className="text-sm text-fg-muted">
              A playbook set to “Listed hosts only” reaches these and its own. Addresses inside the server’s own network
              are refused whatever is listed.
            </p>
            <ListPicker
              setting="state.hosts"
              label="Hosts"
              hint="A host is a name or an address, with a port if needed: api.example.org or api.example.org:8443."
            />
            <p className="text-xs text-fg-muted">
              It holds:{' '}
              {settings.hosts.length ? (
                <span className="font-mono text-fg">{settings.hosts.join(', ')}</span>
              ) : (
                <em>no host yet</em>
              )}
            </p>
          </div>

          <form onSubmit={saveSmtp} className="max-w-xl space-y-3">
            <h3 className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              SMTP server of the e-mail node {smtp.host ? <Badge color="emerald">set</Badge> : <Badge>not set</Badge>}
            </h3>
            <p className="text-sm text-fg-muted">
              “Send an e-mail” sends through this server, to addresses whose domain a playbook may reach. Without a
              server the node fails, and says so.
            </p>
            <div className="grid gap-3 sm:grid-cols-[minmax(0,1fr)_7rem]">
              <label className="flex flex-col gap-1 text-sm text-fg-muted" htmlFor="smtp-host">
                Server
                <input
                  id="smtp-host"
                  type="text"
                  value={smtp.host}
                  autoComplete="off"
                  spellCheck={false}
                  placeholder="smtp.example.org"
                  onChange={(event) => setSmtp({ ...smtp, host: event.target.value })}
                  className={INPUT}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm text-fg-muted" htmlFor="smtp-port">
                Port
                <input
                  id="smtp-port"
                  type="number"
                  min={1}
                  max={65535}
                  value={smtp.port}
                  onChange={(event) => setSmtp({ ...smtp, port: event.target.value })}
                  className={INPUT}
                />
              </label>
            </div>
            <label className="flex flex-col gap-1 text-sm text-fg-muted" htmlFor="smtp-security">
              Encryption
              <select
                id="smtp-security"
                value={smtp.security}
                onChange={(event) => setSmtp({ ...smtp, security: event.target.value })}
                className={`${INPUT} cursor-pointer`}
              >
                {SECURITY.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </label>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="flex flex-col gap-1 text-sm text-fg-muted" htmlFor="smtp-username">
                User name
                <input
                  id="smtp-username"
                  type="text"
                  value={smtp.username}
                  autoComplete="off"
                  spellCheck={false}
                  onChange={(event) => setSmtp({ ...smtp, username: event.target.value })}
                  className={INPUT}
                />
              </label>
              <label className="flex flex-col gap-1 text-sm text-fg-muted" htmlFor="smtp-password">
                Password
                <input
                  id="smtp-password"
                  type="password"
                  value={password}
                  autoComplete="new-password"
                  placeholder={settings.smtp.hasPassword ? 'stored: type to replace it' : ''}
                  onChange={(event) => setPassword(event.target.value)}
                  className={INPUT}
                />
              </label>
            </div>
            <label className="flex flex-col gap-1 text-sm text-fg-muted" htmlFor="smtp-sender">
              Sender address
              <input
                id="smtp-sender"
                type="text"
                value={smtp.sender}
                autoComplete="off"
                spellCheck={false}
                placeholder="nik@example.org"
                onChange={(event) => setSmtp({ ...smtp, sender: event.target.value })}
                className={INPUT}
              />
            </label>
            <label className="flex flex-col gap-1 text-sm text-fg-muted" htmlFor="smtp-ca">
              Certificate authority (PEM), when the server’s certificate is signed by your own
              <textarea
                id="smtp-ca"
                rows={3}
                value={smtp.caPem}
                spellCheck={false}
                onChange={(event) => setSmtp({ ...smtp, caPem: event.target.value })}
                className={INPUT}
              />
            </label>
            <div className="flex flex-wrap items-center gap-2">
              <Button type="submit" disabled={busy}>
                Save the SMTP server
              </Button>
              {settings.smtp.hasPassword && (
                <Button
                  variant="secondary"
                  disabled={busy}
                  onClick={() => save({ smtp: { ...settings.smtp, password: '' } }, 'The stored password was removed.')}
                >
                  Remove the stored password
                </Button>
              )}
            </div>
          </form>
        </>
      )}
    </section>
  )
}
