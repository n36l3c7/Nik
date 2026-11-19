import { useEffect, useState } from 'react'
import { Globe } from 'lucide-react'
import { api } from '../../../services/api.js'
import { Button } from '../../ui/index.js'
import { settingsPath } from '../../../domain/settingsNav.js'
import { setPath } from '../../../lib/location.js'
import ListPicker from '../ListPicker.jsx'

/*
 * Automation → Network and data (admins).
 *
 * Two things every playbook shares: the hosts any "listed hosts only"
 * playbook may reach besides its own (a list: this section says which one is
 * read, and Settings → Lists edits it). What one playbook may reach or send
 * beyond that is chosen on the playbook itself (its Settings tab), behind a
 * double check.
 *
 * Until 5.1 the SMTP server of the e-mail node was set here. Mail is a
 * connector now, and a server is set on one of its instances.
 */

export default function AutomationNetworkSection() {
  const [settings, setSettings] = useState(null)
  const [error, setError] = useState(null)

  useEffect(() => {
    let alive = true
    api
      .get('/automation/settings')
      .then((found) => alive && setSettings(found))
      .catch((failure) => alive && setError(failure.message))
    return () => {
      alive = false
    }
  }, [])

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <Globe className="h-5 w-5 text-accent" aria-hidden="true" />
          <h2 className="text-base font-semibold text-fg">Network and data</h2>
        </div>
        <p className="mt-1 max-w-prose text-sm text-fg-muted">
          What every playbook shares: the hosts they may all reach. What one playbook may reach or send beyond this is
          chosen on that playbook, in its Settings tab.
        </p>
      </div>

      {error && (
        <p role="alert" className="max-w-xl border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
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

          <div className="max-w-xl space-y-2">
            <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">Sending e-mail</h3>
            <p className="text-sm text-fg-muted">
              Mail is a connector: the server to send through, and the mailbox to read, are set on an instance of{' '}
              <em>Mail listener / sender</em>, under Connectors. The SMTP server that was set here until 5.1 became such
              an instance.
            </p>
            <Button variant="secondary" onClick={() => setPath(settingsPath('connectors'))}>
              Open Connectors
            </Button>
          </div>
        </>
      )}
    </section>
  )
}
