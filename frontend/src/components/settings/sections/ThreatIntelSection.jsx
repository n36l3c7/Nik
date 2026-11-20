import { useCallback, useEffect, useState } from 'react'
import { KeyRound, Power, Radar, Trash2 } from 'lucide-react'
import { Badge, Button } from '../../ui/index.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useSettings } from '../../../context/SettingsContext.jsx'
import { api, apiUrl } from '../../../services/api.js'
import { guardDestinations, oldKeyLine, sourceState, typeGroups } from '../../../domain/enrichment.js'
import LookupGuardDialog from './LookupGuardDialog.jsx'
import { settingsPath } from '../../../domain/settingsNav.js'
import { setPath } from '../../../lib/location.js'

/*
 * Threat intelligence: the reputation of indicators, asked of the sources.
 *   - Automatic lookups, per type (off until turned on): every new indicator
 *     of that type is checked once with each source that is on.
 *   - How long an answer stands, per type, and whether an expired one is
 *     asked again.
 *   - Sources: the connectors that judge indicators. A source is asked through
 *     an instance of its connector, with the keys and the limits of that
 *     instance: it is on when one of its instances is. Keys are entered on the
 *     instance (Connectors), never here.
 *   - The API keys this page kept before 6.5, until an instance has them.
 *   - What the look-ups may send: the classes of the data guard an indicator
 *     can carry (an e-mail address in a link, a name under your own domains,
 *     an allowlisted name), each closed until an administrator opens it
 *     behind the double check. It is for the look-ups made outside playbooks;
 *     a playbook keeps to what was opened for it.
 * Never sent: private addresses and internal names, allowlisted values,
 * values of TLP:RED incidents, e-mail addresses.
 */

const RETENTION = [
  { key: 'ip', label: 'IP addresses', fallback: 30 },
  { key: 'url', label: 'URLs and domains', fallback: 30 },
  { key: 'hash', label: 'File hashes', fallback: 180 },
]

const AUTO = [
  { key: 'ip', label: 'IP addresses', hint: 'public addresses only' },
  { key: 'url', label: 'URLs and domains', hint: 'not internal names' },
  { key: 'hash', label: 'File hashes', hint: 'samples, attachments, hashes in the data' },
]

function Toggle({ id, checked, onChange, label, hint, disabled }) {
  return (
    <label htmlFor={id} className="flex cursor-pointer items-start gap-3 border border-line px-3 py-2.5">
      <input
        id={id}
        type="checkbox"
        role="switch"
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
        className="mt-0.5 h-4 w-4 accent-accent"
      />
      <span>
        <span className="block text-sm font-medium text-fg">{label}</span>
        <span className="block text-xs text-fg-muted">{hint}</span>
      </span>
    </label>
  )
}

const OLD_KEY_STATE = {
  waiting: { label: 'waits for its pack', color: 'amber' },
  rejected: { label: 'refused by the vendor', color: 'red' },
  unreadable: { label: 'unreadable', color: 'red' },
  unknown: { label: 'no source', color: 'slate' },
}

/*
 * The API keys kept from before 6.5 that no instance holds yet. Each moves by
 * itself when the pack of its source is installed; one that cannot move stays
 * until an administrator removes it.
 */
function OldKeys({ keys, canManage, onChanged }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  if (!keys.length) return null
  const remove = async (key) => {
    setBusy(true)
    setError(null)
    try {
      await api.del(`/enrichment/old-keys/${encodeURIComponent(key.id)}`)
      onChanged()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div role="region" aria-label="API keys kept from before 6.5" className="space-y-2 border border-med-line p-3">
      <h4 className="font-mono text-xs uppercase tracking-wider text-fg-muted">API keys kept from before 6.5</h4>
      <p className="text-xs text-fg-muted">
        Until 6.5 the keys of the sources were entered on this page. A source is a connector now, and its keys are those
        of an instance of it. These keys are still stored, encrypted, and are not used until an instance has them.
      </p>
      <ul aria-label="Keys kept from before 6.5" className="divide-y divide-line-soft border border-line">
        {keys.map((key) => {
          const state = OLD_KEY_STATE[key.state] ?? OLD_KEY_STATE.unknown
          return (
            <li key={key.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2 py-1.5 text-xs">
              <span className="font-medium text-fg">{key.label}</span>
              <span className="inline-flex items-center gap-1 font-mono text-fg">
                <KeyRound className="h-3 w-3 text-fg-muted" aria-hidden="true" />…{key.hint}
              </span>
              {key.name && <span className="text-fg">{key.name}</span>}
              <Badge color={state.color} title={key.error || undefined}>
                {state.label}
              </Badge>
              <span className="min-w-0 flex-1 basis-64 text-fg-muted">{oldKeyLine(key)}</span>
              {canManage && (
                <Button
                  size="xs"
                  variant="ghost"
                  icon={Trash2}
                  disabled={busy}
                  onClick={() => remove(key)}
                  aria-label={`Remove the ${key.label} key ending in ${key.hint}`}
                />
              )}
            </li>
          )
        })}
      </ul>
      {error && (
        <p role="alert" className="text-xs text-high">
          {error}
        </p>
      )}
    </div>
  )
}

/*
 * What the data guard lets the look-ups made outside playbooks send. Each
 * class says what it is in the words of the playbook's screen, and what it is
 * in an indicator. Opening asks twice (LookupGuardDialog); closing does not.
 */
function LookupGuard({ classes, sources, canManage, actor, onChanged }) {
  const [asking, setAsking] = useState(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const close = async (item) => {
    setBusy(true)
    setError(null)
    try {
      await api.put('/enrichment/guard', { class: item.id, allow: false })
      onChanged()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div role="region" aria-label="What the look-ups may send" className="space-y-2">
      <h4 className="font-mono text-xs uppercase tracking-wider text-fg-muted">What the look-ups may send</h4>
      <p className="text-xs text-fg-muted">
        Before a source is asked, the data guard reads the value as it reads what a playbook sends. A value that carries
        one of these classes is held: its indicator says so where the verdict would be, and no source is asked until the
        class is opened here. This is for “Check now”, the checks in bulk and the automatic look-ups; a look-up a
        playbook makes keeps to what was opened for that playbook. Your own domains are the ones of Mail analysis.
      </p>
      <ul aria-label="Classes of data the look-ups may send" className="divide-y divide-line-soft border border-line">
        {classes.map((item) => (
          <li key={item.id} className="flex items-center justify-between gap-3 px-3 py-2 text-sm">
            <span className="min-w-0 text-fg">
              {item.label}
              <span className="block text-xs text-fg-muted">{item.warning}</span>
              <span className="block text-xs text-fg-muted">{item.example}</span>
            </span>
            <span className="flex shrink-0 items-center gap-2">
              {item.open ? <Badge color="amber">may leave</Badge> : <Badge>closed</Badge>}
              {canManage && (
                <Button
                  variant="secondary"
                  size="xs"
                  disabled={busy}
                  aria-label={item.open ? `Close: ${item.label}` : `Open: ${item.label}`}
                  onClick={() => (item.open ? close(item) : setAsking(item))}
                >
                  {item.open ? 'Close' : 'Open…'}
                </Button>
              )}
            </span>
          </li>
        ))}
      </ul>
      {error && (
        <p role="alert" className="text-xs text-high">
          {error}
        </p>
      )}
      <LookupGuardDialog
        item={asking}
        destinations={guardDestinations(sources)}
        actor={actor}
        onClose={() => setAsking(null)}
        onConfirm={async (check) => {
          await api.put('/enrichment/guard', { class: asking.id, allow: true, ...check })
          setAsking(null)
          onChanged()
        }}
      />
    </div>
  )
}

export default function ThreatIntelSection() {
  const { enrichmentSettings, setEnrichment } = useSettings()
  const { can, currentUser } = useAuth()
  const isAdmin = can('admin')
  const canConnect = can('connectors.manage')
  const [found, setFound] = useState(null)
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(null)
  const loaded = enrichmentSettings !== null

  const reload = useCallback(() => {
    api
      .get('/enrichment/sources')
      .then((res) => setFound({ sources: res.sources ?? [], oldKeys: res.oldKeys ?? [], guard: res.guard ?? [] }))
      .catch((err) => setError(err.message))
  }, [])
  useEffect(() => reload(), [reload])

  // A source that needs no key: its instance is made here, with the name of the connector.
  const turnOn = async (source) => {
    setBusy(source.id)
    setError(null)
    try {
      await api.post(`/automation/connectors/${encodeURIComponent(source.id)}/instances`, {
        name: source.label,
        config: {},
        secrets: {},
        enabled: true,
      })
      reload()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(null)
    }
  }

  const sources = found?.sources ?? []
  return (
    <section className="space-y-5">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <Radar className="h-4 w-4 text-accent" />
          Threat intelligence
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          The reputation of indicators, asked of the sources below and shown in the Indicators tab and on each
          indicator’s page. Never sent: private addresses and internal names, allowlisted values, values of incidents
          whose report is TLP:RED, e-mail addresses. Held until its class is opened below: a value that carries an
          e-mail address, a name under your own domains or an allowlisted name.
        </p>
      </div>

      <div className="space-y-2">
        <h4 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Automatic lookups</h4>
        <div className="grid gap-2 sm:grid-cols-3">
          {AUTO.map((item) => (
            <Toggle
              key={item.key}
              id={`enrich-auto-${item.key}`}
              checked={Boolean(enrichmentSettings?.auto?.[item.key])}
              disabled={!loaded}
              onChange={(on) => setEnrichment({ auto: { [item.key]: on } })}
              label={item.label}
              hint={item.hint}
            />
          ))}
        </div>
      </div>

      <div className="space-y-2">
        <h4 className="font-mono text-xs uppercase tracking-wider text-fg-muted">How long an answer stands</h4>
        <div className="grid gap-2 sm:grid-cols-3">
          {RETENTION.map((item) => (
            <label
              key={item.key}
              htmlFor={`enrich-retention-${item.key}`}
              className="block border border-line px-3 py-2.5"
            >
              <span className="block text-sm font-medium text-fg">{item.label}</span>
              <span className="mt-1 flex items-center gap-2 text-xs text-fg-muted">
                <input
                  id={`enrich-retention-${item.key}`}
                  aria-label={`${item.label}: days an answer stands`}
                  type="number"
                  min={1}
                  max={730}
                  step={1}
                  disabled={!loaded}
                  value={enrichmentSettings?.retentionDays?.[item.key] ?? item.fallback}
                  onChange={(e) => {
                    const days = Math.round(Number(e.target.value))
                    if (days >= 1 && days <= 730) setEnrichment({ retentionDays: { [item.key]: days } })
                  }}
                  className="w-20 border border-line bg-canvas px-2 py-1 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                />
                days
              </span>
            </label>
          ))}
        </div>
        <Toggle
          id="enrich-refresh-expired"
          checked={enrichmentSettings?.refreshExpired ?? true}
          disabled={!loaded}
          onChange={(on) => setEnrichment({ refreshExpired: on })}
          label="Ask again when an answer has expired"
          hint="When an indicator is opened, and in the automatic lookups. Off: the old answer is kept and marked as expired until someone presses Check again."
        />
      </div>

      {found && found.guard.length > 0 && (
        <LookupGuard
          classes={found.guard}
          sources={found.sources}
          canManage={isAdmin}
          actor={currentUser?.username ?? ''}
          onChanged={reload}
        />
      )}

      {found && <OldKeys keys={found.oldKeys} canManage={isAdmin} onChanged={reload} />}

      <div className="space-y-2">
        <h4 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Sources</h4>
        <p className="text-xs text-fg-muted">
          A source is a connector that judges indicators. It is asked through an instance of its connector, with the
          keys and the limits of that instance, and it is on when one of its instances is: the oldest that is on is the
          one asked. Keys are entered on the instance, never here.
        </p>
        {error && (
          <p role="alert" className="text-xs text-high">
            {error}
          </p>
        )}
        {!found ? (
          <p className="text-xs text-fg-muted">Loading…</p>
        ) : sources.length === 0 ? (
          <div className="space-y-2 border border-line p-3">
            <p className="text-sm text-fg">No source is installed.</p>
            <p className="text-xs text-fg-muted">
              The sources come as content packs (VirusTotal, AbuseIPDB, urlscan.io, ThreatFox, URLhaus, MalwareBazaar,
              OTX, GreyNoise, Shodan, Safe Browsing, RDAP, and any pack whose connector judges indicators). Install the
              ones you use, then make an instance of each connector. Until then no indicator is looked up.
            </p>
            <Button size="xs" variant="secondary" onClick={() => setPath(settingsPath('contentPacks'))}>
              Open Content packs
            </Button>
          </div>
        ) : (
          <ul aria-label="Sources of threat intelligence" className="space-y-2">
            {sources.map((source) => {
              const state = sourceState(source)
              return (
                <li key={source.id} className="space-y-1.5 border border-line p-3">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <span className="flex min-w-0 items-start gap-2">
                      {source.logo && (
                        <img src={apiUrl(source.logo)} alt="" className="mt-0.5 h-4 w-4 shrink-0 object-contain" />
                      )}
                      <span className="min-w-0">
                        <span className="block text-sm font-medium text-fg">{source.label}</span>
                        <span className="block text-xs text-fg-muted">
                          {typeGroups(source.types)} · weight {source.weight} in the score
                          {source.informational ? ' · counted only when it flags the value' : ''}
                        </span>
                      </span>
                    </span>
                    <span className="flex flex-wrap items-center gap-1.5">
                      <Badge color={state.color}>{state.badge}</Badge>
                      {state.state === 'none' && source.needsNothing && canConnect && (
                        <Button
                          size="xs"
                          icon={Power}
                          disabled={busy === source.id}
                          onClick={() => turnOn(source)}
                          aria-label={`Turn on ${source.label}`}
                        >
                          Turn on
                        </Button>
                      )}
                    </span>
                  </div>
                  <p className="text-xs text-fg-muted">{state.line}</p>
                </li>
              )
            })}
          </ul>
        )}
        {found && sources.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="xs" variant="secondary" onClick={() => setPath(settingsPath('connectors'))}>
              Open Connectors
            </Button>
            <span className="text-xs text-fg-muted">
              Instances, their keys, the requests a key may make a minute and a day, and the answers an instance keeps.
            </span>
          </div>
        )}
        <p className="text-xs text-fg-muted">
          A look-up runs the command of the connector that is marked for the type of the indicator, never one that needs
          a paid plan or that changes something at the vendor. Check each vendor&apos;s terms before giving an instance
          more than one key: some do not allow several free accounts to raise the limits.
        </p>
      </div>
    </section>
  )
}
