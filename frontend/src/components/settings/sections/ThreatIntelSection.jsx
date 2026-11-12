import { useCallback, useEffect, useState } from 'react'
import { ExternalLink, KeyRound, Plus, Radar, Trash2 } from 'lucide-react'
import { Badge, Button } from '../../ui/index.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useSettings } from '../../../context/SettingsContext.jsx'
import { api } from '../../../services/api.js'
import { typeGroups } from '../../../domain/enrichment.js'

/*
 * Threat intelligence: the reputation of indicators from external services.
 *   - Automatic lookups, per type (off until turned on): every new indicator
 *     of that type is checked once with each provider.
 *   - How long an answer stands, per type, and whether an expired one is
 *     asked again. VirusTotal: the vendors listed and the sections that cost
 *     more requests.
 *   - Providers: allowed or not (anyone), API key (admins only; stored
 *     encrypted, never shown again).
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

const KEY_STATUS = {
  ok: { label: 'working', color: 'emerald', title: '' },
  rejected: { label: 'rejected', color: 'red', title: 'The provider refused this key: it is left out of the rotation' },
  unreadable: {
    label: 'unreadable',
    color: 'red',
    title: 'SECRET_KEY changed since the key was saved: remove it and enter it again',
  },
}

/*
 * The keys of one provider (admins): the list with each key's last four
 * characters, label and state, and a form to add one. With several keys the
 * lookups go round them, each with its own rate limit and daily quota.
 */
function KeyEditor({ provider, onSaved }) {
  const [value, setValue] = useState('')
  const [label, setLabel] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const keys = provider.keys ?? []
  const full = keys.length >= (provider.maxKeys ?? 10)

  const run = async (work) => {
    setBusy(true)
    setError(null)
    try {
      await work()
      onSaved()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  const add = (event) => {
    event.preventDefault()
    run(async () => {
      await api.post(`/enrichment/providers/${provider.id}/keys`, { key: value.trim(), label: label.trim() })
      setValue('')
      setLabel('')
    })
  }

  return (
    <div className="space-y-2">
      {keys.length > 0 && (
        <ul aria-label={`${provider.label} API keys`} className="divide-y divide-line-soft border border-line">
          {keys.map((key) => {
            const state = KEY_STATUS[key.status] ?? KEY_STATUS.ok
            return (
              <li key={key.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 px-2 py-1.5 text-xs">
                <span className="inline-flex items-center gap-1 font-mono text-fg">
                  <KeyRound className="h-3 w-3 text-fg-muted" aria-hidden="true" />…{key.hint}
                </span>
                {key.label && <span className="text-fg">{key.label}</span>}
                <Badge color={state.color} title={key.error || state.title}>
                  {state.label}
                </Badge>
                {key.status === 'rejected' && key.error && <span className="text-med">{key.error}</span>}
                <span className="ml-auto text-fg-subtle">{key.updatedBy}</span>
                <Button
                  size="xs"
                  variant="ghost"
                  icon={Trash2}
                  disabled={busy}
                  onClick={() => run(() => api.del(`/enrichment/providers/${provider.id}/keys/${key.id}`))}
                  aria-label={`Remove the ${provider.label} key ending in ${key.hint}`}
                />
              </li>
            )
          })}
        </ul>
      )}
      {full ? (
        <p className="text-xs text-fg-muted">This provider has its {keys.length} keys: remove one to add another.</p>
      ) : (
        <form onSubmit={add} className="flex flex-wrap items-center gap-2">
          <input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={keys.length ? 'Another API key' : 'API key'}
            autoComplete="off"
            aria-label={`${provider.label} API key`}
            className="min-w-0 flex-[2] border border-line bg-canvas px-2 py-1 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="Label (optional, e.g. whose account)"
            maxLength={60}
            aria-label={`Label of the ${provider.label} key`}
            className="min-w-0 flex-1 border border-line bg-canvas px-2 py-1 text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          />
          <Button type="submit" size="xs" icon={Plus} disabled={busy || value.trim().length < 8}>
            Add key
          </Button>
        </form>
      )}
      {error && (
        <p role="alert" className="text-xs text-high">
          {error}
        </p>
      )}
    </div>
  )
}

const keyCount = (provider) => (provider.keys ?? []).filter((k) => k.status === 'ok').length

export default function ThreatIntelSection() {
  const { enrichmentSettings, setEnrichment } = useSettings()
  const { currentUser } = useAuth()
  const isAdmin = currentUser?.role === 'admin'
  const [providers, setProviders] = useState(null)
  const [error, setError] = useState(null)
  const loaded = enrichmentSettings !== null

  const reload = useCallback(() => {
    api
      .get('/enrichment/providers')
      .then((res) => setProviders(res.providers))
      .catch((err) => setError(err.message))
  }, [])
  useEffect(() => reload(), [reload])

  return (
    <section className="space-y-5">
      <div>
        <h3 className="flex items-center gap-2 text-sm font-semibold text-fg">
          <Radar className="h-4 w-4 text-accent" />
          Threat intelligence
        </h3>
        <p className="mt-1 text-xs text-fg-muted">
          The reputation of indicators from external services, shown in the IOCs tab and on each indicator’s page. Never
          sent: private addresses and internal names, allowlisted values, values of incidents whose report is TLP:RED,
          e-mail addresses.
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

      <div className="space-y-2">
        <h4 className="font-mono text-xs uppercase tracking-wider text-fg-muted">VirusTotal</h4>
        <label className="flex flex-wrap items-center gap-2 text-xs text-fg-muted">
          Security vendors listed
          <select
            value={enrichmentSettings?.virustotal?.engines ?? 'flagged'}
            disabled={!loaded}
            onChange={(e) => setEnrichment({ virustotal: { engines: e.target.value } })}
            className="border border-line bg-canvas px-2 py-1 text-xs text-fg"
            aria-label="VirusTotal vendors listed"
          >
            <option value="flagged">only those that flag the value</option>
            <option value="all">all of them</option>
          </select>
        </label>
        <div className="grid gap-2 sm:grid-cols-2">
          <Toggle
            id="enrich-vt-relations"
            checked={Boolean(enrichmentSettings?.virustotal?.relations)}
            disabled={!loaded}
            onChange={(on) => setEnrichment({ virustotal: { relations: on } })}
            label="Relations"
            hint="Passive DNS, files that contact it, what a file contacts. Two more requests per lookup from the quota."
          />
          <Toggle
            id="enrich-vt-comments"
            checked={Boolean(enrichmentSettings?.virustotal?.comments)}
            disabled={!loaded}
            onChange={(on) => setEnrichment({ virustotal: { comments: on } })}
            label="Community comments"
            hint="One more request per lookup from the quota."
          />
        </div>
      </div>

      <div className="space-y-2">
        <h4 className="font-mono text-xs uppercase tracking-wider text-fg-muted">Providers</h4>
        {error && <p className="text-xs text-high">{error}</p>}
        {!providers ? (
          <p className="text-xs text-fg-muted">Loading…</p>
        ) : (
          <ul className="space-y-2">
            {providers.map((p) => {
              const allowed = enrichmentSettings?.providers?.[p.id] ?? true
              return (
                <li key={p.id} className="space-y-2 border border-line p-3">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <label className="flex cursor-pointer items-start gap-2">
                      <input
                        type="checkbox"
                        checked={allowed}
                        disabled={!loaded}
                        onChange={(e) => setEnrichment({ providers: { [p.id]: e.target.checked } })}
                        className="mt-0.5 h-4 w-4 accent-accent"
                        aria-label={`Use ${p.label}`}
                      />
                      <span>
                        <span className="block text-sm font-medium text-fg">{p.label}</span>
                        <span className="block text-xs text-fg-muted">
                          {typeGroups(p.types)} · {p.note}
                        </span>
                      </span>
                    </label>
                    <span className="flex flex-wrap items-center gap-1.5">
                      {p.key === 'none' ? (
                        <Badge color="emerald">no key needed</Badge>
                      ) : p.configured ? (
                        <Badge color="emerald" title="Lookups go round the working keys">
                          <KeyRound className="h-3 w-3" />{' '}
                          {keyCount(p) === 1 ? `key …${p.keyHint}` : `${keyCount(p)} keys in rotation`}
                        </Badge>
                      ) : p.keys?.length ? (
                        <Badge color="red" title="No key of this provider works: see below">
                          no working key
                        </Badge>
                      ) : (
                        <Badge color={p.key === 'required' ? 'amber' : 'slate'}>
                          {p.key === 'required' ? 'needs a key' : 'key optional'}
                        </Badge>
                      )}
                      <a
                        href={p.signup}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 text-xs text-link hover:underline"
                      >
                        get a key <ExternalLink className="h-3 w-3" aria-hidden="true" />
                      </a>
                    </span>
                  </div>
                  {p.key !== 'none' && isAdmin && <KeyEditor provider={p} onSaved={reload} />}
                </li>
              )
            })}
          </ul>
        )}
        {!isAdmin && <p className="text-xs text-fg-muted">An administrator enters the API keys.</p>}
        <p className="text-xs text-fg-muted">
          Keys are stored encrypted on the server and never shown again; changing the server&apos;s SECRET_KEY makes
          them unreadable. A provider can have several keys: lookups go round them, each with its own rate limit and
          daily quota, and a key the provider refuses is left out and marked here. Check each provider&apos;s terms
          before adding more than one key: some do not allow several free accounts to raise the limits.
        </p>
      </div>
    </section>
  )
}
