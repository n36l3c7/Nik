import { useCallback, useEffect, useState } from 'react'
import { ExternalLink, KeyRound, Radar, Save, Trash2 } from 'lucide-react'
import { Badge, Button } from '../../ui/index.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useSettings } from '../../../context/SettingsContext.jsx'
import { api } from '../../../services/api.js'
import { typeGroups } from '../../../utils/enrichment.js'

/*
 * Threat intelligence: the reputation of indicators from external services.
 *   - Automatic lookups, per type (off until turned on): every new indicator
 *     of that type is checked once with each provider, again after the
 *     cache period. Anyone can change them.
 *   - Providers: allowed or not (anyone), API key (admins only; stored
 *     encrypted, never shown again).
 * Never sent: private addresses and internal names, allowlisted values,
 * values of TLP:RED incidents, e-mail addresses.
 */

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

function KeyEditor({ provider, onSaved }) {
  const [value, setValue] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const save = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.put(`/enrichment/providers/${provider.id}/key`, { key: value.trim() })
      setValue('')
      onSaved()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  const remove = async () => {
    setBusy(true)
    try {
      await api.del(`/enrichment/providers/${provider.id}/key`)
      onSaved()
    } catch (err) {
      setError(err.message)
    } finally {
      setBusy(false)
    }
  }
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2">
        <input
          type="password"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder={provider.configured ? `key …${provider.keyHint} (type to replace)` : 'API key'}
          autoComplete="off"
          aria-label={`${provider.label} API key`}
          className="min-w-0 flex-1 border border-line bg-canvas px-2 py-1 font-mono text-xs text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        />
        <Button size="xs" icon={Save} onClick={save} disabled={busy || value.trim().length < 8}>
          Save key
        </Button>
        {provider.configured || provider.keyUnreadable ? (
          <Button
            size="xs"
            variant="ghost"
            icon={Trash2}
            onClick={remove}
            disabled={busy}
            aria-label={`Remove the ${provider.label} key`}
          />
        ) : null}
      </div>
      {error && <p className="text-xs text-high">{error}</p>}
    </div>
  )
}

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
          The reputation of indicators from external services, shown in the IOCs tab and in “Where seen”. Never sent:
          private addresses and internal names, allowlisted values, values of incidents whose report is TLP:RED, e-mail
          addresses.
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
        <label className="flex items-center gap-2 text-xs text-fg-muted">
          Keep answers for
          <select
            value={enrichmentSettings?.ttlHours ?? 24}
            disabled={!loaded}
            onChange={(e) => setEnrichment({ ttlHours: Number(e.target.value) })}
            className="border border-line bg-canvas px-2 py-1 text-xs text-fg"
            aria-label="Cache period"
          >
            {[6, 12, 24, 72, 168, 720].map((h) => (
              <option key={h} value={h}>
                {h < 72 ? `${h} hours` : `${h / 24} days`}
              </option>
            ))}
          </select>
          before asking again. “Check now” in Where seen asks at once.
        </label>
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
                        <Badge color="emerald" title={`Set by ${p.keyUpdatedBy}`}>
                          <KeyRound className="h-3 w-3" /> key …{p.keyHint}
                        </Badge>
                      ) : p.keyUnreadable ? (
                        <Badge color="red" title="SECRET_KEY changed since the key was saved: enter it again">
                          key unreadable
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
          them unreadable.
        </p>
      </div>
    </section>
  )
}
