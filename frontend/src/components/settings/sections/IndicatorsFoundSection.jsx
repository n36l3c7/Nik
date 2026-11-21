import { useCallback, useEffect, useMemo, useState } from 'react'
import { RotateCcw, Save, ScanSearch } from 'lucide-react'
import { useToast } from '../../../context/ToastContext.jsx'
import { api } from '../../../services/api.js'
import { TYPE_LABELS, changesOf, formOf, problemsOf } from '../../../domain/indicatorsFound.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import { ErrorNote } from '../../auth/SecondFactorParts.jsx'
import { Button, Wait } from '../../ui/index.js'
import FindIndicatorsSwitch from './FindIndicatorsSwitch.jsx'
import Switch from './Switch.jsx'

/*
 * ============================================================================
 * INDICATORS FOUND — what Nik makes an indicator by itself when an incident comes in
 * ============================================================================
 *
 * One setting (GET/PUT /api/iocs/found/settings): whether the fields and the
 * context of a new incident are read for indicators, which types are kept,
 * what is left out, which paths are never read, how many an incident may be
 * given, and whether the automatic look-ups ask about what was found. Under
 * it, the instances that fetch: each follows the setting or is told apart.
 */

const HEADING_CLASS = 'mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted'
const INPUT_CLASS =
  'border border-line bg-panel px-2.5 py-1.5 font-mono text-sm text-fg ' +
  'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function Header() {
  return (
    <div>
      <div className="flex items-center gap-2">
        <ScanSearch className="h-5 w-5 text-accent" aria-hidden="true" />
        <h2 className="text-base font-semibold text-fg">Indicators found</h2>
      </div>
      <p className="mt-1 max-w-prose text-sm text-fg-muted">
        When an incident comes in (fetched, made by hand, through the API or by a playbook) its fields and its context
        are read, and what is an address, a domain, a URL, an e-mail address or a hash there becomes an indicator of the
        incident, with the path it was read at. The War Room says once what was found and what was left out.
      </p>
    </div>
  )
}

function Check({ checked, onChange, children }) {
  return (
    <label className="flex cursor-pointer items-start gap-2 text-sm text-fg">
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="mt-0.5 h-4 w-4 border-line accent-accent focus-visible:ring-2 focus-visible:ring-accent"
      />
      <span>{children}</span>
    </label>
  )
}

export default function IndicatorsFoundSection() {
  const { showToast } = useToast()
  const [found, setFound] = useState(null)
  const [form, setForm] = useState(null)
  const [instances, setInstances] = useState([])
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  const load = useCallback(async () => {
    try {
      const settings = await api.get('/iocs/found/settings')
      setFound(settings)
      setForm(formOf(settings))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
    // The instances that fetch, for who may manage them.
    api
      .get('/fetch')
      .then((answer) => setInstances(answer?.instances ?? []))
      .catch(() => setInstances([]))
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const problems = useMemo(() => (form && found ? problemsOf(form, found) : {}), [form, found])
  const changes = useMemo(() => (form && found ? changesOf(form, found) : {}), [form, found])
  const dirty = Object.keys(changes).length > 0
  const wrong = Object.keys(problems).length > 0

  const save = async () => {
    setSaving(true)
    try {
      const settings = await api.put('/iocs/found/settings', changes)
      setFound(settings)
      setForm(formOf(settings))
      setError(null)
      showToast({ message: 'Saved.' })
      setSaving(false)
      return true
    } catch (failure) {
      setError(failure.message)
      setSaving(false)
      return false
    }
  }
  useUnsavedChanges(dirty, { what: 'How indicators are found', save: wrong ? undefined : () => save() })

  if (!found || !form) {
    return (
      <section className="space-y-4">
        <Header />
        {error ? <ErrorNote>{error}</ErrorNote> : <Wait>Reading the setting…</Wait>}
      </section>
    )
  }

  const set = (name) => (value) => setForm((old) => ({ ...old, [name]: value }))
  const toggleType = (type) => (checked) =>
    setForm((old) => ({
      ...old,
      types: checked ? [...old.types, type] : old.types.filter((item) => item !== type),
    }))

  return (
    <section className="max-w-3xl space-y-8">
      <Header />

      <div>
        <div className="flex items-center gap-3">
          <Switch
            checked={form.enabled}
            onChange={set('enabled')}
            label="Read incidents for indicators as they come in"
          />
          <span className="text-sm font-medium text-fg">Read incidents for indicators as they come in</span>
        </div>
        <p className="mt-2 max-w-prose text-sm text-fg-muted">
          Off, nothing is found by itself: an analyst can still ask for one incident from its Indicators tab, and a
          playbook can make indicators of a value with <code className="font-mono">nik.make-indicators</code>. The
          incidents there were before this was turned on are not read.
        </p>
      </div>

      <fieldset>
        <legend className={HEADING_CLASS}>Types that are kept</legend>
        <div className="grid grid-cols-2 gap-x-6 gap-y-1.5 sm:grid-cols-4">
          {found.allTypes.map((type) => (
            <Check key={type} checked={form.types.includes(type)} onChange={toggleType(type)}>
              {TYPE_LABELS[type] ?? type}
            </Check>
          ))}
        </div>
        {problems.types && <p className="mt-2 text-sm text-high-fg">{problems.types}</p>}
      </fieldset>

      <fieldset className="space-y-2">
        <legend className={HEADING_CLASS}>What is left out</legend>
        <Check checked={form.leaveOutPrivate} onChange={set('leaveOutPrivate')}>
          Private and reserved addresses (10.0.0.0/8, 192.168.0.0/16, 127.0.0.1, link-local…) and URLs on internal names
        </Check>
        <Check checked={form.leaveOutBenign} onChange={set('leaveOutBenign')}>
          What is known to be harmless: names kept for documentation (example.com), the hosts of XML and JSON schemas
          (w3.org, schemas.microsoft.com…), the organisation&apos;s own domains (Mail analysis) and the IOC allowlist
        </Check>
        <p className="max-w-prose text-sm text-fg-muted">
          What is left out is counted in the line of the War Room, and never kept.
        </p>
      </fieldset>

      <div>
        <h3 className={HEADING_CLASS}>How many an incident may be given</h3>
        <label className="flex items-center gap-2 text-sm text-fg">
          <input
            aria-label="Indicators an incident may be given by itself"
            inputMode="numeric"
            value={form.cap}
            onChange={(event) => set('cap')(event.target.value)}
            aria-invalid={Boolean(problems.cap)}
            className={`${INPUT_CLASS} w-24`}
          />
          indicators at most
        </label>
        {problems.cap && <p className="mt-1 text-sm text-high-fg">{problems.cap}</p>}
        <p className="mt-2 max-w-prose text-sm text-fg-muted">
          Past it nothing more is kept, and the War Room says how many were not: the common schema of the context is
          read first (File, URL, IP, Domain, Mail…), then the fields, then what the connector keeps under{' '}
          <code className="font-mono">ext</code>. No more than {found.limits.strings.toLocaleString('en')} values of an
          incident are read.
        </p>
      </div>

      <div>
        <h3 className={HEADING_CLASS}>Paths that are never read</h3>
        <textarea
          aria-label="Paths that are never read"
          value={form.skip}
          onChange={(event) => set('skip')(event.target.value)}
          rows={Math.min(14, Math.max(6, form.skip.split('\n').length + 1))}
          spellCheck={false}
          aria-invalid={Boolean(problems.skip)}
          className={`${INPUT_CLASS} w-full`}
        />
        {problems.skip && <p className="mt-1 text-sm text-high-fg">{problems.skip}</p>}
        <div className="mt-2 flex items-start gap-3">
          <p className="max-w-prose flex-1 text-sm text-fg-muted">
            One a line. A word alone is the name of a key wherever it is (<code className="font-mono">*uuid</code>,{' '}
            <code className="font-mono">console*</code>); with dots it is a whole path as the Context tab shows it,
            without the numbers of a list (<code className="font-mono">context.ext.sentinelone.*Url</code>).{' '}
            <code className="font-mono">*</code> stands for anything; capitals do not matter.
          </p>
          <Button
            variant="ghost"
            size="xs"
            icon={RotateCcw}
            onClick={() => set('skip')(found.skipDefault.join('\n'))}
            disabled={form.skip === found.skipDefault.join('\n')}
          >
            Back to the defaults
          </Button>
        </div>
      </div>

      <div>
        <h3 className={HEADING_CLASS}>Look-ups</h3>
        <Check checked={form.lookUps} onChange={set('lookUps')}>
          The automatic look-ups also ask about indicators that were only found
        </Check>
        <p className="mt-2 max-w-prose text-sm text-fg-muted">
          Finding an indicator asks no source. The automatic look-ups (Threat intelligence) leave out what an incident
          holds only because it was found, so that no quota is spent and no value sent out for something nobody chose;
          ticked, they ask about those too, under the same rules. &quot;Check now&quot; and playbooks ask as always.
        </p>
      </div>

      {error && <ErrorNote>{error}</ErrorNote>}
      <div className="flex items-center gap-3">
        <Button icon={Save} onClick={save} disabled={!dirty || wrong} waiting={saving}>
          Save
        </Button>
        {!dirty && <span className="text-sm text-fg-muted">Nothing was changed.</span>}
      </div>

      {instances.length > 0 && (
        <div>
          <h3 className={HEADING_CLASS}>Instances that fetch</h3>
          <p className="mb-2 max-w-prose text-sm text-fg-muted">
            Each follows the setting above unless it is told apart here. A choice is saved at once.
          </p>
          <ul aria-label="Instances that fetch" className="divide-y divide-line-soft border border-line bg-panel">
            {instances.map((instance) => (
              <li key={instance.instanceId} className="flex flex-wrap items-center gap-3 px-3 py-2">
                <span className="min-w-0 flex-1 truncate text-sm text-fg-muted">{instance.connector}</span>
                {/* Drawn again when the setting changes: its first choice says what the setting is. */}
                <FindIndicatorsSwitch
                  key={`${instance.instanceId}-${found.enabled}`}
                  connectionId={instance.instanceId}
                  name={instance.connection}
                />
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  )
}
