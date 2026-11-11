import { useEffect, useMemo, useState } from 'react'
import { FileUp } from 'lucide-react'
import { Button, Modal } from '../ui/index.js'
import IncidentFields, { EMPTY_INCIDENT_FIELDS, canCreateIncident } from './IncidentFields.jsx'
import { BROWSERS } from '../../config/browsers.js'
import { SHELLS } from '../../config/shells.js'
import { ARTIFACT_CATEGORIES, artifactSourcesFor, getArtifactCategoryById } from '../../config/artifacts.js'
import { DEFAULT_OS } from '../../config/os.js'
import { kindForTab } from '../../domain/artifactRegistry.js'
import { formatRelative } from '../../lib/time.js'

/*
 * A file dropped anywhere in the app: where it goes. Nik proposes a tab (see
 * domain/fileRouting.js); the analyst confirms or changes it, picks the source
 * when needed (browser, shell, artifact category) and chooses, every time,
 * where it goes: an analysis on its own (e-mails, suspicious files and
 * captures only: host evidence always belongs to an incident), the open
 * incident, or a new one (with its identity fields).
 *
 * `drop.known` lists the artifacts with the same SHA-256, when the file was
 * analysed before; `drop.preferAnalysis` is set by "New analysis".
 *
 * onConfirm({ target: 'analysis' | 'current' | 'new', fields, tab, params })
 */

const TABS = [
  { id: 'malware', label: 'Malware Analysis' },
  { id: 'mail', label: 'Mail Analysis' },
  { id: 'network', label: 'Network Analysis' },
  { id: 'eventlogs', label: 'Event Logs' },
  { id: 'browser', label: 'Browser Forensics' },
  { id: 'commands', label: 'Command History' },
  { id: 'endpoint', label: 'Endpoint Artifacts' },
]

const SELECT =
  'w-full border border-line bg-canvas px-3 py-2 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const size = (n) => (n >= 1048576 ? `${(n / 1048576).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`)

function Select({ id, label, value, onChange, options }) {
  return (
    <label htmlFor={id} className="block space-y-1.5">
      <span className="block font-mono text-xs text-fg-muted">{label}</span>
      <select id={id} value={value} onChange={(e) => onChange(e.target.value)} className={SELECT}>
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  )
}

export default function AddFileDialog({ drop, activeIncident, onClose, onConfirm, onOpenKnown }) {
  const route = drop?.route ?? null
  const [target, setTarget] = useState('current')
  const [fields, setFields] = useState(EMPTY_INCIDENT_FIELDS)
  const [tab, setTab] = useState('malware')
  const [params, setParams] = useState({})

  useEffect(() => {
    if (!drop) return
    const analysable = Boolean(kindForTab(route?.tab ?? 'malware'))
    setTarget(
      drop.preferAnalysis && analysable ? 'analysis' : activeIncident ? 'current' : analysable ? 'analysis' : 'new',
    )
    setFields(EMPTY_INCIDENT_FIELDS)
    setTab(route?.tab ?? 'malware')
    setParams(route?.params ?? {})
    // A new drop resets the form; the open incident only sets the default.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [drop])

  const os = target === 'current' ? (activeIncident?.os ?? DEFAULT_OS) : fields.os

  // Choices for the selected tab, defaulted from the detection.
  const browsers = useMemo(() => BROWSERS.filter((b) => !params.engine || b.engine === params.engine), [params.engine])
  const browser = browsers.find((b) => b.id === params.browser) ?? browsers[0]
  const category = getArtifactCategoryById(params.category) ?? ARTIFACT_CATEGORIES[0]
  const categorySources = useMemo(() => artifactSourcesFor(category, os), [category, os])

  if (!drop) return null

  // Only e-mails, files and captures can be analysed without an incident.
  const analysable = Boolean(kindForTab(tab))
  const known = drop.known ?? []

  const resolved = (() => {
    switch (tab) {
      case 'browser': {
        const source = browser.sources.find((s) => s.key === params.source) ?? browser.sources[0]
        return { browser: browser.id, source: source.key }
      }
      case 'commands':
        return { shell: params.shell ?? SHELLS[0].id }
      case 'endpoint':
        return {
          category: category.id,
          source: (categorySources.find((s) => s.key === params.source) ?? categorySources[0])?.key,
        }
      case 'eventlogs':
        return { kind: params.kind ?? (/\.evtx$/i.test(drop.file.name) ? 'evtx' : 'json') }
      default:
        return {}
    }
  })()

  const ready =
    (target === 'analysis' ? analysable : target === 'current' ? Boolean(activeIncident) : canCreateIncident(fields)) &&
    (tab !== 'endpoint' || Boolean(resolved.source))

  const submit = (event) => {
    event.preventDefault()
    if (!ready) return
    onConfirm({ target, fields, tab, params: resolved })
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Add a file"
      maxWidth="max-w-xl"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-add-file" disabled={!ready}>
            {target === 'analysis' ? 'Start analysis' : target === 'new' ? 'Create incident and import' : 'Import'}
          </Button>
        </>
      }
    >
      <form id="form-add-file" onSubmit={submit} className="space-y-4">
        <div className="flex items-start gap-3 border border-line bg-canvas p-3">
          <FileUp className="mt-0.5 h-5 w-5 shrink-0 text-accent" aria-hidden="true" />
          <div className="min-w-0">
            <p className="break-all font-mono text-sm text-fg">{drop.file.name}</p>
            <p className="text-xs text-fg-muted">
              {size(drop.file.size)} ·{' '}
              {route ? (
                <>
                  {route.label} → <span className="text-fg">{TABS.find((t) => t.id === route.tab)?.label}</span>
                </>
              ) : (
                <span className="text-med">not recognised: choose where it goes</span>
              )}
            </p>
          </div>
        </div>

        {known.length > 0 && (
          <div className="space-y-1.5 border border-info-line bg-info-soft/40 p-3 text-sm text-fg">
            <p className="font-semibold">This file was already analysed.</p>
            {known.map((item) => (
              <p key={item.id} className="flex flex-wrap items-center gap-2 text-xs text-fg-muted">
                <span>
                  {item.name} · {item.createdBy || 'unknown'} · {formatRelative(item.createdAt)}
                  {item.incidents.length > 0 ? ` · in ${item.incidents.map((i) => i.name).join(', ')}` : ''}
                </span>
                <Button type="button" variant="secondary" size="xs" onClick={() => onOpenKnown(item)}>
                  Open the existing analysis
                </Button>
              </p>
            ))}
          </div>
        )}

        <fieldset className="space-y-2">
          <legend className="mb-1 font-mono text-xs text-fg-muted">Where</legend>
          {analysable && (
            <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
              <input
                type="radio"
                name="add-file-target"
                checked={target === 'analysis'}
                onChange={() => setTarget('analysis')}
                className="accent-accent"
              />
              Start analysis <span className="text-fg-muted">on its own, no incident (link it later)</span>
            </label>
          )}
          {activeIncident && (
            <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
              <input
                type="radio"
                name="add-file-target"
                checked={target === 'current'}
                onChange={() => setTarget('current')}
                className="accent-accent"
              />
              Add to the open incident <span className="truncate font-mono text-fg-muted">{activeIncident.name}</span>
            </label>
          )}
          <label className="flex cursor-pointer items-center gap-2 text-sm text-fg">
            <input
              type="radio"
              name="add-file-target"
              checked={target === 'new'}
              onChange={() => setTarget('new')}
              className="accent-accent"
            />
            Start a new incident with this file
          </label>
        </fieldset>

        {target === 'new' && (
          <div className="border-l-2 border-line pl-3">
            <IncidentFields value={fields} onChange={setFields} idPrefix="drop" autoFocus={false} />
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <Select
            id="add-file-tab"
            label="Tab"
            value={tab}
            onChange={(next) => {
              setTab(next)
              if (target === 'analysis' && !kindForTab(next)) setTarget(activeIncident ? 'current' : 'new')
              setParams(next === route?.tab ? route.params : {})
            }}
            options={TABS.map((t) => ({ value: t.id, label: t.label }))}
          />
          {tab === 'browser' && (
            <Select
              id="add-file-browser"
              label="Browser"
              value={browser.id}
              onChange={(id) => setParams({ ...params, browser: id })}
              options={browsers.map((b) => ({ value: b.id, label: b.label }))}
            />
          )}
          {tab === 'browser' && !route?.params?.source && (
            <Select
              id="add-file-browser-source"
              label="File"
              value={resolved.source}
              onChange={(key) => setParams({ ...params, source: key })}
              options={browser.sources.map((s) => ({ value: s.key, label: s.label ?? s.key }))}
            />
          )}
          {tab === 'commands' && (
            <Select
              id="add-file-shell"
              label="Shell"
              value={resolved.shell}
              onChange={(shell) => setParams({ ...params, shell })}
              options={SHELLS.map((s) => ({ value: s.id, label: s.label }))}
            />
          )}
          {tab === 'endpoint' && (
            <>
              <Select
                id="add-file-category"
                label="Category"
                value={category.id}
                onChange={(id) => setParams({ category: id })}
                options={ARTIFACT_CATEGORIES.map((c) => ({ value: c.id, label: c.label }))}
              />
              {categorySources.length > 0 ? (
                <Select
                  id="add-file-source"
                  label="Source"
                  value={resolved.source}
                  onChange={(key) => setParams({ ...params, category: category.id, source: key })}
                  options={categorySources.map((s) => ({ value: s.key, label: s.name }))}
                />
              ) : (
                <p className="self-end text-xs text-med">No source for this category on this host's OS.</p>
              )}
            </>
          )}
          {tab === 'eventlogs' && (
            <Select
              id="add-file-eventlog-kind"
              label="Format"
              value={resolved.kind}
              onChange={(kind) => setParams({ ...params, kind })}
              options={[
                { value: 'evtx', label: '.evtx (parsed on the server)' },
                { value: 'json', label: 'JSON of the collection script' },
              ]}
            />
          )}
        </div>
      </form>
    </Modal>
  )
}
