import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Download, FileCode2, ImageUp, Pencil, Plug, Plus, Trash2, Upload, Zap } from 'lucide-react'
import { api, apiUrl } from '../../../services/api.js'
import {
  CONNECTOR_FILTERS,
  authOf,
  capabilities,
  connectorRows,
  instancesText,
  instanceTabs,
  problemLines,
} from '../../../domain/automation/instances.js'
import { stateBadge } from '../../../domain/fetch.js'
import { instanceFromPath, instancePath, settingsPath } from '../../../domain/settingsNav.js'
import { formatRelative } from '../../../lib/time.js'
import { freely, onLocationChange, setPath } from '../../../lib/location.js'
import { leaveHere } from '../../../lib/unsaved.js'
import { PLAYGROUND_ROOT, leaveLine, tryLine } from '../../../domain/playground.js'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { Badge, Button, EmptyState, Modal, SearchInput } from '../../ui/index.js'
import InstancePane from './InstancePane.jsx'
import MirrorQueue from './MirrorQueue.jsx'
import Switch from './Switch.jsx'
import { transfer } from '../../../lib/transfers.js'

/*
 * Automation → Connectors (the role Connectors, or an admin).
 *
 * One page for the connectors and their instances. A connector is a file that
 * says how to talk to a product: what an instance needs and the commands there
 * are. An instance is one system of that product: an address and credentials.
 * A connector may have several, each turned on and off on its own; it is
 * enabled, and its commands are offered to playbooks and the War Room, when
 * one of them is on.
 *
 * Adding a file checks it first: what is wrong is listed with the line it is
 * on, and nothing is installed until the file is right.
 *
 * An instance is opened beside the list, in a form with tabs (InstancePane.jsx):
 * its connection and its keys and, for a connector that fetches, how it
 * fetches, its classifier and its mappers. The address names the instance and
 * the tab (/settings/automation/connectors/<instance>/<tab>), so a link, such
 * as the one of a notification that an instance is failing, opens it there. On
 * the tabs that are tables the form takes the width of the page.
 */

/** The place of a connector's logo: one size for all, empty until the connector brings one. */
function LogoSlot({ connector }) {
  if (connector.logo) {
    return <img src={apiUrl(connector.logo)} alt="" className="h-10 w-10 shrink-0 object-contain" />
  }
  return <span aria-hidden="true" className="h-10 w-10 shrink-0 border border-dashed border-line" />
}

function LastTest({ test }) {
  if (!test) return <span className="text-fg-muted">never tested</span>
  return (
    <span className="flex items-center gap-1.5">
      <Badge color={test.ok ? 'emerald' : 'red'}>{test.ok ? 'ok' : test.status || 'failed'}</Badge>
      <span className="text-fg-muted">{formatRelative(test.at)}</span>
    </span>
  )
}

export default function ConnectorsSection() {
  const { can } = useAuth()
  const [connectors, setConnectors] = useState(null)
  const [instances, setInstances] = useState(null)
  const [query, setQuery] = useState('')
  const [filter, setFilter] = useState('all')
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [upload, setUpload] = useState(null) // { fileName, source, problems, connector }
  const [shown, setShown] = useState(null) // a connector with its source
  const [removing, setRemoving] = useState(null)
  const [editing, setEditing] = useState(null) // { connector, instance: object | null, tab }
  // The instance and the tab the address names: a link opens the form there.
  const [asked, setAsked] = useState(() => instanceFromPath(window.location.pathname))
  const [deleting, setDeleting] = useState(null)
  const [testing, setTesting] = useState(null)
  const [busy, setBusy] = useState(false)
  const fileInput = useRef(null)
  const logoInput = useRef(null)
  const [logoError, setLogoError] = useState(null)
  const menu = useObjectMenu()

  const load = useCallback(async () => {
    try {
      const [first, second] = await Promise.all([api.get('/automation/connectors'), api.get('/automation/instances')])
      setConnectors(first.connectors)
      setInstances(second.instances)
      // An error on the page is left: it is about what was just asked, and reading the list again is part of it.
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const { rows, counts } = useMemo(
    () => connectorRows(connectors, instances, { query, filter }),
    [connectors, instances, query, filter],
  )

  useEffect(() => onLocationChange(() => setAsked(instanceFromPath(window.location.pathname))), [])
  useEffect(() => {
    if (!asked || !connectors || !instances) return
    const instance = instances.find((item) => item.id === asked.instanceId)
    const connector = instance && connectors.find((item) => item.id === instance.connector)
    if (!connector) return
    setEditing((current) =>
      current?.instance?.id === instance.id
        ? current.tab === asked.tab
          ? current
          : { ...current, tab: asked.tab }
        : { connector, instance, tab: asked.tab },
    )
  }, [asked, connectors, instances])

  const pathOf = (next) => (next?.instance ? instancePath(next.instance.id, next.tab) : settingsPath('connectors'))
  /** Show the form of an instance on a tab (a new one when `instance` is null), or none (`null`). */
  const edit = (next) => {
    setEditing(next ? { tab: 'connection', ...next } : null)
    // The address follows the form: whoever asked for the move was asked about what is not saved.
    freely(() => setPath(pathOf(next), { replace: true }))
  }
  /**
   * The same, when the person asks for it: the form that is open may hold changes that are not saved
   * (another part of the same form keeps them; another instance, or closing it, would lose them).
   */
  const openForm = (next) => {
    const sameForm =
      next !== null &&
      editing !== null &&
      next.connector.id === editing.connector.id &&
      (next.instance?.id ?? null) === (editing.instance?.id ?? null)
    if (sameForm) edit(next)
    else leaveHere(() => edit(next))
  }
  const wide =
    editing !== null &&
    Boolean(instanceTabs(editing.connector, editing.instance).find((item) => item.id === editing.tab)?.wide)

  const said = (message) => {
    setError(null)
    setNotice(message)
  }

  /* ---- connector files ---- */
  const check = async (file) => {
    setNotice(null)
    setError(null)
    try {
      const source = await file.text()
      const found = await transfer(`Checking ${file.name}`, () => api.post('/automation/connectors/check', { source }))
      setUpload({ fileName: file.name, source, problems: found.problems, connector: found.connector })
    } catch (failure) {
      setError(`${file.name}: ${failure.message}`)
    }
  }

  const install = async () => {
    setBusy(true)
    setError(null)
    try {
      const made = await api.post('/automation/connectors', { source: upload.source })
      setUpload(null)
      said(
        `${made.name} is installed: version ${made.version}, ${made.commands.length} commands. Add an instance to use it.`,
      )
      load()
    } catch (failure) {
      // The file changed its mind between the check and the install: show what the server says now.
      if (failure.data?.problems) setUpload({ ...upload, problems: failure.data.problems, connector: null })
      else setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  /** Give the connector the image of a file as its logo, or take its logo away (`file` null). */
  const setLogo = async (connector, file) => {
    setLogoError(null)
    const path = `/automation/connectors/${encodeURIComponent(connector.id)}/logo`
    try {
      if (file) await transfer(`Uploading ${file.name}`, () => api.put(path, file))
      else await api.del(path)
      setShown(await api.get(`/automation/connectors/${encodeURIComponent(connector.id)}`))
      load()
    } catch (failure) {
      setLogoError(failure.message)
    }
  }

  const open = async (id) => {
    setLogoError(null)
    setError(null)
    try {
      setShown(await api.get(`/automation/connectors/${encodeURIComponent(id)}`))
    } catch (failure) {
      setError(failure.message)
    }
  }

  const remove = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.del(`/automation/connectors/${encodeURIComponent(removing.id)}`)
      said(`${removing.name} was removed, with its instances.`)
      setRemoving(null)
      setShown(null)
      edit(null)
      load()
    } catch (failure) {
      setRemoving(null)
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  /* ---- instances ---- */
  const toggle = async (instance, enabled) => {
    setError(null)
    // Shown at once; the list read again says what the server kept.
    setInstances((current) => current.map((item) => (item.id === instance.id ? { ...item, enabled } : item)))
    try {
      await api.put(`/automation/instances/${encodeURIComponent(instance.id)}`, { enabled })
      // Not said(): the answer may arrive after another action failed (a test pressed right after
      // the switch), and the error of that one must stay on the screen.
      setNotice(`${instance.name} is ${enabled ? 'on' : 'off'}.`)
    } catch (failure) {
      setError(failure.message)
    }
    load()
  }

  const test = async (instance) => {
    setTesting(instance.id)
    setNotice(null)
    setError(null)
    try {
      const result = await api.post(`/automation/instances/${encodeURIComponent(instance.id)}/test`)
      if (result.ok) setNotice(`${instance.name}: ${result.message}.`)
      else setError(`${instance.name}: ${result.message}`)
      load()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setTesting(null)
    }
  }

  const removeInstance = async () => {
    setError(null)
    setNotice(null)
    try {
      await api.del(`/automation/instances/${encodeURIComponent(deleting.id)}`)
      said(`${deleting.name} was deleted.`)
      edit(null)
      load()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setDeleting(null)
    }
  }

  const lines = problemLines(upload?.problems)

  return (
    <section className="flex flex-col gap-0 lg:flex-row lg:items-start">
      <div className={`min-w-0 flex-1 space-y-5 lg:pr-5 ${wide ? 'hidden' : ''}`}>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <Plug className="h-5 w-5 text-accent" aria-hidden="true" />
              <h2 className="text-base font-semibold text-fg">Connectors</h2>
            </div>
            <p className="mt-1 max-w-prose text-sm text-fg-muted">
              A connector says how to talk to a product; an instance is one system of it, with its address and
              credentials. A connector is enabled, and its commands are offered to playbooks, when one of its instances
              is on.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <input
              ref={fileInput}
              type="file"
              accept=".yml,.yaml,text/yaml,application/x-yaml"
              className="hidden"
              aria-label="Connector file to add"
              onChange={(event) => {
                const file = event.target.files?.[0]
                event.target.value = ''
                if (file) check(file)
              }}
            />
            <a
              href={apiUrl('/automation/connectors/samples')}
              className="inline-flex h-9 items-center gap-2 border border-line px-4 text-sm font-medium text-fg hover:bg-raised focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              <Download className="h-4 w-4" aria-hidden="true" />
              Download the samples
            </a>
            <Button icon={Upload} onClick={() => fileInput.current?.click()}>
              Add a connector file
            </Button>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <SearchInput
            value={query}
            onChange={setQuery}
            label="Find a connector"
            placeholder="Find a connector or an instance"
            className="w-72 max-w-full"
          />
          <div role="group" aria-label="Which connectors" className="flex flex-wrap gap-1">
            {CONNECTOR_FILTERS.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-pressed={filter === item.id}
                onClick={() => setFilter(item.id)}
                className={[
                  'border px-2.5 py-1 text-xs focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                  filter === item.id ? 'border-accent bg-accent text-canvas' : 'border-line text-fg hover:bg-raised',
                ].join(' ')}
              >
                {item.label} · {counts[item.id]}
              </button>
            ))}
          </div>
        </div>

        {error && (
          <p role="alert" className="max-w-3xl border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
            {error}
          </p>
        )}
        {notice && (
          <p
            role="status"
            className="max-w-3xl border border-accent-strong bg-accent-soft px-3 py-2 text-sm text-accent-fg"
          >
            {notice}
          </p>
        )}
        {!connectors && !error && (
          <p role="status" className="font-mono text-sm text-fg-muted">
            Loading…
          </p>
        )}
        {connectors && rows.length === 0 && (
          <EmptyState
            skull
            title={connectors.length === 0 ? 'No connector yet' : 'No connector matches'}
            message={
              connectors.length === 0
                ? 'No connector is installed. A connector comes with a content pack, or as a file added here.'
                : 'No connector matches. Change what you typed, or the filter.'
            }
          />
        )}

        <ul aria-label="Connectors" className="flex max-w-5xl flex-col gap-2.5">
          {rows.map((connector) => (
            <li
              key={connector.id}
              className={`border ${editing?.connector.id === connector.id ? 'border-accent bg-raised/40' : 'border-line'}`}
              onContextMenu={(event) =>
                menu(event, {
                  title: connector.name,
                  actions: [
                    { label: 'Its commands and its file', icon: FileCode2, onSelect: () => open(connector.id) },
                    connector.readable && {
                      label: 'Add instance',
                      icon: Plus,
                      onSelect: () => openForm({ connector, instance: null }),
                    },
                  ],
                  copy: [{ label: 'Copy the id', text: connector.id }],
                })
              }
            >
              <div className="flex flex-wrap items-center gap-x-4 gap-y-2 px-3.5 py-3">
                <LogoSlot connector={connector} />
                <div className="min-w-0 flex-1 basis-64">
                  <p className="flex flex-wrap items-baseline gap-x-2.5">
                    <button
                      type="button"
                      onClick={() => open(connector.id)}
                      title="Its commands and its file"
                      className="text-left text-[15px] font-semibold text-fg hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {connector.name}
                    </button>
                    <span className="font-mono text-[11px] text-fg-muted">
                      v{connector.version}
                      {capabilities(connector) ? ` · ${capabilities(connector)}` : ''}
                    </span>
                  </p>
                  {connector.description && <p className="text-xs text-fg-muted">{connector.description}</p>}
                  <p className="mt-1 flex flex-wrap gap-1 empty:hidden">
                    {connector.builtin && <Badge color="cyan">shipped with Nik</Badge>}
                    {!connector.readable && <Badge color="red">cannot be read</Badge>}
                    {connector.readable && !connector.verified && (
                      <Badge
                        color="amber"
                        title="Written from the vendor’s documentation: nobody ran it against a real system yet"
                      >
                        not verified
                      </Badge>
                    )}
                  </p>
                </div>
                <span className={`font-mono text-xs ${connector.enabled ? 'text-accent-fg' : 'text-fg-muted'}`}>
                  {instancesText(connector.instances)}
                </span>
                <Button
                  variant="secondary"
                  size="sm"
                  icon={Plus}
                  disabled={!connector.readable}
                  aria-label={`Add an instance of ${connector.name}`}
                  onClick={() => openForm({ connector, instance: null })}
                >
                  Add instance
                </Button>
              </div>
              {connector.instances.length > 0 && (
                <ul aria-label={`Instances of ${connector.name}`}>
                  {connector.instances.map((instance) => (
                    <li
                      key={instance.id}
                      className={[
                        'flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-line-soft py-2 pl-3.5 pr-3 text-xs sm:pl-[68px]',
                        editing?.instance?.id === instance.id ? 'bg-accent-soft/40' : '',
                      ].join(' ')}
                      onContextMenu={(event) =>
                        menu(event, {
                          title: instance.name,
                          actions: [
                            {
                              label: 'Edit',
                              icon: Pencil,
                              onSelect: () => openForm({ connector, instance }),
                            },
                            { label: 'Test the instance', icon: Zap, onSelect: () => test(instance) },
                            {
                              label: instance.enabled ? 'Turn off' : 'Turn on',
                              onSelect: () => toggle(instance, !instance.enabled),
                            },
                          ],
                          copy: [
                            { label: 'Copy the name', text: instance.name },
                            { label: 'Copy the host', text: instance.host ?? '' },
                          ],
                          danger: [{ label: 'Delete…', icon: Trash2, onSelect: () => setDeleting(instance) }],
                        })
                      }
                    >
                      <Switch
                        checked={instance.enabled}
                        label={`${instance.name} is ${instance.enabled ? 'on' : 'off'}`}
                        onChange={(next) => toggle(instance, next)}
                      />
                      <span
                        className={`w-48 max-w-full truncate text-sm font-medium ${instance.enabled ? 'text-fg' : 'text-fg-muted'}`}
                      >
                        {instance.name}
                      </span>
                      <span className="min-w-0 flex-1 basis-40 truncate font-mono text-[11px] text-fg-muted">
                        {instance.host ?? '—'}
                      </span>
                      <LastTest test={instance.lastTest} />
                      {instance.fetch?.enabled && (
                        <button
                          type="button"
                          aria-label={`Fetching of ${instance.name}: ${stateBadge(instance.fetch).label}`}
                          title="How it fetches, and how it goes"
                          onClick={() => openForm({ connector, instance, tab: 'fetch' })}
                          className="focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                        >
                          <Badge color={stateBadge(instance.fetch).color}>{stateBadge(instance.fetch).label}</Badge>
                        </button>
                      )}
                      <span className="flex gap-1">
                        <Button
                          waiting={testing === instance.id}
                          variant="secondary"
                          size="xs"
                          icon={Zap}
                          disabled={testing !== null}
                          aria-label={`Test the instance ${instance.name}`}
                          onClick={() => test(instance)}
                        >
                          {testing === instance.id ? 'Testing…' : 'Test'}
                        </Button>
                        <Button
                          variant="ghost"
                          size="xs"
                          icon={Pencil}
                          aria-label={`Edit ${instance.name}`}
                          onClick={() => openForm({ connector, instance })}
                        />
                      </span>
                      {instance.lastTest && !instance.lastTest.ok && (
                        <span className="basis-full text-high-fg sm:pl-11">{instance.lastTest.message}</span>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </li>
          ))}
        </ul>
        <MirrorQueue />
      </div>

      {editing && (
        <InstancePane
          key={editing.instance?.id ?? `new-${editing.connector.id}`}
          connector={editing.connector}
          instance={editing.instance}
          testing={testing !== null}
          tab={editing.tab}
          onTab={(tab) => openForm({ ...editing, tab })}
          wide={wide}
          onClose={() => openForm(null)}
          onTest={test}
          onDelete={setDeleting}
          onChanged={(saved) => {
            // Something of the instance was changed without leaving its form (a secret kept as a credential).
            setEditing((current) => (current?.instance?.id === saved.id ? { ...current, instance: saved } : current))
            load()
          }}
          onSaved={(saved) => {
            edit(null)
            said(`${saved.name} is saved. Test it to see that ${saved.connectorName} answers.`)
            load()
          }}
        />
      )}

      <Modal
        open={upload !== null}
        onClose={() => setUpload(null)}
        title={upload ? `Add ${upload.fileName}` : 'Add a connector'}
        maxWidth="max-w-2xl"
        footer={
          <>
            <Button variant="secondary" onClick={() => setUpload(null)}>
              Cancel
            </Button>
            <Button waiting={busy} disabled={busy || lines.length > 0} onClick={install}>
              {busy ? 'Installing…' : 'Install'}
            </Button>
          </>
        }
      >
        {upload && lines.length > 0 && (
          <div className="flex flex-col gap-2 text-sm">
            <p className="text-fg">
              The file is not a connector yet: {lines.length === 1 ? 'one thing' : `${lines.length} things`} to fix.
              Nothing was installed.
            </p>
            <ol
              aria-label="Problems of the file"
              className="flex max-h-80 flex-col divide-y divide-line-soft overflow-y-auto border border-high-line bg-high-soft"
            >
              {lines.map((line) => (
                <li key={line.key} className="grid grid-cols-[4.5rem_minmax(0,1fr)] gap-2 px-2 py-1.5">
                  <span className="font-mono text-xs text-high-fg">{line.line ? `line ${line.line}` : 'the file'}</span>
                  <span className="min-w-0 break-words text-high-fg">
                    {line.text}
                    {line.where && <span className="block font-mono text-[11px] text-fg-muted">{line.where}</span>}
                  </span>
                </li>
              ))}
            </ol>
          </div>
        )}
        {upload && lines.length === 0 && upload.connector && (
          <div className="flex flex-col gap-2 text-sm">
            <p className="text-fg">
              <span className="font-semibold">{upload.connector.name}</span>{' '}
              <span className="font-mono text-fg-muted">({upload.connector.id})</span>, version{' '}
              {upload.connector.version}: {upload.connector.commands.length} commands. An instance needs{' '}
              {authOf(upload.connector) || 'no credentials'}.
            </p>
            <ul className="flex flex-wrap gap-1">
              {upload.connector.commands.map((command) => (
                <li key={command.name}>
                  <Badge color={command.changesOutside ? 'amber' : 'slate'}>{command.name}</Badge>
                </li>
              ))}
            </ul>
            <p className="text-xs text-fg-muted">
              Installing a file with the id of a connector that is there replaces it. Commands in amber change something
              on the other side and ask for approval by default.
            </p>
          </div>
        )}
      </Modal>

      <Modal
        open={shown !== null}
        onClose={() => setShown(null)}
        title={shown ? shown.name : ''}
        maxWidth="max-w-4xl"
        footer={
          <>
            {shown && (
              <Button variant="secondary" icon={Trash2} onClick={() => setRemoving(shown)}>
                Remove
              </Button>
            )}
            <Button onClick={() => setShown(null)}>Close</Button>
          </>
        }
      >
        {shown && (
          <div className="flex flex-col gap-3 text-sm">
            <p className="text-fg-muted">
              Version {shown.version}
              {shown.apiVersion ? ` · written against ${shown.apiVersion}` : ''} · {shown.instances}{' '}
              {shown.instances === 1 ? 'instance' : 'instances'}
              {shown.usedBy?.length ? ` · used by ${shown.usedBy.join(', ')}` : ' · no playbook uses it'}
            </p>
            {shown.moreHosts?.length > 0 && (
              <p className="text-xs text-fg-muted">
                Beside the address of an instance, its commands reach:{' '}
                <span className="font-mono">{shown.moreHosts.join(', ')}</span>. The credentials of an instance are not
                sent there.
              </p>
            )}
            <div className="flex flex-wrap items-center gap-3">
              <LogoSlot connector={shown} />
              <input
                ref={logoInput}
                type="file"
                accept=".svg,.png,image/svg+xml,image/png"
                className="hidden"
                aria-label={`Logo of ${shown.name}`}
                onChange={(event) => {
                  const file = event.target.files?.[0]
                  event.target.value = ''
                  if (file) setLogo(shown, file)
                }}
              />
              <Button variant="secondary" size="sm" icon={ImageUp} onClick={() => logoInput.current?.click()}>
                {shown.logo ? 'Change the logo' : 'Set a logo'}
              </Button>
              {shown.logo && (
                <Button variant="ghost" size="sm" icon={Trash2} onClick={() => setLogo(shown, null)}>
                  Remove the logo
                </Button>
              )}
              <span className="basis-full text-xs text-fg-muted sm:basis-auto">
                A PNG or an SVG, 256 KB at most. It marks the connector here and the incidents it brings in.
              </span>
              {logoError && (
                <span role="alert" className="basis-full text-xs text-high">
                  {logoError}
                </span>
              )}
            </div>
            {shown.readme && (
              <details open>
                <summary className="cursor-pointer text-sm text-link focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                  README
                </summary>
                <pre
                  aria-label={`README of ${shown.name}`}
                  className="mt-2 max-h-60 overflow-auto whitespace-pre-wrap border border-line bg-sunken p-3 text-xs leading-relaxed text-fg"
                >
                  {shown.readme}
                </pre>
              </details>
            )}
            {shown.commands && (
              <div className="overflow-x-auto border border-line">
                <table className="w-full min-w-[520px] border-collapse text-left text-xs">
                  <caption className="sr-only">Commands of {shown.name}</caption>
                  <thead className="bg-panel font-mono text-fg-muted">
                    <tr>
                      {['Command', 'Takes', 'Gives'].map((heading) => (
                        <th key={heading} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                          {heading}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {shown.commands.map((command) => (
                      <tr key={command.name}>
                        <th scope="row" className="border-b border-line-soft px-3 py-1.5 align-top font-normal">
                          <span className="font-mono text-fg">{command.name}</span>{' '}
                          {command.changesOutside && <Badge color="amber">changes</Badge>}{' '}
                          {command.premium && (
                            <Badge color="violet" title="The vendor gives this command to a paid plan">
                              premium
                            </Badge>
                          )}
                          {command.description && <span className="block text-fg-muted">{command.description}</span>}
                          {can('automation.run') && (
                            <button
                              type="button"
                              aria-label={`Try ${command.name} in the Playground`}
                              onClick={() => {
                                const first = (instances ?? []).find(
                                  (item) => item.connector === shown.id && item.enabled,
                                )
                                leaveLine(tryLine(shown.id, command, first?.name ?? ''))
                                setPath(PLAYGROUND_ROOT)
                              }}
                              className="mt-0.5 text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                            >
                              Try it
                            </button>
                          )}
                        </th>
                        <td className="border-b border-line-soft px-3 py-1.5 align-top font-mono text-fg-muted">
                          {command.arguments
                            .map((argument) => `${argument.name}${argument.required ? '*' : ''}`)
                            .join(', ') || '—'}
                        </td>
                        <td className="border-b border-line-soft px-3 py-1.5 align-top font-mono text-fg-muted">
                          {command.outputs.join(', ') || 'response'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <details>
              <summary className="flex cursor-pointer items-center gap-2 text-sm text-link focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent">
                <FileCode2 className="h-4 w-4" aria-hidden="true" />
                The file
              </summary>
              <pre
                aria-label={`The file of ${shown.name}`}
                className="mt-2 max-h-[45vh] overflow-auto border border-line bg-sunken p-3 font-mono text-xs leading-relaxed text-fg"
              >
                {shown.source}
              </pre>
            </details>
          </div>
        )}
      </Modal>

      <Modal
        open={removing !== null}
        onClose={() => setRemoving(null)}
        title="Remove this connector?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setRemoving(null)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={busy} onClick={remove}>
              Remove
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-semibold">{removing?.name}</span> goes with its instances and their credentials. A
          connector a playbook uses cannot be removed.
          {removing?.builtin ? ' It ships with Nik: it comes back when the server restarts.' : ''}
        </p>
      </Modal>

      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Delete this instance?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={removeInstance}>
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-semibold">{deleting?.name}</span> goes with the credentials typed into it; a stored
          credential it names stays in Settings, Credentials. An instance a playbook uses cannot be deleted; it can be
          turned off.
        </p>
      </Modal>
    </section>
  )
}
