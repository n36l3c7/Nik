import { useState } from 'react'
import { Trash2, X, Zap } from 'lucide-react'
import { api } from '../../../services/api.js'
import {
  KEY_POLICY_DEFAULTS,
  authOf,
  editableKeys,
  fieldsOf,
  formProblem,
  keysPayload,
  keysProblem,
  newKey,
  payloadOf,
  instanceTabs,
  startingValues,
  takesKeys,
} from '../../../domain/automation/instances.js'
import { fetchChanged, fetchForm, fetchPayload, fetchProblem } from '../../../domain/fetch.js'
import { classifierBody, mapperBodies, mapperKey, unsavedText } from '../../../domain/mappers.js'
import { Button } from '../../ui/index.js'
import ResizeHandle, { useResizablePane } from '../../ui/ResizeHandle.jsx'
import InstanceClassifier from './InstanceClassifier.jsx'
import InstanceFetch from './InstanceFetch.jsx'
import InstanceKeys from './InstanceKeys.jsx'
import InstanceMappers from './InstanceMappers.jsx'
import { instanceFromPath, settingsFromPath } from '../../../domain/settingsNav.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * An instance of a connector, beside the list of connectors: its name, its
 * address and its credentials. The form is built from what the connector asks
 * for. Credentials are kept encrypted and never shown again: a field left
 * empty keeps what is stored.
 *
 * One form and one "Save", in parts that are its tabs: the connection (the
 * name, the address and the credentials); for a connector that signs in, its
 * other keys and how they take turns (InstanceKeys.jsx); for one that can
 * fetch, whether the instance fetches and how (InstanceFetch.jsx), its
 * classifier (InstanceClassifier.jsx) and the mappers of its connector
 * (InstanceMappers.jsx). The form holds what every part edits, so going from
 * one tab to another loses nothing, and "Save" sends everything together.
 * The classifier and the mappers are tables: on their tabs the form takes the
 * width of the page (`wide`: the page puts its list away).
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   connector: object,
 *   instance: object | null,          // null: a new one
 *   testing?: boolean,
 *   tab?: string,                     // the part that is shown (see instanceTabs)
 *   onTab?: (tab: string) => void,
 *   wide?: boolean,                   // the form has the width of the page
 *   onClose: () => void,
 *   onSaved: (saved: object) => void,
 *   onTest?: (instance: object) => void,
 *   onDelete?: (instance: object) => void,
 * }} props
 */
export default function InstancePane({
  connector,
  instance,
  testing = false,
  tab = 'connection',
  onTab = () => {},
  wide = false,
  onClose,
  onSaved,
  onTest,
  onDelete,
}) {
  const pane = useResizablePane('connectors.instance', { initial: 380, min: 320, max: 640, edge: 'left' })
  const tabs = instanceTabs(connector, instance)
  const shown = tabs.some((item) => item.id === tab) ? tab : 'connection'
  const [name, setName] = useState(instance?.name ?? '')
  const [values, setValues] = useState(() => startingValues(connector, instance))
  const [removed, setRemoved] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const fields = fieldsOf(connector)
  const keyed = takesKeys(connector)
  // The keys, the first of which is the credentials above: a new instance starts with that one.
  const [keys, setKeys] = useState(() => {
    const held = editableKeys(instance)
    return held.length ? held : [{ ...newKey(connector, 0), id: 'main', name: 'Key 1', isNew: false, state: 'waiting' }]
  })
  const [policy, setPolicy] = useState(() => ({ ...KEY_POLICY_DEFAULTS, ...(instance?.keyPolicy ?? {}) }))
  // Fetching: what is set (saved with the rest) and how it goes (read again while the form is open).
  const fetches = Boolean(connector.fetch)
  const byTime = connector.fetch?.byTime !== false
  const [fetching, setFetching] = useState(() => fetchForm(connector, instance))
  const [fetchStatus, setFetchStatus] = useState(instance?.fetch ?? null)
  // The classifier and the mappers that were changed and are not saved yet, and the sample they are tried on.
  const [classifierDraft, setClassifierDraft] = useState(null)
  const [mapperDrafts, setMapperDrafts] = useState({})
  const [pasted, setPasted] = useState('')
  const unsaved = unsavedText(classifierDraft, mapperDrafts)
  // Nothing unsaved is lost without asking (lib/unsaved.js): the form as it was opened is what it is
  // compared with. Its parts each have an address, and it stays on screen at all of them.
  const snapshot = JSON.stringify({ name, values, removed, keys, policy, fetching })
  const [opened] = useState(snapshot)
  useUnsavedChanges(snapshot !== opened || Boolean(unsaved), {
    what: instance ? 'The instance' : `The new instance of ${connector.name}`,
    name: instance?.name ?? '',
    save: () => submit(),
    stays: (path) => {
      if (settingsFromPath(path)?.id !== 'connectors') return false
      return (instanceFromPath(path)?.instanceId ?? null) === (instance?.id ?? null)
    },
  })
  const problem =
    formProblem(connector, name, values) ??
    (keyed ? keysProblem(connector, keys, policy) : null) ??
    (fetches ? fetchProblem(fetching, { minInterval: fetchStatus?.minIntervalSeconds, byTime }) : null)

  // Resolves true once everything is saved: the question asked before leaving waits on it.
  const submit = async (event) => {
    event?.preventDefault()
    if (problem) return false
    setBusy(true)
    setError(null)
    try {
      const body = { name: name.trim(), ...payloadOf(connector, values, removed) }
      const more = keyed ? keysPayload(keys, policy) : {}
      // How it fetches is sent when it was changed: an instance nobody touched follows its connector.
      if (fetches && fetchChanged(fetching, connector, instance)) more.fetch = fetchPayload(fetching, { byTime })
      let saved
      if (instance) {
        saved = await api.put(`/automation/instances/${encodeURIComponent(instance.id)}`, { ...body, ...more })
      } else {
        // An instance is made with its credentials, then given the rest: one press, two requests.
        saved = await api.post(`/automation/connectors/${encodeURIComponent(connector.id)}/instances`, body)
        if (Object.keys(more).length) {
          saved = await api.put(`/automation/instances/${encodeURIComponent(saved.id)}`, more)
        }
      }
      // What was typed of a secret is not kept in the form once it is saved, whether or not the form stays open.
      setValues(startingValues(connector, saved))
      setRemoved([])
      if (keyed) setKeys(editableKeys(saved))
      // The classifier of the instance and the mappers of its connector, where they were changed.
      let part = 'the classifier'
      try {
        if (classifierDraft) {
          await api.put(`/classifiers/${encodeURIComponent(saved.id)}`, classifierBody(classifierDraft))
          setClassifierDraft(null)
        }
        let left = mapperDrafts
        for (const mapper of mapperBodies(connector.id, mapperDrafts)) {
          part = `the ${mapper.direction} mapper`
          await api.put('/mappers', mapper)
          const { [mapperKey(mapper.direction, mapper.incidentType)]: _saved, ...rest } = left
          left = rest
          setMapperDrafts(left)
        }
      } catch (failure) {
        setError(`The instance is saved; ${part} is not: ${failure.message}`)
        return false
      }
      onSaved(saved)
      return true
    } catch (failure) {
      setError(failure.message)
      return false
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      {!wide && <ResizeHandle {...pane.handle} label="Resize the instance" className="hidden lg:block" />}
      <aside
        aria-label={instance ? `Instance ${instance.name}` : `New instance of ${connector.name}`}
        style={wide ? undefined : pane.style}
        className={[
          'flex w-full shrink-0 flex-col border-t border-line bg-panel lg:sticky lg:top-0 lg:max-h-[calc(100vh-9rem)] lg:self-start lg:border lg:border-line',
          wide ? 'min-w-0 lg:flex-1' : 'lg:w-[var(--pane-w)]',
        ].join(' ')}
      >
        <div className="flex items-start gap-2 border-b border-line-soft p-4">
          <div className="min-w-0 flex-1">
            <p className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">
              {instance ? 'Instance' : 'New instance'} · {connector.name}
            </p>
            <h3 className="mt-1 break-words text-base font-semibold text-fg">
              {instance ? instance.name : name || '…'}
            </h3>
          </div>
          <button
            type="button"
            aria-label="Close the instance"
            onClick={onClose}
            className="p-1 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            <X className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>

        {tabs.length > 1 && (
          <div
            role="tablist"
            aria-label="Parts of the instance"
            className="flex flex-wrap gap-x-1 border-b border-line-soft px-3"
          >
            {tabs.map((item) => (
              <button
                key={item.id}
                type="button"
                role="tab"
                id={`instance-tab-${item.id}`}
                aria-selected={shown === item.id}
                aria-controls="form-instance"
                onClick={() => onTab(item.id)}
                className={[
                  '-mb-px border-b-2 px-2.5 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent',
                  shown === item.id
                    ? 'border-accent font-medium text-fg'
                    : 'border-transparent text-fg-muted hover:text-fg',
                ].join(' ')}
              >
                {item.label}
              </button>
            ))}
          </div>
        )}

        <form
          id="form-instance"
          role={tabs.length > 1 ? 'tabpanel' : undefined}
          aria-labelledby={tabs.length > 1 ? `instance-tab-${shown}` : undefined}
          onSubmit={submit}
          className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4 text-sm"
        >
          {shown === 'connection' && (
            <>
              <label className="flex flex-col gap-1 text-fg-muted" htmlFor="instance-name">
                Name
                <input
                  id="instance-name"
                  type="text"
                  value={name}
                  maxLength={80}
                  autoComplete="off"
                  placeholder={`${connector.name} production`}
                  onChange={(event) => setName(event.target.value)}
                  className={INPUT}
                />
                <span className="text-xs">
                  How nodes name it. Renaming it later means choosing it again on the nodes that use it.
                </span>
              </label>

              <p className="text-xs text-fg-muted">
                {connector.name} signs in with {authOf(connector) || 'no credentials'}.
              </p>
              {fields.map((field) => {
                const id = `instance-field-${field.name}`
                const stored = field.kind === 'secret' && Boolean(instance?.secrets?.[field.name])
                const gone = removed.includes(field.name)
                return (
                  <div key={field.name} className="flex flex-col gap-1">
                    <label className="text-fg-muted" htmlFor={id}>
                      {field.label}
                      {field.required && (
                        <span className="text-med" title="Required">
                          {' '}
                          *
                        </span>
                      )}
                      {stored && !gone && <span className="ml-2 font-mono text-[11px] text-accent-fg">stored</span>}
                      {gone && <span className="ml-2 font-mono text-[11px] text-high-fg">will be removed</span>}
                    </label>
                    {field.type === 'bool' ? (
                      <input
                        id={id}
                        type="checkbox"
                        checked={Boolean(values[field.name])}
                        onChange={(event) => setValues({ ...values, [field.name]: event.target.checked })}
                        className="h-4 w-4 accent-accent"
                      />
                    ) : field.type === 'choice' ? (
                      <select
                        id={id}
                        value={values[field.name] ?? ''}
                        onChange={(event) => setValues({ ...values, [field.name]: event.target.value })}
                        className={`${INPUT} cursor-pointer`}
                      >
                        <option value="">{field.placeholder ? `(default: ${field.placeholder})` : '(not set)'}</option>
                        {field.choices.map((choice) => (
                          <option key={choice} value={choice}>
                            {choice}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <div className="flex gap-2">
                        <input
                          id={id}
                          type={field.masked ? 'password' : 'text'}
                          value={values[field.name] ?? ''}
                          autoComplete={field.masked ? 'new-password' : 'off'}
                          spellCheck={false}
                          placeholder={
                            field.kind === 'secret'
                              ? stored && !gone
                                ? 'stored: type to replace it'
                                : ''
                              : field.type === 'url'
                                ? 'https://…'
                                : field.placeholder
                          }
                          onChange={(event) => {
                            setValues({ ...values, [field.name]: event.target.value })
                            if (gone) setRemoved(removed.filter((item) => item !== field.name))
                          }}
                          className={INPUT}
                        />
                        {stored && !gone && (
                          <Button
                            variant="secondary"
                            size="sm"
                            aria-label={`Remove the stored ${field.label.toLowerCase()}`}
                            onClick={() => setRemoved([...removed, field.name])}
                          >
                            Remove
                          </Button>
                        )}
                      </div>
                    )}
                    {field.help && <span className="text-xs text-fg-muted">{field.help}</span>}
                  </div>
                )
              })}
              <p className="text-xs text-fg-muted">
                Credentials are stored encrypted and are never shown again, here or in the API. Every playbook that uses
                this instance may reach its host.
              </p>
            </>
          )}
          {shown === 'keys' && keyed && (
            <InstanceKeys
              connector={connector}
              instance={instance}
              keys={keys}
              onKeys={setKeys}
              policy={policy}
              onPolicy={setPolicy}
            />
          )}
          {shown === 'fetch' && (
            <InstanceFetch
              connector={connector}
              instance={instance}
              form={fetching}
              onForm={setFetching}
              status={fetchStatus}
              onStatus={setFetchStatus}
            />
          )}
          {shown === 'classifier' && (
            <InstanceClassifier
              connector={connector}
              instance={instance}
              draft={classifierDraft}
              onDraft={setClassifierDraft}
              pasted={pasted}
              onPasted={setPasted}
            />
          )}
          {shown === 'mappers' && (
            <InstanceMappers
              connector={connector}
              instance={instance}
              drafts={mapperDrafts}
              onDrafts={setMapperDrafts}
              pasted={pasted}
              onPasted={setPasted}
            />
          )}
        </form>

        {(error || problem || unsaved) && (
          <div className="flex flex-col gap-1 border-t border-line-soft px-4 pt-3 text-sm">
            {error && (
              <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high">
                {error}
              </p>
            )}
            {problem && <p className="text-xs text-med-fg">{problem}</p>}
            {unsaved && !problem && <p className="text-xs text-fg-muted">Not saved yet: {unsaved}.</p>}
          </div>
        )}
        <div className="flex flex-wrap items-center gap-2 border-t border-line-soft p-4">
          <Button type="submit" form="form-instance" disabled={busy || Boolean(problem)} title={problem ?? undefined}>
            {instance ? 'Save' : 'Create'}
          </Button>
          {instance && onTest && (
            <Button variant="secondary" icon={Zap} disabled={testing} onClick={() => onTest(instance)}>
              {testing ? 'Testing…' : 'Test the connection'}
            </Button>
          )}
          <span className="flex-1" />
          {instance && onDelete && (
            <Button variant="ghost" icon={Trash2} onClick={() => onDelete(instance)}>
              Delete
            </Button>
          )}
        </div>
      </aside>
    </>
  )
}
