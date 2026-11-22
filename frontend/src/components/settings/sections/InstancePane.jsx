import { useCallback, useEffect, useState } from 'react'
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
  hostLines,
} from '../../../domain/automation/instances.js'
import {
  credentialChoices,
  keepable,
  keptKind,
  nameProblem,
  secretMode,
  storedReference,
  suggestedName,
  valueForMode,
} from '../../../domain/automation/credentials.js'
import { fetchChanged, fetchForm, fetchPayload, fetchProblem, mirrorChoiceProblem } from '../../../domain/fetch.js'
import { classifierBody, mapperBodies, mapperKey, unsavedText } from '../../../domain/mappers.js'
import { settingsPath } from '../../../domain/settingsNav.js'
import { setPath } from '../../../lib/location.js'
import { Button, Modal } from '../../ui/index.js'
import ResizeHandle, { useResizablePane } from '../../ui/ResizeHandle.jsx'
import InstanceClassifier from './InstanceClassifier.jsx'
import InstanceFetch from './InstanceFetch.jsx'
import InstanceKeys from './InstanceKeys.jsx'
import InstanceMappers from './InstanceMappers.jsx'
import { instanceFromPath, settingsFromPath } from '../../../domain/settingsNav.js'
import { useUnsavedChanges } from '../../../lib/unsaved.js'
import SecretField from './SecretField.jsx'

/*
 * An instance of a connector, beside the list of connectors: its name, its
 * address and its credentials. The form is built from what the connector asks
 * for. Credentials are kept encrypted and never shown again: a field left
 * empty keeps what is stored. A secret is typed here, or comes from a stored
 * credential (Settings → Credentials): the field then holds the name of the
 * credential, never its value (SecretField.jsx), and a secret that was typed
 * can be kept as a credential without typing it again.
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
 *   onChanged?: (saved: object) => void,  // the instance changed and its form stays open
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
  onChanged = () => {},
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
  // The stored credentials a secret can come from, the way each secret is given where the person chose
  // it ({ field: 'typed' | 'credential' }), and the secret that is being kept as a credential.
  const [credentials, setCredentials] = useState([])
  const [modes, setModes] = useState({})
  const [keeping, setKeeping] = useState(null) // { key, keyName, field, label, kind, name, title, error, busy }
  const secretNames = connector.secrets ?? []
  const loadCredentials = useCallback(() => {
    // Without them the form is the one it always was: every secret is typed.
    api.get('/automation/credentials').then(
      (found) => setCredentials(found.credentials ?? []),
      () => setCredentials([]),
    )
  }, [])
  useEffect(() => {
    loadCredentials()
  }, [loadCredentials])
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
  // Only what Save would send: what a key shows about its stored secrets and credentials is read again
  // from the server (after "Keep as a credential…") and is not a change of the person's.
  const snapshot = JSON.stringify({
    name,
    values,
    removed,
    keys: keys.map((key) => ({ id: key.id, name: key.name, values: key.values })),
    policy,
    fetching,
  })
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
    (fetches ? fetchProblem(fetching, { minInterval: fetchStatus?.minIntervalSeconds, byTime }) : null) ??
    (fetches ? mirrorChoiceProblem(fetching, connector) : null)

  /** Ask under which name the stored secret of a field (of the first key, or of another) is kept. */
  const askKeep = (key, field) =>
    setKeeping({
      key: key.id,
      keyName: key.id === 'main' ? '' : key.name,
      field: field.name,
      label: field.label,
      kind: keptKind(field.name, secretNames, key.secrets, key.credentials),
      name: suggestedName(`${instance.name}${key.id === 'main' ? '' : ` ${key.name}`}`),
      suggested: suggestedName(`${instance.name}${key.id === 'main' ? '' : ` ${key.name}`}`),
      title: '',
      error: null,
      busy: false,
    })
  const keep = async (event) => {
    event.preventDefault()
    setKeeping((current) => ({ ...current, busy: true, error: null }))
    try {
      const saved = await api.post(`/automation/instances/${encodeURIComponent(instance.id)}/credentials`, {
        key: keeping.key,
        field: keeping.field,
        name: keeping.name.trim(),
        title: keeping.title.trim(),
      })
      // What the keys hold is read again; what was typed into the form and is not saved stays.
      setKeys((current) =>
        current.map((key) => {
          const now = saved.keys.find((item) => item.id === key.id)
          return now ? { ...key, secrets: now.secrets, credentials: now.credentials } : key
        }),
      )
      setKeeping(null)
      loadCredentials()
      onChanged(saved)
    } catch (failure) {
      setKeeping((current) => ({ ...current, busy: false, error: failure.message }))
    }
  }
  // The name proposed is not the person's writing; one they changed, or a description, is.
  const keepUnsaved = useUnsavedChanges(
    keeping !== null && (keeping.name !== keeping.suggested || keeping.title.trim() !== ''),
    { what: 'The credential to keep' },
  )
  const keepProblem = keeping
    ? nameProblem(
        keeping.name,
        credentials.map((credential) => credential.name),
      )
    : null

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
      if (fetches && fetchChanged(fetching, connector, instance)) {
        more.fetch = fetchPayload(fetching, { byTime, mirrors: Boolean(connector.mirror) })
      }
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
                if (field.kind === 'secret') {
                  const choices = credentialChoices(credentials, field.name, secretNames)
                  const mode = secretMode({
                    chosen: modes[field.name],
                    typed: values[field.name],
                    stored,
                    reference: storedReference(instance?.credentials, field.name),
                    choices,
                  })
                  const main = { id: 'main', secrets: instance?.secrets, credentials: instance?.credentials }
                  return (
                    <SecretField
                      key={field.name}
                      id={id}
                      label={field.label}
                      field={field.name}
                      masked={field.masked}
                      inputClass={INPUT}
                      value={values[field.name] ?? ''}
                      onValue={(text) => {
                        setValues({ ...values, [field.name]: text })
                        if (gone) setRemoved(removed.filter((item) => item !== field.name))
                      }}
                      onFill={(fills) => {
                        const filled = Object.keys(fills)
                        setValues({ ...values, ...fills })
                        setModes({ ...modes, ...Object.fromEntries(filled.map((name) => [name, 'credential'])) })
                        setRemoved(removed.filter((item) => !filled.includes(item)))
                      }}
                      mode={mode}
                      onMode={(next) => {
                        setModes({ ...modes, [field.name]: next })
                        setValues({ ...values, [field.name]: valueForMode(values[field.name], next) })
                      }}
                      stored={stored}
                      held={instance?.credentials}
                      choices={choices}
                      removed={gone}
                      onRemove={() => setRemoved([...removed, field.name])}
                      onKeep={
                        instance && keepable(stored, instance.credentials, field.name, secretNames)
                          ? () => askKeep(main, field)
                          : undefined
                      }
                      help={field.help}
                    />
                  )
                }
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
                    ) : field.type === 'hosts' ? (
                      // A list of hosts reads better one a line: what is stored with commas is shown so,
                      // and the server takes either.
                      <textarea
                        id={id}
                        rows={4}
                        value={hostLines(values[field.name])}
                        autoComplete="off"
                        spellCheck={false}
                        placeholder={field.placeholder || 'files.vendor.example.com\n*.storage.vendor.example.com'}
                        onChange={(event) => setValues({ ...values, [field.name]: event.target.value })}
                        className={`${INPUT} resize-y`}
                      />
                    ) : (
                      <input
                        id={id}
                        type="text"
                        value={values[field.name] ?? ''}
                        autoComplete="off"
                        spellCheck={false}
                        placeholder={field.type === 'url' ? 'https://…' : field.placeholder}
                        onChange={(event) => setValues({ ...values, [field.name]: event.target.value })}
                        className={INPUT}
                      />
                    )}
                    {field.help && <span className="text-xs text-fg-muted">{field.help}</span>}
                  </div>
                )
              })}
              <p className="text-xs text-fg-muted">
                Credentials are stored encrypted and are never shown again, here or in the API. Every playbook that uses
                this instance may reach its host.
              </p>
              {fields.some((field) => field.kind === 'secret') && (
                <p className="text-xs text-fg-muted">
                  A secret can also be kept once and used by several instances:{' '}
                  <a
                    href={settingsPath('credentials')}
                    onClick={(event) => {
                      event.preventDefault()
                      setPath(settingsPath('credentials'))
                    }}
                    className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    Settings, Credentials
                  </a>
                  . The instance then holds the name of the credential, written{' '}
                  <code className="font-mono">{'{{ credentials.<name> }}'}</code>, and its value is read when a request
                  is sent.
                </p>
              )}
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
              credentials={credentials}
              onKeep={instance ? askKeep : undefined}
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
          <Button
            type="submit"
            form="form-instance"
            waiting={busy}
            disabled={busy || Boolean(problem)}
            title={problem ?? undefined}
          >
            {instance ? 'Save' : 'Create'}
          </Button>
          {instance && onTest && (
            <Button
              waiting={testing}
              variant="secondary"
              icon={Zap}
              disabled={testing}
              onClick={() => onTest(instance)}
            >
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

      <Modal
        open={keeping !== null}
        onClose={() => keepUnsaved.leave(() => setKeeping(null))}
        title="Keep as a credential"
        footer={
          <>
            <Button variant="secondary" onClick={() => setKeeping(null)}>
              Cancel
            </Button>
            <Button
              type="submit"
              form="form-keep-credential"
              waiting={Boolean(keeping?.busy)}
              disabled={Boolean(keepProblem) || keeping?.busy}
            >
              {keeping?.busy ? 'Keeping…' : 'Keep'}
            </Button>
          </>
        }
      >
        {keeping && (
          <form id="form-keep-credential" onSubmit={keep} className="flex flex-col gap-3 text-sm">
            <p className="text-fg">
              {keeping.kind === 'pair'
                ? 'The user name and the password stored in this instance'
                : `The ${keeping.label.toLowerCase()} stored in this instance`}
              {keeping.keyName ? ` (key “${keeping.keyName}”)` : ''} {keeping.kind === 'pair' ? 'are' : 'is'} moved to
              Settings, Credentials under this name, and the instance names the credential from now on. Nothing is typed
              again, and the value is not shown.
            </p>
            <label className="flex flex-col gap-1 text-fg-muted" htmlFor="keep-credential-name">
              Name of the credential
              <input
                id="keep-credential-name"
                type="text"
                value={keeping.name}
                maxLength={40}
                autoComplete="off"
                spellCheck={false}
                onChange={(event) => setKeeping({ ...keeping, name: event.target.value })}
                className={INPUT}
              />
            </label>
            <label className="flex flex-col gap-1 text-fg-muted" htmlFor="keep-credential-title">
              Description
              <input
                id="keep-credential-title"
                type="text"
                value={keeping.title}
                maxLength={200}
                autoComplete="off"
                onChange={(event) => setKeeping({ ...keeping, title: event.target.value })}
                className={INPUT.replace('font-mono ', '')}
              />
            </label>
            {keeping.error && (
              <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high">
                {keeping.error}
              </p>
            )}
            {keepProblem && !keeping.error && <p className="text-xs text-med-fg">{keepProblem}</p>}
          </form>
        )}
      </Modal>
    </>
  )
}
