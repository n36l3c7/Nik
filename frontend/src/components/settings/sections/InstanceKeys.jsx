import { useState } from 'react'
import { ArrowDown, ArrowUp, Plus, Trash2, Zap } from 'lucide-react'
import { api } from '../../../services/api.js'
import {
  credentialChoices,
  keepable,
  secretMode,
  storedReference,
  valueForMode,
} from '../../../domain/automation/credentials.js'
import { KEY_MODES, keyFields, keyShare, keyUse, newKey } from '../../../domain/automation/instances.js'
import { Badge, Button } from '../../ui/index.js'
import SecretField from './SecretField.jsx'

/*
 * The keys of an instance (6.1): more credentials than one for the same
 * product, and how they take turns. The first key is the credentials of the
 * instance, edited on its Connection tab; the others are added, named, ordered and removed
 * here. A key is never shown again after it is saved. Each part of a key is
 * typed, or comes from a stored credential (SecretField.jsx), as the
 * credentials of the Connection tab do.
 *
 * It is a part of the form of the instance (InstancePane.jsx), which holds
 * what is edited here and saves it with everything else: there is one "Save".
 * Only what is not a change of the instance is done from here: testing every
 * key, and forgetting the answers that are kept.
 *
 * Below the keys: how they take turns, the limits each is held to, what a
 * command does when every key is used up, and whether the instance keeps the
 * answers of the commands that change nothing outside.
 */

const INPUT =
  'w-full border border-line bg-canvas px-2 py-1 font-mono text-xs text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'
const STATE_COLOR = { 'in use': 'emerald', 'used up': 'amber', waiting: 'slate', new: 'cyan' }

/**
 * @param {{
 *   connector: object,
 *   instance: object | null,              // null: an instance that is being made (nothing to test yet)
 *   keys: object[],                       // as `editableKeys` gives them, edited here
 *   onKeys: (keys: object[]) => void,
 *   policy: object,
 *   onPolicy: (policy: object) => void,
 *   credentials?: object[],               // the stored credentials a part of a key can come from
 *   onKeep?: (key: object, field: object) => void,  // keep a stored part of a key as a credential
 * }} props
 */
export default function InstanceKeys({
  connector,
  instance,
  keys,
  onKeys: setKeys,
  policy,
  onPolicy: setPolicy,
  credentials = [],
  onKeep,
}) {
  const [busy, setBusy] = useState('')
  const [error, setError] = useState(null)
  const [said, setSaid] = useState('')
  const [tested, setTested] = useState(null) // id → { ok, message }
  const fields = keyFields(connector)
  const secretNames = fields.map((field) => field.name)
  const path = instance ? `/automation/instances/${encodeURIComponent(instance.id)}` : null

  const change = (index, patch) => setKeys(keys.map((key, at) => (at === index ? { ...key, ...patch } : key)))
  const move = (index, by) => {
    const next = [...keys]
    const [taken] = next.splice(index, 1)
    next.splice(index + by, 0, taken)
    setKeys(next)
  }
  const run = (name, work, done) => {
    setBusy(name)
    setError(null)
    setSaid('')
    work()
      .then(done, (failure) => setError(failure.message))
      .finally(() => setBusy(''))
  }
  const test = () =>
    run(
      'test',
      () => api.post(`${path}/keys/test`),
      (found) => {
        setTested(Object.fromEntries(found.keys.map((key) => [key.id, key])))
        const bad = found.keys.filter((key) => !key.ok).length
        setSaid(bad ? `${bad} of ${found.keys.length} keys did not pass.` : `Every key passed (${found.keys.length}).`)
      },
    )
  const forget = () =>
    run(
      'forget',
      () => api.del(`${path}/answers`),
      (done) => setSaid(`${done?.forgotten ?? 0} kept answers were forgotten.`),
    )

  return (
    <section aria-label="Keys" className="flex flex-col gap-3 border-t border-line-soft pt-3 text-sm">
      <div className="flex items-center gap-2">
        <h4 className="flex-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">Keys</h4>
        <Button
          size="xs"
          variant="secondary"
          icon={Plus}
          disabled={keys.length >= 20}
          onClick={() => setKeys([...keys, newKey(connector, keys.length)])}
        >
          Add a key
        </Button>
      </div>
      <ul aria-label="The keys of the instance" className="flex flex-col gap-2">
        {keys.map((key, index) => {
          const first = index === 0
          const share = keyShare(key, policy)
          const result = tested?.[key.id]
          return (
            <li key={key.id || `new-${index}`} className="flex flex-col gap-1.5 border border-line bg-canvas p-2">
              <div className="flex items-center gap-2">
                <input
                  type="text"
                  value={key.name}
                  maxLength={60}
                  aria-label={`Name of key ${index + 1}`}
                  onChange={(event) => change(index, { name: event.target.value })}
                  className={`${INPUT} flex-1`}
                />
                <Badge color={STATE_COLOR[key.state] ?? 'slate'} title={key.freeAt ? `Back at ${key.freeAt}` : ''}>
                  {key.state}
                </Badge>
                {!first && (
                  <>
                    <Button
                      size="xs"
                      variant="ghost"
                      icon={ArrowUp}
                      disabled={index === 1}
                      aria-label={`Move ${key.name} up`}
                      onClick={() => move(index, -1)}
                    />
                    <Button
                      size="xs"
                      variant="ghost"
                      icon={ArrowDown}
                      disabled={index === keys.length - 1}
                      aria-label={`Move ${key.name} down`}
                      onClick={() => move(index, 1)}
                    />
                    <Button
                      size="xs"
                      variant="ghost"
                      icon={Trash2}
                      aria-label={`Remove ${key.name}`}
                      onClick={() => setKeys(keys.filter((_, at) => at !== index))}
                    />
                  </>
                )}
              </div>
              {first ? (
                <p className="text-xs text-fg-muted">The credentials of the instance, set on the Connection tab.</p>
              ) : (
                fields.map((field) => {
                  const choices = credentialChoices(credentials, field.name, secretNames)
                  const stored = Boolean(key.secrets?.[field.name])
                  const typed = key.values?.[field.name] ?? ''
                  const mode = secretMode({
                    chosen: key.modes?.[field.name],
                    typed,
                    stored,
                    reference: storedReference(key.credentials, field.name),
                    choices,
                  })
                  return (
                    <div key={field.name} className="text-xs">
                      <SecretField
                        id={`key-${index}-${field.name}`}
                        label={field.label}
                        field={field.name}
                        masked={field.masked}
                        inputClass={INPUT}
                        value={typed}
                        onValue={(text) => change(index, { values: { ...key.values, [field.name]: text } })}
                        onFill={(fills) =>
                          change(index, {
                            values: { ...key.values, ...fills },
                            modes: {
                              ...key.modes,
                              ...Object.fromEntries(Object.keys(fills).map((name) => [name, 'credential'])),
                            },
                          })
                        }
                        mode={mode}
                        onMode={(next) =>
                          change(index, {
                            modes: { ...key.modes, [field.name]: next },
                            values: { ...key.values, [field.name]: valueForMode(typed, next) },
                          })
                        }
                        stored={stored}
                        held={key.credentials}
                        choices={choices}
                        onKeep={
                          onKeep && key.id && keepable(stored, key.credentials, field.name, secretNames)
                            ? () => onKeep(key, field)
                            : undefined
                        }
                      />
                    </div>
                  )
                })
              )}
              {!key.isNew && (
                <div className="flex items-center gap-2 text-xs text-fg-muted">
                  {Number(policy.perDay) > 0 && (
                    <span aria-hidden="true" className="h-1.5 w-24 bg-line-soft">
                      <span className="block h-1.5 bg-info" style={{ width: `${Math.round(share * 100)}%` }} />
                    </span>
                  )}
                  <span className="font-mono">{keyUse(key, policy)}</span>
                  <span>today</span>
                  {result && (
                    <span className={result.ok ? 'text-accent-fg' : 'text-high-fg'}>
                      · test {result.ok ? 'passed' : `failed: ${result.message || result.status}`}
                    </span>
                  )}
                </div>
              )}
            </li>
          )
        })}
      </ul>
      <p className="text-xs text-fg-muted">
        Keys are tried in this order. A key is never shown again after it is saved.
      </p>

      <fieldset className="flex flex-col gap-2">
        <legend className="mb-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          How the keys take turns
        </legend>
        {KEY_MODES.map((mode) => (
          <label key={mode.id} className="flex items-start gap-2 text-fg">
            <input
              type="radio"
              name="key-mode"
              checked={policy.mode === mode.id}
              onChange={() => setPolicy({ ...policy, mode: mode.id })}
              className="mt-1 accent-accent"
            />
            <span>
              {mode.label}
              <span className="block text-xs text-fg-muted">{mode.hint}</span>
            </span>
          </label>
        ))}
      </fieldset>

      <fieldset className="grid grid-cols-2 gap-2">
        <legend className="mb-1 font-mono text-[11px] uppercase tracking-wider text-fg-muted">
          Limits, for each key
        </legend>
        <label className="flex flex-col gap-0.5 text-xs text-fg-muted">
          Requests a minute
          <input
            type="number"
            min="0"
            value={policy.perMinute}
            onChange={(event) => setPolicy({ ...policy, perMinute: event.target.value })}
            className={INPUT}
          />
        </label>
        <label className="flex flex-col gap-0.5 text-xs text-fg-muted">
          Requests a day
          <input
            type="number"
            min="0"
            value={policy.perDay}
            onChange={(event) => setPolicy({ ...policy, perDay: event.target.value })}
            className={INPUT}
          />
        </label>
        <label className="col-span-2 flex flex-col gap-0.5 text-xs text-fg-muted">
          When every key is used up
          <select
            value={policy.whenExhausted}
            onChange={(event) => setPolicy({ ...policy, whenExhausted: event.target.value })}
            className={`${INPUT} cursor-pointer`}
          >
            <option value="wait">Wait for the first key to come back</option>
            <option value="fail">Fail the command</option>
          </select>
        </label>
        <label className="col-span-2 flex flex-col gap-0.5 text-xs text-fg-muted">
          Keep an answer for this many hours
          <input
            type="number"
            min="0"
            value={policy.cacheHours}
            onChange={(event) => setPolicy({ ...policy, cacheHours: event.target.value })}
            className={INPUT}
          />
          <span>
            0 keeps none. A kept answer is given back without a request; only of commands that change nothing outside.
          </span>
        </label>
      </fieldset>

      <p role="status" className={said ? 'text-xs text-accent-fg' : 'sr-only'}>
        {said}
      </p>
      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high">
          {error}
        </p>
      )}
      {instance && (
        <div className="flex flex-wrap items-center gap-2">
          <Button
            waiting={busy === 'test'}
            size="sm"
            variant="secondary"
            icon={Zap}
            disabled={Boolean(busy)}
            title="Sends the connector's test request with each key as it is saved: save a new key first"
            onClick={test}
          >
            {busy === 'test' ? 'Testing…' : 'Test every key'}
          </Button>
          {Number(instance.keyPolicy?.cacheHours) > 0 && (
            <Button size="sm" variant="ghost" disabled={Boolean(busy)} onClick={forget}>
              Forget the kept answers
            </Button>
          )}
        </div>
      )}
    </section>
  )
}
