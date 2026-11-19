import { useState } from 'react'
import { Trash2, X, Zap } from 'lucide-react'
import { api } from '../../../services/api.js'
import { authOf, fieldsOf, formProblem, payloadOf, startingValues } from '../../../domain/automation/connections.js'
import { Button } from '../../ui/index.js'
import ResizeHandle, { useResizablePane } from '../../ui/ResizeHandle.jsx'

/*
 * An instance of a connector, beside the list of connectors: its name, its
 * address and its credentials. The form is built from what the connector asks
 * for. Credentials are kept encrypted and never shown again: a field left
 * empty keeps what is stored.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

/**
 * @param {{
 *   connector: object,
 *   instance: object | null,          // null: a new one
 *   testing?: boolean,
 *   onClose: () => void,
 *   onSaved: (saved: object) => void,
 *   onTest?: (instance: object) => void,
 *   onDelete?: (instance: object) => void,
 * }} props
 */
export default function InstancePane({ connector, instance, testing = false, onClose, onSaved, onTest, onDelete }) {
  const pane = useResizablePane('connectors.instance', { initial: 380, min: 320, max: 640, edge: 'left' })
  const [name, setName] = useState(instance?.name ?? '')
  const [values, setValues] = useState(() => startingValues(connector, instance))
  const [removed, setRemoved] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const fields = fieldsOf(connector)
  const problem = formProblem(connector, name, values)

  const submit = async (event) => {
    event.preventDefault()
    if (problem) return
    setBusy(true)
    setError(null)
    try {
      const body = { name: name.trim(), ...payloadOf(connector, values, removed) }
      const saved = instance
        ? await api.put(`/automation/connections/${encodeURIComponent(instance.id)}`, body)
        : await api.post(`/automation/connectors/${encodeURIComponent(connector.id)}/instances`, body)
      onSaved(saved)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <>
      <ResizeHandle {...pane.handle} label="Resize the instance" className="hidden lg:block" />
      <aside
        aria-label={instance ? `Instance ${instance.name}` : `New instance of ${connector.name}`}
        style={pane.style}
        className="flex w-full shrink-0 flex-col border-t border-line bg-panel lg:sticky lg:top-0 lg:max-h-[calc(100vh-9rem)] lg:w-[var(--pane-w)] lg:self-start lg:border lg:border-line"
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

        <form
          id="form-instance"
          onSubmit={submit}
          className="flex min-h-0 flex-1 flex-col gap-3 overflow-y-auto p-4 text-sm"
        >
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
          {error && (
            <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high">
              {error}
            </p>
          )}
        </form>

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
