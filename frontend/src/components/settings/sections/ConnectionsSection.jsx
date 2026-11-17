import { useCallback, useEffect, useState } from 'react'
import { Cable, Pencil, Plus, Trash2, Zap } from 'lucide-react'
import { api } from '../../../services/api.js'
import { authOf, fieldsOf, formProblem, payloadOf, startingValues } from '../../../domain/automation/connections.js'
import { formatRelative } from '../../../lib/time.js'
import { Badge, Button, Modal } from '../../ui/index.js'

/*
 * Automation → Connections (the role Connectors, or an admin).
 *
 * A connection is a connector plus an address and credentials: one system
 * playbooks can talk to. The form is built from what the connector asks
 * for. Credentials are kept encrypted and never shown again: a field left
 * empty keeps what is stored. Making a connection lets every playbook that
 * uses it reach its host.
 *
 * "Test" sends the connector's own test request to that host, and nothing
 * else.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

function ConnectionForm({ connectors, connection, onClose, onSaved }) {
  const [connectorId, setConnectorId] = useState(connection?.connector ?? connectors[0]?.id ?? '')
  const connector = connectors.find((item) => item.id === connectorId) ?? null
  const [name, setName] = useState(connection?.name ?? '')
  const [values, setValues] = useState(() => startingValues(connector, connection))
  const [removed, setRemoved] = useState([])
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const fields = fieldsOf(connector)

  const choose = (id) => {
    setConnectorId(id)
    setValues(startingValues(connectors.find((item) => item.id === id) ?? null, null))
    setRemoved([])
  }

  const problem = connector ? formProblem(connector, name, values) : 'Install a connector first'
  const submit = async (event) => {
    event.preventDefault()
    if (problem) return
    setBusy(true)
    setError(null)
    try {
      const body = payloadOf(connector, values, removed)
      const saved = connection
        ? await api.put(`/automation/connections/${encodeURIComponent(connection.id)}`, { name: name.trim(), ...body })
        : await api.post('/automation/connections', { name: name.trim(), connector: connector.id, ...body })
      onSaved(saved)
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={connection ? `Connection: ${connection.name}` : 'New connection'}
      maxWidth="max-w-xl"
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-connection" disabled={busy || Boolean(problem)} title={problem ?? undefined}>
            {connection ? 'Save' : 'Create'}
          </Button>
        </>
      }
    >
      <form id="form-connection" onSubmit={submit} className="flex flex-col gap-3 text-sm">
        <label className="flex flex-col gap-1 text-fg-muted" htmlFor="connection-connector">
          Connector
          <select
            id="connection-connector"
            value={connectorId}
            disabled={Boolean(connection)}
            onChange={(event) => choose(event.target.value)}
            className={`${INPUT} cursor-pointer disabled:opacity-60`}
          >
            {connectors.map((item) => (
              <option key={item.id} value={item.id}>
                {item.name}
              </option>
            ))}
          </select>
        </label>
        <label className="flex flex-col gap-1 text-fg-muted" htmlFor="connection-name">
          Name
          <input
            id="connection-name"
            type="text"
            value={name}
            maxLength={80}
            autoComplete="off"
            placeholder={connector ? `${connector.name} production` : ''}
            onChange={(event) => setName(event.target.value)}
            className={INPUT}
          />
          <span className="text-xs">
            How nodes name it. Renaming it later means choosing it again on the nodes that use it.
          </span>
        </label>

        {connector && (
          <p className="text-xs text-fg-muted">
            {connector.name} signs in with {authOf(connector) || 'no credentials'}.
          </p>
        )}
        {fields.map((field) => {
          const id = `connection-field-${field.name}`
          const stored = field.kind === 'secret' && Boolean(connection?.secrets?.[field.name])
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
          Credentials are stored encrypted and are never shown again, here or in the API. Every playbook that uses this
          connection may reach its host.
        </p>
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high">
            {error}
          </p>
        )}
      </form>
    </Modal>
  )
}

export default function ConnectionsSection() {
  const [connectors, setConnectors] = useState(null)
  const [connections, setConnections] = useState(null)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [editing, setEditing] = useState(null) // null | 'new' | a connection
  const [deleting, setDeleting] = useState(null)
  const [testing, setTesting] = useState(null)

  const load = useCallback(async () => {
    try {
      const [first, second] = await Promise.all([api.get('/automation/connectors'), api.get('/automation/connections')])
      setConnectors(first.connectors.filter((connector) => connector.readable))
      setConnections(second.connections)
      // An error on the page is left: it is about what was just asked, and reading the list again is part of it.
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const test = async (connection) => {
    setTesting(connection.id)
    setNotice(null)
    setError(null)
    try {
      const result = await api.post(`/automation/connections/${encodeURIComponent(connection.id)}/test`)
      if (result.ok) setNotice(`${connection.name}: ${result.message}.`)
      else setError(`${connection.name}: ${result.message}`)
      load()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setTesting(null)
    }
  }

  const remove = async () => {
    setError(null)
    setNotice(null)
    try {
      await api.del(`/automation/connections/${encodeURIComponent(deleting.id)}`)
      setNotice(`${deleting.name} was deleted.`)
      load()
    } catch (failure) {
      setError(failure.message)
    } finally {
      setDeleting(null)
    }
  }

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Cable className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-fg">Connections</h2>
          </div>
          <p className="mt-1 max-w-prose text-sm text-fg-muted">
            A connection is a connector plus an address and credentials: one system playbooks can talk to. A node of a
            connector names the connection it sends through.
          </p>
        </div>
        <Button icon={Plus} disabled={!connectors?.length} onClick={() => setEditing('new')}>
          New connection
        </Button>
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
      {!connections && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading…
        </p>
      )}
      {connectors?.length === 0 && (
        <p className="text-sm text-fg-muted">No connector is installed: add one under Connectors first.</p>
      )}

      {connections && (
        <div className="max-w-5xl overflow-x-auto border border-line">
          <table className="w-full min-w-[720px] border-collapse text-left text-xs">
            <caption className="sr-only">Connections</caption>
            <thead className="bg-panel font-mono text-fg-muted">
              <tr>
                {['Connection', 'Connector', 'Host', 'Last test', ''].map((heading, index) => (
                  <th
                    key={index}
                    scope="col"
                    className="whitespace-nowrap border-b border-line px-3 py-1.5 font-normal"
                  >
                    {heading || <span className="sr-only">Actions</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {connections.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-sm text-fg-muted">
                    No connection yet.
                  </td>
                </tr>
              )}
              {connections.map((connection) => (
                <tr key={connection.id} className="hover:bg-raised/40">
                  <th scope="row" className="border-b border-line-soft px-3 py-2 align-top text-sm font-medium text-fg">
                    {connection.name}
                  </th>
                  <td className="border-b border-line-soft px-3 py-2 align-top text-fg-muted">
                    {connection.connectorName}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top font-mono text-fg-muted">
                    {connection.host ?? '—'}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top">
                    {connection.lastTest ? (
                      <span className="flex flex-wrap items-center gap-2">
                        <Badge color={connection.lastTest.ok ? 'emerald' : 'red'}>
                          {connection.lastTest.ok ? 'ok' : connection.lastTest.status || 'failed'}
                        </Badge>
                        <span className="text-fg-muted">{formatRelative(connection.lastTest.at)}</span>
                        {!connection.lastTest.ok && (
                          <span className="basis-full text-high-fg">{connection.lastTest.message}</span>
                        )}
                      </span>
                    ) : (
                      <span className="text-fg-muted">not tested</span>
                    )}
                  </td>
                  <td className="border-b border-line-soft px-3 py-1.5 align-top">
                    <span className="flex justify-end gap-1">
                      <Button
                        variant="secondary"
                        size="xs"
                        icon={Zap}
                        disabled={testing !== null}
                        aria-label={`Test the connection ${connection.name}`}
                        onClick={() => test(connection)}
                      >
                        {testing === connection.id ? 'Testing…' : 'Test'}
                      </Button>
                      <Button
                        variant="ghost"
                        size="xs"
                        icon={Pencil}
                        aria-label={`Edit ${connection.name}`}
                        onClick={() => setEditing(connection)}
                      />
                      <Button
                        variant="ghost"
                        size="xs"
                        icon={Trash2}
                        aria-label={`Delete ${connection.name}`}
                        onClick={() => setDeleting(connection)}
                      />
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editing !== null && connectors && (
        <ConnectionForm
          key={editing === 'new' ? 'new' : editing.id}
          connectors={connectors}
          connection={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(saved) => {
            setEditing(null)
            setNotice(`${saved.name} is saved. Test it to see that ${saved.connectorName} answers.`)
            load()
          }}
        />
      )}

      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Delete this connection?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleting(null)}>
              Cancel
            </Button>
            <Button variant="danger" onClick={remove}>
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-semibold">{deleting?.name}</span> goes with its credentials. A connection a playbook
          uses cannot be deleted.
        </p>
      </Modal>
    </section>
  )
}
