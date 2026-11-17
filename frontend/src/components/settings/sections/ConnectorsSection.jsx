import { useCallback, useEffect, useRef, useState } from 'react'
import { Download, FileCode2, Plug, Trash2, Upload } from 'lucide-react'
import { api, apiUrl } from '../../../services/api.js'
import { authOf, problemLines } from '../../../domain/automation/connections.js'
import { Badge, Button, Modal } from '../../ui/index.js'

/*
 * Automation → Connectors (the role Connectors, or an admin).
 *
 * A connector is one YAML file that says how to talk to a product: what a
 * connection needs and the commands there are. Each command becomes a node
 * of the canvas. Adding a file checks it first: what is wrong is listed with
 * the line it is on, and nothing is installed until the file is right.
 *
 * The connectors Nik ships can be downloaded as the files they are, to read
 * or to start a new one from.
 */

export default function ConnectorsSection() {
  const [connectors, setConnectors] = useState(null)
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [upload, setUpload] = useState(null) // { fileName, source, problems, connector }
  const [shown, setShown] = useState(null) // a connector with its source
  const [removing, setRemoving] = useState(null)
  const [busy, setBusy] = useState(false)
  const fileInput = useRef(null)

  const load = useCallback(async () => {
    try {
      setConnectors((await api.get('/automation/connectors')).connectors)
      // An error on the page is left: it is about what was just asked, and reading the list again is part of it.
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const check = async (file) => {
    setNotice(null)
    setError(null)
    try {
      const source = await file.text()
      const found = await api.post('/automation/connectors/check', { source })
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
      setNotice(
        `${made.name} is installed: version ${made.version}, ${made.commands.length} commands. Make a connection to use it.`,
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

  const open = async (id) => {
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
      setNotice(`${removing.name} was removed, with its connections.`)
      setRemoving(null)
      setShown(null)
      load()
    } catch (failure) {
      setRemoving(null)
      setError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  const lines = problemLines(upload?.problems)

  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <Plug className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-fg">Connectors</h2>
          </div>
          <p className="mt-1 max-w-prose text-sm text-fg-muted">
            A connector is a file that says how to talk to a product: what a connection needs, and commands. Each
            command is a node of the canvas. The file is YAML and holds no code; its format is in the documentation,
            under Automation.
          </p>
        </div>
        <div className="flex gap-2">
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

      {connectors && (
        <div className="max-w-5xl overflow-x-auto border border-line">
          <table className="w-full min-w-[640px] border-collapse text-left text-xs">
            <caption className="sr-only">Installed connectors</caption>
            <thead className="bg-panel font-mono text-fg-muted">
              <tr>
                {['Connector', 'Version', 'Commands', 'Connections', ''].map((heading, index) => (
                  <th
                    key={index}
                    scope="col"
                    className="whitespace-nowrap border-b border-line px-3 py-1.5 font-normal"
                  >
                    {heading || <span className="sr-only">State</span>}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {connectors.length === 0 && (
                <tr>
                  <td colSpan={5} className="px-3 py-4 text-sm text-fg-muted">
                    No connector is installed.
                  </td>
                </tr>
              )}
              {connectors.map((connector) => (
                <tr key={connector.id} className="hover:bg-raised/40">
                  <th scope="row" className="border-b border-line-soft px-3 py-2 align-top font-normal">
                    <button
                      type="button"
                      onClick={() => open(connector.id)}
                      className="text-left text-sm font-medium text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {connector.name}
                    </button>
                    <span className="ml-2 font-mono text-fg-subtle">{connector.id}</span>
                    {connector.description && (
                      <span className="block max-w-md text-fg-muted">{connector.description}</span>
                    )}
                  </th>
                  <td className="border-b border-line-soft px-3 py-2 align-top font-mono">{connector.version}</td>
                  <td className="border-b border-line-soft px-3 py-2 align-top font-mono">
                    {connector.commands?.length ?? '—'}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top font-mono">{connector.connections}</td>
                  <td className="border-b border-line-soft px-3 py-2 align-top">
                    <span className="flex flex-wrap gap-1">
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
                      {connector.connections === 0 && <Badge>no connection</Badge>}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
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
            <Button disabled={busy || lines.length > 0} onClick={install}>
              Install
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
              {upload.connector.version}: {upload.connector.commands.length} commands. A connection needs{' '}
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
              {shown.apiVersion ? ` · written against ${shown.apiVersion}` : ''} · {shown.connections} connections
              {shown.usedBy?.length ? ` · used by ${shown.usedBy.join(', ')}` : ' · no playbook uses it'}
            </p>
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
                          {command.changesOutside && <Badge color="amber">changes</Badge>}
                          {command.description && <span className="block text-fg-muted">{command.description}</span>}
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
          <span className="font-semibold">{removing?.name}</span> goes with its connections and their credentials. A
          connector a playbook uses cannot be removed.
          {removing?.builtin ? ' It ships with Nik: it comes back when the server restarts.' : ''}
        </p>
      </Modal>
    </section>
  )
}
