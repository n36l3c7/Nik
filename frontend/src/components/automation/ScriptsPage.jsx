import { useCallback, useEffect, useRef, useState } from 'react'
import { FolderOpen, Plus, Trash2, Upload } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { nameProblem } from '../../domain/automation/scripts.js'
import { formatRelative } from '../../lib/time.js'
import { Badge, Button, EmptyState, Modal } from '../ui/index.js'
import { Field, TextInput } from './fields.jsx'
import { useObjectMenu } from '../menu/useObjectMenu.js'
import { usePageMenu } from '../menu/usePageMenu.js'
import { automationPath } from '../../domain/automationNav.js'
import { useUnsavedChanges } from '../../lib/unsaved.js'
import { transfer } from '../../lib/transfers.js'

/*
 * The scripts: a library of Python blocks with named arguments and outputs,
 * each a node of the canvas once a version of it is saved. A script still
 * being written is a draft: it is here, and not yet in the library of nodes.
 */

/** What every script runs in, said where scripts are written. */
export function SandboxBox({ available }) {
  return (
    <section
      aria-label="The box every script runs in"
      className="flex flex-col gap-2 border border-line bg-panel p-4 text-sm"
    >
      <h3 className="font-mono text-[11px] uppercase tracking-wider text-fg-muted">The box every script runs in</h3>
      {!available && (
        <p role="alert" className="border border-med-line bg-med-soft px-2 py-1.5 text-med-fg">
          The sandbox is not configured on this server (SANDBOX_URL): scripts cannot be tested, saved as versions or
          run.
        </p>
      )}
      <ul className="flex list-disc flex-col gap-1 pl-5 text-fg-muted">
        <li>No network, whatever the playbook that uses it may reach.</li>
        <li>No secrets, no database, no files of Nik: only the arguments its node gives it.</li>
        <li>A container of its own, a new process each time, a read-only filesystem, not root.</li>
        <li>10 seconds, 256 MB of memory, 1 MB of result; the standard library of Python 3.12 only.</li>
        <li>Each version is in the audit log with what changed in the code.</li>
      </ul>
    </section>
  )
}

/**
 * @param {{ onOpen: (id: string) => void }} props
 */
export default function ScriptsPage({ onOpen }) {
  const { showToast } = useToast()
  const menu = useObjectMenu()
  const [found, setFound] = useState(null) // { scripts, sandbox }
  const [error, setError] = useState(null)
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [createError, setCreateError] = useState(null)
  const [busy, setBusy] = useState(false)
  const fileInput = useRef(null)
  const { can } = useAuth()
  const canEdit = can('automation.edit')
  const [deleting, setDeleting] = useState(null)

  const load = useCallback(async () => {
    try {
      setFound(await api.get('/automation/scripts'))
      setError(null)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])

  const remove = async () => {
    const gone = deleting
    setDeleting(null)
    try {
      await api.del(`/automation/scripts/${encodeURIComponent(gone.id)}`)
      showToast({ message: `${gone.name} was deleted.` })
      load()
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  const wrongName = name ? nameProblem(name) : null
  const creating = useUnsavedChanges(createOpen && Boolean(name.trim() || description.trim()), {
    what: 'The new script',
  })
  const create = async (event) => {
    event.preventDefault()
    if (nameProblem(name)) return
    setBusy(true)
    setCreateError(null)
    try {
      const made = await api.post('/automation/scripts', { name: name.trim(), description })
      setCreateOpen(false)
      setName('')
      setDescription('')
      onOpen(made.id)
    } catch (failure) {
      setCreateError(failure.message)
    } finally {
      setBusy(false)
    }
  }

  const importFile = async (file) => {
    try {
      const parsed = JSON.parse(await file.text())
      if (parsed?.type !== 'script' || !parsed.script) throw new Error('Not a script file')
      const made = await transfer(`Importing ${file.name}`, () =>
        api.post('/automation/scripts/import', { script: parsed.script }),
      )
      showToast({ message: `${made.name} was imported as a draft: it enters the library when its test passes here.` })
      onOpen(made.id)
    } catch (failure) {
      showToast({ message: `${file.name}: ${failure instanceof SyntaxError ? 'not a JSON file' : failure.message}` })
    }
  }

  const pageMenu = usePageMenu(() => [{ label: 'New script…', icon: Plus, onSelect: () => setCreateOpen(true) }])

  return (
    <div className="flex flex-col gap-4 p-6" onContextMenu={pageMenu}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-prose text-sm text-fg-muted">
          A script is a piece of Python written once, with named arguments and outputs, and used as a node in any
          playbook. A playbook keeps the version of a script it was saved with until someone updates the node.
        </p>
        <div className="flex gap-2">
          <input
            ref={fileInput}
            type="file"
            accept=".json,application/json"
            className="hidden"
            aria-label="Script file to import"
            onChange={(event) => {
              const file = event.target.files?.[0]
              event.target.value = ''
              if (file) importFile(file)
            }}
          />
          <Button variant="secondary" size="sm" icon={Upload} onClick={() => fileInput.current?.click()}>
            Import
          </Button>
          <Button size="sm" icon={Plus} onClick={() => setCreateOpen(true)}>
            New script
          </Button>
        </div>
      </div>

      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {!found && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the scripts…
        </p>
      )}

      {found && (
        <div className="grid gap-4 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
          <div className="overflow-x-auto border border-line">
            <table className="w-full min-w-[560px] border-collapse text-left text-xs">
              <caption className="sr-only">Scripts</caption>
              <thead className="bg-panel font-mono text-fg-muted">
                <tr>
                  {['Script', 'Version', 'State', 'Changed'].map((heading) => (
                    <th
                      key={heading}
                      scope="col"
                      className="whitespace-nowrap border-b border-line px-3 py-1.5 font-normal"
                    >
                      {heading}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {found.scripts.length === 0 && (
                  <tr>
                    <td colSpan={4} className="p-3">
                      <EmptyState
                        skull
                        title="No script yet"
                        message="A script is Python a playbook runs as a node: it enters the library when its test passes."
                      />
                    </td>
                  </tr>
                )}
                {found.scripts.map((script) => (
                  <tr
                    key={script.id}
                    className="hover:bg-raised/40"
                    onContextMenu={(event) =>
                      menu(event, {
                        title: script.name,
                        actions: [{ label: 'Open', icon: FolderOpen, onSelect: () => onOpen(script.id) }],
                        link: automationPath('scripts', script.id),
                        copy: [{ label: 'Copy the name', text: script.name }],
                        danger: canEdit
                          ? [{ label: 'Delete…', icon: Trash2, onSelect: () => setDeleting(script) }]
                          : [],
                      })
                    }
                  >
                    <th scope="row" className="border-b border-line-soft px-3 py-2 align-top font-normal">
                      <button
                        type="button"
                        onClick={() => onOpen(script.id)}
                        className="text-left font-mono text-sm font-medium text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                      >
                        {script.name}
                      </button>
                      {script.description && <span className="block max-w-md text-fg-muted">{script.description}</span>}
                    </th>
                    <td className="border-b border-line-soft px-3 py-2 align-top font-mono">
                      {script.version ?? <span className="text-fg-muted">—</span>}
                    </td>
                    <td className="border-b border-line-soft px-3 py-2 align-top">
                      <span className="flex flex-wrap gap-1">
                        {script.inLibrary ? (
                          <Badge color="emerald">in the library</Badge>
                        ) : (
                          <Badge>draft · not usable yet</Badge>
                        )}
                        {script.inLibrary && script.hasDraft && <Badge color="amber">draft changed</Badge>}
                        {script.builtin && <Badge color="cyan">shipped with Nik</Badge>}
                      </span>
                    </td>
                    <td className="whitespace-nowrap border-b border-line-soft px-3 py-2 align-top text-fg-muted">
                      {formatRelative(script.updatedAt)} · <span className="font-mono">{script.updatedBy}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <SandboxBox available={found.sandbox} />
        </div>
      )}

      <Modal
        open={createOpen}
        onClose={() => creating.leave(() => setCreateOpen(false))}
        title="New script"
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" form="form-new-script" disabled={busy || Boolean(nameProblem(name))}>
              Create
            </Button>
          </>
        }
      >
        <form id="form-new-script" onSubmit={create} className="flex flex-col gap-3">
          <Field
            label="Name"
            required
            hint="How nodes call it: a capital letter, then letters and digits. It cannot be changed later."
            problem={wrongName}
          >
            {(id) => (
              <TextInput id={id} value={name} maxLength={49} autoFocus placeholder="GroupByField" onChange={setName} />
            )}
          </Field>
          <Field label="Description" hint="What it does, in a line: shown in the library of nodes.">
            {(id) => <TextInput id={id} value={description} maxLength={300} onChange={setDescription} />}
          </Field>
          {createError && (
            <p role="alert" className="text-sm text-high-fg">
              {createError}
            </p>
          )}
        </form>
      </Modal>
      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title="Delete this script?"
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
          <span className="font-semibold">{deleting?.name}</span> goes with its versions. A script a playbook uses is
          not deleted: the answer says which.
        </p>
      </Modal>
    </div>
  )
}
