import { useRef, useState } from 'react'
import { FolderOpen, ListTree, Play, Plus, Trash2, Upload } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { formatRelative } from '../../lib/time.js'
import { AsciiSkull, Badge, Button, EmptyState, Modal } from '../ui/index.js'
import { Field, Switch, TextInput } from './fields.jsx'
import { useAutomation } from '../../context/AutomationContext.jsx'
import { useObjectMenu } from '../menu/useObjectMenu.js'
import { usePageMenu } from '../menu/usePageMenu.js'
import { automationPath } from '../../domain/automationNav.js'
import { setPath } from '../../lib/location.js'

/*
 * The playbooks: what starts each, whether it is on, the version that runs,
 * how its last week went and what to watch (a draft not saved as a version,
 * a script with a newer version, a playbook that may reach any host or send
 * a class of data).
 */

const RUN_COLORS = { done: 'emerald', failed: 'red', stopped: 'slate', waiting: 'amber', running: 'cyan' }
const WARNING_COLORS = { 'any host': 'red', 'data opened': 'amber', 'updates available': 'cyan' }

/**
 * @param {{
 *   playbooks: object[] | null,                // null while loading
 *   error: string | null,
 *   onOpen: (id: string, tab?: string | null, branch?: string | null) => void,
 *   onReload: () => Promise<void>,
 * }} props
 */
export default function PlaybooksPage({ playbooks, error, onOpen, onReload }) {
  const { can } = useAuth()
  const canEdit = can('automation.edit')
  const canRun = can('automation.run')
  const { askRun } = useAutomation()
  const menu = useObjectMenu()
  const { showToast } = useToast()
  const [createOpen, setCreateOpen] = useState(false)
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [createError, setCreateError] = useState(null)
  const [busy, setBusy] = useState(false)
  const fileInput = useRef(null)
  const [deleting, setDeleting] = useState(null)

  const remove = async () => {
    const gone = deleting
    setDeleting(null)
    try {
      await api.del(`/automation/playbooks/${encodeURIComponent(gone.id)}`)
      showToast({ message: `${gone.name} was deleted.` })
      onReload()
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  const create = async (event) => {
    event.preventDefault()
    setBusy(true)
    setCreateError(null)
    try {
      const made = await api.post('/automation/playbooks', { name: name.trim(), description })
      setCreateOpen(false)
      setName('')
      setDescription('')
      onReload()
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
      if (parsed?.type !== 'playbook' || !parsed.playbook) throw new Error('Not a playbook file')
      const made = await api.post('/automation/playbooks/import', { playbook: parsed.playbook })
      showToast({
        message: made.problems.length
          ? `${made.name} was imported as a draft: ${made.problems.length} to fix before it can be a version.`
          : `${made.name} was imported as a draft, off. Check it, then save it as a version.`,
      })
      onReload()
      onOpen(made.id)
    } catch (failure) {
      showToast({ message: `${file.name}: ${failure instanceof SyntaxError ? 'not a JSON file' : failure.message}` })
    }
  }

  const toggle = async (playbook, enabled) => {
    try {
      await api.put(`/automation/playbooks/${encodeURIComponent(playbook.id)}/enabled`, { enabled })
      onReload()
    } catch (failure) {
      showToast({ message: failure.message })
    }
  }

  const pageMenu = usePageMenu(() => [
    canEdit && { label: 'New playbook…', icon: Plus, onSelect: () => setCreateOpen(true) },
  ])

  return (
    <div className="flex flex-col gap-4 p-6" onContextMenu={pageMenu}>
      <div className="flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-prose text-sm text-fg-muted">
          A playbook is a drawing of what to do when something happens: nodes joined by lines, started by an event, a
          schedule or a person.
        </p>
        {canEdit && (
          <div className="flex gap-2">
            <input
              ref={fileInput}
              type="file"
              accept=".json,application/json"
              className="hidden"
              aria-label="Playbook file to import"
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
              New playbook
            </Button>
          </div>
        )}
      </div>

      {error && (
        <p role="alert" className="text-sm text-high-fg">
          {error}
        </p>
      )}
      {!playbooks && !error && (
        <p role="status" className="font-mono text-sm text-fg-muted">
          Loading the playbooks…
        </p>
      )}
      {playbooks?.length === 0 && (
        <EmptyState
          illustration={<AsciiSkull preset="medium" eyes="closed" tone="muted" />}
          title="No playbook yet"
          message={
            canEdit
              ? 'Create one: it starts as a draft with a trigger, off until you save a version and turn it on.'
              : 'Nobody has built a playbook yet.'
          }
          action={
            canEdit && (
              <Button icon={Plus} onClick={() => setCreateOpen(true)}>
                New playbook
              </Button>
            )
          }
        />
      )}
      {playbooks?.length > 0 && (
        <div className="overflow-x-auto border border-line">
          <table className="w-full min-w-[860px] border-collapse text-left text-xs">
            <caption className="sr-only">Playbooks</caption>
            <thead className="bg-panel font-mono text-fg-muted">
              <tr>
                {['Playbook', 'Starts', 'On', 'Version', 'Last run', 'Last 7 days', 'Watch'].map((heading) => (
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
              {playbooks.map((playbook) => (
                <tr
                  key={playbook.id}
                  className="hover:bg-raised/40"
                  onContextMenu={(event) =>
                    menu(event, {
                      title: playbook.name,
                      actions: [
                        { label: 'Open', icon: FolderOpen, onSelect: () => onOpen(playbook.id) },
                        {
                          label: 'Its runs',
                          icon: ListTree,
                          onSelect: () => setPath(automationPath('playbooks', playbook.id, 'runs')),
                        },
                        canRun && { label: 'Run…', icon: Play, onSelect: () => askRun({ playbookId: playbook.id }) },
                      ],
                      link: automationPath('playbooks', playbook.id),
                      copy: [{ label: 'Copy the name', text: playbook.name }],
                      danger: canEdit
                        ? [{ label: 'Delete…', icon: Trash2, onSelect: () => setDeleting(playbook) }]
                        : [],
                    })
                  }
                >
                  <th scope="row" className="border-b border-line-soft px-3 py-2 align-top font-normal">
                    <button
                      type="button"
                      onClick={() => onOpen(playbook.id)}
                      className="text-left text-sm font-medium text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                    >
                      {playbook.name}
                    </button>
                    {playbook.description && (
                      <span className="block max-w-md text-fg-muted">{playbook.description}</span>
                    )}
                    {canEdit && playbook.branches?.length > 0 && (
                      <ul aria-label={`Branches of ${playbook.name}`} className="mt-1 border-l border-line pl-2">
                        {playbook.branches.map((branch) => (
                          <li key={branch.id} className="flex items-baseline gap-2 font-mono text-[11px]">
                            <button
                              type="button"
                              onClick={() => onOpen(playbook.id, null, branch.id)}
                              className="text-left text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                            >
                              {branch.name}
                            </button>
                            <span className="text-fg-muted">
                              {branch.createdBy}
                              {branch.behind ? ' · behind' : ''}
                            </span>
                          </li>
                        ))}
                      </ul>
                    )}
                  </th>
                  <td className="border-b border-line-soft px-3 py-2 align-top font-mono text-fg-muted">
                    {playbook.trigger || '—'}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top">
                    <Switch
                      label={playbook.enabled ? `Turn ${playbook.name} off` : `Turn ${playbook.name} on`}
                      checked={playbook.enabled}
                      disabled={!canEdit || (!playbook.version && !playbook.enabled)}
                      onChange={(enabled) => toggle(playbook, enabled)}
                    />
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top font-mono">
                    {playbook.version ?? <span className="text-fg-muted">draft</span>}
                    {playbook.version && playbook.hasDraft ? <span className="text-fg-muted"> + draft</span> : null}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top">
                    {playbook.lastRun ? (
                      <span className="flex items-center gap-2">
                        <Badge color={RUN_COLORS[playbook.lastRun.status] ?? 'slate'}>{playbook.lastRun.status}</Badge>
                        <span className="text-fg-muted">{formatRelative(playbook.lastRun.startedAt)}</span>
                      </span>
                    ) : (
                      <span className="text-fg-muted">never</span>
                    )}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top font-mono text-fg-muted">
                    {playbook.week.total === 0 ? '—' : `${playbook.week.total} runs`}
                    {playbook.week.failed > 0 && <span className="text-high-fg"> · {playbook.week.failed} failed</span>}
                  </td>
                  <td className="border-b border-line-soft px-3 py-2 align-top">
                    <span className="flex flex-wrap gap-1">
                      {playbook.builtin && <Badge color="cyan">shipped with Nik</Badge>}
                      {playbook.warnings.map((warning) => (
                        <Badge key={warning} color={WARNING_COLORS[warning] ?? 'slate'}>
                          {warning}
                        </Badge>
                      ))}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Modal
        open={createOpen}
        onClose={() => setCreateOpen(false)}
        title="New playbook"
        footer={
          <>
            <Button variant="secondary" onClick={() => setCreateOpen(false)}>
              Cancel
            </Button>
            <Button type="submit" form="form-new-playbook" disabled={busy || !name.trim()}>
              Create
            </Button>
          </>
        }
      >
        <form id="form-new-playbook" onSubmit={create} className="flex flex-col gap-3">
          <Field label="Name" required>
            {(id) => <TextInput id={id} value={name} maxLength={120} autoFocus onChange={setName} />}
          </Field>
          <Field label="Description" hint="What it does, for who finds it in this list.">
            {(id) => <TextInput id={id} value={description} maxLength={2000} onChange={setDescription} />}
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
        title="Delete this playbook?"
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
          <span className="font-semibold">{deleting?.name}</span> goes with its versions, its branches and its runs. One
          with a run in progress is not deleted.
        </p>
      </Modal>
    </div>
  )
}
