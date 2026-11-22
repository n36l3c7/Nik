import { useEffect, useState } from 'react'
import { Copy, Download, Plus, Trash2, X } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { useToast } from '../../context/ToastContext.jsx'
import { api } from '../../services/api.js'
import { copyText, saveBlob } from '../../lib/download.js'
import { formatDateTime } from '../../lib/time.js'
import { hostOf } from '../../domain/automation/hosts.js'
import { Badge, Button, Modal } from '../ui/index.js'
import DataGuardDialog from './DataGuardDialog.jsx'
import { DurationInput, Field, NumberInput, SectionTitle, Seg, Switch, TextInput } from './fields.jsx'
import { useUnsavedChanges } from '../../lib/unsaved.js'
import { transfer } from '../../lib/transfers.js'

/*
 * ============================================================================
 * A PLAYBOOK'S SETTINGS — its name, its limits, where it may connect, what
 * may leave
 * ============================================================================
 *
 * Two choices decide what a playbook can do outside Nik, and both belong to
 * an admin:
 *
 *   Network  the hosts it may reach: those listed here and those listed for
 *            every playbook (Settings → Automation), or any host;
 *   Data     the classes of data its nodes may send. Hashes, public
 *            indicators, verdicts and Nik's own ids always leave; the others
 *            are closed until opened here. E-mail bodies, attachments and
 *            samples are whole messages and whole files: they are listed
 *            apart, under a warning of their own, for the playbook that must
 *            forward them. TLP:RED data is not offered at all.
 *
 * Opening either beyond the default asks twice (DataGuardDialog) and is
 * written in the audit log. Limits and the name are for who builds playbooks.
 *
 * A playbook whose trigger says "From outside" gets its address here: a long
 * random token in a URL. Nik shows it once, when it is created, and keeps
 * only its hash: an address that was lost is replaced, not read again.
 */

// Said over the classes that are whole messages and whole files, and again before one is opened.
const WHOLE_WARNING =
  'What is opened here leaves Nik whole, as it is: the text of an e-mail, an attachment as it was sent, a sample as it is held. A sample is live malware.'

function Box({ title, children, aside = null }) {
  return (
    <section aria-label={title} className="flex min-w-0 flex-col gap-3 border border-line bg-panel p-4">
      <SectionTitle action={aside}>{title}</SectionTitle>
      {children}
    </section>
  )
}

/** The address a system outside starts the playbook at: created, replaced, removed. */
function HookBox({ playbook, canEdit, base, onChanged }) {
  const { showToast } = useToast()
  const [made, setMade] = useState(null) // { url }: the address just created, shown this once
  const [busy, setBusy] = useState(false)
  const [confirm, setConfirm] = useState(null) // 'replace' | 'remove'

  const change = async (work) => {
    setBusy(true)
    try {
      const answer = await work()
      setMade(answer?.path ? { url: `${window.location.origin}${answer.path}` } : null)
      onChanged(await api.get(base))
    } catch (error) {
      showToast({ message: error.message })
    } finally {
      setBusy(false)
      setConfirm(null)
    }
  }
  const create = () => change(() => api.post(`${base}/hook`, {}))
  const remove = () => change(() => api.del(`${base}/hook`))
  const copy = async () =>
    showToast({ message: (await copyText(made.url)) ? 'Address copied.' : 'The browser refused to copy.' })

  const waits = Boolean(playbook.triggerConfig?.webhook)
  return (
    <Box title="Address for requests from outside" aside={playbook.hook ? <Badge color="amber">open</Badge> : null}>
      <p className="text-sm text-fg-muted">
        A system outside Nik starts this playbook with a POST to an address that holds a long random token. Whoever has
        the address can start the playbook: nothing else is asked. The request may carry up to 256 kB, which the
        playbook reads as <span className="font-mono">{'{{ trigger.body }}'}</span>, and gets no answer but “accepted”.
      </p>
      {!waits && (
        <p className="border border-med-line bg-med-soft px-3 py-2 text-sm text-med-fg">
          The saved version of this playbook does not start from outside: the address answers “not found” until its
          trigger says so.
        </p>
      )}
      {made && (
        <div className="flex flex-col gap-2 border border-accent-strong bg-accent-soft p-3">
          <span className="text-sm text-fg">Copy the address now: it is not shown again.</span>
          <div className="flex items-center gap-2">
            <code
              id="hook-address"
              className="min-w-0 flex-1 break-all bg-canvas px-2 py-1.5 font-mono text-xs text-fg"
            >
              {made.url}
            </code>
            <Button size="sm" variant="secondary" icon={Copy} onClick={copy}>
              Copy
            </Button>
          </div>
        </div>
      )}
      {playbook.hook && !made && (
        <p className="text-sm text-fg">
          It has an address, created {formatDateTime(Date.parse(playbook.hook.since))}. Nik keeps only its hash.
        </p>
      )}
      {!playbook.hook && <p className="text-sm text-fg">It has no address yet.</p>}
      {canEdit && (
        <div className="flex flex-wrap gap-2">
          {playbook.hook ? (
            <>
              <Button size="sm" variant="secondary" disabled={busy} onClick={() => setConfirm('replace')}>
                Replace the address
              </Button>
              <Button size="sm" variant="danger" icon={Trash2} disabled={busy} onClick={() => setConfirm('remove')}>
                Remove the address
              </Button>
            </>
          ) : (
            <Button size="sm" disabled={busy} onClick={create}>
              Create the address
            </Button>
          )}
        </div>
      )}
      <Modal
        open={confirm !== null}
        onClose={() => setConfirm(null)}
        title={confirm === 'remove' ? 'Remove the address?' : 'Replace the address?'}
        footer={
          <>
            <Button variant="secondary" onClick={() => setConfirm(null)}>
              Cancel
            </Button>
            <Button variant="danger" disabled={busy} onClick={confirm === 'remove' ? remove : create}>
              {confirm === 'remove' ? 'Remove' : 'Replace'}
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          The address in use stops working at once: whatever sends requests to it gets “not found”
          {confirm === 'replace' ? ' until it is given the new one.' : '.'}
        </p>
      </Modal>
    </Box>
  )
}

/**
 * @param {{
 *   playbook: object,                          // GET /api/automation/playbooks/<id>
 *   canEdit: boolean,
 *   onChanged: (detail: object) => void,
 *   onDeleted: () => void,
 * }} props
 */
export default function PlaybookSettingsTab({ playbook, canEdit, onChanged, onDeleted }) {
  const { can, currentUser } = useAuth()
  const isAdmin = can('admin')
  const { showToast } = useToast()
  const base = `/automation/playbooks/${encodeURIComponent(playbook.id)}`

  const [name, setName] = useState(playbook.name)
  const [description, setDescription] = useState(playbook.description)
  const [limits, setLimits] = useState(null)
  const [newHost, setNewHost] = useState('')
  const [classes, setClasses] = useState(null) // { always, classes }
  const [everyHost, setEveryHost] = useState(null) // the hosts listed for every playbook (admins)
  const [guard, setGuard] = useState(null) // what the double check is about
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [busy, setBusy] = useState(false)

  useEffect(() => {
    setName(playbook.name)
    setDescription(playbook.description)
    setLimits({
      maxRunsPerHour: playbook.maxRunsPerHour,
      onePerObject: playbook.onePerObject,
      maxSeconds: playbook.maxSeconds,
      approvalDefault: playbook.approvalDefault,
    })
  }, [playbook])
  useEffect(() => {
    let alive = true
    api
      .get('/automation/data-classes')
      .then((found) => alive && setClasses(found))
      .catch(() => {})
    if (isAdmin) {
      api
        .get('/automation/settings')
        .then((found) => alive && setEveryHost(found.hosts))
        .catch(() => {})
    }
    return () => {
      alive = false
    }
  }, [isAdmin])

  const run = async (work, done) => {
    setBusy(true)
    try {
      const found = await work()
      if (found) onChanged(found)
      if (done) showToast({ message: done })
      return true
    } catch (error) {
      showToast({ message: error.message })
      return false
    } finally {
      setBusy(false)
    }
  }

  const sendGeneral = () => run(() => api.put(base, { name: name.trim(), description }), 'Saved.')
  const saveGeneral = (event) => {
    event.preventDefault()
    sendGeneral()
  }
  useUnsavedChanges(canEdit && (name !== playbook.name || description !== playbook.description), {
    what: 'The name and description of the playbook',
    name: playbook.name,
    save: sendGeneral,
  })
  const limitsChanged =
    limits &&
    (limits.maxRunsPerHour !== playbook.maxRunsPerHour ||
      limits.onePerObject !== playbook.onePerObject ||
      limits.maxSeconds !== playbook.maxSeconds ||
      limits.approvalDefault !== playbook.approvalDefault)
  const sendLimits = () => run(() => api.put(base, limits), 'The limits apply from the next run.')
  const saveLimits = (event) => {
    event.preventDefault()
    sendLimits()
  }
  useUnsavedChanges(canEdit && Boolean(limitsChanged), {
    what: 'The limits of the playbook',
    name: playbook.name,
    save: sendLimits,
  })

  const setHosts = (hosts) => run(() => api.put(`${base}/egress`, { mode: playbook.egressMode, hosts }))
  const addHost = async (event) => {
    event.preventDefault()
    const host = hostOf(newHost)
    if (!host) return
    if (await setHosts([...playbook.egressHosts, host])) setNewHost('')
  }

  const exportFile = async () => {
    try {
      const file = await transfer(`Preparing the export of ${playbook.name}`, () => api.get(`${base}/export`))
      saveBlob(
        new Blob([JSON.stringify(file, null, 2)], { type: 'application/json' }),
        `${playbook.name.replace(/[^\w.-]+/g, '_')}.playbook.json`,
      )
    } catch (error) {
      showToast({ message: error.message })
    }
  }

  const destinations =
    playbook.egressMode === 'any'
      ? 'This playbook may reach any host: what is opened could be sent anywhere a node says.'
      : `It could be sent to: ${[...playbook.egressHosts, ...(everyHost ?? [])].join(', ') || 'no host yet (none is listed)'}. With “Any host” it could be sent anywhere a node says.`

  if (!limits) return null
  const opened = new Set(playbook.dataAllow)
  const known = classes?.classes ?? []
  // E-mail bodies, attachments and samples: offered apart from the classes that are words and names.
  const whole = known.filter((item) => item.sensitive && item.apart)

  /** A class an admin opens and closes: what it is, whether it may leave, the button. */
  const classRow = (item) => (
    <li key={item.id} className="flex items-center justify-between gap-3 px-2 py-1.5">
      <span className="min-w-0">
        {item.label}
        <span className="block text-xs text-fg-muted">{item.warning}</span>
      </span>
      <span className="flex shrink-0 items-center gap-2">
        {opened.has(item.id) ? <Badge color="amber">may leave</Badge> : <Badge>closed</Badge>}
        {isAdmin && (
          <Button
            variant="secondary"
            size="xs"
            disabled={busy}
            aria-label={opened.has(item.id) ? `Close: ${item.label}` : `Open: ${item.label}`}
            onClick={() =>
              opened.has(item.id)
                ? run(
                    () => api.put(`${base}/data-allow`, { class: item.id, allow: false }),
                    `${item.label}: closed again.`,
                  )
                : setGuard({ kind: 'data', item })
            }
          >
            {opened.has(item.id) ? 'Close' : 'Open…'}
          </Button>
        )}
      </span>
    </li>
  )

  return (
    <div className="grid max-w-6xl gap-4 lg:grid-cols-2">
      <Box title="The playbook">
        <form onSubmit={saveGeneral} className="flex flex-col gap-3">
          <Field label="Name">
            {(id) => <TextInput id={id} value={name} maxLength={120} disabled={!canEdit} onChange={setName} />}
          </Field>
          <Field label="Description">
            {(id) => (
              <textarea
                id={id}
                value={description}
                rows={3}
                maxLength={2000}
                disabled={!canEdit}
                onChange={(event) => setDescription(event.target.value)}
                className="w-full border border-line bg-sunken px-2 py-1.5 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60"
              />
            )}
          </Field>
          {canEdit && (
            <Button
              type="submit"
              size="sm"
              className="self-start"
              disabled={busy || !name.trim() || (name === playbook.name && description === playbook.description)}
            >
              Save
            </Button>
          )}
        </form>
        <dl className="grid grid-cols-[8rem_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
          <dt className="text-fg-muted">Starts</dt>
          <dd>{playbook.trigger || 'not set yet'}</dd>
          <dt className="text-fg-muted">Created by</dt>
          <dd className="font-mono">{playbook.createdBy}</dd>
          <dt className="text-fg-muted">Last changed by</dt>
          <dd className="font-mono">{playbook.updatedBy}</dd>
        </dl>
        {canEdit && (
          <div className="flex flex-wrap gap-2 border-t border-line-soft pt-3">
            <Button variant="secondary" size="sm" icon={Download} onClick={exportFile}>
              Export
            </Button>
            <Button variant="secondary" size="sm" icon={Trash2} onClick={() => setDeleteOpen(true)}>
              Delete the playbook
            </Button>
          </div>
        )}
        <p className="text-xs text-fg-muted">
          An exported playbook carries its nodes and limits, never what it may reach or send: those are opened again, by
          an admin, where it is imported.
        </p>
      </Box>

      {(playbook.triggerConfig?.webhook || playbook.hook) && (
        <HookBox playbook={playbook} canEdit={canEdit} base={base} onChanged={onChanged} />
      )}

      <Box title="Limits and approvals">
        <form onSubmit={saveLimits} className="flex flex-col gap-3">
          <Field
            label="Runs an hour, at most"
            hint="A trigger that would start more is refused, and said so in the runs."
          >
            {(id) => (
              <NumberInput
                id={id}
                value={limits.maxRunsPerHour}
                min={1}
                max={10000}
                disabled={!canEdit}
                className="w-28!"
                onChange={(value) => setLimits({ ...limits, maxRunsPerHour: value ?? 1 })}
              />
            )}
          </Field>
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm">One run at a time on the same object</span>
            <Switch
              label="One run at a time on the same object"
              checked={limits.onePerObject}
              disabled={!canEdit}
              onChange={(onePerObject) => setLimits({ ...limits, onePerObject })}
            />
          </div>
          <Field
            label="Longest run"
            hint="A run still going after this is stopped. Time spent waiting for an approval is not counted."
          >
            {(id) => (
              <DurationInput
                id={id}
                value={limits.maxSeconds}
                disabled={!canEdit}
                onChange={(value) =>
                  setLimits({ ...limits, maxSeconds: Math.min(Math.max(value ?? 60, 60), 7 * 86400) })
                }
              />
            )}
          </Field>
          <div className="flex items-center justify-between gap-3">
            <span className="text-sm">
              Ask before what changes something outside Nik
              <span className="block text-xs text-fg-muted">The default for the nodes that do not say otherwise.</span>
            </span>
            <Switch
              label="Ask before what changes something outside Nik"
              checked={limits.approvalDefault}
              disabled={!canEdit}
              onChange={(approvalDefault) => setLimits({ ...limits, approvalDefault })}
            />
          </div>
          {canEdit && (
            <Button type="submit" size="sm" className="self-start" disabled={busy || !limitsChanged}>
              Save the limits
            </Button>
          )}
        </form>
      </Box>

      <Box title="Network" aside={playbook.egressMode === 'any' ? <Badge color="red">any host</Badge> : null}>
        <p className="text-sm text-fg-muted">
          Where the HTTP and e-mail nodes of this playbook may connect. Addresses inside the server’s own network are
          refused whatever is chosen here.
        </p>
        <Seg
          label="Where the playbook may connect"
          value={playbook.egressMode}
          disabled={!isAdmin || busy}
          onChange={(mode) => {
            if (mode === playbook.egressMode) return
            if (mode === 'any') setGuard({ kind: 'egress' })
            else
              run(
                () => api.put(`${base}/egress`, { mode: 'listed', hosts: playbook.egressHosts }),
                'Only the listed hosts from now on.',
              )
          }}
          options={[
            { value: 'listed', label: 'Listed hosts only' },
            { value: 'any', label: 'Any host' },
          ]}
        />
        <div>
          <p className="mb-1 text-xs text-fg-muted">Hosts of this playbook</p>
          <ul className="flex flex-wrap gap-1.5">
            {playbook.egressHosts.length === 0 && <li className="text-xs text-fg-muted">None.</li>}
            {playbook.egressHosts.map((host) => (
              <li
                key={host}
                className="inline-flex items-center gap-1 border border-line bg-sunken pl-2 font-mono text-xs"
              >
                {host}
                {isAdmin && (
                  <button
                    type="button"
                    aria-label={`Remove ${host}`}
                    disabled={busy}
                    onClick={() => setHosts(playbook.egressHosts.filter((item) => item !== host))}
                    className="p-1 text-fg-muted hover:text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    <X className="h-3 w-3" aria-hidden="true" />
                  </button>
                )}
              </li>
            ))}
          </ul>
        </div>
        {isAdmin && (
          <form onSubmit={addHost} className="flex items-end gap-2">
            <div className="min-w-0 flex-1">
              <Field label="Add a host">
                {(id) => (
                  <TextInput
                    id={id}
                    value={newHost}
                    placeholder="api.example.org or api.example.org:8443"
                    onChange={setNewHost}
                  />
                )}
              </Field>
            </div>
            <Button type="submit" variant="secondary" size="sm" icon={Plus} disabled={busy || !newHost.trim()}>
              Add
            </Button>
          </form>
        )}
        {everyHost && (
          <p className="text-xs text-fg-muted">
            Listed for every playbook (Settings → Automation):{' '}
            <span className="font-mono">{everyHost.join(', ') || 'none'}</span>
          </p>
        )}
        {!isAdmin && <p className="text-xs text-fg-muted">Only an admin changes where a playbook may connect.</p>}
      </Box>

      <Box title="Data that may leave" aside={opened.size > 0 ? <Badge color="amber">data opened</Badge> : null}>
        <p className="text-sm text-fg-muted">
          What the nodes of this playbook may send outside Nik. A node that would send something closed is stopped, and
          the run says what was held back.
        </p>
        <dl className="flex flex-col gap-3 text-sm">
          <div>
            <dt className="mb-1 text-xs text-fg-muted">Always</dt>
            <dd className="text-fg">Hashes, public domains, URLs and addresses, verdicts, Nik’s own ids.</dd>
          </div>
          <div>
            <dt className="mb-1 text-xs text-fg-muted">Closed unless opened here</dt>
            <dd>
              <ul className="flex flex-col divide-y divide-line-soft border border-line-soft">
                {known.filter((item) => !item.sensitive).map(classRow)}
              </ul>
            </dd>
          </div>
          {whole.length > 0 && (
            <div>
              <dt className="mb-1 text-xs text-fg-muted">
                Whole messages and files, closed unless an admin opens them here
              </dt>
              <dd className="flex flex-col gap-2">
                <p className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high-fg">{WHOLE_WARNING}</p>
                <ul
                  aria-label="Whole messages and files that may leave"
                  className="flex flex-col divide-y divide-line-soft border border-line-soft"
                >
                  {whole.map(classRow)}
                </ul>
              </dd>
            </div>
          )}
          <div>
            <dt className="mb-1 text-xs text-fg-muted">Never, in any playbook</dt>
            <dd className="text-fg">
              {known
                .filter((item) => item.sensitive && !item.apart)
                .map((item) => item.label)
                .join(', ') || 'TLP:RED data'}
              .
            </dd>
          </div>
        </dl>
        {!isAdmin && <p className="text-xs text-fg-muted">Only an admin opens a class of data.</p>}
      </Box>

      <DataGuardDialog
        open={guard !== null}
        playbookName={playbook.name}
        actor={currentUser?.username ?? ''}
        title={
          guard?.kind === 'data'
            ? `Let ${guard.item.label.toLowerCase()} leave Nik in this playbook?`
            : 'Let this playbook reach any host?'
        }
        warning={
          guard?.kind === 'data'
            ? guard.item.apart
              ? `${guard.item.warning} ${WHOLE_WARNING}`
              : guard.item.warning
            : 'Its HTTP and e-mail nodes will be able to connect to any address on the internet, not only to the hosts you listed.'
        }
        destinations={
          guard?.kind === 'data'
            ? destinations
            : opened.size > 0
              ? 'This playbook has classes of data opened: with any host, they could be sent anywhere a node says.'
              : 'What always leaves (hashes, public indicators, verdicts) could be sent anywhere a node says.'
        }
        acknowledge={
          guard?.kind === 'data'
            ? guard.item.apart
              ? 'These systems are ours, or are made to receive this.'
              : 'These systems are ours, or may hold this data.'
            : 'I know which hosts this playbook contacts, and listing them is not possible.'
        }
        confirmLabel={guard?.kind === 'data' ? `Allow ${guard.item.label.toLowerCase()}` : 'Allow any host'}
        onClose={() => setGuard(null)}
        onConfirm={async (check) => {
          const found =
            guard.kind === 'data'
              ? await api.put(`${base}/data-allow`, { class: guard.item.id, allow: true, ...check })
              : await api.put(`${base}/egress`, { mode: 'any', hosts: playbook.egressHosts, ...check })
          onChanged(found)
          setGuard(null)
        }}
      />

      <Modal
        open={deleteOpen}
        onClose={() => setDeleteOpen(false)}
        title="Delete this playbook?"
        footer={
          <>
            <Button variant="secondary" onClick={() => setDeleteOpen(false)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              disabled={busy}
              onClick={async () => {
                setBusy(true)
                try {
                  await api.del(base)
                  setDeleteOpen(false)
                  showToast({ message: `${playbook.name} was deleted.` })
                  onDeleted()
                } catch (error) {
                  showToast({ message: error.message })
                } finally {
                  setBusy(false)
                }
              }}
            >
              Delete
            </Button>
          </>
        }
      >
        <p className="text-sm text-fg">
          <span className="font-semibold">{playbook.name}</span> goes with its versions and the history of its runs.
          This cannot be undone; export it first to keep a copy.
        </p>
      </Modal>
    </div>
  )
}
