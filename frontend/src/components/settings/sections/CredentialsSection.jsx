import { useCallback, useEffect, useMemo, useState } from 'react'
import { LockKeyhole, Pencil, Plus, Trash2 } from 'lucide-react'
import { api } from '../../../services/api.js'
import {
  CREDENTIAL_KINDS,
  createBody,
  credentialForm,
  credentialProblem,
  filterCredentials,
  referenceText,
  updateBody,
  usedIn,
} from '../../../domain/automation/credentials.js'
import { credentialFromPath, credentialPath, instancePath, settingsPath } from '../../../domain/settingsNav.js'
import { onLocationChange, setPath } from '../../../lib/location.js'
import { formatRelative } from '../../../lib/time.js'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { usePageMenu } from '../../menu/usePageMenu.js'
import { Badge, Button, Modal, SearchInput } from '../../ui/index.js'

/*
 * Settings → Credentials (who manages the connectors).
 *
 * A credential is a secret kept once under a name: an API key or a token (a
 * secret), or a user name and a password (a pair). The instances of the
 * connectors name it where they would hold the value, so one value serves
 * several instances, is changed in one place, and is still here when an
 * instance is made again.
 *
 * The value is never shown: it is typed when the credential is made, and
 * typed again to replace it. The list says what each credential is, where it
 * is used (each instance is a link to its form) and who changed it last. One
 * that is used is not deleted and keeps its name.
 */

const INPUT =
  'w-full border border-line bg-canvas px-3 py-1.5 font-mono text-sm text-fg placeholder:text-fg-subtle focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const KIND_LABEL = Object.fromEntries(CREDENTIAL_KINDS.map((kind) => [kind.id, kind.label]))

/** The form of a credential, in a dialog: a new one, or one that exists (its value is replaced, never shown). */
function CredentialDialog({ existing, taken, onClose, onSaved }) {
  const [form, setForm] = useState(() => credentialForm(existing))
  const [error, setError] = useState(null)
  const [busy, setBusy] = useState(false)
  const used = (existing?.usedBy ?? []).length > 0
  const problem = credentialProblem(form, { existing, taken })
  const pair = form.kind === 'pair'
  const set = (patch) => setForm({ ...form, ...patch })

  const save = async (event) => {
    event.preventDefault()
    if (problem) return
    setBusy(true)
    setError(null)
    try {
      const saved = existing
        ? await api.put(`/automation/credentials/${encodeURIComponent(existing.id)}`, updateBody(form, existing))
        : await api.post('/automation/credentials', createBody(form))
      onSaved(saved, Boolean(existing))
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title={existing ? `Credential ${existing.name}` : 'New credential'}
      footer={
        <>
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" form="form-credential" disabled={busy || Boolean(problem)} title={problem ?? undefined}>
            {existing ? 'Save' : 'Create'}
          </Button>
        </>
      }
    >
      <form id="form-credential" onSubmit={save} className="flex flex-col gap-3 text-sm">
        <label className="flex flex-col gap-1 text-fg-muted" htmlFor="credential-name">
          Name
          <input
            id="credential-name"
            type="text"
            value={form.name}
            maxLength={40}
            autoComplete="off"
            spellCheck={false}
            disabled={used}
            placeholder="vt_key"
            onChange={(event) => set({ name: event.target.value })}
            className={INPUT}
          />
          <span className="text-xs">
            {used
              ? 'It is used: a credential that is used keeps its name.'
              : 'How instances name it. A lower-case letter, then lower-case letters, digits, _ or -.'}
          </span>
        </label>
        <label className="flex flex-col gap-1 text-fg-muted" htmlFor="credential-title">
          Description
          <input
            id="credential-title"
            type="text"
            value={form.title}
            maxLength={200}
            autoComplete="off"
            placeholder="What it is for, whose account it is"
            onChange={(event) => set({ title: event.target.value })}
            className={INPUT.replace('font-mono ', '')}
          />
        </label>
        {existing ? (
          <p className="text-fg-muted">
            Kind: <span className="text-fg">{KIND_LABEL[existing.kind] ?? existing.kind}</span>
          </p>
        ) : (
          <fieldset className="flex flex-col gap-1.5">
            <legend className="mb-1 text-fg-muted">Kind</legend>
            {CREDENTIAL_KINDS.map((kind) => (
              <label key={kind.id} className="flex items-start gap-2 text-fg">
                <input
                  type="radio"
                  name="credential-kind"
                  checked={form.kind === kind.id}
                  onChange={() => set({ kind: kind.id })}
                  className="mt-1 accent-accent"
                />
                <span>
                  {kind.label}
                  <span className="block text-xs text-fg-muted">{kind.hint}</span>
                </span>
              </label>
            ))}
          </fieldset>
        )}
        {pair && (
          <label className="flex flex-col gap-1 text-fg-muted" htmlFor="credential-username">
            User name
            <input
              id="credential-username"
              type="text"
              value={form.username}
              maxLength={500}
              autoComplete="off"
              spellCheck={false}
              onChange={(event) => set({ username: event.target.value })}
              className={INPUT}
            />
          </label>
        )}
        <label className="flex flex-col gap-1 text-fg-muted" htmlFor="credential-value">
          {pair ? 'Password' : 'Value'}
          <input
            id="credential-value"
            type="password"
            value={form.value}
            autoComplete="new-password"
            spellCheck={false}
            placeholder={existing ? 'stored: type to replace it' : ''}
            onChange={(event) => set({ value: event.target.value })}
            className={INPUT}
          />
          <span className="text-xs">
            Stored encrypted and never shown again, here or in the API.
            {used ? ' A new value is what every instance that uses it sends from its next request on.' : ''}
          </span>
        </label>
        {error && (
          <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-high">
            {error}
          </p>
        )}
        {problem && !error && <p className="text-xs text-med-fg">{problem}</p>}
      </form>
    </Modal>
  )
}

/** The instances that use a credential, each a link to the part of its form that names it. */
function UsedIn({ usedBy }) {
  const uses = usedIn(usedBy)
  if (uses.length === 0) return <span className="text-fg-subtle">not used</span>
  return (
    <ul className="flex flex-col gap-0.5">
      {uses.map((use) => {
        const path = instancePath(use.instance, use.tab)
        return (
          <li key={use.instance}>
            <a
              href={path}
              onClick={(event) => {
                event.preventDefault()
                setPath(path)
              }}
              className="text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {use.name}
            </a>
            <span className="text-fg-subtle">
              {' '}
              · {use.connectorName}
              {use.keys.length > 0 ? ` · ${use.keys.join(', ')}` : ''}
            </span>
          </li>
        )
      })}
    </ul>
  )
}

export default function CredentialsSection() {
  const [credentials, setCredentials] = useState(null)
  const [query, setQuery] = useState('')
  const [error, setError] = useState(null)
  const [notice, setNotice] = useState(null)
  const [editing, setEditing] = useState(null) // { existing: object | null }
  const [deleting, setDeleting] = useState(null)
  const [busy, setBusy] = useState(false)
  // The credential an address points at (a link from the form of an instance).
  const [asked, setAsked] = useState(() => credentialFromPath(window.location.pathname))
  const menu = useObjectMenu()
  const pageMenu = usePageMenu(() => [
    { label: 'New credential…', icon: Plus, onSelect: () => setEditing({ existing: null }) },
  ])

  const load = useCallback(async () => {
    try {
      setCredentials((await api.get('/automation/credentials')).credentials)
    } catch (failure) {
      setError(failure.message)
    }
  }, [])
  useEffect(() => {
    load()
  }, [load])
  useEffect(() => onLocationChange(() => setAsked(credentialFromPath(window.location.pathname))), [])

  const shown = useMemo(() => filterCredentials(credentials, query), [credentials, query])
  const names = (credentials ?? []).map((credential) => credential.name)

  const remove = async () => {
    setBusy(true)
    setError(null)
    setNotice(null)
    try {
      await api.del(`/automation/credentials/${encodeURIComponent(deleting.id)}`)
      setNotice(`${deleting.name} was deleted.`)
      if (asked === deleting.name) setPath(settingsPath('credentials'), { replace: true })
    } catch (failure) {
      setError(failure.message)
    } finally {
      setBusy(false)
      setDeleting(null)
      load()
    }
  }

  const inUse = usedIn(deleting?.usedBy)

  return (
    <section className="flex max-w-6xl flex-col gap-5" onContextMenu={pageMenu}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <LockKeyhole className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-fg">Credentials</h2>
            {credentials && <Badge color="slate">{credentials.length}</Badge>}
          </div>
          <p className="mt-1 max-w-prose text-sm text-fg-muted">
            A secret kept once under a name, for the instances of the connectors to use: an API key or a token, or a
            user name and a password. An instance names the credential instead of holding the value, so the value is
            changed in one place and is still here when an instance is made again. Only the fields of an instance read a
            credential: a playbook, a script and a connector file cannot.
          </p>
        </div>
        <Button icon={Plus} onClick={() => setEditing({ existing: null })}>
          New credential…
        </Button>
      </div>

      {error && (
        <p role="alert" className="border border-high-line bg-high-soft px-3 py-2 text-sm text-high">
          {error}
        </p>
      )}
      <p role="status" className={notice ? 'text-sm text-accent-fg' : 'sr-only'}>
        {notice}
      </p>

      <SearchInput
        value={query}
        onChange={setQuery}
        label="Find a credential"
        placeholder="Find a credential or an instance that uses one"
        className="w-80 max-w-full"
      />

      <div className="overflow-x-auto border border-line">
        <table className="w-full border-collapse text-left text-sm">
          <caption className="sr-only">Credentials</caption>
          <thead className="bg-panel font-mono text-xs text-fg-muted">
            <tr>
              {['Credential', 'Kind', 'User name', 'Used in', 'Changed', ''].map((heading, index) => (
                <th key={heading || index} scope="col" className="border-b border-line px-3 py-1.5 font-normal">
                  {heading || <span className="sr-only">Actions</span>}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {shown.map((credential) => (
              <tr
                key={credential.id}
                className={credential.name === asked ? 'bg-accent-soft' : ''}
                onContextMenu={(event) =>
                  menu(event, {
                    title: credential.name,
                    actions: [{ label: 'Edit…', icon: Pencil, onSelect: () => setEditing({ existing: credential }) }],
                    link: credentialPath(credential.name),
                    copy: [
                      { label: 'Copy the name', text: credential.name },
                      {
                        label: 'Copy the variable',
                        text: referenceText(credential.name, credential.kind === 'pair' ? 'password' : ''),
                      },
                    ],
                    danger: [{ label: 'Delete…', icon: Trash2, onSelect: () => setDeleting(credential) }],
                  })
                }
              >
                <th scope="row" className="border-b border-line-soft px-3 py-2 align-top font-normal">
                  <button
                    type="button"
                    onClick={() => setEditing({ existing: credential })}
                    className="font-mono text-link hover:underline focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  >
                    {credential.name}
                  </button>
                  {credential.title && <span className="block text-xs text-fg-muted">{credential.title}</span>}
                  {!credential.readable && (
                    <span className="block text-xs text-high-fg">
                      Its value cannot be read since SECRET_KEY changed: type it again.
                    </span>
                  )}
                </th>
                <td className="border-b border-line-soft px-3 py-2 align-top text-fg-muted">
                  {KIND_LABEL[credential.kind] ?? credential.kind}
                </td>
                <td className="border-b border-line-soft px-3 py-2 align-top font-mono text-xs text-fg-muted">
                  {credential.username || '—'}
                </td>
                <td className="border-b border-line-soft px-3 py-2 align-top text-xs">
                  <UsedIn usedBy={credential.usedBy} />
                </td>
                <td className="border-b border-line-soft px-3 py-2 align-top text-xs text-fg-muted">
                  {formatRelative(credential.updatedAt)}
                  {credential.updatedBy ? ` · ${credential.updatedBy}` : ''}
                </td>
                <td className="border-b border-line-soft px-2 py-1.5 align-top">
                  <div className="flex justify-end gap-1">
                    <Button
                      size="xs"
                      variant="ghost"
                      icon={Pencil}
                      aria-label={`Edit ${credential.name}`}
                      onClick={() => setEditing({ existing: credential })}
                    />
                    <Button
                      size="xs"
                      variant="ghost"
                      icon={Trash2}
                      aria-label={`Delete ${credential.name}`}
                      onClick={() => setDeleting(credential)}
                    />
                  </div>
                </td>
              </tr>
            ))}
            {credentials === null && (
              <tr>
                <td colSpan={6} className="px-3 py-3 font-mono text-sm text-fg-muted">
                  Loading the credentials…
                </td>
              </tr>
            )}
            {credentials !== null && shown.length === 0 && (
              <tr>
                <td colSpan={6} className="px-3 py-3 text-sm text-fg-muted">
                  {credentials.length === 0 ? 'Nothing here yet.' : 'No credential matches.'}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {editing && (
        <CredentialDialog
          existing={editing.existing}
          taken={names.filter((name) => name !== editing.existing?.name)}
          onClose={() => setEditing(null)}
          onSaved={(saved, existed) => {
            setEditing(null)
            setError(null)
            setNotice(`${saved.name} is ${existed ? 'saved' : 'stored'}.`)
            load()
          }}
        />
      )}

      <Modal
        open={deleting !== null}
        onClose={() => setDeleting(null)}
        title={deleting ? `Delete ${deleting.name}?` : 'Delete the credential?'}
        footer={
          inUse.length > 0 ? (
            <Button variant="secondary" onClick={() => setDeleting(null)}>
              Close
            </Button>
          ) : (
            <>
              <Button variant="secondary" onClick={() => setDeleting(null)}>
                Cancel
              </Button>
              <Button variant="danger" disabled={busy} onClick={remove}>
                Delete
              </Button>
            </>
          )
        }
      >
        {inUse.length > 0 ? (
          <div className="flex flex-col gap-2 text-sm text-fg">
            <p>
              It is used, and is not deleted while it is. Give these instances another credential, or a typed value:
            </p>
            <UsedIn usedBy={deleting?.usedBy} />
          </div>
        ) : (
          <p className="text-sm text-fg">
            The value is deleted with it and cannot be read back. No instance uses this credential.
          </p>
        )}
      </Modal>
    </section>
  )
}
