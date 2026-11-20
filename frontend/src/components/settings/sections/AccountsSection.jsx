import { useCallback, useEffect, useState } from 'react'
import {
  AlertCircle,
  Ban,
  MonitorSmartphone,
  Pencil,
  ShieldAlert,
  ShieldCheck,
  ShieldOff,
  Trash2,
  UserPlus,
  Users,
} from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { api } from '../../../services/api.js'
import { formatRelative } from '../../../lib/time.js'
import { rolesOf, sameRoles } from '../../../domain/permissions.js'
import { FACTOR_LABELS, factorState } from '../../../domain/signin.js'
import { useObjectMenu } from '../../menu/useObjectMenu.js'
import { Badge, Button, Modal } from '../../ui/index.js'
import RolePicker, { RoleChips } from '../RolePicker.jsx'
import SessionsList from '../SessionsList.jsx'
import { useUnsavedChanges } from '../../../lib/unsaved.js'

/*
 * Accounts settings section (admin only): the local accounts. An admin adds
 * an account, changes its name, roles or password, disables it (it keeps its
 * history and cannot sign in) or deletes it. Roles are tags: an account holds
 * one or more and may do what they grant together. The server refuses what
 * would lock everybody out (the last admin, one's own admin role) and records
 * each change in the audit log.
 *
 * Each account says whether it has a second factor, and whether its roles ask
 * for one it has not set up yet. An admin sees the open sessions of an account
 * and ends them, and resets the second factor of somebody who lost theirs
 * (not their own: recovery codes are for that).
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-fg'

function ErrorNote({ children }) {
  return (
    <div
      role="alert"
      className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high"
    >
      <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
      <span>{children}</span>
    </div>
  )
}

const FACTOR_BADGES = {
  on: { color: 'emerald', icon: ShieldCheck },
  missing: { color: 'amber', icon: ShieldAlert },
  off: { color: 'slate', icon: null },
}

/** Whether the account has a second factor, or lacks the one its roles ask for. */
function FactorBadge({ user }) {
  const state = factorState(user)
  const { color, icon: Icon } = FACTOR_BADGES[state]
  return (
    <Badge
      color={color}
      title={
        state === 'missing'
          ? 'Its roles require a second factor: it is asked to set one up at its next sign-in, and can do nothing else before'
          : undefined
      }
    >
      {Icon && <Icon className="h-3 w-3" aria-hidden="true" />}
      {FACTOR_LABELS[state]}
    </Badge>
  )
}

/** The open sessions of an account, each ended with its button. */
function AccountSessionsDialog({ user, isSelf, onClose }) {
  const base = `/users/${encodeURIComponent(user.id)}/sessions`
  const load = useCallback(() => api.get(base), [base])
  return (
    <Modal
      open
      onClose={onClose}
      title={`Sessions of ${user.username}`}
      maxWidth="max-w-2xl"
      footer={<Button onClick={onClose}>Close</Button>}
    >
      <div className="space-y-3">
        <p className="text-sm text-fg-muted">
          Where the account is signed in now. A session that is ended is refused at its next request: the person is
          asked to sign in again.
        </p>
        <SessionsList
          label={`Sessions of ${user.username}`}
          load={load}
          end={(session) => api.del(`${base}/${encodeURIComponent(session.id)}`)}
          endOthers={() => api.del(base)}
          endOthersLabel={isSelf ? 'End all the others' : 'End them all'}
        />
      </div>
    </Modal>
  )
}

/** Take the second factor of somebody else away, after asking. */
function ResetFactorDialog({ user, onClose, onDone }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const reset = async () => {
    setBusy(true)
    setError(null)
    try {
      await api.post(`/users/${encodeURIComponent(user.id)}/second-factor/reset`)
      await onDone()
      onClose()
    } catch (failure) {
      setError(failure.message)
      setBusy(false)
    }
  }
  return (
    <Modal
      open
      onClose={onClose}
      title={`Reset the second factor of ${user.username}`}
      maxWidth="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button waiting={busy} variant="danger" icon={ShieldOff} onClick={reset} disabled={busy}>
            {busy ? 'Resetting…' : 'Reset it'}
          </Button>
        </>
      }
    >
      <div className="space-y-2 text-sm text-fg-muted">
        <p>
          For somebody who lost the device and the recovery codes. The second factor and its recovery codes are taken
          away, and the account is signed out everywhere: it signs in with its password alone
          {user.secondFactorRequired
            ? ', and is asked to set a second factor up again before anything else.'
            : ', and is told to set a second factor up again.'}
        </p>
        <p>Make sure it is them who asks. The reset is written in the audit log under your name.</p>
        {error && <ErrorNote>{error}</ErrorNote>}
      </div>
    </Modal>
  )
}

/** Change one account: only what was edited is sent. */
function EditAccountDialog({ user, isSelf, onClose, onSaved }) {
  const { updateUser } = useAuth()
  const [username, setUsername] = useState(user.username)
  const [roles, setRoles] = useState(() => rolesOf(user))
  const [password, setPassword] = useState('')
  const [disabled, setDisabled] = useState(Boolean(user.disabled))
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  const changes = {}
  if (username.trim() !== user.username) changes.username = username.trim()
  if (!sameRoles(roles, rolesOf(user))) changes.roles = roles
  if (password) changes.password = password
  if (disabled !== Boolean(user.disabled)) changes.disabled = disabled
  const dirty = Object.keys(changes).length > 0 && roles.length > 0
  const unsaved = useUnsavedChanges(Object.keys(changes).length > 0, { what: 'The account', name: user.username })

  const save = async (event) => {
    event.preventDefault()
    if (saving || !dirty) return
    setError(null)
    setSaving(true)
    const result = await updateUser(user.id, changes)
    setSaving(false)
    if (!result.ok) {
      setError(result.error)
      return
    }
    onSaved(changes)
    onClose()
  }

  return (
    <Modal
      open
      onClose={() => unsaved.leave(onClose)}
      title={`Account: ${user.username}`}
      maxWidth="max-w-lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Cancel
          </Button>
          <Button waiting={saving} type="submit" form="edit-account-form" disabled={saving || !dirty}>
            {saving ? 'Saving…' : 'Save changes'}
          </Button>
        </>
      }
    >
      <form id="edit-account-form" onSubmit={save} className="space-y-4">
        <div>
          <label htmlFor="edit-username" className={LABEL_CLASS}>
            Username
          </label>
          <input
            id="edit-username"
            type="text"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            autoComplete="off"
            className={INPUT_CLASS}
          />
          <p className="mt-1 text-xs text-fg-muted">
            The incidents assigned to the account follow the new name. Notes, flags and audit entries already written
            keep the old one.
          </p>
        </div>

        <RolePicker
          idPrefix="edit"
          value={roles}
          onChange={setRoles}
          held={rolesOf(user)}
          locked={isSelf ? ['admin'] : []}
          lockedNote="You cannot take it away from your own account."
        />
        {!isSelf && (
          <p className="-mt-2 text-xs text-fg-muted">
            Other roles sign the account out everywhere: the person signs in again, with the new ones.
          </p>
        )}

        <div>
          <label htmlFor="edit-password" className={LABEL_CLASS}>
            New password
          </label>
          <input
            id="edit-password"
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Leave empty to keep the current one"
            autoComplete="new-password"
            className={INPUT_CLASS}
          />
          <p className="mt-1 text-xs text-fg-muted">
            At least 8 characters. Setting it signs the account out everywhere and ends the wait its failed sign-ins
            earned it.
          </p>
        </div>

        <label className="flex items-start gap-2 text-sm text-fg">
          <input
            type="checkbox"
            checked={disabled}
            disabled={isSelf}
            onChange={(event) => setDisabled(event.target.checked)}
            className="mt-0.5 accent-[var(--color-accent)]"
          />
          <span>
            Disabled
            <span className="block text-xs text-fg-muted">
              {isSelf
                ? 'You cannot disable your own account.'
                : 'The account cannot sign in and is signed out now; everything it did is kept.'}
            </span>
          </span>
        </label>

        {error && <ErrorNote>{error}</ErrorNote>}
      </form>
    </Modal>
  )
}

export default function AccountsSection() {
  const { users, currentUser, createUser, deleteUser, refreshUsers } = useAuth()
  const { refreshIncidents } = useIncidents()
  const menu = useObjectMenu()

  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRoles, setNewRoles] = useState(['analyst'])
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const [editing, setEditing] = useState(null)
  const [sessionsOf, setSessionsOf] = useState(null)
  const [resetting, setResetting] = useState(null)
  const [listError, setListError] = useState(null)

  // Read again when the page opens: who has a second factor changes without this page being told.
  useEffect(() => {
    refreshUsers()
  }, [refreshUsers])

  useUnsavedChanges(Boolean(newUsername.trim() || newPassword), { what: 'The new account' })

  const handleAdd = async (event) => {
    event.preventDefault()
    if (submitting) return
    setError(null)
    setSubmitting(true)
    const result = await createUser({ username: newUsername, password: newPassword, roles: newRoles })
    setSubmitting(false)
    if (!result.ok) {
      setError(result.error || 'Unable to create the user.')
      return
    }
    setNewUsername('')
    setNewPassword('')
    setNewRoles(['analyst'])
    refreshIncidents()
  }

  const handleDelete = async (user) => {
    setListError(null)
    const result = await deleteUser(user.id)
    if (!result.ok) setListError(result.error)
    else refreshIncidents()
  }

  const isLastUser = users.length <= 1

  return (
    <section className="space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <Users className="h-5 w-5 text-accent" />
          <h2 className="text-base font-semibold text-fg">Accounts</h2>
          <Badge color="slate">{users.length}</Badge>
        </div>
        <p className="mt-1 text-sm text-fg-muted">
          The local accounts. Each holds one or more roles and may do what they grant together. Change a name, the roles
          or a password, or disable an account, with the pencil. There is always at least one admin that can sign in.
          Which roles must have a second factor is set under Sign-in and sessions.
        </p>
      </div>

      {listError && <ErrorNote>{listError}</ErrorNote>}

      <ul aria-label="Accounts" className="divide-y divide-line-soft overflow-hidden border border-line">
        {users.map((user) => {
          const isSelf = user.id === currentUser?.id
          const deleteDisabled = isLastUser || isSelf
          const deleteTitle = isLastUser
            ? 'Cannot delete the last remaining user'
            : isSelf
              ? 'You cannot delete your own account'
              : `Delete user "${user.username}"`
          const resetTitle = isSelf
            ? 'You cannot reset your own: sign in with a recovery code, then turn it off under My account'
            : !user.secondFactor
              ? 'The account has no second factor'
              : `Reset the second factor of "${user.username}"`
          const resetDisabled = isSelf || !user.secondFactor
          return (
            <li
              key={user.id}
              className="flex items-center justify-between gap-3 px-3 py-2.5"
              onContextMenu={(event) =>
                menu(event, {
                  title: user.username,
                  actions: [
                    { label: 'Edit…', icon: Pencil, onSelect: () => setEditing(user) },
                    { label: 'Sessions…', icon: MonitorSmartphone, onSelect: () => setSessionsOf(user) },
                    {
                      label: 'Reset the second factor…',
                      icon: ShieldOff,
                      disabled: resetDisabled,
                      title: resetDisabled ? resetTitle : undefined,
                      onSelect: () => setResetting(user),
                    },
                  ],
                  copy: [{ label: 'Copy the name', text: user.username }],
                  danger: [
                    {
                      label: 'Delete',
                      icon: Trash2,
                      disabled: deleteDisabled,
                      title: deleteDisabled ? deleteTitle : undefined,
                      onSelect: () => handleDelete(user),
                    },
                  ],
                })
              }
            >
              <div className="min-w-0">
                <div className="flex items-center gap-2">
                  <span
                    className={`truncate text-sm font-medium ${user.disabled ? 'text-fg-muted line-through' : 'text-fg'}`}
                  >
                    {user.username}
                  </span>
                  {isSelf && <Badge color="cyan">You</Badge>}
                  {user.disabled && (
                    <Badge color="slate">
                      <Ban className="h-3 w-3" aria-hidden="true" />
                      Disabled
                    </Badge>
                  )}
                </div>
                <p className="mt-0.5 text-xs text-fg-muted">Created {formatRelative(user.createdAt)}</p>
              </div>
              <div className="flex shrink-0 items-center gap-2">
                <FactorBadge user={user} />
                <RoleChips roles={rolesOf(user)} className="justify-end" />
                <Button
                  variant="ghost"
                  size="xs"
                  icon={MonitorSmartphone}
                  title={`The sessions of "${user.username}"`}
                  aria-label={`Sessions of ${user.username}`}
                  onClick={() => setSessionsOf(user)}
                  className="text-fg-muted hover:text-fg"
                />
                <Button
                  variant="ghost"
                  size="xs"
                  icon={ShieldOff}
                  disabled={resetDisabled}
                  title={resetTitle}
                  aria-label={`Reset the second factor of ${user.username}`}
                  onClick={() => setResetting(user)}
                  className="text-fg-muted hover:text-high"
                />
                <Button
                  variant="ghost"
                  size="xs"
                  icon={Pencil}
                  title={`Change the account "${user.username}"`}
                  aria-label={`Edit user ${user.username}`}
                  onClick={() => setEditing(user)}
                  className="text-fg-muted hover:text-fg"
                />
                <Button
                  variant="ghost"
                  size="xs"
                  icon={Trash2}
                  disabled={deleteDisabled}
                  title={deleteTitle}
                  aria-label={`Delete user ${user.username}`}
                  onClick={() => handleDelete(user)}
                  className="text-fg-muted hover:text-high"
                />
              </div>
            </li>
          )
        })}
      </ul>

      {sessionsOf && (
        <AccountSessionsDialog
          user={sessionsOf}
          isSelf={sessionsOf.id === currentUser?.id}
          onClose={() => setSessionsOf(null)}
        />
      )}
      {resetting && <ResetFactorDialog user={resetting} onClose={() => setResetting(null)} onDone={refreshUsers} />}

      {editing && (
        <EditAccountDialog
          user={editing}
          isSelf={editing.id === currentUser?.id}
          onClose={() => setEditing(null)}
          // A new name moves the assigned incidents; a disabled account leaves the assignee list.
          onSaved={refreshIncidents}
        />
      )}

      <div>
        <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-fg-muted">Add user</h3>
        <form onSubmit={handleAdd} className="space-y-3">
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="add-username" className={LABEL_CLASS}>
                Username
              </label>
              <input
                id="add-username"
                type="text"
                value={newUsername}
                onChange={(event) => setNewUsername(event.target.value)}
                placeholder="e.g. j.doe"
                autoComplete="off"
                className={INPUT_CLASS}
              />
            </div>
            <div>
              <label htmlFor="add-password" className={LABEL_CLASS}>
                Password
              </label>
              <input
                id="add-password"
                type="password"
                value={newPassword}
                onChange={(event) => setNewPassword(event.target.value)}
                placeholder="At least 8 characters"
                autoComplete="new-password"
                className={INPUT_CLASS}
              />
            </div>
          </div>

          {error && <ErrorNote>{error}</ErrorNote>}

          <RolePicker idPrefix="add" value={newRoles} onChange={setNewRoles} />

          <div className="flex justify-end">
            <Button waiting={submitting} type="submit" icon={UserPlus} disabled={submitting || newRoles.length === 0}>
              {submitting ? 'Adding…' : 'Add user'}
            </Button>
          </div>
        </form>
      </div>
    </section>
  )
}
