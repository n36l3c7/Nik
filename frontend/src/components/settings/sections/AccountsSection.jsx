import { useState } from 'react'
import { AlertCircle, Ban, Pencil, ShieldCheck, Trash2, User, UserPlus, Users } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { useIncidents } from '../../../context/IncidentContext.jsx'
import { formatRelative } from '../../../lib/time.js'
import { Badge, Button, Modal, Select } from '../../ui/index.js'

/*
 * Accounts settings section (admin only): the local accounts. An admin adds
 * an account, changes its name, role or password, disables it (it keeps its
 * history and cannot sign in) or deletes it. The server refuses what would
 * lock everybody out (the last admin, one's own role) and records each
 * change in the audit log.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent'

const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-fg'

const ROLE_OPTIONS = [
  { value: 'analyst', label: 'Analyst' },
  { value: 'admin', label: 'Admin' },
]

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

/** Change one account: only what was edited is sent. */
function EditAccountDialog({ user, isSelf, onClose, onSaved }) {
  const { updateUser } = useAuth()
  const [username, setUsername] = useState(user.username)
  const [role, setRole] = useState(user.role)
  const [password, setPassword] = useState('')
  const [disabled, setDisabled] = useState(Boolean(user.disabled))
  const [error, setError] = useState(null)
  const [saving, setSaving] = useState(false)

  const changes = {}
  if (username.trim() !== user.username) changes.username = username.trim()
  if (role !== user.role) changes.role = role
  if (password) changes.password = password
  if (disabled !== Boolean(user.disabled)) changes.disabled = disabled
  const dirty = Object.keys(changes).length > 0

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
      onClose={onClose}
      title={`Account: ${user.username}`}
      maxWidth="max-w-md"
      footer={
        <>
          <Button variant="ghost" onClick={onClose} disabled={saving}>
            Cancel
          </Button>
          <Button type="submit" form="edit-account-form" disabled={saving || !dirty}>
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

        <div>
          <Select value={role} onChange={setRole} options={ROLE_OPTIONS} label="Role" disabled={isSelf} />
          {isSelf && <p className="mt-1 text-xs text-fg-muted">You cannot change your own role.</p>}
        </div>

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
            At least 8 characters. Setting it signs the account out everywhere and unlocks it.
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
  const { users, currentUser, createUser, deleteUser } = useAuth()
  const { refreshIncidents } = useIncidents()

  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('analyst')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)
  const [editing, setEditing] = useState(null)
  const [listError, setListError] = useState(null)

  const handleAdd = async (event) => {
    event.preventDefault()
    if (submitting) return
    setError(null)
    setSubmitting(true)
    const result = await createUser({ username: newUsername, password: newPassword, role: newRole })
    setSubmitting(false)
    if (!result.ok) {
      setError(result.error || 'Unable to create the user.')
      return
    }
    setNewUsername('')
    setNewPassword('')
    setNewRole('analyst')
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
          Local analyst and admin accounts. Change a name, a role or a password, or disable an account, with the pencil.
          There is always at least one admin that can sign in.
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
          return (
            <li key={user.id} className="flex items-center justify-between gap-3 px-3 py-2.5">
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
                <Badge color={user.role === 'admin' ? 'cyan' : 'slate'}>
                  {user.role === 'admin' ? (
                    <ShieldCheck className="h-3 w-3" aria-hidden="true" />
                  ) : (
                    <User className="h-3 w-3" aria-hidden="true" />
                  )}
                  {user.role === 'admin' ? 'Admin' : 'Analyst'}
                </Badge>
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

          <div className="flex flex-wrap items-center justify-between gap-3">
            <Select value={newRole} onChange={setNewRole} options={ROLE_OPTIONS} label="Role" />
            <Button type="submit" icon={UserPlus} disabled={submitting} className="ml-auto">
              {submitting ? 'Adding…' : 'Add user'}
            </Button>
          </div>
        </form>
      </div>
    </section>
  )
}
