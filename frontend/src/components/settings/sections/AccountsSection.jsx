import { useState } from 'react'
import { AlertCircle, ShieldCheck, Trash2, User, UserPlus, Users } from 'lucide-react'
import { useAuth } from '../../../context/AuthContext.jsx'
import { formatRelative } from '../../../lib/time.js'
import { Badge, Button, Select } from '../../ui/index.js'

/*
 * Accounts settings section (admin only): review and manage local accounts.
 * Ported from the old standalone UserManagement modal into the sectioned
 * SettingsPanel. All mutations go through useAuth, which records them in the
 * audit log.
 */

const INPUT_CLASS =
  'w-full border border-line bg-panel px-3 py-2 text-sm text-fg ' +
  'placeholder:text-fg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ' +
  ''

const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-fg'

const ROLE_OPTIONS = [
  { value: 'analyst', label: 'Analyst' },
  { value: 'admin', label: 'Admin' },
]

export default function AccountsSection() {
  const { users, currentUser, createUser, deleteUser } = useAuth()

  const [newUsername, setNewUsername] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [newRole, setNewRole] = useState('analyst')
  const [error, setError] = useState(null)
  const [submitting, setSubmitting] = useState(false)

  const handleAdd = async (event) => {
    event.preventDefault()
    if (submitting) return
    setError(null)
    setSubmitting(true)
    const result = await createUser(
      { username: newUsername, password: newPassword, role: newRole },
      currentUser?.username,
    )
    setSubmitting(false)
    if (!result.ok) {
      setError(result.error || 'Unable to create the user.')
      return
    }
    setNewUsername('')
    setNewPassword('')
    setNewRole('analyst')
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
          Local analyst and admin accounts. You cannot delete the last account or your own.
        </p>
      </div>

      <ul className="divide-y divide-line-soft overflow-hidden border border-line">
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
                  <span className="truncate text-sm font-medium text-fg">{user.username}</span>
                  {isSelf && <Badge color="cyan">You</Badge>}
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
                  icon={Trash2}
                  disabled={deleteDisabled}
                  title={deleteTitle}
                  aria-label={`Delete user ${user.username}`}
                  onClick={() => deleteUser(user.id, currentUser?.username)}
                  className="text-fg-muted hover:text-high"
                />
              </div>
            </li>
          )
        })}
      </ul>

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

          {error && (
            <div
              role="alert"
              className="flex items-start gap-2 border border-high-line bg-high-soft px-3 py-2 text-sm text-high"
            >
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
              <span>{error}</span>
            </div>
          )}

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
