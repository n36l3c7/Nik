import { useState } from 'react'
import { UserPlus, Trash2, AlertCircle, ShieldCheck, User } from 'lucide-react'
import { useAuth } from '../../context/AuthContext.jsx'
import { formatRelative } from '../../utils/time.js'
import { Modal, Button, Badge, Select } from '../ui/index.js'

/*
 * ============================================================================
 * UserManagement
 * ============================================================================
 *
 * Admin modal to review and manage local accounts:
 *  - lists every user with role and creation time,
 *  - adds a new user (username + password + role),
 *  - deletes users (never the last remaining one, never yourself).
 *
 * All mutations go through `useAuth`, which also records them in the audit log.
 */

// Shared input styling (matches the design system used across the app).
const INPUT_CLASS =
  'w-full rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm text-slate-900 ' +
  'placeholder:text-slate-400 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-cyan-500 ' +
  'dark:border-slate-800 dark:bg-slate-950 dark:text-white dark:placeholder:text-slate-500'

const LABEL_CLASS = 'mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300'

const ROLE_OPTIONS = [
  { value: 'analyst', label: 'Analyst' },
  { value: 'admin', label: 'Admin' },
]

export default function UserManagement({ open, onClose }) {
  const { users, currentUser, createUser, deleteUser } = useAuth()

  // "Add user" form state.
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
    // Reset the form on success; the list updates from context automatically.
    setNewUsername('')
    setNewPassword('')
    setNewRole('analyst')
  }

  const handleDelete = (user) => {
    deleteUser(user.id, currentUser?.username)
  }

  const isLastUser = users.length <= 1

  return (
    <Modal open={open} onClose={onClose} title="User management" maxWidth="max-w-xl">
      <div className="space-y-6">
        {/* -------------------------------------------------------------- */}
        {/* Existing users                                                 */}
        {/* -------------------------------------------------------------- */}
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            Users ({users.length})
          </h3>
          <ul className="divide-y divide-slate-200 overflow-hidden rounded-lg border border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {users.map((user) => {
              const isSelf = user.id === currentUser?.id
              // A user cannot be removed if they are the last account, or if
              // they are the currently signed-in analyst.
              const deleteDisabled = isLastUser || isSelf
              const deleteTitle = isLastUser
                ? 'Cannot delete the last remaining user'
                : isSelf
                  ? 'You cannot delete your own account'
                  : `Delete user "${user.username}"`

              return (
                <li
                  key={user.id}
                  className="flex items-center justify-between gap-3 px-3 py-2.5"
                >
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="truncate text-sm font-medium text-slate-800 dark:text-slate-100">
                        {user.username}
                      </span>
                      {isSelf && <Badge color="cyan">You</Badge>}
                    </div>
                    <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                      Created {formatRelative(user.createdAt)}
                    </p>
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
                      onClick={() => handleDelete(user)}
                      className="text-slate-400 hover:text-red-600 dark:text-slate-500 dark:hover:text-red-400"
                    />
                  </div>
                </li>
              )
            })}
          </ul>
        </section>

        {/* -------------------------------------------------------------- */}
        {/* Add a new user                                                 */}
        {/* -------------------------------------------------------------- */}
        <section>
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">
            Add user
          </h3>
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
                className="flex items-start gap-2 rounded-lg border border-red-200 bg-red-50 px-3 py-2 text-sm text-red-700 dark:border-red-900 dark:bg-red-950/60 dark:text-red-400"
              >
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
                <span>{error}</span>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-3">
              <Select
                value={newRole}
                onChange={setNewRole}
                options={ROLE_OPTIONS}
                label="Role"
              />
              <Button
                type="submit"
                icon={UserPlus}
                disabled={submitting}
                className="ml-auto"
              >
                {submitting ? 'Adding…' : 'Add user'}
              </Button>
            </div>
          </form>
        </section>
      </div>
    </Modal>
  )
}
