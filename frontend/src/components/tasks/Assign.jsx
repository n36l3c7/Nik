import { useId } from 'react'
import { useIncidents } from '../../context/IncidentContext.jsx'
import { ROLES } from '../../domain/permissions.js'

/*
 * Who a task is for, as a form control: the owner of the incident, a user or
 * a role. It holds and gives `{ owner } | { user } | { role }`, the shape the
 * API takes.
 */

const INPUT =
  'border border-line bg-canvas px-2 py-1.5 text-sm text-fg focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-60'
const ROLE_OPTIONS = ROLES.filter((role) => role.shown)

/** What the control starts from for a task the API gave. */
export function assigneeOf(task) {
  const who = task?.assignee ?? {}
  if (who.user) return { user: who.user }
  if (who.role) return { role: who.role }
  return { owner: true }
}

/**
 * @param {{
 *   value: { owner?: boolean, user?: string, role?: string },
 *   onChange: (value: object) => void,
 *   disabled?: boolean,
 *   label?: string,
 * }} props
 */
export default function Assign({ value, onChange, disabled = false, label = 'For' }) {
  const { assignees } = useIncidents()
  const id = useId()
  const mode = value.user !== undefined ? 'user' : value.role !== undefined ? 'role' : 'owner'
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs font-medium text-fg-muted">
        {label}
      </label>
      <div className="flex flex-wrap gap-2">
        <select
          id={id}
          value={mode}
          disabled={disabled}
          onChange={(event) =>
            onChange(
              event.target.value === 'user'
                ? { user: assignees[0] ?? '' }
                : event.target.value === 'role'
                  ? { role: 'analyst' }
                  : { owner: true },
            )
          }
          className={`${INPUT} cursor-pointer`}
        >
          <option value="owner">The owner of the incident</option>
          <option value="user">A user</option>
          <option value="role">A role</option>
        </select>
        {mode === 'user' && (
          <select
            aria-label="The user it is for"
            value={value.user}
            disabled={disabled}
            onChange={(event) => onChange({ user: event.target.value })}
            className={`${INPUT} cursor-pointer`}
          >
            {value.user && !assignees.includes(value.user) && <option value={value.user}>{value.user}</option>}
            {assignees.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        )}
        {mode === 'role' && (
          <select
            aria-label="The role it is for"
            value={value.role}
            disabled={disabled}
            onChange={(event) => onChange({ role: event.target.value })}
            className={`${INPUT} cursor-pointer`}
          >
            {ROLE_OPTIONS.map((role) => (
              <option key={role.id} value={role.id}>
                {role.label}
              </option>
            ))}
          </select>
        )}
      </div>
    </div>
  )
}
