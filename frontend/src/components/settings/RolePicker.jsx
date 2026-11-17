import { ShieldCheck } from 'lucide-react'
import { cleanRoles, offeredRoles, roleLabel, toggleRole } from '../../domain/permissions.js'
import { Badge } from '../ui/index.js'

/*
 * Roles are tags: an account or a key holds one or more, and may do what
 * they grant together. RoleChips shows them; RolePicker lets an admin choose
 * them, each with what it grants.
 */

/** The roles of an account or key, one chip each (`admin` stands out). */
export function RoleChips({ roles, className = '' }) {
  const held = cleanRoles(roles)
  return (
    <span className={`inline-flex flex-wrap items-center gap-1 ${className}`} aria-label="Roles">
      {held.length === 0 && <Badge color="amber">No role</Badge>}
      {held.map((id) => (
        <Badge key={id} color={id === 'admin' ? 'cyan' : 'slate'}>
          {id === 'admin' && <ShieldCheck className="h-3 w-3" aria-hidden="true" />}
          {roleLabel(id)}
        </Badge>
      ))}
    </span>
  )
}

/**
 * Choose the roles of an account or a key.
 *
 * @param {{
 *   value: string[],                      // the roles chosen
 *   onChange: (roles: string[]) => void,
 *   held?: string[],                      // what the account holds now (keeps a role of a later release listed)
 *   locked?: string[],                    // roles that cannot be taken away here
 *   lockedNote?: string,                  // why
 *   legend?: string,
 *   idPrefix: string,
 * }} props
 */
export default function RolePicker({
  value,
  onChange,
  held = [],
  locked = [],
  lockedNote = '',
  legend = 'Roles',
  idPrefix,
}) {
  const chosen = new Set(value)
  return (
    <fieldset>
      <legend className="mb-1.5 block text-sm font-medium text-fg">{legend}</legend>
      <ul className="divide-y divide-line-soft border border-line">
        {offeredRoles([...held, ...value]).map((role) => {
          const id = `${idPrefix}-role-${role.id}`
          const isLocked = locked.includes(role.id) && chosen.has(role.id)
          return (
            <li key={role.id}>
              <label htmlFor={id} className="flex cursor-pointer items-start gap-2.5 px-3 py-2 hover:bg-canvas">
                <input
                  id={id}
                  type="checkbox"
                  checked={chosen.has(role.id)}
                  disabled={isLocked}
                  onChange={(event) => onChange(toggleRole(value, role.id, event.target.checked))}
                  aria-describedby={`${id}-what`}
                  className="mt-0.5 accent-[var(--color-accent)]"
                />
                <span className="min-w-0">
                  <span className="block text-sm font-medium text-fg">{role.label}</span>
                  <span id={`${id}-what`} className="block text-xs text-fg-muted">
                    {role.description}
                    {isLocked && lockedNote ? ` ${lockedNote}` : ''}
                  </span>
                </span>
              </label>
            </li>
          )
        })}
      </ul>
      <p className="mt-1 text-xs text-fg-muted">
        Roles add up: an account may do what its roles grant together. Choose at least one.
      </p>
    </fieldset>
  )
}
