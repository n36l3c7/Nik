/*
 * Roles and what they grant, as the server defines them
 * (backend/app/core/permissions.py). The server decides: this copy is for
 * what the interface shows (the role picker and its descriptions) and for the
 * accounts of releases before 4.0, which have a single `role`. What the
 * signed-in account may do comes from `permissions` of GET /api/auth/me.
 */

const READ = 'read'
const WRITE = 'write'

/**
 * Every role an account or a key can hold, in the order they are shown.
 * `shown: false` marks the roles of features that later 4.x releases add:
 * the server stores them already, the picker lists them only on an account
 * that holds one, so nothing is offered that does nothing yet.
 */
export const ROLES = [
  {
    id: 'viewer',
    label: 'Viewer',
    description: 'Reads incidents, artifacts and indicators. Changes nothing.',
    permissions: [READ],
    shown: true,
  },
  {
    id: 'analyst',
    label: 'Analyst',
    description: 'Reads, and works: incidents, uploads, analyses, indicators, the analysts’ settings.',
    permissions: [READ, WRITE, 'automation.run'],
    shown: true,
  },
  {
    id: 'playbooks',
    label: 'Playbooks',
    description: 'Builds playbooks and scripts.',
    permissions: ['automation.run', 'automation.edit', 'automation.debug', 'lists.manage'],
    shown: false,
  },
  {
    id: 'connectors',
    label: 'Connectors',
    description: 'Manages connectors and their connections.',
    permissions: ['connectors.manage'],
    shown: false,
  },
  {
    id: 'rules',
    label: 'Rules',
    description: 'Manages the rule sets: YARA, capa, FLIRT.',
    permissions: ['rules.manage'],
    shown: true,
  },
  {
    id: 'audit',
    label: 'Audit',
    description: 'Reads the audit log.',
    permissions: ['audit.read'],
    shown: true,
  },
  {
    id: 'dashboards',
    label: 'Dashboards',
    description: 'Shares dashboards with others.',
    permissions: ['dashboards.share'],
    shown: false,
  },
  {
    id: 'admin',
    label: 'Admin',
    description: 'Everything, and alone: accounts, API keys, storage, backup, what leaves the server.',
    permissions: null, // every permission
    shown: true,
  },
]

const BY_ID = new Map(ROLES.map((role) => [role.id, role]))
const ORDER = ROLES.map((role) => role.id)

/** Every permission there is (what `admin` grants). */
export const ALL_PERMISSIONS = [
  ...new Set([
    ...ROLES.flatMap((role) => role.permissions ?? []),
    'automation.open',
    'incidents.configure',
    'content.manage',
    'admin',
  ]),
]

/** Known role names, once each, in the order they are shown. */
export function cleanRoles(roles) {
  const held = new Set(Array.isArray(roles) ? roles : [])
  return ORDER.filter((id) => held.has(id))
}

/** The roles of a user or key as the API returns it (a release before 4.0 sent one `role`). */
export function rolesOf(subject) {
  if (!subject) return []
  if (Array.isArray(subject.roles)) return cleanRoles(subject.roles)
  return cleanRoles([subject.role])
}

/** Everything the roles grant together. */
export function permissionsOf(roles) {
  const granted = new Set()
  for (const id of cleanRoles(roles)) {
    for (const permission of BY_ID.get(id).permissions ?? ALL_PERMISSIONS) granted.add(permission)
  }
  return granted
}

/**
 * Whether a user (as GET /api/auth/me returns it) holds one of the permissions.
 * The server's `permissions` list is used when present; the roles otherwise.
 */
export function can(user, ...wanted) {
  if (!user) return false
  const granted = Array.isArray(user.permissions) ? new Set(user.permissions) : permissionsOf(rolesOf(user))
  return wanted.some((permission) => granted.has(permission))
}

export const roleLabel = (id) => BY_ID.get(id)?.label ?? id
export const roleDescription = (id) => BY_ID.get(id)?.description ?? ''

/** "Analyst, Rules" for a list of roles. */
export const describeRoles = (roles) => cleanRoles(roles).map(roleLabel).join(', ') || 'No role'

/** The roles a picker offers: the ones in use now, plus any other the account already holds. */
export function offeredRoles(held = []) {
  const kept = new Set(held)
  return ROLES.filter((role) => role.shown || kept.has(role.id))
}

/** `roles` with one of them switched on or off. */
export function toggleRole(roles, id, on) {
  const next = new Set(roles)
  if (on) next.add(id)
  else next.delete(id)
  return cleanRoles([...next])
}

/** True when both lists hold the same roles. */
export const sameRoles = (a, b) => cleanRoles(a).join() === cleanRoles(b).join()
