"""Roles and what each of them may do.

An account (a user or an API key) holds one or more **roles**. A role is a
tag that grants a set of **permissions**; what an account may do is the union
of the permissions of its roles. Routes ask for a permission, never for a
role, so a new role is a line in the table below.

Some roles and permissions belong to features that later releases of the 4.x
series add (playbooks, connectors, dashboards): they are accepted and stored
from 4.0 on, so an account does not have to be set up again when the feature
arrives.
"""

from __future__ import annotations

from collections.abc import Iterable

# Permissions ---------------------------------------------------------------
READ = "read"  # incidents, artifacts, indicators
WRITE = "write"  # change, upload, analyse
AUTOMATION_RUN = "automation.run"  # run a playbook, approve, stop a run
AUTOMATION_EDIT = "automation.edit"  # playbooks and scripts
AUTOMATION_DEBUG = "automation.debug"
AUTOMATION_OPEN = "automation.open"  # egress to any host, data classes
CONNECTORS_MANAGE = "connectors.manage"
RULES_MANAGE = "rules.manage"  # YARA, capa, FLIRT, script signatures
AUDIT_READ = "audit.read"
LISTS_MANAGE = "lists.manage"
DASHBOARDS_SHARE = "dashboards.share"
INCIDENTS_CONFIGURE = "incidents.configure"  # types, fields, layouts, SLA
CONTENT_MANAGE = "content.manage"  # content packs
ADMIN = "admin"  # accounts, API keys, storage, backup, settings

PERMISSIONS: tuple[str, ...] = (
    READ,
    WRITE,
    AUTOMATION_RUN,
    AUTOMATION_EDIT,
    AUTOMATION_DEBUG,
    AUTOMATION_OPEN,
    CONNECTORS_MANAGE,
    RULES_MANAGE,
    AUDIT_READ,
    LISTS_MANAGE,
    DASHBOARDS_SHARE,
    INCIDENTS_CONFIGURE,
    CONTENT_MANAGE,
    ADMIN,
)
ALL: frozenset[str] = frozenset(PERMISSIONS)

# Roles -----------------------------------------------------------------------
# The system account of the automation engine: never given to a person or a key.
SYSTEM_ROLE = "automation"
# Its name: what a playbook changes is signed with it, so nobody else may take it.
SYSTEM_USER = "nik-automation"

ROLE_PERMISSIONS: dict[str, frozenset[str]] = {
    "viewer": frozenset({READ}),
    "analyst": frozenset({READ, WRITE, AUTOMATION_RUN}),
    "playbooks": frozenset({AUTOMATION_RUN, AUTOMATION_EDIT, AUTOMATION_DEBUG, LISTS_MANAGE}),
    "connectors": frozenset({CONNECTORS_MANAGE}),
    "rules": frozenset({RULES_MANAGE}),
    "audit": frozenset({AUDIT_READ}),
    "dashboards": frozenset({DASHBOARDS_SHARE}),
    "admin": ALL,
    SYSTEM_ROLE: frozenset({READ, WRITE}),
}

# The roles an admin can give, in the order they are shown.
ROLES: tuple[str, ...] = ("viewer", "analyst", "playbooks", "connectors", "rules", "audit", "dashboards", "admin")


class RoleError(ValueError):
    """A list of roles that cannot be stored; the message is safe to show."""


def permissions_of(roles: Iterable[str] | None) -> frozenset[str]:
    """Everything the roles grant together (unknown names grant nothing)."""
    granted: set[str] = set()
    for role in roles or ():
        granted |= ROLE_PERMISSIONS.get(role, frozenset())
    return frozenset(granted)


def clean_roles(roles: object) -> list[str]:
    """The roles as they are stored: known names, once each, in the order of
    ``ROLES``. Raises ``RoleError`` for an empty list, an unknown name or the
    system role."""
    if not isinstance(roles, (list, tuple, set, frozenset)) or not roles:
        raise RoleError("At least one role is required")
    wanted = set()
    for role in roles:
        if not isinstance(role, str) or role not in ROLES:
            raise RoleError("Unknown role: the roles are " + ", ".join(ROLES))
        wanted.add(role)
    return [role for role in ROLES if role in wanted]


def stored_roles(value: object) -> list[str]:
    """The roles read back from a row: a list of known names, [] for anything else."""
    if not isinstance(value, list):
        return []
    return [role for role in value if isinstance(role, str) and role in ROLE_PERMISSIONS]
