"""The sign-in policy: what an administrator sets under Settings → Sign-in and sessions.

One row of ``settings`` holds it. Nothing in it is on by itself: with the
values a server starts with, no role needs a second factor and
administrators sign in from anywhere. What is always there are the times a
session lives and the waits after failed sign-ins, whose defaults are below.

- ``requiredRoles``: the roles whose accounts must have a second factor.
- ``idleMinutes`` / ``idleMinutesAdmin``: a session ends after this long
  without the person doing anything (0: never), for everybody and for the
  accounts that hold the administrator's permission.
- ``lifetimeHours``: a session ends this long after the sign-in, used or not.
- ``attemptsBeforeWait``, ``firstWaitSeconds``, ``maxWaitMinutes``: after so
  many failures in a row a sign-in waits, twice as long after each further
  failure, up to the maximum. ``notifyAfter``: the administrators are told
  once when a run of failures reaches this length.
- ``adminNetworks``: when not empty, the accounts and keys that hold the
  administrator's permission are accepted from these networks only.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .config import settings
from .models import Setting
from .permissions import ADMIN, ROLES, permissions_of

SETTINGS_ID = 5  # 1 the analysts' settings, 2 automation, 3 the catalogue of packs, 4 the workers' state

# The limits of each number: (smallest, largest).
LIMITS: dict[str, tuple[int, int]] = {
    "idleMinutes": (0, 7 * 24 * 60),
    "idleMinutesAdmin": (0, 7 * 24 * 60),
    "lifetimeHours": (1, 30 * 24),
    "attemptsBeforeWait": (3, 50),
    "firstWaitSeconds": (5, 3600),
    "maxWaitMinutes": (1, 24 * 60),
    "notifyAfter": (3, 1000),
}
MAX_NETWORKS = 200
# What the screen recommends where the default is looser, so that an upgrade changes nothing by itself.
RECOMMENDED = {"requiredRoles": ["admin"], "idleMinutesAdmin": 30}


class PolicyError(ValueError):
    """A policy that cannot be stored; the message is safe to show."""


def defaults() -> dict[str, Any]:
    return {
        "requiredRoles": [],
        # A working day: with the lifetime below, a session left alone ends a little sooner than before 6.7.
        "idleMinutes": 480,
        "idleMinutesAdmin": 480,
        # What SESSION_TTL_HOURS says (12 unless the operator changed it), as before 6.7.
        "lifetimeHours": max(1, min(LIMITS["lifetimeHours"][1], settings.SESSION_TTL_HOURS)),
        "attemptsBeforeWait": 5,
        "firstWaitSeconds": 30,
        "maxWaitMinutes": 15,
        "notifyAfter": 10,
        "adminNetworks": [],
    }


def clean_network(value: object) -> str:
    """A network as it is stored (``10.1.0.0/16``, ``2001:db8::/32``; a single address becomes /32 or /128)."""
    text = str(value or "").strip()
    try:
        return str(ipaddress.ip_network(text, strict=False))
    except ValueError:
        raise PolicyError(
            f'"{text[:60]}" is not a network: write it as 10.1.0.0/16 or 2001:db8::/32, or a single address'
        ) from None


def clean(doc: object, base: dict[str, Any] | None = None) -> dict[str, Any]:
    """The policy as it is stored: ``doc`` over ``base`` (the defaults when none), every value checked."""
    policy = dict(base or defaults())
    if not isinstance(doc, dict):
        raise PolicyError("The policy must be an object")
    if "requiredRoles" in doc:
        wanted = doc["requiredRoles"]
        if not isinstance(wanted, list) or any(role not in ROLES for role in wanted):
            raise PolicyError("Unknown role: the roles are " + ", ".join(ROLES))
        policy["requiredRoles"] = [role for role in ROLES if role in wanted]
    for name, (least, most) in LIMITS.items():
        if name not in doc:
            continue
        value = doc[name]
        if isinstance(value, bool) or not isinstance(value, int) or not least <= value <= most:
            raise PolicyError(f"{name} must be a whole number from {least} to {most}")
        policy[name] = value
    if policy["firstWaitSeconds"] > policy["maxWaitMinutes"] * 60:
        raise PolicyError("The first wait cannot be longer than the longest one")
    if "adminNetworks" in doc:
        wanted = doc["adminNetworks"]
        if not isinstance(wanted, list) or len(wanted) > MAX_NETWORKS:
            raise PolicyError(f"The networks must be a list of at most {MAX_NETWORKS}")
        networks: list[str] = []
        for entry in wanted:
            network = clean_network(entry)
            if network not in networks:
                networks.append(network)
        policy["adminNetworks"] = networks
    return policy


def load(db: OrmSession) -> dict[str, Any]:
    """The policy in force: what is stored over the defaults (a stored value that no longer fits is ignored)."""
    row = db.get(Setting, SETTINGS_ID)
    stored = (row.doc if row else None) or {}
    policy = defaults()
    for name in policy:
        if name not in stored:
            continue
        try:
            policy = clean({name: stored[name]}, policy)
        except PolicyError:
            continue
    return policy


def store(db: OrmSession, policy: dict[str, Any]) -> None:
    """Keep the policy (the caller commits)."""
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=dict(policy)))
        return
    row.doc = dict(policy)
    flag_modified(row, "doc")


def is_admin(roles: list[str]) -> bool:
    return ADMIN in permissions_of(roles)


def idle_seconds(policy: dict[str, Any], roles: list[str]) -> int:
    """How long a session of an account with these roles may stay unused; 0 for no limit."""
    return 60 * int(policy["idleMinutesAdmin"] if is_admin(roles) else policy["idleMinutes"])


def lifetime_seconds(policy: dict[str, Any]) -> int:
    return 3600 * int(policy["lifetimeHours"])


def must_have_factor(policy: dict[str, Any], roles: list[str]) -> bool:
    return bool(set(policy["requiredRoles"]) & set(roles))


def admin_networks(policy: dict[str, Any]) -> list:
    return [ipaddress.ip_network(network) for network in policy["adminNetworks"]]
