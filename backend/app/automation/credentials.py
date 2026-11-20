"""Stored credentials: a secret kept once, and named by the instances that use it.

A credential has a name (``vt_key``), a kind and a value. ``secret`` is one
value (an API key, a token); ``pair`` is a user name, which is shown, and a
password, which is not. The value is encrypted as the secrets of an instance
are, and no route gives it back.

An instance uses one by **naming it where it would hold the value**. What the
instance stores in that field is the reference, written as a person may type
it too:

    {{ credentials.vt_key }}                 a secret
    {{ credentials.proxy_account.username }}  the user name of a pair
    {{ credentials.proxy_account.password }}  its password

The reference stands alone in the field: it is not a template, and nothing is
computed from it. It is put in place of the value at the moment a request is
built (``resolved``, called where the secrets of the instance are read for a
runtime), so a value that changes here is the one every instance sends next,
and a connector file never knows a credential exists.

**That field is the only place the name works.** A playbook, a script, the
playground and the templates of a connector file cannot read ``credentials``:
whoever writes a playbook could otherwise send a secret to any host the
playbook may reach. The expression language refuses the name wherever it is
evaluated (``ELSEWHERE``).

A reference to a credential that is not there any more (a database put back
from before it was made) fails the command with a sentence that names it.
Nothing is tried in its place.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..core import vault
from ..core.models import Connection, Connector, Credential
from . import expressions as ex

KINDS = ("secret", "pair")
PARTS = ("username", "password")
NAME_RE = re.compile(r"^[a-z][a-z0-9_-]{0,39}$")
VALUE_MAX = 20_000
# One reference and nothing else, as it is written in a field of an instance.
_REFERENCE = re.compile(r"^\s*\{\{\s*credentials\.([a-z][a-z0-9_-]*)(?:\.([a-z_]+))?\s*\}\}\s*$")
_MENTION = re.compile(r"\{\{\s*credentials\b")

# What the expression language says where the name is read outside a field of an instance.
ELSEWHERE = ex.CREDENTIALS_ELSEWHERE
HOW = (
    "A credential is named alone in the field, as {{ credentials.<name> }} "
    "(a pair: {{ credentials.<name>.username }} or {{ credentials.<name>.password }})"
)
# The two parts of a pair, by the credentials of a connector that are two values of that sort.
PAIR_FIELDS = (("username", "password"), ("client_id", "client_secret"))


class CredentialError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass(frozen=True)
class Reference:
    name: str
    part: str = ""  # "" for a secret; "username" or "password" of a pair

    @property
    def text(self) -> str:
        return "{{ credentials." + self.name + (f".{self.part}" if self.part else "") + " }}"


def mentions(value: Any) -> bool:
    """Whether a text reads ``credentials`` somewhere: a reference, or an attempt at one."""
    return isinstance(value, str) and _MENTION.search(value) is not None


def reference(value: Any) -> Reference | None:
    """The credential a value of an instance names, or None for a value that was typed."""
    if not isinstance(value, str) or "{{" not in value:
        return None
    found = _REFERENCE.match(value)
    if found is None or (found.group(2) or "") not in ("", *PARTS):
        return None
    return Reference(found.group(1), found.group(2) or "")


def by_name(db: OrmSession, name: str) -> Credential | None:
    return db.scalars(select(Credential).where(Credential.name == name)).first()


def _fits(row: Credential, found: Reference) -> None:
    if row.kind == "pair" and not found.part:
        raise CredentialError(
            f'"{row.name}" is a user name and a password: read {{{{ credentials.{row.name}.username }}}} '
            f"or {{{{ credentials.{row.name}.password }}}}"
        )
    if row.kind != "pair" and found.part:
        raise CredentialError(f'"{row.name}" is one value: read it as {{{{ credentials.{row.name} }}}}')


def checked(db: OrmSession, value: Any) -> Any:
    """A value an instance is given for a secret, as it is stored: a typed value as it is, a reference
    in its one spelling. Raises ``CredentialError`` for a reference that is badly written, names a
    credential that does not exist, or asks a part its kind does not have."""
    if not isinstance(value, str) or not mentions(value):
        return value
    found = reference(value)
    if found is None:
        raise CredentialError(HOW)
    row = by_name(db, found.name)
    if row is None:
        raise CredentialError(f'There is no credential called "{found.name}": make it in Settings, Credentials')
    _fits(row, found)
    return found.text


def _value(row: Credential, found: Reference) -> str:
    if found.part == "username":
        return row.username
    value = vault.decrypt(row.secret) if row.secret else ""
    if value is None:
        raise CredentialError(
            f'The credential "{row.name}" cannot be read since SECRET_KEY changed: '
            "type its value again in Settings, Credentials"
        )
    return value


def resolved(db: OrmSession, secrets: dict[str, Any], instance: str = "") -> dict[str, Any]:
    """The secrets of an instance with every reference replaced by the value it names, read now.
    Raises ``CredentialError`` when a credential is missing or cannot be read: nothing takes its place."""
    out: dict[str, Any] = {}
    rows: dict[str, Credential | None] = {}
    for field, value in (secrets or {}).items():
        found = reference(value)
        if found is None:
            out[field] = value
            continue
        if found.name not in rows:
            rows[found.name] = by_name(db, found.name)
        row = rows[found.name]
        whose = f'The instance "{instance}"' if instance else "The instance"
        if row is None:
            raise CredentialError(
                f'{whose} uses the credential "{found.name}", which does not exist: make it again in '
                "Settings, Credentials, or give the instance another"
            )
        try:
            _fits(row, found)
        except CredentialError as error:
            raise CredentialError(f"{whose} cannot use a credential as it names it. {error.message}") from None
        out[field] = _value(row, found)
    return out


def known(db: OrmSession, secrets: dict[str, Any]) -> dict[str, Any]:
    """As ``resolved``, for who only compares values: a secret whose credential is missing or cannot be
    read is left out instead of stopping everything."""
    out: dict[str, Any] = {}
    for field, value in (secrets or {}).items():
        try:
            out.update(resolved(db, {field: value}))
        except CredentialError:
            continue
    return out


def named(db: OrmSession, secrets: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """field → the credential it names, for the fields of an instance that name one: what the form shows
    in place of a value. ``missing`` says the credential is not there any more."""
    out: dict[str, dict[str, Any]] = {}
    for field, value in (secrets or {}).items():
        found = reference(value)
        if found is not None:
            out[field] = {"name": found.name, "part": found.part, "missing": by_name(db, found.name) is None}
    return out


def uses(db: OrmSession) -> dict[str, list[dict[str, Any]]]:
    """credential name → where it is used: one entry for each key of each instance that names it."""
    from . import instance_keys

    connectors = {row.id: row.name for row in db.execute(select(Connector.id, Connector.name))}
    found: dict[str, list[dict[str, Any]]] = {}
    for connection in db.scalars(select(Connection).order_by(func.lower(Connection.name))):
        for key in instance_keys.keys_of(connection):
            fields: dict[str, list[str]] = {}
            for field, value in key.secrets.items():
                held = reference(value)
                if held is not None:
                    fields.setdefault(held.name, []).append(field)
            for name, which in fields.items():
                found.setdefault(name, []).append(
                    {
                        "instance": connection.id,
                        "name": connection.name,
                        "connector": connection.connector_id,
                        "connectorName": connectors.get(connection.connector_id, connection.connector_id),
                        "key": key.id,
                        "keyName": key.name,
                        "fields": sorted(which),
                    }
                )
    return found


def used_text(entries: list[dict[str, Any]]) -> str:
    """ "Shodan production, Proxy (Key 2)": the instances that use a credential, in a sentence."""
    from . import instance_keys

    seen: list[str] = []
    for entry in entries:
        text = entry["name"] + (f" ({entry['keyName']})" if entry["key"] != instance_keys.MAIN else "")
        if text not in seen:
            seen.append(text)
    return ", ".join(seen[:10]) + (f" and {len(seen) - 10} more" if len(seen) > 10 else "")


def clean_name(db: OrmSession, name: Any, but: Credential | None = None) -> str:
    text = str(name or "").strip()
    if not NAME_RE.match(text):
        raise CredentialError(
            "The name of a credential is a lower-case letter, then lower-case letters, digits, _ or - (40 at most)"
        )
    taken = by_name(db, text)
    if taken is not None and (but is None or taken.id != but.id):
        raise CredentialError(f'A credential called "{text}" exists already')
    return text


def clean_value(value: Any, what: str = "The value") -> str:
    if not isinstance(value, str) or value == "":
        raise CredentialError(f"{what} is needed")
    if len(value) > VALUE_MAX:
        raise CredentialError(f"{what} is too long")
    if mentions(value):
        raise CredentialError("A credential holds a value, not the name of another credential")
    return value


def pair_fields(names: list[str]) -> tuple[str, str] | None:
    """The two secrets of a connector that a pair fills together, or None when it has no such two."""
    return next((pair for pair in PAIR_FIELDS if pair[0] in names and pair[1] in names), None)


def what(row: Credential) -> str:
    return "a user name and a password" if row.kind == "pair" else "one value"
