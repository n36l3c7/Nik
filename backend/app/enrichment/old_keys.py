"""The API keys of the sources as they were kept before 6.5, and where they go.

Until 6.5 the look-ups had their own keys (Settings, Threat intelligence; the
table ``integration_keys``). A look-up is now a command of a source's
connector, run on an instance of it with the keys of that instance, so a key
kept the old way has to become the key of an instance.

That cannot be done once and for all at the upgrade: the connector of a source
comes in a pack an administrator installs. So it is done **whenever it can
be**: when Nik starts and when a connector is installed, each connector that a
stored key belongs to and that is installed gets an instance holding the keys
("VirusTotal (from Settings)"), with the limits the look-ups kept for that
source, on or off as the source was. The one key of abuse.ch goes to the three
connectors of its services.

A stored key is deleted only when every connector it belongs to has it. Until
then it stays where it was, encrypted, and Settings says what is missing. A key
that cannot be moved (the vendor had refused it, or it cannot be read since
``SECRET_KEY`` changed) is never deleted here: it is listed for an
administrator to remove.
"""

from __future__ import annotations

import hashlib
import time
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..automation import connector_actions, credentials, instance_keys, state
from ..automation.connector_runtime import AUTH_FIELDS
from ..automation.connectors import ConnectorFile
from ..core import audit, vault
from ..core.models import Connection, Connector, IntegrationKey, Setting
from ..core.security import now_iso

# What a key was stored under before 6.5: the name of the source then, the connectors it is a key of
# now, and the limits the look-ups kept for it (the free tier of each vendor), which the instance takes.
OLD: dict[str, dict[str, Any]] = {
    "virustotal": {"label": "VirusTotal", "connectors": ("virustotal",), "perMinute": 4, "perDay": 500},
    "abuseipdb": {"label": "AbuseIPDB", "connectors": ("abuseipdb",), "perMinute": 60, "perDay": 1000},
    "abusech": {
        "label": "abuse.ch",
        "connectors": ("threatfox", "urlhaus", "malwarebazaar"),
        "perMinute": 60,
        "perDay": 0,
    },
    "otx": {"label": "AlienVault OTX", "connectors": ("otx",), "perMinute": 60, "perDay": 0},
    "urlscan": {"label": "urlscan.io", "connectors": ("urlscan",), "perMinute": 30, "perDay": 1000},
    "greynoise": {"label": "GreyNoise", "connectors": ("greynoise",), "perMinute": 30, "perDay": 50},
    "safebrowsing": {
        "label": "Google Safe Browsing",
        "connectors": ("safebrowsing",),
        "perMinute": 60,
        "perDay": 10_000,
    },
}
ACTOR = "nik"
SUFFIX = " (from Settings)"
STATE_KEY = "lookup_keys_moved"  # {old source: [connector ids that have its keys]}


def key_field(connector: ConnectorFile) -> str | None:
    """The one credential a key of the source is for the connector: the single part of its credentials,
    or its only secret. None when the connector asks for something else than one key."""
    auth = connector.auth
    if auth is not None:
        fields = AUTH_FIELDS.get(auth.type, ())
        return fields[0] if len(fields) == 1 else None
    secrets = [param.name for param in connector.configuration if param.type == "secret"]
    return secrets[0] if len(secrets) == 1 else None


def _movable(db: OrmSession) -> dict[str, list[tuple[IntegrationKey, str]]]:
    """old source → its keys that work, oldest first, each with its secret."""
    found: dict[str, list[tuple[IntegrationKey, str]]] = {}
    for row in db.scalars(select(IntegrationKey).order_by(IntegrationKey.updated_at, IntegrationKey.id)):
        secret = vault.decrypt(row.secret) if row.status == "ok" else None
        if secret and row.provider in OLD:
            found.setdefault(row.provider, []).append((row, secret))
    return found


def _was_on(db: OrmSession, provider: str) -> bool:
    """Whether the source was allowed in the settings of before 6.5 (it was, unless turned off)."""
    from ..routers.settings import SETTINGS_ID as SHARED_ROW

    row = db.get(Setting, SHARED_ROW)
    held = ((row.doc if row is not None else None) or {}).get("enrichment")
    allowed = held.get("providers") if isinstance(held, dict) else None
    return bool(allowed.get(provider, True)) if isinstance(allowed, dict) else True


def _holds(db: OrmSession, connection: Connection, field: str, secret: str) -> bool:
    """Whether a key of the instance is this secret: typed into it, or the value of the credential it names."""
    return any(credentials.known(db, key.secrets).get(field) == secret for key in instance_keys.keys_of(connection))


def _make(
    db: OrmSession, row: Connector, connector: ConnectorFile, field: str, provider: str, keys: list
) -> Connection:
    """The instance that takes over the keys of an old source for one connector (the caller commits)."""
    name, count = f"{connector.name}{SUFFIX}"[:80], 2
    while db.scalars(select(Connection.id).where(func.lower(Connection.name) == name.lower())).first() is not None:
        name, count = f"{connector.name}{SUFFIX} {count}"[:80], count + 1
    now = now_iso()
    first, first_secret = keys[0]
    connection = Connection(
        id=hashlib.sha256(f"lookup-keys-{row.id}-{time.time_ns()}".encode()).hexdigest()[:32],
        name=name,
        connector_id=row.id,
        config={},
        enabled=_was_on(db, provider),
        created_at=now,
        created_by=ACTOR,
        updated_at=now,
        updated_by=ACTOR,
    )
    connector_actions.store_secrets(connection, {field: first_secret})
    names = [first.label.strip() or "Key 1"]
    more = []
    for index, (key, secret) in enumerate(keys[1:], start=2):
        label = key.label.strip() or f"Key {index}"
        if label.lower() in (taken.lower() for taken in names):
            label = f"{label} ({index})"
        names.append(label)
        more.append({"name": label, "secrets": {field: secret}})
    limits = OLD[provider]
    connection.key_policy = {
        **instance_keys.clean_policy({"perMinute": limits["perMinute"], "perDay": limits["perDay"]}),
        "mainName": names[0][:60],
    }
    if more:
        instance_keys.set_extra_keys(connection, more, [field], [field])
    db.add(connection)
    return connection


def adopt(db: OrmSession) -> int:
    """Give the keys stored before 6.5 to instances of the connectors that are installed, and delete the
    ones that have a home everywhere they belong (the caller commits). Returns how many instances it made.
    Safe to call again: what was moved is written down, and an instance someone deleted is not made twice."""
    movable = _movable(db)
    if not movable:
        return 0
    moved: dict[str, list[str]] = {
        provider: list(done) for provider, done in (state.read(db).get(STATE_KEY) or {}).items()
    }
    made = 0
    changed = False
    for provider, keys in movable.items():
        done = moved.setdefault(provider, [])
        for connector_id in OLD[provider]["connectors"]:
            if connector_id in done:
                continue
            row = db.get(Connector, connector_id)
            connector = connector_actions.parsed(row) if row is not None else None
            field = key_field(connector) if connector is not None else None
            if connector is None or field is None:
                continue
            instances = connector_actions.connections_of(db, connector_id)
            # A key an instance holds already (6.1 let the look-ups borrow it) needs no second home.
            missing = [
                (key, secret)
                for key, secret in keys
                if not any(_holds(db, connection, field, secret) for connection in instances)
            ]
            if missing:
                connection = _make(db, row, connector, field, provider, missing)
                made += 1
                audit.record(
                    db,
                    ACTOR,
                    "connection.create",
                    f'Made the instance "{connection.name}" of {connector.name} from the '
                    f"{len(missing)} {OLD[provider]['label']} API key(s) kept in Settings, Threat intelligence"
                    + ("" if connection.enabled else " (off, as the source was)"),
                    target=connection.name,
                )
            done.append(connector_id)
            changed = True
        if set(done) >= set(OLD[provider]["connectors"]):
            for key, _secret in keys:
                db.delete(key)
            changed = True
    if changed:
        state.write(db, **{STATE_KEY: moved})
        db.flush()
    return made


def left(db: OrmSession) -> list[dict[str, Any]]:
    """The keys still stored the old way, as Settings shows them: never a secret, only the last four
    characters, why each is still here and what it waits for."""
    moved = state.read(db).get(STATE_KEY) or {}
    installed = {row.id: row.name for row in db.execute(select(Connector.id, Connector.name))}
    found = []
    for row in db.scalars(select(IntegrationKey).order_by(IntegrationKey.provider, IntegrationKey.updated_at)):
        old = OLD.get(row.provider)
        readable = vault.decrypt(row.secret) is not None
        waiting = [
            connector_id
            for connector_id in (old["connectors"] if old else ())
            if connector_id not in (moved.get(row.provider) or [])
        ]
        if not readable:
            why = "unreadable"
        elif row.status != "ok":
            why = "rejected"
        elif not old:
            why = "unknown"
        else:
            why = "waiting"
        found.append(
            {
                "id": row.id,
                "source": row.provider,
                "label": old["label"] if old else row.provider,
                "hint": row.hint,
                "name": row.label,
                # waiting: for the packs below | rejected: the vendor had refused it | unreadable: SECRET_KEY
                # changed since it was saved | unknown: of a source that does not exist any more
                "state": why,
                "error": row.error,
                "connectors": [
                    {"id": connector_id, "installed": connector_id in installed} for connector_id in waiting
                ],
                "updatedAt": row.updated_at,
                "updatedBy": row.updated_by,
            }
        )
    return found
