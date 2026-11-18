"""Connectors as they are stored, and their commands as actions of the canvas.

A connector is a row holding its YAML (``connectors``); a connection is a
connector plus an address and credentials (``connections``). Every command
of an installed connector is an action, ``<connector id>.<command>``, found
by the registry through the provider at the end of this file; the node names
the connection it uses.

A command goes out like the HTTP node does: the data guard decides on the
arguments first, then the request leaves under the playbook's policy, to
which the host of the connection is added (making a connection is the
permission to reach its host). In a dry run nothing is sent: the step shows
the first request it would make and gives the ``sample`` of the command.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..core import vault
from ..core.models import Connection, Connector
from ..core.security import now_iso
from . import actions, egress, outbound
from . import expressions as ex
from .connector_runtime import AUTH_FIELDS, CommandError, Runtime, forget_tokens
from .connectors import Command, ConnectorError, ConnectorFile, Problem, load

SEED_DIR = Path(__file__).parent / "seed" / "connectors"

# Parsed files, by what they are made of: a connector is read once per version of its text.
_PARSED: dict[str, ConnectorFile] = {}


def parsed(row: Connector) -> ConnectorFile | None:
    """The connector of a row, or None when what is stored cannot be read any more."""
    key = hashlib.sha256(row.source.encode("utf-8")).hexdigest()
    if key not in _PARSED:
        try:
            _PARSED[key] = load(row.source)
        except ConnectorError:
            return None
        if len(_PARSED) > 200:
            _PARSED.pop(next(iter(_PARSED)))
    return _PARSED[key]


# --------------------------------------------------------------------------- #
# Installing                                                                  #
# --------------------------------------------------------------------------- #
def install(db: OrmSession, text: str, actor: str, *, builtin: bool = False) -> tuple[Connector, ConnectorFile]:
    """Add a connector, or replace the one with the same id (the caller commits).

    Raises ``ConnectorError`` with every problem of the file. A file whose
    version is lower than the one installed is refused: versions only go up.
    """
    connector = load(text)
    row = db.get(Connector, connector.id)
    now = now_iso()
    if row is None:
        row = Connector(id=connector.id, created_at=now, created_by=actor)
        db.add(row)
    elif not builtin and row.version > connector.version:
        raise ConnectorError(
            [
                Problem(
                    0, f"Version {row.version} is installed: a file replaces it with the same version or a higher one"
                )
            ]
        )
    row.name = connector.name
    row.version = connector.version
    row.source = text
    row.builtin = builtin
    row.updated_at = now
    row.updated_by = actor
    db.flush()
    return row, connector


def shipped() -> list[tuple[str, ConnectorFile]]:
    """The connectors that come with Nik (``seed/connectors/*.yml``): their text, parsed."""
    found = []
    for path in sorted(SEED_DIR.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        found.append((text, load(text)))
    return found


def seed(db: OrmSession) -> int:
    """Add the shipped connectors that are missing and replace those a release changed
    (the caller commits). One an admin uploaded under the same id is theirs and is left."""
    changed = 0
    for text, connector in shipped():
        row = db.get(Connector, connector.id)
        if row is not None and (not row.builtin or row.source == text):
            continue
        install(db, text, "nik", builtin=True)
        changed += 1
    return changed


# --------------------------------------------------------------------------- #
# Connections                                                                 #
# --------------------------------------------------------------------------- #
def secret_names(connector: ConnectorFile) -> list[str]:
    """The secrets a connection of this connector holds: its credentials' parts, and its ``secret`` values."""
    names = [param.name for param in connector.configuration if param.type == "secret"]
    auth = connector.auth
    return [*names, *(AUTH_FIELDS.get(auth.type, ()) if auth is not None else ())]


def secrets_of(connection: Connection) -> dict[str, str]:
    """The credentials of a connection, decrypted ({} when they cannot be read)."""
    if not connection.secrets:
        return {}
    text = vault.decrypt(connection.secrets)
    try:
        found = json.loads(text) if text else {}
    except ValueError:
        found = {}
    return found if isinstance(found, dict) else {}


def store_secrets(connection: Connection, secrets: dict[str, Any]) -> None:
    kept = {key: str(value) for key, value in secrets.items() if value not in (None, "")}
    connection.secrets = vault.encrypt(json.dumps(kept)) if kept else ""
    forget_tokens(connection.id)


def connections_of(db: OrmSession, connector_id: str) -> list[Connection]:
    return list(db.scalars(select(Connection).where(Connection.connector_id == connector_id).order_by(Connection.name)))


def host_of(connector: ConnectorFile, config: dict[str, Any]) -> str | None:
    """``host`` or ``host:port`` of a connection, as the egress policy lists it; None when it has no address."""
    # With the defaults of what was left out, as the runtime reads it (a region that has a default).
    values = {param.name: param.default for param in connector.configuration if not param.is_auth}
    values.update({key: value for key, value in (config or {}).items() if value not in (None, "")})
    try:
        base = ex.render_text(connector.base_url, ex.Scope(values={"config": values})).data
    except ex.ExpressionError:
        return None
    parts = urlsplit(str(base or ""))
    if not parts.hostname:
        return None
    default = 443 if parts.scheme == "https" else 80
    host = parts.hostname.lower()
    return host if (parts.port or default) == default else f"{host}:{parts.port}"


def find_connection(db: OrmSession, connector_id: str, wanted: str) -> Connection | None:
    """The connection a node names (by id or by name); the only one of the connector when it names none."""
    rows = db.scalars(
        select(Connection).where(Connection.connector_id == connector_id).order_by(func.lower(Connection.name))
    ).all()
    if wanted:
        return next((row for row in rows if wanted in (row.id, row.name)), None)
    return rows[0] if len(rows) == 1 else None


def runtime_for(
    db: OrmSession,
    connector: ConnectorFile,
    connection: Connection,
    playbook: Any | None = None,
    now: float | None = None,
) -> Runtime:
    """A runtime for a connection: under the playbook's policy, or (to test a connection) reaching its host only."""
    host = host_of(connector, connection.config or {})
    if playbook is not None:
        policy = outbound.policy_for(db, playbook, extra_hosts=(host,) if host else ())
    else:
        policy = egress.Policy(mode="listed", hosts=frozenset({host} if host else set()))
    # The engine's clock when it runs a step (its waits are counted on it); the wall clock otherwise.
    clock = (lambda: now) if now else time.time
    return Runtime(
        connector, connection.config or {}, secrets_of(connection), policy, token_key=connection.id, clock=clock
    )


# --------------------------------------------------------------------------- #
# A command as an action                                                      #
# --------------------------------------------------------------------------- #
def _seal(state: dict | None) -> dict | None:
    """The state of a command that waits, with the session it keeps open encrypted."""
    if state and state.get("session"):
        return {**state, "session": vault.encrypt(json.dumps(state["session"]))}
    return state


def _unseal(state: dict | None) -> dict | None:
    if state and isinstance(state.get("session"), str):
        text = vault.decrypt(state["session"])
        return {**state, "session": json.loads(text) if text else None}
    return state


def _record(records: list[dict], decided: dict) -> dict:
    """What a step shows of what was sent: the last request, how many there were, what the guard decided."""
    last = dict(records[-1]) if records else {}
    if len(records) > 1:
        last["requests"] = len(records)
    return {**last, "held": decided}


def run_command(connector_id: str, command_name: str, call: actions.Call) -> actions.Result:
    db = call.db
    row = db.get(Connector, connector_id)
    connector = parsed(row) if row is not None else None
    command = connector.command(command_name) if connector is not None else None
    if command is None:
        raise actions.ActionError("This command is not in the connector any more", retry=False)
    connection = find_connection(db, connector_id, call.connection)
    if connection is None:
        what = f'The connection "{call.connection}" does not exist' if call.connection else "Choose a connection"
        raise actions.ActionError(f"{what}: {connector.name} needs one to know where to send", retry=False)

    args = {key: value for key, value in call.args.items() if value is not None}
    args, decided = outbound.guarded(call, args)
    try:
        runtime = runtime_for(db, connector, connection, call.playbook, call.now)
        if call.dry_run:
            would = {**runtime.would_send(command_name, args), "held": decided, "connection": connection.name}
            sample = command.sample if command.sample is not None else dict.fromkeys(command.outputs)
            return actions.Result(output=sample, request=would)
        answer = runtime.run(command_name, args, _unseal(call.state))
    except egress.EgressError as error:
        raise actions.ActionError(error.message, retry=not error.refused, request=error.record) from None
    except CommandError as error:
        raise actions.ActionError(
            error.message,
            retry=error.retry,
            unknown_outcome=error.sent and error.retry,
            request={**(error.record or {}), "held": decided, "connection": connection.name},
        ) from None
    record = {**_record(answer.records, decided), "connection": connection.name}
    if not answer.done:
        return actions.Result(again_at=answer.again_at, state=_seal(answer.state), request=record)
    # What comes back may repeat what was sent: it keeps the classes of what went out.
    classes = {"": sorted(call.classes)} if call.classes else {}
    return actions.Result(
        output=answer.outputs,
        classes=classes,
        request=record,
        context=answer.context,
        context_source=f"connector:{connector_id}",
    )


def _spec(connector: ConnectorFile, command: Command) -> actions.Spec:
    connector_id, name = connector.id, command.name
    return actions.Spec(
        id=f"{connector.id}.{command.name}",
        group=connector.name,
        name=command.name,
        description=command.description,
        arguments=tuple(argument.model_dump(exclude_none=True) for argument in command.arguments),
        outputs=tuple({"name": key, "type": "any", "description": ""} for key in command.outputs)
        or ({"name": "response", "type": "any", "description": "The answer, as it came"},),
        changes_outside=command.changes_outside,
        idempotent=command.idempotent,
        timeout=command.timeout,
        run=lambda call: run_command(connector_id, name, call),
        extra={"connector": connector.id, "connectorVersion": connector.version, "needsConnection": True},
    )


class Provider:
    """The commands of the installed connectors, for the registry of actions."""

    @staticmethod
    def find(db: OrmSession, action_id: str) -> actions.Spec | None:
        connector_id, _, name = action_id.partition(".")
        if not name:
            return None
        row = db.get(Connector, connector_id)
        connector = parsed(row) if row is not None else None
        command = connector.command(name) if connector is not None else None
        return _spec(connector, command) if command is not None else None

    @staticmethod
    def every(db: OrmSession) -> list[actions.Spec]:
        found = []
        for row in db.scalars(select(Connector).order_by(func.lower(Connector.name))):
            connector = parsed(row)
            if connector is not None:
                found += [_spec(connector, command) for command in connector.commands]
        return found


actions.provide(Provider)
