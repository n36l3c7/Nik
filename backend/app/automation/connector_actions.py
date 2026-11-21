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

A command that carries a file does it through the store of the run
(connector_files.py): a file that comes back is kept as an artifact, one
that is sent is judged by the guard first. The answer of a command that
keeps a file is never one of the kept answers of the instance: asked again,
the file is fetched again, so that the run that asked has it in its incident
and in its audit trail (the store itself holds each file once, by its hash).
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .. import artifact_jobs
from ..core import audit, vault
from ..core.models import Connection, Connector
from ..core.permissions import SYSTEM_USER
from ..core.security import now_iso
from . import (
    actions,
    connector_files,
    connector_logo,
    credentials,
    egress,
    instance_keys,
    mail_evidence,
    outbound,
)
from . import expressions as ex
from .connector_runtime import (
    AUTH_FIELDS,
    FILE_SAMPLE,
    UNPACKED_SAMPLE,
    CommandError,
    NotSent,
    Runtime,
    forget_tokens,
)
from .connectors import Command, ConnectorError, ConnectorFile, Problem, load

SEED_DIR = Path(__file__).parent / "seed" / "connectors"
README_MAX = 100_000

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
def install(
    db: OrmSession, text: str, actor: str, *, builtin: bool = False, extras: dict[str, Any] | None = None
) -> tuple[Connector, ConnectorFile]:
    """Add a connector, or replace the one with the same id (the caller commits).

    Raises ``ConnectorError`` with every problem of the file. A file whose
    version is lower than the one installed is refused: versions only go up.

    ``extras`` is what a package brings beside the file: ``logo`` (bytes, checked here) and
    ``readme``. One that is not given keeps what the connector has; a file alone changes neither.
    """
    connector = load(text)
    logo = None
    if extras and extras.get("logo"):
        try:
            logo = connector_logo.clean(extras["logo"])
        except connector_logo.LogoError as error:
            raise ConnectorError([Problem(0, f"The logo: {error.message}")]) from None
    row = db.get(Connector, connector.id)
    before = parsed(row) if row is not None else None
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
    if logo is not None:
        row.logo, row.logo_type = logo
    if extras and extras.get("readme") is not None:
        row.readme = str(extras["readme"])[:README_MAX]
    row.updated_at = now
    row.updated_by = actor
    db.flush()
    if before is not None:
        carry_key(db, before, connector, actor)
    if connector.native is None and any(command.reputation for command in connector.commands):
        # A source of threat intelligence: a key kept for it before 6.5 becomes the key of an instance.
        from ..enrichment import old_keys

        old_keys.adopt(db)
    return row, connector


def renamed_key(before: ConnectorFile, after: ConnectorFile) -> tuple[str, str] | None:
    """``(old name, new name)`` when a new version of a connector asks for the same one key under another
    name: it had one ``secret`` of its own and no credentials (``api_key``, written into each request by
    hand), and now has credentials of one value (``header``, ``query``, ``bearer``) and that secret no
    more. None in every other case: nothing else can be told to be the same secret."""
    old, new = secret_names(before), secret_names(after)
    gone = [name for name in old if name not in new]
    came = [name for name in new if name not in old]
    one_value = after.auth is not None and len(AUTH_FIELDS.get(after.auth.type, ())) == 1
    if before.auth is None and one_value and len(gone) == 1 and len(came) == 1:
        return gone[0], came[0]
    return None


def carry_key(db: OrmSession, before: ConnectorFile, after: ConnectorFile, actor: str) -> int:
    """Keep the keys of the instances when a new version of their connector calls the key otherwise
    (``renamed_key``): what each key of each instance holds under the old name is held under the new one,
    a typed value and the name of a stored credential alike. Nobody types a key again because a file
    was tidied. Returns how many instances were changed (the caller commits)."""
    names = renamed_key(before, after)
    if names is None:
        return 0
    old, new = names
    changed = 0
    for connection in connections_of(db, after.id):
        moved = False
        for key in instance_keys.keys_of(connection):
            if key.secrets.get(old) and not key.secrets.get(new):
                held = dict(key.secrets)
                held[new] = held.pop(old)
                instance_keys.set_key_secrets(connection, key.id, held)
                moved = True
        if moved:
            changed += 1
            audit.record(
                db,
                actor,
                "connection.update",
                f'Kept the key of the instance "{connection.name}" under the name version {after.version} of '
                f"{after.name} asks for it ({old} is {new} now)",
                target=connection.name,
            )
    return changed


def package_of(folder: Path) -> tuple[str, dict[str, Any]]:
    """A connector kept as a folder (``connector.yml``, and beside it ``logo.svg`` or ``logo.png``
    and ``README.md``): its file and what it comes with."""
    extras: dict[str, Any] = {}
    for path in sorted(folder.iterdir()):
        if path.is_file() and connector_logo.by_name(path.name):
            extras["logo"] = path.read_bytes()
        elif path.is_file() and path.name.lower() == "readme.md":
            extras["readme"] = path.read_text(encoding="utf-8")
    return (folder / "connector.yml").read_text(encoding="utf-8"), extras


def shipped() -> list[tuple[str, ConnectorFile]]:
    """The connectors that come with Nik: their text, parsed. Each is a file (``seed/connectors/<id>.yml``)
    or a package (``seed/connectors/<id>/connector.yml`` with its logo and README, see ``shipped_extras``)."""
    found = []
    for path in sorted([*SEED_DIR.glob("*.yml"), *SEED_DIR.glob("*/connector.yml")], key=lambda p: p.as_posix()):
        text = path.read_text(encoding="utf-8")
        found.append((text, load(text)))
    return found


def shipped_extras() -> dict[str, dict[str, Any]]:
    """connector id → the logo and the README a shipped connector comes with (packages only)."""
    found = {}
    for path in sorted(SEED_DIR.glob("*/connector.yml")):
        text, extras = package_of(path.parent)
        if extras:
            found[load(text).id] = extras
    return found


def seed(db: OrmSession) -> int:
    """Add the shipped connectors that are missing and replace those a release changed
    (the caller commits). One an admin uploaded under the same id is theirs and is left."""
    changed = 0
    extras = shipped_extras()
    for text, connector in shipped():
        row = db.get(Connector, connector.id)
        if row is not None and (not row.builtin or row.source == text):
            continue
        install(db, text, "nik", builtin=True, extras=extras.get(connector.id))
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


def usable_secrets(db: OrmSession, connection: Connection, key: instance_keys.Key | None = None) -> dict[str, Any]:
    """The secrets a request of the instance goes with (those of ``key``, or of its first key): what was
    typed as it is, and in place of each stored credential the instance names, the value it has now
    (credentials.py). A credential that is missing fails the command, by its name: nothing stands in."""
    held = secrets_of(connection) if key is None or key.id == instance_keys.MAIN else key.secrets
    try:
        return credentials.resolved(db, held, connection.name)
    except credentials.CredentialError as error:
        raise CommandError(error.message, retry=False) from None


def connections_of(db: OrmSession, connector_id: str) -> list[Connection]:
    return list(db.scalars(select(Connection).where(Connection.connector_id == connector_id).order_by(Connection.name)))


def logo_path(row: Connector | None) -> str | None:
    """Where the logo of a connector is served from (under ``/api``), or None when it has none. The
    address changes when the logo does, so a browser may keep it."""
    if row is None or not row.logo:
        return None
    mark = hashlib.sha256(bytes(row.logo)).hexdigest()[:12]
    return f"/automation/connectors/{row.id}/logo?v={mark}"


def logos_by_connection(db: OrmSession) -> dict[str, dict[str, Any]]:
    """connection id → the connector it is an instance of, by name, and its logo: what an incident
    a connector brought in is marked with."""
    connectors = {row.id: row for row in db.scalars(select(Connector))}
    found = {}
    for connection_id, name, connector_id in db.execute(
        select(Connection.id, Connection.name, Connection.connector_id)
    ):
        row = connectors.get(connector_id)
        found[connection_id] = {
            "connection": name,
            "connector": row.name if row is not None else connector_id,
            "logo": logo_path(row),
        }
    return found


ADOPTED_NAME = "Mail (from Settings)"


def adopt_smtp(db: OrmSession) -> bool:
    """Make the SMTP server of the settings of 4.x an instance of the Mail connector, once (the caller
    commits). Until 5.1 the e-mail node read that server; mail is a connector now, and its instances
    are where a server is set. Nothing is done when there is no server, when the Mail connector has
    an instance already, or when this was done before (the instance may have been deleted since)."""
    from . import state

    settings = state.read(db)
    smtp = dict(settings.get("smtp") or {})
    if settings.get("smtp_adopted") or not smtp.get("host") or not smtp.get("sender"):
        return False
    if db.get(Connector, "mail") is None:
        return False
    state.write(db, smtp_adopted=True)
    if db.scalars(select(Connection.id).where(Connection.connector_id == "mail")).first() is not None:
        return True
    name, count = ADOPTED_NAME, 2
    while db.scalars(select(Connection.id).where(func.lower(Connection.name) == name.lower())).first() is not None:
        name, count = f"{ADOPTED_NAME} {count}", count + 1
    now = now_iso()
    row = Connection(
        id=hashlib.sha256(f"mail-adopted-{now}".encode()).hexdigest()[:32],
        name=name,
        connector_id="mail",
        config={
            "smtp_host": str(smtp.get("host") or ""),
            "smtp_port": int(smtp.get("port") or 587),
            "smtp_security": str(smtp.get("security") or "starttls"),
            "sender": str(smtp.get("sender") or ""),
            **({"ca_pem": str(smtp["ca_pem"])} if smtp.get("ca_pem") else {}),
        },
        created_at=now,
        created_by="nik",
        updated_at=now,
        updated_by="nik",
    )
    password = vault.decrypt(smtp["password"]) if smtp.get("password") else ""
    secrets = {"username": str(smtp.get("username") or ""), "password": password or ""}
    store_secrets(row, {key: value for key, value in secrets.items() if value})
    db.add(row)
    return True


def enabled_connectors(db: OrmSession) -> set[str]:
    """The connectors that have an instance that is on: the ones whose commands can be used."""
    return set(db.scalars(select(Connection.connector_id).where(Connection.enabled.is_(True)).distinct()))


def host_of(connector: ConnectorFile, config: dict[str, Any]) -> str | None:
    """``host`` or ``host:port`` of a connection, as the egress policy lists it; None when it has no address."""
    # With the defaults of what was left out, as the runtime reads it (a region that has a default).
    values = {param.name: param.default for param in connector.configuration if not param.is_auth}
    values.update({key: value for key, value in (config or {}).items() if value not in (None, "")})
    if connector.native == "mail":
        # A mailbox: the server it is read from, or the one it sends through.
        return egress.clean_host(str(values.get("imap_host") or values.get("smtp_host") or "")) or None
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
    """The instance a node names (by id or by name), on or off; when it names none, the only one of
    the connector that is on."""
    rows = db.scalars(
        select(Connection).where(Connection.connector_id == connector_id).order_by(func.lower(Connection.name))
    ).all()
    if wanted:
        return next((row for row in rows if wanted in (row.id, row.name)), None)
    on = [row for row in rows if row.enabled]
    return on[0] if len(on) == 1 else None


def runtime_for(
    db: OrmSession,
    connector: ConnectorFile,
    connection: Connection,
    playbook: Any | None = None,
    now: float | None = None,
    key: instance_keys.Key | None = None,
) -> Runtime:
    """A runtime for a connection: under the playbook's policy, or (to test a connection) reaching its host only.
    ``key`` is the key of the instance the requests go with (its first one when not said)."""
    host = host_of(connector, connection.config or {})
    # Its own host, and the other hosts its file lists: installing the connector and making the instance
    # is the permission to reach them.
    reach = tuple(found for found in (host, *connector.more_hosts) if found)
    if playbook is not None:
        policy = outbound.policy_for(db, playbook, extra_hosts=reach)
    else:
        policy = egress.Policy(mode="listed", hosts=frozenset(reach))
    # The engine's clock when it runs a step (its waits are counted on it); the wall clock otherwise.
    clock = (lambda: now) if now else time.time
    if connector.native == "mail":
        from .mail_runtime import MailRuntime

        # A recipient is judged by the playbook's own policy: the host of the mailbox is not one.
        if playbook is not None:
            policy = outbound.policy_for(db, playbook)
        return MailRuntime(connector, connection.config or {}, usable_secrets(db, connection), policy)
    if key is None or key.id == instance_keys.MAIN:
        return Runtime(
            connector,
            connection.config or {},
            usable_secrets(db, connection),
            policy,
            token_key=connection.id,
            clock=clock,
        )
    # Another key signs in on its own: its token is not the first key's.
    return Runtime(
        connector,
        connection.config or {},
        usable_secrets(db, connection, key),
        policy,
        token_key=f"{connection.id}:{key.id}",
        clock=clock,
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
        what = f'The instance "{call.connection}" does not exist' if call.connection else "Choose an instance"
        raise actions.ActionError(f"{what}: {connector.name} needs one to know where to send", retry=False)
    if not connection.enabled:
        raise actions.ActionError(
            f'The instance "{connection.name}" of {connector.name} is off: turn it on in Settings, Connectors',
            retry=False,
        )

    args = {key: value for key, value in call.args.items() if value is not None}
    # The recipients of a message are where it goes, judged by the hosts the playbook may reach;
    # what the guard judges is what is said.
    where = {"to"} & set(args) if connector.native == "mail" else set()
    said, decided = outbound.guarded(
        call, {key: value for key, value in args.items() if key not in where}, dict.fromkeys(where, "_")
    )
    args = {**said, **{key: args[key] for key in where}}
    now = call.now or time.time()
    classes = {"": sorted(call.classes)} if call.classes else {}
    if isinstance((call.state or {}).get("kept"), dict):
        # The command is done; what it kept was handed to the API process, and the step waits for it.
        return _when_kept(call, call.state, now)
    state = _unseal(call.state)
    # What the command keeps goes to the store from here, or through the API process when this one
    # cannot write to it: the step then waits for the files before it gives its outputs.
    keeper = artifact_jobs.Keeper.of(call, SYSTEM_USER)
    asked_before = list((state or {}).get("keeping") or [])
    # The keys of the instance take turns (instance_keys.py). Not in a dry run, which sends nothing, and
    # not for a connector Nik speaks for, which has its own way in.
    turns = connector.native is None and not call.dry_run
    # An answer is kept for a command that only reads, and reads something that can be repeated: not a file.
    keeps = turns and not command.changes_outside and not command.gives_file
    if keeps and not state:
        kept = instance_keys.kept_answer(db, connection, command_name, args, now)
        if kept is not None:
            return actions.Result(
                output=kept["outputs"],
                classes=classes,
                request={"kept": True, "keptAt": kept["at"], "held": decided, "connection": connection.name},
                context=[tuple(pair) for pair in kept["context"]],
                context_source=f"connector:{connector_id}",
            )
    # A command that waits and comes back goes on with the key it started with.
    pinned = (state or {}).get("key") if turns else None
    tried: set[str] = set()
    refusal: actions.ActionError | None = None
    while True:
        key = None
        if turns:
            key = next((held for held in instance_keys.keys_of(connection) if held.id == pinned), None)
            if key is None:
                key, wait = instance_keys.choose(db, connection, now, skip=tried)
            if key is None:
                if refusal is not None:  # every key was tried for this request, and each was refused
                    raise refusal
                minutes = max(1, round(wait / 60))
                said_wait = (
                    f'Every key of the instance "{connection.name}" is used up: the first is back in {minutes} min'
                )
                if instance_keys.policy_of(connection)["whenExhausted"] == "wait":
                    return actions.Result(
                        again_at=now + wait,
                        state=call.state,
                        request={"waiting": "keys", "note": said_wait, "held": decided, "connection": connection.name},
                    )
                raise actions.ActionError(said_wait, retry=False)
        try:
            runtime = runtime_for(db, connector, connection, call.playbook, call.now, key=key)
            runtime.idempotency_key = idempotency_key(call, command_name)
            if connector.native == "mail":
                # What a message quotes and carries of another is known once that one is read: the
                # runtime asks the guard then, and keeps what it is asked to keep through the store
                # of this run.
                runtime.judge = lambda quoted, found: outbound.guarded_message(call, quoted, found, decided)
                runtime.keep = lambda found, message, wanted: mail_evidence.keep_attachments(
                    call, found, message, wanted, keeper
                )
            else:
                # A file a command gives is kept there, one it sends is read from there once the guard
                # has judged it: what the guard says is added to what it said of the arguments.
                runtime.store = connector_files.Store(call, connector.name, command_name, decided, keeper)
            if call.dry_run:
                would = {**runtime.would_send(command_name, args), "held": decided, "connection": connection.name}
                sample = command.sample if command.sample is not None else dict.fromkeys(command.outputs)
                if command.sample is None and not command.outputs and command.gives_file:
                    sample = {**FILE_SAMPLE, **(UNPACKED_SAMPLE if command.unpacks else {})}
                return actions.Result(output=sample, request=would)
            answer = runtime.run(command_name, args, state)
            break
        except egress.EgressError as error:
            raise actions.ActionError(error.message, retry=not error.refused, request=error.record) from None
        except NotSent as error:
            if call.held != "drop":
                raise actions.ActionError(error.message, retry=False, request={"held": decided}) from None
            # The node drops what is held, and what was held is the file: nothing left, and the step goes on
            # with empty outputs, saying why.
            return actions.Result(
                output=dict.fromkeys(command.outputs),
                request={"notSent": error.message, "held": decided, "connection": connection.name}
                | ({"dry_run": True} if call.dry_run else {}),
            )
        except CommandError as error:
            failure = actions.ActionError(
                error.message,
                retry=error.retry,
                unknown_outcome=error.sent and error.retry,
                request={**(error.record or {}), "held": decided, "connection": connection.name},
            )
            if key is not None and error.sent:
                instance_keys.used(db, connection, key.id, now)
            if getattr(error, "kept", None):
                # The command failed and kept something all the same (an archive that could not be
                # unpacked). A step that fails keeps nothing of what it did, so this one first gives
                # itself back, which keeps the file (and waits for the API process when it is the one
                # that writes it), and fails when it is called again.
                failed = {"message": failure.message, "request": {**(failure.request or {}), "kept": error.kept}}
                kept = {
                    "jobs": [*asked_before, *keeper.pending],
                    "until": now + artifact_jobs.WAIT_FOR,
                    "audits": [*_audits(state), *keeper.audits],
                    "request": failed["request"],
                    "fail": failed,
                }
                return actions.Result(
                    again_at=now + (artifact_jobs.WAIT_EVERY if kept["jobs"] else 0),
                    state={"kept": kept},
                    request=failed["request"],
                    log=failure.message,
                )
            if key is not None and error.status == instance_keys.QUOTA_STATUS and not pinned:
                # The vendor says this key is used up: it is left alone, and the next one is tried.
                instance_keys.refused(db, connection, key.id, now)
                tried.add(key.id)
                refusal = failure
                continue
            raise failure from None
    if key is not None:
        instance_keys.used(db, connection, key.id, now)
    record = {**_record(answer.records, decided), "connection": connection.name}
    if key is not None and len(instance_keys.keys_of(connection)) > 1:
        record["key"] = key.name
    asked = [*asked_before, *keeper.pending]
    if not answer.done:
        waiting = {**(answer.state or {}), "key": key.id} if key is not None else dict(answer.state or {})
        if asked:
            # A step of the command kept a file and the command waits for something else: the files
            # asked for so far are waited for when it ends.
            waiting["keeping"], waiting["keeping_audits"] = asked, [*_audits(state), *keeper.audits]
        return actions.Result(again_at=answer.again_at, state=_seal(waiting), request=record)
    if keeps:
        instance_keys.keep_answer(db, connection, command_name, args, answer.outputs, answer.context, now)
    # What comes back may repeat what was sent: it keeps the classes of what went out, beside those
    # the command gives its own outputs (the name of an attachment).
    result = actions.Result(
        output=answer.outputs,
        classes={**answer.classes, **classes},
        request=record,
        context=answer.context,
        context_source=f"connector:{connector_id}",
    )
    if not asked:
        return result
    kept = {
        "jobs": asked,
        "until": now + artifact_jobs.WAIT_FOR,
        "audits": [*_audits(state), *keeper.audits],
        "output": result.output,
        "classes": result.classes,
        "request": result.request,
        "context": [list(pair) for pair in result.context],
        "source": result.context_source,
    }
    return _when_kept(call, {"kept": kept}, now)


def _audits(state: dict | None) -> list:
    return list((state or {}).get("keeping_audits") or [])


def _when_kept(call: actions.Call, state: dict, now: float) -> actions.Result:
    """The result of a command whose files the API process keeps: given once they are kept, and the
    step looks again until then. A file that could not be kept fails the step."""
    kept = state["kept"]
    try:
        done = artifact_jobs.kept(call.db, kept, SYSTEM_USER, now)
    except artifact_jobs.JobError as error:
        raise actions.ActionError(str(error), retry=False, request=kept.get("request")) from None
    if not done:
        return actions.Result(
            again_at=now + artifact_jobs.WAIT_EVERY,
            state=state,
            request=kept.get("request"),
            log="Waiting for the server to keep the file",
        )
    if kept.get("fail"):
        if kept.get("jobs"):
            # Kept by the API process just now: its line of the audit log is written with this call,
            # and a step that fails keeps nothing it wrote. So the step fails at the next one.
            settled = {**kept, "jobs": [], "audits": []}
            return actions.Result(again_at=now, state={"kept": settled}, request=kept.get("request"))
        # What was kept is kept: the command itself failed, and says so now.
        raise actions.ActionError(str(kept["fail"]["message"]), retry=False, request=kept["fail"].get("request"))
    return actions.Result(
        output=kept.get("output"),
        classes=kept.get("classes") or {},
        request=kept.get("request"),
        context=[tuple(pair) for pair in kept.get("context") or []],
        context_source=str(kept.get("source") or ""),
    )


# What a command that keeps a file gives when its file names no outputs: what describes the file.
_FILE_OUTPUTS = (
    {"name": "name", "type": "text", "description": "The name of the file"},
    {"name": "type", "type": "text", "description": "Its type, as the answer said it"},
    {"name": "size", "type": "number", "description": "Its size in bytes"},
    {"name": "sha256", "type": "text", "description": "Its SHA-256"},
    {"name": "artifact", "type": "text", "description": "The artifact it was kept as (file-…)"},
    {"name": "linked", "type": "bool", "description": "Whether the incident of the run references it"},
)


# And when the file is an archive that is unpacked: the files that were inside it.
_UNPACKED_OUTPUTS = (
    {
        "name": "files",
        "type": "list",
        "description": "The files that were in the archive: {name, type, size, sha256, artifact}",
        "shape": [
            {"name": "[0].name", "type": "text", "description": "The name of the first file, as the archive says it"},
            {"name": "[0].type", "type": "text", "description": "What it is, as Nik detected it"},
            {"name": "[0].size", "type": "number", "description": "Its size in bytes"},
            {"name": "[0].sha256", "type": "text", "description": "Its SHA-256"},
            {"name": "[0].artifact", "type": "text", "description": "The artifact it was kept as (file-…)"},
        ],
    },
    {"name": "count", "type": "number", "description": "How many files were taken out"},
    {
        "name": "skipped",
        "type": "list",
        "description": "What was in the archive and was not taken out, and why: {name, reason}",
        "shape": [
            {"name": "[0].name", "type": "text", "description": "The name of the first that was left"},
            {"name": "[0].reason", "type": "text", "description": "Why"},
        ],
    },
)


def idempotency_key(call: actions.Call, command: str) -> str:
    """What ``{{ idempotency.key }}`` gives a command run by a step: the same for every try of
    that step (a retry, a try after a restart, "do it again" after an interruption), another for
    every other step and run. One of its own when no step runs it."""
    run_id = str(getattr(call.run, "id", "") or "")
    if not run_id or not call.step_id:
        return uuid.uuid4().hex
    return hashlib.sha256(f"{run_id}:{call.step_id}:{command}".encode()).hexdigest()[:32]


def _spec(connector: ConnectorFile, command: Command) -> actions.Spec:
    connector_id, name = connector.id, command.name
    described = command.gives_file and not command.outputs
    secret = command.secret_arguments
    return actions.Spec(
        id=f"{connector.id}.{command.name}",
        group=connector.name,
        name=command.name,
        description=command.description,
        arguments=tuple(
            {**argument.model_dump(exclude_none=True), **({"secret": True} if argument.name in secret else {})}
            for argument in command.arguments
        ),
        outputs=tuple({"name": key, "type": "any", "description": ""} for key in command.outputs)
        or (
            (*_FILE_OUTPUTS, *(_UNPACKED_OUTPUTS if command.unpacks else ()))
            if described
            else ({"name": "response", "type": "any", "description": "The answer, as it came"},)
        ),
        changes_outside=command.changes_outside,
        # Safe to do again after a restart cut it: by its nature, or by the key it sends the product.
        idempotent=command.idempotent or command.idempotency_key,
        timeout=command.timeout,
        run=lambda call: run_command(connector_id, name, call),
        extra={
            "connector": connector.id,
            "premium": command.premium,
            "connectorVersion": connector.version,
            "needsConnection": True,
            # What an answer looks like, when the file says: the editor reads the sub-fields from it.
            **({"sample": command.sample} if isinstance(command.sample, dict) else {}),
        },
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
