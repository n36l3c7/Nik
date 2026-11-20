"""The sources of an indicator's reputation: the connectors that say they judge one.

A **source** is an installed connector with a command marked ``reputation: <kind>``
(``ip``, ``domain``, ``url``, ``file``): the command is given the value as its
first argument and answers ``verdict``, ``summary`` and ``link`` among its
outputs. Nothing here names a vendor: a connector installed tomorrow that marks
a command takes part in the look-ups.

**Which command.** For a kind, the first command of the file marked for it that
changes nothing outside, is not ``premium`` (a look-up never spends what only a
paid plan gives), carries no file and takes the value as its first argument.

**Which instance.** A source is asked through **the oldest instance of its
connector that is on**: one place to look when an answer surprises, and turning
that instance off (or deleting it) hands the look-ups to the next. A connector
with no instance that is on is a source that is off.

**Keys, limits and kept answers** are the instance's (``automation/instance_keys.py``):
its keys take turns as it says, a key that reached the limit set on the instance
or that the vendor refused (HTTP 429) is left alone, and an answer the instance
keeps is given back without a request, to a look-up as to a playbook. The
look-ups keep no count of their own.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..automation import connector_actions, egress, instance_keys
from ..automation.connector_runtime import CommandError
from ..automation.connectors import Command, ConnectorFile
from ..core.models import Connection, Connector

HASHES = ("md5", "sha1", "sha256")
# The kinds a command can be marked for that the look-ups ask about ("email" is a kind too, for the
# playbooks: an e-mail address is never looked up by itself).
KINDS = ("ip", "domain", "url", "file")
VERDICTS = ("malicious", "suspicious", "harmless", "unknown")
AUTH_PAUSE = 600  # seconds the automatic look-ups leave a source alone after it refused the credentials


def command_kind(kind: str) -> str:
    """The kind a command is marked with for a type of indicator: the three digests are a ``file``."""
    return "file" if kind in HASHES else kind


@dataclass(frozen=True)
class Source:
    """A connector as a source: what it is asked for each kind, and through which instance."""

    id: str  # the connector's id: what an answer is stored under
    label: str
    weight: int
    informational: bool
    commands: dict[str, str]  # kind of command (ip, domain, url, file, email) → the command's name
    connector: ConnectorFile
    instance: Connection | None  # the one the look-ups go through; None: no instance is on
    instances: int  # how many instances the connector has, on or off

    def supports(self, kind: str) -> bool:
        return command_kind(kind) in self.commands

    @property
    def on(self) -> bool:
        return self.instance is not None

    @property
    def types(self) -> list[str]:
        """The types of indicator it judges, as the look-ups name them."""
        found = [kind for kind in ("ip", "domain", "url") if kind in self.commands]
        return [*found, *(HASHES if "file" in self.commands else ())]


class Unavailable(Exception):
    """The source cannot be asked now: every key of its instance is used up. ``wait`` in seconds."""

    def __init__(self, message: str, wait: float):
        super().__init__(message)
        self.message = message
        self.wait = wait


class Failed(Exception):
    """The source was asked, or could not be reached, and gave no answer: a sentence safe to show."""

    def __init__(self, message: str, *, auth: bool = False):
        super().__init__(message)
        self.message = message
        self.auth = auth


# --------------------------------------------------------------------------- #
# Which connectors are sources                                                #
# --------------------------------------------------------------------------- #
def eligible(command: Command) -> bool:
    """Whether a command marked ``reputation`` may be run by a look-up nobody approves."""
    return (
        command.reputation is not None
        and not command.premium
        and not command.changes_outside
        and not command.gives_file
        and not command.sends_file
        and bool(command.arguments)
        and command.arguments[0].type != "file"
    )


def commands_of(connector: ConnectorFile) -> dict[str, str]:
    """kind → the command of the connector a look-up of that kind runs (the first that may be)."""
    found: dict[str, str] = {}
    for command in connector.commands:
        if eligible(command):
            found.setdefault(str(command.reputation), command.name)
    return found


# The connector files, read once per version of each: a file is large, and the list of indicators asks
# for the weight of every source on every page.
_FILES: dict[str, tuple[tuple, ConnectorFile | None]] = {}


def forget() -> None:
    _FILES.clear()


def _files(db: OrmSession) -> dict[str, ConnectorFile]:
    marks = {
        row.id: (row.version, row.updated_at, row.size)
        for row in db.execute(
            select(Connector.id, Connector.version, Connector.updated_at, func.length(Connector.source).label("size"))
        )
    }
    for gone in set(_FILES) - set(marks):
        _FILES.pop(gone, None)
    changed = [connector_id for connector_id, mark in marks.items() if _FILES.get(connector_id, (None,))[0] != mark]
    if changed:
        for row in db.scalars(select(Connector).where(Connector.id.in_(changed))):
            _FILES[row.id] = (marks[row.id], connector_actions.parsed(row))
    return {connector_id: found for connector_id, (_mark, found) in _FILES.items() if found is not None}


def sources(db: OrmSession) -> list[Source]:
    """Every source there is, by name: the installed connectors with a command a look-up may run."""
    files = {connector_id: found for connector_id, found in _files(db).items() if found.native is None}
    judging = {connector_id: commands_of(found) for connector_id, found in files.items()}
    judging = {connector_id: commands for connector_id, commands in judging.items() if commands}
    if not judging:
        return []
    first: dict[str, Connection] = {}
    count: dict[str, int] = {}
    for row in db.scalars(
        select(Connection).where(Connection.connector_id.in_(judging)).order_by(Connection.created_at, Connection.id)
    ):
        count[row.connector_id] = count.get(row.connector_id, 0) + 1
        if row.enabled:
            first.setdefault(row.connector_id, row)
    found = []
    for connector_id, commands in judging.items():
        connector = files[connector_id]
        lookups = connector.lookups
        found.append(
            Source(
                id=connector_id,
                label=connector.name,
                weight=lookups.weight if lookups is not None else 1,
                informational=bool(lookups and lookups.informational),
                commands=commands,
                connector=connector,
                instance=first.get(connector_id),
                instances=count.get(connector_id, 0),
            )
        )
    return sorted(found, key=lambda source: (source.label.lower(), source.id))


def weights(db: OrmSession) -> dict[str, tuple[int, bool]]:
    """source id → (weight, informational), of every installed connector that says how it counts."""
    return {
        connector_id: (found.lookups.weight, found.lookups.informational)
        for connector_id, found in _files(db).items()
        if found.lookups is not None
    }


def labels(db: OrmSession) -> dict[str, str]:
    return {connector_id: found.name for connector_id, found in _files(db).items()}


# --------------------------------------------------------------------------- #
# Asking one                                                                  #
# --------------------------------------------------------------------------- #
# Sources that refused the credentials of their instance, and until when the automatic look-ups leave
# them alone (per process): a wrong key is not tried on every indicator. "Check now" still asks.
_PAUSED: dict[str, float] = {}


def reset() -> None:
    _PAUSED.clear()


def keys_count(source: Source) -> int:
    return len(instance_keys.keys_of(source.instance)) if source.instance is not None else 0


def wait(db: OrmSession, source: Source, now: float | None = None, *, automatic: bool = True) -> float:
    """Seconds before the source can be asked: 0 when a key of its instance is free. ``automatic``: for
    a look-up nobody asked for by hand, which also leaves alone a source that just refused its credentials."""
    if source.instance is None:
        return float("inf")
    now = time.time() if now is None else now
    paused = _PAUSED.get(source.id, 0) - time.monotonic() if automatic else 0.0
    key, seconds = instance_keys.choose(db, source.instance, now)
    return max(0.0, paused, 0.0 if key is not None else seconds)


def left_today(db: OrmSession, source: Source, now: float | None = None) -> int | None:
    """Requests the keys of the instance can still make today; None: the instance sets no daily limit."""
    if source.instance is None:
        return 0
    now = time.time() if now is None else now
    shown = instance_keys.shown(db, source.instance, [], now)
    per_day = shown["policy"]["perDay"]
    if not per_day:
        return None
    return sum(max(0, per_day - key["usedToday"]) for key in shown["keys"])


def arguments(command: Command, value: str) -> dict[str, Any]:
    """What the command is run with: the value, and the defaults of its other arguments, written as a
    node of a playbook that sets nothing else sends them, so that the two share the answers kept."""
    given = {argument.name: argument.default for argument in command.arguments if argument.default is not None}
    if command.reputation_of == "registered_domain":
        # A registry knows the domain that was registered, not the hosts under it.
        from ..mail.verify import org_domain

        value = org_domain(value)
    return {**given, command.arguments[0].name: value}


def ask(
    db: OrmSession,
    source: Source,
    kind: str,
    value: str,
    *,
    playbook: Any | None = None,
    again: bool = False,
    now: float | None = None,
) -> dict[str, Any]:
    """Run the reputation command of the source for the value, on its instance, and give its outputs.

    The caller has checked that the value may leave (``service.blocked``) and commits. ``again``: the
    answer the instance keeps is not given back (someone asked to check again); the new one is kept.
    ``playbook``: the playbook the look-up is made for, whose rules on where it may send apply too.
    Raises ``Unavailable`` (every key is used up) or ``Failed``.
    """
    connection = source.instance
    command = source.connector.command(source.commands.get(command_kind(kind), ""))
    if connection is None or command is None:
        raise Failed(f"{source.label} has no instance that is on")
    now = time.time() if now is None else now
    args = arguments(command, value)
    if not again:
        kept = instance_keys.kept_answer(db, connection, command.name, args, now)
        if kept is not None and isinstance(kept["outputs"], dict):
            return kept["outputs"]
    tried: set[str] = set()
    refusal: Failed | None = None
    while True:
        key, seconds = instance_keys.choose(db, connection, now, skip=tried)
        if key is None:
            if refusal is not None:  # every key was tried for this request, and each was refused
                raise refusal
            minutes = max(1, round(seconds / 60))
            raise Unavailable(
                f'every key of the instance "{connection.name}" is used up: the first is back in {minutes} min',
                seconds,
            )
        try:
            runtime = connector_actions.runtime_for(db, source.connector, connection, playbook, key=key)
            answer = runtime.run(command.name, args)
        except egress.EgressError as error:
            raise Failed(error.message[:500]) from None
        except CommandError as error:
            if error.sent:
                instance_keys.used(db, connection, key.id, now)
            if error.status == instance_keys.QUOTA_STATUS:
                # The vendor says this key is used up: it is left alone, and the next one is tried.
                instance_keys.refused(db, connection, key.id, now)
                tried.add(key.id)
                refusal = Failed(error.message[:500])
                continue
            auth = error.status in (401, 403)
            if auth:
                _PAUSED[source.id] = time.monotonic() + AUTH_PAUSE
            raise Failed(error.message[:500], auth=auth) from None
        break
    instance_keys.used(db, connection, key.id, now)
    if not answer.done or not isinstance(answer.outputs, dict):
        raise Failed(f"{source.label}: the command {command.name} gives its answer later, a look-up cannot wait for it")
    _PAUSED.pop(source.id, None)
    instance_keys.keep_answer(db, connection, command.name, args, answer.outputs, answer.context, now)
    return answer.outputs


def verdict_of(outputs: dict[str, Any]) -> str:
    verdict = str(outputs.get("verdict") or "unknown").lower()
    return verdict if verdict in VERDICTS else "unknown"
