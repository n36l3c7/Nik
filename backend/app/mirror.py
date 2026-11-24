"""Mirroring: an incident and one object of another product kept in step.

An incident is mirrored with one connection whose connector has a ``mirror``:
``incident.mirror`` holds the connection, the id of the object on the other
side, the direction (``in``, ``out`` or ``both``, shown as In, Out, In-out),
where the direction came from and how it goes.

- **In.** The worker reads the object every ``mirror.interval_seconds``
  (``pull``): ``mirror.get`` → the item → the incoming mapper → the fields,
  written under the provenance rule: what a person set in Nik stays, unless
  the mapper marks the field authoritative. Comments not seen before become
  lines of the War Room. A closed incident is read for a day more, then left.
  An object that is gone on the other side is read no more: one line, one
  notice, until someone reads it by hand and finds it again.
- **Out.** A change, made in Nik, of a field the outgoing mapper reads, and a
  note tagged ``mirror``, are queued (``mirror_queue``) and sent by the
  worker (``push``) with ``mirror.update`` and ``mirror.comments.add``. What
  is sent passes the data guard, with the classes opened when mirroring was
  started, and reaches the host of the connection only. A send that fails is
  tried again later and later, eight times.

**Who starts it.** A person, on the incident (``start``); or the fetch that
made the incident (``start_fetched``), in the direction its instance says
(``connections.fetch_settings``: ``mirror``, and ``mirrorAllow``, the classes
of data it may send). The id of the object is then what the connector says of
the fetched item (``mirror.id``, or the ``item_id`` of the fetch). A mapper
that writes ``mirror_id`` and ``mirror_direction`` is obeyed first, as it was
before instances had a choice. ``origin`` remembers which: ``instance``,
``mapper`` or ``here``.

**Kinds.** A product with more than one object to mirror (a threat, an
alert) names the others under ``mirror.kinds``; an id written
``<kind>:<id>`` is of that kind, and is read and written by its calls.

**Fed by the fetch.** A connector whose mirror has a ``thread`` and no
``get`` (mail) is not read at an interval: an item its fetch brings that goes
on with a conversation an incident holds becomes a line of that incident
(``absorb``), and is kept as evidence of it as the first one was. Such a
mirror goes in only: nothing is sent.

A loop is not possible: a change whose source is the connector of the mirror
is never sent back, and a comment Nik sent is known when it comes back.
"""

from __future__ import annotations

import hashlib
import logging
import re
import time
from typing import Any

from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import context as incident_context
from . import fetch, indicators_found, mapping, war_room
from . import fields as registry
from .automation import connector_actions as store
from .automation import expressions as ex
from .automation import guard
from .automation.connector_runtime import CommandError
from .automation.connectors import ConnectorFile, MirrorCall, MirrorSpec, can_send
from .core import audit, clock
from .core.ids import new_id
from .core.locking import lock_incident
from .core.models import Connection, Connector, FetchedItem, Incident, MirrorJob, WarRoomEntry
from .core.security import now_iso

logger = logging.getLogger("nik.mirror")

DIRECTIONS = ("in", "out", "both")
# What an instance says of the incidents its fetch makes: no mirror, or a direction.
NONE = "none"
CHOICES = (NONE, *DIRECTIONS)
LABELS = {NONE: "None", "in": "In", "out": "Out", "both": "In-out"}
TAG = "mirror"  # a note with this tag is sent to the other side as a comment
ATTEMPTS_MAX = 8
BACKOFF_MAX = fetch.BACKOFF_MAX  # an hour at most between two tries, as for a fetch
AFTER_CLOSE = 86_400  # a closed incident is read for a day more
SEEN_MAX = 300
THREAD_MAX = 200  # the ids of a conversation an incident keeps
COMMENT_MAX = 20_000
ID_MAX = 300
APPLY_MAX = 5000  # the open incidents one "apply to what was fetched" goes through
GONE = "The object is gone on the other side: it is read no more. Read it by hand to try again, or stop mirroring"
# The classes of data an instance may open for the mirrors its fetch starts: those a playbook is
# offered beside the others. The sensitive ones are opened on the incident, by who may open them.
OFFERED = frozenset(guard.CLASSES) - guard.ALWAYS - guard.SENSITIVE


class MirrorError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# State                                                                       #
# --------------------------------------------------------------------------- #
def state_of(incident: Incident) -> dict[str, Any] | None:
    held = incident.mirror if isinstance(incident.mirror, dict) else None
    return dict(held) if held and held.get("connection") and held.get("id") else None


def _keep(incident: Incident, state: dict[str, Any] | None) -> None:
    incident.mirror = state
    flag_modified(incident, "mirror")
    # The same, by the names of the registry: what expressions and the page read.
    stored = dict(incident.fields) if isinstance(incident.fields, dict) else {}
    for name, value in (
        ("mirror_id", state.get("id") if state else None),
        ("mirror_direction", state.get("direction") if state else None),
        ("mirror_last_sync", state.get("lastSync") if state else None),
    ):
        if value in (None, ""):
            stored.pop(name, None)
        else:
            stored[name] = value
    incident.fields = stored
    flag_modified(incident, "fields")


def _connector(db: OrmSession, connection: Connection | None) -> ConnectorFile | None:
    row = db.get(Connector, connection.connector_id) if connection is not None else None
    return store.parsed(row) if row is not None else None


def _parts(db: OrmSession, state: dict[str, Any]) -> tuple[Connection, ConnectorFile]:
    connection = db.get(Connection, state.get("connection") or "")
    connector = _connector(db, connection)
    if connection is None or connector is None or connector.mirror is None:
        raise MirrorError("The instance this incident is mirrored with is gone, or its connector mirrors no more")
    return connection, connector


def origin_of(state: dict[str, Any]) -> str:
    """Where the direction of a mirror came from: ``instance``, ``mapper`` or ``here``. A mirror an
    older release started says only who started it: a connector is a mapper, anyone else a person."""
    held = state.get("origin")
    if held in ("instance", "mapper", "here"):
        return held
    return "mapper" if str(state.get("startedBy") or "").startswith("connector:") else "here"


def abilities(spec: MirrorSpec | Any) -> dict[str, bool]:
    """What a mirror with a connector (or one of its kinds) does, each way."""
    comments = getattr(spec, "comments", None)
    return {
        "fieldsIn": spec.get is not None,
        "commentsIn": comments is not None or getattr(spec, "thread", None) is not None,
        "fieldsOut": spec.update is not None,
        "commentsOut": comments is not None and comments.add is not None,
    }


def mirroring_connections(db: OrmSession) -> list[dict[str, Any]]:
    """The connections an incident can be mirrored with, and what each can do."""
    found = []
    for connection in db.scalars(select(Connection).where(Connection.enabled.is_(True)).order_by(Connection.name)):
        connector = _connector(db, connection)
        if connector is None or connector.mirror is None:
            continue
        found.append(
            {
                "id": connection.id,
                "name": connection.name,
                "connector": connector.name,
                "out": can_send(connector.mirror),
                "comments": connector.mirror.comments is not None or connector.mirror.thread is not None,
            }
        )
    return found


def out(db: OrmSession, incident: Incident) -> dict[str, Any]:
    state = state_of(incident)
    if state is None:
        return {"mirrored": False}
    connection = db.get(Connection, state["connection"])
    connector = _connector(db, connection)
    waiting = db.scalars(
        select(MirrorJob).where(MirrorJob.incident_id == incident.id, MirrorJob.status == "pending")
    ).all()
    can = {"fieldsIn": False, "commentsIn": False, "fieldsOut": False, "commentsOut": False}
    if connector is not None and connector.mirror is not None:
        can = abilities(connector.mirror.of(state["id"])[2])
    return {
        "mirrored": True,
        "instanceId": state["connection"],
        "connection": connection.name if connection is not None else "(a connection that is gone)",
        "id": state["id"],
        "direction": state["direction"],
        # Where the direction came from: the instance that fetched it, its mapper, or a person here.
        "origin": origin_of(state),
        "dataAllow": state.get("allow") or [],
        "startedBy": state.get("startedBy", ""),
        "startedAt": state.get("startedAt"),
        "lastSync": state.get("lastSync"),
        "lastPull": state.get("lastPull"),
        "lastPush": state.get("lastPush"),
        "error": state.get("error") or "",
        # The object is gone on the other side, and is read no more.
        "gone": bool(state.get("gone")),
        # Fed by what the instance fetches: there is nothing to read now.
        "fed": bool(state.get("fed")),
        "can": can,
        "waiting": len(waiting),
    }


def _one_id(value: Any) -> str:
    return str(value or "").strip()[:ID_MAX]


def start(
    db: OrmSession,
    incident: Incident,
    connection: Connection,
    mirror_id: str,
    direction: str,
    actor: str,
    now: float,
    allow: list[str] | None = None,
    *,
    origin: str = "here",
    thread: list[str] | None = None,
) -> dict[str, Any]:
    """Mirror an incident with an object of a connection (the caller commits)."""
    connector = _connector(db, connection)
    if connector is None or connector.mirror is None:
        raise MirrorError("The connector of this instance does not say how to mirror")
    mirror_id = str(mirror_id or "").strip()
    if not mirror_id or len(mirror_id) > ID_MAX:
        raise MirrorError("Say which object of the other side this incident is: its id there")
    if direction not in DIRECTIONS:
        raise MirrorError("Mirroring is in, out or both")
    part = connector.mirror.of(mirror_id)[2]
    if direction in ("out", "both") and not can_send(part):
        raise MirrorError("This connector reads the other side but does not write to it: mirror in")
    fed = part.get is None
    # The classes of data this mirror may send, besides those that always may.
    opened = sorted(set(allow or []) & (set(guard.CLASSES) - guard.ALWAYS))
    state = {
        "connection": connection.id,
        "id": mirror_id,
        "direction": direction,
        "origin": origin,
        "allow": opened,
        "startedBy": actor,
        "startedAt": now_iso(),
        "nextAt": now,
        "seen": [],
        "sent": [],
    }
    if fed:
        # The conversation so far: the item itself and what it goes on from. It was read already.
        state.update(fed=True, seen=[mirror_id], thread=_thread([mirror_id, *(thread or [])], mirror_id))
    _keep(incident, state)
    war_room.system(
        db,
        incident.id,
        f"{actor} started mirroring with {connection.name}, object {mirror_id} ({direction})",
    )
    audit.record(
        db,
        actor,
        "mirror.start",
        f"Mirroring with {connection.name}, object {mirror_id}, direction {direction}"
        + (f", sending {', '.join(opened)}" if opened else ""),
        incident,
        target=connection.name,
    )
    return state


def redirect(
    db: OrmSession,
    incident: Incident,
    direction: str,
    actor: str,
    now: float,
    allow: list[str] | None = None,
    *,
    origin: str = "here",
) -> dict[str, Any]:
    """Change the direction of a mirror, and the classes it may send when they are given (the
    caller commits). What it saw and sent is kept: nothing is said twice for the change."""
    state = state_of(incident)
    if state is None:
        raise MirrorError("This incident is not mirrored", 409)
    connection, connector = _parts(db, state)
    if direction not in DIRECTIONS:
        raise MirrorError("Mirroring is in, out or both")
    if direction != "in" and not can_send(connector.mirror.of(state["id"])[2]):
        raise MirrorError("This connector reads the other side but does not write to it: mirror in")
    before = state["direction"]
    if allow is not None:
        state["allow"] = sorted(set(allow) & (set(guard.CLASSES) - guard.ALWAYS))
    if direction == "in":
        state["allow"] = []
        for job in db.scalars(
            select(MirrorJob).where(MirrorJob.incident_id == incident.id, MirrorJob.status == "pending")
        ):
            job.status, job.error = "failed", "Mirroring does not send any more"
    state.update(direction=direction, origin=origin)
    if direction != "out":
        state["nextAt"] = now
    _keep(incident, state)
    opened = state.get("allow") or []
    war_room.system(db, incident.id, f"{actor} changed mirroring with {connection.name} from {before} to {direction}")
    audit.record(
        db,
        actor,
        "mirror.direction",
        f"Mirroring with {connection.name}, object {state['id']}: direction {before} → {direction}"
        + (f", sending {', '.join(opened)}" if opened else ""),
        incident,
        target=connection.name,
    )
    return state


def stop(db: OrmSession, incident: Incident, actor: str) -> None:
    state = state_of(incident)
    if state is None:
        return
    _keep(incident, None)
    for job in db.scalars(select(MirrorJob).where(MirrorJob.incident_id == incident.id, MirrorJob.status == "pending")):
        job.status, job.error = "failed", "Mirroring was stopped"
    war_room.system(db, incident.id, f"{actor} stopped mirroring")
    audit.record(db, actor, "mirror.stop", "Stopped mirroring", incident)


# --------------------------------------------------------------------------- #
# What an instance says of the incidents its fetch makes                      #
# --------------------------------------------------------------------------- #
def choice_of(connection: Connection) -> tuple[str, list[str]]:
    """The direction an instance gives the incidents it fetches (``none`` when it says nothing)
    and the classes of data their mirrors may send."""
    held = connection.fetch_settings if isinstance(connection.fetch_settings, dict) else {}
    direction = held.get("mirror")
    if direction not in DIRECTIONS:
        return NONE, []
    allow = held.get("mirrorAllow")
    opened = sorted(set(allow) & OFFERED) if isinstance(allow, list) and direction != "in" else []
    return direction, opened


def set_choice(connection: Connection, connector: ConnectorFile, given: dict[str, Any]) -> list[str]:
    """Change what an instance says (``mirror``, ``mirrorAllow``; each kept when left out). The
    caller commits. Gives what changed, in words."""
    before = choice_of(connection)
    direction, allow = before
    if given.get("mirror") is not None:
        direction = str(given["mirror"])
        if direction not in CHOICES:
            raise MirrorError("Mirroring is none, in, out or both")
    if given.get("mirrorAllow") is not None:
        asked = given["mirrorAllow"]
        if not isinstance(asked, list) or any(not isinstance(name, str) for name in asked):
            raise MirrorError("The classes of data a mirror may send are a list of their names")
        unknown = sorted(set(asked) - OFFERED)
        if unknown:
            raise MirrorError(f'"{unknown[0]}" is not a class of data an instance can open for its mirrors')
        allow = sorted(set(asked))
    spec = connector.mirror
    if direction != NONE:
        if spec is None:
            why = f": {connector.no_mirror}" if connector.no_mirror else ""
            raise MirrorError(f"{connector.name} does not mirror{why}")
        if direction != "in" and not can_send(spec):
            raise MirrorError(f"{connector.name} is read and never written to: mirroring with it is None or In")
    if direction in (NONE, "in"):
        allow = []
    held = dict(connection.fetch_settings) if isinstance(connection.fetch_settings, dict) else {}
    held.pop("mirror", None)
    held.pop("mirrorAllow", None)
    if direction != NONE:
        held["mirror"] = direction
        if allow:
            held["mirrorAllow"] = allow
    connection.fetch_settings = held or None
    flag_modified(connection, "fetch_settings")
    changes = []
    if direction != before[0]:
        changes.append(f"mirroring {LABELS[before[0]]} → {LABELS[direction]}")
    if allow != before[1]:
        changes.append(f"its mirrors may send: {', '.join(allow) or 'nothing beyond what always may'}")
    return changes


def choice_out(connection: Connection, connector: ConnectorFile) -> dict[str, Any]:
    """The choice of an instance and what its connector lets it choose, for its form."""
    direction, allow = choice_of(connection)
    spec = connector.mirror
    can = abilities(spec) if spec is not None else None
    offered = [NONE]
    if spec is not None:
        offered.append("in")
        if can_send(spec):
            offered += ["out", "both"]
    return {
        "direction": direction,
        "allow": allow,
        "offered": offered,
        "can": can,
        "fed": spec is not None and spec.get is None,
        "noMirror": connector.no_mirror or "",
        "classes": [
            {"id": name, "label": guard.CLASSES[name]["label"], "warning": guard.CLASSES[name]["warning"]}
            for name in guard.CLASSES
            if name in OFFERED
        ],
    }


def _ids(value: Any) -> list[str]:
    """Ids as a template gives them: a list, or a text of ids separated by spaces or commas."""
    if isinstance(value, (list, tuple)):
        parts = [str(item) for item in value if item not in (None, "")]
    else:
        parts = re.split(r"[\s,]+", str(value or ""))
    found: list[str] = []
    for part in parts:
        one = _one_id(part)
        if one and one not in found:
            found.append(one)
    return found


def _thread(ids: list[str], root: str) -> list[str]:
    """The ids of a conversation, each once, the first one always kept."""
    found: list[str] = []
    for one in ids:
        if one and one != root and one not in found:
            found.append(one)
    return [root, *found[-(THREAD_MAX - 1) :]]


def _of_item(template: str, item: Any) -> Any:
    try:
        return ex.render_text(template, ex.Scope(values={"item": item, "config": {}, "state": {}})).data
    except ex.ExpressionError:
        return None


def id_for(connector: ConnectorFile, item: Any, item_id: str) -> str:
    """The id, on the other side, of the object a fetched item is."""
    spec = connector.mirror
    if spec is None or spec.id is None:
        return _one_id(item_id)
    return _one_id(_of_item(spec.id, item))


def start_fetched(
    db: OrmSession,
    incident: Incident,
    connection: Connection,
    connector: ConnectorFile,
    item: Any,
    item_id: str,
    source: str,
    now: float,
) -> list[str]:
    """Start the mirror of an incident a fetch just made, when there is one to start (the caller
    commits). Gives what could not be done.

    A mapper that wrote both ``mirror_id`` and ``mirror_direction`` is obeyed, as before instances
    had a choice. Otherwise the instance says the direction (nothing starts when it says none) and
    the id is the mapper's ``mirror_id`` when it wrote one, else what the connector says of the item."""
    held = incident.fields if isinstance(incident.fields, dict) else {}
    mapped_id, mapped_direction = held.get("mirror_id"), held.get("mirror_direction")
    direction, allow = choice_of(connection)
    if mapped_id and mapped_direction:
        mirror_id, wanted, origin = str(mapped_id), str(mapped_direction), "mapper"
    elif direction == NONE or connector.mirror is None:
        return []
    else:
        mirror_id, wanted, origin = str(mapped_id or "") or id_for(connector, item, item_id), direction, "instance"
        if not mirror_id:
            return ["Mirroring was not started: the item does not say which object of the other side it is"]
    thread = None
    if connector.mirror is not None and connector.mirror.thread is not None:
        thread = _ids(_of_item(connector.mirror.thread.ids, item))
    try:
        start(db, incident, connection, mirror_id, wanted, source, now, allow, origin=origin, thread=thread)
    except MirrorError as error:
        return [error.message]
    # Written now: what keeps the item as evidence reads the incident again from the database.
    db.flush()
    return []


def _fetched_open(db: OrmSession, connection: Connection) -> list[str]:
    return list(
        db.scalars(
            select(Incident.id)
            .where(Incident.source_connection_id == connection.id, Incident.status != "closed")
            .order_by(Incident.id)
            .limit(APPLY_MAX)
        )
    )


def open_count(db: OrmSession, connection: Connection) -> dict[str, Any]:
    """How many open incidents an instance fetched, and how many of them are mirrored with it:
    what applying its choice to them would go through."""
    ids = _fetched_open(db, connection)
    mirrored = 0
    for incident_id in ids:
        state = state_of(db.get(Incident, incident_id))
        if state is not None and state["connection"] == connection.id:
            mirrored += 1
    return {"open": len(ids), "mirrored": mirrored, "direction": choice_of(connection)[0], "most": APPLY_MAX}


def _id_of_fetched(db: OrmSession, incident: Incident, connection: Connection, connector: ConnectorFile) -> str:
    """The id of the object an incident fetched earlier was made from: the id of its item, or what
    the connector reads in the item, which the first line of its War Room kept as it came."""
    spec = connector.mirror
    if spec.id is None:
        made = db.scalars(
            select(FetchedItem.item_id)
            .where(FetchedItem.connection_id == connection.id, FetchedItem.incident_id == incident.id)
            .order_by(FetchedItem.fetched_at)
        ).first()
        return _one_id(made)
    lines = db.scalars(
        select(WarRoomEntry)
        .where(WarRoomEntry.incident_id == incident.id, WarRoomEntry.kind == "system")
        .order_by(WarRoomEntry.at)
        .limit(20)
    )
    for line in lines:
        item = line.body.get("item") if isinstance(line.body, dict) else None
        if isinstance(item, dict) and not item.get("truncated"):
            return id_for(connector, item, "")
    return ""


def apply_choice(db: OrmSession, connection: Connection, actor: str, now: float) -> dict[str, int]:
    """Give the open incidents an instance fetched the direction it says now: start the mirror of
    those that have none, change the others, and stop them all when it says none. An incident
    mirrored with another instance is left as it is. Commits as it goes, an incident at a time."""
    connector = _connector(db, connection)
    if connector is None or (connector.mirror is None and choice_of(connection)[0] != NONE):
        raise MirrorError("The connector of this instance does not say how to mirror")
    direction, allow = choice_of(connection)
    name, connection_id = connection.name, connection.id
    counts = {"started": 0, "changed": 0, "stopped": 0, "unchanged": 0, "skipped": 0}
    for incident_id in _fetched_open(db, connection):
        incident = lock_incident(db, incident_id)
        if incident is None:
            continue
        state = state_of(incident)
        done = "unchanged"
        try:
            if state is not None and state["connection"] != connection_id:
                done = "skipped"  # a person mirrored it with something else
            elif direction == NONE:
                if state is not None:
                    stop(db, incident, actor)
                    done = "stopped"
            elif state is None:
                mirror_id = _id_of_fetched(db, incident, connection, connector)
                if mirror_id:
                    start(db, incident, connection, mirror_id, direction, actor, now, allow, origin="instance")
                    done = "started"
                else:
                    done = "skipped"  # Nik no longer holds what says which object it is
            elif state["direction"] != direction or (state.get("allow") or []) != allow:
                redirect(db, incident, direction, actor, now, allow, origin="instance")
                done = "changed"
        except MirrorError:
            db.rollback()
            done = "skipped"
        counts[done] += 1
        db.commit()
    said = ", ".join(f"{count} {what}" for what, count in counts.items() if count) or "none to change"
    audit.record(
        db,
        actor,
        "mirror.apply",
        f'Applied mirroring {LABELS[direction]} of "{name}" to the open incidents it fetched: {said}',
        target=name,
    )
    db.commit()
    return counts


# --------------------------------------------------------------------------- #
# Calling the other side                                                      #
# --------------------------------------------------------------------------- #
def _args(connector: ConnectorFile, call: MirrorCall, values: dict[str, Any]) -> dict[str, Any]:
    """What a command of mirroring is given: its templates, or the id to its first argument."""
    command = connector.command(call.command)
    if call.args:
        rendered = ex.render(call.args, ex.Scope(values=values)).data
        return {key: value for key, value in rendered.items() if value not in (None, "")}
    names = [argument.name for argument in command.arguments]
    given = {names[0]: values["mirror"]["id"]}
    if "fields" in values and len(names) > 1 and "fields" in names:
        given["fields"] = values["fields"]
    if "comment" in values and "text" in names:
        given["text"] = values["comment"]["text"]
    return given


def _run(db: OrmSession, connection: Connection, connector: ConnectorFile, call: MirrorCall, values: dict) -> dict:
    runtime = store.runtime_for(db, connector, connection)
    try:
        answer = runtime.run(call.command, _args(connector, call, values))
    finally:
        runtime.close()
    if not answer.done:
        raise CommandError("The other side takes too long to answer for mirroring")
    return answer.outputs or {}


# --------------------------------------------------------------------------- #
# In                                                                          #
# --------------------------------------------------------------------------- #
def due(db: OrmSession, now: float) -> list[str]:
    """The mirrored incidents whose time to be read has come."""
    found = []
    for incident in db.scalars(select(Incident).where(Incident.mirror.isnot(None))):
        state = state_of(incident)
        if state is None or state["direction"] not in ("in", "both"):
            continue
        if incident.archived_at:
            continue  # an archived incident is read-only: nothing is pulled into it
        if state.get("fed") or state.get("gone"):
            continue  # fed by the fetch; or gone on the other side, until someone reads it by hand
        if float(state.get("nextAt") or 0) > now:
            continue
        if incident.status == "closed" and not _closed_lately(incident, now):
            continue
        found.append(incident.id)
    return found


def _closed_lately(incident: Incident, now: float) -> bool:
    closed = clock.stamp(incident.closed_at)
    return bool(closed) and now - closed < AFTER_CLOSE


def _digest(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8", "replace")).hexdigest()[:16]


def _gone(db: OrmSession, incident: Incident, state: dict, connection: Connection, now: float) -> dict[str, Any]:
    """The object is not on the other side any more: the mirror is read no more, and that is said
    once, on the incident and to who has it (the caller commits)."""
    first = not state.get("gone")
    state.update(gone=True, error=GONE, fails=0, nextAt=now + BACKOFF_MAX)
    _keep(incident, state)
    if first:
        war_room.system(
            db, incident.id, f"Object {state['id']} is gone from {connection.name}: mirroring reads it no more"
        )
        _tell(db, incident, f"{incident.name}: the object it is mirrored with is gone from {connection.name}")
    return {"changed": [], "kept": [], "comments": 0, "problems": [GONE], "gone": True}


def _tell(db: OrmSession, incident: Incident, text: str) -> None:
    """Tell who has the incident; when nobody has it, who manages connectors."""
    from . import tasks
    from .core.models import User
    from .core.permissions import CONNECTORS_MANAGE, permissions_of

    link = f"/incident/{incident.id}"
    owner = str((incident.doc or {}).get("assignee") or "") if isinstance(incident.doc, dict) else ""
    if owner:
        tasks.notify(db, owner, "mirror.gone", text, link)
        return
    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if CONNECTORS_MANAGE in permissions_of(user.roles or []):
            tasks.notify(db, user.username, "mirror.gone", text, link)


def pull(db: OrmSession, incident: Incident, now: float) -> dict[str, Any]:
    """Read the other side once and apply it (the caller commits). Returns what changed."""
    state = state_of(incident)
    if state is None:
        raise MirrorError("This incident is not mirrored", 409)
    connection, connector = _parts(db, state)
    kind, mirror_id, spec = connector.mirror.of(state["id"])
    if spec.get is None:
        raise MirrorError("This mirror is fed by what its instance fetches: there is nothing to read now", 409)
    source = f"connector:{connector.id}"
    values = {"mirror": {"id": mirror_id, "kind": kind}, "since": state.get("lastCommentAt") or ""}
    try:
        result = _run(db, connection, connector, spec.get, values)
    except CommandError as error:
        if error.status in (404, 410):
            return _gone(db, incident, state, connection, now)
        raise
    try:
        item = ex.render_text(spec.item, ex.Scope(values={"result": result})).data
    except ex.ExpressionError:
        item = result
    if item in (None, "", [], {}):
        # A list that was asked for one id and came back empty: the object is not there.
        return _gone(db, incident, state, connection, now)
    changed: list[str] = []
    kept: list[str] = []
    problems: list[str] = []
    mapper = mapping.find_mapper(db, connector.id, "incoming", incident.type_id)
    mapped = mapping.apply_incoming(
        db, mapper.rules if mapper is not None else [], item, connector.id, incident.type_id
    )
    problems += mapped.problems
    current = registry.read(db, incident)
    comments = 0
    # Fields, context and comments are one update: what it brought is read for indicators once,
    # when it is whole, and leaves one line (indicators_found.py).
    with indicators_found.together(db, incident):
        for name, value in mapped.fields.items():
            if name in mapping._SOURCE or current.get(name) == value:
                continue
            last = registry.source_of(db, incident, name)
            if not incident_context.may_overwrite(last, source, name in mapped.authoritative):
                kept.append(name)  # a person set it in Nik: it stays
                continue
            try:
                # A value the registry keeps another way (a tag in lower case) may be what is there already.
                if registry.update(db, incident, {name: value}, source, source):
                    changed.append(name)
            except registry.FieldError as error:
                problems.append(error.message)
        if mapped.context:
            try:
                incident_context.apply(db, incident, list(mapped.context), source, source)
            except incident_context.ContextError as error:
                problems.append(f"Context: {error.message}")
        if spec.comments is not None:
            comments, closing = _comments_in(db, incident, connection, connector, spec.comments, state, values)
            # The status as this read left it: the fields above may have just closed it.
            if spec.comments.close_notes and closing and registry.read(db, incident).get("status") == "closed":
                _close_notes(db, incident, closing, source, changed, kept, problems)
    stamp = now_iso()
    state.update(
        lastSync=stamp,
        lastPull=stamp,
        nextAt=now + connector.mirror.interval_seconds,
        error="; ".join(problems)[:500],
        fails=0,
    )
    state.pop("gone", None)
    _keep(incident, state)
    return {"changed": changed, "kept": kept, "comments": comments, "problems": problems}


def _comments_in(
    db: OrmSession,
    incident: Incident,
    connection: Connection,
    connector: ConnectorFile,
    spec,
    state: dict,
    values: dict,
) -> tuple[int, str]:
    """The comments of the other side not seen before, as lines of the War Room. Gives how many
    came, and the last one a person wrote there (any, seen before or not; "" when there is none):
    what a connector whose product keeps the note of closing as a comment makes the close notes."""
    result = _run(db, connection, connector, spec.list, values)
    try:
        found = ex.render_text(spec.items, ex.Scope(values={"result": result})).data
    except ex.ExpressionError:
        found = []
    seen = list(state.get("seen") or [])
    sent = set(state.get("sent") or [])
    machines = _automations(connection, connector, spec) if spec.close_notes else set()
    added = 0
    latest = str(state.get("lastCommentAt") or "")
    closing, closing_at = "", ""
    for item in found if isinstance(found, list) else []:
        scope = ex.Scope(values={"item": item})
        comment_id, text = _read(spec.id, scope), _read(spec.text, scope)
        if not text:
            continue
        at, author = _read(spec.at, scope), _read(spec.author, scope)
        mine = _digest(text) in sent
        if spec.close_notes and not mine and author.casefold() not in machines and at >= closing_at:
            closing, closing_at = text[:COMMENT_MAX], at
        key = comment_id or _digest(text)
        if key in seen:
            continue
        seen.append(key)
        if mine:
            continue  # Nik sent it: it is not said twice
        war_room.add(
            db,
            incident.id,
            "mirror",
            {
                "text": text[:COMMENT_MAX],
                "from": author,
                "at": at,
                "direction": "in",
                "connection": connection.name,
            },
            f"connector:{connector.id}",
        )
        # What the other side said is read for indicators with the update it came in.
        indicators_found.after_update(db, incident, f"connector:{connector.id}", [text[:COMMENT_MAX]])
        latest = max(latest, at)
        added += 1
    state["seen"] = seen[-SEEN_MAX:]
    if latest:
        state["lastCommentAt"] = latest
    return added, closing


def _automations(connection: Connection, connector: ConnectorFile, spec) -> set[str]:
    """The authors of comments that are not people, as the instance names them (lower case)."""
    config: dict[str, Any] = {}
    given = connection.config if isinstance(connection.config, dict) else {}
    for param in connector.configuration:
        if param.is_auth or param.type == "secret":
            continue
        value = given.get(param.name)
        config[param.name] = param.default if value in (None, "") else value
    try:
        named = ex.render_text(spec.automations, ex.Scope(values={"config": config})).data if spec.automations else ""
    except ex.ExpressionError:
        named = ""
    items = named if isinstance(named, list) else str(named or "").split(",")
    return {str(item).strip().casefold() for item in items if str(item).strip()}


def _close_notes(
    db: OrmSession, incident: Incident, text: str, source: str, changed: list, kept: list, problems: list
) -> None:
    """The close notes of a closed incident become what a person last wrote on the other side,
    unless a person wrote them in Nik."""
    if str(registry.read(db, incident).get("close_notes") or "").strip() == text.strip():
        return
    if not incident_context.may_overwrite(registry.source_of(db, incident, "close_notes"), source, False):
        kept.append("close_notes")
        return
    try:
        if registry.update(db, incident, {"close_notes": text}, source, source):
            changed.append("close_notes")
    except registry.FieldError as error:
        problems.append(error.message)


def _read(template: str, scope: ex.Scope) -> str:
    """A part of a comment, as text; "" when the comment does not have it."""
    try:
        return ex._text(ex.render_text(template, scope).data).strip()
    except ex.ExpressionError:
        return ""


def absorb(
    db: OrmSession, connection: Connection, connector: ConnectorFile, item: Any, item_id: str, now: float
) -> dict[str, Any] | None:
    """A fetched item that goes on with a conversation an incident holds, for a connector whose
    mirror is fed by its fetch: it becomes a line of the War Room of that incident and makes none of
    its own (the caller commits). None when it belongs to no incident mirrored in with this
    instance. ``fresh`` is false for an item that was there already (the same message twice);
    ``text`` is what the line says, for whoever reads it for indicators once its evidence is kept.

    An item belongs to an incident when it names an id of its conversation, or is itself named
    there (a reply that came before what it answers). The incident mirrored the longest wins."""
    spec = connector.mirror
    if spec is None or spec.thread is None:
        return None
    own = id_for(connector, item, item_id)
    named = _ids(_of_item(spec.thread.ids, item))
    wanted = set(named) | ({own} if own else set())
    if not wanted:
        return None
    found: list[tuple[str, str]] = []
    for incident in db.scalars(select(Incident).where(Incident.mirror.isnot(None))):
        state = state_of(incident)
        if state is None or state["connection"] != connection.id or not state.get("fed"):
            continue
        if state["direction"] not in ("in", "both"):
            continue
        if incident.archived_at:
            continue  # read-only: what goes on with its conversation is an item of its own
        if incident.status == "closed" and not _closed_lately(incident, now):
            continue
        if wanted & set(state.get("thread") or [state["id"]]):
            found.append((str(state.get("startedAt") or ""), incident.id))
    if not found:
        return None
    incident = lock_incident(db, min(found)[1])
    state = state_of(incident) if incident is not None else None
    if state is None:
        return None
    seen = list(state.get("seen") or [])
    fresh = not own or own not in seen
    text = ""
    if fresh:
        scope = ex.Scope(values={"item": item, "config": {}, "state": {}})
        text = _read(spec.thread.text, scope)[:COMMENT_MAX]
        war_room.add(
            db,
            incident.id,
            "mirror",
            {
                "text": text or "(nothing written)",
                "from": _read(spec.thread.author, scope),
                "at": _read(spec.thread.at, scope),
                "direction": "in",
                "connection": connection.name,
            },
            f"connector:{connector.id}",
        )
        if own:
            seen.append(own)
    stamp = now_iso()
    state.update(
        seen=seen[-SEEN_MAX:],
        thread=_thread([*(state.get("thread") or []), own, *named], state["id"]),
        lastSync=stamp,
        lastPull=stamp,
        error="",
    )
    _keep(incident, state)
    db.flush()  # as in start_fetched: the evidence is kept on the incident read again
    return {"incident_id": incident.id, "fresh": fresh, "text": text}


def run_pull(incident_id: str, now: float | None = None) -> None:
    """Read the other side for one incident, in a session of its own (the worker's pool)."""
    from .core.db import SessionLocal

    now = time.time() if now is None else now
    with SessionLocal() as db:
        incident = lock_incident(db, incident_id)
        if incident is None or state_of(incident) is None:
            return
        if incident.archived_at:
            logger.debug("Mirror: the incident %s is archived, it is not read", incident_id)
            return
        try:
            pull(db, incident, now)
            db.commit()
        except (MirrorError, CommandError, ex.ExpressionError) as error:
            db.rollback()
            _failed_pull(db, incident_id, getattr(error, "message", str(error)), now)
        except Exception:  # noqa: BLE001 - the worker must survive a bad read
            db.rollback()
            logger.exception("Mirror: reading for incident %s failed", incident_id)
            _failed_pull(db, incident_id, "Reading the other side failed for a reason Nik did not expect", now)


def _failed_pull(db: OrmSession, incident_id: str, message: str, now: float) -> None:
    incident = db.get(Incident, incident_id)
    state = state_of(incident) if incident is not None else None
    if state is None:
        return
    fails = int(state.get("fails") or 0) + 1
    state.update(error=message[:500], fails=fails, nextAt=now + min(BACKOFF_MAX, 120 * (2 ** min(fails, 10))))
    _keep(incident, state)
    db.commit()


# --------------------------------------------------------------------------- #
# Out                                                                         #
# --------------------------------------------------------------------------- #
def _reads(rules: list | None) -> set[str]:
    """The fields of the incident an outgoing mapper reads."""
    found: set[str] = set()
    for rule in rules or []:
        template = rule.get("from")
        if not isinstance(template, str) or "{{" not in template:
            continue
        try:
            found |= ex.first_names(template, "incident")
        except ex.ExpressionError:
            continue
    return found


def _enqueue(db: OrmSession, incident: Incident, state: dict, kind: str, payload: dict, actor: str, now: float) -> None:
    db.add(
        MirrorJob(
            id=new_id(),
            incident_id=incident.id,
            connection_id=state["connection"],
            kind=kind,
            payload=payload,
            next_at=now,
            created_at=now_iso(),
            created_by=actor[:200],
        )
    )


def sends(db: OrmSession, incident: Incident, changed: list[str], source: str) -> bool:
    """Whether a change of these fields of the incident, made by ``source``, is sent to the other
    side: the incident is mirrored Out or In-out, from the instance or not, the object is not gone,
    the outgoing mapper reads one of the fields and the connector can write them. What the mirror's
    own connector wrote is never sent back."""
    state = state_of(incident)
    if state is None or state["direction"] not in ("out", "both") or not changed:
        return False
    if state.get("gone"):
        return False  # there is nothing on the other side to write to
    connection = db.get(Connection, state["connection"])
    if connection is None or source == f"connector:{connection.connector_id}":
        return False
    mapper = mapping.find_mapper(db, connection.connector_id, "outgoing", incident.type_id)
    if mapper is None or not (_reads(mapper.rules) & set(changed)):
        return False
    connector = _connector(db, connection)
    # A connector that sends comments and no fields sends nothing for a field.
    return (
        connector is not None
        and connector.mirror is not None
        and connector.mirror.of(state["id"])[2].update is not None
    )


def on_fields_changed(db: OrmSession, incident: Incident, changed: list[str], source: str, now: float) -> bool:
    """A field of a mirrored incident changed in Nik: queue it for the other side when it is sent
    (``sends``; the caller commits)."""
    if not sends(db, incident, changed, source):
        return False
    state = state_of(incident)
    db.flush()
    waiting = db.scalars(
        select(MirrorJob).where(
            MirrorJob.incident_id == incident.id, MirrorJob.kind == "update", MirrorJob.status == "pending"
        )
    ).first()
    if waiting is None:
        # One update waiting is enough: it sends the incident as it is when it goes.
        _enqueue(db, incident, state, "update", {"changed": sorted(changed)}, source, now)
    return True


def on_note(db: OrmSession, incident: Incident, text: str, tags: list[str], actor: str, now: float) -> bool:
    """A note tagged ``mirror`` on an incident mirrored out: queue it as a comment (the caller
    commits). On an incident mirrored with something that never sends (a mailbox), the War Room
    says that the note stayed here."""
    state = state_of(incident)
    if state is None or TAG not in (tags or []):
        return False
    connection = db.get(Connection, state["connection"])
    connector = _connector(db, connection)
    if connector is None or connector.mirror is None:
        return False
    comments = connector.mirror.of(state["id"])[2].comments
    if comments is None or comments.add is None:
        if not can_send(connector.mirror):
            war_room.system(
                db,
                incident.id,
                f"The note tagged {TAG} was not sent: {connection.name} is read and never written to. "
                "Use the reply command of the instance to answer.",
            )
        return False
    if state["direction"] not in ("out", "both") or state.get("gone"):
        return False
    _enqueue(db, incident, state, "comment", {"text": text[:COMMENT_MAX], "author": actor}, f"user:{actor}", now)
    return True


def jobs_due(db: OrmSession, now: float) -> list[str]:
    return list(
        db.scalars(
            select(MirrorJob.id)
            .where(MirrorJob.status == "pending", MirrorJob.next_at <= now)
            .order_by(MirrorJob.created_at)
            .limit(50)
        )
    )


def push(db: OrmSession, job: MirrorJob, now: float) -> None:
    """Send one thing to the other side (the caller commits). Raises what went wrong."""
    incident = db.get(Incident, job.incident_id)
    state = state_of(incident) if incident is not None else None
    if state is None or state["connection"] != job.connection_id:
        raise MirrorError("The incident is not mirrored any more")
    if incident.archived_at:
        # Archived after this was queued: nothing is sent, and nothing is written to the incident.
        logger.debug("Mirror: the incident %s is archived, job %s sends nothing", incident.id, job.id)
        return
    if state["direction"] not in ("out", "both"):
        raise MirrorError("Mirroring does not send any more")
    connection, connector = _parts(db, state)
    kind, mirror_id, spec = connector.mirror.of(state["id"])
    values: dict[str, Any] = {
        "mirror": {"id": mirror_id, "kind": kind},
        "incident": registry.read(db, incident),
        "context": incident_context.read(db, incident.id),
        "since": "",
    }
    if job.kind == "update":
        if spec.update is None:
            raise MirrorError("This connector does not write to the other side")
        mapper = mapping.find_mapper(db, connector.id, "outgoing", incident.type_id)
        fields = mapping.apply_outgoing(
            db, mapper.rules if mapper is not None else [], incident, {"id": mirror_id, "kind": kind}
        )
        if not fields:
            return  # the mapper sends nothing for this incident: there is nothing to say
        values["fields"] = fields
        call = spec.update
    else:
        if spec.comments is None or spec.comments.add is None:
            raise MirrorError("This connector does not send comments")
        text = str(job.payload.get("text") or "")
        values["comment"] = {"text": text, "author": str(job.payload.get("author") or "")}
        call = spec.comments.add
    # What leaves passes the data guard, with the classes opened when mirroring was started.
    args = _args(connector, call, values)
    decision = guard.check(args, frozenset(), frozenset(state.get("allow") or []), guard.context_from(db))
    if not decision.allowed:
        raise MirrorError(decision.sentence())
    _run_args(db, connection, connector, call.command, args)
    if job.kind == "comment":
        sent = list(state.get("sent") or [])
        sent.append(_digest(str(job.payload.get("text") or "")))
        state["sent"] = sent[-SEEN_MAX:]
        war_room.add(
            db,
            incident.id,
            "mirror",
            {"text": "Sent as a comment", "direction": "out", "connection": connection.name},
            f"connector:{connector.id}",
        )
    stamp = now_iso()
    state.update(lastSync=stamp, lastPush=stamp)
    _keep(incident, state)


def _run_args(db: OrmSession, connection: Connection, connector: ConnectorFile, command: str, args: dict) -> dict:
    runtime = store.runtime_for(db, connector, connection)
    try:
        answer = runtime.run(command, args)
    finally:
        runtime.close()
    if not answer.done:
        raise CommandError("The other side takes too long to answer for mirroring")
    return answer.outputs or {}


UNKNOWN = "it is not known whether the comment reached the other side. Look there, and send it again if it did not"


def run_push(job_id: str, now: float | None = None, holder: str | None = None) -> None:
    """Send one queued thing, in a session of its own (the worker's pool).

    **Across a restart.** The job is marked ``sending``, with who sends it, in a commit of its own
    before the request leaves, and ``done`` in the commit that keeps what the send changed here.
    A job another worker finds ``sending`` was cut in between (``take_back``):

    - an **update** writes the fields of the incident as they are when it is sent. Sending it twice
      leaves the other side as sending it once: it is **sent again**;
    - a **comment** sent twice is two comments, and nobody here can tell whether the first
      arrived: it is **not sent again**. The job fails with a sentence that says so, on the
      incident and in the queue, where a person sends it again or leaves it.

    The same holds for a comment whose request left and got no answer."""
    from .core.db import SessionLocal

    now = time.time() if now is None else now
    if holder is None:
        from .automation import worker

        holder = worker.HOLDER
    with SessionLocal() as db:
        won = db.execute(
            update(MirrorJob)
            .where(MirrorJob.id == job_id, MirrorJob.status == "pending")
            .values(status="sending", holder=holder)
        ).rowcount
        db.commit()
        if not won:
            return
        job = db.get(MirrorJob, job_id)
        db.refresh(job)
        unknown = False
        try:
            push(db, job, now)
            job.status, job.error, job.holder = "done", "", None
            db.commit()
            return
        except (MirrorError, CommandError, ex.ExpressionError) as error:
            message = getattr(error, "message", str(error))
            unknown = (
                job.kind == "comment" and bool(getattr(error, "sent", False)) and bool(getattr(error, "retry", False))
            )
        except Exception:  # noqa: BLE001 - the worker must survive a bad send
            logger.exception("Mirror: sending job %s failed", job_id)
            message = "Sending failed for a reason Nik did not expect: see the server's log"
        db.rollback()
        job = db.get(MirrorJob, job_id)
        job.attempts = (job.attempts or 0) + 1
        job.error, job.holder = message[:500], None
        if unknown:
            job.status, job.error = "failed", f"No answer came back: {UNKNOWN}"[:500]
        elif job.attempts >= ATTEMPTS_MAX:
            job.status = "failed"
        else:
            job.status = "pending"
            job.next_at = now + min(BACKOFF_MAX, 60 * (2**job.attempts))
        db.commit()


def take_back(db: OrmSession, now: float, holder: str) -> int:
    """The jobs that were being sent by a worker that is gone (this one holds the lease, so a job
    ``sending`` under another name lost its worker), by the rule of ``run_push``. Commits. Returns
    how many."""
    lost = db.scalars(
        select(MirrorJob).where(
            MirrorJob.status == "sending", or_(MirrorJob.holder.is_(None), MirrorJob.holder != holder)
        )
    ).all()
    for job in lost:
        job.holder = None
        if job.kind == "update":
            job.status, job.next_at = "pending", now
            job.error = "Interrupted by a restart: sent again"
        else:
            job.status = "failed"
            job.error = f"Interrupted by a restart: {UNKNOWN}"[:500]
        logger.warning("Mirror: job %s (%s) was being sent when the worker stopped: %s", job.id, job.kind, job.status)
    if lost:
        db.commit()
    return len(lost)


def queue(db: OrmSession, limit: int = 200) -> list[dict[str, Any]]:
    """What waits to be sent or could not be, the newest first."""
    rows = db.scalars(
        select(MirrorJob).where(MirrorJob.status != "done").order_by(MirrorJob.created_at.desc()).limit(limit)
    ).all()
    out_rows = []
    for row in rows:
        incident = db.get(Incident, row.incident_id)
        connection = db.get(Connection, row.connection_id)
        out_rows.append(
            {
                "id": row.id,
                "incidentId": row.incident_id,
                "incident": incident.name if incident is not None else "",
                "connection": connection.name if connection is not None else "",
                "kind": row.kind,
                "status": row.status,
                "attempts": row.attempts,
                "error": row.error,
                "nextAt": row.next_at,
                "createdAt": row.created_at,
                "createdBy": row.created_by,
            }
        )
    return out_rows
