"""Mirroring: an incident and one object of another product kept in step.

An incident is mirrored with one connection whose connector has a ``mirror``:
``incident.mirror`` holds the connection, the id of the object on the other
side, the direction (``in``, ``out`` or ``both``) and how it goes.

- **In.** The worker reads the object every ``mirror.interval_seconds``
  (``pull``): ``mirror.get`` → the item → the incoming mapper → the fields,
  written under the provenance rule: what a person set in Nik stays, unless
  the mapper marks the field authoritative. Comments not seen before become
  lines of the War Room. A closed incident is read for a day more, then left.
- **Out.** A change, made in Nik, of a field the outgoing mapper reads, and a
  note tagged ``mirror``, are queued (``mirror_queue``) and sent by the
  worker (``push``) with ``mirror.update`` and ``mirror.comments.add``. What
  is sent passes the data guard, with the classes opened when mirroring was
  started, and reaches the host of the connection only. A send that fails is
  tried again later and later, eight times.

A loop is not possible: a change whose source is the connector of the mirror
is never sent back, and a comment Nik sent is known when it comes back.
"""

from __future__ import annotations

import hashlib
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import context as incident_context
from . import fields as registry
from . import mapping, war_room
from .automation import connector_actions as store
from .automation import expressions as ex
from .automation import guard
from .automation.connector_runtime import CommandError
from .automation.connectors import ConnectorFile, MirrorCall
from .core import audit
from .core.models import Connection, Connector, Incident, MirrorJob
from .core.security import now_iso

logger = logging.getLogger("nik.mirror")

DIRECTIONS = ("in", "out", "both")
TAG = "mirror"  # a note with this tag is sent to the other side as a comment
ATTEMPTS_MAX = 8
BACKOFF_MAX = 3600
AFTER_CLOSE = 86_400  # a closed incident is read for a day more
SEEN_MAX = 300
COMMENT_MAX = 20_000


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


def _parts(db: OrmSession, state: dict[str, Any]) -> tuple[Connection, ConnectorFile]:
    connection = db.get(Connection, state.get("connection") or "")
    row = db.get(Connector, connection.connector_id) if connection is not None else None
    connector = store.parsed(row) if row is not None else None
    if connection is None or connector is None or connector.mirror is None:
        raise MirrorError("The instance this incident is mirrored with is gone, or its connector mirrors no more")
    return connection, connector


def mirroring_connections(db: OrmSession) -> list[dict[str, Any]]:
    """The connections an incident can be mirrored with, and what each can do."""
    found = []
    for connection in db.scalars(select(Connection).where(Connection.enabled.is_(True)).order_by(Connection.name)):
        row = db.get(Connector, connection.connector_id)
        connector = store.parsed(row) if row is not None else None
        if connector is None or connector.mirror is None:
            continue
        found.append(
            {
                "id": connection.id,
                "name": connection.name,
                "connector": connector.name,
                "out": connector.mirror.update is not None,
                "comments": connector.mirror.comments is not None,
            }
        )
    return found


def out(db: OrmSession, incident: Incident) -> dict[str, Any]:
    state = state_of(incident)
    if state is None:
        return {"mirrored": False}
    connection = db.get(Connection, state["connection"])
    waiting = db.scalars(
        select(MirrorJob).where(MirrorJob.incident_id == incident.id, MirrorJob.status == "pending")
    ).all()
    return {
        "mirrored": True,
        "instanceId": state["connection"],
        "connection": connection.name if connection is not None else "(a connection that is gone)",
        "id": state["id"],
        "direction": state["direction"],
        "dataAllow": state.get("allow") or [],
        "startedBy": state.get("startedBy", ""),
        "startedAt": state.get("startedAt"),
        "lastSync": state.get("lastSync"),
        "error": state.get("error") or "",
        "waiting": len(waiting),
    }


def start(
    db: OrmSession,
    incident: Incident,
    connection: Connection,
    mirror_id: str,
    direction: str,
    actor: str,
    now: float,
    allow: list[str] | None = None,
) -> dict[str, Any]:
    """Mirror an incident with an object of a connection (the caller commits)."""
    row = db.get(Connector, connection.connector_id)
    connector = store.parsed(row) if row is not None else None
    if connector is None or connector.mirror is None:
        raise MirrorError("The connector of this instance does not say how to mirror")
    mirror_id = str(mirror_id or "").strip()
    if not mirror_id or len(mirror_id) > 300:
        raise MirrorError("Say which object of the other side this incident is: its id there")
    if direction not in DIRECTIONS:
        raise MirrorError("Mirroring is in, out or both")
    if direction in ("out", "both") and connector.mirror.update is None:
        raise MirrorError("This connector reads the other side but does not write to it: mirror in")
    # The classes of data this mirror may send, besides those that always may.
    opened = sorted(set(allow or []) & (set(guard.CLASSES) - guard.ALWAYS))
    state = {
        "connection": connection.id,
        "id": mirror_id,
        "direction": direction,
        "allow": opened,
        "startedBy": actor,
        "startedAt": now_iso(),
        "nextAt": now,
        "seen": [],
        "sent": [],
    }
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
        if float(state.get("nextAt") or 0) > now:
            continue
        if incident.status == "closed" and not _closed_lately(incident, now):
            continue
        found.append(incident.id)
    return found


def _closed_lately(incident: Incident, now: float) -> bool:
    try:
        closed = datetime.fromisoformat(str(incident.closed_at).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return False
    if closed.tzinfo is None:
        closed = closed.replace(tzinfo=timezone.utc)
    return now - closed.timestamp() < AFTER_CLOSE


def _digest(text: str) -> str:
    return hashlib.sha256(text.strip().encode("utf-8", "replace")).hexdigest()[:16]


def pull(db: OrmSession, incident: Incident, now: float) -> dict[str, Any]:
    """Read the other side once and apply it (the caller commits). Returns what changed."""
    state = state_of(incident)
    if state is None:
        raise MirrorError("This incident is not mirrored", 409)
    connection, connector = _parts(db, state)
    spec = connector.mirror
    source = f"connector:{connector.id}"
    values = {"mirror": {"id": state["id"]}, "since": state.get("lastCommentAt") or ""}
    result = _run(db, connection, connector, spec.get, values)
    try:
        item = ex.render_text(spec.item, ex.Scope(values={"result": result})).data
    except ex.ExpressionError:
        item = result
    changed: list[str] = []
    kept: list[str] = []
    problems: list[str] = []
    mapper = mapping.find_mapper(db, connector.id, "incoming", incident.type_id)
    mapped = mapping.apply_incoming(
        db, mapper.rules if mapper is not None else [], item, connector.id, incident.type_id
    )
    problems += mapped.problems
    current = registry.read(db, incident)
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

    comments = 0
    if spec.comments is not None:
        comments = _comments_in(db, incident, connection, connector, state, values)
    state.update(lastSync=now_iso(), nextAt=now + spec.interval_seconds, error="; ".join(problems)[:500], fails=0)
    _keep(incident, state)
    return {"changed": changed, "kept": kept, "comments": comments, "problems": problems}


def _comments_in(
    db: OrmSession, incident: Incident, connection: Connection, connector: ConnectorFile, state: dict, values: dict
) -> int:
    spec = connector.mirror.comments
    result = _run(db, connection, connector, spec.list, values)
    try:
        found = ex.render_text(spec.items, ex.Scope(values={"result": result})).data
    except ex.ExpressionError:
        found = []
    seen = list(state.get("seen") or [])
    sent = set(state.get("sent") or [])
    added = 0
    latest = str(state.get("lastCommentAt") or "")
    for item in found if isinstance(found, list) else []:
        scope = ex.Scope(values={"item": item})
        comment_id, text = _read(spec.id, scope), _read(spec.text, scope)
        if not text:
            continue
        key = comment_id or _digest(text)
        if key in seen:
            continue
        seen.append(key)
        if _digest(text) in sent:
            continue  # Nik sent it: it is not said twice
        at = _read(spec.at, scope)
        war_room.add(
            db,
            incident.id,
            "mirror",
            {
                "text": text[:COMMENT_MAX],
                "from": _read(spec.author, scope),
                "at": at,
                "direction": "in",
                "connection": connection.name,
            },
            f"connector:{connector.id}",
        )
        latest = max(latest, at)
        added += 1
    state["seen"] = seen[-SEEN_MAX:]
    if latest:
        state["lastCommentAt"] = latest
    return added


def _read(template: str, scope: ex.Scope) -> str:
    """A part of a comment, as text; "" when the comment does not have it."""
    try:
        return ex._text(ex.render_text(template, scope).data).strip()
    except ex.ExpressionError:
        return ""


def run_pull(incident_id: str, now: float | None = None) -> None:
    """Read the other side for one incident, in a session of its own (the worker's pool)."""
    from .core.db import SessionLocal
    from .core.locking import lock_incident

    now = time.time() if now is None else now
    with SessionLocal() as db:
        incident = lock_incident(db, incident_id)
        if incident is None or state_of(incident) is None:
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
            parts = ex.parse(template)
        except ex.ExpressionError:
            continue
        for part in parts:
            if isinstance(part, ex.Expr) and part.root == "incident" and part.steps and isinstance(part.steps[0], str):
                found.add(part.steps[0])
    return found


def _enqueue(db: OrmSession, incident: Incident, state: dict, kind: str, payload: dict, actor: str, now: float) -> None:
    db.add(
        MirrorJob(
            id=uuid.uuid4().hex,
            incident_id=incident.id,
            connection_id=state["connection"],
            kind=kind,
            payload=payload,
            next_at=now,
            created_at=now_iso(),
            created_by=actor[:200],
        )
    )


def on_fields_changed(db: OrmSession, incident: Incident, changed: list[str], source: str, now: float) -> bool:
    """A field of a mirrored incident changed in Nik: queue it for the other side when the
    outgoing mapper reads it (the caller commits). What the mirror's own connector wrote is never sent back."""
    state = state_of(incident)
    if state is None or state["direction"] not in ("out", "both") or not changed:
        return False
    connection = db.get(Connection, state["connection"])
    if connection is None or source == f"connector:{connection.connector_id}":
        return False
    mapper = mapping.find_mapper(db, connection.connector_id, "outgoing", incident.type_id)
    if mapper is None or not (_reads(mapper.rules) & set(changed)):
        return False
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
    """A note tagged ``mirror`` on an incident mirrored out: queue it as a comment (the caller commits)."""
    state = state_of(incident)
    if state is None or state["direction"] not in ("out", "both") or TAG not in (tags or []):
        return False
    connection = db.get(Connection, state["connection"])
    row = db.get(Connector, connection.connector_id) if connection is not None else None
    connector = store.parsed(row) if row is not None else None
    if connector is None or connector.mirror is None or connector.mirror.comments is None:
        return False
    if connector.mirror.comments.add is None:
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
    connection, connector = _parts(db, state)
    spec = connector.mirror
    values: dict[str, Any] = {
        "mirror": {"id": state["id"]},
        "incident": registry.read(db, incident),
        "context": incident_context.read(db, incident.id),
        "since": "",
    }
    if job.kind == "update":
        if spec.update is None:
            raise MirrorError("This connector does not write to the other side")
        mapper = mapping.find_mapper(db, connector.id, "outgoing", incident.type_id)
        fields = mapping.apply_outgoing(db, mapper.rules if mapper is not None else [], incident, {"id": state["id"]})
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
    state["lastSync"] = now_iso()
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


def run_push(job_id: str, now: float | None = None) -> None:
    """Send one queued thing, in a session of its own (the worker's pool)."""
    from .core.db import SessionLocal

    now = time.time() if now is None else now
    with SessionLocal() as db:
        job = db.get(MirrorJob, job_id)
        if job is None or job.status != "pending":
            return
        try:
            push(db, job, now)
            job.status, job.error = "done", ""
            db.commit()
            return
        except (MirrorError, CommandError, ex.ExpressionError) as error:
            message = getattr(error, "message", str(error))
        except Exception:  # noqa: BLE001 - the worker must survive a bad send
            logger.exception("Mirror: sending job %s failed", job_id)
            message = "Sending failed for a reason Nik did not expect: see the server's log"
        db.rollback()
        job = db.get(MirrorJob, job_id)
        job.attempts = (job.attempts or 0) + 1
        job.error = message[:500]
        if job.attempts >= ATTEMPTS_MAX:
            job.status = "failed"
        else:
            job.next_at = now + min(BACKOFF_MAX, 60 * (2**job.attempts))
        db.commit()


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
