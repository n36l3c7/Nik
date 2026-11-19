"""Fetching: a connection brings alerts in, and each becomes an incident.

A connection whose connector has a ``fetch`` and that was told to fetch is
read by the automation worker every ``interval_seconds``. One cycle:

1. the request is rendered with the ``state`` the last cycle left (before the
   first, what ``first_state`` says of the moment ``first_fetch`` ago), and
   its pages are read, 200 items at most;
2. each item is told apart by ``item_id``: one already in ``fetched_items``
   for this connection is skipped;
3. a new one is classified (its type), mapped (its fields and context),
   passed through the pre-processing rules, and then, in one transaction,
   becomes an incident with its context, a line of its War Room that holds
   the item as it came, and a row of ``fetched_items``;
4. ``next_state`` is saved when the whole cycle was read.

It reaches the host of its own connection and nothing else, and the data
guard is not involved: data comes in. A connection that makes more than 500
incidents in an hour is *paused* until someone looks; one whose request
fails is *failing* and tried again later and later, an hour at most.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import context as incident_context
from . import fields as registry
from . import mapping, timers, war_room
from .automation import connector_actions as store
from .automation import expressions as ex
from .automation.connector_runtime import CommandError
from .automation.connectors import ConnectorFile
from .core import audit
from .core.models import Connection, Connector, FetchedItem, Incident, User
from .core.permissions import CONNECTORS_MANAGE, permissions_of
from .core.security import now_iso

logger = logging.getLogger("nik.fetch")

ITEMS_PER_CYCLE = 200
INCIDENTS_PER_HOUR = 500
BACKOFF_MAX = 3600
ITEM_SHOWN = 20_000  # characters of an item kept as it came (the War Room line, the sample)
ITEM_ID_MAX = 300


class FetchError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


def _moment(epoch: float) -> dict[str, Any]:
    stamp = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {"iso": stamp, "epoch": int(epoch), "epoch_ms": int(epoch * 1000)}


def _cut(item: Any) -> Any:
    """An item as it is kept to be shown: whole when it is small, its start otherwise."""
    try:
        text = json.dumps(item, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return {"note": "The item could not be kept as JSON"}
    if len(text) <= ITEM_SHOWN:
        return json.loads(text)
    return {"truncated": True, "start": text[:2000]}


def connector_of(db: OrmSession, connection: Connection) -> ConnectorFile | None:
    row = db.get(Connector, connection.connector_id)
    return store.parsed(row) if row is not None else None


def status_of(connection: Connection) -> dict[str, Any]:
    return dict(connection.fetch_status) if isinstance(connection.fetch_status, dict) else {}


def _keep_status(connection: Connection, **changes: Any) -> None:
    connection.fetch_status = {**status_of(connection), **changes}
    flag_modified(connection, "fetch_status")


def enable(db: OrmSession, connection: Connection, enabled: bool, now: float) -> None:
    """Tell a connection to fetch, or not to (the caller commits)."""
    connector = connector_of(db, connection)
    if enabled and (connector is None or connector.fetch is None):
        raise FetchError("The connector of this instance does not say how to fetch")
    connection.fetch_enabled = bool(enabled)
    if enabled:
        mapping.default_classifier(db, connection)
        _keep_status(connection, state="ok", error="", fails=0, nextAt=now, pausedWhy="")


def resume(db: OrmSession, connection: Connection, now: float) -> None:
    """Let a paused or failing connection fetch again at once (the caller commits)."""
    _keep_status(connection, state="ok", error="", fails=0, nextAt=now, pausedWhy="", resumedAt=now_iso())


def due(db: OrmSession, now: float) -> list[str]:
    """The connections whose time to fetch has come."""
    found = []
    # An instance that is off fetches nothing, and goes on from where it was when it is on again.
    wanted = select(Connection).where(Connection.fetch_enabled.is_(True), Connection.enabled.is_(True))
    for connection in db.scalars(wanted):
        status = status_of(connection)
        if status.get("state") == "paused":
            continue
        if float(status.get("nextAt") or 0) <= now:
            found.append(connection.id)
    return found


def _made_lately(db: OrmSession, connection_id: str, now: float, since_iso: str | None = None) -> int:
    since = datetime.fromtimestamp(now - 3600, timezone.utc).isoformat()
    if since_iso and since_iso > since:
        since = since_iso  # someone looked and let it go on: the hour is counted from then
    return (
        db.scalar(
            select(func.count())
            .select_from(FetchedItem)
            .where(
                FetchedItem.connection_id == connection_id,
                FetchedItem.outcome.in_(("created", "incomplete")),
                FetchedItem.fetched_at >= since,
            )
        )
        or 0
    )


def _tell_managers(db: OrmSession, kind: str, text: str) -> None:
    from . import tasks

    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if CONNECTORS_MANAGE in permissions_of(user.roles or []):
            tasks.notify(db, user.username, kind, text, "/settings/automation/fetch-status")


# --------------------------------------------------------------------------- #
# One item                                                                    #
# --------------------------------------------------------------------------- #
# Fields that say where an incident came from: not written by hand, set here.
_SOURCE_COLUMNS = {"source_id": "source_id"}


def _set_source(incident: Incident, name: str, value: Any) -> None:
    if name in _SOURCE_COLUMNS:
        setattr(incident, _SOURCE_COLUMNS[name], str(value)[:500])
        return
    stored = dict(incident.fields) if isinstance(incident.fields, dict) else {}
    stored[name] = value
    incident.fields = stored
    flag_modified(incident, "fields")


def candidate(db: OrmSession, connection: Connection, connector: ConnectorFile, item: Any) -> dict[str, Any]:
    """What an item would become, before anything is written: its type, what the mapper made of it."""
    type_id = mapping.classify_for(db, connection.id, item)
    mapper = mapping.find_mapper(db, connector.id, "incoming", type_id)
    mapped = mapping.apply_incoming(db, mapper.rules if mapper is not None else [], item, connector.id, type_id)
    return {"type": type_id, "mapped": mapped, "mapper": mapper is not None}


def create_incident(
    db: OrmSession,
    connection: Connection,
    connector: ConnectorFile,
    item: Any,
    item_id: str,
    occurred: Any,
    made: dict[str, Any],
    now: float,
) -> tuple[Incident, list[str]]:
    """Make the incident of a fetched item (the caller commits). Returns it and what could not be set."""
    from .automation import triggers
    from .routers.incidents import _sync_columns

    mapped: mapping.Mapped = made["mapped"]
    source = f"connector:{connector.id}"
    stamp = now_iso()
    incident_id = str(uuid.uuid4())
    name = str(mapped.fields.get("name") or f"{connector.name} {item_id}")[:300]
    doc = {
        "id": incident_id,
        "name": name,
        "status": "open",
        "assignee": "",
        "createdAt": stamp,
        "updatedAt": stamp,
        "createdBy": source,
        "data": {},
        "flags": [],
        "notes": [],
    }
    incident = Incident(id=incident_id, doc=doc)
    incident.source_connection_id = connection.id
    incident.source_id = item_id
    _sync_columns(incident)
    db.add(incident)
    db.flush()
    _set_source(incident, "source_connector", connector.id)
    problems = list(mapped.problems)
    triggers.incident_changed(db, incident, "incident.created")

    values: dict[str, Any] = {}
    if made["type"]:
        values["type"] = made["type"]
    if occurred not in (None, "") and "occurred" not in mapped.fields:
        values["occurred"] = occurred
    for field_name, value in mapped.fields.items():
        if field_name in mapping._SOURCE:
            _set_source(incident, field_name, value)
        elif field_name != "name":
            values[field_name] = value
    # The type first, then each field on its own: one the registry refuses does not lose the others.
    for field_name in sorted(values, key=lambda key: key != "type"):
        try:
            registry.update(db, incident, {field_name: values[field_name]}, source, source)
        except registry.FieldError as error:
            problems.append(error.message)
    if mapped.context:
        try:
            incident_context.apply(db, incident, list(mapped.context), source, source)
        except incident_context.ContextError as error:
            problems.append(f"Context: {error.message}")
    war_room.add(
        db,
        incident.id,
        "system",
        {"text": f"Fetched from {connection.name} ({connector.name}), item {item_id}", "item": _cut(item)},
        source,
    )
    # A mapper that says which object of the other side this is, and which way, starts the mirror.
    held = incident.fields if isinstance(incident.fields, dict) else {}
    if held.get("mirror_id") and held.get("mirror_direction"):
        from . import mirror

        try:
            mirror.start(db, incident, connection, held["mirror_id"], str(held["mirror_direction"]), source, now)
        except mirror.MirrorError as error:
            problems.append(error.message)
    timers.sync(db, incident, now)
    audit.record(db, source, "incident.create", f'Fetched the incident "{name}" from {connection.name}', incident)
    return incident, problems


def ingest(
    db: OrmSession, connection: Connection, connector: ConnectorFile, item: Any, item_id: str, occurred: Any, now: float
) -> str:
    """What becomes of one new item (the caller commits): the outcome kept in ``fetched_items``."""
    from . import preprocess

    made = candidate(db, connection, connector, item)
    decided = preprocess.decide(db, connection, connector, item, item_id, made, now)
    outcome, note, incident_id = decided["outcome"], decided.get("note", ""), decided.get("incident_id")
    if outcome == "create":
        incident, problems = create_incident(db, connection, connector, item, item_id, occurred, made, now)
        mapped: mapping.Mapped = made["mapped"]
        missing = list(mapped.missing)
        if not made["mapper"]:
            problems.insert(0, "There is no incoming mapper for this connector: only the name of the item was kept")
        outcome = "incomplete" if (missing or problems) else "created"
        said = []
        if missing:
            said.append("needed and not given: " + ", ".join(missing))
        said += problems
        note = "; ".join(said)[:500]
        incident_id = incident.id
        if decided.get("after") == "close_duplicate":
            preprocess.close_as_duplicate(db, incident, decided, now)
            outcome, note = "duplicate", decided.get("note", "")
    db.add(
        FetchedItem(
            connection_id=connection.id,
            item_id=item_id,
            incident_id=incident_id,
            outcome=outcome,
            note=note[:500],
            fetched_at=now_iso(),
        )
    )
    return outcome


# --------------------------------------------------------------------------- #
# One cycle                                                                   #
# --------------------------------------------------------------------------- #
def cycle(db: OrmSession, connection: Connection, now: float | None = None) -> dict[str, Any]:
    """Fetch once from a connection and make what is new into incidents. It commits as it goes
    (an item at a time) and returns what happened: ``{state, fetched, new, created, …}``."""
    now = time.time() if now is None else now
    connector = connector_of(db, connection)
    if connector is None or connector.fetch is None:
        raise FetchError("The connector of this instance does not say how to fetch")
    spec = connector.fetch
    counts = {"fetched": 0, "new": 0, "created": 0, "incomplete": 0, "dropped": 0, "linked": 0, "duplicate": 0}
    first = _moment(now - spec.first_seconds)
    try:
        runtime = store.runtime_for(db, connector, connection)
        state = connection.fetch_state
        if not isinstance(state, dict):
            scope = ex.Scope(values={"config": runtime.config, "first": first, "now": _moment(now)})
            state = ex.render(spec.first_state, scope).data if spec.first_state else {}
        try:
            found = runtime.fetch(spec, state, first, _moment(now), ITEMS_PER_CYCLE)
        finally:
            runtime.close()
    except (CommandError, ex.ExpressionError) as error:
        return _failed(db, connection, spec.interval_seconds, getattr(error, "message", str(error)), now, counts)

    items = found["items"]
    counts["fetched"] = len(items)
    seen_now: set[str] = set()
    processed: list[Any] = []
    paused = ""
    resumed_at = status_of(connection).get("resumedAt")
    for item in items:
        try:
            item_id = str(
                ex.render_text(spec.item_id, ex.Scope(values={"item": item, "config": {}, "state": state})).data
            )
        except ex.ExpressionError:
            item_id = ""
        item_id = item_id.strip()[:ITEM_ID_MAX]
        if not item_id:
            processed.append(item)  # an item with nothing to tell it apart cannot be kept from coming back
            continue
        if item_id in seen_now or db.get(FetchedItem, (connection.id, item_id)) is not None:
            processed.append(item)
            continue
        if _made_lately(db, connection.id, now, resumed_at) >= INCIDENTS_PER_HOUR:
            paused = f"More than {INCIDENTS_PER_HOUR} incidents in an hour: look at what it fetches, then let it go on"
            break
        occurred = None
        if spec.occurred:
            try:
                occurred = ex.render_text(
                    spec.occurred, ex.Scope(values={"item": item, "config": {}, "state": state})
                ).data
            except ex.ExpressionError:
                occurred = None
        try:
            outcome = ingest(db, connection, connector, item, item_id, occurred, now)
            db.commit()
        except Exception:  # noqa: BLE001 - one item must not stop the others, nor the worker
            db.rollback()
            logger.exception(
                "Fetch: item %s of connection %s could not be made into an incident", item_id, connection.id
            )
            connection = db.get(Connection, connection.id)
            continue
        seen_now.add(item_id)
        processed.append(item)
        counts["new"] += 1
        counts[outcome] = counts.get(outcome, 0) + 1

    connection = db.get(Connection, connection.id)
    whole = len(processed) == len(items)
    if items and (whole or processed):
        # The state moves only as far as what was read and dealt with.
        scope = ex.Scope(
            values={
                "config": {},
                "state": state,
                "first": first,
                "now": _moment(now),
                "response": found.get("response"),
                "status": found.get("status"),
                "headers": found.get("headers"),
                "items": processed,
            }
        )
        next_state = dict(state)
        for key, template in spec.next_state.items():
            try:
                value = ex.render(template, scope).data
            except ex.ExpressionError:
                continue  # nothing to move this value by: it stays
            if value not in (None, ""):
                next_state[key] = value
        connection.fetch_state = next_state
        flag_modified(connection, "fetch_state")
    elif not isinstance(connection.fetch_state, dict):
        connection.fetch_state = state  # the first cycle found nothing: the next starts from the same moment
        flag_modified(connection, "fetch_state")
    changes: dict[str, Any] = {
        "state": "paused" if paused else "ok",
        "error": "",
        "fails": 0,
        "pausedWhy": paused,
        "lastAt": now_iso(),
        "nextAt": now + spec.interval_seconds,
        "last": counts,
        "truncated": bool(found.get("truncated")),
    }
    if items:
        changes["sample"] = _cut(items[-1])
    _keep_status(connection, **changes)
    if paused:
        _tell_managers(db, "fetch.paused", f"Fetching from {connection.name} is paused: too many incidents")
        audit.record(
            db, "nik", "fetch.paused", f"Fetching from {connection.name} was paused: {paused}", target=connection.name
        )
    db.commit()
    return {"state": changes["state"], **counts, "pausedWhy": paused}


def _failed(db: OrmSession, connection: Connection, interval: int, message: str, now: float, counts: dict) -> dict:
    status = status_of(connection)
    fails = int(status.get("fails") or 0) + 1
    wait = min(BACKOFF_MAX, interval * (2 ** min(fails, 10)))
    was_ok = status.get("state") != "failing"
    _keep_status(connection, state="failing", error=message[:500], fails=fails, lastAt=now_iso(), nextAt=now + wait)
    if was_ok:
        _tell_managers(db, "fetch.failing", f"Fetching from {connection.name} fails: {message[:200]}")
    db.commit()
    return {"state": "failing", "error": message[:500], **counts}


def run(connection_id: str, now: float | None = None) -> None:
    """One cycle for a connection, in a session of its own (the worker's pool)."""
    from .core.db import SessionLocal

    with SessionLocal() as db:
        connection = db.get(Connection, connection_id)
        if connection is None or not connection.fetch_enabled:
            return
        try:
            cycle(db, connection, now)
        except FetchError as error:
            db.rollback()
            connection = db.get(Connection, connection_id)
            _failed(db, connection, 300, error.message, time.time() if now is None else now, {})
        except Exception:  # noqa: BLE001 - the worker must survive a bad cycle
            db.rollback()
            logger.exception("Fetch cycle of connection %s failed", connection_id)
            connection = db.get(Connection, connection_id)
            if connection is not None:
                _failed(db, connection, 300, "The cycle failed for a reason Nik did not expect: see the server's log",
                        time.time() if now is None else now, {})  # fmt: skip


# --------------------------------------------------------------------------- #
# Showing                                                                     #
# --------------------------------------------------------------------------- #
def out(db: OrmSession, connection: Connection) -> dict[str, Any]:
    connector = connector_of(db, connection)
    status = status_of(connection)
    spec = connector.fetch if connector is not None else None
    return {
        "connectionId": connection.id,
        "connection": connection.name,
        "connectorId": connection.connector_id,
        "connector": connector.name if connector is not None else connection.connector_id,
        "canFetch": spec is not None,
        "enabled": bool(connection.fetch_enabled),
        "intervalSeconds": spec.interval_seconds if spec is not None else None,
        "state": (status.get("state") or "ok") if connection.fetch_enabled else "off",
        "error": status.get("error") or "",
        "pausedWhy": status.get("pausedWhy") or "",
        "lastAt": status.get("lastAt"),
        "nextAt": status.get("nextAt"),
        "last": status.get("last") or {},
        "truncated": bool(status.get("truncated")),
        "madeLastHour": _made_lately(db, connection.id, time.time(), status.get("resumedAt")),
        "limitPerHour": INCIDENTS_PER_HOUR,
        "hasSample": "sample" in status,
        "fetchState": connection.fetch_state if isinstance(connection.fetch_state, dict) else None,
    }


def recent(db: OrmSession, connection_id: str, limit: int = 100, outcome: str = "") -> list[dict[str, Any]]:
    stmt = select(FetchedItem).where(FetchedItem.connection_id == connection_id)
    if outcome:
        stmt = stmt.where(FetchedItem.outcome == outcome)
    rows = db.scalars(stmt.order_by(FetchedItem.fetched_at.desc()).limit(limit))
    return [
        {
            "itemId": row.item_id,
            "incidentId": row.incident_id,
            "outcome": row.outcome,
            "note": row.note,
            "fetchedAt": row.fetched_at,
        }
        for row in rows
    ]
