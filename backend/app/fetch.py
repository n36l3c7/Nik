"""Fetching: a connection brings alerts in, and each becomes an incident.

A connection whose connector has a ``fetch`` and that was told to fetch is
read by the automation worker at its interval. How often, how far back the
first cycle reads and the look-back are the instance's own
(``connections.fetch_settings``); what it does not set is its connector's.
One cycle:

1. the request is rendered with ``since``, the moment to ask from, and with
   the ``state`` the last cycle left (before the first, what ``first_state``
   says of the moment the first fetch reads back to), and its pages are read,
   200 items at most;
2. each item is told apart by ``item_id``: one already in ``fetched_items``
   for this connection is skipped;
3. a new one is classified (its type), mapped (its fields and context),
   passed through the pre-processing rules, and then, in one transaction,
   becomes an incident with its context, a line of its War Room that holds
   the item as it came, and a row of ``fetched_items``;
4. ``next_state`` is saved when the whole cycle was read, and with it how far
   the cycle reached.

``since`` is worked out here, for every connector whose request filters by
time. Nik keeps *reached*: the first-fetch moment when the first cycle
starts, then the newest time it saw on an item (a time later than the start
of the cycle that saw it is not believed; a cycle that finds nothing leaves
it where it is).
A connector that gives no time to its items has the start of each whole cycle
instead. ``since`` is *reached* less the look-back of the instance. So an
item is asked for again as long as its time is not older than the newest one
seen less the look-back, and is made once, because its id is remembered. A
look-back of 0 still asks from the newest time seen, that moment included:
it catches what has the same time as the last item, and misses what turns up
later with an older time. A cycle that was cut at its 200 items goes on from
where it stopped, without the look-back, until one cycle reads everything.

*reached* is kept in ``fetch_state`` under ``_since``, beside what the
connector keeps there. Resetting the last run empties ``fetch_state``: the
next cycle starts from the first fetch again, and ``fetched_items`` stays, so
nothing is made twice.

A connector that can give what an item was made of gives it once the item has
an incident, and it is kept as evidence of that incident: the Mail connector
gives the message as it was received, which becomes an e-mail artifact with
the analysis an uploaded ``.eml`` gets. Nothing is kept for an item a rule
dropped; one a rule linked to an incident there was is evidence of that one.

An incident a fetch makes starts mirrored in the direction its instance
says (``mirror.start_fetched``; none, until someone chooses). For a connector
whose mirror is fed by its fetch (a mailbox), an item that goes on with a
conversation an incident mirrored in holds is not made into an incident: it
becomes a line of that one, with what it was made of kept as its evidence
(``mirror.absorb``; the outcome ``mirrored``). The rules are not asked about it.

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
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
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
from .automation.connectors import (
    FETCH_MAX_INTERVAL,
    FETCH_MIN_INTERVAL,
    LOOKBACK_MAX_MINUTES,
    ConnectorFile,
    FetchSpec,
    first_fetch_seconds,
)
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
# Where the engine keeps its own part of ``fetch_state``: {"reached": seconds since 1970, "cut": bool}.
ENGINE = "_since"


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


# --------------------------------------------------------------------------- #
# How an instance fetches                                                     #
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Settings:
    """How an instance fetches: its own values, and its connector's where it sets none."""

    interval: int  # seconds between two cycles
    first_fetch: str  # "3 days": how far back the first cycle reads
    lookback: int  # minutes

    @property
    def first_seconds(self) -> int:
        return first_fetch_seconds(self.first_fetch) or 0

    def out(self) -> dict[str, Any]:
        return {"intervalSeconds": self.interval, "firstFetch": self.first_fetch, "lookbackMinutes": self.lookback}


def settings_of(connection: Connection, spec: FetchSpec) -> Settings:
    held = connection.fetch_settings if isinstance(connection.fetch_settings, dict) else {}
    interval = held.get("intervalSeconds")
    first = held.get("firstFetch")
    lookback = held.get("lookbackMinutes")
    return Settings(
        interval=interval if _whole_number(interval) and interval >= FETCH_MIN_INTERVAL else spec.interval_seconds,
        first_fetch=str(first) if first and first_fetch_seconds(str(first)) else spec.first_fetch,
        lookback=lookback if _whole_number(lookback) is not None and lookback >= 0 else spec.lookback_minutes,
    )


def _whole_number(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def set_settings(db: OrmSession, connection: Connection, given: dict[str, Any], now: float) -> list[str]:
    """Change how an instance fetches (the caller commits): ``intervalSeconds``, ``firstFetch``,
    ``lookbackMinutes``, each kept when it is left out. A value that is its connector's is not kept,
    so the instance goes on following its connector. ``mirror`` and ``mirrorAllow``, the direction
    the incidents it fetches are mirrored in and what their mirrors may send, are kept beside them
    (``mirror.set_choice``). Gives what changed, in words."""
    connector = connector_of(db, connection)
    if connector is None or connector.fetch is None:
        raise FetchError("The connector of this instance does not say how to fetch")
    spec = connector.fetch
    before = settings_of(connection, spec)
    held = dict(connection.fetch_settings) if isinstance(connection.fetch_settings, dict) else {}
    if given.get("intervalSeconds") is not None:
        interval = _whole_number(given["intervalSeconds"])
        if interval is None or not FETCH_MIN_INTERVAL <= interval <= FETCH_MAX_INTERVAL:
            raise FetchError(f"An instance fetches every {FETCH_MIN_INTERVAL} seconds at the least, once a day at most")
        held["intervalSeconds"] = interval
    if given.get("firstFetch") is not None:
        first = " ".join(str(given["firstFetch"]).lower().split())
        if first_fetch_seconds(first) is None:
            raise FetchError("The first fetch is a length of time, a month at most: 30 minutes, 12 hours, 3 days")
        held["firstFetch"] = first
    if given.get("lookbackMinutes") is not None:
        lookback = _whole_number(given["lookbackMinutes"])
        if lookback is None or not 0 <= lookback <= LOOKBACK_MAX_MINUTES:
            raise FetchError(f"The look-back is a number of minutes, {LOOKBACK_MAX_MINUTES} at most")
        held["lookbackMinutes"] = lookback
    theirs = {
        "intervalSeconds": spec.interval_seconds,
        "firstFetch": spec.first_fetch,
        "lookbackMinutes": spec.lookback_minutes,
    }
    kept = {name: value for name, value in held.items() if name in theirs and value != theirs[name]}
    # Beside how it fetches: the direction its incidents are mirrored in, which mirror.py owns.
    kept.update({name: held[name] for name in ("mirror", "mirrorAllow") if name in held})
    connection.fetch_settings = kept or None
    after = settings_of(connection, spec)
    changes = []
    if given.get("mirror") is not None or given.get("mirrorAllow") is not None:
        from . import mirror

        try:
            changes += mirror.set_choice(connection, connector, given)
        except mirror.MirrorError as error:
            raise FetchError(error.message) from None
    if after.interval != before.interval:
        changes.append(f"every {after.interval} s")
        # A shorter interval is not made to wait for the turn the longer one had set.
        status = status_of(connection)
        if status.get("state", "ok") == "ok" and float(status.get("nextAt") or 0) > now + after.interval:
            _keep_status(connection, nextAt=now + after.interval)
    if after.first_fetch != before.first_fetch:
        changes.append(f"first fetch {after.first_fetch}")
    if after.lookback != before.lookback:
        changes.append(f"look-back {after.lookback} min")
    return changes


def _epoch_of(value: Any) -> float | None:
    """The time a connector gives of an item, as seconds since 1970: a number (seconds, or
    milliseconds when it is that large), an ISO date, or the date of a message. None when it is none."""
    if isinstance(value, bool) or value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        number = float(value)
    else:
        text = str(value).strip()
        try:
            number = float(text)
        except ValueError:
            try:
                moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
            except ValueError:
                try:
                    moment = parsedate_to_datetime(text)
                except (TypeError, ValueError):
                    return None
            if moment.tzinfo is None:
                moment = moment.replace(tzinfo=timezone.utc)
            return moment.timestamp()
    if number <= 0 or number != number:
        return None
    return number / 1000 if number > 1e11 else number


def _engine_of(connection: Connection) -> dict[str, Any]:
    """The engine's own part of the state a cycle left."""
    held = connection.fetch_state if isinstance(connection.fetch_state, dict) else {}
    part = held.get(ENGINE)
    return dict(part) if isinstance(part, dict) else {}


def since_of(connection: Connection, settings: Settings, now: float) -> float:
    """The moment the next cycle asks from: how far the cycles reached, less the look-back. Before
    the first cycle, and for a state an older release left, the moment the first fetch reads back to."""
    part = _engine_of(connection)
    reached = part.get("reached")
    if isinstance(reached, bool) or not isinstance(reached, (int, float)):
        return now - settings.first_seconds
    return float(reached) - (0 if part.get("cut") else settings.lookback * 60)


def reset(db: OrmSession, connection: Connection) -> None:
    """Forget where the last run stopped (the caller commits): the next cycle starts from the first
    fetch. What was fetched before stays in ``fetched_items``, so none of it is made twice."""
    connection.fetch_state = None
    flag_modified(connection, "fetch_state")
    _keep_status(connection, truncated=False)


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


def instance_link(connection_id: str) -> str:
    """Where the fetching of an instance is seen and set: its form, on Connectors."""
    return f"/settings/automation/connectors/{connection_id}/fetch"


def _tell_managers(db: OrmSession, kind: str, text: str, connection: Connection) -> None:
    from . import tasks

    for user in db.scalars(select(User).where(User.disabled.is_(False))):
        if CONNECTORS_MANAGE in permissions_of(user.roles or []):
            tasks.notify(db, user.username, kind, text, instance_link(connection.id))


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
    # The mirror starts in the direction the instance says, with the object the connector says the
    # item is; a mapper that says both which object and which way is obeyed first (mirror.py).
    from . import mirror

    problems += mirror.start_fetched(db, incident, connection, connector, item, item_id, source, now)
    timers.sync(db, incident, now)
    audit.record(db, source, "incident.create", f'Fetched the incident "{name}" from {connection.name}', incident)
    return incident, problems


def _evidence(db: OrmSession, runtime: Any, connector: ConnectorFile, item: Any, incident_id: str) -> str:
    """Keep what an item was made of as evidence of its incident, when the runtime has it to give
    (the caller commits). Gives what to say when it could not be kept, or nothing."""
    give = getattr(runtime, "evidence", None)
    incident = db.get(Incident, incident_id) if give is not None else None
    if incident is None:
        return ""
    from .automation import mail_evidence

    try:
        found = give(item)
    except CommandError as error:
        return f"The message was not kept as evidence: {error.message}"
    if found is None:
        return ""
    name, raw = found
    return mail_evidence.keep_message(db, incident, raw, name, f"connector:{connector.id}")


def ingest(
    db: OrmSession,
    connection: Connection,
    connector: ConnectorFile,
    item: Any,
    item_id: str,
    occurred: Any,
    now: float,
    runtime: Any = None,
) -> str:
    """What becomes of one new item (the caller commits): the outcome kept in ``fetched_items``.
    ``runtime`` is the one that fetched it, asked for what is kept as evidence."""
    from . import indicators_found, mirror, preprocess

    # An item that goes on with a conversation an incident mirrored in holds (a reply to a message)
    # is a line of that incident, and what it was made of is evidence of it: it makes no incident.
    taken = mirror.absorb(db, connection, connector, item, item_id, now)
    if taken is not None:
        note = "A line of the incident it goes on with" if taken["fresh"] else "It was there already"
        if taken["fresh"]:
            unkept = _evidence(db, runtime, connector, item, taken["incident_id"])
            note = "; ".join(part for part in (note, unkept) if part)
            # As for an item that makes an incident: once what it was made of is kept and analysed,
            # what the reply says is read for the indicators its incident does not hold yet.
            joined = db.get(Incident, taken["incident_id"])
            if joined is not None:
                indicators_found.after_update(db, joined, f"connector:{connector.id}", [taken["text"]])
        db.add(
            FetchedItem(
                connection_id=connection.id,
                item_id=item_id,
                incident_id=taken["incident_id"],
                outcome="mirrored",
                note=note[:500],
                fetched_at=now_iso(),
            )
        )
        return "mirrored"
    made = candidate(db, connection, connector, item)
    decided = preprocess.decide(db, connection, connector, item, item_id, made, now)
    outcome, note, incident_id = decided["outcome"], decided.get("note", ""), decided.get("incident_id")
    created: Incident | None = None
    if outcome == "create":
        incident, problems = create_incident(db, connection, connector, item, item_id, occurred, made, now)
        created = incident
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
    if incident_id and outcome != "dropped":
        unkept = _evidence(db, runtime, connector, item, incident_id)
        if unkept:
            note = "; ".join(part for part in (note, unkept) if part)
            outcome = "incomplete" if outcome == "created" else outcome
    if created is not None:
        # The incident is whole, and what it was made of is kept and analysed: its fields and its
        # context are read for the indicators it does not hold yet (indicators_found.py).
        indicators_found.scan(db, created, "fetch")
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
    settings = settings_of(connection, spec)
    counts = {"fetched": 0, "new": 0, "created": 0, "incomplete": 0, "dropped": 0, "linked": 0, "duplicate": 0}
    first = _moment(now - settings.first_seconds)
    if connector.mirror is not None and connector.mirror.thread is not None:
        counts["mirrored"] = 0  # what went on with a conversation an incident holds
    since = since_of(connection, settings, now)
    try:
        runtime = store.runtime_for(db, connector, connection)
        if isinstance(connection.fetch_state, dict):
            # The connector's part: what the engine keeps beside it is not the connector's to read.
            state = {key: value for key, value in connection.fetch_state.items() if key != ENGINE}
        else:
            scope = ex.Scope(values={"config": runtime.config, "first": first, "now": _moment(now)})
            state = ex.render(spec.first_state, scope).data if spec.first_state else {}
        try:
            found = runtime.fetch(spec, state, first, _moment(now), ITEMS_PER_CYCLE, since=_moment(since))
        finally:
            runtime.close()
    except (CommandError, ex.ExpressionError) as error:
        return _failed(db, connection, settings.interval, getattr(error, "message", str(error)), now, counts)
    try:
        return _made(db, connection, connector, runtime, found, state, first, since, now, counts)
    finally:
        runtime.close()  # it may have been opened again, for what is kept as evidence


def _time_of(spec: FetchSpec, item: Any, state: dict[str, Any]) -> float | None:
    """The time of an item the request filters on, as seconds since 1970; None when it gives none."""
    template = spec.item_time or spec.occurred
    if not template:
        return None
    try:
        return _epoch_of(ex.render_text(template, ex.Scope(values={"item": item, "config": {}, "state": state})).data)
    except ex.ExpressionError:
        return None


def _made(
    db: OrmSession,
    connection: Connection,
    connector: ConnectorFile,
    runtime: Any,
    found: dict[str, Any],
    state: dict[str, Any],
    first: dict[str, Any],
    since: float,
    now: float,
    counts: dict[str, int],
) -> dict[str, Any]:
    """The second half of a cycle: what was fetched is made into incidents, and the state moves."""
    spec = connector.fetch
    settings = settings_of(connection, spec)
    before = _engine_of(connection)
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
            outcome = ingest(db, connection, connector, item, item_id, occurred, now, runtime)
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
    next_state = dict(state)
    if items and (whole or processed):
        # The state moves only as far as what was read and dealt with.
        scope = ex.Scope(
            values={
                "config": {},
                "state": state,
                "first": first,
                "now": _moment(now),
                "since": _moment(since),
                "response": found.get("response"),
                "status": found.get("status"),
                "headers": found.get("headers"),
                "items": processed,
            }
        )
        for key, template in spec.next_state.items():
            try:
                value = ex.render(template, scope).data
            except ex.ExpressionError:
                continue  # nothing to move this value by: it stays
            if value not in (None, ""):
                next_state[key] = value
    if spec.by_time:
        # How far the cycles reached. It starts at the first-fetch moment and never goes back; a
        # time later than the start of this cycle is a clock that is wrong, and is not believed.
        held = before.get("reached")
        reached = float(held) if isinstance(held, (int, float)) and not isinstance(held, bool) else since
        cut = bool(found.get("truncated")) or not whole
        if spec.item_time or spec.occurred:
            times = [_time_of(spec, item, state) for item in processed]
            reached = max([reached, *(moment for moment in times if moment is not None and moment <= now)])
        elif not cut:
            reached = now  # its items have no time: what is known is when everything was read
        next_state[ENGINE] = {"reached": reached, "cut": cut}
    # The first cycle, even when it found nothing: the next starts from the same moment.
    connection.fetch_state = next_state
    flag_modified(connection, "fetch_state")
    changes: dict[str, Any] = {
        "state": "paused" if paused else "ok",
        "error": "",
        "fails": 0,
        "pausedWhy": paused,
        "lastAt": now_iso(),
        "nextAt": now + settings.interval,
        "last": counts,
        "truncated": bool(found.get("truncated")),
    }
    if items:
        changes["sample"] = _cut(items[-1])
    _keep_status(connection, **changes)
    if paused:
        _tell_managers(db, "fetch.paused", f"Fetching from {connection.name} is paused: too many incidents", connection)
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
        _tell_managers(db, "fetch.failing", f"Fetching from {connection.name} fails: {message[:200]}", connection)
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
    settings = settings_of(connection, spec) if spec is not None else None
    by_time = spec is not None and spec.by_time
    started = isinstance(connection.fetch_state, dict)
    return {
        "instanceId": connection.id,
        "connection": connection.name,
        "connectorId": connection.connector_id,
        "connector": connector.name if connector is not None else connection.connector_id,
        "canFetch": spec is not None,
        "enabled": bool(connection.fetch_enabled),
        # How it fetches (its own values, or its connector's), and what its connector says.
        "intervalSeconds": settings.interval if settings is not None else None,
        "firstFetch": settings.first_fetch if settings is not None else None,
        "lookbackMinutes": settings.lookback if settings is not None else None,
        "defaults": (
            {
                "intervalSeconds": spec.interval_seconds,
                "firstFetch": spec.first_fetch,
                "lookbackMinutes": spec.lookback_minutes,
            }
            if spec is not None
            else None
        ),
        "minIntervalSeconds": FETCH_MIN_INTERVAL,
        "maxLookbackMinutes": LOOKBACK_MAX_MINUTES,
        # Whether its request asks from a moment: the look-back applies only then.
        "byTime": by_time,
        # Whether a cycle ran since the last reset, and the moment the next one asks from.
        "started": started,
        "sinceAt": (
            _moment(since_of(connection, settings, time.time()))["iso"]
            if by_time and settings is not None and (started or connection.fetch_enabled)
            else None
        ),
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
        "link": instance_link(connection.id),
        # The direction the incidents it fetches are mirrored in, and what its connector lets it choose.
        "mirror": _mirror_out(connection, connector),
    }


def _mirror_out(connection: Connection, connector: ConnectorFile | None) -> dict[str, Any] | None:
    if connector is None or connector.fetch is None:
        return None
    from . import mirror

    return mirror.choice_out(connection, connector)


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
