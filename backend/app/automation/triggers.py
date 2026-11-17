"""From what happens in Nik to runs: the outbox, matching, limits.

A change (an incident created or updated) writes an event to the outbox
(``automation_events``) **in its own transaction**: the event exists exactly
when the change does. The worker reads the outbox and, for each event, starts
a run of every enabled playbook whose trigger waits for it and whose
conditions hold, within the limits:

- **no loop**: a playbook never starts on an event its own run caused, and an
  event more than three runs deep starts nothing ("incident updated → the
  playbook updates the incident → incident updated …");
- **one run at a time for the same object**, when the playbook says so: the
  event is dropped and counted;
- **runs per hour** per playbook, and a ceiling of active runs for the whole
  server.
"""

from __future__ import annotations

import logging
import time
import uuid
from contextvars import ContextVar
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..core.config import settings
from ..core.models import AutomationEvent, AutomationSchedule, Incident, Playbook, PlaybookVersion, Run
from . import engine, graph, payloads, schedules
from . import expressions as ex

logger = logging.getLogger("nik.automation")

MAX_DEPTH = 3
# The run whose step is making the changes of the current thread, if any: the
# events those changes write say so, which is what stops a loop.
current_run: ContextVar[tuple[str, int] | None] = ContextVar("nik_automation_run", default=None)


# --------------------------------------------------------------------------- #
# Writing the outbox                                                          #
# --------------------------------------------------------------------------- #
def publish(db: OrmSession, kind: str, object_kind: str, object_id: str, data: dict, classes: dict) -> None:
    """Add an event to the outbox, in the caller's transaction (the caller commits)."""
    if settings.AUTOMATION_WORKER == "off":
        return
    cause = current_run.get()
    db.add(
        AutomationEvent(
            id=uuid.uuid4().hex,
            kind=kind,
            object_kind=object_kind,
            object_id=str(object_id)[:1100],
            payload={
                "data": data,
                "classes": classes,
                "caused_by_run": cause[0] if cause else None,
                "depth": (cause[1] + 1) if cause else 0,
            },
            created_at=engine.iso(time.time()),
        )
    )


def incident_changed(db: OrmSession, incident: Incident, kind: str, changed: list[str] | None = None) -> None:
    data, classes = payloads.incident_event(incident, changed)
    publish(db, kind, "incident", incident.id, data, classes)


# --------------------------------------------------------------------------- #
# Matching                                                                    #
# --------------------------------------------------------------------------- #
def trigger_config(db: OrmSession, playbook: Playbook) -> dict:
    version = db.get(PlaybookVersion, (playbook.id, playbook.current_version)) if playbook.current_version else None
    node = graph.trigger_of(version.graph) if version else None
    return (node or {}).get("config") or {}


def accepts(config: dict, kind: str, data: dict, classes: dict) -> bool:
    """Whether a trigger waits for this event and its conditions hold."""
    if config.get("event") != kind:
        return False
    conditions = config.get("conditions")
    if not conditions:
        return True
    try:
        return engine.holds(conditions, ex.Scope(values={"trigger": data}, classes={"trigger": classes}))
    except (ex.ExpressionError, engine.StepFailed):
        return False


def _active_for(db: OrmSession, playbook: Playbook, object_kind: str, object_id: str) -> int:
    return (
        db.scalar(
            select(func.count())
            .select_from(Run)
            .where(
                Run.playbook_id == playbook.id,
                Run.object_kind == object_kind,
                Run.object_id == object_id,
                Run.status.notin_(engine.FINISHED),
                Run.parent_run_id.is_(None),
            )
        )
        or 0
    )


def refusal(db: OrmSession, playbook: Playbook, object_kind: str, object_id: str, now: float) -> str | None:
    """Why a run of the playbook cannot start now (None when it can)."""
    active = db.scalar(select(func.count()).select_from(Run).where(Run.status.notin_(engine.FINISHED))) or 0
    if active >= settings.AUTOMATION_MAX_ACTIVE_RUNS:
        return "Too many runs are in progress on this server"
    since = engine.iso(now - 3600)
    recent = (
        db.scalar(
            select(func.count())
            .select_from(Run)
            .where(Run.playbook_id == playbook.id, Run.started_at >= since, Run.parent_run_id.is_(None))
        )
        or 0
    )
    if recent >= (playbook.max_runs_per_hour or 60):
        return "The playbook reached its runs per hour"
    if playbook.one_per_object and object_id and _active_for(db, playbook, object_kind, object_id):
        return "A run of this playbook is already in progress for this object"
    return None


def handle_event(db: OrmSession, event: AutomationEvent, now: float) -> list[Run]:
    """Start the runs an event triggers (the caller commits)."""
    payload = event.payload or {}
    data, classes = payload.get("data") or {}, payload.get("classes") or {}
    cause, depth = payload.get("caused_by_run"), int(payload.get("depth") or 0)
    started: list[Run] = []
    if depth > MAX_DEPTH:
        logger.info("Event %s dropped: more than %d runs deep", event.kind, MAX_DEPTH)
        return started
    caused_by = db.get(Run, cause) if cause else None
    for playbook in db.scalars(
        select(Playbook).where(Playbook.enabled.is_(True), Playbook.current_version.isnot(None))
    ):
        # A playbook never starts on what its own run did.
        if caused_by is not None and caused_by.playbook_id == playbook.id:
            continue
        if not accepts(trigger_config(db, playbook), event.kind, data, classes):
            continue
        why = refusal(db, playbook, event.object_kind, event.object_id, now)
        if why:
            logger.info('Event %s did not start "%s": %s', event.kind, playbook.name, why)
            continue
        started.append(
            engine.start_run(
                db,
                playbook,
                kind=event.kind,
                payload=data,
                classes=classes,
                object_kind=event.object_kind,
                object_id=event.object_id,
                incident_id=event.object_id if event.object_kind == "incident" else None,
                started_by="nik-automation",
                event_id=event.id,
                caused_by_run=cause,
                depth=depth,
                now=now,
            )
        )
        db.flush()
    return started


# --------------------------------------------------------------------------- #
# Schedules                                                                   #
# --------------------------------------------------------------------------- #
def sync_schedule(db: OrmSession, playbook: Playbook, now: float) -> None:
    """Keep the schedule row of a playbook as its trigger and its switch say (the caller commits)."""
    config = trigger_config(db, playbook) if playbook.enabled else {}
    version = db.get(PlaybookVersion, (playbook.id, playbook.current_version)) if playbook.current_version else None
    node = graph.trigger_of(version.graph) if version else None
    existing = db.scalars(select(AutomationSchedule).where(AutomationSchedule.playbook_id == playbook.id)).all()
    cron, zone = config.get("cron"), config.get("timezone") or "UTC"
    for row in existing:
        if not cron or node is None or row.node_id != node["id"]:
            db.delete(row)
    if not cron or node is None or schedules.cron_problem(cron, zone):
        return
    row = next((r for r in existing if r.node_id == node["id"]), None)
    if row is None:
        # Counted from now: firings missed while it was off are not replayed.
        db.add(
            AutomationSchedule(
                playbook_id=playbook.id,
                node_id=node["id"],
                cron=cron,
                timezone=zone,
                next_at=schedules.next_after(cron, zone, now),
            )
        )
    elif (row.cron, row.timezone) != (cron, zone):
        row.cron, row.timezone = cron, zone
        row.next_at = schedules.next_after(cron, zone, now)


def fire_schedules(db: OrmSession, now: float) -> list[Run]:
    """Start the runs of the schedules that are due (the caller commits)."""
    started: list[Run] = []
    for row in db.scalars(select(AutomationSchedule).where(AutomationSchedule.next_at <= now)):
        playbook = db.get(Playbook, row.playbook_id)
        row.next_at = schedules.next_after(row.cron, row.timezone, now)
        if playbook is None or not playbook.enabled or not playbook.current_version:
            continue
        # A run of the last firing still in progress: this one is skipped and counted.
        if _active_for(db, playbook, "schedule", row.node_id) or refusal(db, playbook, "schedule", row.node_id, now):
            row.skipped = (row.skipped or 0) + 1
            continue
        data, classes = payloads.schedule(engine.iso(now), row.cron)
        started.append(
            engine.start_run(
                db,
                playbook,
                kind="schedule",
                payload=data,
                classes=classes,
                object_kind="schedule",
                object_id=row.node_id,
                started_by="nik-automation",
                now=now,
            )
        )
        db.flush()
    return started


def manual_object(db: OrmSession, object_kind: str, object_id: str, actor: str) -> tuple[dict, dict, str | None] | None:
    """The payload of a run started by hand on an object: (data, classes, incident id); None when it does not exist."""
    if not object_kind:
        data, classes = payloads.manual(actor, None)
        return data, classes, None
    if object_kind == "incident":
        incident = db.get(Incident, object_id)
        if incident is None:
            return None
        data, classes = payloads.manual(actor, incident)
        return data, classes, incident.id
    return None


def describe(config: dict[str, Any]) -> str:
    """A trigger in a few words, for the list of playbooks."""
    parts = []
    if config.get("event"):
        parts.append(str(config["event"]))
    if config.get("cron"):
        parts.append(f"schedule {config['cron']}")
    if config.get("manual"):
        parts.append("by hand")
    return ", ".join(parts) or "none"
