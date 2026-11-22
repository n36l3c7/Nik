"""From what happens in Nik to runs: the outbox, matching, limits.

A change (an incident created or updated, an e-mail, a file or an address
analysed, a verdict that changed) writes an event to the outbox
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

**Exactly once.** The event is in the transaction of the change, so it is
there exactly when the change is. The runs it starts and its mark of done are
one commit too: a worker that stops in between starts them again from the
same event, and finds none of them there. And each run an event starts
carries a key, ``<event>:<playbook>``, that the database holds unique: the
same event cannot start the same playbook twice, whatever the order of what
went wrong (``event_key``).
"""

from __future__ import annotations

import logging
import time
import uuid
from contextvars import ContextVar
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..core import origin
from ..core.config import settings
from ..core.models import (
    Artifact,
    AutomationEvent,
    AutomationSchedule,
    Incident,
    Mail,
    NetworkCapture,
    Playbook,
    PlaybookVersion,
    Run,
    Sample,
    SampleCapa,
    SampleCode,
    UrlScan,
)
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
    # A change one of many made by a bulk job (bulk.py): the event says which, to the worker and,
    # as ``trigger.bulk``, to the playbooks it starts.
    job = origin.bulk.get()
    if job:
        data = {**data, "bulk": job}
        classes = {**classes, "bulk": ["nik_id"]}
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
                **({"bulk": job} if job else {}),
            },
            created_at=engine.iso(time.time()),
        )
    )


def incident_changed(db: OrmSession, incident: Incident, kind: str, changed: list[str] | None = None) -> None:
    data, classes = payloads.incident_event(incident, changed)
    publish(db, kind, "incident", incident.id, data, classes)


def _announce(db: OrmSession, kind: str, data: dict) -> None:
    """The same event to the webhooks subscribed to it (``events.py``): what an
    admin asked to be told of, at the address they gave."""
    from ..events import emit_detached

    emit_detached(db, kind, data)


def mail_analysed(db: OrmSession, mail: Mail, incident: Incident | None = None, from_mailbox: str = "") -> None:
    data, classes = payloads.mail_event(mail, incident, from_mailbox)
    publish(db, "mail.analysed", "artifact", data["mail"]["artifact_id"], data, classes)
    _announce(db, "mail.analysed", data)


def file_analysed(db: OrmSession, sample: Sample, artifact: Artifact | None, incident: Incident | None = None) -> None:
    data, classes = payloads.file_event(sample, artifact, incident)
    publish(db, "file.analysed", "artifact", data["file"]["artifact_id"], data, classes)
    _announce(db, "file.analysed", data)


def code_analysed(db: OrmSession, row: SampleCode) -> None:
    """The disassembly of a file ended, done or failed: once for each, whoever asked for it."""
    sample = db.get(Sample, row.sha256)
    if sample is None:
        return
    data, classes = payloads.code_event(sample, db.get(Artifact, f"file-{row.sha256}"), row)
    publish(db, "code.analysed", "artifact", data["file"]["artifact_id"], data, classes)
    _announce(db, "code.analysed", data)


def capabilities_analysed(db: OrmSession, row: SampleCapa) -> None:
    """capa ended on a file, done or failed: once for each run of it."""
    sample = db.get(Sample, row.sha256)
    if sample is None:
        return
    data, classes = payloads.capabilities_event(sample, db.get(Artifact, f"file-{row.sha256}"), row)
    publish(db, "capabilities.analysed", "artifact", data["file"]["artifact_id"], data, classes)
    _announce(db, "capabilities.analysed", data)


def capture_analysed(db: OrmSession, capture: NetworkCapture) -> None:
    """The analysis of a capture ended, ready or failed."""
    incident = db.get(Incident, capture.incident_id) if capture.incident_id else None
    data, classes = payloads.capture_event(capture, incident)
    publish(db, "capture.analysed", "artifact", data["capture"]["artifact_id"], data, classes)
    _announce(db, "capture.analysed", data)


def url_analysed(db: OrmSession, scan: UrlScan) -> None:
    data, classes = payloads.scan_event(scan)
    publish(db, "url.analysed", "artifact", data["scan"]["artifact_id"], data, classes)
    _announce(db, "url.analysed", data)


def verdict_changed(db: OrmSession, kind: str, value: str, old: str, new: str, sources: list[str]) -> None:
    data, classes = payloads.verdict_changed(db, kind, value, old, new, sources)
    publish(db, "ioc.verdict_changed", "indicator", indicator_id(kind, value), data, classes)
    _announce(db, "ioc.verdict_changed", data)


def artifact_expiring(db: OrmSession, artifact: Artifact, days_left: int) -> None:
    data, classes = payloads.artifact_expiry(artifact, days_left)
    publish(db, "artifact.expiring", "artifact", artifact.id, data, classes)
    _announce(db, "artifact.expiring", data)


def artifact_expired(db: OrmSession, artifact: Artifact) -> None:
    data, classes = payloads.artifact_expiry(artifact, 0)
    publish(db, "artifact.expired", "artifact", artifact.id, data, classes)
    _announce(db, "artifact.expired", data)


def storage_low(db: OrmSession, total: int, free: int) -> None:
    data, classes = payloads.storage_low(total, free)
    publish(db, "storage.low", "storage", "", data, classes)
    _announce(db, "storage.low", data)


def sla_breached(db: OrmSession, incident: Incident, field: str, label: str, due_s: int, elapsed_s: int) -> None:
    data, classes = payloads.sla_breached(incident, field, label, due_s, elapsed_s)
    publish(db, "sla.breached", "incident", incident.id, data, classes)
    _announce(db, "sla.breached", data)


def watch_hit(db: OrmSession, incident: Incident, hits: list[dict]) -> None:
    if settings.AUTOMATION_WORKER == "off" or not hits:
        return
    data, classes = payloads.watch_hit(db, incident, hits)
    publish(db, "ioc.watch_hit", "incident", incident.id, data, classes)


def indicators_found(db: OrmSession, incident: Incident, door: str, found: list[dict], kept: int) -> None:
    """A reading of an incident kept indicators that are new to it (``indicators_found.scan``):
    one event for the reading, never one for each indicator, in the transaction of the reading."""
    if settings.AUTOMATION_WORKER == "off" or not found:
        return
    data, classes = payloads.indicators_found(db, incident, door, found, kept)
    publish(db, "indicators.found", "incident", incident.id, data, classes)


def indicator_id(kind: str, value: str) -> str:
    """An indicator as the object of a run: ``domain:evil.example``."""
    return f"{kind}:{value}"


# --------------------------------------------------------------------------- #
# Matching                                                                    #
# --------------------------------------------------------------------------- #
def trigger_config(db: OrmSession, playbook: Playbook) -> dict:
    version = db.get(PlaybookVersion, (playbook.id, playbook.current_version)) if playbook.current_version else None
    node = graph.trigger_of(version.graph) if version else None
    return (node or {}).get("config") or {}


def accepts(config: dict, kind: str, data: dict, classes: dict, db: OrmSession | None = None) -> bool:
    """Whether a trigger waits for this event and its conditions hold."""
    if config.get("event") != kind:
        return False
    conditions = config.get("conditions")
    if not conditions:
        return True
    try:
        scope = ex.Scope(values={"trigger": data}, classes={"trigger": classes}, in_list=engine._in_list(db))
        return engine.holds(conditions, scope)
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
                Run.debug.is_(False),
            )
        )
        or 0
    )


def refusal(db: OrmSession, playbook: Playbook, object_kind: str, object_id: str, now: float) -> str | None:
    """Why a run of the playbook cannot start now (None when it can)."""
    real = Run.debug.is_(False)  # a debug run counts for no limit
    active = db.scalar(select(func.count()).select_from(Run).where(Run.status.notin_(engine.FINISHED), real)) or 0
    if active >= settings.AUTOMATION_MAX_ACTIVE_RUNS:
        return "Too many runs are in progress on this server"
    since = engine.iso(now - 3600)
    recent = (
        db.scalar(
            select(func.count())
            .select_from(Run)
            .where(Run.playbook_id == playbook.id, Run.started_at >= since, Run.parent_run_id.is_(None), real)
        )
        or 0
    )
    if recent >= (playbook.max_runs_per_hour or 60):
        return "The playbook reached its runs per hour"
    if playbook.one_per_object and object_id and _active_for(db, playbook, object_kind, object_id):
        return "A run of this playbook is already in progress for this object"
    return None


def _incident_of(object_kind: str, object_id: str, data: dict) -> str | None:
    """The incident a run belongs to: its object, or the incident its object was analysed in."""
    if object_kind == "incident":
        return object_id
    held = data.get("incident")
    return str(held["id"]) if isinstance(held, dict) and held.get("id") else None


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
        if not accepts(trigger_config(db, playbook), event.kind, data, classes, db):
            continue
        key = event_key(event.id, playbook.id)
        if db.scalar(select(Run.id).where(Run.event_key == key)) is not None:
            continue  # this event started this playbook already
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
                incident_id=_incident_of(event.object_kind, event.object_id, data),
                artifact_id=event.object_id if event.object_kind == "artifact" else None,
                started_by="nik-automation",
                event_id=event.id,
                caused_by_run=cause,
                depth=depth,
                event_key=key,
                now=now,
            )
        )
        db.flush()
    return started


def event_key(event_id: str, playbook_id: str) -> str:
    """What makes a run of a playbook for an event one of a kind."""
    return f"{event_id}:{playbook_id}"[:80]


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
        # Once, however many of its times passed while the worker was stopped (schedules.py); the
        # move of the next time and the run are one commit, so a restart neither loses nor repeats it.
        due = float(row.next_at or now)
        missed = schedules.missed_between(row.cron, row.timezone, due, now) if now - due >= 60 else 0
        row.next_at = schedules.next_after(row.cron, row.timezone, now)
        if playbook is None or not playbook.enabled or not playbook.current_version:
            continue
        if missed:
            row.skipped = (row.skipped or 0) + missed
        # A run of the last firing still in progress: this one is skipped and counted.
        if _active_for(db, playbook, "schedule", row.node_id) or refusal(db, playbook, "schedule", row.node_id, now):
            row.skipped = (row.skipped or 0) + 1
            continue
        data, classes = payloads.schedule(engine.iso(now), row.cron, engine.iso(due), int(max(0, now - due)), missed)
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


def manual_object(db: OrmSession, object_kind: str, object_id: str, actor: str) -> tuple[dict, dict, str, str] | None:
    """The payload of a run started by hand on an object: (data, classes, what
    it is, incident id); None when it does not exist. What it is: ``incident``,
    ``mail``, ``file``, ``url``, ``indicator``, or nothing."""
    if not object_kind:
        data, classes = payloads.manual(actor, None)
        return data, classes, "", ""
    if object_kind == "incident":
        incident = db.get(Incident, object_id)
        if incident is None:
            return None
        data, classes = payloads.manual(actor, incident)
        return data, classes, "incident", incident.id
    if object_kind == "artifact":
        artifact = db.get(Artifact, object_id)
        found = payloads.artifact_manual(actor, db, artifact) if artifact is not None else None
        if found is None:
            return None
        return found[0], found[1], artifact.kind, ""
    if object_kind == "indicator":
        from ..iocs import TYPES

        kind, _, value = object_id.partition(":")
        if kind not in TYPES or not value:
            return None
        data, classes = payloads.indicator_manual(actor, db, kind, value)
        return data, classes, "indicator", ""
    return None


# What each event is about. A playbook run by hand on something else would read fields that are not there.
_ABOUT = {
    "incident.created": "incident",
    "incident.updated": "incident",
    "ioc.watch_hit": "incident",
    "indicators.found": "incident",
    "mail.analysed": "mail",
    "file.analysed": "file",
    "code.analysed": "file",
    "capabilities.analysed": "file",
    "capture.analysed": "pcap",
    "url.analysed": "url",
    "ioc.verdict_changed": "indicator",
}
_NAMES = {
    "incident": "an incident",
    "mail": "an e-mail",
    "file": "a file",
    "pcap": "a capture",
    "url": "an address",
    "indicator": "an indicator",
}


def object_of(config: dict[str, Any]) -> str:
    """What a trigger's event is about ("" when it has none, or one about nothing)."""
    return _ABOUT.get(str(config.get("event") or ""), "")


def manual_problem(config: dict[str, Any], what: str) -> str | None:
    """Why a playbook cannot be run by hand on this kind of object (None when it can)."""
    wanted = object_of(config)
    if what and wanted and what != wanted:
        return f"This playbook runs on {_NAMES[wanted]}, not on {_NAMES[what]}"
    return None


def describe(config: dict[str, Any]) -> str:
    """A trigger in a few words, for the list of playbooks."""
    parts = []
    if config.get("event"):
        parts.append(str(config["event"]))
    if config.get("cron"):
        parts.append(f"schedule {config['cron']}")
    if config.get("webhook"):
        parts.append("webhook")
    if config.get("manual"):
        parts.append("by hand")
    return ", ".join(parts) or "none"
