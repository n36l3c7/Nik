"""The optional expiry of an artifact.

Nothing has a date unless someone gives it one: there is no default and no
retention for artifacts as a whole. An artifact with a date is deleted by the
worker once that day has come, through the same code as a deletion by hand,
with a line of the audit log and the event ``artifact.expired``. Seven days
before, ``artifact.expiring`` says so once.

An artifact that an incident which is not closed still references is **not**
deleted: its date is put off by a week, and the artifact says why. Evidence
of work in progress does not disappear because a date was set months ago.

The original of host evidence (``hostfile``) never expires while an incident holds
it as evidence, closed or not: its date is put off the same way. Once no incident
holds it, it expires like the others and the original is removed.
"""

from __future__ import annotations

import logging
import time
from datetime import date, datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .core import audit
from .core.models import Artifact, ArtifactLink, Incident

logger = logging.getLogger("nik.artifacts")

NOTICE_DAYS = 7
PUT_OFF_DAYS = 7
MAX_YEARS = 20
PER_TICK = 25  # artifacts deleted in one pass of the worker
ACTOR = "nik"


class ExpiryError(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


def today(now: float | None = None) -> date:
    return datetime.fromtimestamp(time.time() if now is None else now, timezone.utc).date()


def clean_date(value: Any, now: float | None = None) -> str | None:
    """A date an artifact can expire on: ``YYYY-MM-DD`` (or an ISO time, of which the day is kept),
    not in the past. None for no date."""
    if value in (None, ""):
        return None
    try:
        day = date.fromisoformat(str(value).strip()[:10])
    except ValueError:
        raise ExpiryError("An expiry is a date: 2027-01-31") from None
    current = today(now)
    if day <= current:
        raise ExpiryError("An expiry is a day to come: to delete an artifact now, delete it")
    if day > current + timedelta(days=366 * MAX_YEARS):
        raise ExpiryError(f"An expiry is {MAX_YEARS} years away at most: leave it without a date instead")
    return day.isoformat()


def set_expiry(db: OrmSession, row: Artifact, value: Any, now: float | None = None) -> str | None:
    """Give an artifact a date, or take it away (the caller commits and writes the audit entry)."""
    row.expires_at = clean_date(value, now)
    row.expiry_note = ""
    row.expiry_noticed = None
    return row.expires_at


def days_left(row: Artifact, now: float | None = None) -> int | None:
    if not row.expires_at:
        return None
    try:
        return (date.fromisoformat(row.expires_at) - today(now)).days
    except ValueError:
        return None


def open_incident(db: OrmSession, row: Artifact) -> Incident | None:
    """An incident that references the artifact and is not closed."""
    return db.scalars(
        select(Incident)
        .join(ArtifactLink, ArtifactLink.incident_id == Incident.id)
        .where(ArtifactLink.artifact_id == row.id, Incident.status != "closed")
        .limit(1)
    ).first()


def tick(db: OrmSession, now: float | None = None) -> dict[str, int]:
    """What the worker does about dates: say that an artifact is about to go, delete the ones whose
    day has come, put off those an open incident holds. Commits as it goes."""
    from .automation import triggers
    from .routers.artifacts import delete_artifact_data

    current = today(now)
    done = {"noticed": 0, "expired": 0, "put_off": 0}
    soon = (current + timedelta(days=NOTICE_DAYS)).isoformat()
    dated = db.scalars(
        select(Artifact)
        .where(Artifact.expires_at.is_not(None), Artifact.expires_at <= soon)
        .order_by(Artifact.expires_at)
    ).all()
    for row in dated:
        left = days_left(row, now)
        if left is None:
            continue
        if left > 0:
            if row.expiry_noticed != row.expires_at:
                row.expiry_noticed = row.expires_at
                triggers.artifact_expiring(db, row, left)
                db.commit()
                done["noticed"] += 1
            continue
        if done["expired"] >= PER_TICK:
            break
        held = open_incident(db, row)
        if row.kind == "hostfile":
            from .evidence import originals

            count = originals.holders(db, row.ref)
            if count:
                later = (current + timedelta(days=PUT_OFF_DAYS)).isoformat()
                row.expires_at = later
                row.expiry_noticed = later
                row.expiry_note = f"Put off to {later}: {count} incident(s) hold it as evidence"
                said = f"Put off the expiry of {row.kind} {row.name or row.ref[:12]} to {later}"
                audit.record(db, ACTOR, "artifact.expiry", said, target=row.id)
                db.commit()
                done["put_off"] += 1
                continue
            held = None
        if held is not None:
            later = (current + timedelta(days=PUT_OFF_DAYS)).isoformat()
            name = str((held.doc or {}).get("name") or held.name or held.id)[:120]
            row.expires_at = later
            row.expiry_noticed = later  # it was said once already: a date put off is not a new warning
            row.expiry_note = f'Put off to {later}: the incident "{name}" still references it and is not closed'
            audit.record(
                db, ACTOR, "artifact.expiry", f"Put off the expiry of {row.kind} {row.name or row.ref[:12]} to {later}",
                target=row.id,
            )  # fmt: skip
            db.commit()
            done["put_off"] += 1
            continue
        try:
            said = (
                f"Deleted {row.kind} {row.name or row.ref[:12]} ({row.ref[:12]}…): its expiry of {row.expires_at} came"
            )
            triggers.artifact_expired(db, row)
            audit.record(db, ACTOR, "artifact.expire", said, target=row.id)
            delete_artifact_data(db, row)
            db.commit()
            done["expired"] += 1
        except Exception:  # noqa: BLE001 - one artifact that cannot be deleted must not stop the others
            db.rollback()
            logger.exception("The expired artifact %s could not be deleted", row.id)
    return done


def out(row: Artifact, now: float | None = None) -> dict[str, Any]:
    return {"expiresAt": row.expires_at, "expiryNote": row.expiry_note or "", "expiresInDays": days_left(row, now)}


def storage_lists(db: OrmSession, limit: int = 50) -> dict[str, Any]:
    """For the Storage page: the artifacts with a date, the soonest first, and how much has none."""
    from sqlalchemy import func

    dated = db.scalars(
        select(Artifact).where(Artifact.expires_at.is_not(None)).order_by(Artifact.expires_at, Artifact.id).limit(limit)
    ).all()
    count, size = db.execute(
        select(func.count(), func.coalesce(func.sum(Artifact.size), 0)).where(Artifact.expires_at.is_(None))
    ).one()
    with_date = db.scalar(select(func.count()).select_from(Artifact).where(Artifact.expires_at.is_not(None))) or 0
    return {
        "dated": [
            {
                "artifactId": row.id,
                "kind": row.kind,
                "name": row.name or f"{row.ref[:16]}…",
                "bytes": int(row.size or 0),
                **out(row),
            }
            for row in dated
        ],
        "datedCount": int(with_date),
        "undated": {"count": int(count or 0), "bytes": int(size or 0)},
    }
