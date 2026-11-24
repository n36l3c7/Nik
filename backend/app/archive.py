"""Archiving a closed incident (7.0).

A closed incident that nobody works on any more can be archived. It is then
**read-only** and **out of the normal lists**: it is found with a filter
(``archived:true``) and by the global search, and its summary, its War Room, its
indicators and its report stay readable. Nothing writes to it: every writer
calls ``guard`` and is refused with ``Archived``, answered ``409``. Deleting it
is still allowed. Reopening it needs taking it out of the archive first.

**What leaves the database.** The records of host evidence (``evidence_records``
and what hangs on them) are the bulk of an incident. Archiving drops them, for
the files that have an original in the store, and keeps what is small: the
sources with their parse reports, the originals, and the flags and notes on
records (``evidence_marks``, which hang on the natural key of a record, not on
its row). A source without an original (one of before 7.0, one listed as not
here, one whose file is gone) keeps its records: they could not come back.

**Taking it out.** Every source that was archived is read again from its
original, one after the other, as "Analyse again" does; the flags and notes are
on the records again, because the keys are the same. The caller starts the
readings after the commit.

**The rule.** A setting, off by default: archive the incidents closed for more
than N days. It runs in the hourly housekeeping of ``work.py``, archives a
bounded number of incidents a pass, each in its own commit, as ``nik``.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import work
from .core import copy
from .core.models import EvidenceRecord, EvidenceSource, Incident, Setting
from .core.security import now_iso

logger = logging.getLogger("nik.archive")

SETTINGS_ID = 91  # 90 is evidence/legacy.py
DEFAULTS: dict[str, Any] = {"enabled": False, "days": 180}
DAYS = (1, 3650)
PER_PASS = 50
SENTENCE = "The incident is archived: take it out of the archive first"
ARCHIVED = "archived"
READING = ("queued", "parsing")


class Archived(Exception):
    """A write to an archived incident: the sentence says what to do."""

    def __init__(self, message: str = SENTENCE):
        super().__init__(message)
        self.message = message


def guard(incident: Incident | None) -> None:
    """Refuse a write to an incident that is archived."""
    if incident is not None and incident.archived_at:
        raise Archived()


def is_archived(db: OrmSession, incident_id: str | None) -> bool:
    """Whether the incident with this id is archived (False for one that does not exist)."""
    if not incident_id:
        return False
    return bool(db.scalar(select(Incident.archived_at).where(Incident.id == incident_id)))


def guard_id(db: OrmSession, incident_id: str | None) -> None:
    """``guard`` for a writer that holds the id and not the row."""
    if is_archived(db, incident_id):
        raise Archived()


# --------------------------------------------------------------------------- #
# Archiving                                                                   #
# --------------------------------------------------------------------------- #
def _sources(db: OrmSession, incident: Incident) -> list[EvidenceSource]:
    return list(db.scalars(select(EvidenceSource).where(EvidenceSource.incident_id == incident.id)))


def _can_return(source: EvidenceSource) -> bool:
    """Whether the records of a source can be read again: it has an original, and it is a file."""
    from .evidence import originals

    return bool(
        source.kind != "collection"
        and not source.legacy
        and source.sha256
        and originals.SHA256_RE.fullmatch(source.sha256)
        and originals.has(source.sha256)
    )


def _plural(count: int, word: str) -> str:
    return f"{count} {word}{'' if count == 1 else 's'}"


def put(db: OrmSession, incident: Incident, actor: str) -> dict[str, int]:
    """Archive a closed incident that is locked (the caller commits). Raises ``ValueError`` with a
    sentence when it cannot be. Returns ``{"files", "records", "kept"}``: the files whose records
    left the database, how many records, and the files that keep theirs."""
    from . import war_room
    from .core import audit
    from .evidence import parse

    if incident.archived_at:
        raise ValueError("The incident is archived already")
    if incident.status != "closed":
        raise ValueError("Only a closed incident can be archived: close it first")
    sources = _sources(db, incident)
    if any(source.state in READING for source in sources):
        raise ValueError("A file of the incident is being read: archive it when the reading has ended")
    files = records = kept = 0
    for source in sources:
        if source.state == ARCHIVED:
            continue
        held = int(
            db.scalar(select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.source_id == source.id))
            or 0
        )
        if not _can_return(source):
            kept += 1 if held else 0
            continue
        records += held
        files += 1
        parse.clear(db, source.id)
        source.state = ARCHIVED
    incident.archived_at, incident.archived_by = now_iso(), actor[:200]
    said = f"Archived: {_plural(records, 'record')} of {_plural(files, 'file')} left the database"
    if kept:
        said += f"; {_plural(kept, 'file')} without an original (of before 7.0, or not given again) keep theirs"
    audit.record(db, actor, "incident.archive", said, incident)
    war_room.add(db, incident.id, "system", {"text": said + "."}, actor)
    return {"files": files, "records": records, "kept": kept}


def take_out(db: OrmSession, incident: Incident, actor: str) -> list[str]:
    """Take an incident that is locked out of the archive (the caller commits). Returns the ids of
    the sources to read again: the caller starts each (``parse.start``) after the commit."""
    from . import war_room
    from .core import audit
    from .evidence import parse

    if not incident.archived_at:
        raise ValueError("The incident is not archived")
    incident.archived_at = incident.archived_by = None
    back = [source for source in _sources(db, incident) if source.state == ARCHIVED]
    for source in back:
        parse.again(db, source)
    said = f"Taken out of the archive: {_plural(len(back), 'file')} are read again from their originals"
    audit.record(db, actor, "incident.unarchive", said, incident)
    war_room.add(db, incident.id, "system", {"text": said + "."}, actor)
    return [source.id for source in back]


# --------------------------------------------------------------------------- #
# The rule                                                                    #
# --------------------------------------------------------------------------- #
def config(db: OrmSession) -> dict[str, Any]:
    """The setting: ``{"enabled", "days"}``."""
    row = db.get(Setting, SETTINGS_ID)
    held = row.doc if row is not None and isinstance(row.doc, dict) else {}
    days = held.get("days")
    ok = isinstance(days, int) and not isinstance(days, bool) and DAYS[0] <= days <= DAYS[1]
    return {"enabled": held.get("enabled") is True, "days": days if ok else DEFAULTS["days"]}


def save(db: OrmSession, body: dict[str, Any]) -> dict[str, Any]:
    """Keep the setting (the caller commits and audits). What the body leaves out stays. Raises
    ``ValueError`` with a sentence."""
    doc = config(db)
    if body.get("enabled") is not None:
        if not isinstance(body["enabled"], bool):
            raise ValueError("enabled is true or false")
        doc["enabled"] = body["enabled"]
    if body.get("days") is not None:
        days = body["days"]
        if isinstance(days, bool) or not isinstance(days, int) or not DAYS[0] <= days <= DAYS[1]:
            raise ValueError(f"days is a whole number between {DAYS[0]} and {DAYS[1]}")
        doc["days"] = days
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
    else:
        row.doc = doc
        flag_modified(row, "doc")
    return doc


def auto(db: OrmSession, now: float) -> int:
    """The rule, once: archive up to ``PER_PASS`` incidents closed for more than the days of the
    setting, oldest first, each in its own commit, as ``nik``. One that cannot be archived now (a
    file of it is being read) is left for the next pass. Returns how many were archived.

    A copy of a server (``NIK_COPY``) does nothing: it is a database of its own, but a copy is
    there to be looked at and tried, and its records stay as they were restored."""
    from .core.locking import lock_incident

    if copy.is_copy():
        return 0
    cfg = config(db)
    if not cfg["enabled"]:
        return 0
    cutoff = (datetime.fromtimestamp(now, timezone.utc) - timedelta(days=cfg["days"])).isoformat()
    wanted = db.scalars(
        select(Incident.id)
        .where(Incident.status == "closed", Incident.archived_at.is_(None), Incident.closed_at < cutoff)
        .order_by(Incident.closed_at.asc())
    ).all()
    done = 0
    for incident_id in wanted:
        if done >= PER_PASS:
            break
        row = lock_incident(db, incident_id)
        try:
            if row is None:
                continue
            put(db, row, "nik")
            db.commit()
            done += 1
        except ValueError as error:
            db.rollback()
            logger.info("The incident %s is not archived this pass: %s", incident_id, error)
        except Exception:  # noqa: BLE001 - one incident must not stop the others
            db.rollback()
            logger.exception("The incident %s could not be archived", incident_id)
    return done


work.hourly.append(auto)
