"""The process-chain rules: Sigma rules of the log source ``product: nik, service: process-chain``, run over the
processes of a host once they are linked (7.0).

A rule of this log source says what a *chain* of processes looks like (Word that starts PowerShell, a web server
that starts a shell), which a rule on one record cannot say. After the processes of a host are linked
(``processes.py``), each is given to the forensics worker (``POST /sigma/try``, as the screen that tries a rule
does) as one synthetic record of the kind ``process-chain``, 2,000 at a time, with the fields:

``Image``, ``CommandLine``, ``User``, ``IntegrityLevel``, ``ParentImage``, ``ParentCommandLine``,
``GrandParentImage``, ``GrandParentCommandLine``, ``Ancestors`` (the images of up to 8 ancestors, the nearest
first, as a list; a ghost parent counts as the last), ``Depth`` (how many ancestors that is), ``Host`` and
``Platform`` (``windows``, ``linux`` or ``macos``, from the image).

A match is a detection on the record of the process (the table and the screens of every detection) and sets
``evidence_processes.level``. A run replaces the chain detections of the hosts it covers and leaves the others
alone; a record's level is made again from the detections it has left. With no worker, or with no chain rule at
all, nothing is run and nothing is taken away; with chain rules that are all switched off the old detections go.
"""

from __future__ import annotations

import logging
from typing import Any

from sqlalchemy import delete, func, or_, select, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session as OrmSession

from .. import work
from ..core.db import SessionLocal
from ..core.models import EvidenceDetection, EvidenceProcess, EvidenceRecord, EvidenceSource, Incident
from ..core.security import now_iso
from ..sigma import detections as sigma_detections
from ..sigma import ruleset, worker

logger = logging.getLogger("nik.evidence.chains")

BATCH = 2000  # processes in one call to the worker
ANCESTORS = 8
CACHE_MAX = 100_000
KIND = "process-chain"
IN_MAX = 500
MACOS = ("/System/", "/Applications/", "/Library/", "/usr/libexec/", "/private/var/")


def platform_of(image: str) -> str:
    """The system a process is of, out of the path of its image."""
    if "\\" in image or (len(image) > 1 and image[1] == ":"):
        return "windows"
    if image.startswith(MACOS):
        return "macos"
    return "linux" if image.startswith("/") else "windows"


class _Parents:
    """What the chains need of a process they pass through: looked up by the database, a chunk at a time, and
    kept (a small cache: the parents of a host are few, however many processes it has)."""

    def __init__(self, db: OrmSession, incident_id: str):
        self.db = db
        self.incident_id = incident_id
        self.held: dict[int, tuple[str, str, int | None, str, str]] = {}

    def fetch(self, ids: set[int]) -> None:
        wanted = sorted(ids - self.held.keys())
        p = EvidenceProcess
        if len(self.held) > CACHE_MAX:
            self.held.clear()
        for start in range(0, len(wanted), IN_MAX):
            found = self.db.execute(
                select(p.id, p.image, p.command_line, p.parent_id, p.parent_image, p.parent_command_line).where(
                    p.incident_id == self.incident_id, p.id.in_(wanted[start : start + IN_MAX])
                )
            )
            for process_id, image, command, parent_id, ghost, ghost_command in found:
                self.held[process_id] = (image, command, parent_id, ghost, ghost_command)

    def chains(self, rows: list[Any]) -> dict[int, list[tuple[str, str]]]:
        """For each process, its ancestors nearest first as ``(image, command line)``, up to ``ANCESTORS``."""
        out: dict[int, list[tuple[str, str]]] = {row.id: [] for row in rows}
        at: dict[int, int | None] = {}
        for row in rows:
            if row.parent_id is not None:
                at[row.id] = row.parent_id
            elif row.parent_image:
                out[row.id].append((row.parent_image, row.parent_command_line))
        for _level in range(ANCESTORS):
            if not at:
                break
            self.fetch({parent for parent in at.values() if parent is not None})
            following: dict[int, int | None] = {}
            for process_id, parent in at.items():
                known = self.held.get(parent) if parent is not None else None
                if known is None:
                    continue
                image, command, grand, ghost, ghost_command = known
                out[process_id].append((image, command))
                if len(out[process_id]) >= ANCESTORS:
                    continue
                if grand is not None and grand != parent:
                    following[process_id] = grand
                elif grand is None and ghost:
                    out[process_id].append((ghost, ghost_command))
            at = following
        return {process_id: found[:ANCESTORS] for process_id, found in out.items()}


def _given(row: Any, host: str, ancestors: list[tuple[str, str]]) -> dict[str, Any]:
    parent = ancestors[0] if ancestors else ("", "")
    grand = ancestors[1] if len(ancestors) > 1 else ("", "")
    return {
        "kind": KIND,
        "channel": "",
        "event_id": None,
        "key": f"proc:{row.id}",
        "ts": row.start_ts,
        "host": host,
        "username": row.username,
        "summary": row.image,
        "data": {
            "Image": row.image,
            "CommandLine": row.command_line,
            "User": row.username,
            "IntegrityLevel": row.integrity,
            "ParentImage": parent[0],
            "ParentCommandLine": parent[1],
            "GrandParentImage": grand[0],
            "GrandParentCommandLine": grand[1],
            "Ancestors": [image for image, _command in ancestors],
            "Depth": len(ancestors),
            "Host": host,
            "Platform": platform_of(row.image),
        },
    }


def _forget(db: OrmSession, incident_id: str, host: str, every: set[str]) -> None:
    """Take away the chain detections of the processes of a host, and what they raised."""
    p, d, r = EvidenceProcess, EvidenceDetection, EvidenceRecord
    mine = select(p.record_id).where(p.incident_id == incident_id, p.host == host, p.record_id.is_not(None))
    for start in range(0, len(every), IN_MAX):
        part = sorted(every)[start : start + IN_MAX]
        db.execute(delete(d).where(d.incident_id == incident_id, d.rule_id.in_(part), d.record_id.in_(mine)))
    # What a record's level is, made again from the detections it still has.
    top = select(func.max(d.level)).where(d.record_id == r.id).scalar_subquery()
    db.execute(
        update(r)
        .where(r.incident_id == incident_id, r.level.is_not(None), r.id.in_(mine))
        .values(level=top)
        .execution_options(synchronize_session=False)
    )
    db.execute(update(p).where(p.incident_id == incident_id, p.host == host, p.level.is_not(None)).values(level=None))


def _keep(db: OrmSession, incident_id: str, matches: list[dict[str, Any]], rows: dict[int, Any], meta: dict) -> int:
    """Write the matches of a batch as detections of the records of their processes."""
    table = EvidenceDetection.__table__
    insert = postgresql.insert if db.get_bind().dialect.name == "postgresql" else sqlite.insert
    levels: dict[int, int] = {}
    records: dict[int, int] = {}
    detections: list[dict[str, Any]] = []
    now = now_iso()
    seen: set[tuple[int, str]] = set()
    for match in matches:
        key, rule = match.get("key"), match.get("rule")
        if not isinstance(key, str) or not key.startswith("proc:") or rule not in meta:
            continue
        try:
            process_id = int(key[5:])
        except ValueError:
            continue
        row = rows.get(process_id)
        if row is None:
            continue
        level = int(meta[rule]["level"])
        levels[process_id] = max(levels.get(process_id, 0), level)
        if row.record_id is None or (row.record_id, rule) in seen:
            continue
        seen.add((row.record_id, rule))
        records[row.record_id] = max(records.get(row.record_id, 0), level)
        detections.append(
            {
                "incident_id": incident_id,
                "record_id": row.record_id,
                "rule_id": rule,
                "rule_title": str(meta[rule]["title"])[:300],
                "rule_author": str(meta[rule]["author"])[:300],
                "level": level,
                "tags": meta[rule]["tags"],
                "records": [],
                "created_at": now,
            }
        )
    for start in range(0, len(detections), 500):
        db.execute(
            insert(table).on_conflict_do_nothing(index_elements=["record_id", "rule_id"]),
            detections[start : start + 500],
        )
    sigma_detections._raise(db, records)
    by_level: dict[int, list[int]] = {}
    for process_id, level in levels.items():
        by_level.setdefault(level, []).append(process_id)
    for level, ids in by_level.items():
        for start in range(0, len(ids), IN_MAX):
            db.execute(
                update(EvidenceProcess)
                .where(
                    EvidenceProcess.id.in_(ids[start : start + IN_MAX]),
                    or_(EvidenceProcess.level.is_(None), EvidenceProcess.level < level),
                )
                .values(level=level)
            )
    return len(levels)


def _host(
    incident_id: str,
    host: str,
    given: dict[str, Any],
    meta: dict,
    every: set[str],
    claim: work.Claim | None,
) -> int:
    """Run the rules over the processes of one host; returns how many matched a rule. What an earlier run found
    on the host is taken away when the worker has answered the first batch, so a worker that refuses leaves it."""
    forgotten = False
    from .processes import _chunks  # the same walk, in start order

    p = EvidenceProcess
    matched = 0
    seen = 0
    for rows in _chunks(incident_id, host):
        for start in range(0, len(rows), BATCH):
            ids = [row.id for row in rows[start : start + BATCH]]
            with SessionLocal() as db:
                full = {
                    row.id: row
                    for row in db.execute(
                        select(
                            p.id,
                            p.record_id,
                            p.image,
                            p.command_line,
                            p.username,
                            p.integrity,
                            p.start_ts,
                            p.parent_id,
                            p.parent_image,
                            p.parent_command_line,
                        ).where(p.incident_id == incident_id, p.id.in_(ids))
                    )
                }
                ancestors = _Parents(db, incident_id).chains(list(full.values()))
                records = [_given(full[i], host, ancestors[i]) for i in ids if i in full]
                status, said = worker.ask("/sigma/try", {**given, "records": records}, timeout=300)
                if status != 200:
                    raise _Refused(worker.sentence(status, said))
                found = [m for m in said.get("matches") or [] if isinstance(m, dict)]
                if not forgotten:
                    _forget(db, incident_id, host, every)
                    forgotten = True
                matched += _keep(db, incident_id, found, full, meta)
                db.commit()
            seen += len(ids)
            if claim is not None:
                claim.progress(f"{host}: {seen} processes judged by the chain rules"[:200])
    return matched


class _Refused(Exception):
    """The worker did not take a batch: the run of this host stops, what was done stays."""


def sync_levels(incident_id: str, hosts: list[str]) -> None:
    """A process has the level of its record: the highest of the detections of the record, whichever rule found it
    (a rule that read the file, or a chain rule). Made again for these hosts after the chain rules ran."""
    p, r = EvidenceProcess, EvidenceRecord
    for host in hosts:
        with SessionLocal() as db:
            wanted = select(r.level).where(r.id == p.record_id).scalar_subquery()
            db.execute(
                update(p)
                # Only the processes whose level is not the record's: a host of many is not written over for nothing.
                .where(
                    p.incident_id == incident_id,
                    p.host == host,
                    p.record_id.is_not(None),
                    p.level.is_distinct_from(wanted),
                )
                .values(level=wanted)
                .execution_options(synchronize_session=False)
            )
            db.commit()


def refresh(incident_id: str, hosts: list[str]) -> int:
    """The chain rules ran over these hosts: the detections in the report of each finished file that holds processes
    of them are counted again from the table (a file read earlier, or a file the chains found something in after
    another one was read). A file still being read is closed by its own reading. Returns how many were changed."""
    changed = 0
    with SessionLocal() as db:
        ids = list(
            db.scalars(
                select(EvidenceProcess.source_id)
                .where(EvidenceProcess.incident_id == incident_id, EvidenceProcess.host.in_(hosts))
                .distinct()
            )
        )
        for source in db.scalars(
            select(EvidenceSource).where(EvidenceSource.id.in_(ids), EvidenceSource.state == "done")
        ):
            found = sigma_detections.Detected.from_table(db, incident_id, source.id)
            report = dict(source.report or {})
            if not (found.total or "detections" in report):
                continue
            now = found.report()
            if report.get("detections") != now:
                report["detections"] = now
                source.report = report
                changed += 1
        db.commit()
    return changed


def run(incident_id: str, hosts: list[str], claim: work.Claim | None = None) -> dict[str, int]:
    """Run the chain rules over the processes of these hosts (linked already). Returns ``{"hosts", "matched"}``.
    Nothing when the worker is not configured: the detections of an earlier run stay as they were."""
    if not worker.configured():
        return {"hosts": 0, "matched": 0}
    with SessionLocal() as db:
        lines, meta, every = ruleset.chains(db)
        hours = ruleset.hours(db, db.get(Incident, incident_id))
    if not every:
        return {"hosts": 0, "matched": 0}
    done = matched = 0
    for host in hosts:
        if not lines:  # every chain rule is switched off: what they found goes
            with SessionLocal() as db:
                _forget(db, incident_id, host, every)
                db.commit()
            continue
        try:
            matched += _host(incident_id, host, {"rules": lines, "hours": hours}, meta, every, claim)
        except _Refused as refused:
            logger.warning("The chain rules were not run over %s of %s: %s", host, incident_id, refused)
            continue
        done += 1
    return {"hosts": done, "matched": matched}
