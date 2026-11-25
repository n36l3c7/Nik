"""An original of host evidence becomes a source of an incident (7.0).

``accept`` is where every door ends: the parts of a large file put together
(``uploads.finish``), an upload of the API of before (``POST
/incidents/{id}/upload``), a file taken out of a collection. It writes the row
of ``evidence_sources`` (queued), the artifact of the original and its link to
the incident, and wants the reading of the file (``parse.WORK``) in the same
transaction: the file is read exactly when its row exists.

A file the incident already holds (same SHA-256, same section and source) is
not imported twice: the row it has is returned, and the screens say "already
imported" with a link to its report.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .. import archive, work
from ..core.models import ArtifactLink, AuditEntry, EvidenceMark, EvidenceSource, Incident
from ..core.security import now_iso
from . import originals

PARSE_WORK = "evidence-parse"
# The state of a file an imported incident lists and does not hold: its name, hash and report came
# with the export, its original did not.
ABSENT = "absent"
KINDS = ("eventlog", "endpoint", "browser", "commands", "disk", "syslog", "collection")
MAX_RESTORED = 5000
MAX_RESTORED_MARKS = 20_000


_PARSER_OF = {"commands": "history", "browser": "browser", "endpoint": "endpoint"}


def reader(kind: str, source: str, file_name: str) -> tuple[str, str]:
    """The parser and the source name of a file, from what its section says of it. A section that
    names the source names the parser too: the worker is not left to guess from a file name what
    the person already said. An event log is an EVTX file, or the JSON of Nik's script. An empty
    parser is a file the worker has to recognise by itself."""
    if kind == "eventlog":
        if source == "nik-eventlogs.json" or (not source and (file_name or "").lower().endswith(".json")):
            return "eventlog-json", "nik-eventlogs.json"
        if source in ("", "evtx"):
            return "evtx", "evtx"
        return "", source
    return (_PARSER_OF.get(kind, "") if source else ""), source


def _held(db: OrmSession, incident_id: str, sha256: str, kind: str, source: str) -> EvidenceSource | None:
    """The row the incident has for these bytes in this section. A file given without a source is
    whichever row holds it: its source was written by the worker after reading."""
    query = select(EvidenceSource).where(
        EvidenceSource.incident_id == incident_id,
        EvidenceSource.sha256 == sha256,
        EvidenceSource.kind == kind,
    )
    if source:
        query = query.where(EvidenceSource.source == source)
    return db.scalars(query.order_by(EvidenceSource.created_at, EvidenceSource.id)).first()


def is_duplicate(db: OrmSession, incident_id: str, sha256: str, file_name: str, params: dict[str, Any]) -> bool:
    """Whether ``accept`` would give back a file the incident holds. A listing that is ``absent`` is
    not one: giving it its file is what it waits for."""
    kind = str(params.get("kind") or "")
    _, source = reader(kind, str(params.get("source") or "")[:60], file_name)
    found = _held(db, incident_id, sha256, kind, source)
    return found is not None and found.state != ABSENT


def accept(
    db: OrmSession, incident_id: str, sha256: str, size: int, file_name: str, params: dict[str, Any], actor: str
) -> EvidenceSource:
    """The source of an original just kept (the caller commits). ``params``: ``kind`` (the section),
    ``source`` (what it is to the section, or empty: the worker recognises it), ``host``, ``user``,
    ``profile``, ``collectionId``, ``filePath``. Raises ``archive.Archived`` for an incident that is
    archived: nothing is added to it."""
    archive.guard_id(db, incident_id)
    kind = str(params.get("kind") or "")
    if kind not in KINDS:
        raise ValueError(f"Not a section of host evidence: {kind or '(none)'}")
    parser, source = reader(kind, str(params.get("source") or "")[:60], file_name)
    found = _held(db, incident_id, sha256, kind, source)
    if found is not None and found.state != ABSENT:
        return found
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise ValueError("Incident not found")
    if found is not None:
        # Listed by an import of the incident, and not here until now: the file was given again.
        db.delete(found)
        db.flush()
    row = EvidenceSource(
        id=uuid.uuid4().hex,
        incident_id=incident_id,
        kind=kind,
        source=source,
        sha256=sha256,
        file_name=(file_name or "")[:500],
        file_path=str(params.get("filePath") or "")[:1000],
        size=size,
        collection_id=params.get("collectionId") or None,
        host=str(params.get("host") or "")[:255],
        username=str(params.get("user") or "")[:255],
        profile=str(params.get("profile") or "")[:120],
        parser=parser,
        state="queued",
        read="unknown",
        report={},
        created_at=now_iso(),
        created_by=actor,
    )
    db.add(row)
    artifact = originals.register(db, sha256, file_name, size, actor, detail=kind)
    db.flush()
    if db.get(ArtifactLink, (artifact.id, incident_id)) is None:
        db.add(ArtifactLink(artifact_id=artifact.id, incident_id=incident_id))
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()),
            at=now_iso(),
            actor=actor,
            action="evidence.import",
            target=file_name,
            details=f"Imported {file_name} ({size} bytes, SHA-256 {sha256}) into {kind}",
            incident_id=incident_id,
            incident_name=(incident.doc or {}).get("name"),
        )
    )
    work.want(db, PARSE_WORK, row.id)
    return row


def restore(db: OrmSession, incident_id: str, exported: Any, actor: str) -> dict[str, int]:
    """Take back what an export said of an incident's host evidence (``browse.exported``), for the
    incident an import just made (the caller commits). Each file is listed as ``absent``: its name,
    SHA-256, counts and report as they were, no original and no record. The flags and notes come
    back by key, so giving a file again puts them on its records. What is not in the shape of an
    export is left out, never guessed."""
    done = {"sources": 0, "marks": 0}
    if not isinstance(exported, dict):
        return done
    for entry in [item for item in exported.get("sources") or [] if isinstance(item, dict)][:MAX_RESTORED]:
        kind, sha256 = str(entry.get("kind") or ""), str(entry.get("sha256") or "").lower()
        if kind not in KINDS or (sha256 and not originals.SHA256_RE.fullmatch(sha256)):
            continue

        def number(name: str, entry: dict = entry) -> int:
            value = entry.get(name)
            return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 0 else 0

        report = entry.get("report") if isinstance(entry.get("report"), dict) else {}
        db.add(
            EvidenceSource(
                id=uuid.uuid4().hex,
                incident_id=incident_id,
                kind=kind,
                source=str(entry.get("source") or "")[:60],
                sha256=sha256,
                file_name=str(entry.get("fileName") or "")[:500],
                file_path=str(entry.get("filePath") or "")[:1000],
                size=number("size"),
                host=str(entry.get("host") or "")[:255],
                username=str(entry.get("username") or "")[:255],
                profile=str(entry.get("profile") or "")[:120],
                parser=str(entry.get("parser") or "")[:40],
                parser_version=str(entry.get("parserVersion") or "")[:20],
                state=ABSENT,
                legacy=bool(entry.get("legacy")),
                read=str(entry.get("read") or "unknown")[:10],
                in_file=number("inFile") if entry.get("inFile") is not None else None,
                read_count=number("readCount"),
                kept=0,
                duplicates=number("duplicates"),
                skipped=number("skipped"),
                notes=number("notes"),
                truncated=number("truncated"),
                # What it held where it was exported from, beside the report it had there.
                report={**report, "exported": {"kept": number("kept"), "by": actor, "at": now_iso()}},
                created_at=str(entry.get("createdAt") or now_iso())[:40],
                created_by=str(entry.get("createdBy") or "")[:200],
            )
        )
        done["sources"] += 1
    for entry in [item for item in exported.get("marks") or [] if isinstance(item, dict)][:MAX_RESTORED_MARKS]:
        key = entry.get("key")
        if not isinstance(key, str) or not key or len(key) > 300 or db.get(EvidenceMark, (incident_id, key)):
            continue
        db.add(
            EvidenceMark(
                incident_id=incident_id,
                key=key,
                flagged=bool(entry.get("flagged")),
                note=str(entry.get("note") or "")[:5000],
                updated_by=str(entry.get("updatedBy") or actor)[:200],
                updated_at=str(entry.get("updatedAt") or now_iso())[:40],
            )
        )
        done["marks"] += 1
    return done
