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

from .. import work
from ..core.models import ArtifactLink, AuditEntry, EvidenceSource, Incident
from ..core.security import now_iso
from . import originals

PARSE_WORK = "evidence-parse"
KINDS = ("eventlog", "endpoint", "browser", "commands", "disk", "syslog", "collection")


def accept(
    db: OrmSession, incident_id: str, sha256: str, size: int, file_name: str, params: dict[str, Any], actor: str
) -> EvidenceSource:
    """The source of an original just kept (the caller commits). ``params``: ``kind`` (the section),
    ``source`` (what it is to the section, or empty: the worker recognises it), ``host``, ``user``,
    ``profile``, ``collectionId``, ``filePath``."""
    kind = str(params.get("kind") or "")
    if kind not in KINDS:
        raise ValueError(f"Not a section of host evidence: {kind or '(none)'}")
    source = str(params.get("source") or "")[:60]
    found = db.scalars(
        select(EvidenceSource).where(
            EvidenceSource.incident_id == incident_id,
            EvidenceSource.sha256 == sha256,
            EvidenceSource.kind == kind,
            EvidenceSource.source == source,
        )
    ).first()
    if found is not None:
        return found
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise ValueError("Incident not found")
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
