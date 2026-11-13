"""Artifacts: files, e-mails, packet captures and URLs analysed on their own.

An artifact is the registry entry of something Nik analysed: a sample
(``file``), an e-mail (``mail``), a capture (``pcap``) or a scanned address
(``url``). It exists whether or
not an incident references it, so an analyst can study a file first and decide
later whether it belongs to a case.

- ``register_*`` writes or refreshes the entry after an analysis.
- ``sync_links`` keeps ``artifact_links`` equal to what an incident's document
  references; it runs each time an incident is saved (``iocs.reindex_incident``),
  so the documents stay the single source of truth.
- ``relate`` records where an artifact comes from (an attachment of an e-mail,
  an object extracted from a capture).
- ``backfill`` writes the entries of what was stored before 2.19.0.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .core.models import (
    Artifact,
    ArtifactLink,
    ArtifactRelation,
    Incident,
    Mail,
    NetworkCapture,
    Sample,
    UrlScan,
)
from .core.security import now_iso

logger = logging.getLogger("nik.artifacts")

KINDS = ("file", "mail", "pcap", "url", "mailbox")
TAG_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,39}")
TAGS_MAX = 12
_ID_RE = re.compile(r"(file|mail)-[0-9a-f]{64}|(pcap|url|mailbox)-[0-9a-f]{32}")


def artifact_id(kind: str, ref: str) -> str:
    return f"{kind}-{ref}"


def is_artifact_id(value: str) -> bool:
    return bool(_ID_RE.fullmatch(value or ""))


def file_verdict(analysis: dict[str, Any], size: int) -> str:
    """``high`` / ``medium`` from the YARA matches, ``medium`` when most of the
    file is high-entropy (packed or encrypted), otherwise empty."""
    severities = {str((m.get("meta") or {}).get("severity") or "").lower() for m in analysis.get("yara") or []}
    if "high" in severities:
        return "high"
    if "medium" in severities:
        return "medium"
    if size > 0 and (analysis.get("highEntropyBytes") or 0) / size > 0.5:
        return "medium"
    return ""


def _upsert(db: OrmSession, kind: str, ref: str, name: str, actor: str, created_at: str, **fields: Any) -> Artifact:
    row = db.get(Artifact, artifact_id(kind, ref))
    if row is None:
        row = Artifact(
            id=artifact_id(kind, ref),
            kind=kind,
            ref=ref,
            name=name[:255],
            tags=[],
            created_at=created_at or now_iso(),
            created_by=actor,
        )
        db.add(row)
        db.flush()  # a second registration in the same request must find it
    elif name and not row.name:
        row.name = name[:255]
    for key, value in fields.items():
        setattr(row, key, value)
    return row


def register_file(db: OrmSession, sample: Sample, name: str = "") -> Artifact:
    return _upsert(
        db,
        "file",
        sample.sha256,
        name,
        sample.created_by,
        sample.created_at,
        verdict=file_verdict(sample.analysis or {}, sample.size),
        score=None,
        detail=sample.type_label or "",
        size=sample.size,
    )


def register_mail(db: OrmSession, mail: Mail, name: str = "") -> Artifact:
    return _upsert(
        db,
        "mail",
        mail.sha256,
        mail.subject or name or mail.sha256[:16],
        mail.created_by,
        mail.created_at,
        verdict=mail.verdict,
        score=mail.score,
        detail=mail.sender or "",
        size=mail.size,
    )


def register_capture(db: OrmSession, capture: NetworkCapture) -> Artifact:
    label = (capture.meta or {}).get("label") or capture.file_name
    detail = "isolated browser session" if capture.kind == "browser" else f"{capture.packets} packets"
    return _upsert(
        db,
        "pcap",
        capture.id,
        str(label or capture.id),
        capture.created_by,
        capture.created_at,
        verdict="",
        score=None,
        detail=detail if capture.status in ("ready", "live") else capture.status,
        size=capture.size,
    )


def register_url(db: OrmSession, scan: UrlScan) -> Artifact:
    parts = scan.url.split("://", 1)[-1].split("?", 1)[0].rstrip("/")
    final = (scan.result or {}).get("finalUrl") or ""
    detail = scan.status if scan.status != "done" else (final.split("://", 1)[-1].split("/", 1)[0] or scan.host)
    return _upsert(
        db,
        "url",
        scan.id,
        parts[:160],
        scan.created_by,
        scan.created_at,
        verdict=scan.verdict if scan.status == "done" else "",
        score=scan.score if scan.status == "done" else None,
        detail=detail,
        size=0,
    )


def register_mailbox(db: OrmSession, mailbox) -> Artifact:
    """A mailbox (mbox, Maildir, PST): its verdict is the worst of the messages imported from it."""
    meta = mailbox.meta or {}
    counts = meta.get("verdicts") or {}
    verdict = "phishing" if counts.get("phishing") else "suspicious" if counts.get("suspicious") else ""
    if mailbox.status == "ready":
        detail = f"{meta.get('imported', 0)} of {mailbox.total} messages imported"
    else:
        detail = mailbox.status
    return _upsert(
        db,
        "mailbox",
        mailbox.id,
        mailbox.file_name or mailbox.id,
        mailbox.created_by,
        mailbox.created_at,
        verdict=verdict,
        score=None,
        detail=detail,
        size=mailbox.size,
    )


def relate(db: OrmSession, parent_id: str, child_id: str, relation: str) -> None:
    """Record that ``child`` was taken out of ``parent`` (kept once)."""
    if parent_id == child_id or db.get(ArtifactRelation, (parent_id, child_id)) is not None:
        return
    db.flush()  # both artifacts must exist before the relation refers to them
    db.add(ArtifactRelation(parent_id=parent_id, child_id=child_id, relation=relation, created_at=now_iso()))


def forget(db: OrmSession, kind: str, ref: str) -> None:
    """Drop the entry (its links and relations go with it)."""
    row = db.get(Artifact, artifact_id(kind, ref))
    if row is not None:
        db.delete(row)
        db.flush()


def sync_links(
    db: OrmSession,
    incident: Incident,
    samples: dict[str, Sample],
    mails: dict[str, Mail],
    captures: dict[str, NetworkCapture],
    names: dict[str, str],
    urls: dict[str, UrlScan] | None = None,
) -> None:
    """Make ``artifact_links`` match what the incident's document references.

    ``names`` gives the file name each reference carries, used for an entry
    that does not exist yet.
    """
    wanted: set[str] = set()
    for sample in samples.values():
        wanted.add(register_file(db, sample, names.get(sample.sha256, "")).id)
    for mail in mails.values():
        wanted.add(register_mail(db, mail, names.get(mail.sha256, "")).id)
    for capture in captures.values():
        wanted.add(register_capture(db, capture).id)
    for scan in (urls or {}).values():
        wanted.add(register_url(db, scan).id)
    db.flush()
    current = set(db.scalars(select(ArtifactLink.artifact_id).where(ArtifactLink.incident_id == incident.id)))
    gone = current - wanted
    if gone:
        db.execute(
            delete(ArtifactLink).where(ArtifactLink.incident_id == incident.id, ArtifactLink.artifact_id.in_(gone))
        )
    db.add_all(ArtifactLink(artifact_id=item, incident_id=incident.id) for item in wanted - current)


def set_tags(db: OrmSession, row: Artifact, tags: Iterable[str]) -> list[str]:
    clean: list[str] = []
    for tag in tags:
        value = str(tag).strip().lower()
        if TAG_RE.fullmatch(value) and value not in clean:
            clean.append(value)
    row.tags = clean[:TAGS_MAX]
    flag_modified(row, "tags")
    return row.tags


def backfill(session_factory) -> int:
    """Startup pass: entries for the samples, e-mails and captures stored
    before artifacts existed. Links follow from re-indexing the incidents."""
    from .iocs import reindex_incident

    with session_factory() as db:
        if db.scalar(select(Artifact.id).limit(1)) is not None:
            return 0
        stored = (
            db.scalar(select(Sample.sha256).limit(1)),
            db.scalar(select(Mail.sha256).limit(1)),
            db.scalar(select(NetworkCapture.id).limit(1)),
        )
        if not any(stored):
            return 0
        for incident in db.scalars(select(Incident)).all():
            reindex_incident(db, incident)
        for sample in db.scalars(select(Sample)).all():
            register_file(db, sample)
        for mail in db.scalars(select(Mail)).all():
            register_mail(db, mail)
        for capture in db.scalars(select(NetworkCapture)).all():
            register_capture(db, capture)
        for scan in db.scalars(select(UrlScan)).all():
            register_url(db, scan)
        db.commit()
        count = len(db.scalars(select(Artifact.id)).all())
        logger.info("Registered %d artifact(s) stored by earlier releases", count)
        return count
