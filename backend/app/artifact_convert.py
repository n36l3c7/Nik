"""A file Nik holds, analysed as what it is: an e-mail, or a packet capture.

A file reaches the store in many ways that do not say what it is: a command
of a connector downloaded it, it came out of an archive, it was attached to a
message. When it is a message (``.eml``, ``.msg``) or a capture (``.pcap``,
``.pcapng``), "Analyse as an e-mail" and "Analyse as a capture" make of it the
artifact an upload of the same file would have made, with the analysis of its
kind:

- **As an e-mail** the bytes are read from the store and analysed as an
  uploaded message is. The e-mail artifact is the one that message always
  has (its id is its SHA-256): asked twice, nothing is made twice.
- **As a capture** the bytes are copied to the store of captures, under the
  limit of a capture (``PCAP_MAX_MB``), and analysed by the packet capture
  worker; without that worker the capture is stored and says so. A file is
  made a capture once: asked again, the capture it became is given.

The file stays what it was. What was made of it is recorded as made from it,
and goes to the incidents the file is in: all of them for an e-mail, the one
incident for a capture (a capture belongs to one incident at most), or the
incident the caller names.

Nothing is run or opened: both analyses are those of an upload.
"""

from __future__ import annotations

from typing import Any

from fastapi import HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import artifacts
from .core.config import settings
from .core.locking import lock_incident
from .core.models import Artifact, ArtifactLink, ArtifactRelation, Incident, NetworkCapture
from .malware.samples import read_sample, sample_path
from .network import store as capture_store

KINDS = ("mail", "capture")
RELATION = "analysed"
_MAIL_NAMES = (".eml", ".msg")
_CAPTURE_NAMES = (".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz")
_HEADERS = (b"received:", b"from:", b"subject:", b"message-id:", b"return-path:", b"mime-version:", b"date:")
_OLE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class ConvertError(Exception):
    """A file that cannot be analysed this way, with a sentence a person can act on."""

    def __init__(self, message: str, status: int = 422):
        super().__init__(message)
        self.message, self.status = message, status


def by_name(row: Artifact) -> list[str]:
    """What the name of a file says it could be analysed as, without reading it: for the lists."""
    if row.kind != "file":
        return []
    name = (row.name or "").lower()
    if name.endswith(_MAIL_NAMES):
        return ["mail"]
    return ["capture"] if name.endswith(_CAPTURE_NAMES) else []


def fitting(row: Artifact) -> list[str]:
    """What a file can be analysed as, by its first bytes: a capture by its magic number, a message
    by the headers it starts with (an Outlook ``.msg`` by its container and its name)."""
    if row.kind != "file":
        return []
    try:
        with open(sample_path(row.ref), "rb") as handle:
            head = handle.read(8192)
    except (OSError, ValueError):
        return []
    if capture_store.capture_format(head) in ("pcap", "pcapng"):
        return ["capture"]
    if head.startswith(_OLE):
        return ["mail"] if (row.name or "").lower().endswith(".msg") else []
    lines = [line.strip().lower() for line in head.split(b"\n")[:60]]
    named = sum(1 for line in lines if line.startswith(_HEADERS))
    return ["mail"] if named >= 2 and b"\x00" not in head[:1024] else []


def _incidents(db: OrmSession, row: Artifact, wanted: str, one: bool) -> list[Incident]:
    """The incidents what is made goes to: the one that is named, or those the file is in."""
    if wanted:
        incident = lock_incident(db, wanted)
        if incident is None:
            raise ConvertError("The incident does not exist", 404)
        return [incident]
    linked = db.scalars(select(ArtifactLink.incident_id).where(ArtifactLink.artifact_id == row.id)).all()
    if one and len(linked) != 1:
        return []  # a capture belongs to one incident: with several, a person says which
    return [incident for incident in (lock_incident(db, item) for item in sorted(linked)) if incident is not None]


def _file(db: OrmSession, row: Artifact) -> bytes:
    if row.kind != "file":
        raise ConvertError("Only a file is analysed as an e-mail or as a capture")
    try:
        return read_sample(row.ref)
    except (OSError, ValueError):
        raise ConvertError("The file could not be read from the store", 404) from None


def as_mail(db: OrmSession, row: Artifact, actor: str, incident_id: str = "") -> Artifact:
    """Analyse a file as an e-mail (the caller commits): the e-mail artifact, made from the file."""
    from .mail.parse import MailError
    from .routers import mails as mail_routes

    data = _file(db, row)
    if len(data) > settings.SAMPLE_MAX_MB * 1024 * 1024:
        raise ConvertError(f"The file exceeds the {settings.SAMPLE_MAX_MB} MB limit of an e-mail", 413)
    targets = _incidents(db, row, incident_id, one=False)
    try:
        mail, _ref = mail_routes.keep_mail(db, targets[0] if targets else None, data, row.name, actor)
    except MailError as error:
        raise ConvertError(f"It is not an e-mail Nik can read: {error}") from None
    for incident in targets[1:]:
        mail_routes.attach_mail(db, incident, mail, row.name, actor)
    made = db.get(Artifact, artifacts.artifact_id("mail", mail.sha256))
    artifacts.relate(db, row.id, made.id, RELATION)
    return made


def as_capture(db: OrmSession, row: Artifact, actor: str, background_tasks: Any, incident_id: str = "") -> Artifact:
    """Analyse a file as a packet capture: the capture artifact, made from the file. The analysis is
    queued on ``background_tasks``, as that of an uploaded capture is (the function commits, as an
    upload does)."""
    from .routers import network as capture_routes

    known = db.scalars(
        select(Artifact)
        .join(ArtifactRelation, ArtifactRelation.child_id == Artifact.id)
        .where(ArtifactRelation.parent_id == row.id, ArtifactRelation.relation == RELATION, Artifact.kind == "pcap")
    ).first()
    if known is not None:
        capture = db.get(NetworkCapture, known.ref)
        if capture is not None and incident_id and not capture.incident_id:
            from .network import service as captures

            targets = _incidents(db, row, incident_id, one=True)
            if targets:
                captures.attach(db, capture, targets[0])
        return known
    data = _file(db, row)
    targets = _incidents(db, row, incident_id, one=True)
    try:
        capture = capture_routes.keep_capture(
            db, targets[0] if targets else None, data, row.name, actor, background_tasks, f"file {row.ref[:12]}…"
        )
    except HTTPException as error:
        raise ConvertError(str(error.detail), error.status_code) from None
    made = db.get(Artifact, artifacts.artifact_id("pcap", capture.id))
    artifacts.relate(db, row.id, made.id, RELATION)
    db.commit()
    return made
