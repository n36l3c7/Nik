"""What the Mail connector keeps in Nik's store.

Two things come out of a mailbox and stay:

- **The attachments of a message**, when a playbook asks for them
  (``get-attachments``). Each becomes a file artifact, analysed as an uploaded
  file is, in the incident the run works on when there is one. When the
  message itself is an e-mail artifact already (the listener kept it), the
  files are recorded as taken out of it.
- **The message the listener made an incident from**, as it was received. It
  becomes an e-mail artifact of that incident and gets the analysis an
  uploaded ``.eml`` gets, so that the Evidence tab shows what the incident is
  about and not only the text the mapper copied.

The store holds live malware. A file is written under its SHA-256, read as
bytes by the analysis, and never opened by the program it is meant for; what
is over the limit of an upload is not kept, and says so.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as OrmSession

from .. import artifacts
from ..core import audit
from ..core.config import settings
from ..core.locking import lock_incident
from ..core.models import Artifact, Incident
from ..core.permissions import SYSTEM_USER
from . import triggers
from .actions import ActionError, Call


def limit() -> int:
    """The size above which nothing is kept: the one of an upload."""
    return settings.SAMPLE_MAX_MB * 1024 * 1024


def keep_attachments(call: Call, found: list[dict[str, Any]], message: dict[str, Any], wanted: Any) -> list[dict]:
    """Keep the attachments of a message as file artifacts, for a step of a run. ``found`` is what the
    runtime read (``name``, ``data``, ``readable``), ``message`` says which message they come from, and
    ``wanted`` is the incident the node names (the one of the run when it names none; none at all, and
    the files are kept on their own). Gives, for each, ``{artifact, linked, note}``: one that could not
    be kept has no artifact and a note that says why."""
    from ..routers import samples as sample_routes

    db = call.db
    incident_id = str(wanted or call.run.incident_id or "")
    incident = lock_incident(db, incident_id) if incident_id else None
    if incident_id and incident is None:
        raise ActionError("The incident does not exist", retry=False)
    # Taken out of an e-mail Nik holds: the page of each shows the other.
    parent = artifacts.artifact_id("mail", str(message.get("sha256") or ""))
    if db.get(Artifact, parent) is None:
        parent = ""
    subject = str(message.get("subject") or "")
    origin = f"e-mail “{subject[:80]}”" if subject else "an e-mail"
    kept = []
    for item in found:
        data = item.get("data") or b""
        if not item.get("readable"):
            note = "It could not be read"
        elif not data:
            note = "It is empty"
        elif len(data) > limit():
            note = f"It exceeds the {settings.SAMPLE_MAX_MB} MB limit of a sample"
        else:
            row, _ref = sample_routes.keep_sample(
                db,
                incident,
                data,
                str(item.get("name") or ""),
                SYSTEM_USER,
                origin,
                parent=(parent, "attachment") if parent else None,
            )
            kept.append(
                {"artifact": artifacts.artifact_id("file", row.sha256), "linked": incident is not None, "note": ""}
            )
            continue
        kept.append({"artifact": "", "linked": False, "note": note})
    stored = sum(1 for item in kept if item["artifact"])
    if stored:
        playbook = (call.run.trigger or {}).get("playbook", "")
        who = f", approved by {call.approved_by}" if call.approved_by else ""
        audit.record(
            db,
            SYSTEM_USER,
            "mail.attachments.keep",
            f"Kept {stored} attachment(s) of the message {message.get('uid')} of {message.get('folder')}"
            f' (playbook "{playbook}", run {call.run.id}{who})',
            incident,
        )
        if incident is not None:
            triggers.incident_changed(db, incident, "incident.updated", ["data"])
    return kept


def keep_message(db: OrmSession, incident: Incident, raw: bytes, name: str, actor: str) -> str:
    """Keep a message the listener read as an e-mail artifact of the incident it made (the caller
    commits). A message Nik holds already is not analysed again: the incident references it.
    Gives what to say when it was not kept, or nothing."""
    from ..mail.parse import MailError
    from ..routers import mails as mail_routes

    if not raw:
        return "The message came empty: it was not kept as evidence"
    if len(raw) > limit():
        return f"The message exceeds the {settings.SAMPLE_MAX_MB} MB limit: it was not kept as evidence"
    try:
        mail_routes.keep_mail(db, incident, raw, name, actor)
    except MailError as error:
        return f"The message was not kept as evidence: {error}"
    return ""
