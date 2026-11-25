"""What can be done to many artifacts at once (``bulk.py`` runs it).

Each action is the single action of the artifact's page, called once for each
artifact: the functions the routes of ``routers/artifacts.py`` call, with
their checks and their audit entries.

**Analysing again** is for files and e-mails: the static analysis of the file
is run again, the message is analysed again, as "Re-analyse" does first. The
long work "Re-analyse" then asks of the workers for one file (the disassembly,
capa) is not asked for hundreds of files at once: it is started from the file.
A capture, a scanned address, a mailbox and the original of host evidence are skipped: visiting an address
again is seen by its site, and a capture takes its worker for minutes.

Deleting the original of host evidence is refused while an incident holds it as evidence.

Downloading many together is not a job: it is the export of the artifacts
(``POST /api/artifacts/export``), one archive made by the API with the files
inside an encrypted archive, as a single download gives them.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import artifacts, bulk
from .bulk_incidents import clean_tags, describe_tags
from .core import audit
from .core.models import Artifact, ArtifactLink, Incident, Mail, Sample
from .core.permissions import WRITE
from .core.security import Principal

REANALYSED = ("file", "mail")


def _resolve(db: OrmSession, caller: Principal, ids: list[str] | None, query: dict[str, Any] | None):
    from .routers.artifacts import matching

    wanted = select(Artifact.id, Artifact.name, Artifact.ref)
    if ids is not None:
        found = {}
        for start in range(0, len(ids), 500):
            for row in db.execute(wanted.where(Artifact.id.in_(ids[start : start + 500]))):
                found[row.id] = row
        return [(item, _called(found.get(item))) for item in ids]
    query = query or {}
    linked = query.get("linked")
    conditions = matching(
        db,
        caller,
        str(query.get("q") or ""),
        str(query.get("tag") or ""),
        bool(query.get("mine")),
        linked if isinstance(linked, bool) else None,
    )
    kind = str(query.get("kind") or "")
    if kind:
        if kind not in artifacts.KINDS:
            raise bulk.BulkError("The kind is one of: " + ", ".join(artifacts.KINDS), 422)
        conditions.append(Artifact.kind == kind)
    rows = db.execute(wanted.where(*conditions).order_by(Artifact.created_at.desc())).all()
    return [(row.id, _called(row)) for row in rows]


def _called(row: Any) -> str:
    return "" if row is None else str(row.name or row.ref[:16])


def _row(db: OrmSession, ref: str) -> Artifact:
    row = db.get(Artifact, ref) if artifacts.is_artifact_id(ref) else None
    if row is None:
        raise bulk.Refused("There is no such artifact any more")
    return row


def _incident(db: OrmSession, params: dict[str, Any]) -> dict[str, Any]:
    row = db.get(Incident, str(params.get("incident") or ""))
    if row is None:
        raise bulk.BulkError("There is no such incident", 404)
    return {"incident": row.id, "name": row.name}


def _artifact_tag(raw: Any) -> str:
    value = str(raw or "").strip().lower().lstrip("#")
    return value if artifacts.TAG_RE.fullmatch(value) else ""


def _tags(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    from .routers.artifacts import tag

    row = _row(db, ref)
    held = list(row.tags or [])
    wanted = [item for item in held if item not in params["remove"]]
    wanted += [item for item in params["add"] if item not in wanted]
    if wanted == held:
        raise bulk.Skipped("It was so already")
    if len(wanted) > artifacts.TAGS_MAX:
        raise bulk.Refused(f"An artifact holds {artifacts.TAGS_MAX} tags at most")
    tag(db, row, wanted, caller)
    return ""


def _reanalyse(db: OrmSession, ref: str, _params: dict[str, Any], caller: Principal) -> str:
    row = _row(db, ref)
    if row.kind == "file":
        from .routers import samples

        sample = db.get(Sample, row.ref)
        if sample is None:
            raise bulk.Refused("Its file is not in the store any more")
        samples.analyse_again(db, sample)
        audit.record(db, caller.actor, "sample.reanalyse", f"Re-analysed sample {row.ref[:12]}… ({sample.type_label})")
        return ""
    if row.kind == "mail":
        from .mail.parse import MailError
        from .routers import mails

        mail = db.get(Mail, row.ref)
        if mail is None:
            raise bulk.Refused("Its message is not in the store any more")
        try:
            result = mails._analyse(db, mails.read_mail(row.ref))
        except (OSError, MailError):
            raise bulk.Refused("The stored message cannot be analysed") from None
        mails.analysed_again(db, mail, result)
        audit.record(db, caller.actor, "mail.reanalyse", f"Re-analysed e-mail {row.ref[:12]}… ({mail.verdict})")
        return ""
    raise bulk.Skipped("Only files and e-mails are analysed again in bulk")


def _plan_reanalyse(db: OrmSession, refs: list[str], _params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    count = 0
    for start in range(0, len(refs), 500):
        kinds = db.scalars(select(Artifact.kind).where(Artifact.id.in_(refs[start : start + 500])))
        count += sum(1 for kind in kinds if kind in REANALYSED)
    return {
        "applies": count,
        "notes": ["Files and e-mails are analysed again; the disassembly and capa of a file are started from the file"],
    }


def _link(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    from .routers.artifacts import link_to

    row = _row(db, ref)
    if row.kind == "mailbox":
        raise bulk.Skipped("A mailbox is not linked to an incident")
    if row.kind == "hostfile":
        raise bulk.Skipped("Host evidence is given to an incident when it is imported there, not linked")
    incident = db.get(Incident, params["incident"])
    if incident is None:
        raise bulk.Refused("The incident is not there any more")
    if db.get(ArtifactLink, (row.id, incident.id)) is not None:
        raise bulk.Skipped("It was in the incident already")
    link_to(db, row, incident, caller)
    return ""


def _unlink(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    from .routers.artifacts import unlink_from

    row = _row(db, ref)
    incident = db.get(Incident, params["incident"])
    if incident is None:
        raise bulk.Refused("The incident is not there any more")
    if row.kind == "hostfile":
        raise bulk.Skipped("Host evidence is taken out of an incident from its evidence, not unlinked")
    if row.kind == "mailbox" or db.get(ArtifactLink, (row.id, incident.id)) is None:
        raise bulk.Skipped("It is not in the incident")
    unlink_from(db, row, incident, caller)
    return ""


def _plan_unlink(db: OrmSession, refs: list[str], params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    count = 0
    for start in range(0, len(refs), 500):
        count += len(
            db.scalars(
                select(ArtifactLink.artifact_id).where(
                    ArtifactLink.incident_id == params["incident"],
                    ArtifactLink.artifact_id.in_(refs[start : start + 500]),
                )
            ).all()
        )
    return {"applies": count}


def _clean_expiry(_db: OrmSession, params: dict[str, Any], _caller: Principal) -> dict[str, Any]:
    from . import artifact_expiry

    day = params.get("expiresAt")
    if day in (None, ""):
        return {"expiresAt": None}
    try:
        return {"expiresAt": artifact_expiry.clean_date(day)}
    except artifact_expiry.ExpiryError as error:
        raise bulk.BulkError(error.message, 400) from None


def _expiry(db: OrmSession, ref: str, params: dict[str, Any], caller: Principal) -> str:
    from .routers.artifacts import expire

    row = _row(db, ref)
    if (row.expires_at or None) == params["expiresAt"]:
        raise bulk.Skipped("It was so already")
    expire(db, row, params["expiresAt"], caller)
    return ""


def _delete(db: OrmSession, ref: str, _params: dict[str, Any], caller: Principal) -> str:
    from .routers.artifacts import remove

    row = db.get(Artifact, ref) if artifacts.is_artifact_id(ref) else None
    if row is None:
        raise bulk.Skipped("It was deleted already")
    remove(db, row, caller)
    return ""


LIST = bulk.register(bulk.Listing("artifacts", ("artifact", "artifacts"), _resolve))
LIST.add(
    bulk.Action(
        "tags",
        "Change the tags",
        WRITE,
        apply=_tags,
        clean=lambda _db, params, _caller: clean_tags(params, _artifact_tag),
        describe=describe_tags,
    )
)
LIST.add(bulk.Action("reanalyse", "Analyse again", WRITE, apply=_reanalyse, plan=_plan_reanalyse, events=True))
LIST.add(
    bulk.Action(
        "link",
        "Link to an incident",
        WRITE,
        apply=_link,
        clean=lambda db, params, _caller: _incident(db, params),
        describe=lambda params: f'Link to the incident "{params.get("name", "")}"',
        events=True,
    )
)
LIST.add(
    bulk.Action(
        "unlink",
        "Take out of an incident",
        WRITE,
        apply=_unlink,
        clean=lambda db, params, _caller: _incident(db, params),
        describe=lambda params: f'Take out of the incident "{params.get("name", "")}"',
        plan=_plan_unlink,
        events=True,
    )
)
LIST.add(
    bulk.Action(
        "expiry",
        "Set the expiry",
        WRITE,
        apply=_expiry,
        clean=_clean_expiry,
        describe=lambda params: (
            f"Expire on {params['expiresAt']}" if params.get("expiresAt") else "Take the expiry away"
        ),
    )
)
LIST.add(bulk.Action("delete", "Delete", WRITE, apply=_delete, destructive=True, verb="delete"))
