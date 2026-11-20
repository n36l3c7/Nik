"""The "Files" nodes: what a playbook does with files and artifacts.

Whatever an analyst does with a file on the screens, a node does here: add a
file to an incident, link and unlink an artifact, list the artifacts of an
incident, read one, start its analysis again and read what the analysis
found, tag it, give it a day to expire on, and put host evidence (an event
log, a browser history, a shell history, an endpoint collection) in an
incident.

Three things hold for all of them:

- **Nothing is run or opened.** An analysis a node starts is one Nik already
  makes of an artifact: the static analysis, the disassembly and capa on
  their workers, the analysis of an e-mail, of a packet capture. A file a
  node keeps is stored as it came, under its SHA-256, like an upload.
- **A file is passed by reference.** What a node gives is the artifact (its
  id, name, type, size, SHA-256), never its bytes: nothing of a sample enters
  the stored state of a run. What an analysis found is given in a bounded
  form: lists are cut, long texts too.
- **The API process does what the worker cannot.** The worker that runs
  playbooks reads the store read-only and reaches no analysis worker. Keeping
  a file and starting an analysis are written down as a job
  (``artifact_jobs.py``); the node gives its step back and looks again, as
  ``nik.scan-url`` does for a scan.

The values they return carry classes (payloads.py): a file name is a file
name, a subject a subject, a sender an e-mail address. The artifact made from
a content carries the classes the content came in with, so a later node that
sends that file out is judged by where its content came from as well as by
what it is (an attachment, a sample).
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import hashlib
import json
from datetime import timedelta
from typing import Any

from sqlalchemy import select

from .. import artifact_expiry, artifact_jobs, artifacts
from ..core import audit
from ..core.config import settings
from ..core.models import (
    Artifact,
    ArtifactJob,
    ArtifactLink,
    ArtifactRelation,
    Incident,
    Mail,
    NetworkCapture,
    Sample,
    SampleCapa,
    SampleCode,
    UrlScan,
)
from ..malware.samples import is_sha256
from . import guard, payloads, triggers
from .actions import ActionError, Call, Result, action
from .nik_actions import ACTOR, INCIDENT_ARG, _incident, _scan_output, _truthy, _wanted, signature

GROUP = "Files"
JOB_EVERY = 2  # seconds between two looks at a job the API process has not finished
STORE_WAIT = 300  # how long a file may take to be kept before the step fails
WAIT_MINUTES = 15  # how long an analysis is waited for when the node does not say
LIST_MAX = 200  # artifacts a node lists at most
FOUND_MAX = 100  # indicators, rules, hosts, capabilities an analysis gives at most
TEXT_MAX = 500
WORKERS_PAGE = "Settings → System → Workers"

ARTIFACT_ARG = {
    "name": "artifact",
    "type": "text",
    "required": True,
    "description": "The artifact's id (file-…, mail-…, pcap-…, url-…), the SHA-256 of a file, or what a node gave",
}

# An artifact as these nodes give it: each key with its type and what it is.
_ARTIFACT = (
    ("artifact", "text", "Its id: what an argument called artifact takes"),
    ("kind", "text", "file, mail, pcap, url or mailbox"),
    ("name", "text", "Its name: the file name, the subject of an e-mail, the address"),
    ("type", "text", "What the file is, as Nik detected it; e-mail, capture or address for the others"),
    ("size", "number", "Its size in bytes"),
    ("sha256", "text", "Its SHA-256 (empty for an address)"),
    ("verdict", "text", "The verdict of its analysis, when it has one"),
    ("score", "number", "The score of its analysis, when it has one"),
    ("tags", "list", "Its tags"),
    ("page", "text", "Its address in Nik"),
)
ARTIFACT_OUT = [{"name": name, "type": kind, "description": said} for name, kind, said in _ARTIFACT]
_TYPES = {"mail": "e-mail", "pcap": "capture", "url": "address", "mailbox": "mailbox"}


def _shape(fields: tuple, prefix: str = "") -> list[dict[str, str]]:
    return [{"name": f"{prefix}{name}", "type": kind, "description": said} for name, kind, said in fields]


def _artifact_id(given: Any) -> str:
    """The id an argument names: an id, the SHA-256 of a file, or the artifact another node gave
    (its ``artifact`` is read, so ``{{ add_file }}`` works as well as ``{{ add_file.artifact }}``)."""
    if isinstance(given, dict):
        given = given.get("artifact") or given.get("artifact_id") or given.get("id")
    text = str(given or "").strip()
    return f"file-{text.lower()}" if is_sha256(text.lower()) else text


def _artifact(call: Call) -> Artifact:
    wanted = _artifact_id(call.args.get("artifact"))
    row = call.db.get(Artifact, wanted) if artifacts.is_artifact_id(wanted) else None
    if row is None:
        raise ActionError("The artifact does not exist" if wanted else "No artifact was given", retry=False)
    return row


def _sha256_of(db, row: Artifact) -> str:
    if row.kind in ("file", "mail"):
        return row.ref
    if row.kind == "pcap":
        capture = db.get(NetworkCapture, row.ref)
        return (capture.sha256 if capture is not None else "") or ""
    return ""


def _described(db, row: Artifact) -> dict[str, Any]:
    return {
        "artifact": row.id,
        "kind": row.kind,
        "name": row.name or row.ref[:16],
        "type": _TYPES.get(row.kind) or row.detail or "",
        "size": int(row.size or 0),
        "sha256": _sha256_of(db, row),
        "verdict": row.verdict or "",
        "score": row.score,
        "tags": list(row.tags or []),
        "page": f"/artifact/{row.id}",
    }


def _nothing(artifact: str = "") -> dict[str, Any]:
    """An artifact that is not there, with every key an artifact has."""
    kind = artifact.split("-", 1)[0] if artifacts.is_artifact_id(artifact) else ""
    sha256 = artifact.split("-", 1)[1] if kind in ("file", "mail") else ""
    return {
        "artifact": artifact,
        "kind": kind,
        "name": "",
        "type": _TYPES.get(kind, ""),
        "size": 0,
        "sha256": sha256,
        "verdict": "",
        "score": None,
        "tags": [],
        "page": f"/artifact/{artifact}" if kind else "",
    }


def _name_classes(db, row: Artifact) -> list[str]:
    """What the name of an artifact is: a file name, the subject of an e-mail, or an address, which
    has the classes Nik holds of it as an indicator."""
    if row.kind == "mail":
        return ["subject"]
    if row.kind == "url":
        scan = db.get(UrlScan, row.ref)
        return payloads.indicator_data(db, "url", scan.url)[1] if scan is not None else []
    return ["attachment_name"]


def _classes(names: list[str], prefix: str = "") -> dict[str, list[str]]:
    said = {
        "artifact": ["nik_id"],
        "page": ["nik_id"],
        "sha256": ["hash"],
        "name": names,
        "kind": ["verdict"],
        "type": ["verdict"],
        "size": ["verdict"],
        "verdict": ["verdict"],
        "score": ["verdict"],
    }
    return {f"{prefix}{key}": held for key, held in said.items()}


def _depth() -> int:
    cause = triggers.current_run.get()
    return cause[1] if cause else 0


def _playbook(call: Call) -> str:
    return str((call.run.trigger or {}).get("playbook", ""))


# --------------------------------------------------------------------------- #
# Adding a file                                                               #
# --------------------------------------------------------------------------- #
def _content(call: Call, limit_mb: int) -> bytes:
    """The bytes a node was given as a content: a text as UTF-8, or base64. What a step gave as
    JSON (the answer of a request) is written as JSON."""
    raw = call.args.get("content")
    if isinstance(raw, (dict, list)):
        text = json.dumps(raw, ensure_ascii=False, indent=2)
    else:
        text = "" if raw is None else str(raw)
    if str(call.args.get("encoding") or "text") == "base64":
        try:
            data = base64.b64decode("".join(text.split()), validate=True)
        except (binascii.Error, ValueError):
            raise ActionError("The content is not base64", retry=False) from None
    else:
        data = text.encode("utf-8")
    if not data:
        raise ActionError("The file is empty", retry=False)
    if len(data) > limit_mb * 1024 * 1024:
        raise ActionError(f"The file is larger than the {limit_mb} MB limit of an upload: it was not kept", retry=False)
    return data


def _held(call: Call, *names: str) -> list[str]:
    """The classes the named arguments came in with that do not leave freely: what is made from them
    carries these."""
    found: set[str] = set()
    for name, held in (call.arg_classes or {}).items():
        if name.split(".")[0] in names:
            found.update(held)
    return sorted(found - guard.ALWAYS)


def _link(call: Call, row: Artifact, incident: Incident) -> None:
    """Put an artifact in an incident, as "Link to incident" does."""
    from .. import urlscan
    from ..network import service as captures
    from ..routers import mails as mail_routes
    from ..routers import samples as sample_routes

    db = call.db
    if row.kind == "file":
        sample_routes.attach_sample(db, incident, db.get(Sample, row.ref), row.name, ACTOR)
    elif row.kind == "mail":
        mail_routes.attach_mail(db, incident, db.get(Mail, row.ref), row.name, ACTOR)
    elif row.kind == "url":
        urlscan.attach(db, incident, db.get(UrlScan, row.ref), ACTOR)
    elif row.kind == "pcap":
        capture = db.get(NetworkCapture, row.ref)
        if capture.incident_id and capture.incident_id != incident.id:
            raise ActionError("The capture is in another incident: it is taken out of that one first", retry=False)
        if capture.status == "live":
            raise ActionError("The browser session is still open: its capture is linked when it is closed", retry=False)
        captures.attach(db, capture, incident)
    else:
        raise ActionError("A mailbox is not linked: its messages are, from its page", retry=False)
    audit.record(
        db,
        ACTOR,
        "artifact.link",
        f"Linked {row.kind} {row.name or row.ref[:12]} to the incident" + signature(call),
        incident,
    )
    triggers.incident_changed(db, incident, "incident.updated", ["data"])


def _target(call: Call) -> str:
    """The incident a file goes to: the one the node names, the one of the run, or none (the file
    is then kept on its own). One that is named and does not exist fails the step before anything."""
    wanted = _wanted(call, call.args.get("incident"))
    if wanted and call.db.get(Incident, wanted) is None:
        raise ActionError("The incident does not exist", retry=False)
    return wanted


def _added(call: Call, row: Artifact, *, linked: bool, known: bool, held: list[str]) -> Result:
    output = {**_described(call.db, row), "linked": linked, "known": known}
    if call.args.get("type") and row.kind == "file":
        output["type"] = str(call.args["type"])[:200]
    names = sorted({*_name_classes(call.db, row), *_held(call, "name")})
    classes = _classes(names)
    for key in ("artifact", "sha256", "page"):
        classes[key] = sorted({*classes[key], *held})
    return Result(output=output, classes=classes, log=f"{output['name']}: {output['artifact']}")


def _wait_for_file(call: Call, state: dict) -> Result:
    job = call.db.get(ArtifactJob, str(state.get("job") or ""))
    if job is None:
        raise ActionError("What was asked of the server about this file is no longer there", retry=False)
    if job.status == "error":
        raise ActionError(f"The file was not kept: {job.error}", retry=False)
    if job.status != "done":
        if call.now < float(state.get("until") or 0):
            return Result(again_at=call.now + JOB_EVERY, state=state, log="Waiting for the server to keep the file")
        raise ActionError(
            f"The file was not kept in {STORE_WAIT // 60} minutes: see whether the server answers ({WORKERS_PAGE})",
            retry=False,
        )
    result = job.result or {}
    row = call.db.get(Artifact, artifacts.artifact_id(str(result.get("kind")), str(result.get("ref"))))
    if row is None:
        raise ActionError("The file was kept and deleted before the step read it", retry=False)
    said = f"Added the {'e-mail' if row.kind == 'mail' else 'file'} {row.name or row.ref[:12]} ({row.ref[:12]}…)"
    incident = call.db.get(Incident, str(state.get("incident") or "")) if state.get("incident") else None
    audit.record(call.db, ACTOR, "artifact.add", said + signature(call), incident)
    return _added(
        call, row, linked=bool(result.get("linked")), known=bool(result.get("known")), held=_held(call, "content")
    )


def _attachment_of(call: Call, row: Artifact, wanted: str) -> dict[str, Any]:
    """The attachment a node names, as the analysis of the e-mail describes it."""
    mail = call.db.get(Mail, row.ref)
    listed = (mail.analysis or {}).get("attachments") if mail is not None else None
    found = artifact_jobs.find_attachment(listed or [], wanted)
    if found is None:
        raise ActionError("The e-mail has no attachment with this name", retry=False)
    item = found[1]
    size = int(item.get("size") or 0)
    if not size:
        raise ActionError("The attachment is empty", retry=False)
    if size > settings.SAMPLE_MAX_MB * 1024 * 1024:
        raise ActionError(
            f"The attachment is larger than the {settings.SAMPLE_MAX_MB} MB limit of an upload: it was not kept",
            retry=False,
        )
    return {
        "place": found[0],
        "name": str(item.get("name") or ""),
        "size": size,
        "sha256": str((item.get("hashes") or {}).get("sha256") or ""),
        "type": str((item.get("type") or {}).get("label") or ""),
    }


@action(
    "nik.add-file",
    group=GROUP,
    name="Add a file",
    description=(
        "Put a file in an incident, as Add a file… does. A playbook has no browser to upload from, so the "
        "file is one of three things a step before gave: a file Nik holds already (what a command of a "
        "connector kept, what get-attachments kept), an attachment of an e-mail Nik holds, or a content "
        "(a report, a JSON answer, a CSV) as text or base64 with a file name. A content becomes a file "
        "artifact, stored as it came and analysed as an upload is; nothing is run or opened. Without an "
        "incident the file is kept on its own."
    ),
    arguments=[
        INCIDENT_ARG,
        {
            "name": "artifact",
            "type": "text",
            "description": "A file Nik holds (file-…, or what a node gave), or the e-mail (mail-…) an attachment is in",
        },
        {
            "name": "attachment",
            "type": "text",
            "description": "With an e-mail: the attachment to take out, by its file name or its place (0, 1, 2.0)",
        },
        {"name": "content", "type": "text", "description": "The content of a new file, when no artifact is given"},
        {
            "name": "encoding",
            "type": "choice",
            "choices": ["text", "base64"],
            "default": "text",
            "description": "How the content is written: as text (kept as UTF-8) or as base64",
        },
        {"name": "name", "type": "text", "description": "The file name of the content"},
        {
            "name": "type",
            "type": "text",
            "description": "What the content is, for the steps after (text/csv…); what Nik detects when left empty",
        },
        {
            "name": "as",
            "type": "choice",
            "choices": ["file", "mail"],
            "default": "file",
            "description": "mail: the content is a message (.eml, .msg) and is analysed as an e-mail",
        },
    ],
    outputs=[
        *ARTIFACT_OUT,
        {"name": "linked", "type": "bool", "description": "It is in an incident"},
        {"name": "known", "type": "bool", "description": "Nik held this very file before"},
    ],
    timeout=120,
)
def add_file(call: Call) -> Result:
    state = call.state or {}
    if state:
        return _wait_for_file(call, state)
    db = call.db
    given = _artifact_id(call.args.get("artifact"))
    has_content = call.args.get("content") not in (None, "")
    if given and has_content:
        raise ActionError("Give an artifact or a content, not both", retry=False)
    if not given and not has_content:
        raise ActionError("Nothing to add: give an artifact or a content", retry=False)
    wanted = _target(call)
    playbook = _playbook(call)

    if given:
        attachment = str(call.args.get("attachment") or "").strip()
        row = db.get(Artifact, given) if artifacts.is_artifact_id(given) else None
        if row is None:
            if call.dry_run and artifacts.is_artifact_id(given):
                # What a dry run did not keep is not there: the step shows what it would have done.
                would = {"would": "add the file", "artifact": given, "incident": wanted}
                return Result(output={**_nothing(given), "linked": False, "known": False}, request=would)
            raise ActionError("The artifact does not exist", retry=False)
        if not attachment:
            if call.dry_run:
                would = {"would": "link the artifact", "artifact": row.id, "incident": wanted}
                result = _added(call, row, linked=False, known=True, held=[])
                result.request = would
                return result
            if wanted:
                _link(call, row, _incident(call, wanted))
            return _added(call, row, linked=bool(wanted), known=True, held=[])
        if row.kind != "mail":
            raise ActionError("Only an e-mail has attachments", retry=False)
        found = _attachment_of(call, row, attachment)
        if call.dry_run:
            kept = _nothing(f"file-{found['sha256']}" if found["sha256"] else "")
            kept.update(name=found["name"], size=found["size"], type=found["type"])
            would = {"would": "add the attachment", "name": found["name"][:200], "incident": wanted}
            return Result(
                output={**kept, "linked": False, "known": False}, classes=_classes(["attachment_name"]), request=would
            )
        params = {"mail": row.ref, "attachment": found["place"], "incident": wanted}
        job = artifact_jobs.ask(db, "attachment", params, ACTOR, call.run.id, _depth(), call.now)
        return Result(
            again_at=call.now + JOB_EVERY,
            state={"job": job.id, "until": call.now + STORE_WAIT, "incident": wanted},
            log=f"Taking {found['name']} out of the e-mail",
        )

    name = str(call.args.get("name") or "").strip()[:255]
    if not name:
        raise ActionError("A content needs a file name", retry=False)
    data = _content(call, settings.SAMPLE_MAX_MB)
    kind = "mail" if str(call.args.get("as") or "file") == "mail" else "file"
    if call.dry_run:
        kept = _nothing(f"{kind}-{hashlib.sha256(data).hexdigest()}")
        kept.update(name=name, size=len(data), type=str(call.args.get("type") or "")[:200] or kept["type"])
        would = {"would": f"add the {'e-mail' if kind == 'mail' else 'file'}", "name": name, "bytes": len(data)}
        names = sorted({"attachment_name", *_held(call, "name")})
        return Result(output={**kept, "linked": False, "known": False}, classes=_classes(names), request=would)
    params = {"as": kind, "name": name, "incident": wanted, "origin": f'playbook "{playbook}"'}
    job = artifact_jobs.ask(db, "store", params, ACTOR, call.run.id, _depth(), call.now, data)
    return Result(
        again_at=call.now + JOB_EVERY,
        state={"job": job.id, "until": call.now + STORE_WAIT, "incident": wanted},
        log=f"Keeping {name} ({len(data)} bytes)",
    )


# --------------------------------------------------------------------------- #
# Host evidence                                                               #
# --------------------------------------------------------------------------- #
EVIDENCE = ("eventlogs", "browser", "commands", "endpoint")


@action(
    "nik.add-evidence",
    group=GROUP,
    name="Add host evidence",
    description=(
        "Put what was collected on a host in an incident, as Add a file… does for these four: a Windows "
        "event log (.evtx), a browser's history or downloads, a shell history, an endpoint collection. The "
        "file is a file artifact Nik holds or a content a step gave; it is parsed as an upload is and what "
        "it holds goes to the tab of its kind. The file itself is not kept."
    ),
    arguments=[
        INCIDENT_ARG,
        {
            "name": "kind",
            "type": "choice",
            "choices": list(EVIDENCE),
            "required": True,
            "description": "Which tab it goes to: eventlogs, browser, commands or endpoint",
        },
        {"name": "artifact", "type": "text", "description": "A file Nik holds (file-…, or what a node gave)"},
        {"name": "content", "type": "text", "description": "The content of the file, when no artifact is given"},
        {
            "name": "encoding",
            "type": "choice",
            "choices": ["text", "base64"],
            "default": "text",
            "description": "How the content is written: as text or as base64",
        },
        {"name": "name", "type": "text", "description": "The file name, as the tab shows it"},
        {"name": "browser", "type": "text", "description": "browser: which one (chrome, edge, firefox…)"},
        {"name": "profile", "type": "text", "description": "browser: the profile, made if missing (Default)"},
        {"name": "source", "type": "text", "description": "browser and endpoint: the source (history, cron…)"},
        {"name": "shell", "type": "text", "description": "commands: which shell (bash, powershell…)"},
        {"name": "category", "type": "text", "description": "endpoint: the category (persistence…)"},
    ],
    outputs=[
        {"name": "rows", "type": "number", "description": "How many rows were read"},
        {"name": "format", "type": "text", "description": "What the file was read as"},
        {"name": "target", "type": "text", "description": "Where it went: eventlogs/Security, commands/bash…"},
    ],
    timeout=300,
)
def add_evidence(call: Call) -> Result:
    import copy

    from sqlalchemy.orm.attributes import flag_modified

    from ..core.security import now_iso
    from ..iocs import reindex_incident
    from ..malware.samples import read_sample
    from ..parsing.registry import apply_upload
    from ..routers.incidents import _UPLOAD_ACTIONS, _sync_columns

    tab = str(call.args.get("kind") or "")
    if tab not in EVIDENCE:
        raise ActionError("The kind is eventlogs, browser, commands or endpoint", retry=False)
    given = _artifact_id(call.args.get("artifact"))
    has_content = call.args.get("content") not in (None, "")
    if bool(given) == has_content:
        raise ActionError("Give an artifact or a content, one of the two", retry=False)
    wanted = _wanted(call, call.args.get("incident"))
    if not wanted:
        raise ActionError("No incident was given", retry=False)
    limit = settings.ARTIFACT_MAX_MB * 1024 * 1024
    name = str(call.args.get("name") or "").strip()[:255]
    if given:
        row = call.db.get(Artifact, given) if artifacts.is_artifact_id(given) else None
        if row is None and call.dry_run and given.startswith("file-") and artifacts.is_artifact_id(given):
            would = {"would": f"add {tab} evidence", "artifact": given}
            return Result(output={"rows": 0, "format": "", "target": ""}, request=would)
        if row is None or row.kind != "file":
            raise ActionError("The evidence is read from a file artifact (file-…): this is not one", retry=False)
        if int(row.size or 0) > limit:
            raise ActionError(
                f"The file is larger than the {settings.ARTIFACT_MAX_MB} MB limit of an upload", retry=False
            )
        try:
            data = read_sample(row.ref)
        except (OSError, ValueError):
            raise ActionError("The file could not be read from the store", retry=False) from None
        name = name or row.name or row.ref
    else:
        data = _content(call, settings.ARTIFACT_MAX_MB)
        name = name or "upload"
    routing = ("browser", "profile", "source", "shell", "category")
    params = {key: (str(call.args.get(key)).strip() if call.args.get(key) else None) for key in routing}
    # A dry run reads the incident and changes nothing, so it does not lock it.
    incident = call.db.get(Incident, wanted) if call.dry_run else _incident(call, wanted)
    if incident is None:
        raise ActionError("The incident does not exist", retry=False)
    # The parsers write into the document they are given: a dry run gives them a copy.
    doc = copy.deepcopy(incident.doc or {}) if call.dry_run else dict(incident.doc or {})
    try:
        summary = apply_upload(doc, tab, params, data, name)
    except ValueError as error:
        raise ActionError(str(error), retry=False) from None
    output = {
        "rows": int(summary.get("rows") or 0),
        "format": str(summary.get("format") or ""),
        "target": str(summary.get("target") or ""),
    }
    classes = {"rows": ["verdict"], "format": ["verdict"]}
    if call.dry_run:
        would = {"would": f"add {tab} evidence", "name": name[:200], "rows": output["rows"]}
        return Result(output=output, classes=classes, request=would)
    doc["updatedAt"] = now_iso()
    incident.doc = doc
    flag_modified(incident, "doc")
    _sync_columns(incident)
    reindex_incident(call.db, incident)
    audit.record(
        call.db,
        ACTOR,
        _UPLOAD_ACTIONS.get(tab, "upload"),
        f"Uploaded {name} → {output['target']} ({output['rows']} rows)" + signature(call),
        incident,
    )
    triggers.incident_changed(call.db, incident, "incident.updated", ["data"])
    return Result(output=output, classes=classes, log=f"{output['rows']} rows → {output['target']}")


# --------------------------------------------------------------------------- #
# Linking, listing, reading                                                   #
# --------------------------------------------------------------------------- #
@action(
    "nik.link-artifact",
    group=GROUP,
    name="Link an artifact",
    description=(
        "Put an analysed file, e-mail, capture or address in an incident, as Link to incident does. A "
        "capture belongs to one incident at most."
    ),
    arguments=[ARTIFACT_ARG, INCIDENT_ARG],
    outputs=[{"name": "linked", "type": "bool", "description": "It is in the incident"}],
)
def link_artifact(call: Call) -> Result:
    row = _artifact(call)
    if row.kind not in ("file", "mail", "url", "pcap"):
        raise ActionError("Only a file, an e-mail, a capture or an address can be linked by a playbook", retry=False)
    if call.dry_run:
        return Result(output={"linked": False}, request={"would": "link the artifact", "artifact": row.id})
    _link(call, row, _incident(call, call.args.get("incident")))
    return Result(output={"linked": True})


@action(
    "nik.unlink-artifact",
    group=GROUP,
    name="Take an artifact out of the incident",
    description=(
        "Remove an artifact from an incident, as Remove from this incident does. The artifact and its "
        "analysis stay in Nik: a playbook deletes no evidence."
    ),
    arguments=[ARTIFACT_ARG, INCIDENT_ARG],
    outputs=[{"name": "removed", "type": "bool", "description": "False when the incident did not hold it"}],
)
def unlink_artifact(call: Call) -> Result:
    from .. import urlscan
    from ..network import service as captures
    from ..routers import mails as mail_routes
    from ..routers import samples as sample_routes

    row = _artifact(call)
    if row.kind not in ("file", "mail", "url", "pcap"):
        raise ActionError("Only a file, an e-mail, a capture or an address is in an incident", retry=False)
    if call.dry_run:
        would = {"would": "take the artifact out of the incident", "artifact": row.id}
        return Result(output={"removed": False}, request=would)
    db = call.db
    incident = _incident(call, call.args.get("incident"))
    if row.kind == "file":
        removed = sample_routes.detach_sample(db, incident, row.ref)
    elif row.kind == "mail":
        removed = mail_routes.detach_mail(db, incident, row.ref)
    elif row.kind == "url":
        removed = urlscan.detach(db, incident, row.ref)
    else:
        capture = db.get(NetworkCapture, row.ref)
        removed = capture is not None and capture.incident_id == incident.id
        if removed and capture.status == "live":
            raise ActionError("The browser session is still open: a person closes it", retry=False)
        if removed:
            captures.detach(db, capture)
    if removed:
        said = f"Removed {row.kind} {row.name or row.ref[:12]} from the incident"
        audit.record(db, ACTOR, "artifact.unlink", said + signature(call), incident)
        triggers.incident_changed(db, incident, "incident.updated", ["data"])
    return Result(output={"removed": bool(removed)})


def _list_classes(db, rows: list[Artifact], prefix: str) -> dict[str, list[str]]:
    names: set[str] = set()
    # Beyond the first addresses, the guard's scan of what leaves decides.
    addresses = 0
    for row in rows:
        if row.kind == "url":
            addresses += 1
            if addresses > payloads.HITS_CLASSED:
                continue
        names.update(_name_classes(db, row))
    return _classes(sorted(names - {"public_indicator"}) or ["public_indicator"], prefix)


@action(
    "nik.list-artifacts",
    group=GROUP,
    name="List the artifacts of an incident",
    description=(
        "The files, e-mails, captures and addresses an incident holds, the oldest first: all of them, "
        "those of one kind, or those whose name matches. 200 at most."
    ),
    arguments=[
        INCIDENT_ARG,
        {
            "name": "kind",
            "type": "choice",
            "choices": ["", "file", "mail", "pcap", "url"],
            "default": "",
            "description": "Only this kind; all of them when left empty",
        },
        {
            "name": "name",
            "type": "text",
            "description": "Only those whose name holds this text; with * and ?, those whose name matches (*.docx)",
        },
    ],
    outputs=[
        {
            "name": "artifacts",
            "type": "list",
            "description": "Each artifact: {artifact, kind, name, type, size, sha256, verdict, score, tags, page}",
            "shape": _shape(_ARTIFACT, "[0]."),
        },
        {"name": "ids", "type": "list", "description": "Their ids, for a For each"},
        {"name": "count", "type": "number", "description": "How many are given"},
        {"name": "total", "type": "number", "description": "How many matched, when more than are given"},
    ],
)
def list_artifacts(call: Call) -> Result:
    wanted = _wanted(call, call.args.get("incident"))
    if not wanted:
        raise ActionError("No incident was given", retry=False)
    if call.db.get(Incident, wanted) is None:
        raise ActionError("The incident does not exist", retry=False)
    kind = str(call.args.get("kind") or "")
    if kind and kind not in ("file", "mail", "pcap", "url"):
        raise ActionError("The kind is file, mail, pcap or url", retry=False)
    query = (
        select(Artifact)
        .join(ArtifactLink, ArtifactLink.artifact_id == Artifact.id)
        .where(ArtifactLink.incident_id == wanted)
        .order_by(Artifact.created_at, Artifact.id)
    )
    if kind:
        query = query.where(Artifact.kind == kind)
    rows = list(call.db.scalars(query))
    pattern = str(call.args.get("name") or "").strip().lower()
    if pattern:
        if any(mark in pattern for mark in "*?"):
            rows = [row for row in rows if fnmatch.fnmatchcase((row.name or "").lower(), pattern)]
        else:
            rows = [row for row in rows if pattern in (row.name or "").lower()]
    shown = rows[:LIST_MAX]
    found = [_described(call.db, row) for row in shown]
    return Result(
        output={
            "artifacts": found,
            "ids": [item["artifact"] for item in found],
            "count": len(found),
            "total": len(rows),
        },
        classes={
            **_list_classes(call.db, shown, "artifacts."),
            "ids": ["nik_id"],
            "count": ["verdict"],
            "total": ["verdict"],
        },
    )


@action(
    "nik.get-artifact",
    group=GROUP,
    name="Get an artifact",
    description=(
        "What Nik holds of an artifact: its name, type, size, hash, verdict and tags, the incidents it is "
        "in, the day it expires on and the artifacts it was taken out of or that were taken out of it."
    ),
    arguments=[ARTIFACT_ARG],
    outputs=[
        {"name": "found", "type": "bool", "description": "Nik holds it"},
        *ARTIFACT_OUT,
        {"name": "incidents", "type": "list", "description": "The ids of the incidents it is in"},
        {"name": "expires", "type": "text", "description": "The day it is deleted on, when it has one"},
        {"name": "parents", "type": "list", "description": "The artifacts it was taken out of (ids)"},
        {"name": "children", "type": "list", "description": "The artifacts taken out of it (ids)"},
    ],
)
def get_artifact(call: Call) -> Result:
    db = call.db
    wanted = _artifact_id(call.args.get("artifact"))
    if not wanted:
        raise ActionError("No artifact was given", retry=False)
    row = db.get(Artifact, wanted) if artifacts.is_artifact_id(wanted) else None
    more = {"incidents": ["nik_id"], "parents": ["nik_id"], "children": ["nik_id"], "found": ["verdict"]}
    if row is None:
        missing = {"found": False, **_nothing(wanted), "incidents": [], "expires": "", "parents": [], "children": []}
        return Result(output=missing, classes={**_classes([]), **more})
    linked = db.scalars(select(ArtifactLink.incident_id).where(ArtifactLink.artifact_id == row.id)).all()
    parents = db.scalars(select(ArtifactRelation.parent_id).where(ArtifactRelation.child_id == row.id)).all()
    children = db.scalars(select(ArtifactRelation.child_id).where(ArtifactRelation.parent_id == row.id)).all()
    output = {
        "found": True,
        **_described(db, row),
        "incidents": sorted(linked),
        "expires": row.expires_at or "",
        "parents": sorted(parents)[:LIST_MAX],
        "children": sorted(children)[:LIST_MAX],
    }
    return Result(output=output, classes={**_classes(_name_classes(db, row)), **more, "expires": ["nik_id"]})


# --------------------------------------------------------------------------- #
# Tags and expiry                                                             #
# --------------------------------------------------------------------------- #
ARTIFACT_TAGS_ARG = {
    "name": "tags",
    "type": "list",
    "required": True,
    "description": "The tags: a list, or words separated by commas (lower case; letters, digits and . _ : -)",
}
ARTIFACT_TAGS_OUT = [
    {"name": "tags", "type": "list", "description": "The tags of the artifact afterwards"},
    {"name": "changed", "type": "bool", "description": "Whether its tags are not what they were"},
]


def _tag_artifact(call: Call, add: bool) -> Result:
    row = _artifact(call)
    given = call.args.get("tags")
    items = given if isinstance(given, (list, tuple)) else str(given or "").split(",")
    wanted = list(dict.fromkeys(str(item).strip().lower() for item in items if str(item or "").strip()))
    if not wanted:
        raise ActionError("At least one tag is needed", retry=False)
    bad = [tag for tag in wanted if not artifacts.TAG_RE.fullmatch(tag)]
    if bad and add:
        raise ActionError(
            "A tag of an artifact is lower-case letters, digits and . _ : - (40 characters at most): "
            + ", ".join(tag[:40] for tag in bad[:5]),
            retry=False,
        )
    held = list(row.tags or [])
    after = [*held, *(tag for tag in wanted if tag not in held)] if add else [tag for tag in held if tag not in wanted]
    if len(after) > artifacts.TAGS_MAX:
        raise ActionError(f"An artifact has {artifacts.TAGS_MAX} tags at most", retry=False)
    changed = after != held
    if call.dry_run:
        would = {"would": "tag the artifact" if add else "take tags off the artifact", "tags": wanted[:50]}
        return Result(output={"tags": after, "changed": changed}, request=would)
    if changed:
        after = artifacts.set_tags(call.db, row, after)
        said = f"Tagged {row.kind} {row.name or row.ref[:12]}: {', '.join(after) or 'none'}"
        audit.record(call.db, ACTOR, "artifact.tags", said + signature(call))
    return Result(output={"tags": after, "changed": changed})


@action(
    "nik.add-artifact-tags",
    group=GROUP,
    name="Tag an artifact",
    description="Add tags to an artifact. The tags it has already stay as they are; 12 at most.",
    arguments=[ARTIFACT_ARG, ARTIFACT_TAGS_ARG],
    outputs=ARTIFACT_TAGS_OUT,
)
def add_artifact_tags(call: Call) -> Result:
    return _tag_artifact(call, True)


@action(
    "nik.remove-artifact-tags",
    group=GROUP,
    name="Take tags off an artifact",
    description="Remove tags from an artifact. A tag it does not have changes nothing.",
    arguments=[ARTIFACT_ARG, ARTIFACT_TAGS_ARG],
    outputs=ARTIFACT_TAGS_OUT,
)
def remove_artifact_tags(call: Call) -> Result:
    return _tag_artifact(call, False)


@action(
    "nik.set-artifact-expiry",
    group=GROUP,
    name="Set the expiry of an artifact",
    description=(
        "Give an artifact a day to be deleted on, or take the date away. Nothing has a date unless someone "
        "sets one; an artifact an open incident still holds is not deleted when its day comes, it is put off."
    ),
    arguments=[
        ARTIFACT_ARG,
        {
            "name": "expires",
            "type": "text",
            "description": "A day (2027-01-31), a number of days from today, or empty to take the date away",
        },
    ],
    outputs=[
        {"name": "expires", "type": "text", "description": "The day it is deleted on (empty: it has no date)"},
        {"name": "changed", "type": "bool", "description": "Whether the date is not what it was"},
    ],
)
def set_artifact_expiry(call: Call) -> Result:
    row = _artifact(call)
    given = call.args.get("expires")
    text = "" if given is None else str(given).strip()
    try:
        if text.replace(".", "", 1).isdigit():
            days = int(float(text))
            if days < 1:
                raise artifact_expiry.ExpiryError("An expiry is at least a day away")
            text = (artifact_expiry.today(call.now) + timedelta(days=days)).isoformat()
        day = artifact_expiry.clean_date(text, call.now)
    except (artifact_expiry.ExpiryError, OverflowError, ValueError) as error:
        raise ActionError(getattr(error, "message", "An expiry is a date: 2027-01-31"), retry=False) from None
    changed = (row.expires_at or None) != day
    if call.dry_run:
        would = {"would": "set the expiry of the artifact", "expires": day or ""}
        return Result(output={"expires": day or "", "changed": changed}, request=would)
    if changed:
        artifact_expiry.set_expiry(call.db, row, day, call.now)
        what = f"expires on {day}" if day else "has no expiry any more"
        audit.record(
            call.db, ACTOR, "artifact.expiry", f"{row.kind} {row.name or row.ref[:12]} {what}" + signature(call)
        )
    return Result(output={"expires": day or "", "changed": changed}, classes={"expires": ["nik_id"]})


# --------------------------------------------------------------------------- #
# Starting an analysis                                                        #
# --------------------------------------------------------------------------- #
# What each analysis on a worker is called in a sentence, and the worker that makes it.
_ON_WORKER = {
    "code": ("The disassembly", "the analyzer worker"),
    "capabilities": ("capa", "the capa worker"),
    "capture": ("The analysis of the capture", "the packet capture worker"),
}
_SKIPPED = [
    {"name": "[0].analysis", "type": "text", "description": "The first analysis that was not started"},
    {"name": "[0].reason", "type": "text", "description": "Why"},
]
ANALYSE_OUT = [
    {"name": "artifact", "type": "text", "description": "The artifact"},
    {"name": "kind", "type": "text", "description": "file, mail or pcap"},
    {"name": "asked", "type": "bool", "description": "The analysis was asked for (false in a dry run)"},
    {"name": "finished", "type": "bool", "description": "Everything that was started has ended"},
    {"name": "started", "type": "list", "description": "What was started: static, code, capabilities, mail, capture"},
    {
        "name": "skipped",
        "type": "list",
        "description": "What was left out, and why: {analysis, reason}",
        "shape": _SKIPPED,
    },
    {"name": "verdict", "type": "text", "description": "The verdict of the artifact afterwards, when it has one"},
    {"name": "page", "type": "text", "description": "Its address in Nik"},
    {"name": "summary", "type": "text", "description": "What happened, in a line"},
]
_ANALYSE_CLASSES = {
    "artifact": ["nik_id"],
    "page": ["nik_id"],
    "kind": ["verdict"],
    "asked": ["verdict"],
    "finished": ["verdict"],
    "started": ["verdict"],
    "skipped": ["verdict"],
    "verdict": ["verdict"],
    "summary": ["verdict"],
}


def _analysed(row: Artifact, *, asked: bool, finished: bool, started: list, skipped: list, summary: str) -> Result:
    output = {
        "artifact": row.id,
        "kind": row.kind,
        "asked": asked,
        "finished": finished,
        "started": started,
        "skipped": skipped,
        "verdict": row.verdict or "",
        "page": f"/artifact/{row.id}",
        "summary": summary[:TEXT_MAX],
    }
    return Result(output=output, classes=dict(_ANALYSE_CLASSES), log=summary[:TEXT_MAX])


def _progress(db, row: Artifact, started: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Of the analyses a job started on a worker: those still running, and those that failed with
    what their worker said."""
    from ..workers import analyzer, capa

    running: list[str] = []
    failed: list[tuple[str, str]] = []
    interrupted = "it was interrupted"
    for name in started:
        if name == "code":
            job = db.get(SampleCode, row.ref)
            status, error = (job.status, job.error) if job is not None else ("error", "it was dropped")
            if job is not None and analyzer.is_stale(job):
                status, error = "error", interrupted
        elif name == "capabilities":
            job = db.get(SampleCapa, row.ref)
            status, error = (job.status, job.error) if job is not None else ("error", "it was dropped")
            if job is not None and capa.is_stale(job):
                status, error = "error", interrupted
        elif name == "capture":
            capture = db.get(NetworkCapture, row.ref)
            held = capture.status if capture is not None else "error"
            status = {"indexing": "running", "ready": "done"}.get(held, "error")
            error = (capture.error if capture is not None else "") or "it was dropped"
        else:
            continue  # made by the API process itself: it ended with the job
        if status in ("queued", "running"):
            running.append(name)
        elif status == "error":
            failed.append((name, str(error or "it failed")))
    return running, failed


def _wait_for_analysis(call: Call, state: dict) -> Result:
    db = call.db
    row = db.get(Artifact, str(state.get("artifact") or ""))
    job = db.get(ArtifactJob, str(state.get("job") or ""))
    if row is None or job is None:
        raise ActionError("The artifact was deleted before its analysis ended", retry=False)
    minutes = int(state.get("minutes") or WAIT_MINUTES)
    late = call.now >= float(state.get("until") or 0)
    if job.status == "error":
        raise ActionError(str(job.error or "The analysis was not started"), retry=False)
    if job.status != "done":
        if not late:
            return Result(again_at=call.now + JOB_EVERY, state=state, log="Waiting for the server to start it")
        raise ActionError(
            f"The analysis was not started in {minutes} minutes: see whether the server answers ({WORKERS_PAGE})",
            retry=False,
        )
    started = list((job.result or {}).get("started") or [])
    skipped = list((job.result or {}).get("skipped") or [])
    running, failed = _progress(db, row, started)
    if failed:
        name, error = failed[0]
        what, worker = _ON_WORKER[name]
        raise ActionError(f"{what} failed: {error[:300]} ({worker}; {WORKERS_PAGE})", retry=False)
    if running and not late:
        waiting = ", ".join(_ON_WORKER[name][0].lower() for name in running)
        return Result(again_at=call.now + JOB_EVERY * 3, state=state, log=f"Waiting for {waiting}")
    if running:
        what = ", ".join(_ON_WORKER[name][0].lower() for name in running)
        workers = ", ".join(dict.fromkeys(_ON_WORKER[name][1] for name in running))
        raise ActionError(
            f"The analysis did not end in {minutes} minutes: {what} still running. "
            f"See whether {workers} answers ({WORKERS_PAGE})",
            retry=False,
        )
    summary = f"Analysed again: {', '.join(started) or 'nothing'}"
    if skipped:
        summary += "; left out: " + ", ".join(item["analysis"] for item in skipped)
    return _analysed(row, asked=True, finished=True, started=started, skipped=skipped, summary=summary)


@action(
    "nik.analyse-artifact",
    group=GROUP,
    name="Analyse an artifact",
    description=(
        "Start the analysis of an artifact again, as Re-analyse does: of a file the static analysis and "
        "the YARA rules, then the disassembly and capa where their workers are there; of an e-mail its "
        "analysis with the DNS checks; of a capture the packet capture worker. Or one analysis of a file "
        "alone: static, code (Disassemble) or capabilities (Run capa). Nothing is run or opened: these "
        "are the analyses Nik makes of an upload. The node waits for the result, or starts and goes on. "
        "An address is visited again with Scan an address."
    ),
    arguments=[
        ARTIFACT_ARG,
        {
            "name": "analysis",
            "type": "choice",
            "choices": ["", *artifact_jobs.ANALYSES],
            "default": "",
            "description": "One analysis of a file alone (static, code, capabilities); what Re-analyse does when empty",
        },
        {
            "name": "wait",
            "type": "bool",
            "default": True,
            "description": "Wait for the analysis to end (off: start it and go on)",
        },
        {
            "name": "wait_minutes",
            "type": "number",
            "default": WAIT_MINUTES,
            "description": "How long to wait before the step fails (1 to 120)",
        },
    ],
    outputs=ANALYSE_OUT,
)
def analyse_artifact(call: Call) -> Result:
    state = call.state or {}
    if state:
        return _wait_for_analysis(call, state)
    db = call.db
    wanted = _artifact_id(call.args.get("artifact"))
    which = str(call.args.get("analysis") or "")
    if which not in ("", *artifact_jobs.ANALYSES):
        raise ActionError("The analysis is static, code or capabilities, or empty", retry=False)
    row = db.get(Artifact, wanted) if artifacts.is_artifact_id(wanted) else None
    if row is None:
        if call.dry_run and artifacts.is_artifact_id(wanted):
            # What a dry run did not keep is not there to analyse: the step says what it would do.
            empty = Artifact(id=wanted, kind=wanted.split("-", 1)[0], ref=wanted.split("-", 1)[1], verdict="")
            result = _analysed(
                empty, asked=False, finished=False, started=[], skipped=[], summary="Dry run: nothing was started"
            )
            result.request = {"would": "analyse the artifact", "artifact": wanted, "analysis": which or "all"}
            return result
        raise ActionError("The artifact does not exist" if wanted else "No artifact was given", retry=False)
    if row.kind == "url":
        raise ActionError("An address is visited again with Scan an address, which the data guard judges", retry=False)
    if row.kind not in ("file", "mail", "pcap"):
        raise ActionError("Only a file, an e-mail or a capture is analysed again", retry=False)
    if which and row.kind != "file":
        raise ActionError(f"{which} is an analysis of files: leave the analysis empty for this artifact", retry=False)
    if call.dry_run:
        result = _analysed(
            row, asked=False, finished=False, started=[], skipped=[], summary="Dry run: nothing was started"
        )
        result.request = {"would": "analyse the artifact", "artifact": row.id, "analysis": which or "all"}
        return result
    try:
        minutes = max(1, min(int(float(call.args.get("wait_minutes") or WAIT_MINUTES)), 120))
    except (TypeError, ValueError):
        minutes = WAIT_MINUTES
    params = {"artifact": row.id, "analysis": which, "by": signature(call)}
    job = artifact_jobs.ask(db, "analyse", params, ACTOR, call.run.id, _depth(), call.now)
    wait = call.args.get("wait")
    if wait is not None and wait != "" and not _truthy(wait):
        summary = "Asked for: the run goes on without waiting"
        return _analysed(row, asked=True, finished=False, started=[], skipped=[], summary=summary)
    return Result(
        again_at=call.now + JOB_EVERY,
        state={"job": job.id, "artifact": row.id, "until": call.now + minutes * 60, "minutes": minutes},
        log=f"Analysing {row.name or row.id}",
    )


# --------------------------------------------------------------------------- #
# Reading what an analysis found                                              #
# --------------------------------------------------------------------------- #
_FILE = (
    ("sha256", "text", "Its SHA-256"),
    ("sha1", "text", "Its SHA-1"),
    ("md5", "text", "Its MD5"),
    ("size", "number", "Its size in bytes"),
    ("type", "text", "What the file is, as Nik detected it"),
    ("entropy", "number", "Its entropy, 0 to 8"),
    ("packed", "bool", "Most of it is of high entropy: packed or encrypted"),
    ("yara", "list", "The names of the YARA rules that matched"),
    ("yara_severity", "text", "high or medium, by the rules that matched; empty when none says"),
    ("strings", "number", "How many strings were found"),
    ("code_status", "text", "The disassembly: none, queued, running, done or error"),
    ("functions", "number", "How many functions the disassembly found"),
    ("capabilities_status", "text", "capa: none, queued, running, done, error or unsupported"),
    ("capabilities", "list", "The names of the capabilities capa found"),
    ("attack", "list", "The ATT&CK techniques of those capabilities (T1055…)"),
)
_MAIL = (
    ("subject", "text", "The subject"),
    ("sender", "text", "The address it says it is from"),
    ("sender_domain", "text", "The domain of that address"),
    ("spf", "text", "SPF: pass, fail, softfail, none…"),
    ("dkim", "text", "DKIM: pass, fail, none…"),
    ("dmarc", "text", "DMARC: pass, fail, none…"),
    ("findings", "list", "The reasons behind the verdict, by their codes (dmarc-fail, lookalike-domain…)"),
    ("urls", "list", "Where its links lead"),
    ("attachments", "list", "Its attachments: {name, sha256, size, type, place}"),
    ("attachments[0].name", "text", "The file name of the first attachment"),
    ("attachments[0].sha256", "text", "Its SHA-256"),
    ("attachments[0].size", "number", "Its size in bytes"),
    ("attachments[0].type", "text", "What it is"),
    ("attachments[0].place", "text", "Its place in the message: what Add a file takes as attachment"),
)
_CAPTURE = (
    ("status", "text", "live, indexing, ready, error or stored (no worker)"),
    ("error", "text", "Why it could not be analysed, when it could not"),
    ("packets", "number", "How many packets"),
    ("hosts", "list", "The public addresses it talks to"),
    ("domains", "list", "The names it asks for or connects to"),
    ("posts", "number", "How many POST requests"),
    ("beacons", "number", "How many regular connections that look like a beacon"),
    ("objects", "number", "How many files could be taken out of it"),
)
_SCAN = (
    ("url", "text", "The address"),
    ("final_url", "text", "Where the browser ended"),
    ("redirected", "bool", "It ended somewhere else than the address"),
    ("title", "text", "The title of the page"),
    ("password_form", "bool", "The page asks for a password"),
    ("findings", "list", "The reasons behind the verdict"),
)


def _file_found(db, sample: Sample | None) -> dict[str, Any]:
    analysis = (sample.analysis or {}) if sample is not None else {}
    rules: list[str] = []
    for match in analysis.get("yara") or []:
        rule = str((match or {}).get("rule") or "")
        if rule and rule not in rules:
            rules.append(rule)
    severities = {str((match.get("meta") or {}).get("severity") or "").lower() for match in analysis.get("yara") or []}
    code = db.get(SampleCode, sample.sha256) if sample is not None else None
    capa_row = db.get(SampleCapa, sample.sha256) if sample is not None else None
    found = (capa_row.result or {}).get("capabilities") or [] if capa_row is not None else []
    techniques: list[str] = []
    for item in found:
        for entry in item.get("attack") or []:
            if entry.get("id") and entry["id"] not in techniques:
                techniques.append(str(entry["id"]))
    size = int(sample.size or 0) if sample is not None else 0
    return {
        "sha256": sample.sha256 if sample is not None else "",
        "sha1": sample.sha1 if sample is not None else "",
        "md5": sample.md5 if sample is not None else "",
        "size": size,
        "type": (sample.type_label or "") if sample is not None else "",
        "entropy": float(sample.entropy or 0) if sample is not None else 0,
        "packed": bool(size) and (analysis.get("highEntropyBytes") or 0) / size > 0.5,
        "yara": rules[:FOUND_MAX],
        "yara_severity": "high" if "high" in severities else "medium" if "medium" in severities else "",
        "strings": int(analysis.get("stringsTotal") or 0),
        "code_status": code.status if code is not None else "none",
        "functions": len((code.summary or {}).get("functions") or []) if code is not None else 0,
        "capabilities_status": capa_row.status if capa_row is not None else "none",
        "capabilities": [str(item.get("name") or "")[:200] for item in found][:FOUND_MAX],
        "attack": techniques[:FOUND_MAX],
    }


def _mail_auth(analysis: dict[str, Any], method: str) -> str:
    """What the analysis says of SPF, DKIM or DMARC: Nik's own check, or what a server reported."""
    auth = analysis.get("auth") or {}
    checked = ((auth.get("verified") or {}).get(method) or {}).get("result")
    if checked not in (None, "none", "temperror"):
        return str(checked)
    reported = (((auth.get("reported") or {}).get("summary") or {}).get(method) or {}).get("result")
    return str(reported or checked or "none")


def _mail_found(mail: Mail | None) -> dict[str, Any]:
    analysis = (mail.analysis or {}) if mail is not None else {}
    data = payloads.mail_data(mail) if mail is not None else {}
    attachments = [
        {
            "name": str(item.get("name") or "")[:255],
            "sha256": str((item.get("hashes") or {}).get("sha256") or ""),
            "size": int(item.get("size") or 0),
            "type": str((item.get("type") or {}).get("label") or ""),
            "place": place,
        }
        for place, item in artifact_jobs.attachments_of(analysis.get("attachments") or [])[:50]
    ]
    return {
        "subject": str(data.get("subject") or "")[:TEXT_MAX],
        "sender": str(data.get("sender") or ""),
        "sender_domain": str(data.get("sender_domain") or ""),
        "spf": _mail_auth(analysis, "spf") if mail is not None else "",
        "dkim": _mail_auth(analysis, "dkim") if mail is not None else "",
        "dmarc": _mail_auth(analysis, "dmarc") if mail is not None else "",
        # By their codes: the sentences quote the message.
        "findings": list(dict.fromkeys(str(item.get("id") or "") for item in analysis.get("findings") or []))[:50],
        "urls": [str(url)[:2000] for url in (data.get("urls") or [])[:FOUND_MAX]],
        "attachments": attachments,
    }


def _capture_found(capture: NetworkCapture | None) -> dict[str, Any]:
    summary = (capture.summary or {}) if capture is not None else {}
    domains: list[str] = []
    for item in [*(summary.get("dns") or []), *(summary.get("tlsServerNames") or [])]:
        name = str((item or {}).get("name") or "")
        if name and name not in domains:
            domains.append(name)
    return {
        "status": capture.status if capture is not None else "",
        "error": str(capture.error or "")[:TEXT_MAX] if capture is not None else "",
        "packets": int(capture.packets or 0) if capture is not None else 0,
        "hosts": [str(host["address"]) for host in summary.get("hosts") or [] if host.get("public")][:FOUND_MAX],
        "domains": domains[:FOUND_MAX],
        "posts": len(summary.get("posts") or []),
        "beacons": len(summary.get("beacons") or []),
        "objects": len(summary.get("objects") or []),
    }


def _scan_found(scan: UrlScan | None) -> dict[str, Any]:
    if scan is None:
        return {"url": "", "final_url": "", "redirected": False, "title": "", "password_form": False, "findings": []}
    given = _scan_output(scan, scan.status == "done")
    return {key: given[key] for key in ("url", "final_url", "redirected", "title", "password_form", "findings")}


def _indicators(row: Artifact, sample, mail, capture, scan) -> list[tuple[str, str]]:
    """The indicators the analysis of an artifact found: those an incident that holds it lists."""
    from .. import urlscan
    from ..iocs import TYPES, capture_iocs

    found: list[tuple[str, str]] = []
    if row.kind == "file" and sample is not None:
        found += [("sha256", sample.sha256), ("sha1", sample.sha1), ("md5", sample.md5)]
        for item in (sample.analysis or {}).get("iocs") or []:
            if item.get("kind") in ("url", "domain", "ip", "email") and item.get("value"):
                found.append((item["kind"], str(item["value"])))
    elif row.kind == "mail" and mail is not None:
        for item in (mail.analysis or {}).get("iocs") or []:
            if item.get("type") in TYPES and item.get("value"):
                found.append((item["type"], str(item["value"])))
    elif row.kind == "pcap" and capture is not None:
        found += [(kind, value) for kind, value, _when in capture_iocs(capture.summary or {})]
    elif row.kind == "url" and scan is not None and scan.status == "done":
        found += urlscan.url_iocs(scan)
    return list(dict.fromkeys(found))


def _state(row: Artifact, found: dict[str, Any], capture, scan) -> str:
    """Where the analysis of an artifact is: done, running, error, or none (no worker made it)."""
    if row.kind == "file":
        parts = (found["file"]["code_status"], found["file"]["capabilities_status"])
        return "running" if any(part in ("queued", "running") for part in parts) else "done"
    if row.kind == "pcap" and capture is not None:
        return {"ready": "done", "error": "error", "stored": "none"}.get(capture.status, "running")
    if row.kind == "url" and scan is not None:
        return {"done": "done", "error": "error"}.get(scan.status, "running")
    return "done"


def _summary(row: Artifact, found: dict[str, Any], status: str) -> str:
    name = row.name or row.ref[:16]
    if row.kind == "file":
        rules = found["file"]["yara"]
        said = f"{name}: {found['file']['type'] or 'unknown type'}, {row.verdict or 'no verdict'}"
        return said + (f"; YARA: {', '.join(rules[:5])}" if rules else "")
    if row.kind == "mail":
        mail = found["mail"]
        checks = f"SPF {mail['spf']}, DKIM {mail['dkim']}, DMARC {mail['dmarc']}"
        return f"{row.verdict or 'clean'} (score {row.score or 0}): “{name}” from {mail['sender']}; {checks}"
    if row.kind == "pcap":
        capture = found["capture"]
        if status != "done":
            return f"{name}: {capture['status']}" + (f" ({capture['error']})" if capture["error"] else "")
        return f"{name}: {capture['packets']} packets, {len(capture['hosts'])} public hosts, {capture['posts']} POSTs"
    if row.kind == "url":
        return f"{row.verdict or status}: {name}"
    return name


ANALYSIS_OUT = [
    {"name": "found", "type": "bool", "description": "Nik holds the artifact (false only in a dry run)"},
    {"name": "artifact", "type": "text", "description": "The artifact"},
    {"name": "kind", "type": "text", "description": "file, mail, pcap, url or mailbox"},
    {"name": "name", "type": "text", "description": "Its name"},
    {"name": "status", "type": "text", "description": "Where its analysis is: done, running, error or none"},
    {"name": "verdict", "type": "text", "description": "The verdict, when the analysis gives one"},
    {"name": "score", "type": "number", "description": "The score, when the analysis gives one"},
    {"name": "summary", "type": "text", "description": "What was found, in a line"},
    {
        "name": "indicators",
        "type": "list",
        "description": "The indicators the analysis found: [{type, value}], 100 at most",
        "shape": [
            {"name": "[0].type", "type": "text", "description": "The type of the first indicator"},
            {"name": "[0].value", "type": "text", "description": "The indicator"},
        ],
    },
    {"name": "indicator_count", "type": "number", "description": "How many indicators it found in all"},
    {
        "name": "file",
        "type": "object",
        "description": "Of a file: hashes, type, rules, capabilities",
        "shape": _shape(_FILE),
    },
    {
        "name": "mail",
        "type": "object",
        "description": "Of an e-mail: sender, checks, links, attachments",
        "shape": _shape(_MAIL),
    },
    {
        "name": "capture",
        "type": "object",
        "description": "Of a capture: packets, hosts, names",
        "shape": _shape(_CAPTURE),
    },
    {
        "name": "scan",
        "type": "object",
        "description": "Of an address: where it led, what the page asks",
        "shape": _shape(_SCAN),
    },
    {"name": "page", "type": "text", "description": "Its address in Nik"},
]


@action(
    "nik.get-analysis",
    group=GROUP,
    name="Read an analysis",
    description=(
        "What the analysis of an artifact found, for a playbook to decide on: the verdict and the score, "
        "the indicators, and by kind the hashes, the type and the rules that matched of a file, the "
        "sender, the SPF, DKIM and DMARC checks, the links and the attachments of an e-mail, the hosts "
        "and names of a capture, where an address led. Lists are cut at 100 items. Nothing of the file "
        "itself is given."
    ),
    arguments=[ARTIFACT_ARG],
    outputs=ANALYSIS_OUT,
)
def get_analysis(call: Call) -> Result:
    db = call.db
    wanted = _artifact_id(call.args.get("artifact"))
    row = db.get(Artifact, wanted) if artifacts.is_artifact_id(wanted) else None
    if row is None and not (call.dry_run and artifacts.is_artifact_id(wanted)):
        raise ActionError("The artifact does not exist" if wanted else "No artifact was given", retry=False)
    missing = row is None
    if missing:
        # What a dry run did not keep has no analysis: every output is there all the same, empty.
        row = Artifact(id=wanted, kind=wanted.split("-", 1)[0], ref=wanted.split("-", 1)[1], name="", verdict="")
    sample = db.get(Sample, row.ref) if row.kind == "file" else None
    mail = db.get(Mail, row.ref) if row.kind == "mail" else None
    capture = db.get(NetworkCapture, row.ref) if row.kind == "pcap" else None
    scan = db.get(UrlScan, row.ref) if row.kind == "url" else None
    found = {
        "file": _file_found(db, sample),
        "mail": _mail_found(mail),
        "capture": _capture_found(capture),
        "scan": _scan_found(scan),
    }
    status = "none" if missing else _state(row, found, capture, scan)
    indicators = _indicators(row, sample, mail, capture, scan)
    output = {
        "found": not missing,
        "artifact": row.id,
        "kind": row.kind,
        "name": row.name or ("" if missing else row.ref[:16]),
        "status": status,
        "verdict": row.verdict or "",
        "score": row.score,
        "summary": ("Dry run: the artifact is not there" if missing else _summary(row, found, status))[:TEXT_MAX],
        "indicators": [{"type": kind, "value": value[:2000]} for kind, value in indicators[:FOUND_MAX]],
        "indicator_count": len(indicators),
        **found,
        "page": f"/artifact/{row.id}",
    }
    names = [] if missing else _name_classes(db, row)
    classes = {
        "found": ["verdict"],
        "artifact": ["nik_id"],
        "page": ["nik_id"],
        "kind": ["verdict"],
        "status": ["verdict"],
        "verdict": ["verdict"],
        "score": ["verdict"],
        "indicator_count": ["verdict"],
        "indicators.type": ["verdict"],
        "name": names,
        # The line repeats the name, and of an e-mail its sender.
        "summary": sorted({*names, *(["email_address"] if row.kind == "mail" else [])}),
        **{f"file.{key}": ["hash" if key in ("sha256", "sha1", "md5") else "verdict"] for key, _k, _s in _FILE},
        "mail.subject": ["subject"],
        "mail.sender": ["email_address"],
        "mail.spf": ["verdict"],
        "mail.dkim": ["verdict"],
        "mail.dmarc": ["verdict"],
        "mail.findings": ["verdict"],
        "mail.attachments.name": ["attachment_name"],
        "mail.attachments.sha256": ["hash"],
        "mail.attachments.size": ["verdict"],
        "mail.attachments.type": ["verdict"],
        "mail.attachments.place": ["verdict"],
        **{f"capture.{key}": ["verdict"] for key in ("status", "packets", "posts", "beacons", "objects")},
        "scan.redirected": ["verdict"],
        "scan.password_form": ["verdict"],
        "scan.url": payloads.indicator_data(db, "url", scan.url)[1] if scan is not None else [],
    }
    return Result(output=output, classes=classes, log=output["summary"])
