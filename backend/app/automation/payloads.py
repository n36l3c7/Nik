"""What an event carries to the playbooks it triggers, and the classes of its fields.

One builder per event. Each returns the data (what ``{{ trigger.… }}`` reads)
and, beside it, a map of the classes of data its fields hold, so the data
guard knows what a value is without guessing from its content:

    data    = {"incident": {"id": …, "name": …, "assignee": …}, "changed": […]}
    classes = {"incident.id": ["nik_id"], "incident.name": ["incident_text"], …}

Classes are defined in guard.py. A field that is not in the map has none of
its own and is caught, if at all, by the guard's scan of what leaves. A list
has the classes of its items: ``mail.attachments.name``.
"""

from __future__ import annotations

import hashlib
from typing import Any
from urllib.parse import urlsplit

from ..core.models import Artifact, Incident, Mail, Sample, UrlScan

# How many addresses, attachments, rules or hits an event carries at most.
LIST_MAX = 200
# Above this many hits their values are not looked up one by one: the guard's scan decides.
HITS_CLASSED = 20

# The fields of an incident a trigger can compare and a playbook can read, and their classes.
_INCIDENT = {
    "id": "nik_id",
    "url": "nik_id",
    "status": "verdict",
    "severity": "verdict",
    "name": "incident_text",
    "ticket": "incident_text",
    "host": "private_value",
    "username": "private_value",
    "assignee": "private_value",
    "os": "verdict",
    "created": "nik_id",
    "modified": "nik_id",
}


def incident_data(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "url": f"/incident/{incident.id}",
        "name": incident.name,
        "ticket": incident.ticket_id,
        "host": incident.host,
        "username": incident.username,
        "os": incident.os,
        "status": incident.status or "open",
        "severity": incident.severity or "",
        "assignee": incident.assignee or "",
        "created": incident.created_at,
        "modified": incident.updated_at,
    }


def incident_classes(prefix: str = "incident") -> dict[str, list[str]]:
    return {f"{prefix}.{name}": [held] for name, held in _INCIDENT.items()}


def incident_event(incident: Incident, changed: list[str] | None = None) -> tuple[dict, dict]:
    """``incident.created`` / ``incident.updated``."""
    data = {"incident": incident_data(incident), "changed": sorted(changed or [])}
    return data, incident_classes()


def registry_classes() -> dict[str, list[str]]:
    """The classes of an incident's fields by the names of the registry (``{{ incident.owner }}``).
    A custom field has none of its own: the guard's scan of what leaves decides."""
    return {
        "id": ["nik_id"],
        "type": ["verdict"],
        "status": ["verdict"],
        "severity": ["verdict"],
        "tlp": ["verdict"],
        "created": ["nik_id"],
        "modified": ["nik_id"],
        "closed": ["nik_id"],
        "occurred": ["nik_id"],
        "due": ["nik_id"],
        "name": ["incident_text"],
        "ticket": ["incident_text"],
        "details": ["incident_text"],
        "close_notes": ["incident_text"],
        "host": ["private_value"],
        "username": ["private_value"],
        "owner": ["private_value"],
        "affected_hosts": ["private_value"],
        "affected_users": ["private_value"],
    }


def _with_incident(data: dict, classes: dict, incident: Incident | None) -> None:
    if incident is not None:
        data["incident"] = incident_data(incident)
        classes.update(incident_classes())


def manual(actor: str, incident: Incident | None) -> tuple[dict, dict]:
    """A run started by hand, on an incident or on nothing."""
    data: dict[str, Any] = {"actor": actor}
    classes: dict[str, list[str]] = {"actor": ["private_value"]}
    _with_incident(data, classes, incident)
    return data, classes


def schedule(at: str, cron: str) -> tuple[dict, dict]:
    return {"at": at, "cron": cron}, {}


# --------------------------------------------------------------------------- #
# E-mails, files, addresses                                                   #
# --------------------------------------------------------------------------- #
_MAIL = {
    "mail.sha256": ["hash"],
    "mail.subject": ["subject"],
    "mail.sender": ["email_address"],
    "mail.sender_sha256": ["hash"],
    "mail.verdict": ["verdict"],
    "mail.score": ["verdict"],
    "mail.artifact_id": ["nik_id"],
    "mail.url": ["nik_id"],
    "mail.attachments.name": ["attachment_name"],
    "mail.attachments.sha256": ["hash"],
}
_FILE = {
    "file.sha256": ["hash"],
    "file.name": ["attachment_name"],
    "file.type": ["verdict"],
    "file.verdict": ["verdict"],
    "file.yara": ["verdict"],
    "file.artifact_id": ["nik_id"],
    "file.url": ["nik_id"],
}
_SCAN = {
    "scan.id": ["nik_id"],
    "scan.verdict": ["verdict"],
    "scan.score": ["verdict"],
    "scan.artifact_id": ["nik_id"],
    "scan.page": ["nik_id"],
}


def mail_data(mail: Mail) -> dict[str, Any]:
    analysis = mail.analysis or {}
    sender = (mail.sender or "").strip().lower()
    attachments = [
        {
            "name": str(item.get("name") or ""),
            "sha256": (item.get("hashes") or {}).get("sha256") or "",
            "size": item.get("size") or 0,
        }
        for item in (analysis.get("attachments") or [])[:LIST_MAX]
        if isinstance(item, dict)
    ]
    urls: list[str] = []
    for link in analysis.get("links") or []:
        target = str((link or {}).get("target") or "")
        if target.lower().startswith(("http://", "https://")) and target not in urls:
            urls.append(target)
        if len(urls) >= LIST_MAX:
            break
    artifact = f"mail-{mail.sha256}"
    return {
        "sha256": mail.sha256,
        "subject": mail.subject or "",
        "sender": sender,
        "sender_domain": sender.rsplit("@", 1)[1] if "@" in sender else "",
        # The sender as a value that can leave when the address cannot: the same sender gives the same hash.
        "sender_sha256": hashlib.sha256(sender.encode("utf-8")).hexdigest() if sender else "",
        "verdict": mail.verdict or "",
        "score": mail.score or 0,
        "urls": urls,
        "attachments": attachments,
        "artifact_id": artifact,
        "url": f"/artifact/{artifact}",
    }


def mail_event(mail: Mail, incident: Incident | None = None, from_mailbox: str = "") -> tuple[dict, dict]:
    """``mail.analysed``: an e-mail was analysed, on its own, in an incident or out of a mailbox."""
    data: dict[str, Any] = {"mail": mail_data(mail), "from_mailbox": from_mailbox or ""}
    classes: dict[str, list[str]] = {**_MAIL, "from_mailbox": ["nik_id"]}
    _with_incident(data, classes, incident)
    return data, classes


def file_data(sample: Sample, artifact: Artifact | None) -> dict[str, Any]:
    rules: list[str] = []
    for match in (sample.analysis or {}).get("yara") or []:
        rule = str((match or {}).get("rule") or "")
        if rule and rule not in rules:
            rules.append(rule)
    entry = f"file-{sample.sha256}"
    return {
        "sha256": sample.sha256,
        "name": (artifact.name if artifact is not None else "") or sample.sha256,
        "size": sample.size,
        "type": sample.type_label or "",
        "verdict": (artifact.verdict if artifact is not None else "") or "",
        "yara": rules[:LIST_MAX],
        "artifact_id": entry,
        "url": f"/artifact/{entry}",
    }


def file_event(sample: Sample, artifact: Artifact | None, incident: Incident | None = None) -> tuple[dict, dict]:
    """``file.analysed``: the analysis of a file ended."""
    data: dict[str, Any] = {"file": file_data(sample, artifact)}
    classes: dict[str, list[str]] = dict(_FILE)
    _with_incident(data, classes, incident)
    return data, classes


def scan_data(scan: UrlScan) -> dict[str, Any]:
    entry = f"url-{scan.id}"
    return {
        "id": scan.id,
        "url": scan.url,
        "final_url": (scan.result or {}).get("finalUrl") or scan.url,
        "host": scan.host or "",
        "verdict": scan.verdict or "",
        "score": scan.score or 0,
        "artifact_id": entry,
        "page": f"/artifact/{entry}",
    }


def scan_event(scan: UrlScan) -> tuple[dict, dict]:
    """``url.analysed``: the scan of an address ended."""
    return {"scan": scan_data(scan)}, dict(_SCAN)


def artifact_manual(actor: str, db, artifact: Artifact) -> tuple[dict, dict] | None:
    """A run started by hand on an analysed e-mail, file or address: what its
    event carries, and who started it. None for what has no event of its own."""
    found: tuple[dict, dict] | None = None
    if artifact.kind == "mail":
        mail = db.get(Mail, artifact.ref)
        found = mail_event(mail) if mail is not None else None
    elif artifact.kind == "file":
        sample = db.get(Sample, artifact.ref)
        found = file_event(sample, artifact) if sample is not None else None
    elif artifact.kind == "url":
        scan = db.get(UrlScan, artifact.ref)
        found = scan_event(scan) if scan is not None else None
    if found is None:
        return None
    data, classes = found
    return {**data, "actor": actor}, {**classes, "actor": ["private_value"]}


# --------------------------------------------------------------------------- #
# Indicators                                                                  #
# --------------------------------------------------------------------------- #
def _is_private(kind: str, value: str) -> bool:
    """Whether the value names something inside a network: a private address, an internal name."""
    from ..enrichment.service import internal_host

    host = value
    if kind == "url":
        try:
            host = urlsplit(value).hostname or ""
        except ValueError:
            return False
    elif kind == "email":
        host = value.rsplit("@", 1)[-1]
    elif kind not in ("ip", "domain"):
        return False
    return bool(host) and internal_host(host) is not None


def indicator_data(db, kind: str, value: str) -> tuple[dict, list[str]]:
    """What Nik knows of an indicator, and the classes of its value: public
    unless something says it is yours."""
    from .. import ioc_library as lib
    from ..iocs import Allowlist
    from ..routers.settings import read_settings

    shared = read_settings(db)
    # An indicator Nik holds nowhere has no row: what it is still follows from its value.
    rows = lib.library(db, shared, only={(kind, value)})
    row = rows[0] if rows else {}
    private = _is_private(kind, value)
    allowlisted = Allowlist(shared.get("iocAllowlist") or []).matches(kind, value)
    red = row.get("tlp") == "red" or (kind, value) in lib.red_pairs(db)
    held = [name for name, on in (("private_value", private), ("allowlisted", allowlisted), ("tlp_red", red)) if on]
    data = {
        "kind": kind,
        "value": value,
        "verdict": row.get("verdict") or "",
        "score": row.get("score"),
        "tlp": "red" if red else (row.get("tlp") or ""),
        "tags": row.get("tags") or [],
        "private": private,
        "allowlisted": allowlisted,
        "lists": [entry["name"] for entry in row.get("lists") or []],
        "incidents": row.get("incidents") or 0,
    }
    return data, held or ["public_indicator"]


def _ioc_classes(held: list[str]) -> dict[str, list[str]]:
    said = ("kind", "verdict", "score", "old", "new", "tlp", "private", "allowlisted", "incidents", "sources")
    return {"ioc.value": held, **{f"ioc.{name}": ["verdict"] for name in said}}


def verdict_changed(db, kind: str, value: str, old: str, new: str, sources: list[str]) -> tuple[dict, dict]:
    """``ioc.verdict_changed``: what the sources say of an indicator, taken together, changed."""
    ioc, held = indicator_data(db, kind, value)
    ioc.update(old=old, new=new, sources=sorted(sources))
    return {"ioc": ioc}, _ioc_classes(held)


def indicator_manual(actor: str, db, kind: str, value: str) -> tuple[dict, dict]:
    """A run started by hand on an indicator."""
    ioc, held = indicator_data(db, kind, value)
    return {"ioc": ioc, "actor": actor}, {**_ioc_classes(held), "actor": ["private_value"]}


def watch_hit(db, incident: Incident, hits: list[dict]) -> tuple[dict, dict]:
    """``ioc.watch_hit``: an incident newly holds indicators of a watched list.

    ``hits`` is what the webhook of the same name sends; ``ioc`` and ``list``
    are those of the first, for a playbook that handles one at a time."""
    first, hits = hits[0], hits[:LIST_MAX]
    ioc, held = indicator_data(db, first["type"], first["value"])
    classes = _ioc_classes(held)
    if len(hits) <= HITS_CLASSED:
        every = set(held)
        for hit in hits[1:]:
            every.update(indicator_data(db, hit["type"], hit["value"])[1])
        classes["hits.value"] = sorted(every)
    classes["hits.incident.name"] = ["incident_text"]
    classes["hits.incident.id"] = ["nik_id"]
    classes["hits.list.id"] = ["nik_id"]
    classes["list.id"] = ["nik_id"]
    data = {"ioc": ioc, "list": dict(first["list"]), "hits": hits, "incident": incident_data(incident)}
    classes.update(incident_classes())
    return data, classes


# --------------------------------------------------------------------------- #
# The server, the outside                                                     #
# --------------------------------------------------------------------------- #
def sla_breached(incident: Incident, field: str, label: str, due_s: int, elapsed_s: int) -> tuple[dict, dict]:
    """``sla.breached``: a timer of an incident passed the time its type allows."""
    data = {
        "incident": incident_data(incident),
        "timer": {"field": field, "label": label, "due_minutes": due_s // 60, "elapsed_minutes": elapsed_s // 60},
    }
    classes = incident_classes()
    for key in ("field", "label", "due_minutes", "elapsed_minutes"):
        classes[f"timer.{key}"] = ["verdict"]
    return data, classes


def artifact_expiry(artifact: Artifact, days_left: int) -> tuple[dict, dict]:
    """``artifact.expiring`` and ``artifact.expired``: an artifact with a date is about to be deleted, or was."""
    data = {
        "artifact": {
            "id": artifact.id,
            "kind": artifact.kind,
            "name": artifact.name or artifact.ref[:16],
            "ref": artifact.ref,
            "size": int(artifact.size or 0),
            "expires_at": artifact.expires_at or "",
            "days_left": days_left,
            "url": f"/artifact/{artifact.id}",
        }
    }
    classes = {
        "artifact.id": ["nik_id"],
        "artifact.url": ["nik_id"],
        "artifact.name": ["attachment_name"],
        "artifact.ref": ["hash"],
    }
    return data, classes


def storage_low(total: int, free: int) -> tuple[dict, dict]:
    """``storage.low``: the disk that holds the evidence is nearly full."""
    percent = round(100 * free / total, 1) if total else 0
    return {"disk": {"total": total, "used": total - free, "free": free, "free_percent": percent}}, {}


def webhook(body: Any, headers: dict[str, str], query: dict[str, str]) -> tuple[dict, dict]:
    """A request to the playbook's address. Nothing in it has a class of its own:
    it comes from outside, and the guard's scan decides what may leave again."""
    return {"body": body, "headers": headers, "query": query}, {}
