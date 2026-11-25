"""The "Host evidence" nodes: what a playbook reads of the files and records of an incident (7.0).

Up to 6.x a playbook (and so a script, which only computes on what a node hands it) could not read host evidence
at all, and before 7.0 it sat in the incident document. Now it lives in tables, and two read-only nodes give it:

- **List the host evidence files of an incident**: each file with what it is, its counts and its parse report.
- **Read host evidence records**: a page of records, with the same filters as the API (``GET
  /incidents/{id}/evidence/records``), at most ``LIMIT_MAX`` of them, and the cursor of the next page.

A script gets what these nodes give as the arguments of its node, as for any other value.

Two things hold for both:

- **Nothing here changes anything.** They read the tables the screens read, in a dry run too.
- **What they give carries its classes** (payloads.py): a host or a user name is an internal name, a summary and the
  fields of a record can name anything, so they have the classes of internal names; a file name is a file name. A
  later node that sends them out is judged by that, as for the artifacts of the "Files" nodes.

A record is given light (its summary, not its fields) unless ``fields`` names the keys of its data that are wanted
(12 at most, each cut at 500 characters): a page of records never carries a whole event log.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..core.models import EvidenceSource, Incident
from ..evidence import browse
from .actions import ActionError, Call, Result, action
from .nik_actions import INCIDENT_ARG, _truthy, _wanted

GROUP = "Host evidence"
FILES_MAX = 200  # files a node lists at most
LIMIT_DEFAULT = 100
LIMIT_MAX = browse.LIMIT_MAX  # records of one page: the API's own limit
FIELDS_MAX = 12  # keys of data a record may carry
REASONS_MAX = 20  # reasons of a parse report that are given
KINDS = ("eventlog", "disk", "endpoint", "browser", "commands", "syslog")

_FILE = (
    ("file", "text", "Its id: what an argument called file takes"),
    ("kind", "text", "Its section: eventlog, disk, endpoint, browser, commands, syslog or collection"),
    ("source", "text", "What the parser reads it as (evtx, mft, auth.log…)"),
    ("name", "text", "The file name"),
    ("size", "number", "Its size in bytes"),
    ("sha256", "text", "The SHA-256 of the original"),
    ("host", "text", "The host it comes from"),
    ("user", "text", "The user it comes from"),
    ("parser", "text", "The parser that read it"),
    ("state", "text", "queued, parsing, done, failed, absent (listed by an import, no original) or archived"),
    ("read", "text", "complete, partial (something was lost or not reached), failed or unknown"),
    ("in_file", "number", "How many records the file says it holds, when its format says"),
    ("read_count", "number", "Records the parser gave"),
    ("kept", "number", "Records stored"),
    ("duplicates", "number", "Records another file of the incident already gave"),
    ("skipped", "number", "Records lost: the report says why and where"),
    ("truncated", "number", "Records with a value cut in the database"),
    ("first_ts", "number", "The time of its oldest record (ms since the epoch)"),
    ("last_ts", "number", "The time of its newest record"),
    ("seen", "bool", "A person acknowledged that it was read in part"),
    ("error", "text", "Why it could not be read"),
    ("report.ended", "bool", "The parser reached the end of the file"),
    ("report.seconds", "number", "How long the reading took"),
    ("report.reasons", "list", "What was lost, grouped: {reason, count, lost}"),
    ("report.notes", "list", "What is worth saying and lost nothing: {reason, count}"),
    ("report.detections", "number", "How many detections its records have"),
)
_RECORD = (
    ("id", "number", "Its id: what the page of a record opens"),
    ("key", "text", "Its natural key, the same each time the file is read"),
    ("kind", "text", "Its section"),
    ("type", "text", "What it is (event, file, run key, line…)"),
    ("ts", "number", "Its time, ms since the epoch UTC (empty for a record with none)"),
    ("seq", "number", "Its place in its file"),
    ("host", "text", "The host"),
    ("username", "text", "The user"),
    ("event_id", "number", "The id of an event"),
    ("channel", "text", "The channel or program"),
    ("summary", "text", "What the lists show of it in one line"),
    ("level", "number", "The highest level of its detections, 1 (informational) to 5 (critical); empty for none"),
    ("truncated", "bool", "A value of it was cut in the database"),
    ("file", "text", "The id of its file"),
    ("flagged", "bool", "A person flagged it"),
    ("note", "text", "The note on it"),
    ("data", "object", "The keys of its data that were asked for with fields"),
)


def _shape(fields: tuple, prefix: str = "") -> list[dict[str, str]]:
    return [{"name": f"{prefix}{name}", "type": kind, "description": said} for name, kind, said in fields]


_FILE_CLASSES = {
    "file": ["nik_id"],
    "kind": ["verdict"],
    "source": ["verdict"],
    "name": ["attachment_name"],
    "size": ["verdict"],
    "sha256": ["hash"],
    "host": ["private_value"],
    "user": ["private_value"],
    "parser": ["verdict"],
    "state": ["verdict"],
    "read": ["verdict"],
    "in_file": ["verdict"],
    "read_count": ["verdict"],
    "kept": ["verdict"],
    "duplicates": ["verdict"],
    "skipped": ["verdict"],
    "truncated": ["verdict"],
    "first_ts": ["verdict"],
    "last_ts": ["verdict"],
    "seen": ["verdict"],
    "error": ["incident_text"],
    "report": ["verdict"],
}
_RECORD_CLASSES = {
    "id": ["nik_id"],
    "key": ["private_value"],
    "kind": ["verdict"],
    "type": ["verdict"],
    "ts": ["verdict"],
    "seq": ["verdict"],
    "host": ["private_value"],
    "username": ["private_value"],
    "event_id": ["verdict"],
    "channel": ["private_value"],
    "summary": ["private_value"],
    "level": ["verdict"],
    "truncated": ["verdict"],
    "file": ["nik_id"],
    "flagged": ["verdict"],
    "note": ["incident_text"],
    "data": ["private_value"],
}


def _incident(call: Call) -> str:
    wanted = _wanted(call, call.args.get("incident"))
    if not wanted:
        raise ActionError("No incident was given", retry=False)
    if call.db.get(Incident, wanted) is None:
        raise ActionError("The incident does not exist", retry=False)
    return wanted


def _whole(value: Any, name: str, low: int, high: int | None = None) -> int | None:
    """A whole number an argument gave (a number, or a text of digits), or None for none; ``ActionError`` otherwise."""
    if value is None or value == "":
        return None
    try:
        number = (
            int(str(value).strip()) if not isinstance(value, (int, float)) or isinstance(value, bool) else int(value)
        )
    except ValueError:
        raise ActionError(f"{name} is a whole number", retry=False) from None
    if number < low or (high is not None and number > high):
        raise ActionError(f"{name} is {low} to {high}" if high is not None else f"{name} is {low} or more", retry=False)
    return number


def _millis(value: Any, name: str) -> int | None:
    """A time as ms since the epoch: a number, or a date in ISO form (UTC when it has no zone)."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return int(value)
    text = str(value).strip()
    if text.lstrip("-").isdigit():
        return int(text)
    try:
        moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        raise ActionError(f"{name} is ms since the epoch, or a date like 2026-11-20T09:30:00Z", retry=False) from None
    return int((moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)).timestamp() * 1000)


def _file_of(row: EvidenceSource) -> dict[str, Any]:
    report = row.report if isinstance(row.report, dict) else {}
    reasons = [
        {"reason": reason, "count": int(held.get("count") or 0), "lost": int(held.get("lost") or 0)}
        for reason, held in list((report.get("reasons") or {}).items())[:REASONS_MAX]
        if isinstance(held, dict)
    ]
    notes = [
        {"reason": reason, "count": int(held.get("count") or 0)}
        for reason, held in list((report.get("notes") or {}).items())[:REASONS_MAX]
        if isinstance(held, dict)
    ]
    detections = report.get("detections")
    return {
        "file": row.id,
        "kind": row.kind,
        "source": row.source or "",
        "name": row.file_name or "",
        "size": int(row.size or 0),
        "sha256": row.sha256 or "",
        "host": row.host or "",
        "user": row.username or "",
        "parser": row.parser or "",
        "state": row.state,
        "read": row.read,
        "in_file": row.in_file,
        "read_count": int(row.read_count or 0),
        "kept": int(row.kept or 0),
        "duplicates": int(row.duplicates or 0),
        "skipped": int(row.skipped or 0),
        "truncated": int(row.truncated or 0),
        "first_ts": row.first_ts,
        "last_ts": row.last_ts,
        "seen": bool(row.seen_at),
        "error": row.error or "",
        "report": {
            "ended": bool(report.get("ended")),
            "seconds": report.get("seconds"),
            "reasons": reasons,
            "notes": notes,
            "detections": int(detections.get("total") or 0) if isinstance(detections, dict) else 0,
        },
    }


@action(
    "nik.list-evidence-files",
    group=GROUP,
    name="List the host evidence files of an incident",
    description=(
        "The files of host evidence an incident holds (event logs, disk, endpoint artifacts, browser, command "
        "history, syslog and collections), the newest first: what each is, how many records were read, kept, "
        "duplicated or lost, and its parse report in short. Nothing of the records. 200 at most."
    ),
    arguments=[
        INCIDENT_ARG,
        {
            "name": "kind",
            "type": "choice",
            "choices": ["", *KINDS, "collection"],
            "default": "",
            "description": "Only this section; all of them when left empty",
        },
        {"name": "partial", "type": "bool", "description": "Only the files that were read in part or failed"},
    ],
    outputs=[
        {
            "name": "files",
            "type": "list",
            "description": "Each file: {file, kind, name, size, sha256, host, state, read, kept, report…}",
            "shape": _shape(_FILE, "[0]."),
        },
        {"name": "ids", "type": "list", "description": "Their ids, for a For each"},
        {"name": "count", "type": "number", "description": "How many are given"},
        {"name": "total", "type": "number", "description": "How many matched, when more than are given"},
        {"name": "records", "type": "number", "description": "Records the files given hold, all of them"},
    ],
)
def list_files(call: Call) -> Result:
    wanted = _incident(call)
    kind = str(call.args.get("kind") or "")
    if kind and kind not in (*KINDS, "collection"):
        raise ActionError("The kind is eventlog, disk, endpoint, browser, commands, syslog or collection", retry=False)
    rows = browse.sources(call.db, wanted, kind or None)
    if _truthy(call.args.get("partial")):
        rows = [row for row in rows if row.read in ("partial", "failed") or row.state == "failed"]
    shown = rows[:FILES_MAX]
    files = [_file_of(row) for row in shown]
    classes = {f"files.{name}": held for name, held in _FILE_CLASSES.items()}
    classes.update({"ids": ["nik_id"], "count": ["verdict"], "total": ["verdict"], "records": ["verdict"]})
    return Result(
        output={
            "files": files,
            "ids": [item["file"] for item in files],
            "count": len(files),
            "total": len(rows),
            "records": sum(item["kept"] for item in files),
        },
        classes=classes,
    )


@action(
    "nik.get-evidence-records",
    group=GROUP,
    name="Read host evidence records",
    description=(
        "A page of the records of the host evidence of an incident, oldest first, with the filters of the "
        "Evidence pages. A record is given light (its summary, host, user, time); name the keys of its data that "
        "are wanted in Data fields. 500 at most a page: when there is more, Next is the cursor to give back."
    ),
    arguments=[
        INCIDENT_ARG,
        {
            "name": "kind",
            "type": "choice",
            "choices": ["", *KINDS],
            "default": "",
            "description": "Only this section",
        },
        {"name": "type", "type": "text", "description": "Only these types of record (event, file…), comma-separated"},
        {"name": "file", "type": "text", "description": "Only the records of this file (an id from the list of files)"},
        {"name": "source", "type": "text", "description": "Only the files the parser read as this (evtx, mft…)"},
        {"name": "host", "type": "text", "description": "Only this host"},
        {"name": "username", "type": "text", "description": "Only this user"},
        {"name": "channel", "type": "text", "description": "Only this channel or program"},
        {"name": "event_id", "type": "number", "description": "Only this event id"},
        {
            "name": "level",
            "type": "number",
            "description": "Only the records with a detection of this level or more (1 to 5)",
        },
        {"name": "rule", "type": "text", "description": "Only the records this Sigma rule matched (its id)"},
        {"name": "flagged", "type": "bool", "description": "Only the records a person flagged"},
        {"name": "q", "type": "text", "description": "Only the records whose summary holds this text"},
        {
            "name": "from",
            "type": "text",
            "description": "Not before this time: ms since the epoch, or 2026-11-20T09:30:00Z",
        },
        {"name": "to", "type": "text", "description": "Not after this time"},
        {
            "name": "order",
            "type": "choice",
            "choices": ["time", "-time", "file"],
            "default": "time",
            "description": "Oldest first, newest first, or the order of the file (needs file)",
        },
        {
            "name": "limit",
            "type": "number",
            "default": LIMIT_DEFAULT,
            "description": f"Records of the page, {LIMIT_MAX} at most",
        },
        {"name": "cursor", "type": "text", "description": "The Next of the page before, for the one after"},
        {
            "name": "fields",
            "type": "text",
            "description": f"Keys of the data of each record to give, comma-separated ({FIELDS_MAX} at most)",
        },
    ],
    outputs=[
        {
            "name": "records",
            "type": "list",
            "description": "Each record: {id, key, kind, type, ts, host, username, event_id, summary, level, file…}",
            "shape": _shape(_RECORD, "[0]."),
        },
        {"name": "returned", "type": "number", "description": "How many are in this page"},
        {"name": "next", "type": "text", "description": "The cursor of the next page; empty at the end"},
        {
            "name": "count",
            "type": "number",
            "description": "How many records match, counted on the first page (empty after)",
        },
        {"name": "count_capped", "type": "bool", "description": "The count stopped at 100,001"},
    ],
)
def get_records(call: Call) -> Result:
    wanted = _incident(call)
    if call.db.get(Incident, wanted).archived_at:
        raise ActionError(
            "The incident is archived: its records are not loaded. Take it out of the archive first", retry=False
        )
    args = call.args
    kind = str(args.get("kind") or "")
    if kind and kind not in KINDS:
        raise ActionError("The kind is eventlog, disk, endpoint, browser, commands or syslog", retry=False)
    types = [name.strip() for name in str(args.get("type") or "").split(",") if name.strip()]
    if len(types) > 40 or any(len(name) > 40 for name in types):
        raise ActionError("type is 40 values at most, 40 characters each", retry=False)
    filters: dict[str, Any] = {
        "kind": kind,
        "type": types,
        "sourceId": str(args.get("file") or "").strip()[:32],
        "source": str(args.get("source") or "").strip()[:60],
        "host": str(args.get("host") or "")[:255],
        "username": str(args.get("username") or "")[:255],
        "channel": str(args.get("channel") or "")[:120],
        "eventId": _whole(args.get("event_id"), "event_id", -(2**31), 2**31 - 1),
        "level": _whole(args.get("level"), "level", 1, 5),
        "rule": str(args.get("rule") or "").strip()[:64],
        "flagged": _truthy(args.get("flagged")),
        "q": str(args.get("q") or "")[:200],
        "from": _millis(args.get("from"), "from"),
        "to": _millis(args.get("to"), "to"),
    }
    order = str(args.get("order") or "time")
    limit = _whole(args.get("limit"), "limit", 1, LIMIT_MAX) or LIMIT_DEFAULT
    cursor = str(args.get("cursor") or "").strip()[:200] or None
    names = [name.strip() for name in str(args.get("fields") or "").split(",") if name.strip()]
    if len(names) > FIELDS_MAX:
        raise ActionError(f"fields is {FIELDS_MAX} keys at most", retry=False)
    try:
        page = browse.records(call.db, wanted, filters, order, limit, cursor, names or None)
    except browse.BadQuery as error:
        raise ActionError(str(error), retry=False) from None
    records = [
        {
            "id": shown["id"],
            "key": shown["key"],
            "kind": shown["kind"],
            "type": shown["type"],
            "ts": shown["ts"],
            "seq": shown["seq"],
            "host": shown["host"],
            "username": shown["username"],
            "event_id": shown["eventId"],
            "channel": shown["channel"],
            "summary": shown["summary"],
            "level": shown["level"],
            "truncated": shown["truncated"],
            "file": shown["sourceId"],
            "flagged": shown["flagged"],
            "note": shown["note"],
            "data": shown.get("data") or {},
        }
        for shown in page["records"]
    ]
    classes = {f"records.{name}": held for name, held in _RECORD_CLASSES.items()}
    classes.update({"returned": ["verdict"], "next": ["verdict"], "count": ["verdict"], "count_capped": ["verdict"]})
    return Result(
        output={
            "records": records,
            "returned": len(records),
            "next": page["next"] or "",
            "count": page["count"],
            "count_capped": bool(page["countCapped"]),
        },
        classes=classes,
    )
