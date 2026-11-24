"""Reading a file of host evidence: the forensics worker reads, this module keeps (7.0).

The worker (``workers/forensics``) is given the original and answers with the
events of its reading, one JSON object per line, as it finds them: records,
what it could not read and why (``skip``), what is worth saying and lost
nothing (``note``), and an ``end`` line when it reached the end of the file.
This module turns them into rows of ``evidence_records`` and into the parse
report of the source (``evidence_sources.report`` and its counts).

**The report.** ``in_file`` is what the file itself says it holds, when its
format says so; ``read_count`` what the parser gave; ``kept`` what was stored;
``duplicates`` what another file of the incident had already given (same
natural key); ``skipped`` what was lost; ``truncated`` the records with a value
cut in the database. ``read`` is the verdict: ``complete`` when the parser
reached the end and lost nothing, ``partial`` when anything was lost or the
parser stopped before the end (what came is kept), ``failed`` when nothing
could be read at all. The reasons are grouped, each with its count and a few
examples with their place in the file; the counts are exact, the examples are
capped.

**Starting again.** The reading is work of its own (``work.py``, kind
``evidence-parse``, started again after a restart). It first removes what an
earlier try stored for the source, then reads the file from the beginning:
rows are committed batch by batch, so a file of millions of records never
holds one transaction open. The flags and notes people put on records
(``evidence_marks``) are by key and are never touched here: a file read again
gives the same keys, and they are still on them.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session as OrmSession

from .. import work
from ..core.config import settings
from ..core.db import SessionLocal
from ..core.models import (
    EvidenceDetection,
    EvidenceLogon,
    EvidenceProcess,
    EvidenceRecord,
    EvidenceSource,
)
from ..core.security import now_iso
from ..workers import handover, watching
from . import originals
from .imports import PARSE_WORK as WORK

logger = logging.getLogger("nik.evidence.parse")

HEADER = "X-Forensics-Token"
BATCH = 5000
EXAMPLES = 50
# Distinct indicators of one file that are looked at: a log of millions of logons names few addresses.
INDICATORS = 20_000
# How long the worker may say nothing: a pass over a file of gigabytes before the first record.
READ_TIMEOUT = 1800
NOT_CONFIGURED = "The forensics worker is not configured (FORENSICS_URL): the file is kept, and is read once it is"


class ParseError(Exception):
    """The worker could not be asked, or refused: a sentence for the report."""


def configured() -> bool:
    return bool(settings.FORENSICS_URL)


# --------------------------------------------------------------------------- #
# The worker                                                                  #
# --------------------------------------------------------------------------- #
def _events(sha256: str, body: dict[str, Any], job: str) -> Iterator[dict[str, Any]]:
    """The events of a parse, as the worker sends them. The original is given to the worker when it
    says it does not hold it. Raises ``ParseError`` when the worker cannot be asked; a stream that is
    cut is simply over (the caller sees that no ``end`` came)."""
    name = f"{sha256}.bin"
    url, token = settings.FORENSICS_URL, settings.FORENSICS_TOKEN
    data = json.dumps({**body, "name": name}).encode("utf-8")
    for attempt in (1, 2):
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            f"{url}/parse",
            data=data,
            method="POST",
            headers={HEADER: token, "Content-Type": "application/json", watching.HEADER: job},
        )
        try:
            response = urllib.request.urlopen(request, timeout=READ_TIMEOUT)  # noqa: S310
        except urllib.error.HTTPError as error:
            try:
                answer = json.loads(error.read() or b"{}")
            except ValueError:
                answer = {}
            if attempt == 1 and handover.missing_of(error, answer):
                try:
                    handover.give(url, HEADER, token, name, originals.path_of(sha256))
                except handover.NotGiven as refused:
                    raise ParseError(str(refused)) from None
                continue
            detail = answer.get("detail") if isinstance(answer, dict) else None
            raise ParseError(str(detail or f"The forensics worker answered {error.code}")) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise ParseError(f"The forensics worker cannot be reached: {getattr(error, 'reason', error)}") from None
        with response:
            try:
                for line in response:
                    if not line.strip():
                        continue
                    try:
                        event = json.loads(line)
                    except ValueError:
                        yield {"t": "skip", "reason": "a line of the worker could not be read", "lost": 0}
                        continue
                    if isinstance(event, dict):
                        yield event
            except (OSError, ValueError) as error:  # the connection went: the stream is over, without its end
                logger.warning("The stream of the parse of %s was cut: %s", sha256[:12], error)
        return


# --------------------------------------------------------------------------- #
# The report                                                                  #
# --------------------------------------------------------------------------- #
class Report:
    """What a reading lost and noted, grouped by reason."""

    def __init__(self) -> None:
        self.reasons: dict[str, dict[str, Any]] = {}
        self.notes: dict[str, dict[str, Any]] = {}
        self.skips = 0
        self.lost = 0

    def skip(self, event: dict[str, Any]) -> None:
        reason = str(event.get("reason") or "not read")[:120]
        lost = max(0, int(event.get("lost") or 0))
        held = self.reasons.setdefault(reason, {"count": 0, "lost": 0, "examples": []})
        held["count"] += 1
        held["lost"] += lost
        self.skips += 1
        self.lost += lost
        if len(held["examples"]) < EXAMPLES:
            held["examples"].append(
                {
                    "offset": event.get("offset") if isinstance(event.get("offset"), int) else None,
                    "length": event.get("length") if isinstance(event.get("length"), int) else None,
                    "detail": str(event.get("detail") or "")[:500],
                }
            )

    def note(self, event: dict[str, Any]) -> None:
        reason = str(event.get("reason") or "note")[:120]
        held = self.notes.setdefault(reason, {"count": 0, "detail": ""})
        held["count"] += max(0, int(event.get("count") or 1))
        held["detail"] = held["detail"] or str(event.get("detail") or "")[:500]

    def out(self, ended: bool) -> dict[str, Any]:
        return {"reasons": self.reasons, "notes": self.notes, "ended": ended}


# --------------------------------------------------------------------------- #
# Keeping                                                                     #
# --------------------------------------------------------------------------- #
def _row(event: dict[str, Any], source: EvidenceSource) -> dict[str, Any] | None:
    key = event.get("key")
    if not isinstance(key, str) or not key or len(key) > 300:
        return None
    ts = event.get("ts")
    event_id = event.get("event_id")
    return {
        "incident_id": source.incident_id,
        "source_id": source.id,
        "kind": source.kind,
        "type": str(event.get("type") or "")[:40],
        "key": key,
        "ts": int(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) else None,
        "seq": int(event.get("seq") or 0),
        "host": str(event.get("host") or source.host or "")[:255],
        "username": str(event.get("username") or source.username or "")[:255],
        "event_id": int(event_id) if isinstance(event_id, int) and not isinstance(event_id, bool) else None,
        "channel": str(event.get("channel") or "")[:120],
        "summary": str(event.get("summary") or "")[:1000],
        "data": event.get("data") if isinstance(event.get("data"), dict) else {},
        "truncated": bool(event.get("trunc")),
        "locator": event.get("loc") if isinstance(event.get("loc"), dict) else {},
    }


def _insert(db: OrmSession, rows: list[dict[str, Any]]) -> int:
    """Store a batch, leaving out the records another file of the incident already gave (same key).
    Returns how many were stored."""
    if not rows:
        return 0
    insert = postgresql.insert if db.get_bind().dialect.name == "postgresql" else sqlite.insert
    # Two records of one batch may share a key (a log exported twice into one file): the first stays.
    seen: set[str] = set()
    unique = [row for row in rows if not (row["key"] in seen or seen.add(row["key"]))]
    table = EvidenceRecord.__table__
    # What comes back is what was stored: the rows a conflict left out give no id.
    stored = db.execute(
        insert(table).on_conflict_do_nothing(index_elements=["incident_id", "key"]).returning(table.c.id),
        unique,
    )
    return len(stored.all())


def clear(db: OrmSession, source_id: str) -> None:
    """Remove what a reading stored for the source (the caller commits). Marks stay: they are by key."""
    records = select(EvidenceRecord.id).where(EvidenceRecord.source_id == source_id)
    db.execute(delete(EvidenceDetection).where(EvidenceDetection.record_id.in_(records)))
    db.execute(delete(EvidenceProcess).where(EvidenceProcess.source_id == source_id))
    db.execute(delete(EvidenceLogon).where(EvidenceLogon.source_id == source_id))
    db.execute(delete(EvidenceRecord).where(EvidenceRecord.source_id == source_id))


def _fail(db: OrmSession, source_id: str, sentence: str) -> None:
    row = db.get(EvidenceSource, source_id)
    if row is not None and row.state in ("queued", "parsing"):
        row.state, row.read, row.error = "failed", "failed", sentence[:500]
        row.parsed_at = now_iso()


def read(source_id: str, claim: work.Claim | None = None) -> None:
    """Read the original of a source and keep what comes. Run held (``work``)."""
    with SessionLocal() as db:
        source = db.get(EvidenceSource, source_id)
        if source is None or source.state not in ("queued", "parsing"):
            return
        if not configured():
            _fail(db, source_id, NOT_CONFIGURED)
            db.commit()
            return
        clear(db, source_id)
        source.state, source.error = "parsing", None
        db.commit()
        db.refresh(source)
        db.expunge(source)
    body = {
        "fileName": source.file_name,
        "parser": source.parser or None,
        "source": source.source or None,
        "params": {
            "host": source.host,
            "username": source.username,
            "profile": source.profile,
            "file_name": source.file_name,
        },
    }
    report = Report()
    counts = {"read": 0, "kept": 0, "truncated": 0}
    ended: dict[str, Any] | None = None
    said: dict[str, Any] = {}
    batch: list[dict[str, Any]] = []
    declared: dict[tuple[str, str], None] = {}
    undeclared = 0
    job = watching.job_name(WORK, source_id, getattr(claim, "attempts", 1) or 1)

    def flush() -> None:
        if not batch:
            return
        with SessionLocal() as db:
            counts["kept"] += _insert(db, batch)
            db.commit()
        batch.clear()
        if claim is not None:
            claim.progress(f"{counts['read']} records read")

    try:
        for event in _events(source.sha256, body, job):
            kind = event.get("t")
            if kind == "r":
                row = _row(event, source)
                if row is None:
                    report.skip({"reason": "a record came without a usable key", "lost": 1})
                    continue
                counts["read"] += 1
                counts["truncated"] += int(row["truncated"])
                for pair in event.get("ioc") or ():
                    if isinstance(pair, list) and len(pair) == 2 and all(isinstance(part, str) for part in pair):
                        if tuple(pair) in declared:
                            continue
                        if len(declared) < INDICATORS:
                            declared[(pair[0], pair[1])] = None
                        else:
                            undeclared += 1
                batch.append(row)
                if len(batch) >= BATCH:
                    flush()
            elif kind == "skip":
                report.skip(event)
            elif kind == "note":
                report.note(event)
            elif kind == "source":
                said = event
                # What the file says of itself fills what the import did not: a person's word stays.
                source.host = source.host or str(event.get("host") or "")[:255]
                source.username = source.username or str(event.get("username") or "")[:255]
            elif kind == "end":
                ended = event
        flush()
    except ParseError as error:
        flush()
        with SessionLocal() as db:
            if counts["kept"] == 0:
                clear(db, source_id)
                _fail(db, source_id, str(error))
                db.commit()
                if claim is not None:
                    claim.failed = True  # type: ignore[attr-defined]
                return
            db.commit()
        report.skip({"reason": "the worker stopped answering", "lost": 0, "detail": str(error)})

    if undeclared:
        report.note(
            {
                "reason": "indicators not looked at",
                "count": undeclared,
                "detail": f"the file names more than {INDICATORS} distinct ones: the first {INDICATORS} were",
            }
        )
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        if row is None:
            return
        row.indicators = _indicators(db, row, list(declared))
        first, last = db.execute(
            select(func.min(EvidenceRecord.ts), func.max(EvidenceRecord.ts)).where(
                EvidenceRecord.source_id == source_id
            )
        ).one()
        row.parser = str(said.get("parser") or row.parser or "")[:40]
        row.parser_version = str(said.get("version") or "")[:20]
        row.source = row.source or str(said.get("source") or "")[:60]
        row.host = row.host or source.host
        row.username = row.username or source.username
        in_file = (ended or {}).get("in_file")
        row.in_file = int(in_file) if isinstance(in_file, int) and not isinstance(in_file, bool) else None
        row.read_count, row.kept = counts["read"], counts["kept"]
        row.duplicates = max(0, counts["read"] - counts["kept"])
        row.skipped, row.truncated = report.lost, counts["truncated"]
        row.notes = sum(note["count"] for note in report.notes.values())
        row.first_ts, row.last_ts = first, last
        row.report = report.out(ended is not None)
        nothing = counts["read"] == 0 and ended is None
        row.read = "failed" if nothing else "complete" if ended is not None and not report.skips else "partial"
        row.state = "failed" if nothing else "done"
        row.error = _first_reason(report) if nothing else None
        row.parsed_at = now_iso()
        row.seen_by, row.seen_at, row.seen_note = None, None, ""
        from .. import war_room

        # One line for the file, whatever it held: what was read of it, and whether anything was not.
        war_room.add(db, row.incident_id, "system", {"text": sentence(row), "evidence": {"source": row.id}}, "nik")
        db.commit()
    if claim is not None and nothing:
        claim.failed = True  # type: ignore[attr-defined]


def sentence(source: EvidenceSource) -> str:
    """What the reading of a file gave, in the one line the War Room keeps."""
    name = source.file_name or source.sha256[:12]
    if source.read == "failed":
        return f"{name} could not be read: {source.error or 'no reason was given'}."
    text = f"{name} read: {source.kept} record{'' if source.kept == 1 else 's'} kept"
    if source.duplicates:
        text += f", {source.duplicates} already imported from another file"
    if source.read == "partial":
        lost = f"{source.skipped} record{'' if source.skipped == 1 else 's'} were not read" if source.skipped else ""
        ended = "" if (source.report or {}).get("ended") else "the parser stopped before the end of the file"
        text += ". Read in part: " + "; ".join(part for part in (lost, ended) if part)
        if not lost and not ended:
            text += "part of the file could not be read"
        text += " (its report says what and where)"
    return text + "."


def _indicators(db: OrmSession, source: EvidenceSource, declared: list[tuple[str, str]]) -> int:
    """Keep the indicators a file declared as found indicators of its incident, by the rules and
    within the limit of the setting (``indicators_found``): one line in the War Room when any is
    new. Returns how many were. Nothing when incidents are not read for indicators."""
    from .. import indicators_found
    from ..core.models import Incident

    incident = db.get(Incident, source.incident_id)
    if incident is None or not declared:
        return 0
    cfg = indicators_found.config(db)
    if not indicators_found.on_for(cfg, incident):
        return 0
    path = f"evidence.{source.kind}.{source.file_name}"[: indicators_found.PATH_MAX]
    values = [(kind, value, path) for kind, value in declared]
    result = indicators_found.given(values, cfg, indicators_found.known_of(db))
    return int(indicators_found.keep(db, incident, "evidence", result, cfg, whole=False)["new"])


def _first_reason(report: Report) -> str:
    for reason, held in report.reasons.items():
        detail = next((example["detail"] for example in held["examples"] if example["detail"]), "")
        return f"{reason}: {detail}"[:500] if detail else reason
    return "The file could not be read"


# --------------------------------------------------------------------------- #
# The work                                                                    #
# --------------------------------------------------------------------------- #
def start(source_id: str, _params: dict[str, Any] | None = None) -> bool:
    """Read the source in a thread of this process (the request that wanted it committed)."""

    def run() -> None:
        try:
            with work.hold(WORK, source_id) as claim:
                read(source_id, claim)
        except work.Taken:
            return

    work.thread(run)
    return True


def again(db: OrmSession, source: EvidenceSource) -> None:
    """Have a source read again ("Analyse again": a new version of its parser, or a file that
    failed). The caller commits, then calls ``start``."""
    source.state, source.error = "queued", None
    work.want(db, WORK, source.id)


work.register(work.Kind(WORK, "a file of host evidence being read", "again", start=start, fail=_fail))
