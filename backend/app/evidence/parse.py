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
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from .. import work
from ..core.config import settings
from ..core.db import SessionLocal, without_statement_limit
from ..core.models import (
    EvidenceDetection,
    EvidenceLogon,
    EvidenceProcess,
    EvidenceRecord,
    EvidenceSource,
    Incident,
)
from ..core.security import now_iso
from ..sigma import detections as sigma_detections
from ..sigma import ruleset as sigma_ruleset
from ..workers import handover, watching
from . import imports, originals, processes
from .imports import PARSE_WORK as WORK

logger = logging.getLogger("nik.evidence.parse")

HEADER = "X-Forensics-Token"
BATCH = 5000
EXAMPLES = 50
# Distinct indicators of one file that are looked at: a log of millions of logons names few addresses.
INDICATORS = 20_000
CHANNELS_CAP = 50  # distinct channels a report counts
# How long the worker may say nothing: a pass over a file of gigabytes before the first record.
READ_TIMEOUT = 1800
# The worker reads a few files at a time (FORENSICS_MAX_JOBS) and answers 503 "busy" to the others: a file
# that was sent while it was full waits its turn instead of failing (a take-out of the archive, or ten files
# sent together, start one reading each).
BUSY_WAIT = 3.0
BUSY_TRIES = 600
NOT_CONFIGURED = "The forensics worker is not configured (FORENSICS_URL): the file is kept, and is read once it is"


class ParseError(Exception):
    """The worker could not be asked, or refused: a sentence for the report."""


def configured() -> bool:
    return bool(settings.FORENSICS_URL)


# --------------------------------------------------------------------------- #
# The worker                                                                  #
# --------------------------------------------------------------------------- #
def _events(sha256: str, body: dict[str, Any], job: str, route: str = "/parse") -> Iterator[dict[str, Any]]:
    """The events of a parse (``route``: or of another that answers in lines, ``/unpack``), as the worker sends
    them. The original is given to the worker when it says it does not hold it, and so is the set of rules
    (``body["rules"]``, a digest) when it lacks it;
    then the question is asked again, each of them once. Raises ``ParseError`` when the worker cannot be
    asked; a stream that is cut is simply over (the caller sees that no ``end`` came).

    A set of rules the worker does not take does not stop the reading of the file: it is read without
    rules (``body`` loses its ``rules``, which the caller looks at) and a ``note`` says so."""
    name = f"{sha256}.bin"
    url, token = settings.FORENSICS_URL, settings.FORENSICS_TOKEN
    gave_file = gave_rules = False
    busy = 0
    while True:
        data = json.dumps({**body, "name": name}).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            f"{url}{route}",
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
            if not gave_file and handover.missing_of(error, answer):
                gave_file = True
                try:
                    handover.give(url, HEADER, token, name, originals.path_of(sha256))
                except handover.NotGiven as refused:
                    raise ParseError(str(refused)) from None
                continue
            lacking = answer.get("missingRules") if error.code == 409 and isinstance(answer, dict) else None
            if not gave_rules and isinstance(lacking, str) and lacking and body.get("rules"):
                gave_rules = True
                refused_rules = sigma_ruleset.give(lacking)
                if refused_rules is not None:
                    body.pop("rules", None)  # the file is read, without the rules
                    body.get("params", {}).pop("hours", None)
                    yield {"t": "note", "reason": "rules not applied", "count": 1, "detail": refused_rules}
                continue
            detail = answer.get("detail") if isinstance(answer, dict) else None
            if error.code == 503 and "busy" in str(detail) and busy < BUSY_TRIES:
                busy += 1
                time.sleep(BUSY_WAIT)
                continue
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
        self.channels: dict[str, int] = {}
        # What the rules matched, when the file was read with rules: ``Detected.report()``.
        self.detections: dict[str, Any] | None = None
        # How many processes and logons the file gave (rows stored): the screens of them say what a file holds.
        self.processes = 0
        self.logons = 0

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

    def channel(self, name: str) -> None:
        """Count a record's channel; the 51st distinct one and the ones after it are not counted."""
        if name and (name in self.channels or len(self.channels) < CHANNELS_CAP):
            self.channels[name] = self.channels.get(name, 0) + 1

    def out(self, ended: bool, seconds: float | None = None) -> dict[str, Any]:
        held = {
            "reasons": self.reasons,
            "notes": self.notes,
            "channels": self.channels,
            "ended": ended,
            "seconds": seconds,
        }
        if self.detections is not None:
            held["detections"] = self.detections
        if self.processes:
            held["processes"] = self.processes
        if self.logons:
            held["logons"] = self.logons
        return held


# --------------------------------------------------------------------------- #
# Keeping                                                                     #
# --------------------------------------------------------------------------- #
def _row(event: dict[str, Any], source: EvidenceSource) -> dict[str, Any] | None:
    key = event.get("key")
    if not isinstance(key, str) or not key or len(key) > 300:
        return None
    ts = event.get("ts")
    event_id = event.get("event_id")
    # A record may be of another section and source than its file (an export of Plaso, a registry hive): it says so.
    kind = event.get("k")
    own = event.get("src")
    return {
        "incident_id": source.incident_id,
        "source_id": source.id,
        "kind": kind if isinstance(kind, str) and kind in imports.KINDS and kind != "collection" else source.kind,
        "source": own[:60] if isinstance(own, str) and own else None,
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


def _insert(db: OrmSession, rows: list[dict[str, Any]], placed: dict[str, int] | None = None) -> int:
    """Store a batch, leaving out the records another file of the incident already gave (same key).
    Returns how many were stored. ``placed``, when given, is filled with the id of each record stored, by
    key: what the detections and the processes of the batch need to name them, without asking again."""
    if not rows:
        return 0
    insert = postgresql.insert if db.get_bind().dialect.name == "postgresql" else sqlite.insert
    # Two records of one batch may share a key (a log exported twice into one file): the first stays.
    seen: set[str] = set()
    unique = [row for row in rows if not (row["key"] in seen or seen.add(row["key"]))]
    table = EvidenceRecord.__table__
    # What comes back is what was stored: the rows a conflict left out give no id.
    stored = db.execute(
        insert(table).on_conflict_do_nothing(index_elements=["incident_id", "key"]).returning(table.c.id, table.c.key),
        unique,
    ).all()
    if placed is not None:
        placed.update((key, found) for found, key in stored)
    return len(stored)


def clear(db: OrmSession, source_id: str) -> None:
    """Remove what a reading stored for the source (the caller commits). Marks stay: they are by key. A file of millions
    of records takes longer than a statement may, so the limit is lifted for the rest of the transaction."""
    without_statement_limit(db)
    records = select(EvidenceRecord.id).where(EvidenceRecord.source_id == source_id)
    processes.detach(db, source_id)
    db.execute(delete(EvidenceDetection).where(EvidenceDetection.record_id.in_(records)))
    db.execute(delete(EvidenceProcess).where(EvidenceProcess.source_id == source_id))
    db.execute(delete(EvidenceLogon).where(EvidenceLogon.source_id == source_id))
    db.execute(delete(EvidenceRecord).where(EvidenceRecord.source_id == source_id))


def _fail(db: OrmSession, source_id: str, sentence: str) -> None:
    row = db.get(EvidenceSource, source_id)
    if row is not None and row.state in ("queued", "parsing"):
        row.state, row.read, row.error = "failed", "failed", sentence[:500]
        row.parsed_at = now_iso()


class _Gone(Exception):
    """The source was removed while its file was being read (its incident was deleted): nothing is left to
    store the records under, and nothing to say."""


def read(source_id: str, claim: work.Claim | None = None) -> None:
    """Read the original of a source and keep what comes. Run held (``work``). A source that goes away
    while it is read (its incident was deleted) ends the reading quietly."""
    try:
        _read(source_id, claim)
    except _Gone:
        return


def _read(source_id: str, claim: work.Claim | None = None) -> None:
    """Read the original of a source and keep what comes. Run held (``work``)."""
    with SessionLocal() as db:
        source = db.get(EvidenceSource, source_id)
        if source is None or source.state not in ("queued", "parsing"):
            return
        if not configured():
            _fail(db, source_id, NOT_CONFIGURED)
            db.commit()
            return
        # What the file's earlier reading made of processes is linked again when this one ends.
        old_hosts = processes.hosts_of(db, source_id)
        clear(db, source_id)
        source.state, source.error = "parsing", None
        db.commit()
        db.refresh(source)
        db.expunge(source)
        # The rules to read it with: those enabled and supported (none: the file is read as it always was).
        rules_now = sigma_ruleset.current(db)
        hours = sigma_ruleset.hours(db, db.get(Incident, source.incident_id)) if rules_now else None
    body: dict[str, Any] = {
        "fileName": source.file_name,
        "kind": source.kind,
        "parser": source.parser or None,
        "source": source.source or None,
        "params": {
            "host": source.host,
            "username": source.username,
            "profile": source.profile,
            "file_name": source.file_name,
        },
    }
    if source.file_time:
        body["params"]["file_time"] = source.file_time
    if rules_now is not None:
        body["rules"] = rules_now.digest
        body["params"]["hours"] = hours
    detected = sigma_detections.Detected(rules_now, source.incident_id)
    held = processes.Held(source)
    began = time.monotonic()
    report = Report()
    counts = {"read": 0, "kept": 0, "truncated": 0}
    ended: dict[str, Any] | None = None
    said: dict[str, Any] = {}
    batch: list[dict[str, Any]] = []
    declared: dict[tuple[str, str], None] = {}
    undeclared = 0
    job = watching.job_name(WORK, source_id, getattr(claim, "attempts", 1) or 1)
    placed: dict[str, int] = {}  # the ids of the records of the batch being stored, by key

    def flush() -> None:
        if not batch and not detected.pending and not held:
            return
        with SessionLocal() as db:
            try:
                placed.clear()
                if batch:
                    counts["kept"] += _insert(db, batch, placed)
                detected.write(db, placed)  # after the records they are of
                held.write(db, placed)  # so are the processes and the logons
                db.commit()
            except IntegrityError:
                # The rows these belong to are gone: the incident was deleted under the reading.
                db.rollback()
                if db.get(EvidenceSource, source_id) is None:
                    raise _Gone from None
                raise
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
                report.channel(row["channel"])
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
            elif kind == "det":
                detected.add(event)
                if detected.full():
                    flush()
            elif held.add(event):
                if held.full():
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
        with SessionLocal() as db:
            held.retry(db)  # the ends of processes that were met before their start
            db.commit()
    except ParseError as error:
        flush()
        with SessionLocal() as db:
            if counts["kept"] == 0:
                clear(db, source_id)
                _fail(db, source_id, str(error))
                db.commit()
                if claim is not None:
                    claim.failed = True  # type: ignore[attr-defined]
                processes.after(source.incident_id, old_hosts)
                return
            db.commit()
        report.skip({"reason": "the worker stopped answering", "lost": 0, "detail": str(error)})

    if "rules" not in body:
        detected.set = None  # no rules were given, or the worker did not take them: nothing was matched
    elif detected:
        report.detections = detected.report()
        for reason, count in (
            ("detection of a record that is not here", detected.unplaced),
            ("detection of a rule that is not in the set", detected.unknown),
        ):
            if count:
                report.note({"reason": reason, "count": count})
    report.processes, report.logons = held.processes, held.logon_rows
    hosts = old_hosts | held.hosts
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
        row.report = report.out(ended is not None, round(time.monotonic() - began, 1))
        nothing = counts["read"] == 0 and ended is None
        row.read = "failed" if nothing else "complete" if ended is not None and not report.skips else "partial"
        # A file that gave processes is not finished until their tree and the chain rules are: it stays "parsing"
        # (with "linking processes" as its progress) and is closed by ``_finish`` below.
        linking = bool(hosts) and not nothing
        row.state = "failed" if nothing else "parsing" if linking else "done"
        row.error = _first_reason(report) if nothing else None
        row.parsed_at = now_iso()
        row.seen_by, row.seen_at, row.seen_note = None, None, ""
        if not linking:
            _said(db, row, detected)
        db.commit()
    if claim is not None and nothing:
        claim.failed = True  # type: ignore[attr-defined]
    # The processes of the hosts this file touched, and those it touched before, are linked, and the chain rules
    # run over them; then the file is finished, with the detections of the chains in its report, its War Room line
    # and its event.
    if linking and claim is not None:
        claim.progress("linking processes")
    try:
        processes.after(source.incident_id, hosts)
    finally:
        if linking:
            _finish(source_id)


def _said(db: OrmSession, row: EvidenceSource, detected: sigma_detections.Detected | None) -> None:
    """The lines a finished file leaves: one in the War Room for what was read, and what the rules found."""
    from .. import war_room

    # One line for the file, whatever it held: what was read of it, and whether anything was not.
    war_room.add(db, row.incident_id, "system", {"text": sentence(row), "evidence": {"source": row.id}}, "nik")
    if detected is not None and detected.total:
        _detected(db, row, detected)


def _finish(source_id: str) -> None:
    """The tree and the chain rules of a file's hosts are done (or were not run): the file is done. What it found is
    counted from the table, so that the chain rules' detections are in the report, the War Room line and the event."""
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        if row is None or row.state != "parsing":
            return
        found = sigma_detections.Detected.from_table(db, row.incident_id, source_id)
        report = dict(row.report or {})
        if found.total or "detections" in report:
            report["detections"] = found.report()
            row.report = report
        row.state = "done"
        _said(db, row, found)
        db.commit()


def _detected(db: OrmSession, source: EvidenceSource, found: sigma_detections.Detected) -> None:
    """What the rules found in a file: a line in the War Room when any is of level medium or more, and
    the event ``evidence.detected`` for the playbooks that wait for it (one for the file, not one for
    each detection). Detections never change the severity of the incident."""
    from .. import war_room
    from ..automation import triggers

    line = sigma_detections.sentence(source.file_name or source.sha256[:12], found)
    if line:
        war_room.add(db, source.incident_id, "system", {"text": line, "evidence": {"source": source.id}}, "nik")
    incident = db.get(Incident, source.incident_id)
    if incident is not None:
        triggers.evidence_detected(db, incident, source, found.total, found.highest(), found.top())


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
