"""Host evidence from before 7.0: out of the incident document, into the tables.

Until 7.0 an incident kept what was read of its host evidence inside its
document: ``data.eventlogs``, ``data.endpoint``, ``data.browser`` and
``data.commands``, with the flags and comments on records in ``flags``. From
7.0 it is in ``evidence_sources`` and ``evidence_records``, and the document
holds none of it.

``move`` does it for one incident, in the caller's transaction:

- each file the document knew becomes a source marked ``legacy``: no original
  (6.x kept none), no parse report (``read`` is ``unknown``). Its page says
  "imported before 7.0: import the file again to have its report";
- each record becomes a row. An event of an event log gets the key the 7.0
  parser gives the same event (``evtx:<computer>:<channel>:<record id>``): the
  log imported again later meets its old records as duplicates, and the flags
  on them are still there. The others had only an id made at each import
  (``legacy:<id>``);
- a flag on a record, with its comments, becomes the mark of that record
  (``evidence_marks``) and leaves ``flags``; the flags of everything else
  (e-mails, files, captures) stay where they are;
- the four keys leave ``data``.

It runs in two places. **After the upgrade**, a loop of the API process goes
through every incident once, one transaction each (``sweep``): a server with
thousands of incidents starts at once and moves them in the background, and
where it is is kept (settings row 90). **At every write of a document** that
still brings such data (an API client of before, a 6.x export imported): it
is moved in the transaction of the write, so the tables are the only place
host evidence is ever read from.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from collections.abc import Iterator
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core import leases
from ..core.locking import lock_incident
from ..core.models import EvidenceMark, EvidenceRecord, EvidenceSource, Incident, Setting
from ..core.security import now_iso
from . import parse

logger = logging.getLogger("nik.evidence.legacy")

SETTINGS_ID = 90
KEYS = ("eventlogs", "endpoint", "browser", "commands")
PARSER = "legacy"
LEASE = "evidence-legacy"
LEASE_SECONDS = 120
BATCH = 2000
MAX_VALUE = 8000
FAILED_KEPT = 200
_OS = {"windows": "windows", "macos": "macos", "mac": "macos", "linux": "linux"}
_BROWSER_LISTS = (("history", "visit"), ("downloads", "download"), ("bookmarks", "bookmark"), ("shortcuts", "shortcut"))
_started = False


def holds(doc: dict[str, Any] | None) -> bool:
    """Whether a document still holds host evidence of before 7.0."""
    data = (doc or {}).get("data")
    return isinstance(data, dict) and any(data.get(key) for key in KEYS)


def _text(value: Any, limit: int = 255) -> str:
    return str(value if value is not None else "")[:limit]


def _ms(value: Any) -> int | None:
    return int(value) if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def _cut(fields: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """The values of a record as the tables keep them: a text longer than the limit is cut, and said."""
    cut = False
    held: dict[str, Any] = {}
    for name, value in fields.items():
        if isinstance(value, str) and len(value) > MAX_VALUE:
            value, cut = value[:MAX_VALUE], True
        held[str(name)[:200]] = value
    return held, cut


class _Mover:
    """One incident being moved: its sources and rows as they are made, and the old id of each record."""

    def __init__(self, db: OrmSession, incident: Incident) -> None:
        self.db, self.incident = db, incident
        self.rows: list[dict[str, Any]] = []
        self.keys: dict[str, str] = {}  # the id a flag names → the key of the record
        self.sources = 0
        self.records = 0

    def source(self, kind: str, source: str, meta: Any, **more: Any) -> EvidenceSource:
        meta = meta if isinstance(meta, dict) else {}
        row = EvidenceSource(
            id=uuid.uuid4().hex,
            incident_id=self.incident.id,
            kind=kind,
            source=source[:60],
            sha256="",  # no original: 6.x kept none
            file_name=_text(meta.get("fileName"), 500),
            size=int(meta.get("size") or 0) if isinstance(meta.get("size"), (int, float)) else 0,
            host=_text(more.get("host") or self.incident.host),
            username=_text(more.get("username") or ""),
            profile=_text(more.get("profile") or "", 120),
            parser=PARSER,
            parser_version="6",
            state="done",
            legacy=True,
            read="unknown",
            # What 6.x said of the file, kept as it was: the hash it noted (the browser parsers did),
            # how many rows it gave, when.
            report={"legacy": {key: meta[key] for key in sorted(meta) if key != "fileName"}},
            created_at=_text(meta.get("importedAt") or self.incident.created_at or now_iso(), 40),
            created_by="",
            parsed_at=_text(meta.get("importedAt") or "", 40) or None,
        )
        self.db.add(row)
        # The source alone: its records name it. The incident is written once, when it is whole.
        self.db.flush([row])
        self.sources += 1
        return row

    def record(
        self,
        source: EvidenceSource,
        old_id: Any,
        key: str,
        kind: str,
        ts: Any,
        summary: str,
        data: dict[str, Any],
        **more: Any,
    ) -> None:
        held, cut = _cut(data)
        key = key[:300]
        if old_id is not None:
            self.keys[str(old_id)] = key
        self.rows.append(
            {
                "incident_id": self.incident.id,
                "source_id": source.id,
                "kind": source.kind,
                "type": kind[:40],
                "key": key,
                "ts": _ms(ts),
                "seq": int(more.get("seq") or 0),
                "host": _text(more.get("host") or source.host),
                "username": _text(more.get("username") or source.username),
                "event_id": more.get("event_id") if isinstance(more.get("event_id"), int) else None,
                "channel": _text(more.get("channel") or "", 120),
                "summary": _text(summary, 1000),
                "data": held,
                "truncated": cut,
                "locator": {},
            }
        )
        if len(self.rows) >= BATCH:
            self.flush()

    def flush(self) -> None:
        if self.rows:
            self.records += parse._insert(self.db, self.rows)  # noqa: SLF001 - the one place rows are stored
            self.rows = []

    # -- the four kinds -------------------------------------------------------- #
    def eventlogs(self, held: Any) -> None:
        channels = held.get("channels") if isinstance(held, dict) else None
        for name, channel in (channels or {}).items() if isinstance(channels, dict) else ():
            if not isinstance(channel, dict):
                continue
            meta = channel.get("meta") if isinstance(channel.get("meta"), dict) else {}
            kind = "nik-eventlogs.json" if meta.get("format") == "json" else "evtx"
            source = self.source("eventlog", kind, meta)
            for position, event in enumerate(channel.get("events") or []):
                if not isinstance(event, dict):
                    continue
                computer = _text(event.get("computer"))
                channel_name = _text(event.get("channel") or name, 120)
                number = event.get("recordId")
                key = (
                    f"evtx:{computer}:{channel_name}:{number}"
                    if number is not None
                    else f"legacy:{event.get('id') or uuid.uuid4().hex}"
                )
                data = {"provider": event.get("provider"), "level": event.get("level")}
                data.update(event.get("data") if isinstance(event.get("data"), dict) else {})
                if event.get("recovered"):
                    data["recovered"] = True
                event_id = event.get("eventId") if isinstance(event.get("eventId"), int) else None
                self.record(
                    source,
                    event.get("id"),
                    key,
                    "event",
                    event.get("time"),
                    f"{event.get('provider') or channel_name} {event_id if event_id is not None else ''}".strip(),
                    data,
                    seq=position,
                    host=computer,
                    event_id=event_id,
                    channel=channel_name,
                )

    def browser(self, held: Any) -> None:
        browsers = held.get("browsers") if isinstance(held, dict) else None
        for browser, entry in (browsers or {}).items() if isinstance(browsers, dict) else ():
            profiles = entry.get("profiles") if isinstance(entry, dict) else None
            for profile in (profiles or {}).values() if isinstance(profiles, dict) else ():
                if not isinstance(profile, dict):
                    continue
                name = _text(profile.get("name") or profile.get("id") or "Default", 120)
                meta = profile.get("meta") if isinstance(profile.get("meta"), dict) else {}
                for listed, kind in _BROWSER_LISTS:
                    rows = [row for row in profile.get(listed) or [] if isinstance(row, dict)]
                    if not rows:
                        continue
                    # Firefox keeps everything in places.sqlite; a Chromium History holds the downloads too.
                    said = (
                        meta.get(listed)
                        or meta.get("places")
                        or (meta.get("history") if listed == "downloads" else None)
                    )
                    source = self.source("browser", f"{browser}.{listed}", said, profile=name)
                    for position, row in enumerate(rows):
                        data = {key: value for key, value in row.items() if key != "id"}
                        data |= {"browser": browser, "profile": name}
                        when = (
                            row.get("visitTime")
                            or row.get("startTime")
                            or row.get("dateAdded")
                            or row.get("lastAccessTime")
                        )
                        title = (
                            row.get("title")
                            or row.get("fileName")
                            or row.get("name")
                            or row.get("text")
                            or row.get("url")
                        )
                        self.record(
                            source,
                            row.get("id"),
                            f"legacy:{row.get('id') or uuid.uuid4().hex}",
                            kind,
                            when,
                            _text(title, 1000),
                            data,
                            seq=position,
                        )

    def endpoint(self, held: Any) -> None:
        system = _OS.get(str(self.incident.os or "").strip().lower(), "unknown")
        categories = held.get("categories") if isinstance(held, dict) else None
        for category, entry in (categories or {}).items() if isinstance(categories, dict) else ():
            sources = entry.get("sources") if isinstance(entry, dict) else None
            for name, kept in (sources or {}).items() if isinstance(sources, dict) else ():
                if not isinstance(kept, dict):
                    continue
                rows = [row for row in kept.get("records") or [] if isinstance(row, dict)]
                if not rows and not kept.get("meta"):
                    continue
                source = self.source("endpoint", f"{system}.{category}.{name}", kept.get("meta"))
                for position, row in enumerate(rows):
                    fields = row.get("fields") if isinstance(row.get("fields"), dict) else {}
                    data = {**fields, "category": category, "os": system}
                    telling = (
                        fields.get("command")
                        or fields.get("path")
                        or fields.get("target")
                        or fields.get("serial")
                        or ""
                    )
                    label = " ".join(
                        part
                        for part in (_text(fields.get("name") or fields.get("device"), 300), _text(telling, 600))
                        if part
                    )
                    self.record(
                        source,
                        row.get("id"),
                        f"legacy:{row.get('id') or uuid.uuid4().hex}",
                        str(name),
                        row.get("time"),
                        label,
                        data,
                        seq=position,
                    )

    def commands(self, held: Any) -> None:
        shells = held.get("shells") if isinstance(held, dict) else None
        for shell, entry in (shells or {}).items() if isinstance(shells, dict) else ():
            if not isinstance(entry, dict):
                continue
            rows = [row for row in entry.get("commands") or [] if isinstance(row, dict)]
            meta = entry.get("meta") if isinstance(entry.get("meta"), dict) else {}
            if not rows and not meta:
                continue
            source = self.source("commands", str(shell), meta.get("history"), username=self.incident.username)
            for position, row in enumerate(rows):
                command = str(row.get("command") or "")
                line = row.get("lineNo") if isinstance(row.get("lineNo"), int) else position + 1
                self.record(
                    source,
                    row.get("id"),
                    f"legacy:{row.get('id') or uuid.uuid4().hex}",
                    "command",
                    row.get("time"),
                    command,
                    {"command": command, "shell": shell, "line": line},
                    seq=line,
                )

    def marks(self, flags: Any) -> dict[str, Any]:
        """The flags on moved records become marks; what is left of ``flags`` is returned."""
        if not isinstance(flags, dict):
            return flags
        left: dict[str, Any] = {}
        for name, flag in flags.items():
            key = self.keys.get(str(name))
            if key is None or not isinstance(flag, dict):
                left[name] = flag
                continue
            said = [
                f"{comment.get('author') or 'someone'} ({comment.get('at') or '?'}): {comment.get('text') or ''}"
                for comment in flag.get("comments") or []
                if isinstance(comment, dict) and comment.get("text")
            ]
            mark = self.db.get(EvidenceMark, (self.incident.id, key))
            if mark is None:
                mark = EvidenceMark(incident_id=self.incident.id, key=key, updated_at=now_iso())
                self.db.add(mark)
            mark.flagged = True
            mark.note = "\n".join(part for part in (mark.note or "", *said) if part)
            mark.updated_by = _text(flag.get("flaggedBy"), 200)
            mark.updated_at = _text(flag.get("flaggedAt") or now_iso(), 40)
        return left


def move(db: OrmSession, incident: Incident) -> dict[str, int] | None:
    """Move the host evidence an incident's document holds into the tables (the caller holds the
    incident locked, and commits). Returns what was moved, or None when the document held none."""
    doc = incident.doc or {}
    if not holds(doc):
        return None
    data = dict(doc.get("data") or {})
    mover = _Mover(db, incident)
    # The document is written once, as it is at the end: a write of an incident is one revision, and
    # what the caller changed in it and has not written yet goes with it. Until then nothing writes it.
    with db.no_autoflush:
        mover.eventlogs(data.get("eventlogs"))
        mover.browser(data.get("browser"))
        mover.endpoint(data.get("endpoint"))
        mover.commands(data.get("commands"))
        mover.flush()
        for row in [source for source in db.new if isinstance(source, EvidenceSource)]:
            db.flush([row])
        for row in db.scalars(
            select(EvidenceSource).where(EvidenceSource.incident_id == incident.id, EvidenceSource.legacy)
        ):
            if row.kept == 0 and row.read_count == 0:
                count, first, last = db.execute(
                    select(func.count(), func.min(EvidenceRecord.ts), func.max(EvidenceRecord.ts)).where(
                        EvidenceRecord.source_id == row.id
                    )
                ).one()
                row.kept = row.read_count = int(count or 0)
                row.first_ts, row.last_ts = first, last
        doc = dict(doc)
        doc["flags"] = mover.marks(doc.get("flags"))
        if doc["flags"] is None:
            doc.pop("flags")
        doc["data"] = {key: value for key, value in data.items() if key not in KEYS}
        incident.doc = doc
        flag_modified(incident, "doc")
    # Read from what the document held, after the document was set: what this writes, it writes once.
    _indicators(db, incident, data)
    return {"sources": mover.sources, "records": mover.records}


def _indicators(db: OrmSession, incident: Incident, data: dict[str, Any]) -> None:
    """The indicators 6.x read out of host evidence in the document (the sites visited, what was
    downloaded and from where, what the commands, the endpoint artifacts and the events name)
    stay indicators of the incident: they are read once more here, before the data leaves the
    document, and kept as found indicators by the rules and within the limit of the setting
    (``indicators_found``). Nothing when incidents are not read for indicators."""
    from .. import indicators_found

    cfg = indicators_found.config(db)
    if not indicators_found.on_for(cfg, incident):
        return

    def rows(held: Any, name: str) -> list[dict[str, Any]]:
        held = held.get(name) if isinstance(held, dict) else None
        return [row for row in held if isinstance(row, dict)] if isinstance(held, list) else []

    def groups(held: Any, name: str) -> list[Any]:
        held = held.get(name) if isinstance(held, dict) else None
        return list(held.values()) if isinstance(held, dict) else []

    def values() -> Iterator[tuple[str, str]]:
        for entry in groups(data.get("browser"), "browsers"):
            for profile in groups(entry, "profiles"):
                for listed in ("history", "downloads"):
                    for row in rows(profile, listed):
                        yield "evidence.browser", row.get("url")
                        yield "evidence.browser", row.get("referrer")
        for shell in groups(data.get("commands"), "shells"):
            for row in rows(shell, "commands"):
                yield "evidence.commands", row.get("command")
        for category in groups(data.get("endpoint"), "categories"):
            for source in groups(category, "sources"):
                for row in rows(source, "records"):
                    for value in (row.get("fields") or {}).values() if isinstance(row.get("fields"), dict) else ():
                        yield "evidence.endpoint", value
        for channel in groups(data.get("eventlogs"), "channels"):
            for row in rows(channel, "events"):
                for value in (row.get("data") or {}).values() if isinstance(row.get("data"), dict) else ():
                    yield "evidence.eventlog", value

    result = indicators_found.texts(values(), cfg, indicators_found.known_of(db))
    indicators_found.keep(db, incident, "evidence", result, cfg, whole=False)


# --------------------------------------------------------------------------- #
# Every incident, once, after the upgrade                                     #
# --------------------------------------------------------------------------- #
def state(db: OrmSession) -> dict[str, Any]:
    row = db.get(Setting, SETTINGS_ID)
    return dict((row.doc if row else None) or {})


def _keep(db: OrmSession, doc: dict[str, Any]) -> None:
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
    else:
        row.doc = doc
        flag_modified(row, "doc")


def sweep(holder: str, budget: float = 30.0, now: float | None = None) -> dict[str, Any]:
    """One pass: move the incidents after the one the last pass ended at, for ``budget`` seconds.
    Returns the state: ``{"cursor", "moved", "records", "done"}``."""
    from ..core.db import SessionLocal

    clock = time.monotonic()
    with SessionLocal() as db:
        held = state(db)
        if held.get("done") or not leases.take(db, LEASE, holder, LEASE_SECONDS, now):
            return held
    while time.monotonic() - clock < budget and not leases.stopping():
        with SessionLocal() as db:
            cursor = str(held.get("cursor") or "")
            following = db.scalars(
                select(Incident.id).where(Incident.id > cursor).order_by(Incident.id).limit(1)
            ).first()
            if following is None:
                held = {**held, "done": True, "finishedAt": now_iso()}
                _keep(db, held)
                db.commit()
                logger.info(
                    "Host evidence of before 7.0: every incident was looked at (%s moved)", held.get("moved", 0)
                )
                return held
            try:
                incident = lock_incident(db, following)
                moved = move(db, incident) if incident is not None else None
                if moved is not None:
                    from ..iocs import reindex_incident

                    db.flush()
                    reindex_incident(db, incident)
                    held["moved"] = int(held.get("moved") or 0) + 1
                    held["records"] = int(held.get("records") or 0) + moved["records"]
            except Exception:  # noqa: BLE001 - one document that cannot be moved must not hold the others back
                # Its document is left as it is, and it is named: nothing of it was lost, and it is
                # moved the next time it is written, or by hand once the reason is known.
                db.rollback()
                logger.exception("The host evidence of the incident %s could not be moved", following)
                held["failed"] = [*(held.get("failed") or []), following][:FAILED_KEPT]
            held["cursor"] = following
            _keep(db, held)
            db.commit()
            leases.take(db, LEASE, holder, LEASE_SECONDS)
    return held


def _loop() -> None:
    holder = uuid.uuid4().hex
    leases.wait(20)  # let the API start
    while not leases.stopping():
        try:
            if sweep(holder).get("done"):
                return
        except Exception:  # noqa: BLE001 - one incident that cannot be moved must not stop the server
            logger.exception("Moving the host evidence of before 7.0 failed on a pass: tried again")
            leases.wait(60)
        leases.wait(1)


def start() -> None:
    """Start the loop in this process (the API process), once."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="nik-evidence-legacy", daemon=True).start()
