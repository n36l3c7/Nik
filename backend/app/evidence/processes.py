"""The processes and the logons a reading of host evidence finds, and the linking of the processes into trees (7.0).

**What the worker says.** After the ``r`` line of a record, a parser may write lines of what the record is of:
``proc`` (a process started), ``proc_end`` (one ended) and ``logon`` (a logon or an attempt). They name the
record by its key. ``Held`` collects them while a file is read and writes them after each batch of records
(the record is then stored), the way detections are: a record that another file of the incident held first has
the row it already has, and gives no second one.

**Linking.** A row of ``evidence_processes`` is made with what its log said of its parent (``parent_guid`` where
the log has one, ``ppid``, and the parent's image and command line). Linking finds the parent *in the evidence*
and writes ``parent_id``: the process of the same host with that ``parent_guid`` (Sysmon), else the latest one
with a ``pid`` equal to the ``ppid`` that started before it and had not ended. A process whose parent is not in
the evidence keeps ``parent_id`` empty and shows what the log said (a ghost parent: shown, not a row).

Linking works one host at a time, in start order, in chunks of ``CHUNK`` rows: what it holds is the chunk and a
dictionary of the latest process of each pid (the pids of a host, never its processes), and a guid is looked up
by the database for the chunk. A host of two million processes is read in a hundred chunks, each committed.
Running it again gives the same links and writes only the ones that changed.

**When.** A file read, a file read again and a file removed each leave the hosts they touched to be linked: held
work (``evidence-link``, by incident, its params the hosts), run by the thread that did the reading, or by the
sweeper after a restart. Two runs of one incident in this process wait for each other. After the links, the
process-chain rules are run over the same hosts (``chains.py``).
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Iterator
from typing import Any

from sqlalchemy import and_, bindparam, func, or_, select, text, update
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.orm import Session as OrmSession

from .. import work
from ..core.db import SessionLocal
from ..core.models import EvidenceLogon, EvidenceProcess, EvidenceRecord

logger = logging.getLogger("nik.evidence.processes")

LINK_WORK = "evidence-link"
CHUNK = 20_000
IN_MAX = 500
PENDING_MAX = 20_000  # lines held before they are written, whatever the size of the batch
LATER_MAX = 100_000  # ends of a process that matched none yet, kept for the end of the file
HOSTS_MAX = 500  # hosts a piece of linking names; past it, every host of the incident is linked
COMMAND_MAX = 8000
OUTCOMES = ("success", "failure", "logoff", "explicit", "privileged")
LOGON_TYPES_MAX = 99


# --------------------------------------------------------------------------- #
# Small things                                                                #
# --------------------------------------------------------------------------- #
def _whole(value: Any) -> int | None:
    """A whole number out of what the worker said (a text of digits is one), else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value == int(value):
        return int(value)
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    return None


def _text(value: Any, size: int) -> str:
    return "" if value is None else str(value)[:size]


def _parts(items: list[Any], size: int = IN_MAX) -> Iterator[list[Any]]:
    for start in range(0, len(items), size):
        yield items[start : start + size]


def _insert(db: OrmSession) -> Any:
    return postgresql.insert if db.get_bind().dialect.name == "postgresql" else sqlite.insert


def _placed(db: OrmSession, incident_id: str, keys: set[str]) -> dict[str, int]:
    """The ids of the records of the incident with these keys, whichever file of it holds them."""
    found: dict[str, int] = {}
    for part in _parts(sorted(keys)):
        rows = db.execute(
            select(EvidenceRecord.key, EvidenceRecord.id).where(
                EvidenceRecord.incident_id == incident_id, EvidenceRecord.key.in_(part)
            )
        )
        found.update(rows.all())
    return found


# --------------------------------------------------------------------------- #
# Keeping what a reading says                                                  #
# --------------------------------------------------------------------------- #
class Held:
    """The ``proc``, ``proc_end`` and ``logon`` lines of one reading: collected, then written."""

    def __init__(self, source: Any):
        self.source = source  # the file; what it says of its host comes while it is read
        self.incident_id = source.incident_id
        self.source_id = source.id
        self.procs: list[dict[str, Any]] = []
        self.ends: list[dict[str, Any]] = []
        self.logons: list[dict[str, Any]] = []
        self.later: list[dict[str, Any]] = []  # ends that found no process yet
        self.processes = 0  # rows stored
        self.logon_rows = 0
        self.hosts: set[str] = set()

    def add(self, event: dict[str, Any]) -> bool:
        """Take a line; whether it was one of these."""
        kind = event.get("t")
        if kind == "proc":
            self.procs.append(event)
        elif kind == "proc_end":
            self.ends.append(event)
        elif kind == "logon":
            self.logons.append(event)
        else:
            return False
        return True

    @property
    def host(self) -> str:
        return self.source.host or ""

    def __bool__(self) -> bool:
        return bool(self.procs or self.ends or self.logons)

    def full(self) -> bool:
        return len(self.procs) + len(self.ends) + len(self.logons) >= PENDING_MAX

    # ---- writing
    def write(self, db: OrmSession) -> None:
        """Write what is held (the caller commits). The records the lines name are stored by now."""
        if not self:
            return
        procs, ends, logons = self.procs, self.ends, self.logons
        self.procs, self.ends, self.logons = [], [], []
        placed = _placed(db, self.incident_id, {str(e.get("key")) for e in (*procs, *logons) if e.get("key")})
        if procs:
            self._write_processes(db, procs, placed)
        if logons:
            self._write_logons(db, logons, placed)
        if ends:
            self.later = [*self.later, *self._write_ends(db, ends)][:LATER_MAX]

    def retry(self, db: OrmSession) -> None:
        """The end of the file: the ends that found no process meanwhile are tried once more."""
        if self.later:
            self._write_ends(db, self.later)
            self.later = []

    def _taken(self, db: OrmSession, table: Any, ids: list[int]) -> set[int]:
        """The records that already have a row (another file of the incident gave the record first)."""
        held: set[int] = set()
        for part in _parts(ids):
            held.update(db.scalars(select(table.c.record_id).where(table.c.record_id.in_(part))))
        return held

    def _write_processes(self, db: OrmSession, events: list[dict[str, Any]], placed: dict[str, int]) -> None:
        table = EvidenceProcess.__table__
        taken = self._taken(db, table, [placed[e["key"]] for e in events if e.get("key") in placed])
        rows: list[dict[str, Any]] = []
        for event in events:
            record_id = placed.get(str(event.get("key")))
            if record_id is None or record_id in taken:
                continue
            taken.add(record_id)
            ts = _whole(event.get("ts"))
            pid = _whole(event.get("pid"))
            host = _text(event.get("host") or self.host, 255)
            guid = _text(event.get("guid"), 80) or f"{host[:40]}|{pid if pid is not None else ''}|{ts or ''}"[:80]
            hashes = event.get("hashes")
            rows.append(
                {
                    "incident_id": self.incident_id,
                    "source_id": self.source_id,
                    "record_id": record_id,
                    "host": host,
                    "guid": guid,
                    "parent_guid": _text(event.get("parent_guid"), 80),
                    "pid": pid,
                    "ppid": _whole(event.get("ppid")),
                    "image": _text(event.get("image"), 1000),
                    "command_line": _text(event.get("command_line"), COMMAND_MAX),
                    "username": _text(event.get("user"), 255),
                    "logon_id": _text(event.get("logon_id"), 40),
                    "integrity": _text(event.get("integrity"), 20),
                    "start_ts": ts,
                    "end_ts": None,
                    "level": None,
                    "parent_id": None,
                    "parent_image": _text(event.get("parent_image"), 1000),
                    "parent_command_line": _text(event.get("parent_command_line"), COMMAND_MAX),
                    "hashes": (
                        {str(k)[:20]: str(v)[:200] for k, v in list(hashes.items())[:10]}
                        if isinstance(hashes, dict)
                        else {}
                    ),
                }
            )
            self.hosts.add(host)
        for part in _parts(rows, 2000):
            db.execute(table.insert(), part)
        self.processes += len(rows)

    def _write_logons(self, db: OrmSession, events: list[dict[str, Any]], placed: dict[str, int]) -> None:
        table = EvidenceLogon.__table__
        taken = self._taken(db, table, [placed[e["key"]] for e in events if e.get("key") in placed])
        rows: list[dict[str, Any]] = []
        for event in events:
            record_id = placed.get(str(event.get("key")))
            outcome = event.get("outcome")
            if record_id is None or record_id in taken or outcome not in OUTCOMES:
                continue
            taken.add(record_id)
            kind = _whole(event.get("logon_type"))
            rows.append(
                {
                    "incident_id": self.incident_id,
                    "source_id": self.source_id,
                    "record_id": record_id,
                    "ts": _whole(event.get("ts")),
                    "host": _text(event.get("host") or self.host, 255),
                    "source_host": _text(event.get("source_host"), 255),
                    "source_ip": _text(event.get("source_ip"), 64),
                    "username": _text(event.get("user"), 255),
                    "domain": _text(event.get("domain"), 255),
                    "logon_type": kind if kind is not None and 0 <= kind <= LOGON_TYPES_MAX else None,
                    "logon_id": _text(event.get("logon_id"), 40),
                    "outcome": outcome,
                    "method": _text(event.get("method"), 40),
                    "status": _text(event.get("status"), 120),
                    "target_host": _text(event.get("target_host"), 255),
                }
            )
        for part in _parts(rows, 2000):
            db.execute(table.insert(), part)
        self.logon_rows += len(rows)

    def _write_ends(self, db: OrmSession, ends: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Give each ended process its ``end_ts``: the process with that guid, else the latest one of the host
        with that pid that started before the end and has not ended. Returns the ends that matched none."""
        table = EvidenceProcess.__table__
        updates: list[dict[str, Any]] = []
        used: set[int] = set()
        left: list[dict[str, Any]] = []
        clean: list[tuple[str, str, int | None, int | None]] = []  # host, guid, pid, ts
        for event in ends:
            ts = _whole(event.get("ts"))
            if ts is None:
                continue
            clean.append(
                (_text(event.get("host") or self.host, 255), _text(event.get("guid"), 80), _whole(event.get("pid")), ts)
            )
        by_guid: dict[tuple[str, str], int] = {}
        guids = sorted({guid for _host, guid, _pid, _ts in clean if guid})
        for part in _parts(guids):
            found = db.execute(
                select(table.c.host, table.c.guid, table.c.id).where(
                    table.c.incident_id == self.incident_id, table.c.guid.in_(part), table.c.end_ts.is_(None)
                )
            )
            for host, guid, process_id in found:
                by_guid.setdefault((host, guid), process_id)
        pending: list[tuple[str, int, int]] = []  # host, pid, ts of the ends to find by pid
        for host, guid, pid, ts in sorted(clean, key=lambda item: item[3] or 0):
            process_id = by_guid.get((host, guid)) if guid else None
            if process_id is not None and process_id not in used:
                used.add(process_id)
                updates.append({"b_id": process_id, "b_end": ts})
            elif pid is not None:
                pending.append((host, pid, ts))
            else:
                left.append({"host": host, "guid": guid, "pid": pid, "ts": ts})
        if pending:
            wanted = sorted({pid for _host, pid, _ts in pending})
            held: dict[tuple[str, int], list[tuple[int, int]]] = {}
            for part in _parts(wanted):
                found = db.execute(
                    select(table.c.host, table.c.pid, table.c.id, table.c.start_ts).where(
                        table.c.incident_id == self.incident_id, table.c.pid.in_(part), table.c.end_ts.is_(None)
                    )
                )
                for host, pid, process_id, start in found:
                    held.setdefault((host, pid), []).append((start if start is not None else -1, process_id))
            for items in held.values():
                items.sort()
            for host, pid, ts in pending:
                items = held.get((host, pid)) or []
                chosen = next(
                    (item for item in reversed(items) if item[0] <= ts and item[1] not in used),
                    None,
                )
                if chosen is None:
                    left.append({"host": host, "guid": "", "pid": pid, "ts": ts})
                    continue
                used.add(chosen[1])
                updates.append({"b_id": chosen[1], "b_end": ts})
        if updates:
            statement = update(table).where(table.c.id == bindparam("b_id")).values(end_ts=bindparam("b_end"))
            for part in _parts(updates, 2000):
                db.execute(statement, part)
        return left


# --------------------------------------------------------------------------- #
# What a source leaves                                                        #
# --------------------------------------------------------------------------- #
def hosts_of(db: OrmSession, source_id: str) -> set[str]:
    """The hosts the processes of a source are of (what is to be linked again when the source goes)."""
    return set(db.scalars(select(EvidenceProcess.host).where(EvidenceProcess.source_id == source_id).distinct()))


def detach(db: OrmSession, source_id: str) -> None:
    """Before the processes of a source are removed: the processes of other files that name them as their
    parent lose that link (linking finds them another, if there is one)."""
    mine = select(EvidenceProcess.id).where(EvidenceProcess.source_id == source_id)
    db.execute(
        update(EvidenceProcess)
        .where(EvidenceProcess.parent_id.in_(mine), EvidenceProcess.source_id != source_id)
        .values(parent_id=None)
    )


# --------------------------------------------------------------------------- #
# Linking                                                                     #
# --------------------------------------------------------------------------- #
def _chunks(incident_id: str, host: str) -> Iterator[list[Any]]:
    """The processes of a host in start order, ``CHUNK`` at a time, each in a session of its own: the ones with
    no start time first (by id), then the others (by start and id). Keyset paging, never an offset."""
    p = EvidenceProcess
    columns = (p.id, p.pid, p.ppid, p.parent_guid, p.start_ts, p.end_ts, p.parent_id)
    base = select(*columns).where(p.incident_id == incident_id, p.host == host)
    last_id = 0
    while True:
        with SessionLocal() as db:
            rows = db.execute(base.where(p.start_ts.is_(None), p.id > last_id).order_by(p.id).limit(CHUNK)).all()
        if not rows:
            break
        yield rows
        last_id = rows[-1].id
    after: tuple[int, int] | None = None
    while True:
        query = base.where(p.start_ts.is_not(None))
        if after is not None:
            query = query.where(or_(p.start_ts > after[0], and_(p.start_ts == after[0], p.id > after[1])))
        with SessionLocal() as db:
            rows = db.execute(query.order_by(p.start_ts, p.id).limit(CHUNK)).all()
        if not rows:
            break
        yield rows
        after = (rows[-1].start_ts, rows[-1].id)


def _set_parents(db: OrmSession, pairs: list[tuple[int, int | None]]) -> None:
    """Write ``parent_id`` for the processes whose link changed."""
    if not pairs:
        return
    if db.get_bind().dialect.name == "postgresql":
        for part in _parts(pairs, CHUNK):
            db.execute(
                text(
                    "UPDATE evidence_processes AS p SET parent_id = v.parent "
                    "FROM unnest(CAST(:ids AS BIGINT[]), CAST(:parents AS BIGINT[])) AS v(id, parent) "
                    "WHERE p.id = v.id"
                ),
                {"ids": [item[0] for item in part], "parents": [item[1] for item in part]},
            )
        return
    table = EvidenceProcess.__table__
    statement = update(table).where(table.c.id == bindparam("b_id")).values(parent_id=bindparam("b_parent"))
    for part in _parts(pairs, 5000):
        db.execute(statement, [{"b_id": item[0], "b_parent": item[1]} for item in part])


def link_host(incident_id: str, host: str, claim: work.Claim | None = None) -> dict[str, int]:
    """Find the parent of every process of a host that the evidence holds. Returns ``{"processes",
    "linked", "changed"}``."""
    p = EvidenceProcess
    # The latest process of each pid so far: (id, end). Processes come in start order, so the latest one that
    # started before a child is the last one written under its pid.
    live: dict[int, tuple[int, int | None]] = {}
    seen = linked = changed = 0
    for rows in _chunks(incident_id, host):
        guids = sorted({row.parent_guid for row in rows if row.parent_guid})
        by_guid: dict[str, int] = {}
        pairs: list[tuple[int, int | None]] = []
        with SessionLocal() as db:
            for part in _parts(guids):
                found = db.execute(
                    select(p.guid, p.id).where(p.incident_id == incident_id, p.host == host, p.guid.in_(part))
                )
                for guid, process_id in found:
                    if guid not in by_guid or process_id < by_guid[guid]:
                        by_guid[guid] = process_id
            for row in rows:
                parent: int | None = None
                if row.parent_guid:
                    parent = by_guid.get(row.parent_guid)
                elif row.ppid is not None:
                    held = live.get(row.ppid)
                    if held is not None and (held[1] is None or row.start_ts is None or held[1] >= row.start_ts):
                        parent = held[0]
                if parent == row.id:
                    parent = None
                if row.pid is not None:
                    live[row.pid] = (row.id, row.end_ts)
                if parent is not None:
                    linked += 1
                if parent != row.parent_id:
                    pairs.append((row.id, parent))
            _set_parents(db, pairs)
            db.commit()
        seen += len(rows)
        changed += len(pairs)
        if claim is not None:
            claim.progress(f"{host}: {seen} processes linked"[:200])
    return {"processes": seen, "linked": linked, "changed": changed}


# --------------------------------------------------------------------------- #
# The work                                                                    #
# --------------------------------------------------------------------------- #
_locks: dict[str, threading.Lock] = {}
_locks_guard = threading.Lock()


def _lock_of(incident_id: str) -> threading.Lock:
    with _locks_guard:
        return _locks.setdefault(incident_id, threading.Lock())


def want(db: OrmSession, incident_id: str, hosts: set[str]) -> None:
    """Write down that these hosts are to be linked (the caller commits), with the hosts already waiting."""
    from ..core.models import WorkClaim

    row = db.get(WorkClaim, (LINK_WORK, incident_id))
    held: dict[str, Any] = dict(row.params or {}) if row is not None and row.state in work.ACTIVE else {}
    names = set(held.get("hosts") or ()) | set(hosts)
    params: dict[str, Any] = {"all": True} if held.get("all") or len(names) > HOSTS_MAX else {"hosts": sorted(names)}
    work.want(db, LINK_WORK, incident_id, params)


def targets(db: OrmSession, incident_id: str, params: dict[str, Any]) -> list[str]:
    """The hosts a piece of work links: those it names, or every host of the incident that has processes."""
    if params.get("all"):
        found = db.scalars(select(EvidenceProcess.host).where(EvidenceProcess.incident_id == incident_id).distinct())
        return sorted(set(found))
    return sorted(str(name) for name in params.get("hosts") or ())


def run(incident_id: str) -> None:
    """Do the linking that was asked for this incident, then run the chain rules over the same hosts. Run held;
    a run of this incident already going on here is waited for."""
    from . import chains

    with _lock_of(incident_id):
        try:
            with work.hold(LINK_WORK, incident_id) as claim:
                with SessionLocal() as db:
                    hosts = targets(db, incident_id, claim.params)
                for host in hosts:
                    link_host(incident_id, host, claim)
                if hosts:
                    chains.run(incident_id, hosts, claim)
                    chains.sync_levels(incident_id, hosts)
                    chains.refresh(incident_id, hosts)
        except work.Taken:
            return


def after(incident_id: str, hosts: set[str]) -> None:
    """The hosts of a reading or a removal are to be linked: write that down, and do it."""
    if not hosts:
        return
    with SessionLocal() as db:
        want(db, incident_id, hosts)
        db.commit()
    run(incident_id)


def start(incident_id: str, _params: dict[str, Any] | None = None) -> bool:
    """Do it in a thread of this process (what a restart does with the work that was wanted)."""
    with SessionLocal() as db:
        from ..core.models import Incident

        if db.get(Incident, incident_id) is None:
            return False
    work.thread(run, incident_id)
    return True


def _fail(_db: OrmSession, ref: str, sentence: str) -> None:
    logger.warning("The linking of the processes of %s was given up: %s", ref, sentence)


work.register(work.Kind(LINK_WORK, "the processes of an incident being linked", "again", start=start, fail=_fail))


def counts(db: OrmSession, incident_id: str) -> dict[str, int]:
    """How many processes and logons the incident holds (``count`` over the incident's index)."""
    return {
        "processes": int(
            db.scalar(
                select(func.count()).select_from(EvidenceProcess).where(EvidenceProcess.incident_id == incident_id)
            )
            or 0
        ),
        "logons": int(
            db.scalar(select(func.count()).select_from(EvidenceLogon).where(EvidenceLogon.incident_id == incident_id))
            or 0
        ),
    }
