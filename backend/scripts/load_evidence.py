"""A load test of host evidence: feed N generated records to a database and time what the screens ask of them.

    python scripts/load_evidence.py --records 1000000 --max-seconds 5

Run it from ``backend/``, against a database that is migrated (``alembic upgrade head``) and that nobody is
using: ``DATABASE_URL`` says which (PostgreSQL for a figure that means anything; SQLite works for a small run).
It makes an incident, then reads four generated files of it (an event log, an NTFS volume, endpoint artifacts, a
syslog) through ``evidence.parse.read``, the code that stores what the forensics worker sends: only the worker's
answer is faked, so the batches, the indexes, the detections and the report are the real ones. Then,
through the API (in this process, no network), it times the first page of each screen:

    records (first page and its count), a text search in the records, records of one event, flagged records,
    the "events that matter" count, the summary of the header, the histogram, a stack of a column and of a
    field of ``data``, the detections, and the global search (Ctrl+K).

Each is asked ``--runs`` times after one that warms the caches; the table gives the slowest of them. The exit
code is 1 when any is slower than ``--max-seconds`` (or does not answer 200); a load or a database that fails stops
it with a message and a non-zero code too: that is what CI looks at.

    --keep         leave the incident (and its records) in the database when done; without it they are deleted
    --skip-load    do not load: time the queries on the incident given by ``--incident``
    --files N      files to split the records into (4 or more, spread over the four kinds)
    --detections   detections per 1,000 records (default 3)

It needs a database nobody else uses because it creates the first administrator when there is none; when users
exist, give ``--user`` and ``--password`` of an account that can read incidents. Nothing is sent anywhere.
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

# The application reads its settings when it is imported: say what a test of this kind needs first.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("RATE_LIMIT_DEFAULT", "1000000/minute")
os.environ.setdefault("COOKIE_SECURE", "false")
os.environ.setdefault("API_BACKGROUND", "false")
os.environ.setdefault("ENRICHMENT_WORKER", "false")

BATCH_NOTE = "a generated file (scripts/load_evidence.py)"
HOSTS = [f"WKS-{n:03d}" for n in range(60)] + [f"SRV-{n:02d}" for n in range(12)]
USERS = ["alice", "bob", "carol", "dave", "svc_backup", "svc_sql", "SYSTEM", "administrator", "guest", "operator"]
CHANNELS = [
    ("Security", (4624, 4624, 4624, 4625, 4634, 4648, 4672, 4688, 4689, 4768)),
    ("System", (7036, 7045, 7040, 6005, 6006, 41)),
    ("Microsoft-Windows-Sysmon/Operational", (1, 3, 5, 7, 10, 11, 13, 22)),
    ("Application", (1000, 1001, 1002, 11707)),
]
PROGRAMS = [
    "svchost.exe",
    "powershell.exe",
    "cmd.exe",
    "chrome.exe",
    "outlook.exe",
    "python.exe",
    "msedge.exe",
    "wmic.exe",
]
FOLDERS = [
    "Users\\{u}\\AppData\\Local\\Temp",
    "Windows\\System32",
    "Program Files\\Vendor\\App",
    "Users\\{u}\\Downloads",
]
SYSLOG = [
    ("sshd", "Failed password for invalid user {u} from {ip} port {port} ssh2"),
    ("sshd", "Accepted publickey for {u} from {ip} port {port} ssh2"),
    ("sudo", "{u} : TTY=pts/0 ; PWD=/home/{u} ; USER=root ; COMMAND=/usr/bin/apt update"),
    ("CRON", "({u}) CMD (/usr/local/bin/backup.sh >/dev/null 2>&1)"),
    ("systemd", "Started Session {port} of user {u}."),
    ("kernel", "[UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=10.0.0.5 PROTO=TCP SPT={port} DPT=22"),
]
RULES = {
    "load-r1": {
        "title": "Suspicious PowerShell command line",
        "author": "Nik",
        "level": 4,
        "tags": ["attack.t1059.001"],
    },
    "load-r2": {"title": "Failed logon burst", "author": "Nik", "level": 3, "tags": ["attack.t1110"]},
    "load-r3": {"title": "New service installed", "author": "Nik", "level": 3, "tags": ["attack.t1543.003"]},
    "load-r4": {"title": "Executable in a temporary folder", "author": "Nik", "level": 2, "tags": ["attack.t1204"]},
    "load-r5": {"title": "Event log cleared", "author": "Nik", "level": 5, "tags": ["attack.t1070.001"]},
}
KINDS = (
    # kind of the section, name of the file, share of the records
    ("eventlog", "Security-{n}.evtx", 0.40),
    ("disk", "$MFT-{n}", 0.30),
    ("endpoint", "autoruns-{n}.csv", 0.10),
    ("syslog", "auth-{n}.log", 0.20),
)
RARE = "canary-7f3a"
START = 1_700_000_000_000  # 2023-11-14: the first record
SPAN = 90 * 86_400_000  # records fall in these 90 days


# --------------------------------------------------------------------------- #
# The records                                                                  #
# --------------------------------------------------------------------------- #
def _record(kind: str, i: int, number: int, rng: random.Random, total: int) -> dict[str, Any]:
    """The line the worker would send for record ``i`` of a file of ``total``: realistic in size and in the
    spread of its values (a few hosts and users, many event ids), unique in its key."""
    host = HOSTS[rng.randrange(len(HOSTS))]
    user = USERS[rng.randrange(len(USERS))]
    ts = START + (i * SPAN) // max(1, total) + rng.randrange(0, 30_000)
    ip = f"10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(1, 255)}"
    base: dict[str, Any] = {"t": "r", "seq": i, "host": host, "username": user, "ts": ts, "trunc": False}
    word = f" {RARE}" if number % 50_000 == 7 else ""
    if kind == "eventlog":
        channel, ids = CHANNELS[rng.randrange(len(CHANNELS))]
        event_id = ids[rng.randrange(len(ids))]
        program = PROGRAMS[rng.randrange(len(PROGRAMS))]
        return {
            **base,
            "key": f"evtx:{host}:{channel}:{number}",
            "type": "event",
            "event_id": event_id,
            "channel": channel,
            "summary": f"{event_id}: {user} on {host} ran {program} from {ip}{word}",
            "data": {
                "EventID": event_id,
                "Computer": host,
                "Channel": channel,
                "TargetUserName": user,
                "TargetDomainName": "CORP",
                "LogonType": str(rng.randrange(2, 11)),
                "IpAddress": ip,
                "ProcessName": f"C:\\Windows\\System32\\{program}",
                "CommandLine": f"C:\\Windows\\System32\\{program} -k netsvcs -p -s Schedule",
                "SubjectLogonId": f"0x{rng.randrange(1 << 20):x}",
                "WorkstationName": host,
                "Status": "0x0",
            },
            "loc": {"offset": 4096 + i * 512, "length": 512},
        }
    if kind == "disk":
        folder = FOLDERS[rng.randrange(len(FOLDERS))].format(u=user)
        name = f"f{rng.randrange(10**7):07d}.{('dll', 'tmp', 'exe', 'txt', 'lnk', 'log')[rng.randrange(6)]}"
        return {
            **base,
            "key": f"mft:{number}:{rng.randrange(1, 9)}",
            "type": "file",
            "summary": f"C:\\{folder}\\{name} created{word}",
            "data": {
                "Path": f"C:\\{folder}\\{name}",
                "Name": name,
                "Size": rng.randrange(0, 5_000_000),
                "InUse": True,
                "IsDirectory": False,
                "Created": ts,
                "Modified": ts + rng.randrange(0, 86_400_000),
                "MftChanged": ts + rng.randrange(0, 86_400_000),
                "ParentEntry": rng.randrange(1_000_000),
                "Flags": "ARCHIVE",
                "Sid": f"S-1-5-21-1000-{rng.randrange(1000, 1100)}",
            },
            "loc": {"offset": 1024 * number, "length": 1024},
        }
    if kind == "endpoint":
        program = PROGRAMS[rng.randrange(len(PROGRAMS))]
        return {
            **base,
            "key": f"endpoint:autoruns:{number}",
            "type": "persistence",
            "summary": f"Run key {program} for {user}{word}",
            "data": {
                "name": f"Updater{rng.randrange(1000)}",
                "command": f"C:\\Users\\{user}\\AppData\\Roaming\\{program} --silent",
                "location": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "user": user,
                "signer": ("", "Microsoft Corporation", "Unknown")[rng.randrange(3)],
            },
            "loc": {"line": i + 2},
        }
    channel, line = SYSLOG[rng.randrange(len(SYSLOG))]
    text = line.format(u=user, ip=ip, port=rng.randrange(1024, 65535))
    return {
        **base,
        "key": f"syslog:{host}:{number}",
        "type": "line",
        "channel": channel,
        "summary": f"{host} {channel}: {text}{word}",
        "data": {"program": channel, "message": text, "facility": "auth", "pid": rng.randrange(1, 40000)},
        "loc": {"line": i + 1},
    }


def stream(kind: str, count: int, first: int, per_1000: float, rng: random.Random) -> Iterator[dict[str, Any]]:
    """What the worker says of one file: its ``source`` line, the records (with a ``det`` after some), the ``end``."""
    yield {"t": "source", "parser": kind, "version": "2", "kind": kind, "source": kind, "host": HOSTS[0]}
    every = max(1, round(1000 / per_1000)) if per_1000 else 0
    names = list(RULES)
    for i in range(count):
        row = _record(kind, i, first + i, rng, count)
        yield row
        if every and i % every == 0:
            yield {"t": "det", "key": row["key"], "rule": names[rng.randrange(len(names))], "records": []}
    yield {"t": "end", "in_file": count, "read": count}


# --------------------------------------------------------------------------- #
# Loading                                                                      #
# --------------------------------------------------------------------------- #
def load(records: int, files: int, per_1000: float, seed: int) -> tuple[str, float, int]:
    """Make the incident and read the files. Returns its id, the seconds it took and the records kept."""
    from app.core.db import SessionLocal
    from app.core.models import EvidenceSource, Incident
    from app.evidence import imports, originals, parse
    from app.sigma import ruleset

    rng = random.Random(seed)
    incident_id = f"load-{int(time.time())}"
    with SessionLocal() as db:
        db.add(Incident(id=incident_id, doc={"name": f"Load test of {records} records"}, name="Load test"))
        db.commit()
    # Each kind has its share of the records, in as many files as ``files`` allows (at least one each).
    plan: list[tuple[str, int]] = []
    per_kind = max(1, files // len(KINDS))
    for kind, _name, share in KINDS:
        plan.extend((kind, int(records * share / per_kind)) for _ in range(per_kind))
    plan[-1] = (plan[-1][0], plan[-1][1] + records - sum(count for _kind, count in plan))
    sources: list[tuple[str, str, int]] = []
    with SessionLocal() as db:
        for position, (kind, count) in enumerate(plan):
            pattern = next(name for known, name, _share in KINDS if known == kind)
            name = pattern.format(n=position)
            sha256 = originals.keep_bytes(f"{BATCH_NOTE} {incident_id} {position}".encode() + os.urandom(16))
            row = imports.accept(db, incident_id, sha256, 64, name, {"kind": kind}, "load-test")
            sources.append((row.id, kind, count))
        db.commit()

    # What is faked is the worker alone: its rules (a set the worker would have been given) and its answer.
    first = {"n": 0}
    answers: dict[str, Iterator[dict[str, Any]]] = {}

    def faked(_sha256: str, body: dict[str, Any], _job: str, route: str = "/parse") -> Iterator[dict[str, Any]]:
        yield from answers[body["fileName"]]

    parse.configured = lambda: True
    parse._events = faked  # noqa: SLF001
    ruleset.current = lambda _db: ruleset.Set("0" * 64, b"", len(RULES), RULES) if per_1000 else None
    ruleset.hours = lambda _db, _incident: None

    started = time.monotonic()
    kept = 0
    for source_id, kind, count in sources:
        with SessionLocal() as db:
            name = db.get(EvidenceSource, source_id).file_name
        answers[name] = stream(kind, count, first["n"], per_1000, rng)
        first["n"] += count
        began = time.monotonic()
        parse.read(source_id)
        with SessionLocal() as db:
            row = db.get(EvidenceSource, source_id)
            kept += row.kept
            print(
                f"  {name}: {row.kept} kept of {row.read_count}, {row.state}/{row.read}, "
                f"{row.read_count / max(0.001, time.monotonic() - began):.0f} records/s",
                flush=True,
            )
            if row.state != "done":
                raise SystemExit(f"{name} was not read: {row.error or row.state}")
    return incident_id, time.monotonic() - started, kept


# --------------------------------------------------------------------------- #
# The queries                                                                  #
# --------------------------------------------------------------------------- #
def queries(incident_id: str, rare: str) -> list[tuple[str, str, dict[str, Any]]]:
    """``(what the screen does, path, params)``: the first request of each screen over the incident."""
    base = f"/api/incidents/{incident_id}/evidence"
    return [
        ("records, first page (with its count)", f"{base}/records", {"limit": 100}),
        ("records, one section", f"{base}/records", {"limit": 100, "kind": "eventlog"}),
        ("records, text search (a rare word)", f"{base}/records", {"limit": 100, "q": rare}),
        ("records, text search (a common word)", f"{base}/records", {"limit": 100, "q": "created"}),
        ("records, one event id", f"{base}/records", {"limit": 100, "kind": "eventlog", "eventId": 4624}),
        ("records, one host", f"{base}/records", {"limit": 100, "host": HOSTS[3]}),
        (
            "records, a window of one hour",
            f"{base}/records",
            {"limit": 100, "from": START + SPAN // 2, "to": START + SPAN // 2 + 3_600_000},
        ),
        (
            "records, events that matter (its count)",
            f"{base}/records",
            {"limit": 1, "kind": "eventlog", "matter": "true"},
        ),
        ("records, detections of a level or more", f"{base}/records", {"limit": 100, "level": 3}),
        ("records, with a rule", f"{base}/records", {"limit": 100, "rule": "load-r1"}),
        ("records, flagged", f"{base}/records", {"limit": 1, "flagged": "true"}),
        ("summary (the header)", f"{base}/summary", {}),
        ("histogram", f"{base}/histogram", {"buckets": 120}),
        ("histogram, one section", f"{base}/histogram", {"buckets": 120, "kind": "syslog"}),
        ("stack of a column (host)", f"{base}/stack", {"field": "host", "order": "common", "limit": 100}),
        (
            "stack of a column (channel, one section)",
            f"{base}/stack",
            {"field": "channel", "limit": 1, "kind": "eventlog"},
        ),
        ("stack of a field of data", f"{base}/stack", {"field": "data.TargetUserName", "order": "rare", "limit": 100}),
        ("detections", f"{base}/detections", {}),
        ("global search (Ctrl+K)", "/api/search", {"q": rare}),
    ]


def signed_in(client: Any, user: str | None, password: str | None) -> None:
    """A session that can read: the account given, else ``loadtest``, which the first run made as the first
    administrator (and that a later run of this tool signs in as)."""
    if not user:
        client.post("/api/users", json={"username": "loadtest", "password": "load-test-password"})  # first run only
        user, password = "loadtest", "load-test-password"
    answer = client.post("/api/auth/login", json={"username": user, "password": password})
    if answer.status_code != 200:
        raise SystemExit(
            f"Cannot sign in as {user} ({answer.status_code}): give --user and --password of an account that can read"
        )


def timed(client: Any, path: str, params: dict[str, Any], runs: int) -> tuple[float, float, int]:
    """Seconds of the fastest and of the slowest of ``runs`` requests (after one that warms), and the status."""
    client.get(path, params=params)
    seen: list[float] = []
    status = 0
    for _ in range(runs):
        began = time.perf_counter()
        answer = client.get(path, params=params)
        seen.append(time.perf_counter() - began)
        status = answer.status_code
    return min(seen), max(seen), status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--records", type=int, default=1_000_000, help="records to generate (default 1,000,000)")
    parser.add_argument("--files", type=int, default=4, help="files to split them into (default 4: one for each kind)")
    parser.add_argument("--detections", type=float, default=3.0, help="detections per 1,000 records (default 3)")
    parser.add_argument("--max-seconds", type=float, default=5.0, help="the slowest a query may be (default 5)")
    parser.add_argument("--runs", type=int, default=3, help="times each query is timed (default 3)")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--keep", action="store_true", help="leave the incident in the database")
    parser.add_argument("--skip-load", action="store_true", help="only time the queries, on --incident")
    parser.add_argument("--incident", default="", help="the incident of --skip-load")
    parser.add_argument("--user", default=None)
    parser.add_argument("--password", default=None)
    args = parser.parse_args()

    from fastapi.testclient import TestClient
    from sqlalchemy import text

    from app.core.db import SessionLocal, without_statement_limit
    from app.main import app

    logging.disable(logging.INFO)  # the application says each request it serves: the table is what is wanted

    with SessionLocal() as db:
        try:
            db.execute(text("SELECT 1 FROM evidence_records LIMIT 1"))
        except Exception as error:  # noqa: BLE001
            raise SystemExit(f"The database is not migrated (alembic upgrade head): {error}") from None
    incident_id, loaded = args.incident, 0.0
    if args.skip_load:
        if not incident_id:
            raise SystemExit("--skip-load needs --incident")
    else:
        print(f"Loading {args.records:,} records in {args.files} files…", flush=True)
        incident_id, loaded, kept = load(args.records, args.files, args.detections, args.seed)
        print(f"Loaded {kept:,} records in {loaded:.0f} s ({kept / max(0.001, loaded):.0f} records/s)\n", flush=True)

    with SessionLocal() as db:
        total = db.execute(
            text("SELECT count(*) FROM evidence_records WHERE incident_id = :i"), {"i": incident_id}
        ).scalar()
        size = (
            db.execute(text("SELECT pg_total_relation_size('evidence_records')")).scalar()
            if db.get_bind().dialect.name == "postgresql"
            else None
        )
    rare = RARE  # a word that one record in 50,000 holds
    client = TestClient(app)
    signed_in(client, args.user, args.password)
    rows: list[tuple[str, float, float, int]] = []
    for name, path, params in queries(incident_id, rare):
        fastest, slowest, status = timed(client, path, params, args.runs)
        rows.append((name, fastest, slowest, status))
    print(f"{'query':<46}{'fastest':>10}{'slowest':>10}  status")
    for name, fastest, slowest, status in rows:
        flag = "  SLOW" if slowest > args.max_seconds or status != 200 else ""
        print(f"{name:<46}{fastest:>9.3f}s{slowest:>9.3f}s  {status}{flag}")
    print(
        f"\nrecords in the incident: {total:,}"
        + (f"; evidence_records on disk: {size / 2**30:.2f} GiB with its indexes" if size else "")
    )
    if not args.keep and not args.skip_load:
        with SessionLocal() as db:
            without_statement_limit(db)  # a million records and what hangs on them: longer than a statement may take
            db.execute(text("DELETE FROM incidents WHERE id = :i"), {"i": incident_id})
            db.commit()
        print("The incident was deleted again.")
    bad = [name for name, _fast, slowest, status in rows if slowest > args.max_seconds or status != 200]
    if bad:
        print(f"\nTOO SLOW or failed (limit {args.max_seconds} s): " + "; ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
