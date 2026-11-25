"""Reading a file of host evidence (7.0): what the worker says becomes records and a parse report.

The worker is not there in these tests: ``parse._events`` is what it would have sent, written here.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import EvidenceMark, EvidenceRecord, EvidenceSource
from app.evidence import imports, originals, parse
from app.main import app as fastapi_app
from tests.conftest import make_key

SOURCE = {"t": "source", "parser": "evtx", "version": "1", "kind": "eventlog", "source": "evtx", "host": "WKS-042"}


def record(number: int, **more) -> dict:
    return {
        "t": "r",
        "key": f"evtx:WKS-042:Security:{number}",
        "type": "event",
        "ts": 1_700_000_000_000 + number * 1000,
        "seq": number,
        "event_id": 4624,
        "channel": "Security",
        "summary": f"logon {number}",
        "data": {"TargetUserName": "admin"},
        "loc": {"offset": 4096 + number * 512, "length": 512},
        "trunc": False,
        **more,
    }


def end(read: int, in_file: int | None = None) -> dict:
    return {"t": "end", "in_file": in_file, "read": read, "first_ts": None, "last_ts": None}


@pytest.fixture()
def incident(admin, monkeypatch):
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    client.post("/api/incidents", headers=key, json={"id": "ev-parse", "data": {}})
    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    monkeypatch.setattr(parse, "start", lambda source_id, _params=None: True)
    return "ev-parse"


def a_source(incident: str, data: bytes, name: str = "Security.evtx") -> str:
    sha256 = originals.keep_bytes(data)
    with SessionLocal() as db:
        source = imports.accept(db, incident, sha256, len(data), name, {"kind": "eventlog"}, "tester")
        db.commit()
        return source.id


def worker_says(monkeypatch, events: list[dict]) -> list[dict]:
    asked: list[dict] = []

    def fake(sha256, body, job):
        asked.append({"sha256": sha256, **body})
        yield from events

    monkeypatch.setattr(parse, "_events", fake)
    return asked


def source_of(source_id: str) -> EvidenceSource:
    with SessionLocal() as db:
        return db.get(EvidenceSource, source_id)


def records_of(source_id: str) -> list[EvidenceRecord]:
    with SessionLocal() as db:
        return list(
            db.scalars(select(EvidenceRecord).where(EvidenceRecord.source_id == source_id).order_by(EvidenceRecord.seq))
        )


def test_a_file_read_to_its_end_with_nothing_lost_is_complete(incident, monkeypatch):
    source_id = a_source(incident, b"ElfFile\x00 one")
    asked = worker_says(
        monkeypatch,
        [
            SOURCE,
            record(1),
            record(2, trunc=True),
            {"t": "note", "reason": "stale chunk", "count": 8},
            end(2, in_file=2),
        ],
    )
    parse.read(source_id)
    source = source_of(source_id)
    assert asked[0]["fileName"] == "Security.evtx" and asked[0]["params"]["host"] == ""
    assert (source.state, source.read, source.parser, source.parser_version) == ("done", "complete", "evtx", "1")
    assert (source.in_file, source.read_count, source.kept, source.duplicates, source.skipped) == (2, 2, 2, 0, 0)
    assert (source.truncated, source.notes, source.host, source.source) == (1, 8, "WKS-042", "evtx")
    seconds = source.report.pop("seconds")  # how long the reading took, to a tenth
    assert isinstance(seconds, float) and 0 <= seconds < 60 and seconds == round(seconds, 1)
    assert source.report == {
        "reasons": {},
        "notes": {"stale chunk": {"count": 8, "detail": ""}},
        "channels": {"Security": 2},
        "ended": True,
    }
    assert (source.first_ts, source.last_ts) == (1_700_000_001_000, 1_700_000_002_000)
    first, second = records_of(source_id)
    assert (first.incident_id, first.kind, first.type, first.event_id, first.channel) == (
        incident,
        "eventlog",
        "event",
        4624,
        "Security",
    )
    assert first.host == "WKS-042" and first.locator == {"offset": 4608, "length": 512} and second.truncated is True


def test_what_was_lost_makes_the_file_read_in_part_and_says_where(incident, monkeypatch):
    source_id = a_source(incident, b"ElfFile\x00 two")
    skip = {
        "t": "skip",
        "reason": "record cannot be read",
        "offset": 168576,
        "length": 1024,
        "lost": 1,
        "detail": "bad",
    }
    worker_says(monkeypatch, [SOURCE, record(1), skip, {**skip, "offset": 200000}, end(1, in_file=3)])
    parse.read(source_id)
    source = source_of(source_id)
    assert (source.state, source.read, source.in_file, source.read_count, source.skipped) == (
        "done",
        "partial",
        3,
        1,
        2,
    )
    reason = source.report["reasons"]["record cannot be read"]
    assert reason["count"] == 2 and reason["lost"] == 2
    assert reason["examples"][0] == {"offset": 168576, "length": 1024, "detail": "bad"}


def test_a_parser_that_stopped_before_the_end_keeps_what_came(incident, monkeypatch):
    source_id = a_source(incident, b"ElfFile\x00 three")
    stopped = {"t": "skip", "reason": "the parser stopped", "lost": 0, "detail": "it was ended by the signal SIGSEGV"}
    worker_says(monkeypatch, [SOURCE, record(1), record(2), stopped])
    parse.read(source_id)
    source = source_of(source_id)
    assert (source.state, source.read, source.kept, source.skipped) == ("done", "partial", 2, 0)
    assert source.report["ended"] is False and "the parser stopped" in source.report["reasons"]


def test_a_file_nothing_could_be_read_of_has_failed_with_the_reason(incident, monkeypatch):
    source_id = a_source(incident, b"not a log at all")
    said = {"t": "skip", "reason": "no parser reads this file", "lost": 0, "detail": "No parser of Nik reads this file"}
    worker_says(monkeypatch, [said])
    parse.read(source_id)
    source = source_of(source_id)
    assert (source.state, source.read) == ("failed", "failed")
    assert source.error == "no parser reads this file: No parser of Nik reads this file"

    # The worker cannot be reached at all: the same, with its sentence; and no worker configured.
    def unreachable(sha256, body, job):
        raise parse.ParseError("The forensics worker cannot be reached: refused")
        yield  # pragma: no cover - makes it a generator

    monkeypatch.setattr(parse, "_events", unreachable)
    with SessionLocal() as db:
        parse.again(db, db.get(EvidenceSource, source_id))
        db.commit()
    parse.read(source_id)
    assert source_of(source_id).error == "The forensics worker cannot be reached: refused"
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    with SessionLocal() as db:
        parse.again(db, db.get(EvidenceSource, source_id))
        db.commit()
    parse.read(source_id)
    assert source_of(source_id).error == parse.NOT_CONFIGURED


def test_records_another_file_already_gave_are_counted_not_stored_twice(incident, monkeypatch):
    first = a_source(incident, b"ElfFile\x00 export of monday")
    worker_says(monkeypatch, [SOURCE, record(1), record(2), end(2, in_file=2)])
    parse.read(first)
    second = a_source(incident, b"ElfFile\x00 export of tuesday")
    worker_says(monkeypatch, [SOURCE, record(2), record(3), record(3), end(3, in_file=3)])
    parse.read(second)
    source = source_of(second)
    assert (source.read, source.read_count, source.kept, source.duplicates) == ("complete", 3, 1, 2)
    assert [row.key for row in records_of(second)] == ["evtx:WKS-042:Security:3"]


def test_reading_again_replaces_the_records_and_keeps_the_marks(incident, monkeypatch):
    source_id = a_source(incident, b"ElfFile\x00 again")
    worker_says(monkeypatch, [SOURCE, record(1), record(2), end(2, in_file=2)])
    parse.read(source_id)
    with SessionLocal() as db:
        db.add(
            EvidenceMark(
                incident_id=incident, key="evtx:WKS-042:Security:2", flagged=True, note="look", updated_at="now"
            )
        )
        db.commit()
        parse.again(db, db.get(EvidenceSource, source_id))
        db.commit()
        assert db.get(EvidenceSource, source_id).state == "queued"
    # A newer parser gives one more record for the same file.
    worker_says(monkeypatch, [{**SOURCE, "version": "2"}, record(1), record(2), record(3), end(3, in_file=3)])
    parse.read(source_id)
    source = source_of(source_id)
    assert (source.parser_version, source.kept, source.duplicates) == ("2", 3, 0)
    assert [row.key.rsplit(":", 1)[1] for row in records_of(source_id)] == ["1", "2", "3"]
    with SessionLocal() as db:
        mark = db.get(EvidenceMark, (incident, "evtx:WKS-042:Security:2"))
        assert mark.flagged and mark.note == "look"


def test_the_indicators_a_file_declares_become_found_indicators_of_the_incident(incident, monkeypatch):
    from app.core.models import FoundIndicator, WarRoomEntry

    source_id = a_source(incident, b"ElfFile\x00 with addresses")
    worker_says(
        monkeypatch,
        [
            SOURCE,
            record(1, ioc=[["ip", "45.155.205.233"], ["domain", "payroll-harbourline-login.com"]]),
            record(2, ioc=[["ip", "45.155.205.233"], ["ip", "10.1.2.3"], ["ip", "not an address"]]),
            end(2, in_file=2),
        ],
    )
    parse.read(source_id)
    with SessionLocal() as db:
        found = {(row.type, row.value): row for row in db.scalars(select(FoundIndicator))}
        # The private address is left out by the setting, as for any other reading; what is not an
        # address of the type declared is not one.
        assert ("ip", "45.155.205.233") in found and ("ip", "10.1.2.3") not in found
        row = found[("ip", "45.155.205.233")]
        assert (row.door, row.path) == ("evidence", "evidence.eventlog.Security.evtx")
        lines = [entry.body.get("text", "") for entry in db.scalars(select(WarRoomEntry))]
        assert sum("found" in line for line in lines) == 1, "one line for the file, not one per indicator"
    assert source_of(source_id).indicators == len(found) >= 1


def test_the_war_room_gets_one_line_for_each_file_read(incident, monkeypatch):
    from app.core.models import WarRoomEntry

    whole = a_source(incident, b"ElfFile\x00 whole")
    worker_says(monkeypatch, [SOURCE, record(1), record(2), end(2, in_file=2)])
    parse.read(whole)
    part = a_source(incident, b"ElfFile\x00 part", "System.evtx")
    skip = {"t": "skip", "reason": "record cannot be read", "offset": 9000, "length": 512, "lost": 3}
    worker_says(monkeypatch, [SOURCE, record(2), record(3), skip, end(2, in_file=5)])
    parse.read(part)
    with SessionLocal() as db:
        lines = [entry.body["text"] for entry in db.scalars(select(WarRoomEntry).order_by(WarRoomEntry.at))]
    assert "Security.evtx read: 2 records kept." in lines
    assert (
        "System.evtx read: 1 record kept, 1 already imported from another file. Read in part: 3 records were not "
        "read (its report says what and where)." in lines
    )


def test_the_report_counts_the_channels_of_a_file_up_to_the_cap():
    report = parse.Report()
    for number in range(parse.CHANNELS_CAP + 5):
        report.channel(f"c{number}")
    report.channel("c0")
    report.channel("")
    assert len(report.channels) == parse.CHANNELS_CAP and report.channels["c0"] == 2
    assert "c54" not in report.channels and "" not in report.channels
    assert report.out(True)["channels"] is report.channels


def test_the_files_own_time_is_kept_with_its_source_and_sent_to_the_worker(incident, monkeypatch):
    sha256 = originals.keep_bytes(b"Nov  5 10:00:01 h sshd[1]: x")
    stamp = 1_700_000_000_000
    with SessionLocal() as db:
        rows = [
            imports.accept(db, incident, sha256, 28, "auth.log", {"kind": "syslog", "fileTime": value}, "tester")
            for value in (stamp,)
        ]
        db.commit()
        kept = rows[0].id
    assert source_of(kept).file_time == stamp
    asked = worker_says(monkeypatch, [SOURCE, record(1), end(1, in_file=1)])
    parse.read(kept)
    assert asked[0]["params"]["file_time"] == stamp
    # Absent or not a plausible time: nothing is sent, the worker uses the date it has.
    for index, value in enumerate((None, "yesterday", 0, -1, True, 10**18)):
        other = originals.keep_bytes(b"line %d" % index)
        with SessionLocal() as db:
            row = imports.accept(db, incident, other, 6, "auth.log", {"kind": "syslog", "fileTime": value}, "tester")
            db.commit()
            row_id = row.id
        assert source_of(row_id).file_time is None, value
        asked = worker_says(monkeypatch, [SOURCE, end(0, in_file=0)])
        parse.read(row_id)
        assert "file_time" not in asked[0]["params"]


def test_a_file_sent_while_the_worker_is_full_waits_its_turn_and_is_not_failed(monkeypatch):
    import io
    import urllib.error

    calls: list[str] = []
    waits: list[float] = []

    class Answer:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            return False

        def __iter__(self):
            return iter([b'{"t": "end", "in_file": 0, "read": 0}\n'])

    def urlopen(request, timeout):
        calls.append(request.full_url)
        if len(calls) <= 3:
            raise urllib.error.HTTPError(
                request.full_url,
                503,
                "busy",
                {},
                io.BytesIO(b'{"detail": "The forensics worker is busy; try again later"}'),
            )
        return Answer()

    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    monkeypatch.setattr(parse.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(parse.time, "sleep", waits.append)
    events = list(parse._events("a" * 64, {"fileName": "x"}, "job"))
    assert [event["t"] for event in events] == ["end"] and len(calls) == 4 and waits == [parse.BUSY_WAIT] * 3
    # After the tries it gives up with the worker's own sentence; another refusal fails at once.
    calls.clear()
    monkeypatch.setattr(parse, "BUSY_TRIES", 2)
    with pytest.raises(parse.ParseError, match="busy"):
        list(parse._events("a" * 64, {"fileName": "x"}, "job"))
    assert len(calls) == 3

    def refused(request, timeout):
        raise urllib.error.HTTPError(request.full_url, 422, "no", {}, io.BytesIO(b'{"detail": "not a file"}'))

    monkeypatch.setattr(parse.urllib.request, "urlopen", refused)
    waits.clear()
    with pytest.raises(parse.ParseError, match="not a file"):
        list(parse._events("a" * 64, {"fileName": "x"}, "job"))
    assert waits == []
