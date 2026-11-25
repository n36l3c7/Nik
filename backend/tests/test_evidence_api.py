"""The read API of host evidence (7.0): files, records paged by key, marks, the summary.

Records are made the way the app makes them, through ``parse.read`` with the worker's events written
here; nothing is inserted by hand except the rows a rule would add (detections).
"""

from __future__ import annotations

import base64

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import (
    ArtifactLink,
    AuditEntry,
    EvidenceDetection,
    EvidenceMark,
    EvidenceRecord,
    EvidenceSource,
    WarRoomEntry,
)
from app.evidence import imports, originals, parse
from app.main import app as fastapi_app
from tests.conftest import make_key

BASE = 1_700_000_000_000
SOURCE = {"t": "source", "parser": "evtx", "version": "1", "kind": "eventlog", "source": "evtx", "host": "WKS-042"}


def event(number: int, **more) -> dict:
    return {
        "t": "r",
        "key": f"evtx:WKS-042:Security:{number}",
        "type": "event",
        "ts": BASE + number * 1000,
        "seq": number,
        "event_id": 4624,
        "channel": "Security",
        "summary": f"logon {number}",
        "data": {"TargetUserName": "admin"},
        "loc": {"offset": number * 512, "length": 512},
        "trunc": False,
        **more,
    }


def end(read: int) -> dict:
    return {"t": "end", "in_file": read, "read": read}


@pytest.fixture()
def env(admin, monkeypatch):
    client = TestClient(fastapi_app)
    writer = make_key(admin, roles=["analyst"])
    reader = make_key(admin, roles=["viewer"])
    for name in ("ev-api", "ev-other"):
        assert (
            client.post("/api/incidents", headers=writer, json={"id": name, "data": {"name": name}}).status_code == 201
        )
    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    started: list[str] = []
    monkeypatch.setattr(parse, "start", lambda source_id, _params=None: started.append(source_id) or True)
    return {"client": client, "w": writer, "r": reader, "started": started, "monkeypatch": monkeypatch}


def make_source(
    env,
    events: list[dict],
    incident: str = "ev-api",
    data: bytes | None = None,
    kind: str = "eventlog",
    source: str = "",
):
    data = data if data is not None else f"ElfFile {incident} {len(events)} {id(events)}".encode()
    sha256 = originals.keep_bytes(data)
    with SessionLocal() as db:
        row = imports.accept(
            db, incident, sha256, len(data), "Security.evtx", {"kind": kind, "source": source}, "tester"
        )
        db.commit()
        source_id = row.id

    def fake(_sha256, _body, _job):
        yield from events

    env["monkeypatch"].setattr(parse, "_events", fake)
    parse.read(source_id)
    return source_id


def get(env, path: str, who: str = "r", **params):
    return env["client"].get(f"/api/incidents/{path}", headers=env[who], params=params)


def keys_of(page: dict) -> list[str]:
    return [row["key"] for row in page["records"]]


def whole(env, order: str, **params) -> list[dict]:
    """Every record of the incident through the pages of 100, and the number of pages."""
    rows, cursor = [], None
    while True:
        extra = {"cursor": cursor} if cursor else {}
        res = get(env, "ev-api/evidence/records", order=order, limit=100, **extra, **params)
        assert res.status_code == 200, res.text
        page = res.json()
        rows += page["records"]
        cursor = page["next"]
        if cursor is None:
            return rows


# --------------------------------------------------------------------------- #
# Paging                                                                      #
# --------------------------------------------------------------------------- #
def test_250_records_with_ties_and_no_time_come_once_each_in_every_order(env):
    events = []
    for number in range(250):
        # Five records share each millisecond; every third one has no time at all.
        ts = None if number % 3 == 0 else BASE + (number // 5) * 1000
        events.append(event(number, ts=ts, seq=number // 2))
    source_id = make_source(env, events)
    with SessionLocal() as db:
        stored = {row.key: row for row in db.scalars(select(EvidenceRecord))}
    assert len(stored) == 250

    def flat(order: str) -> list[int]:
        return [row["id"] for row in whole(env, order)]

    def by(order: str) -> list[int]:
        rows = list(stored.values())
        timed = sorted((r for r in rows if r.ts is not None), key=lambda r: (r.ts, r.id), reverse=False)
        untimed = sorted((r for r in rows if r.ts is None), key=lambda r: r.id)
        if order == "time":
            return [r.id for r in timed + untimed]
        timed = sorted((r for r in rows if r.ts is not None), key=lambda r: (-r.ts, -r.id))
        untimed = sorted((r for r in rows if r.ts is None), key=lambda r: -r.id)
        return [r.id for r in timed + untimed]

    for order in ("time", "-time"):
        got = flat(order)
        assert len(got) == len(set(got)) == 250
        assert got == by(order)
    file_rows = whole(env, "file", sourceId=source_id)
    assert [(r["seq"], r["id"]) for r in file_rows] == sorted((r.seq, r.id) for r in stored.values())
    assert len({r["id"] for r in file_rows}) == 250


def test_the_first_page_counts_and_the_others_do_not(env):
    make_source(env, [event(n) for n in range(130)])
    first = get(env, "ev-api/evidence/records", limit=50).json()
    assert (first["count"], first["countCapped"], len(first["records"])) == (130, False, 50)
    second = get(env, "ev-api/evidence/records", limit=50, cursor=first["next"]).json()
    assert second["count"] is None and len(second["records"]) == 50
    last = get(env, "ev-api/evidence/records", limit=50, cursor=second["next"]).json()
    assert len(last["records"]) == 30 and last["next"] is None
    row = first["records"][0]
    assert set(row) == {
        "id",
        "key",
        "kind",
        "type",
        "ts",
        "seq",
        "host",
        "username",
        "eventId",
        "channel",
        "summary",
        "level",
        "truncated",
        "sourceId",
        "flagged",
        "note",
    }


def test_the_count_stops_at_its_cap(env, monkeypatch):
    from app.evidence import browse

    make_source(env, [event(n) for n in range(12)])
    monkeypatch.setattr(browse, "COUNT_CAP", 6)
    page = get(env, "ev-api/evidence/records").json()
    assert (page["count"], page["countCapped"]) == (6, True)


def test_a_wrong_cursor_or_order_is_refused(env):
    make_source(env, [event(n) for n in range(10)])
    path = "ev-api/evidence/records"
    assert get(env, path, cursor="not-a-cursor").status_code == 400
    forged = base64.urlsafe_b64encode(b'["t","x",1]').decode()
    assert get(env, path, cursor=forged).status_code == 400
    cursor = get(env, path, limit=3).json()["next"]
    # A cursor of one order is not another order's.
    assert get(env, path, cursor=cursor, order="-time").status_code == 400
    assert get(env, path, order="sideways").status_code == 400
    assert get(env, path, order="file").status_code == 400  # needs a sourceId
    assert get(env, path, limit=501).status_code == 422
    assert get(env, path, level=6).status_code == 422


# --------------------------------------------------------------------------- #
# Filters                                                                     #
# --------------------------------------------------------------------------- #
def test_each_filter_narrows_the_page(env):
    events = [
        event(1, type="event", host="A", username="u1", event_id=4624, channel="Security", summary="Logon 100%_x"),
        event(2, type="event", host="B", username="u2", event_id=4625, channel="System", summary="logoff 100 abc"),
        event(3, type="key", host="A", username="u1", event_id=None, channel="", summary="Run key", ts=None),
        event(4, type="event", host="A", username="u1", event_id=4624, channel="Security", summary="another"),
    ]
    first = make_source(env, events)
    other = make_source(env, [event(9, key="x:9")], data=b"another file", kind="endpoint")
    with SessionLocal() as db:
        by_key = {row.key: row for row in db.scalars(select(EvidenceRecord))}
        by_key["evtx:WKS-042:Security:1"].level = 4
        by_key["evtx:WKS-042:Security:2"].level = 2
        db.commit()

    def seen(**params) -> list[str]:
        res = get(env, "ev-api/evidence/records", **params)
        assert res.status_code == 200, res.text
        return [row["summary"] for row in res.json()["records"]]

    assert seen(kind="endpoint") == ["logon 9"]
    assert seen(type="key") == ["Run key"]
    assert seen(sourceId=other) == ["logon 9"]
    assert seen(sourceId=first, host="B") == ["logoff 100 abc"]
    assert seen(username="u2") == ["logoff 100 abc"]
    assert seen(channel="System") == ["logoff 100 abc"]
    assert sorted(seen(eventId=4624, sourceId=first)) == ["Logon 100%_x", "another"]
    assert seen(level=3) == ["Logon 100%_x"]
    assert sorted(seen(level=2)) == ["Logon 100%_x", "logoff 100 abc"]
    # Text: any case, and % and _ are letters.
    assert seen(q="LOGON", sourceId=first) == ["Logon 100%_x"]
    assert seen(q="100%") == ["Logon 100%_x"]
    assert seen(q="%_x") == ["Logon 100%_x"]
    assert seen(q="100 a") == ["logoff 100 abc"]
    # Time: inclusive, and the record with no time is left out as soon as a bound is given.
    assert "Run key" in seen(sourceId=first)
    assert seen(sourceId=first, **{"from": BASE + 2000, "to": BASE + 3000}) == ["logoff 100 abc"]
    assert sorted(seen(sourceId=first, **{"from": BASE + 2000})) == ["another", "logoff 100 abc"]
    assert sorted(seen(sourceId=first, to=BASE + 2000)) == ["Logon 100%_x", "logoff 100 abc"]


def test_flagged_and_notes_come_with_the_records(env):
    make_source(env, [event(n) for n in range(1, 5)])
    assert (
        env["client"]
        .put(
            "/api/incidents/ev-api/evidence/marks",
            headers=env["w"],
            json={"key": "evtx:WKS-042:Security:2", "flagged": True, "note": "bad"},
        )
        .status_code
        == 200
    )
    page = get(env, "ev-api/evidence/records", flagged=True).json()
    assert keys_of(page) == ["evtx:WKS-042:Security:2"] and page["count"] == 1
    assert (page["records"][0]["flagged"], page["records"][0]["note"]) == (True, "bad")
    everything = get(env, "ev-api/evidence/records").json()
    assert [row["flagged"] for row in everything["records"]] == [False, True, False, False]


# --------------------------------------------------------------------------- #
# Files                                                                       #
# --------------------------------------------------------------------------- #
def test_sources_list_without_the_report_and_open_with_it(env):
    skip = {"t": "skip", "reason": "record cannot be read", "offset": 10, "length": 5, "lost": 1, "detail": "bad"}
    older = make_source(env, [SOURCE, event(1), end(1)], data=b"first original")
    newer = make_source(env, [SOURCE, event(2), skip, end(2)], data=b"second original", kind="endpoint")
    listed = get(env, "ev-api/evidence/sources").json()["sources"]
    assert [row["id"] for row in listed] == [newer, older]
    assert "report" not in listed[0] and listed[0]["read"] == "partial" and listed[0]["work"] is None
    assert listed[0]["parserVersion"] == "1" and listed[0]["seen"] is None and listed[0]["host"] == "WKS-042"
    assert [row["id"] for row in get(env, "ev-api/evidence/sources", kind="eventlog").json()["sources"]] == [older]
    one = get(env, f"ev-api/evidence/sources/{newer}").json()
    assert one["report"]["reasons"]["record cannot be read"]["count"] == 1
    assert isinstance(one["report"]["seconds"], float)
    assert one["artifactId"] == f"hostfile-{one['sha256']}"
    # The list says why a file was read in part, without its report; a complete one says nothing.
    assert (listed[0]["firstReason"], listed[1]["firstReason"]) == ("record cannot be read", None)
    assert get(env, f"ev-other/evidence/sources/{newer}").status_code == 404


def test_a_source_being_read_says_how_far_the_work_is(env):
    source_id = make_source(env, [SOURCE, event(1), end(1)])
    with SessionLocal() as db:
        parse.again(db, db.get(EvidenceSource, source_id))
        db.commit()
    row = get(env, "ev-api/evidence/sources").json()["sources"][0]
    assert row["state"] == "queued" and row["work"]["state"] == "wanted"


def test_reading_again_starts_the_work_and_keeps_the_marks(env):
    source_id = make_source(env, [SOURCE, event(1), event(2), end(2)])
    put = {"key": "evtx:WKS-042:Security:2", "flagged": True, "note": "keep"}
    assert env["client"].put("/api/incidents/ev-api/evidence/marks", headers=env["w"], json=put).status_code == 200
    path = f"/api/incidents/ev-api/evidence/sources/{source_id}/again"
    assert env["client"].post(path, headers=env["r"]).status_code == 403
    res = env["client"].post(path, headers=env["w"])
    assert res.status_code == 202 and res.json()["state"] == "queued" and env["started"] == [source_id]
    assert env["client"].post(path, headers=env["w"]).status_code == 409  # already queued
    parse.read(source_id)
    page = get(env, "ev-api/evidence/records").json()
    assert [(row["flagged"], row["note"]) for row in page["records"]] == [(False, ""), (True, "keep")]


def test_a_legacy_source_or_one_without_original_cannot_be_read_again(env):
    legacy = make_source(env, [SOURCE, event(1), end(1)])
    bare = make_source(env, [SOURCE, event(2), end(2)], data=b"no copy of this one")
    with SessionLocal() as db:
        db.get(EvidenceSource, legacy).legacy = True
        db.get(EvidenceSource, bare).sha256 = "0" * 64
        db.commit()
    res = env["client"].post(f"/api/incidents/ev-api/evidence/sources/{legacy}/again", headers=env["w"])
    assert res.status_code == 409 and res.json()["detail"].startswith("This evidence was imported before 7.0")
    assert (
        env["client"].post(f"/api/incidents/ev-api/evidence/sources/{bare}/again", headers=env["w"]).status_code == 409
    )
    assert env["started"] == []


def test_a_file_read_in_part_is_acknowledged_in_the_audit_and_the_war_room(env):
    skip = {"t": "skip", "reason": "record cannot be read", "lost": 1}
    partial = make_source(env, [SOURCE, event(1), skip, end(1)], data=b"partial one")
    whole_one = make_source(env, [SOURCE, event(2), end(2)], data=b"complete one")
    base = "/api/incidents/ev-api/evidence/sources"
    assert env["client"].post(f"{base}/{whole_one}/seen", headers=env["w"], json={"note": "x"}).status_code == 409
    assert env["client"].post(f"{base}/{partial}/seen", headers=env["r"], json={"note": "x"}).status_code == 403
    assert env["client"].post(f"{base}/{partial}/seen", headers=env["w"], json={"note": "y" * 1001}).status_code == 422
    res = env["client"].post(f"{base}/{partial}/seen", headers=env["w"], json={"note": "the tail is padding"})
    assert res.status_code == 200
    seen = res.json()["seen"]
    assert seen["by"].startswith("api:") and seen["note"] == "the tail is padding" and seen["at"]
    summary = get(env, "ev-api/evidence/summary").json()
    assert summary["partialUnseen"] == 0
    with SessionLocal() as db:
        audit = list(db.scalars(select(AuditEntry).where(AuditEntry.action == "evidence.seen")))
        # The readings of the files leave lines of their own (author nik): the one a person made is asked for.
        room = [
            entry
            for entry in db.scalars(select(WarRoomEntry).where(WarRoomEntry.incident_id == "ev-api"))
            if entry.author != "nik"
        ]
    assert len(audit) == 1 and audit[0].incident_id == "ev-api" and "the tail is padding" in audit[0].details
    assert len(room) == 1 and "Security.evtx" in room[0].body["text"] and "the tail is padding" in room[0].body["text"]
    assert env["client"].delete(f"{base}/{partial}/seen", headers=env["w"]).json()["seen"] is None
    assert get(env, "ev-api/evidence/summary").json()["partialUnseen"] == 1
    with SessionLocal() as db:
        assert db.scalar(select(AuditEntry).where(AuditEntry.action == "evidence.seen").offset(1)) is not None


def test_removing_a_file_drops_its_records_and_its_link_but_not_the_marks(env):
    shared = b"the same original in two files"
    one = make_source(env, [SOURCE, event(1), end(1)], data=shared)
    other_incident = make_source(env, [SOURCE, event(1, key="k:1")], incident="ev-other", data=shared)
    base = "/api/incidents/ev-api/evidence/sources"
    put = {"key": "evtx:WKS-042:Security:1", "flagged": True, "note": ""}
    assert env["client"].put("/api/incidents/ev-api/evidence/marks", headers=env["w"], json=put).status_code == 200
    assert env["client"].delete(f"{base}/{one}", headers=env["r"]).status_code == 403
    assert env["client"].delete(f"/api/incidents/ev-other/evidence/sources/{one}", headers=env["w"]).status_code == 404
    with SessionLocal() as db:
        sha256 = db.get(EvidenceSource, one).sha256
        assert db.get(ArtifactLink, (f"hostfile-{sha256}", "ev-api")) is not None
        db.get(EvidenceSource, one).state = "parsing"
        db.commit()
    assert env["client"].delete(f"{base}/{one}", headers=env["w"]).status_code == 409
    with SessionLocal() as db:
        db.get(EvidenceSource, one).state = "done"
        db.commit()
    assert env["client"].delete(f"{base}/{one}", headers=env["w"]).status_code == 200
    with SessionLocal() as db:
        assert db.get(EvidenceSource, one) is None
        assert db.get(ArtifactLink, (f"hostfile-{sha256}", "ev-api")) is None
        assert db.get(ArtifactLink, (f"hostfile-{sha256}", "ev-other")) is not None
        assert db.get(EvidenceSource, other_incident) is not None
        assert db.scalar(select(EvidenceRecord).where(EvidenceRecord.incident_id == "ev-api")) is None
        assert db.scalar(select(EvidenceRecord).where(EvidenceRecord.incident_id == "ev-other")) is not None
        assert db.get(EvidenceMark, ("ev-api", "evtx:WKS-042:Security:1")) is not None
        assert db.scalar(select(AuditEntry).where(AuditEntry.action == "evidence.remove")) is not None
    assert get(env, "ev-api/evidence/sources").json()["sources"] == []


def test_a_link_stays_while_another_file_of_the_incident_has_the_original(env):
    data = b"one original twice"
    first = make_source(env, [SOURCE, event(1), end(1)], data=data)
    with SessionLocal() as db:
        sha256 = db.get(EvidenceSource, first).sha256
    second = make_source(env, [SOURCE, event(2), end(2)], data=data, kind="endpoint")
    assert env["client"].delete(f"/api/incidents/ev-api/evidence/sources/{first}", headers=env["w"]).status_code == 200
    with SessionLocal() as db:
        assert db.get(EvidenceSource, second) is not None
        assert db.get(ArtifactLink, (f"hostfile-{sha256}", "ev-api")) is not None


# --------------------------------------------------------------------------- #
# One record, marks, the summary                                              #
# --------------------------------------------------------------------------- #
def test_one_record_comes_whole_with_its_file_and_detections(env):
    source_id = make_source(env, [SOURCE, event(1), end(1)])
    with SessionLocal() as db:
        row = db.scalars(select(EvidenceRecord)).one()
        db.add(
            EvidenceDetection(
                incident_id="ev-api",
                record_id=row.id,
                rule_id="r1",
                rule_title="Logon",
                rule_author="someone",
                level=3,
                tags=["attack.t1078"],
                records=[],
                created_at="now",
            )
        )
        db.commit()
        record_id = row.id
    page = get(env, f"ev-api/evidence/records/{record_id}").json()
    assert page["data"] == {"TargetUserName": "admin"} and page["locator"] == {"offset": 512, "length": 512}
    assert (
        page["source"]["id"] == source_id
        and page["source"]["parser"] == "evtx"
        and page["source"]["read"] == "complete"
    )
    assert page["detections"] == [
        {
            "ruleId": "r1",
            "ruleTitle": "Logon",
            "ruleAuthor": "someone",
            "level": 3,
            "tags": ["attack.t1078"],
            "records": [],
        }
    ]
    assert get(env, f"ev-other/evidence/records/{record_id}").status_code == 404
    assert get(env, "ev-api/evidence/records/999999").status_code == 404


def test_a_mark_is_made_changed_and_removed_and_audited_when_the_flag_changes(env):
    make_source(env, [event(1), event(2)])
    url = "/api/incidents/ev-api/evidence/marks"
    key = "evtx:WKS-042:Security:1"

    def put(**body):
        return env["client"].put(url, headers=env["w"], json={"key": key, **body})

    def audited() -> int:
        with SessionLocal() as db:
            return len(list(db.scalars(select(AuditEntry).where(AuditEntry.action == "evidence.mark"))))

    assert env["client"].put(url, headers=env["r"], json={"key": key, "flagged": True}).status_code == 403
    assert put(flagged=True, note="a").json() == {"key": key, "flagged": True, "note": "a"}
    assert audited() == 1
    put(flagged=True, note="b")  # the note only: not audited
    assert audited() == 1
    with SessionLocal() as db:
        assert db.get(EvidenceMark, ("ev-api", key)).note == "b"
    put(flagged=False, note="b")
    assert audited() == 2
    put(flagged=False, note="")
    with SessionLocal() as db:
        assert db.get(EvidenceMark, ("ev-api", key)) is None
    assert audited() == 2
    assert put(flagged=False, note="").status_code == 200  # nothing to remove is not an error
    assert env["client"].put(url, headers=env["w"], json={"key": "nope", "flagged": True}).status_code == 404
    # The key of another incident's record is not a record of this one.
    make_source(env, [event(1, key="only:other")], incident="ev-other", data=b"other incident file")
    assert env["client"].put(url, headers=env["w"], json={"key": "only:other", "flagged": True}).status_code == 404
    assert env["client"].put(url, headers=env["w"], json={"key": key, "note": "z" * 5001}).status_code == 422


def test_the_summary_counts_per_section(env):
    skip = {"t": "skip", "reason": "record cannot be read", "lost": 1}
    make_source(env, [SOURCE, event(1), event(2), end(2)], data=b"a")
    make_source(env, [SOURCE, event(3), skip, end(1)], data=b"b")
    make_source(env, [SOURCE, event(4), end(1)], data=b"c", kind="endpoint")
    failed = make_source(env, [{"t": "skip", "reason": "no parser", "lost": 0}], data=b"d", kind="endpoint")
    queued = make_source(env, [SOURCE, event(5), end(1)], data=b"e", kind="browser")
    with SessionLocal() as db:
        parse.again(db, db.get(EvidenceSource, queued))
        db.commit()
    assert get(env, f"ev-api/evidence/sources/{failed}").json()["state"] == "failed"
    summary = get(env, "ev-api/evidence/summary").json()
    none_found = {"1": 0, "2": 0, "3": 0, "4": 0, "5": 0}  # what the Sigma rules found, by level
    assert summary["kinds"]["eventlog"] == {
        "sources": 2,
        "records": 3,
        "partial": 1,
        "failed": 0,
        "parsing": 0,
        "absent": 0,
        "detections": none_found,
    }
    assert summary["kinds"]["endpoint"] == {
        "sources": 2,
        "records": 1,
        "partial": 0,
        "failed": 1,
        "parsing": 0,
        "absent": 0,
        "detections": none_found,
    }
    assert summary["kinds"]["browser"]["parsing"] == 1
    assert summary["partialUnseen"] == 1
    assert get(env, "ev-other/evidence/summary").json() == {"kinds": {}, "partialUnseen": 0}


def test_every_route_answers_404_for_an_unknown_incident(env):
    base = "/api/incidents/nope/evidence"
    for path in ("/sources", "/sources/x", "/records", "/records/1", "/summary"):
        assert env["client"].get(base + path, headers=env["r"]).status_code == 404, path
    assert env["client"].post(base + "/sources/x/again", headers=env["w"]).status_code == 404
    assert env["client"].post(base + "/sources/x/seen", headers=env["w"], json={}).status_code == 404
    assert env["client"].delete(base + "/sources/x", headers=env["w"]).status_code == 404
    assert env["client"].put(base + "/marks", headers=env["w"], json={"key": "k"}).status_code == 404


# --------------------------------------------------------------------------- #
# The filters of 7.0, the projection and the channels of a file               #
# --------------------------------------------------------------------------- #
def summaries(env, **params) -> list[str]:
    res = get(env, "ev-api/evidence/records", **params)
    assert res.status_code == 200, res.text
    return sorted(row["summary"] for row in res.json()["records"])


@pytest.fixture()
def mixed(env):
    shell = {**SOURCE, "source": "powershell"}
    make_source(
        env,
        [
            shell,
            event(1, channel="Security", event_id=4624, summary="curated logon", data={"Ip": "10.0.0.1"}),
            event(2, channel="Security", event_id=9999, summary="other security", data={"Ip": "10.0.0.2"}),
            event(3, channel="MICROSOFT-WINDOWS-SYSMON/OPERATIONAL", event_id=1, summary="sysmon one"),
            event(4, channel="System", event_id=1, summary="system one"),
            event(5, type="script", channel="", event_id=4624, summary="no channel", ts=None),
            end(5),
        ],
        data=b"one",
        source="powershell",  # an event log says its source, as a file sent with one does
    )
    run = {**SOURCE, "source": "windows.persistence.run", "kind": "endpoint"}
    make_source(
        env,
        [run, event(9, key="p:9", type="key", channel="", event_id=None, summary="a run key"), end(1)],
        data=b"two",
        kind="endpoint",
    )
    visit = event(10, key="b:10", type="visit", channel="", event_id=None, summary="a visit")
    path = make_source(env, [{**SOURCE, "source": "chrome.history"}, visit, end(1)], data=b"3", kind="browser")
    with SessionLocal() as db:
        db.get(EvidenceSource, path).profile = "Profile 1"
        db.commit()
    return env


def test_type_takes_a_list_and_one_value_behaves_as_before(mixed):
    assert summaries(mixed, type="key") == ["a run key"]
    assert summaries(mixed, type="key,visit") == ["a run key", "a visit"]
    assert summaries(mixed, type=" key , ,visit,nothing") == ["a run key", "a visit"]
    assert get(mixed, "ev-api/evidence/records", type=",".join(f"t{n}" for n in range(41))).status_code == 400
    assert get(mixed, "ev-api/evidence/records", type="x" * 41).status_code == 400


def test_a_file_is_chosen_by_its_source_its_prefix_or_its_profile(mixed):
    assert summaries(mixed, source="chrome.history") == ["a visit"]
    assert summaries(mixed, source="chrome") == []
    assert summaries(mixed, sourcePrefix="windows.persistence.") == ["a run key"]
    assert summaries(mixed, sourcePrefix="windows_persistence") == []  # _ is a letter, not a wildcard
    assert summaries(mixed, sourcePrefix="windows%") == []
    assert summaries(mixed, profile="Profile 1") == ["a visit"]
    assert summaries(mixed, profile="Profile 1", source="powershell") == []
    assert len(summaries(mixed, source="powershell")) == 5
    assert get(mixed, "ev-api/evidence/records", source="x" * 61).status_code == 422


def test_dated_keeps_the_records_with_a_time_or_without(mixed):
    assert summaries(mixed, dated="false") == ["no channel"]
    assert len(summaries(mixed, dated="true")) == 6
    assert len(summaries(mixed)) == 7


def test_a_key_of_the_data_is_compared_as_text(mixed):
    assert summaries(mixed, dataKey="Ip", dataValue="10.0.0.2") == ["other security"]
    assert summaries(mixed, dataKey="Ip", dataValue="nobody") == []
    for params in ({"dataKey": "Ip"}, {"dataValue": "x"}, {"dataKey": "a b", "dataValue": "x"}):
        assert get(mixed, "ev-api/evidence/records", **params).status_code == 400
    assert get(mixed, "ev-api/evidence/records", dataKey="Ip", dataValue="x" * 501).status_code == 422


def test_matter_keeps_the_event_log_records_the_curated_list_names(mixed):
    # The channel is compared in lower case, and a record with no channel is not matched.
    assert summaries(mixed, matter="true") == ["curated logon", "sysmon one"]
    assert len(summaries(mixed, matter="false")) == 7


def test_fields_bring_the_asked_keys_of_the_data_that_exist(mixed):
    rows = get(mixed, "ev-api/evidence/records").json()["records"]
    assert all("data" not in row for row in rows)
    asked = {"fields": "Ip,Nothing", "dataKey": "Ip", "dataValue": "10.0.0.2"}
    rows = get(mixed, "ev-api/evidence/records", **asked).json()["records"]
    assert [row["data"] for row in rows] == [{"Ip": "10.0.0.2"}]
    assert get(mixed, "ev-api/evidence/records", fields="Nothing", q="curated").json()["records"][0]["data"] == {}
    for bad in ("a b", ",", ",".join(f"k{n}" for n in range(13)), "a;b"):
        assert get(mixed, "ev-api/evidence/records", fields=bad).status_code == 400


def test_a_long_text_of_the_data_is_cut_and_other_values_stay(env):
    held = {"Long": "x" * 900, "Count": 7, "On": True, "Tree": {"a": [1]}}
    make_source(env, [SOURCE, event(1, data=held), end(1)])
    row = get(env, "ev-api/evidence/records", fields="Long,Count,On,Tree").json()["records"][0]
    assert row["data"] == {"Long": "x" * 500, "Count": 7, "On": True, "Tree": {"a": [1]}}


def test_a_source_names_its_main_channels_most_records_first(env):
    events = [event(n, channel="Security") for n in range(1, 4)]
    events += [event(10 + n, channel=f"Chan{n}") for n in range(1, 6)]
    events += [event(20, channel="Aaa"), event(21, channel="Aaa"), event(22, channel="")]
    source_id = make_source(env, [SOURCE, *events, end(len(events))])
    held = get(env, f"ev-api/evidence/sources/{source_id}").json()
    assert held["channels"] == ["Security", "Aaa", "Chan1", "Chan2", "Chan3"] and held["source"] == "evtx"
    assert held["report"]["channels"]["Security"] == 3 and "" not in held["report"]["channels"]
    assert get(env, "ev-api/evidence/sources").json()["sources"][0]["channels"] == held["channels"]
    other = make_source(env, [event(99, key="p:1", channel="")], data=b"none")
    assert get(env, f"ev-api/evidence/sources/{other}").json()["channels"] == []
