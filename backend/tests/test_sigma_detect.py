"""What the Sigma rules find in host evidence (7.0): the ``det`` lines of the worker become rows, a report, a
line of the War Room and an event; the rule set is handed over by its digest; the screens read the rows; and a
rule is tried on an incident.

The worker is not there: ``parse._events`` says what it would send, and ``tests/sigma_double.py`` answers for
its rule routes.
"""

# ruff: noqa: F811 - the fixture ``incident`` is imported, and each test names it as its argument
from __future__ import annotations

import io
import json
import urllib.error

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.models import AutomationEvent, EvidenceDetection, EvidenceSource, Incident, WarRoomEntry
from app.evidence import originals, parse
from app.main import app as fastapi_app
from app.sigma import ruleset, trying
from tests.conftest import make_key
from tests.sigma_double import FakeSigma, rule_text
from tests.test_evidence_parse import (  # noqa: F401 - incident is a fixture
    SOURCE,
    a_source,
    end,
    incident,
    record,
    records_of,
    source_of,
    worker_says,
)

RULE_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
RULE_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
RULE_C = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
BASE = f"/api/incidents/{'ev-parse'}/evidence"
RULES = "/api/sigma/rules"


def det(number: int, rule: str, **more) -> dict:
    return {"t": "det", "key": f"evtx:WKS-042:Security:{number}", "rule": rule, **more}


@pytest.fixture()
def rules_in(admin: TestClient, incident, monkeypatch) -> FakeSigma:
    """Three rules saved through the (fake) worker: a high one, a medium one, an informational one."""
    fake = FakeSigma(monkeypatch)
    for rule_id, title, level, author in (
        (RULE_A, "Log cleared", "high", "Nik"),
        (RULE_B, "Odd logon", "medium", "Florian Roth"),
        (RULE_C, "Noted", "informational", "Nik"),
    ):
        made = admin.post(RULES, json={"source": rule_text(rule_id, title=title, level=level, author=author)})
        assert made.status_code == 201, made.text
    return fake


def stored() -> list[EvidenceDetection]:
    with SessionLocal() as db:
        return list(db.scalars(select(EvidenceDetection).order_by(EvidenceDetection.id)))


def read(incident: str, monkeypatch, events: list[dict], data: bytes = b"ElfFile\x00 sigma") -> tuple[str, list[dict]]:
    source_id = a_source(incident, data)
    asked = worker_says(monkeypatch, events)
    parse.read(source_id)
    return source_id, asked


# --------------------------------------------------------------------------- #
# Reading a file with rules                                                    #
# --------------------------------------------------------------------------- #
def test_a_file_is_read_with_the_set_of_rules_and_the_hours_and_what_matched_is_kept(
    incident, rules_in, admin: TestClient, monkeypatch
):
    events = [
        SOURCE,
        record(1, host="WKS-042"),
        det(1, RULE_A),
        det(1, RULE_B),
        record(2),
        det(2, RULE_A),
        record(3),
        det(3, RULE_C),
        end(3, in_file=3),
    ]
    source_id, asked = read(incident, monkeypatch, events)
    with SessionLocal() as db:
        found = ruleset.current(db)
    assert asked[0]["rules"] == found.digest and found.count == 3
    assert asked[0]["params"]["hours"] == {"tz": "UTC", "days": [1, 2, 3, 4, 5], "start": "08:00", "end": "18:00"}
    first, second, third = records_of(source_id)
    assert (first.level, second.level, third.level) == (4, 4, 1)  # the highest level of what matched
    rows = stored()
    assert [(d.record_id, d.rule_id, d.level) for d in rows] == [
        (first.id, RULE_A, 4),
        (first.id, RULE_B, 3),
        (second.id, RULE_A, 4),
        (third.id, RULE_C, 1),
    ]
    assert (rows[0].rule_title, rows[0].rule_author, rows[0].tags) == (
        "Log cleared",
        "Nik",
        ["attack.defense-evasion", "attack.t1070.001"],
    )
    assert rows[1].rule_author == "Florian Roth" and rows[0].incident_id == incident and rows[0].records == []
    source = source_of(source_id)
    assert source.report["detections"] == {
        "total": 4,
        "byLevel": {"1": 1, "2": 0, "3": 1, "4": 2, "5": 0},
        "rules": [
            {"id": RULE_A, "title": "Log cleared", "level": 4, "count": 2},
            {"id": RULE_B, "title": "Odd logon", "level": 3, "count": 1},
            {"id": RULE_C, "title": "Noted", "level": 1, "count": 1},
        ],
    }
    assert source.read == "complete"
    with SessionLocal() as db:
        lines = [e.body["text"] for e in db.scalars(select(WarRoomEntry).where(WarRoomEntry.incident_id == incident))]
        assert db.get(Incident, incident).severity != "critical"
    assert lines[-1] == (
        "Security.evtx: 3 detections (2 high, 1 medium). The most frequent: Log cleared (2); Odd logon (1)."
    )


def test_an_event_is_published_once_for_the_file_with_the_level_as_a_word_and_a_number(incident, rules_in, monkeypatch):
    read(
        incident, monkeypatch, [SOURCE, record(1), det(1, RULE_A), det(1, RULE_B), record(2), det(2, RULE_B), end(2, 2)]
    )
    with SessionLocal() as db:
        (event,) = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "evidence.detected")).all()
        file = db.scalars(select(EvidenceSource)).one()
    data = event.payload["data"]
    assert event.object_kind == "incident" and event.object_id == incident
    assert data["source"] == {"id": file.id, "fileName": "Security.evtx", "kind": "eventlog"}
    assert (data["count"], data["level"], data["levelNumber"]) == (3, "high", 4)
    assert data["rules"] == [
        {"id": RULE_B, "title": "Odd logon", "level": 3, "count": 2},
        {"id": RULE_A, "title": "Log cleared", "level": 4, "count": 1},
    ]
    assert data["incident"]["id"] == incident
    assert event.payload["classes"]["levelNumber"] == ["verdict"] and event.payload["classes"]["source.fileName"]
    # A file with nothing that matched makes no event and no line of the War Room.
    before = len(event.payload)
    read(incident, monkeypatch, [SOURCE, record(5), end(1, 1)], b"ElfFile\x00 quiet")
    with SessionLocal() as db:
        assert len(db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "evidence.detected")).all()) == 1
    assert before


def test_low_levels_make_no_line_in_the_war_room_but_still_an_event(incident, rules_in, monkeypatch):
    read(incident, monkeypatch, [SOURCE, record(1), det(1, RULE_C), end(1, 1)])
    with SessionLocal() as db:
        texts = [e.body["text"] for e in db.scalars(select(WarRoomEntry))]
        assert len(db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "evidence.detected")).all()) == 1
    assert texts == ["Security.evtx read: 1 record kept."]


def test_the_rule_is_copied_as_it_was_and_reading_again_makes_the_detections_again(
    incident, rules_in, admin: TestClient, monkeypatch
):
    source_id, _ = read(incident, monkeypatch, [SOURCE, record(1), det(1, RULE_A), end(1, 1)])
    admin.put(f"{RULES}/{RULE_A}", json={"source": rule_text(RULE_A, title="Renamed later", level="low")})
    assert [(d.rule_title, d.level) for d in stored()] == [("Log cleared", 4)]  # as it was when it matched
    worker_says(monkeypatch, [SOURCE, record(1), det(1, RULE_A), det(1, RULE_B), end(1, 1)])
    with SessionLocal() as db:
        parse.again(db, db.get(EvidenceSource, source_id))
        db.commit()
    parse.read(source_id)
    assert [(d.rule_title, d.level) for d in stored()] == [("Renamed later", 2), ("Odd logon", 3)]
    assert records_of(source_id)[0].level == 3
    assert source_of(source_id).report["detections"]["total"] == 2


def test_a_detection_of_a_record_another_file_held_first_is_on_that_record_and_never_twice(
    incident, rules_in, monkeypatch
):
    first, _ = read(incident, monkeypatch, [SOURCE, record(1), record(2), end(2, 2)])
    assert [r.level for r in records_of(first)] == [None, None]
    second, _ = read(
        incident,
        monkeypatch,
        [SOURCE, record(2), det(2, RULE_A), record(3), det(3, RULE_B), end(2, 2)],
        b"ElfFile\x00 2",
    )
    owner = records_of(first)[1]
    rows = stored()
    assert [(d.record_id, d.rule_id) for d in rows] == [(owner.id, RULE_A), (records_of(second)[0].id, RULE_B)]
    assert owner.level == 4
    assert source_of(second).kept == 1 and source_of(second).duplicates == 1
    # A third file that says the same of the same record adds nothing.
    third, _ = read(incident, monkeypatch, [SOURCE, record(2), det(2, RULE_A), end(1, 1)], b"ElfFile\x00 3")
    assert len(stored()) == 2 and source_of(third).report["detections"]["total"] == 0


def test_a_correlation_is_on_the_record_that_completed_it_with_the_keys_of_the_records(
    incident, rules_in, admin: TestClient, monkeypatch
):
    keys = [f"evtx:WKS-042:Security:{n}" for n in range(1, 4)]
    read(
        incident,
        monkeypatch,
        [SOURCE, record(1), record(2), record(3), det(3, RULE_B, records=keys, count=3), end(3, 3)],
    )
    (row,) = stored()
    assert row.rule_id == RULE_B and row.records == keys and row.level == 3
    # The record says them: the viewer can open the records that made the detection.
    shown = admin.get(f"{BASE}/records/{row.record_id}").json()
    assert [(d["ruleId"], d["records"]) for d in shown["detections"]] == [(RULE_B, keys)]


def test_what_the_worker_names_that_is_not_here_is_counted_and_not_stored(incident, rules_in, monkeypatch):
    source_id, _ = read(
        incident,
        monkeypatch,
        [
            SOURCE,
            record(1),
            det(1, "not-a-rule"),
            {"t": "det", "key": "nowhere", "rule": RULE_A},
            det(1, RULE_A),
            end(1, 1),
        ],
    )
    assert [d.rule_id for d in stored()] == [RULE_A]
    notes = source_of(source_id).report["notes"]
    assert notes["detection of a record that is not here"]["count"] == 1
    assert notes["detection of a rule that is not in the set"]["count"] == 1


def test_without_an_enabled_rule_the_file_is_read_as_it_always_was(incident, admin: TestClient, monkeypatch):
    FakeSigma(monkeypatch)
    source_id, asked = read(incident, monkeypatch, [SOURCE, record(1), det(1, RULE_A), end(1, 1)])
    assert "rules" not in asked[0] and "hours" not in asked[0]["params"]
    assert stored() == [] and "detections" not in source_of(source_id).report


def test_a_batch_that_is_full_is_written_with_the_detections_of_the_records_before_it(incident, rules_in, monkeypatch):
    monkeypatch.setattr(parse, "BATCH", 2)
    events = [SOURCE]
    for n in range(1, 6):
        events += [record(n), det(n, RULE_A)]
    source_id, _ = read(incident, monkeypatch, events + [end(5, 5)])
    assert len(stored()) == 5 and all(r.level == 4 for r in records_of(source_id))


# --------------------------------------------------------------------------- #
# The worker is given the rules                                                #
# --------------------------------------------------------------------------- #
class Stream:
    def __init__(self, lines: list[dict]):
        self.lines = [json.dumps(line).encode() + b"\n" for line in lines]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def __iter__(self):
        return iter(self.lines)


def missing(url: str, **body) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(url, 409, "missing", {}, io.BytesIO(json.dumps(body).encode()))


def test_a_worker_that_lacks_the_rules_is_given_them_and_asked_once_more(incident, rules_in, monkeypatch):
    sha256 = originals.keep_bytes(b"for the worker")
    with SessionLocal() as db:
        found = ruleset.current(db)
    calls, given = [], []

    def urlopen(request, timeout):
        calls.append(json.loads(request.data).get("rules"))
        if len(calls) == 1:
            raise missing(request.full_url, missing=["x.bin"], missingRules=found.digest)
        if len(calls) == 2:
            raise missing(request.full_url, missing=[], missingRules=found.digest)
        return Stream([SOURCE, end(0)])

    monkeypatch.setattr(parse.urllib.request, "urlopen", urlopen)
    monkeypatch.setattr(parse.handover, "give", lambda *args, **_: given.append(args[3]))
    body = {"fileName": "x.evtx", "rules": found.digest, "params": {"hours": {"tz": "UTC"}}}
    events = list(parse._events(sha256, body, "job"))
    assert [e["t"] for e in events] == ["source", "end"]
    assert calls == [found.digest] * 3 and given == [f"{sha256}.bin"]
    assert rules_in.sets[found.digest] == found.body  # PUT /rules/<digest>, with the bytes of the set


def test_a_worker_that_does_not_take_the_rules_reads_the_file_without_them_and_says_so(
    incident, rules_in, admin: TestClient, monkeypatch
):
    sha256 = originals.keep_bytes(b"for the worker")
    with SessionLocal() as db:
        found = ruleset.current(db)
    rules_in.refuse_sets = True
    calls = []

    def urlopen(request, timeout):
        sent = json.loads(request.data)
        calls.append(sent)
        if "rules" in sent:
            raise missing(request.full_url, missing=[], missingRules=found.digest)
        return Stream([SOURCE, record(1), end(1)])

    monkeypatch.setattr(parse.urllib.request, "urlopen", urlopen)
    body = {"fileName": "x.evtx", "rules": found.digest, "params": {"hours": {"tz": "UTC"}}}
    events = list(parse._events(sha256, body, "job"))
    assert events[0] == {
        "t": "note",
        "reason": "rules not applied",
        "count": 1,
        "detail": "The worker has no room for rules",
    }
    assert [e["t"] for e in events[1:]] == ["source", "r", "end"]
    assert "rules" not in calls[1] and "hours" not in calls[1]["params"]
    assert "rules" not in body  # what the reading looks at to know that nothing was matched

    # A worker that keeps saying it lacks the rules, once they were given, is a refusal.
    def always(request, timeout):
        raise missing(request.full_url, missing=[], missingRules=found.digest)

    rules_in.refuse_sets = False
    monkeypatch.setattr(parse.urllib.request, "urlopen", always)
    with pytest.raises(parse.ParseError):
        list(parse._events(sha256, {"rules": found.digest, "params": {}}, "job"))


def test_a_file_read_by_a_worker_that_took_no_rules_says_so_in_its_report(incident, rules_in, monkeypatch):
    def stripped(sha256, body, job):
        body.pop("rules")
        yield {"t": "note", "reason": "rules not applied", "count": 1, "detail": "no room"}
        yield from [SOURCE, record(1), end(1, 1)]

    source_id = a_source(incident, b"ElfFile\x00 nothing")
    monkeypatch.setattr(parse, "_events", stripped)
    parse.read(source_id)
    source = source_of(source_id)
    assert "detections" not in source.report and source.report["notes"]["rules not applied"]["detail"] == "no room"
    assert source.read == "complete"


# --------------------------------------------------------------------------- #
# What the screens read                                                        #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def found(incident, rules_in, admin: TestClient, monkeypatch) -> TestClient:
    """Two files with detections: records of two hosts."""
    events = [
        SOURCE,
        record(1, host="WKS-1"),
        det(1, RULE_A),
        det(1, RULE_B),
        record(2, host="WKS-2"),
        det(2, RULE_A),
        record(3, host="WKS-2"),
        det(3, RULE_C),
        record(4, host="WKS-1"),
        end(4, 4),
    ]
    read(incident, monkeypatch, events)
    return admin


def test_the_detections_are_grouped_by_rule_highest_level_first(found: TestClient):
    answer = found.get(f"{BASE}/detections")
    assert answer.status_code == 200
    body = answer.json()
    assert (body["total"], body["detections"]) == (3, 4) and body["byLevel"] == {"1": 1, "2": 0, "3": 1, "4": 2, "5": 0}
    first, second, third = body["rules"]
    assert [r["ruleId"] for r in body["rules"]] == [RULE_A, RULE_B, RULE_C]
    assert first == {
        "ruleId": RULE_A,
        "title": "Log cleared",
        "author": "Nik",
        "level": 4,
        "levelName": "high",
        "tags": ["attack.defense-evasion", "attack.t1070.001"],
        "count": 2,
        "firstTs": 1_700_000_001_000,
        "lastTs": 1_700_000_002_000,
        "hosts": ["WKS-1", "WKS-2"],
        "hostCount": 2,
    }
    assert (second["author"], second["hosts"], third["levelName"]) == ("Florian Roth", ["WKS-1"], "informational")
    assert [r["ruleId"] for r in found.get(f"{BASE}/detections", params={"level": 3}).json()["rules"]] == [
        RULE_A,
        RULE_B,
    ]
    assert found.get(f"{BASE}/detections", params={"level": 3}).json()["byLevel"]["1"] == 0
    assert found.get(f"{BASE}/detections", params={"kind": "browser"}).json()["rules"] == []
    assert found.get(f"{BASE}/detections", params={"kind": "eventlog", "limit": 1}).json()["total"] == 3
    assert len(found.get(f"{BASE}/detections", params={"limit": 1}).json()["rules"]) == 1
    file_id = found.get(f"{BASE}/sources").json()["sources"][0]["id"]
    assert len(found.get(f"{BASE}/detections", params={"sourceId": file_id}).json()["rules"]) == 3
    assert found.get(f"{BASE}/detections", params={"sourceId": "other"}).json()["rules"] == []
    assert len(found.get(f"{BASE}/detections", params={"source": "evtx"}).json()["rules"]) == 3
    assert found.get(f"{BASE}/detections", params={"source": "mft"}).json()["rules"] == []
    assert found.get(f"{BASE}/detections", params={"level": 9}).status_code == 422
    assert found.get("/api/incidents/nope/evidence/detections").status_code == 404


def test_the_records_the_histogram_and_the_stack_take_a_rule(found: TestClient):
    listed = found.get(f"{BASE}/records", params={"rule": RULE_A}).json()
    assert [(r["summary"], r["level"]) for r in listed["records"]] == [("logon 1", 4), ("logon 2", 4)]
    assert listed["count"] == 2
    assert found.get(f"{BASE}/records", params={"rule": RULE_B, "host": "WKS-2"}).json()["records"] == []
    assert found.get(f"{BASE}/records", params={"level": 4}).json()["count"] == 2
    assert found.get(f"{BASE}/records", params={"rule": "nope"}).json()["count"] == 0
    histogram = found.get(f"{BASE}/histogram", params={"rule": RULE_A}).json()
    assert sum(bucket["count"] for bucket in histogram["buckets"]) == 2
    stack = found.get(f"{BASE}/stack", params={"field": "host", "rule": RULE_A, "order": "common"}).json()
    assert {item["value"]: item["count"] for item in stack["values"]} == {"WKS-1": 1, "WKS-2": 1}
    # A record says its detections, with the author of the rule.
    record_id = listed["records"][0]["id"]
    whole = found.get(f"{BASE}/records/{record_id}").json()
    assert [(d["ruleId"], d["ruleAuthor"], d["level"]) for d in whole["detections"]] == [
        (RULE_A, "Nik", 4),
        (RULE_B, "Florian Roth", 3),
    ]
    assert [d["records"] for d in whole["detections"]] == [[], []]


def test_the_summary_counts_the_detections_by_level_for_each_section(found: TestClient):
    kinds = found.get(f"{BASE}/summary").json()["kinds"]
    assert kinds["eventlog"]["detections"] == {"1": 1, "2": 0, "3": 1, "4": 2, "5": 0}
    assert found.get(f"{BASE}/sources").json()["sources"][0]["id"]
    report = found.get(f"{BASE}/sources/{found.get(f'{BASE}/sources').json()['sources'][0]['id']}").json()["report"]
    assert report["detections"]["total"] == 4 and report["detections"]["rules"][0]["id"] == RULE_A


def test_the_report_of_the_incident_names_the_rules_that_matched_and_their_authors(found: TestClient, incident):
    html = found.post(f"/api/incidents/{incident}/report", json={"format": "html", "scope": "all"}).text
    assert "Rule matches" in html and "Log cleared" in html and "Florian Roth" in html
    assert "T1070.001" in html and "credited to their authors" in html


# --------------------------------------------------------------------------- #
# Trying a rule                                                                #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def trial(incident, admin: TestClient, monkeypatch) -> FakeSigma:
    fake = FakeSigma(monkeypatch)
    events = [SOURCE]
    for n in range(1, 11):
        events.append(record(n, event_id=1102 if n % 3 == 0 else 4624))
    read(incident, monkeypatch, events + [end(10, 10)])
    return fake


def tried(admin: TestClient, text: str, **more):
    return admin.post(f"{RULES}/try", json={"source": text, "incidentId": "ev-parse", **more})


def test_a_rule_is_tried_on_the_records_of_an_incident_in_time_order_and_nothing_is_saved(
    trial: FakeSigma, admin: TestClient
):
    text = rule_text(RULE_A, title="Cleared", event=1102)
    answer = tried(admin, text)
    assert answer.status_code == 200, answer.text
    body = answer.json()
    assert (body["scanned"], body["cut"], body["cutReason"], body["matchCount"]) == (10, False, "", 3)
    assert [m["summary"] for m in body["matches"]] == ["logon 3", "logon 6", "logon 9"]
    first = body["matches"][0]
    assert (first["ruleId"], first["title"], first["level"], first["ts"]) == (RULE_A, "Cleared", 4, 1_700_000_003_000)
    assert first["key"] == "evtx:WKS-042:Security:3" and isinstance(first["recordId"], int)
    assert body["ran"] == [RULE_A] and body["notEvaluated"] == [] and body["limits"]["page"] == 20_000
    assert body["rules"][0]["supported"] is True and admin.get(f"{RULES}/{RULE_A}").status_code == 404
    (sent,) = trial.of("/sigma/try")
    assert sent["hours"]["tz"] == "UTC" and len(sent["records"]) == 10
    assert [r["ts"] for r in sent["records"]] == sorted(r["ts"] for r in sent["records"])
    assert set(sent["records"][0]) == {
        "kind",
        "channel",
        "event_id",
        "key",
        "ts",
        "host",
        "username",
        "summary",
        "data",
    }
    assert sent["rules"][0]["level"] == 4 and sent["rules"][0]["id"] == RULE_A
    assert tried(admin, text, kind="browser").json()["scanned"] == 0
    assert tried(admin, text, kind="eventlog").json()["matchCount"] == 3


def test_a_try_is_run_in_pages_and_stops_at_its_limits_and_says_so(trial: FakeSigma, admin: TestClient, monkeypatch):
    monkeypatch.setattr(trying, "PAGE", 4)
    text = rule_text(RULE_A, title="Cleared", event=1102)
    whole = tried(admin, text).json()
    assert [len(call["records"]) for call in trial.of("/sigma/try")] == [4, 4, 2]
    assert (whole["scanned"], whole["cut"], whole["matchCount"]) == (10, False, 3)
    trial.calls.clear()
    monkeypatch.setattr(trying, "RECORDS_MAX", 6)
    cut = tried(admin, text).json()
    assert (cut["scanned"], cut["cut"], cut["cutReason"], cut["matchCount"]) == (6, True, "records", 2)
    # The same number of records as the limit is not a cut.
    monkeypatch.setattr(trying, "RECORDS_MAX", 10)
    assert tried(admin, text).json()["cut"] is False
    monkeypatch.setattr(trying, "RECORDS_MAX", 200_000)
    monkeypatch.setattr(trying, "SECONDS_MAX", -1)
    slow = tried(admin, text).json()
    assert (slow["cut"], slow["cutReason"], slow["scanned"]) == (True, "time", 4)


def test_a_rule_that_cannot_run_is_not_sent_and_a_bad_text_says_where(trial: FakeSigma, admin: TestClient):
    linux = tried(admin, rule_text(RULE_B, product="linux", service="", category="network_connection"))
    body = linux.json()
    assert linux.status_code == 200 and body["ran"] == [] and body["scanned"] == 0 and body["matches"] == []
    assert body["rules"][0]["reason"] == "Nik reads no records of this log source: linux/network_connection"
    assert trial.of("/sigma/try") == []
    bad = tried(admin, "title: no id\n")
    assert bad.status_code == 400 and bad.json()["errors"][0]["line"] == 1
    assert tried(admin, rule_text(RULE_A), kind="x" * 17).status_code == 422
    assert admin.post(f"{RULES}/try", json={"source": rule_text(RULE_A), "incidentId": "nope"}).status_code == 404
    assert admin.post(f"{RULES}/try", json={"source": rule_text(RULE_A)}).status_code == 422


def test_a_correlation_is_tried_within_a_page_and_says_what_was_not_run(trial: FakeSigma, admin: TestClient):
    text = rule_text(RULE_C, title="Many", more={"correlation": {"type": "event_count", "rules": ["x"]}})
    body = tried(admin, text).json()
    assert body["notEvaluated"] == [{"rule": RULE_C, "reason": "a correlation is not run by this double"}]
    assert body["notes"] == [trying.CORRELATION_NOTE]


def test_trying_needs_to_manage_rules_and_to_read_incidents(trial: FakeSigma, admin: TestClient):
    caller = TestClient(fastapi_app)
    body = {"source": rule_text(RULE_A), "incidentId": "ev-parse"}
    only_rules = make_key(admin, label="r", roles=["rules"])
    assert caller.post(f"{RULES}/try", headers=only_rules, json=body).status_code == 403  # it cannot read incidents
    analyst = make_key(admin, label="a", roles=["analyst"])
    assert caller.post(f"{RULES}/try", headers=analyst, json=body).status_code == 403  # nor change rules
    both = make_key(admin, label="b", roles=["rules", "viewer"])
    assert caller.post(f"{RULES}/try", headers=both, json=body).status_code == 200
