"""What reads host evidence besides its own screens (7.0): the counts of the list, the incident report.

The worker is not there: ``parse._events`` is what it would have sent, written here, as in
``test_evidence_parse.py``. One incident also comes from a document of 6.x, moved by ``evidence/legacy``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, insert, select

from app.core.config import settings
from app.core.db import SessionLocal, engine
from app.core.models import EvidenceDetection, EvidenceMark, EvidenceRecord, EvidenceSource, Incident
from app.evidence import imports, originals, parse, reporting
from app.incident_quick import counts, counts_for
from app.main import app as fastapi_app
from app.report import build_html, evidence
from tests.conftest import make_key
from tests.test_evidence_legacy import old_document

BASE = 1_700_000_000_000
SOURCE = {"t": "source", "parser": "evtx", "version": "1.2", "host": "WKS-042"}


def row(number: int, type_: str, **more) -> dict:
    return {
        "t": "r",
        "key": f"k:{more.pop('tag', type_)}:{number}",
        "type": type_,
        "ts": BASE + number * 1000,
        "seq": number,
        "summary": f"{type_} {number}",
        "data": {},
        "loc": {},
        "trunc": False,
        **more,
    }


def event_row(number: int, event_id: int, channel: str, **more) -> dict:
    more.setdefault("tag", channel)
    return row(number, "event", event_id=event_id, channel=channel, **more)


def end(read: int, in_file: int | None = None) -> dict:
    return {"t": "end", "in_file": in_file, "read": read, "first_ts": None, "last_ts": None}


@pytest.fixture()
def world(admin, monkeypatch):
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    monkeypatch.setattr(parse, "start", lambda source_id, _params=None: True)
    return client, key, monkeypatch


def an_incident(world, name: str, doc: dict | None = None) -> str:
    client, key, _ = world
    made = client.post("/api/incidents", headers=key, json={"id": name, "data": {}, **(doc or {})})
    assert made.status_code == 201, made.text
    return name


def read_file(world, incident: str, kind: str, name: str, events: list[dict], source: str = "") -> str:
    """A file of ``kind`` imported into the incident and read, the worker saying ``events``."""
    monkeypatch = world[2]
    data = f"{incident}/{kind}/{name}".encode()
    sha256 = originals.keep_bytes(data)
    with SessionLocal() as db:
        found = imports.accept(db, incident, sha256, len(data), name, {"kind": kind, "source": source}, "tester")
        db.commit()
        source_id = found.id
    monkeypatch.setattr(parse, "_events", lambda sha, body, job: iter(events))
    parse.read(source_id)
    return source_id


def source_of(source_id: str) -> EvidenceSource:
    with SessionLocal() as db:
        return db.get(EvidenceSource, source_id)


def host_evidence(world, incident: str) -> str:
    """Records of every kind: the same numbers are checked in the counts and in the report."""
    read_file(
        world,
        incident,
        "browser",
        "History",
        [
            SOURCE,
            row(1, "visit", data={"url": "https://a.example"}),
            row(2, "visit", data={"url": "https://b.example"}),
            row(3, "download", data={"url": "https://c.example/x.exe", "fileName": "x.exe"}),
            row(4, "bookmark"),
            row(5, "shortcut"),
            end(5, 5),
        ],
        "chrome.history",
    )
    read_file(
        world,
        incident,
        "commands",
        "ConsoleHost_history.txt",
        [SOURCE, row(1, "command", data={"command": "whoami"}), row(2, "command"), row(3, "command"), end(3, 3)],
        "powershell",
    )
    read_file(
        world,
        incident,
        "endpoint",
        "runkeys.csv",
        [SOURCE, row(1, "runkeys", data={"name": "MSUpdate"}), row(2, "runkeys"), end(2, 2)],
        "windows.persistence.runkeys",
    )
    return read_file(
        world,
        incident,
        "eventlog",
        "Security.evtx",
        [SOURCE] + [event_row(n, 4624, "Security") for n in range(1, 5)] + [end(4, 4)],
        "evtx",
    )


# --------------------------------------------------------------------------- #
# The counts of the list                                                      #
# --------------------------------------------------------------------------- #
def test_counts_of_one_incident_and_of_a_page_of_them(world):
    first, second, third = (an_incident(world, name) for name in ("rd-1", "rd-2", "rd-3"))
    host_evidence(world, first)
    read_file(world, second, "eventlog", "System.evtx", [SOURCE, event_row(1, 7045, "System"), end(1, 1)], "evtx")
    with SessionLocal() as db:
        doc = {"flags": {"a": {}}, "notes": [{}, {}]}
        assert counts(db, first, doc) == {
            "browserEvents": 3,
            "commands": 3,
            "endpointArtifacts": 2,
            "eventLogs": 4,
            "flagged": 1,
            "bookmarks": 1,
            "notes": 2,
        }
        seen: list[str] = []

        def watch(_conn, _cursor, statement, *_rest):
            seen.append(statement)

        event.listen(engine, "before_cursor_execute", watch)
        try:
            page = counts_for(db, {first: doc, second: {}, third: None, "nothing": None})
        finally:
            event.remove(engine, "before_cursor_execute", watch)
    # One grouped query for the whole page, over the counts and no record.
    assert len(seen) == 1 and "GROUP BY" in seen[0] and "count(" in seen[0].lower()
    assert page[first]["eventLogs"] == 4 and page[first]["notes"] == 2
    assert page[second] == {**page[third], "eventLogs": 1}
    assert page[third] == {
        "browserEvents": 0,
        "commands": 0,
        "endpointArtifacts": 0,
        "eventLogs": 0,
        "flagged": 0,
        "bookmarks": 0,
        "notes": 0,
    }
    assert page["nothing"] == page[third]


def test_the_quick_view_serves_the_counts_of_the_tables(world):
    client, key, _ = world
    incident = an_incident(world, "rd-quick")
    host_evidence(world, incident)
    body = client.get(f"/api/incidents/{incident}/quick", headers=key).json()
    assert body["counts"]["eventLogs"] == 4 and body["counts"]["browserEvents"] == 3
    assert body["counts"]["endpointArtifacts"] == 2 and body["counts"]["commands"] == 3


# --------------------------------------------------------------------------- #
# The report                                                                  #
# --------------------------------------------------------------------------- #
def test_the_report_reads_flags_files_logs_and_cleared_logs_from_the_tables(world):
    client, key, _ = world
    incident = an_incident(world, "rd-rep", {"name": "WKS-042"})
    host_evidence(world, incident)
    read_file(
        world,
        incident,
        "eventlog",
        "System.evtx",
        [
            SOURCE,
            event_row(1, 1102, "Security", tag="cleared", data={"SubjectUserName": "admin"}),
            event_row(2, 104, "System", data={"Channel": "microsoft-windows-sysmon/operational"}),
            event_row(3, 7045, "Microsoft-Windows-Sysmon/Operational"),
            end(3, 3),
        ],
        "evtx",
    )
    with SessionLocal() as db:
        db.add_all(
            [
                EvidenceMark(
                    incident_id=incident,
                    key="k:Security:2",
                    flagged=True,
                    note="first <logon>",
                    updated_by="elena",
                    updated_at="x",
                ),
                EvidenceMark(
                    incident_id=incident,
                    key="k:visit:1",
                    flagged=False,
                    note="only a note",
                    updated_by="elena",
                    updated_at="x",
                ),
            ]
        )
        db.commit()
        host = reporting.gather(db, incident)
        doc = db.get(Incident, incident).doc

    flagged = host["flagged"]
    assert flagged["total"] == 1 and flagged["sources"] and flagged["channels"] == {"Security"}
    assert flagged["records"][0]["summary"] == "event 2" and flagged["records"][0]["file"] == "Security.evtx"
    assert flagged["records"][0]["note"] == "first <logon>" and flagged["records"][0]["time"] == BASE + 2000

    overview = {c["channel"]: c for c in host["channels"]}
    assert overview["Security"] == {
        "channel": "Security",
        "events": 5,
        "first": BASE + 1000,
        "last": BASE + 4000,
        "files": ["Security.evtx", "System.evtx"],
    }
    assert overview["System"]["events"] == 1 and overview["Microsoft-Windows-Sysmon/Operational"]["files"] == [
        "System.evtx"
    ]
    # 1102 clears Security; 104 names the log, given the case of the one the incident holds.
    assert host["cleared"] == {"Security": [BASE + 1000], "Microsoft-Windows-Sysmon/Operational": [BASE + 2000]}

    # The appendix: a row per file with its section, SHA-256, records kept and reading.
    rows = {r["fileName"]: r for r in evidence(doc, None, host)}
    assert set(rows) == {"History", "ConsoleHost_history.txt", "runkeys.csv", "Security.evtx", "System.evtx"}
    assert rows["Security.evtx"]["tab"] == "Event logs" and rows["Security.evtx"]["rows"] == 4
    assert len(rows["History"]["sha256"]) == 64 and rows["History"]["read"] == "complete"

    html = client.post(f"/api/incidents/{incident}/report", headers=key, json={"format": "html"}).text
    assert "first &lt;logon&gt;" in html and "event 2" in html and "<logon>" not in html
    flagged_part = html.split("Evidence integrity")[0]
    assert "Security.evtx" in flagged_part and "History" not in flagged_part.split("Evidence appendix")[1]
    everything = client.post(
        f"/api/incidents/{incident}/report", headers=key, json={"format": "html", "scope": "all"}
    ).text
    events_part = everything.split("Windows event logs")[1].split("Analyst notes")[0]
    assert "Microsoft-Windows-Sysmon/Operational" in events_part and 'class="high"' in events_part
    assert "5 files, 0 read in part, 0 failed." in everything
    assert client.post(f"/api/incidents/{incident}/report", headers=key, json={"format": "pdf"}).content.startswith(
        b"%PDF"
    )


def test_the_integrity_section_says_what_was_read_of_every_file(world):
    client, key, _ = world
    incident = an_incident(world, "rd-int", old_document())  # a 6.x document: moved, its files are legacy
    complete = read_file(
        world, incident, "eventlog", "Logon.evtx", [SOURCE, event_row(1, 4624, "Security"), end(1, 1)], "evtx"
    )
    skip = {"t": "skip", "reason": "record cannot be read", "offset": 4096, "length": 512, "lost": 1, "detail": "bad"}
    other = {"t": "skip", "reason": "chunk checksum does not match", "lost": 3}
    partial = read_file(
        world,
        incident,
        "eventlog",
        "Application.evtx",
        [SOURCE, event_row(1, 1000, "Application"), skip, skip, other, end(1, 7)],
        "evtx",
    )
    failed = read_file(
        world,
        incident,
        "commands",
        "garbage.bin",
        [{"t": "skip", "reason": "no parser reads this file", "lost": 0, "detail": "No parser of Nik reads this file"}],
        "powershell",
    )
    assert source_of(partial).read == "partial" and source_of(failed).read == "failed"
    with SessionLocal() as db:
        found = db.get(EvidenceSource, partial)
        found.seen_by, found.seen_at, found.seen_note = "elena", "2026-11-24T10:00:00Z", "damaged on the disk, known"
        db.commit()
        host = reporting.gather(db, incident)
        doc = db.get(Incident, incident).doc

    total = len(host["sources"])
    assert total == 8  # five of the 6.x document, three of the test
    html = build_html(doc, host=host, scope="all", sections=["evidence", "integrity"])
    # Right after the evidence appendix, with its closing line.
    assert html.index("Evidence appendix") < html.index("Evidence integrity")
    section = html.split("Evidence integrity")[1]
    assert f"{total} files, 1 read in part, 1 failed." in section
    assert section.count("<tr>") == total + 1  # one row per file, and the header
    by_name = {part.split("<br>")[0].removeprefix("<td>"): part for part in section.split("<tr>")[1:]}
    # A file read to its end: its hash, parser and version, the counts and the verdict.
    ok = by_name["Logon.evtx"]
    assert source_of(complete).sha256 in ok and "evtx 1.2" in ok and "in the file 1 · read 1 · kept 1" in ok
    assert "already imported 0 · lost 0" in ok and "complete" in ok
    # A file read in part: the reasons with their counts and what they lost, and the acknowledgement.
    part = by_name["Application.evtx"]
    assert "read in part" in part and "in the file 7 · read 1 · kept 1" in part and "lost 5" in part
    assert "record cannot be read: 2 (lost 2)" in part and "chunk checksum does not match: 1 (lost 3)" in part
    assert "Acknowledged by elena on 2026-11-24 10:00 UTC" in part and "damaged on the disk, known" in part
    # A failed file: the reason it gave.
    bad = by_name["garbage.bin"]
    assert "failed" in bad and "no parser reads this file: No parser of Nik reads this file" in bad
    # Imported before 7.0: no report, no original, and the hash 6.x noted when it noted one.
    old = by_name["History"]
    assert "no report: imported before 7.0" in old and "not kept: imported before 7.0" in old and "ab" * 32 in old
    # In the Italian report too, and the endpoint puts the section on by default and lets it off.
    assert "Integrità delle prove" in build_html(doc, lang="it", host=host, sections=["integrity"])
    answer = client.post(
        f"/api/incidents/{incident}/report", headers=key, json={"format": "html", "sections": ["notes"]}
    )
    assert "Evidence integrity" in answer.text and "Analyst notes" in answer.text
    off = client.post(f"/api/incidents/{incident}/report", headers=key, json={"format": "html", "integrity": False})
    assert "Evidence integrity" not in off.text


def test_an_incident_without_files_says_so_in_the_integrity_section(world):
    incident = an_incident(world, "rd-none")
    with SessionLocal() as db:
        host = reporting.gather(db, incident)
        doc = db.get(Incident, incident).doc
    assert host["sources"] == [] and host["channels"] == [] and host["cleared"] == {}
    html = build_html(doc, host=host, sections=["integrity"])
    assert "Evidence integrity" in html and "No file was imported." in html


def test_detections_of_the_tables_stand_in_when_the_browser_sends_none(world):
    client, key, _ = world
    incident = an_incident(world, "rd-det")
    read_file(
        world,
        incident,
        "eventlog",
        "Security.evtx",
        [SOURCE, event_row(1, 1102, "Security"), event_row(2, 4624, "Security"), end(2, 2)],
        "evtx",
    )
    with SessionLocal() as db:
        ids = list(db.scalars(select(EvidenceRecord.id).order_by(EvidenceRecord.id)))
        for number, (rule, title, level, tags, record) in enumerate(
            [
                ("r-clear", "Security log cleared", 4, ["attack.defense_evasion", "attack.t1070.001"], ids[0]),
                ("r-clear", "Security log cleared", 4, ["attack.t1070.001"], ids[1]),
                ("r-logon", "Logon", 1, ["attack.initial_access"], ids[1]),
            ]
        ):
            db.add(
                EvidenceDetection(
                    incident_id=incident,
                    record_id=record,
                    rule_id=rule,
                    rule_title=title,
                    level=level,
                    tags=tags,
                    records=[],
                    created_at=f"2026-11-24T10:00:0{number}Z",
                )
            )
        db.commit()
        found = reporting.detections(db, incident)
        assert len(reporting.detections(db, incident, limit=1)) == 1
    assert [(d["id"], d["severity"], d["count"], d["attack"]) for d in found] == [
        ("r-clear", "high", 2, ["T1070.001"]),
        ("r-logon", "informational", 1, []),
    ]
    assert found[0]["summary"] == "event 1" and found[0]["time"] == BASE + 1000

    html = client.post(f"/api/incidents/{incident}/report", headers=key, json={"format": "html", "scope": "all"}).text
    assert "T1070.001" in html and "SOC · Security log cleared ×2" in html
    sent = {"detections": [{"id": "x", "label": "from the browser", "count": 1, "attack": ["T1003"]}]}
    html = client.post(f"/api/incidents/{incident}/report", headers=key, json={"format": "html", **sent}).text
    assert "T1003" in html and "T1070.001" not in html


def test_a_report_of_twenty_thousand_records_asks_a_bounded_number_of_questions(world):
    client, key, _ = world
    incident = an_incident(world, "rd-big", {"name": "big"})
    source_id = read_file(
        world, incident, "eventlog", "Big.evtx", [SOURCE, event_row(1, 4624, "Security"), end(1, 1)], "evtx"
    )
    rows = [
        {
            "incident_id": incident,
            "source_id": source_id,
            "kind": "eventlog",
            "type": "event",
            "key": f"big:{n}",
            "ts": BASE + n,
            "seq": n,
            "event_id": 1102 if n % 5001 == 0 else 4624,
            "channel": "Security" if n % 2 else "System",
            "summary": f"event {n}",
            "data": {"TargetUserName": "admin"},
        }
        for n in range(2, 20_002)
    ]
    with SessionLocal() as db:
        db.execute(insert(EvidenceRecord), rows)
        db.add_all(
            EvidenceMark(incident_id=incident, key=f"big:{n}", flagged=True, note="", updated_by="e", updated_at="x")
            for n in range(2, 5000, 50)
        )
        db.commit()
    seen: list[str] = []

    def watch(_conn, _cursor, statement, *_rest):
        seen.append(" ".join(statement.split()))

    event.listen(engine, "before_cursor_execute", watch)
    try:
        answer = client.post(f"/api/incidents/{incident}/report", headers=key, json={"format": "html", "scope": "all"})
    finally:
        event.remove(engine, "before_cursor_execute", watch)
    assert answer.status_code == 200 and "Big.evtx" in answer.text
    assert len(seen) < 60, len(seen)
    # Every question to the records is a count, a group or a capped list: none loads them.
    for statement in (s for s in seen if "FROM evidence_records" in s):
        assert "count(" in statement.lower() or "GROUP BY" in statement or " LIMIT " in statement, statement
    with SessionLocal() as db:
        host = reporting.gather(db, incident)
    assert host["channels"][0]["events"] + host["channels"][1]["events"] == 20_001
    assert len(host["flagged"]["records"]) == 100 and host["flagged"]["total"] == 100
    assert host["cleared"] == {"Security": [BASE + 5001, BASE + 15003]}
