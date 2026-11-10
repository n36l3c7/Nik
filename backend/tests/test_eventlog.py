"""Windows event logs: record normalization, the .evtx upload and its limits."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.main import app as fastapi_app
from app.parsing import eventlog
from tests.conftest import make_key

HOUR = 3600 * 1000


def record(record_id, event_id, channel="Security", when="2026-03-02T10:00:00.1234567Z", data=None, **extra):
    """A record as the evtx parser yields it (``data`` is the event as JSON)."""
    event_id_node = {"#attributes": {"Qualifiers": 16384}, "#text": event_id} if channel == "System" else event_id
    event = {
        "Event": {
            "System": {
                "Provider": {"#attributes": {"Name": "Microsoft-Windows-Security-Auditing"}},
                "EventID": event_id_node,
                "Level": 0,
                "TimeCreated": {"#attributes": {"SystemTime": when}},
                "EventRecordID": record_id,
                "Channel": channel,
                "Computer": "WKS-042",
            },
            **(data or {}),
        }
    }
    return {"event_record_id": record_id, "timestamp": when, "data": json.dumps(event), **extra}


def test_normalize_record_keeps_curated_ids_only():
    channel, time_ms, event = eventlog.normalize_record(
        record(
            7,
            4624,
            data={
                "EventData": {
                    "TargetUserName": "m.rossi",
                    "LogonType": 10,
                    "IpAddress": "185.220.101.47",
                    "WorkstationName": "-",
                    "LogonGuid": "{00000000-0000-0000-0000-000000000000}",
                }
            },
        )
    )
    assert channel == "Security" and time_ms == 1772445600123
    assert event["id"] == "evt:Security:7" and event["eventId"] == 4624
    assert event["computer"] == "WKS-042"
    # Values are strings; placeholders and empty values are dropped.
    assert event["data"] == {"TargetUserName": "m.rossi", "LogonType": "10", "IpAddress": "185.220.101.47"}

    channel, _, event = eventlog.normalize_record(record(8, 4907))
    assert channel == "Security" and event is None


def test_normalize_record_user_data_and_unnamed_fields():
    _, _, cleared = eventlog.normalize_record(
        record(
            1,
            104,
            channel="System",
            data={"UserData": {"LogFileCleared": {"#attributes": {"xmlns": "x"}, "SubjectUserName": "tony"}}},
        )
    )
    assert cleared["eventId"] == 104 and cleared["data"] == {"SubjectUserName": "tony"}

    _, _, pipeline = eventlog.normalize_record(
        record(2, 800, channel="windows powershell", data={"EventData": {"Data": ["Get-Process", "", "HostName=x"]}})
    )
    # The channel gets its canonical spelling; unnamed <Data> elements are numbered.
    assert pipeline["channel"] == "Windows PowerShell"
    assert pipeline["data"] == {"Data1": "Get-Process", "Data3": "HostName=x"}

    long_script = "A" * (eventlog.MAX_VALUE + 50)
    _, _, block = eventlog.normalize_record(
        record(
            3,
            4104,
            channel="Microsoft-Windows-PowerShell/Operational",
            data={"EventData": {"ScriptBlockText": long_script}},
        )
    )
    assert block["data"]["ScriptBlockText"].endswith("[…]")
    assert len(block["data"]["ScriptBlockText"]) < len(long_script)


def test_silent_periods():
    times = [0, HOUR, 2 * HOUR, 20 * HOUR, 21 * HOUR, 30 * HOUR]
    assert eventlog.silent_periods(times) == [[2 * HOUR, 20 * HOUR], [21 * HOUR, 30 * HOUR]]
    assert eventlog.silent_periods([]) == []


def test_parse_evtx_stats_cap_and_recovered(monkeypatch):
    records = [
        record(1, 4624, when="2026-03-01T08:00:00Z"),
        record(2, 4907, when="2026-03-01T09:00:00Z"),
        record(3, 4625, when="2026-03-02T09:00:00Z"),
        # A recovered copy of a live record is ignored; a lost one is kept.
        record(3, 4625, when="2026-03-02T09:00:00Z", recovered=True),
        record(9, 1102, when="2026-02-01T09:00:00Z", recovered=True),
    ]
    monkeypatch.setattr(eventlog, "_records", lambda data: iter(records))
    monkeypatch.setattr(eventlog, "MAX_EVENTS_PER_CHANNEL", 2)
    result = eventlog.parse_evtx(b"ElfFile\x00")
    security = result["Security"]
    assert [e["recordId"] for e in security["events"]] == [3, 1]  # newest first, capped
    stats = security["stats"]
    assert stats["total"] == 5 and stats["kept"] == 2 and stats["dropped"] == 1
    # Coverage comes from the live records of any id.
    assert stats["first"] == 1772352000000 and stats["last"] == 1772442000000
    assert stats["gaps"] == [[1772355600000, 1772442000000]]


def test_parse_evtx_rejects_other_files():
    with pytest.raises(ValueError, match="Not an .evtx file"):
        eventlog.parse_evtx(b"MZ\x90\x00 not a log")


def test_upload_evtx(admin: TestClient, monkeypatch):
    k = TestClient(fastapi_app)
    key = make_key(admin, role="analyst")
    k.post("/api/incidents", headers=key, json={"id": "ev1", "data": {}})

    r = k.post("/api/incidents/ev1/upload?tab=eventlogs", headers=key, files={"file": ("x.evtx", b"garbage")})
    assert r.status_code == 400 and "evtx" in r.json()["detail"]

    records = [record(1, 4624, data={"EventData": {"TargetUserName": "admin"}}), record(2, 1102)]
    monkeypatch.setattr(eventlog, "_records", lambda data: iter(records))
    r = k.post(
        "/api/incidents/ev1/upload?tab=eventlogs&async=true",
        headers=key,
        files={"file": ("Security.evtx", b"ElfFile\x00rest")},
    )
    assert r.status_code == 202
    job = k.get(f"/api/jobs/{r.json()['jobId']}", headers=key).json()
    assert job["status"] == "done" and job["result"]["rows"] == 2 and job["result"]["channels"] == ["Security"]

    channel = k.get("/api/incidents/ev1", headers=key).json()["data"]["eventlogs"]["channels"]["Security"]
    assert sorted(e["eventId"] for e in channel["events"]) == [1102, 4624]
    meta = channel["meta"]
    assert meta["fileName"] == "Security.evtx" and meta["format"] == "evtx" and len(meta["sha256"]) == 64

    actions = [e["action"] for e in admin.get("/api/audit", headers=key).json()["entries"]]
    assert "eventlog.upload" in actions
