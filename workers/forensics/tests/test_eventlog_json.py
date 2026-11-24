"""The ``nik-eventlogs.json`` reader: the same shape as an ``.evtx`` event, the keys, the report.

Every file is made here at test time: harmless content, never evidence.
"""

from __future__ import annotations

import io
import json
import os
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import eventlog_json, evtx  # noqa: E402


def said(path: str, params: dict | None = None) -> list[dict]:
    out = io.BytesIO()
    eventlog_json.parse(path, Context(out, params or {}), "nik-eventlogs.json")
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def write(tmp_path, name: str, data) -> str:
    path = tmp_path / name
    path.write_bytes(
        data if isinstance(data, bytes) else (data if isinstance(data, str) else json.dumps(data)).encode()
    )
    return str(path)


def records(found: list[dict]) -> list[dict]:
    return [event for event in found if event["t"] == "r"]


def notes(found: list[dict]) -> dict[str, int]:
    return {event["reason"]: event["count"] for event in found if event["t"] == "note"}


LOGON = {
    "TimeCreated": "2024-05-01T10:00:00.1234567Z",
    "Id": 4624,
    "LogName": "Security",
    "ProviderName": "Microsoft-Windows-Security-Auditing",
    "RecordId": 1842,
    "MachineName": "WKS-042",
    "Level": 0,
    "Data": {
        "SubjectUserName": "WKS-042$",
        "TargetUserName": "alice",
        "TargetDomainName": "CORP",
        "LogonType": "3",
        "IpAddress": "10.1.2.3",
        "level": "kept as it is",
        "Empty": "-",
    },
}
SYSMON = {
    "TimeCreated": "2024-05-01T10:05:00.0000000Z",
    "Id": 3,
    "LogName": "Microsoft-Windows-Sysmon/Operational",
    "ProviderName": "Microsoft-Windows-Sysmon",
    "RecordId": 77,
    "MachineName": "WKS-042",
    "Level": 4,
    "Data": {"User": "CORP\\alice", "Image": "C:\\x\\a.exe", "DestinationIp": "203.0.113.9", "DestinationPort": "443"},
}


def evtx_record(event: dict) -> dict:
    """The same event as the evtx parser's JSON gives it."""
    system = {
        "Provider": {"#attributes": {"Name": event["ProviderName"]}},
        "EventID": event["Id"],
        "Level": event["Level"],
        "Channel": event["LogName"],
        "Computer": event["MachineName"],
        "EventRecordID": event["RecordId"],
        "TimeCreated": {"#attributes": {"SystemTime": event["TimeCreated"]}},
    }
    return {
        "event_record_id": event["RecordId"],
        "timestamp": "",
        "data": json.dumps({"Event": {"System": system, "EventData": event["Data"]}}),
    }


@pytest.mark.parametrize("event", [LOGON, SYSMON])
def test_an_event_has_the_shape_the_evtx_parser_gives(event):
    mine = eventlog_json.normalise_event(event)
    theirs = evtx.normalise(evtx_record(event))
    for name in ("computer", "channel", "record_id", "ts", "event_id", "username", "summary", "ioc", "script"):
        assert mine[name] == theirs[name], name
    # The JSON holds less than the .evtx: the shared keys are equal, the .evtx adds task, opcode, pid...
    assert {name: value for name, value in theirs["data"].items() if name in mine["data"]} == mine["data"]
    assert set(theirs["data"]) - set(mine["data"]) <= {"task", "opcode", "keywords", "pid", "tid"}


def test_the_export_gives_one_record_per_event_with_the_evtx_key(tmp_path):
    document = {
        "format": "nik-eventlogs",
        "host": "WKS-042",
        "logs": [{"name": "Security", "total": 52013, "first": "2024-01-01T00:00:00Z", "last": "2024-05-02T00:00:00Z"}],
        "events": [LOGON, SYSMON],
    }
    found = said(write(tmp_path, "nik-eventlogs.json", "\ufeff" + json.dumps(document)))
    source, *rest = found
    assert (source["parser"], source["kind"], source["source"]) == ("eventlog-json", "eventlog", "nik-eventlogs.json")
    recs = records(found)
    assert [r["key"] for r in recs] == [
        "evtx:WKS-042:Security:1842",
        "evtx:WKS-042:Microsoft-Windows-Sysmon/Operational:77",
    ]
    first = recs[0]
    assert (first["type"], first["event_id"], first["channel"], first["host"], first["username"]) == (
        "event",
        4624,
        "Security",
        "WKS-042",
        "alice",
    )
    assert first["ts"] == 1714557600123 and first["loc"] == {"index": 0} and recs[1]["loc"] == {"index": 1}
    assert (
        first["data"]["provider"] == "Microsoft-Windows-Security-Auditing"
        and first["data"]["Data.level"] == "kept as it is"
    )
    assert "Empty" not in first["data"] and first["ioc"] == [["ip", "10.1.2.3"]]
    assert recs[1]["ioc"] == [["ip", "203.0.113.9"]]
    assert notes(found) == {"collection script export": 2, "log sizes said by the script": 1}
    export = next(e for e in found if e["t"] == "note" and e["reason"] == "collection script export")
    assert export["detail"] == "the script exports the event IDs it was told to: this is not the whole log"
    assert (
        next(e for e in found if e["t"] == "note" and e["reason"] == "log sizes said by the script")["detail"]
        == "Security 52013"
    )
    assert rest[-1]["in_file"] == 2 and rest[-1]["read"] == 2
    again = said(write(tmp_path, "again.json", document))
    assert [r["key"] for r in records(again)] == [r["key"] for r in recs]


def test_an_array_a_single_event_and_the_properties_list_are_read(tmp_path):
    plain = {
        "Id": 1,
        "LogName": "System",
        "RecordId": "9",
        "Message": "The service started.",
        "TimeCreated": "/Date(1714557600000)/",
    }
    listed = {
        "Id": 4688,
        "Channel": "Security",
        "EventRecordID": 10,
        "Computer": "H",
        "Properties": [{"Value": "a.exe"}, {"Value": "-"}, "b"],
        "TimeCreated": {"value": "2024-05-01T12:00:00+02:00"},
    }
    found = said(write(tmp_path, "a.json", [plain, listed]), {"host": "X"})
    first, second = records(found)
    assert (
        first["key"] == "evtx:X:System:9"
        and first["data"]["Message"] == "The service started."
        and first["ts"] == 1714557600000
    )
    assert second["data"]["Data1"] == "a.exe" and second["data"]["Data3"] == "b" and "Data2" not in second["data"]
    assert second["ts"] == 1714557600000  # 12:00 at +02:00 is 10:00 UTC
    one = records(said(write(tmp_path, "one.json", LOGON)))
    assert len(one) == 1 and one[0]["key"] == "evtx:WKS-042:Security:1842"


def test_the_report_says_what_is_missing_or_wrong(tmp_path):
    events = [
        dict(LOGON),
        dict(LOGON),  # the same record number twice
        {"Id": 7, "LogName": "System", "Data": {"a": "b"}},  # no record number, no time
        "not an event",
        {"Level": 4},  # neither an ID nor a channel
    ]
    found = said(write(tmp_path, "x.json", events), {"host": "H"})
    recs = records(found)
    assert [r["key"] for r in recs] == [
        "evtx:WKS-042:Security:1842",
        "evtx:WKS-042:Security:1842",
        "evtx:H:System:pos3",
    ]
    assert recs[2]["ts"] is None and recs[2]["loc"] == {"index": 2}
    skips = [e for e in found if e["t"] == "skip"]
    assert [(s["reason"], s["lost"]) for s in skips] == [("element is not an event", 1)] * 2
    assert "index 3" in skips[0]["detail"] and "index 4" in skips[1]["detail"]
    assert notes(found) == {
        "collection script export": 5,
        "event without a usable time": 1,
        "event without a record number": 1,
    }
    # in_file = events in the array = read + lost
    assert found[-1]["in_file"] == 5 and found[-1]["read"] + 2 == 5


def test_a_file_that_stops_being_json_keeps_what_came_before_and_fails(tmp_path):
    text = json.dumps({"host": "H", "events": [LOGON, SYSMON]})
    path = write(tmp_path, "cut.json", text[: text.rindex("DestinationIp")])
    out = io.BytesIO()
    with pytest.raises(ValueError):
        eventlog_json.parse(path, Context(out), "nik-eventlogs.json")
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [line["t"] for line in lines if line["t"] != "note"] == ["source", "r", "skip"]
    assert lines[2]["reason"] == "the file stops being JSON" and "after 1 events" in lines[2]["detail"]
    assert not any(line["t"] == "end" for line in lines)


def test_a_big_export_is_streamed_across_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(eventlog_json, "CHUNK", 64)
    events = [{**LOGON, "RecordId": number, "Data": {"TargetUserName": "u\u00e9" * 5}} for number in range(1, 40)]
    found = said(write(tmp_path, "many.json", {"events": events, "host": "H"}))
    assert [r["event_id"] for r in records(found)] == [4624] * 39
    assert [r["key"].rsplit(":", 1)[1] for r in records(found)] == [str(n) for n in range(1, 40)]
    assert found[-1]["in_file"] == 39
    utf16 = said(write(tmp_path, "u16.json", json.dumps([LOGON]).encode("utf-16")))
    assert len(records(utf16)) == 1


def test_a_file_over_the_limit_is_skipped_and_the_name_is_sniffed(tmp_path, monkeypatch):
    monkeypatch.setattr(eventlog_json, "MAX_FILE", 5)
    found = said(write(tmp_path, "big.json", [LOGON]))
    assert not records(found) and [e["reason"] for e in found if e["t"] == "skip"] == ["file too large to read"]
    assert eventlog_json.sniff("/x", "C:\\case\\nik-eventlogs.json", b"[]") == "nik-eventlogs.json"
    assert eventlog_json.sniff("/x", "events.json", b"[]") is None
