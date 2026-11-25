"""The Plaso parser: the events of a psort export (JSON lines, dynamic CSV, l2tcsv) and the section each goes to.

Run in the worker's image: ``python -m pytest tests`` from /opt/nik-forensics. The exports are made here, line by line,
in the shape ``psort`` writes them: harmless text, never evidence.
"""

from __future__ import annotations

import io
import json
import os
import pathlib
import sys
import tempfile

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from nik_forensics import parsers, triage  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import ViewError, plaso  # noqa: E402

MICROSECONDS = 1_700_000_000_000_000  # 2023-11-14T22:13:20Z


def event(data_type: str, **more) -> dict:
    return {
        "__container_type__": "event",
        "__type__": "AttributeContainer",
        "data_type": data_type,
        "display_name": "OS:/evidence/file",
        "message": f"a message of {data_type}",
        "parser": "something",
        "timestamp": MICROSECONDS,
        "timestamp_desc": "Content Modification Time",
        **more,
    }


def export(tmp_path, events: list, name: str = "timeline.jsonl", tail: bytes = b"") -> str:
    path = tmp_path / name
    path.write_bytes(
        b"\n".join(json.dumps(item).encode() if not isinstance(item, bytes) else item for item in events) + b"\n" + tail
    )
    return str(path)


def read(path: str, source: str = "plaso.jsonl", params=None) -> list[dict]:
    out = io.BytesIO()
    plaso.parse(path, Context(out, params or {}), source)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def records(found: list[dict]) -> list[dict]:
    return [line for line in found if line["t"] == "r"]


def route_of(data_type: str, **more) -> tuple[str, str]:
    folder = pathlib.Path(tempfile.mkdtemp())
    (record,) = records(read(export(folder, [event(data_type, **more)])))
    return record["k"], record["src"]


# --------------------------------------------------------------------------- #
# The section of an event                                                     #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("data_type", "kind", "source"),
    [
        ("windows:evtx:record", "eventlog", "evtx"),
        ("fs:stat", "disk", "plaso.filestat"),
        ("fs:stat:ntfs", "disk", "ntfs.mft"),
        ("fs:mft:entry", "disk", "ntfs.mft"),
        ("fs:ntfs:usn_change", "disk", "ntfs.usnjrnl"),
        ("windows:prefetch:execution", "endpoint", "windows.execution.prefetch"),
        ("windows:registry:amcache", "endpoint", "windows.execution.amcache"),
        ("windows:registry:appcompatcache", "endpoint", "windows.execution.shimcache"),
        ("windows:registry:userassist", "endpoint", "windows.execution.userassist"),
        ("windows:registry:bam", "endpoint", "windows.execution.bam-hive"),
        ("windows:registry:service", "endpoint", "windows.persistence.services-hive"),
        ("windows:registry:usbstor", "endpoint", "windows.usb.usbstor-hive"),
        ("windows:registry:mounted_devices", "endpoint", "windows.usb.mounteddevices"),
        ("windows:registry:mrulistex", "endpoint", "windows.fileaccess.recentdocs"),
        ("windows:lnk:link", "endpoint", "windows.fileaccess.lnk"),
        ("olecf:dest_list:entry", "endpoint", "windows.fileaccess.jumplist"),
        ("windows:srum:network_usage", "endpoint", "windows.network.srum-network"),
        ("windows:srum:application_usage", "endpoint", "windows.network.srum-apps"),
        ("chrome:history:page_visited", "browser", "chrome.history"),
        ("chrome:history:file_downloaded", "browser", "chrome.history"),
        ("firefox:places:page_visited", "browser", "firefox.places"),
        ("safari:history:visit_sqlite", "browser", "safari.history"),
        ("bash:history:command", "commands", "bash"),
        ("shell:zsh:history", "commands", "zsh"),
        ("syslog:line", "syslog", "linux.auth"),
        ("syslog:ssh:login", "syslog", "linux.auth"),
        ("linux:utmp:event", "syslog", "linux.auth"),
        ("selinux:line", "syslog", "linux.audit"),
        ("systemd:journal", "syslog", "linux.journal"),
        ("mac:asl:event", "syslog", "macos.unifiedlog"),
        ("something:nobody:knows", "endpoint", "plaso.other"),
    ],
)
def test_each_event_goes_to_the_section_its_data_type_says(data_type, kind, source):
    assert route_of(data_type) == (kind, source)


def test_a_run_key_of_the_registry_is_a_persistence_record_and_another_key_is_not():
    assert route_of(
        "windows:registry:key_value", key_path="HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
    ) == (
        "endpoint",
        "windows.persistence.runkeys-hive",
    )
    assert route_of("windows:registry:key_value", key_path="HKEY_CURRENT_USER\\Software\\Other") == (
        "endpoint",
        "plaso.other",
    )


def test_a_chromium_event_is_of_the_browser_the_path_of_its_file_says():
    assert route_of(
        "chrome:history:page_visited",
        display_name="TSK:/Users/a/AppData/Local/Microsoft/Edge/User Data/Default/History",
    ) == (
        "browser",
        "edge.history",
    )
    assert (
        route_of("chrome:history:page_visited", filename="/home/a/.config/BraveSoftware/Brave-Browser/Default/History")[
            1
        ]
        == "brave.history"
    )


def test_what_is_not_known_keeps_its_data_type_as_its_type(tmp_path):
    (record,) = records(
        read(export(tmp_path, [event("vendor:thing:happened", hostname="H1", username="u1", foo="bar")]))
    )
    assert (record["k"], record["src"], record["type"], record["host"], record["username"]) == (
        "endpoint",
        "plaso.other",
        "vendor:thing:happened",
        "H1",
        "u1",
    )
    assert record["data"]["foo"] == "bar" and record["data"]["timestampDesc"] == "Content Modification Time"
    assert record["data"]["dataType"] == "vendor:thing:happened" and "__type__" not in record["data"]


# --------------------------------------------------------------------------- #
# Event logs, as the native reader keys them                                  #
# --------------------------------------------------------------------------- #
def test_an_evtx_event_has_the_key_of_the_real_log_and_its_fields(tmp_path):
    xml = (
        "<Event><System><Channel>Security</Channel><Computer>WKS-042</Computer></System>"
        '<EventData><Data Name="TargetUserName">bob</Data><Data Name="LogonType">3</Data></EventData></Event>'
    )
    (record,) = records(
        read(
            export(
                tmp_path,
                [
                    event(
                        "windows:evtx:record",
                        computer_name="WKS-042",
                        event_identifier=4624 | (1 << 16),
                        record_number=1842,
                        source_name="Microsoft-Windows-Security-Auditing",
                        strings=["bob", "3"],
                        xml_string=xml,
                        timestamp_desc="Creation Time",
                        username="-",
                    )
                ],
            )
        )
    )
    assert record["key"] == "evtx:WKS-042:Security:1842"
    assert (record["k"], record["src"], record["channel"], record["event_id"], record["host"]) == (
        "eventlog",
        "evtx",
        "Security",
        4624,
        "WKS-042",
    )
    assert record["data"]["TargetUserName"] == "bob" and record["data"]["LogonType"] == "3"
    assert record["ts"] == 1_700_000_000_000 and record["username"] == ""


def test_the_channel_of_an_evtx_event_without_xml_comes_from_the_file_name(tmp_path):
    (record,) = records(
        read(
            export(
                tmp_path,
                [event("windows:evtx:record", record_number=5, filename="/C/Windows/System32/winevt/Logs/System.evtx")],
            )
        )
    )
    assert record["channel"] == "System" and record["key"].endswith(":System:5")


# --------------------------------------------------------------------------- #
# Times, keys, the file                                                       #
# --------------------------------------------------------------------------- #
def test_one_object_with_several_times_is_several_records_with_distinct_keys(tmp_path):
    descriptions = ["Content Modification Time", "Last Access Time", "Creation Time", "Metadata Modification Time"]
    found = read(
        export(
            tmp_path,
            [
                event("fs:stat", timestamp=MICROSECONDS + n * 10**6, timestamp_desc=d)
                for n, d in enumerate(descriptions)
            ],
        )
    )
    rows = records(found)
    assert len(rows) == 4 and len({row["key"] for row in rows}) == 4
    assert [row["ts"] for row in rows] == [1_700_000_000_000 + n * 1000 for n in range(4)]
    assert [row["data"]["timestampDesc"] for row in rows] == descriptions
    assert found[-1] == {
        "t": "end",
        "in_file": 4,
        "read": 4,
        "first_ts": 1_700_000_000_000,
        "last_ts": 1_700_000_003_000,
    }
    same_time = records(
        read(export(tmp_path, [event("fs:stat", timestamp_desc=d) for d in descriptions[:2]], "same.jsonl"))
    )
    assert same_time[0]["key"] != same_time[1]["key"]


def test_the_same_export_read_twice_gives_the_same_keys(tmp_path):
    path = export(
        tmp_path,
        [event("syslog:line", message=f"line {n}") for n in range(5)] + [event("syslog:line", message="line 0")],
    )
    first, second = records(read(path)), records(read(path))
    assert [row["key"] for row in first] == [row["key"] for row in second]
    assert len({row["key"] for row in first}) == 6, "two identical events are two records: the second has a counter"


def test_events_without_a_time_are_kept_and_counted(tmp_path):
    found = read(export(tmp_path, [event("fs:stat", timestamp=0), event("fs:stat", timestamp=None), event("fs:stat")]))
    assert [row["ts"] for row in records(found)] == [None, None, 1_700_000_000_000]
    assert {line["reason"]: line["count"] for line in found if line["t"] == "note"} == {"event without a time": 2}


def test_times_in_seconds_milliseconds_and_text_are_understood(tmp_path):
    values = [
        1_700_000_000,
        1_700_000_000_000,
        1_700_000_000_000_000,
        "2023-11-14T22:13:20.000000+00:00",
        "2023-11-14T22:13:20Z",
    ]
    assert {
        row["ts"] for row in records(read(export(tmp_path, [event("fs:stat", timestamp=value) for value in values])))
    } == {1_700_000_000_000}


def test_lines_that_are_not_events_are_skips_with_their_place(tmp_path):
    good = json.dumps(event("fs:stat")).encode()
    path = export(tmp_path, [good, b"this is not json {", b"[1, 2]", b"", good.replace(b"fs:stat", b"fs:stat2")])
    found = read(path)
    skips = [line for line in found if line["t"] == "skip"]
    assert [skip["reason"] for skip in skips] == ["line is not JSON", "line is not a Plaso event"]
    assert skips[0]["offset"] == len(good) + 1 and skips[0]["length"] == len(b"this is not json {") + 1
    assert len(records(found)) == 2 and found[-1]["in_file"] == 4
    blank = [line for line in found if line["t"] == "note"]
    assert blank == [{"t": "note", "reason": "blank line", "count": 1, "detail": ""}]


def test_a_line_longer_than_the_limit_is_skipped_and_the_next_is_read(tmp_path, monkeypatch):
    monkeypatch.setattr(plaso, "MAX_LINE", 2000)
    big = json.dumps(event("fs:stat", message="x" * 5000)).encode()
    found = read(export(tmp_path, [event("fs:stat"), big, event("fs:stat", message="after")]))
    assert [line["reason"] for line in found if line["t"] == "skip"] == ["line longer than the limit"]
    assert [row["summary"] for row in records(found)][-1] == "after" and len(records(found)) == 2


def test_the_place_of_a_record_opens_the_lines_of_the_original(tmp_path):
    path = export(tmp_path, [event("fs:stat", message=f"event {n}") for n in range(8)])
    row = records(read(path))[5]
    shown = plaso.view(path, "plaso.jsonl", row["loc"])
    assert row["loc"]["line"] == 6 and "event 5" in shown["text"] and shown["highlight"] == [6, 6]
    with pytest.raises(ViewError):
        plaso.view(path, "plaso.jsonl", {"offset": 10**9, "length": 5, "line": 3})


# --------------------------------------------------------------------------- #
# The CSV outputs, and recognising a file                                     #
# --------------------------------------------------------------------------- #
DYNAMIC = (
    "datetime,timestamp_desc,source,source_long,message,parser,display_name,tag\n"
    "2023-11-14T22:13:20.000000+00:00,Content Modification Time,FILE,OS Metadata,"
    "/etc/passwd Type: file,filestat,OS:/etc/passwd,-\n"
    "2023-11-14T22:13:21.000000+00:00,Creation Time,EVT,WinEVTX,"
    '"[4624] ""quoted"", with a comma",winevtx,OS:/C/Security.evtx,-\n'
    "0000-00-00T00:00:00+00:00,Not a time,LOG,Syslog line,no time here,syslog,OS:/var/log/auth.log,-\n"
    "2023-11-14T22:13:22.000000+00:00,Last Visited Time,WEBHIST,Chrome,only five cells,chrome_27_history\n"
)
L2T = (
    "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra\n"
    "11/14/2023,22:13:20,UTC,M...,FILE,OS Metadata,Content Modification Time,-,WKS,short text,"
    "/etc/hosts Type: file,2,/etc/hosts,12,-,filestat,-\n"
)


def test_a_dynamic_csv_is_read_row_by_row_and_a_row_of_the_wrong_width_is_a_skip(tmp_path):
    path = tmp_path / "timeline.csv"
    path.write_bytes(DYNAMIC.encode())
    head = path.read_bytes()[:4096]
    assert plaso.sniff(str(path), "timeline.csv", head) == "plaso.csv"
    found = read(str(path), "plaso.csv", {"host": "H"})
    rows = records(found)
    assert [(row["k"], row["src"]) for row in rows] == [
        ("disk", "plaso.filestat"),
        ("eventlog", "evtx"),
        ("syslog", "linux.auth"),
    ]
    assert rows[0]["ts"] == 1_700_000_000_000 and rows[2]["ts"] is None and rows[0]["host"] == "H"
    assert "quoted" in rows[1]["summary"] and rows[1]["data"]["timestampDesc"] == "Creation Time"
    (skip,) = [line for line in found if line["t"] == "skip"]
    assert (
        skip["reason"].startswith("row with another number of cells")
        and skip["offset"] > 0
        and "6 cells" in skip["detail"]
    )
    assert found[-1]["in_file"] == 4 and found[-1]["read"] == 3
    assert plaso.view(str(path), "plaso.csv", rows[1]["loc"])["highlight"] == [3, 3]


def test_an_l2tcsv_is_told_by_its_header_and_its_time_is_read(tmp_path):
    path = tmp_path / "l2t.csv"
    path.write_bytes(L2T.encode())
    assert plaso.sniff(str(path), "l2t.csv", path.read_bytes()[:4096]) == "plaso.csv"
    (row,) = records(read(str(path), "plaso.csv"))
    assert (
        row["ts"] == 1_700_000_000_000 and row["host"] == "WKS" and (row["k"], row["src"]) == ("disk", "plaso.filestat")
    )


def test_a_csv_is_never_taken_for_plaso_by_its_name_alone(tmp_path):
    path = tmp_path / "psort.csv"
    path.write_bytes(b"a,b,c\n1,2,3\n")
    assert plaso.sniff(str(path), "psort.csv", path.read_bytes()) is None
    assert plaso.sniff(str(path), "plaso.jsonl", b'{"some": "json"}\n') is None
    assert plaso.sniff(str(path), "x", b"SQLite format 3\x00" + b"\x00" * 100) is None


def test_a_psort_json_line_file_is_recognised_by_what_a_worker_recognises_with(tmp_path):
    path = export(tmp_path, [event("fs:stat")], "whatever.dat")
    module, source = parsers.recognise(path, "whatever.dat")
    assert (module.NAME, module.KIND, source) == ("plaso", "collection", "plaso.jsonl")
    assert parsers.by_source("collection", "plaso.csv").NAME == "plaso"
    assert triage.what_is(path, "whatever.dat") == {
        "parser": "plaso",
        "version": "2",
        "kind": "collection",
        "source": "plaso.jsonl",
    }


def test_a_record_may_name_its_own_section_and_the_detector_is_shown_it():
    class Detector:
        def __init__(self) -> None:
            self.seen: list[tuple[str, str]] = []

        def see(self, kind, key, type_, ts, host, username, event_id, channel, summary, data, source):  # noqa: PLR0913
            self.seen.append((kind, source))
            return []

    out = io.BytesIO()
    ctx = Context(out)
    ctx.detector = Detector()
    ctx.source("plaso", "1", "collection", "plaso.jsonl")
    ctx.record(key="k", type="event", kind="eventlog", source="evtx")
    ctx.record(key="k2", type="event")
    first, second = [json.loads(line) for line in out.getvalue().splitlines()[1:]]
    assert (first["k"], first["src"]) == ("eventlog", "evtx") and "k" not in second and "src" not in second
    assert ctx.detector.seen == [("eventlog", "evtx"), ("collection", "plaso.jsonl")]
