"""The browser parser and the safe SQLite reader. Every database is built here, a handful of rows each.

Run in the worker's image: ``python -m pytest tests/test_browser.py`` from /opt/nik-forensics.
"""

# ruff: noqa: E501 - the schemas are copied from the queries of the parser, one line each
from __future__ import annotations

import datetime
import io
import json
import os
import plistlib
import sqlite3
import sys

import pytest

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from nik_forensics import sqlite_safe  # noqa: E402
from nik_forensics.context import Context  # noqa: E402
from nik_forensics.parsers import browser  # noqa: E402

WEBKIT = 13300000000000000  # 2022-06-18T04:26:40Z
WEBKIT_MS = 1655526400000
PRTIME = 1700000000000000
PRTIME_MS = 1700000000000
MAC = 700000000
MAC_MS = 1678307200000
PARAMS = {"profile": "Default", "host": "WKS-1", "username": "ana"}


def said(path, source, params=None, parser=browser) -> list[dict]:
    out = io.BytesIO()
    parser.parse(str(path), Context(out, PARAMS if params is None else params), source)
    return [json.loads(line) for line in out.getvalue().splitlines() if line]


def records(events, kind=None):
    return [e for e in events if e["t"] == "r" and (kind is None or e["type"] == kind)]


def of(events, kind):
    return [e for e in events if e["t"] == kind]


def end(events):
    (last,) = of(events, "end")
    return last


def build(tmp_path, name, statements, rows=()):
    path = tmp_path / name
    conn = sqlite3.connect(path)
    for sql in statements:
        conn.execute(sql)
    for sql, args in rows:
        conn.execute(sql, args)
    conn.commit()
    conn.close()
    return path


CHROME_SCHEMA = [
    "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_time INTEGER)",
    "CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER, from_visit INTEGER, transition INTEGER)",
    "CREATE TABLE downloads(id INTEGER PRIMARY KEY, target_path TEXT, current_path TEXT, tab_url TEXT, referrer TEXT,"
    " start_time INTEGER, end_time INTEGER, total_bytes INTEGER, received_bytes INTEGER, mime_type TEXT, state INTEGER)",
    "CREATE TABLE downloads_url_chain(id INTEGER, chain_index INTEGER, url TEXT)",
]
CHROME_SEARCH = [
    "CREATE TABLE keyword_search_terms(keyword_id INTEGER, url_id INTEGER, term TEXT, normalized_term TEXT)"
]


def chrome_history(tmp_path, name="History", search=True, downloads=True, extra=()):
    schema = [s for s in CHROME_SCHEMA if downloads or "downloads" not in s] + (CHROME_SEARCH if search else [])
    rows = [
        ("INSERT INTO urls VALUES(1,'https://Example.com:8443/a','Example',3,?)", (WEBKIT,)),
        ("INSERT INTO urls VALUES(2,'https://www.google.com/search?q=nik','Search',1,?)", (WEBKIT,)),
        ("INSERT INTO urls VALUES(3,'file:///C:/x.txt','',1,0)", ()),
        ("INSERT INTO visits VALUES(10,1,?,0,0x20000005)", (WEBKIT,)),
        ("INSERT INTO visits VALUES(11,1,?,10,0x40000000)", (WEBKIT + 1_000_000,)),
        ("INSERT INTO visits VALUES(12,2,?,0,1)", (WEBKIT + 2_000_000,)),
        ("INSERT INTO visits VALUES(13,3,0,0,1)", ()),
    ]
    if downloads:
        rows += [
            (
                "INSERT INTO downloads VALUES(5,'C:\\Users\\ana\\Downloads\\tool.exe','','https://t.example/p',"
                "'https://t.example/ref',?,?,100,100,'application/x-msdownload',1)",
                (WEBKIT, WEBKIT + 5_000_000),
            ),
            ("INSERT INTO downloads_url_chain VALUES(5,0,'https://cdn.example.net/redir')", ()),
            ("INSERT INTO downloads_url_chain VALUES(5,1,'https://cdn.example.net/tool.exe')", ()),
        ]
    if search:
        rows += [("INSERT INTO keyword_search_terms VALUES(2,2,'nik forensics','nik forensics')", ())]
    return build(tmp_path, name, schema, rows + list(extra))


# --------------------------------------------------------------------------- #
# Chromium                                                                    #
# --------------------------------------------------------------------------- #
def test_chromium_history_visits_downloads_and_searches(tmp_path):
    ev = said(chrome_history(tmp_path), "edge.history")
    (source,) = of(ev, "source")
    assert (source["parser"], source["version"], source["kind"], source["source"]) == (
        "browser",
        "1",
        "browser",
        "edge.history",
    )
    assert (source["host"], source["username"]) == ("WKS-1", "ana")
    visits = records(ev, "visit")
    assert [v["data"]["visitId"] for v in visits] == [10, 11, 12, 13]
    first = visits[0]
    assert first["key"] == "web:WKS-1:ana:edge:Default:visit:10"
    assert first["ts"] == WEBKIT_MS
    assert first["summary"] == "Example"
    assert first["loc"] == {"table": "visits", "rowid": 10}
    assert first["ioc"] == [["domain", "example.com"]]  # lower-case, no port
    assert first["data"]["url"] == "https://Example.com:8443/a" and first["data"]["visitCount"] == 3
    assert first["data"]["browser"] == "edge" and first["data"]["profile"] == "Default"
    assert first["data"]["isRedirect"] is False and visits[1]["data"]["isRedirect"] is True
    assert visits[1]["data"]["fromVisitId"] == 10 and visits[0]["data"]["fromVisitId"] is None
    assert visits[1]["ts"] == WEBKIT_MS + 1000
    assert visits[3]["ioc"] == [] and visits[3]["summary"] == "file:///C:/x.txt" and visits[3]["ts"] is None

    (download,) = records(ev, "download")
    assert download["key"] == "web:WKS-1:ana:edge:Default:download:5"
    assert download["ts"] == WEBKIT_MS and download["loc"] == {"table": "downloads", "rowid": 5}
    assert download["summary"] == "tool.exe <- cdn.example.net"
    assert download["ioc"] == [["url", "https://cdn.example.net/tool.exe"]]  # the end of the chain
    assert download["data"]["fileName"] == "tool.exe" and download["data"]["endTime"] == WEBKIT_MS + 5000
    assert download["data"]["mimeType"] == "application/x-msdownload" and download["data"]["state"] == 1
    assert download["data"]["referrer"] == "https://t.example/ref" and download["data"]["totalBytes"] == 100

    (search,) = records(ev, "search")
    assert search["summary"] == "nik forensics" and search["ts"] == WEBKIT_MS
    assert search["data"] == {
        "term": "nik forensics",
        "url": "https://www.google.com/search?q=nik",
        "browser": "edge",
        "profile": "Default",
    }
    assert search["key"].startswith("web:WKS-1:ana:edge:Default:search:2:")
    assert search["loc"] == {"table": "keyword_search_terms", "rowid": 1}

    # The file says 4 + 1 + 1 rows and all were read; the visit with no time is a note.
    last = end(ev)
    assert last["in_file"] == 6 and last["read"] == 6
    assert of(ev, "skip") == []
    assert {n["reason"]: n["count"] for n in of(ev, "note")} == {"row without a usable time": 1}


def test_chromium_shortcuts(tmp_path):
    path = build(
        tmp_path,
        "Shortcuts",
        [
            "CREATE TABLE omni_box_shortcuts(id TEXT PRIMARY KEY, text TEXT, url TEXT, contents TEXT, last_access_time INTEGER, number_of_hits INTEGER)"
        ],
        [
            ("INSERT INTO omni_box_shortcuts VALUES('g-1','ex','https://example.org/x','Example',?,4)", (WEBKIT,)),
            ("INSERT INTO omni_box_shortcuts VALUES('g-2','tt','https://t.test/','T',-5,1)", ()),
        ],
    )
    ev = said(path, "brave.shortcuts")
    first, second = records(ev, "shortcut")
    assert first["key"] == "web:WKS-1:ana:brave:Default:shortcut:g-1" and first["ts"] == WEBKIT_MS
    assert first["data"]["text"] == "ex" and first["data"]["title"] == "Example" and first["data"]["hits"] == 4
    assert first["loc"] == {"table": "omni_box_shortcuts", "rowid": 1} and first["ioc"] == [
        ["url", "https://example.org/x"]
    ]
    assert second["ts"] is None
    assert (end(ev)["in_file"], end(ev)["read"]) == (2, 2)


def test_chromium_bookmarks_json(tmp_path):
    tree = {
        "roots": {
            "bookmark_bar": {
                "name": "Bookmarks bar",
                "children": [
                    {"type": "url", "name": "Nik", "url": "https://nik.example/", "date_added": str(WEBKIT)},
                    {
                        "type": "folder",
                        "name": "Work",
                        "children": [{"type": "url", "name": "Wiki", "url": "http://wiki.local/"}],
                    },
                    {"type": "url", "name": "Nik", "url": "https://nik.example/", "date_added": str(WEBKIT)},
                ],
            },
            "other": {"name": "Other", "children": []},
            "sync_transaction_version": "3",
        }
    }
    path = tmp_path / "Bookmarks"
    path.write_text(json.dumps(tree))
    assert browser.sniff(str(path), "Bookmarks", path.read_bytes()[:4096]) == "chrome.bookmarks"
    ev = said(path, "opera.bookmarks")
    nik, wiki, again = records(ev, "bookmark")
    assert nik["ts"] == WEBKIT_MS and nik["data"] == {
        "name": "Nik",
        "url": "https://nik.example/",
        "folder": "Bookmarks bar",
        "dateAdded": WEBKIT_MS,
        "browser": "opera",
        "profile": "Default",
    }
    assert nik["loc"] == {"path": "Bookmarks bar"} and wiki["loc"] == {"path": "Bookmarks bar > Work"}
    assert wiki["ts"] is None and wiki["ioc"] == [["url", "http://wiki.local/"]]
    assert nik["key"] != again["key"] and again["key"].startswith(nik["key"])  # the same bookmark twice stays two rows
    assert (end(ev)["in_file"], end(ev)["read"]) == (3, 3)


def test_a_bookmarks_file_that_is_not_json_is_a_skip(tmp_path):
    path = tmp_path / "Bookmarks"
    path.write_text("{ not json")
    ev = said(path, "chrome.bookmarks")
    (skip,) = of(ev, "skip")
    assert skip["reason"] == "file cannot be read" and skip["lost"] == 0
    assert end(ev)["in_file"] is None


# --------------------------------------------------------------------------- #
# Firefox                                                                     #
# --------------------------------------------------------------------------- #
FIREFOX_SCHEMA = [
    "CREATE TABLE moz_places(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER, last_visit_date INTEGER)",
    "CREATE TABLE moz_historyvisits(id INTEGER PRIMARY KEY, from_visit INTEGER, place_id INTEGER, visit_date INTEGER, visit_type INTEGER)",
    "CREATE TABLE moz_bookmarks(id INTEGER PRIMARY KEY, type INTEGER, fk INTEGER, parent INTEGER, title TEXT, dateAdded INTEGER, guid TEXT)",
    "CREATE TABLE moz_anno_attributes(id INTEGER PRIMARY KEY, name TEXT)",
    "CREATE TABLE moz_annos(id INTEGER PRIMARY KEY, place_id INTEGER, anno_attribute_id INTEGER, content TEXT, dateAdded INTEGER)",
]


def firefox_places(tmp_path, annos=True):
    schema = [s for s in FIREFOX_SCHEMA if annos or "anno" not in s]
    rows = [
        ("INSERT INTO moz_places VALUES(1,'https://Mozilla.org/','Mozilla',2,?)", (PRTIME,)),
        ("INSERT INTO moz_places VALUES(2,'https://files.example/a.zip','',1,?)", (PRTIME + 7_000_000,)),
        ("INSERT INTO moz_historyvisits VALUES(1,0,1,?,1)", (PRTIME,)),
        ("INSERT INTO moz_historyvisits VALUES(2,1,1,?,5)", (PRTIME + 1_000_000,)),
        ("INSERT INTO moz_bookmarks VALUES(1,2,NULL,0,'',?,'root________')", (PRTIME,)),
        ("INSERT INTO moz_bookmarks VALUES(2,2,NULL,1,'toolbar',?,'toolbar_____')", (PRTIME,)),
        ("INSERT INTO moz_bookmarks VALUES(3,2,NULL,2,'Dev',?,'devguid')", (PRTIME,)),
        ("INSERT INTO moz_bookmarks VALUES(4,1,1,3,'Mozilla',?,'bm1')", (PRTIME,)),
        ("INSERT INTO moz_bookmarks VALUES(5,2,NULL,1,'',?,'tags________')", (PRTIME,)),
        ("INSERT INTO moz_bookmarks VALUES(6,1,1,5,'Mozilla',?,'bm2')", (PRTIME,)),
    ]
    if annos:
        rows += [
            ("INSERT INTO moz_anno_attributes VALUES(1,'downloads/destinationFileURI')", ()),
            ("INSERT INTO moz_anno_attributes VALUES(2,'downloads/metaData')", ()),
            ("INSERT INTO moz_annos VALUES(1,2,1,'file:///C:/Users/ana/a%20b.zip',0)", ()),
            ('INSERT INTO moz_annos VALUES(2,2,2,\'{"state":1,"endTime":1700000009000,"fileSize":2048}\',0)', ()),
        ]
    return build(tmp_path, "places.sqlite", schema, rows)


def test_firefox_places(tmp_path):
    path = firefox_places(tmp_path)
    assert browser.sniff(str(path), "places.sqlite", path.read_bytes()[:4096]) == "firefox.places"
    ev = said(path, "firefox.places")
    one, two = records(ev, "visit")
    assert one["key"] == "web:WKS-1:ana:firefox:Default:visit:1" and one["ts"] == PRTIME_MS
    assert (
        one["ioc"] == [["domain", "mozilla.org"]]
        and one["data"]["isRedirect"] is False
        and two["data"]["isRedirect"] is True
    )
    assert two["loc"] == {"table": "visits", "rowid": 2}
    (bookmark,) = records(ev, "bookmark")  # the tag entry is not a second bookmark
    assert bookmark["data"]["folder"] == "Bookmarks Toolbar > Dev" and bookmark["ts"] == PRTIME_MS
    assert bookmark["loc"] == {"table": "moz_bookmarks", "rowid": 4}
    (download,) = records(ev, "download")
    # The annotation has no date: the last visit of the place stands in (the browser's own screen does the same).
    assert download["ts"] == PRTIME_MS + 7000
    assert download["data"]["fileName"] == "a b.zip" and download["data"]["totalBytes"] == 2048
    assert download["data"]["endTime"] == 1700000009000 and download["loc"] == {"table": "moz_annos", "rowid": 1}
    assert download["ioc"] == [["url", "https://files.example/a.zip"]]
    assert download["summary"] == "a b.zip <- files.example"
    last = end(ev)
    assert (last["in_file"], last["read"]) == (4, 4)
    assert [n["reason"] for n in of(ev, "note")] == ["tag entry, not a bookmark"]
    assert of(ev, "skip") == []


def test_firefox_without_annotations_says_so_in_a_note(tmp_path):
    ev = said(firefox_places(tmp_path, annos=False), "firefox.places")
    assert of(ev, "skip") == []
    assert any(n["reason"] == "table missing" and "moz_annos" in n["detail"] for n in of(ev, "note"))
    assert end(ev)["read"] == end(ev)["in_file"] == 3


# --------------------------------------------------------------------------- #
# Safari                                                                      #
# --------------------------------------------------------------------------- #
def test_safari_history_and_plists(tmp_path):
    path = build(
        tmp_path,
        "History.db",
        [
            "CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT, visit_count INTEGER)",
            "CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL, title TEXT, redirect_source INTEGER)",
        ],
        [
            ("INSERT INTO history_items VALUES(1,'https://apple.com/',2)", ()),
            ("INSERT INTO history_visits VALUES(7,1,?,'Apple',NULL)", (MAC,)),
            ("INSERT INTO history_visits VALUES(8,1,?,'Apple',7)", (MAC + 1.5,)),
        ],
    )
    assert browser.sniff(str(path), "History.db", path.read_bytes()[:4096]) == "safari.history"
    ev = said(path, "safari.history")
    one, two = records(ev, "visit")
    assert one["key"] == "web:WKS-1:ana:safari:Default:visit:7" and one["ts"] == MAC_MS and two["ts"] == MAC_MS + 1500
    assert one["data"]["isRedirect"] is False and two["data"]["isRedirect"] is True and two["data"]["fromVisitId"] == 7
    assert one["loc"] == {"table": "visits", "rowid": 7} and one["ioc"] == [["domain", "apple.com"]]
    assert (end(ev)["in_file"], end(ev)["read"]) == (2, 2)

    when = datetime.datetime(2023, 3, 8, 12, 0, 0)
    downloads = tmp_path / "Downloads.plist"
    downloads.write_bytes(
        plistlib.dumps(
            {
                "DownloadHistory": [
                    {
                        "DownloadEntryURL": "https://dl.example/x.dmg",
                        "DownloadEntryPath": "/Users/ana/Downloads/x.dmg",
                        "DownloadEntryDateAddedKey": when,
                        "DownloadEntryDateFinishedKey": when + datetime.timedelta(seconds=9),
                        "DownloadEntryProgressTotalToLoad": 10,
                        "DownloadEntryProgressBytesSoFar": 10,
                    },
                    "garbage",
                ]
            },
            fmt=plistlib.FMT_BINARY,
        )
    )
    assert browser.sniff(str(downloads), "Downloads.plist", downloads.read_bytes()[:4096]) == "safari.downloads"
    ev = said(downloads, "safari.downloads")
    (download,) = records(ev, "download")
    stamp = int(when.replace(tzinfo=datetime.timezone.utc).timestamp() * 1000)
    assert download["ts"] == stamp and download["data"]["endTime"] == stamp + 9000 and download["data"]["state"] == 1
    assert download["loc"] == {"index": 0} and download["ioc"] == [["url", "https://dl.example/x.dmg"]]
    (skip,) = of(ev, "skip")
    assert skip["reason"] == "row cannot be read" and skip["lost"] == 1 and "DownloadHistory[1]" in skip["detail"]
    assert (end(ev)["in_file"], end(ev)["read"]) == (2, 1)

    marks = tmp_path / "Bookmarks.plist"
    marks.write_bytes(
        plistlib.dumps(
            {
                "Children": [
                    {
                        "WebBookmarkType": "WebBookmarkTypeList",
                        "Title": "BookmarksBar",
                        "Children": [
                            {
                                "WebBookmarkType": "WebBookmarkTypeLeaf",
                                "URLString": "https://a.example/",
                                "URIDictionary": {"title": "A"},
                            },
                            {"WebBookmarkType": "WebBookmarkTypeLeaf", "Title": "no url"},
                        ],
                    }
                ]
            }
        )
    )
    ev = said(marks, "safari.bookmarks")
    (mark,) = records(ev, "bookmark")
    assert (
        mark["data"]["folder"] == "Favorites" and mark["data"]["name"] == "A" and mark["loc"] == {"path": "Favorites"}
    )
    assert len(of(ev, "skip")) == 1 and (end(ev)["in_file"], end(ev)["read"]) == (2, 1)
    assert said(marks, "")[0]["source"] == "safari.bookmarks"  # by content, with no name


def test_a_plist_that_does_not_parse_is_a_skip(tmp_path):
    path = tmp_path / "Downloads.plist"
    path.write_bytes(b"bplist00\x00\x01garbage")
    ev = said(path, "safari.downloads")
    (skip,) = of(ev, "skip")
    assert skip["reason"] == "file cannot be read" and end(ev)["read"] == 0


# --------------------------------------------------------------------------- #
# Generic exports                                                             #
# --------------------------------------------------------------------------- #
def test_generic_json_and_csv_exports(tmp_path):
    path = tmp_path / "history.json"
    path.write_text(
        json.dumps(
            {
                "history": [
                    {"URL": "https://x.example/p", "Title": "X", "Date": "2024-01-02T03:04:05Z"},
                    {"title": "no url"},
                    5,
                ]
            }
        )
    )
    ev = said(path, "chrome.json")
    (visit,) = records(ev, "visit")
    assert visit["ts"] == 1704164645000 and visit["loc"] == {"row": 0} and visit["ioc"] == [["domain", "x.example"]]
    assert [s["reason"] for s in of(ev, "skip")] == ["row without what it is about", "row cannot be read"]
    assert (end(ev)["in_file"], end(ev)["read"]) == (3, 1)

    csv_path = tmp_path / "marks.csv"
    csv_path.write_text("Name,URL,Folder,Date Added\nSite,https://s.example/,Work,\n")
    ev = said(csv_path, "firefox.csv")
    (mark,) = records(ev, "bookmark")
    assert (
        mark["data"]["folder"] == "Work"
        and mark["ts"] is None
        and mark["key"].startswith("web:WKS-1:ana:firefox:Default:bookmark:")
    )


# --------------------------------------------------------------------------- #
# Damage                                                                      #
# --------------------------------------------------------------------------- #
def test_a_missing_required_table_is_a_skip_with_nothing_counted_lost(tmp_path):
    ev = said(chrome_history(tmp_path, downloads=False), "chrome.history")
    (skip,) = of(ev, "skip")
    assert skip["reason"] == "table missing" and skip["lost"] == 0 and skip["detail"].startswith("downloads:")
    assert len(records(ev, "visit")) == 4 and end(ev)["in_file"] == end(ev)["read"]


def test_a_missing_optional_table_is_a_note(tmp_path):
    ev = said(chrome_history(tmp_path, search=False), "chrome.history")
    assert of(ev, "skip") == []
    assert any(
        n["reason"] == "table missing" and n["detail"].startswith("keyword_search_terms") for n in of(ev, "note")
    )


def test_an_absurd_time_keeps_the_row_without_a_time(tmp_path):
    path = chrome_history(
        tmp_path,
        extra=[
            ("INSERT INTO urls VALUES(4,'https://z.example/','Z',1,0)", ()),
            ("INSERT INTO visits VALUES(20,4,9223372036854775807,0,0)", ()),
            ("INSERT INTO visits VALUES(21,4,'not a time',0,0)", ()),
        ],
    )
    ev = said(path, "chrome.history")
    by_id = {v["data"]["visitId"]: v for v in records(ev, "visit")}
    assert by_id[20]["ts"] is None and by_id[21]["ts"] is None and by_id[12]["ts"] == WEBKIT_MS + 2000
    assert {n["reason"]: n["count"] for n in of(ev, "note")}["row without a usable time"] == 3
    assert of(ev, "skip") == [] and end(ev)["in_file"] == end(ev)["read"] == 8


def test_a_row_that_raises_is_a_skip_and_the_rest_goes_on(tmp_path, monkeypatch):
    real = browser._host_of

    def broken(url):
        if "google" in url:
            raise RuntimeError("boom")
        return real(url)

    monkeypatch.setattr(browser, "_host_of", broken)
    ev = said(chrome_history(tmp_path, search=False), "chrome.history")
    (skip,) = of(ev, "skip")
    assert skip["reason"] == "row cannot be read" and skip["lost"] == 1 and skip["detail"].startswith("visits rowid 12")
    assert len(records(ev, "visit")) == 3 and end(ev)["in_file"] == 5 and end(ev)["read"] == 4


def test_a_database_truncated_in_the_middle_says_what_it_could_not_read(tmp_path):
    many = [
        ("INSERT INTO urls VALUES(?,?,?,1,?)", (100 + n, f"https://h{n}.example/{'p' * 60}", "t" * 40, WEBKIT))
        for n in range(400)
    ]
    many += [("INSERT INTO visits VALUES(?,?,?,0,0)", (100 + n, 100 + n, WEBKIT + n)) for n in range(400)]
    path = chrome_history(tmp_path, extra=many)
    size = path.stat().st_size
    assert size > 20_000
    with open(path, "r+b") as handle:
        handle.truncate(size // 2)
    ev = said(path, "chrome.history")
    skips = of(ev, "skip")
    assert skips, "the damage must be in the report"
    assert all(s["reason"] in ("table cannot be read to its end", "database cannot be opened") for s in skips)
    assert any("cannot be read to its end" in s["reason"] or "opened" in s["reason"] for s in skips)
    last = end(ev)
    if last["in_file"] is not None:  # whatever count was possible, read + lost accounts for it
        assert last["read"] + sum(s["lost"] for s in skips) >= min(last["read"], last["in_file"])


def test_a_table_that_stops_at_a_damaged_page_counts_what_was_lost(tmp_path, monkeypatch):
    path = chrome_history(tmp_path, search=False)
    real = sqlite_safe.rows

    def failing(conn, sql, params=()):
        for n, row in enumerate(real(conn, sql, params)):
            if n == 2 and "FROM visits" in sql:
                raise sqlite3.DatabaseError("database disk image is malformed")
            yield row

    monkeypatch.setattr(sqlite_safe, "rows", failing)
    ev = said(path, "chrome.history")
    (skip,) = of(ev, "skip")
    assert skip["reason"] == "table cannot be read to its end" and skip["lost"] == 2
    assert skip["detail"].startswith("visits after 2 rows") and "malformed" in skip["detail"]
    assert len(records(ev, "download")) == 1  # the next table was read
    assert end(ev)["in_file"] == 5 and end(ev)["read"] + 2 == 5


def test_a_file_that_is_not_sqlite_under_a_history_name_is_a_skip(tmp_path):
    path = tmp_path / "History"
    path.write_bytes(b"this is not a database at all" * 20)
    assert browser.sniff(str(path), "History", path.read_bytes()[:4096]) is None
    ev = said(path, "chrome.history")
    (skip,) = of(ev, "skip")
    assert skip["reason"] == "database cannot be opened" and skip["lost"] == 0
    assert end(ev)["read"] == 0 and end(ev)["in_file"] is None


def test_the_row_cap_is_a_skip_with_the_rows_not_read(tmp_path, monkeypatch):
    monkeypatch.setattr(browser, "MAX_ROWS", 2)
    ev = said(chrome_history(tmp_path, search=False), "chrome.history")
    limit = [s for s in of(ev, "skip") if s["reason"] == "limit reached"]
    assert len(limit) == 1 and limit[0]["lost"] == 2 and limit[0]["detail"].startswith("visits")
    assert len(records(ev, "visit")) == 2


def test_a_database_in_wal_mode_is_noted(tmp_path):
    path = chrome_history(tmp_path, search=False)
    data = bytearray(path.read_bytes())
    data[18] = data[19] = 2
    path.write_bytes(bytes(data))
    ev = said(path, "chrome.history")
    note = [n for n in of(ev, "note") if n["reason"] == "database in WAL mode"]
    assert len(note) == 1 and "-wal" in note[0]["detail"]
    assert len(records(ev, "visit")) == 4
    assert not [n for n in os.listdir(tmp_path) if n.endswith(("-wal", "-shm"))]


# --------------------------------------------------------------------------- #
# Keys, profiles, sniff                                                       #
# --------------------------------------------------------------------------- #
def test_keys_are_stable_and_profiles_and_hosts_do_not_collide(tmp_path):
    path = chrome_history(tmp_path)
    again = [r["key"] for r in records(said(path, "chrome.history"))]
    assert again == [r["key"] for r in records(said(path, "chrome.history"))]
    assert len(set(again)) == len(again)
    other_profile = {r["key"] for r in records(said(path, "chrome.history", {**PARAMS, "profile": "Profile 1"}))}
    other_host = {r["key"] for r in records(said(path, "chrome.history", {**PARAMS, "host": "WKS-2"}))}
    other_browser = {r["key"] for r in records(said(path, "edge.history"))}
    assert not set(again) & (other_profile | other_host | other_browser)
    empty = records(said(path, "chrome.history", {}))
    assert empty[0]["key"] == "web:::chrome::visit:10"


def test_sniff_by_name_by_tables_and_with_a_source_that_is_unknown(tmp_path):
    history = chrome_history(tmp_path, search=False)
    head = history.read_bytes()[:4096]
    assert browser.sniff(str(history), "History", head) == "chrome.history"
    assert browser.sniff(str(history), "Default\\History", head) == "chrome.history"
    odd = tmp_path / "copy-of-something"
    odd.write_bytes(head if len(history.read_bytes()) <= 4096 else history.read_bytes())
    assert browser.sniff(str(odd), "copy-of-something", odd.read_bytes()[:4096]) == "chrome.history"  # by its tables
    assert browser.sniff(str(odd), "notes.txt", b"plain text") is None
    firefox = firefox_places(tmp_path)
    assert browser.sniff(str(firefox), "x.db", firefox.read_bytes()[:4096]) == "firefox.places"
    # A source that is not one of ours: the parser finds out what the file is.
    assert said(odd, "")[0]["source"] == "chrome.history"
    assert said(odd, "nonsense")[0]["source"] == "chrome.history"
    unknown = tmp_path / "unknown.bin"
    unknown.write_bytes(b"\x00\x01\x02")
    with pytest.raises(ValueError):
        said(unknown, "")
    assert all(s.split(".")[0] in ("chrome", "edge", "brave", "opera", "firefox", "safari") for s in browser.SOURCES)


def test_times_of_the_three_epochs():
    assert browser.webkit_to_ms(WEBKIT) == WEBKIT_MS
    assert browser.firefox_to_ms(PRTIME) == PRTIME_MS
    assert browser.mac_to_ms(MAC) == MAC_MS
    for bad in (None, 0, -1, "x", b"\x01", float("nan"), 9e30):
        assert browser.webkit_to_ms(bad) is None and browser.firefox_to_ms(bad) is None
    assert browser.mac_to_ms(9e30) is None


# --------------------------------------------------------------------------- #
# sqlite_safe                                                                 #
# --------------------------------------------------------------------------- #
def test_sqlite_safe_reads_and_counts(tmp_path):
    path = chrome_history(tmp_path)
    conn = sqlite_safe.open_ro(str(path))
    try:
        assert {"urls", "visits", "downloads"} <= sqlite_safe.tables(conn)
        assert sqlite_safe.count(conn, "visits") == 4 and sqlite_safe.count(conn, "nope") is None
        assert "visit_time" in sqlite_safe.columns(conn, "visits")
        (row, *_rest) = sqlite_safe.rows(conn, "SELECT id, url FROM urls WHERE id = ?", (1,))
        assert row == {"id": 1, "url": "https://Example.com:8443/a"}
        assert sqlite_safe.scalar(conn, "SELECT count(*) FROM urls") == 3
        with pytest.raises(ValueError):
            sqlite_safe.count(conn, 'urls"; DROP TABLE urls; --')
    finally:
        conn.close()
    assert sorted(os.listdir(tmp_path)) == ["History"]  # immutable: no -shm or -wal was made


def test_sqlite_safe_refuses_attach_pragma_writes_and_extensions(tmp_path):
    path = chrome_history(tmp_path)
    before = path.read_bytes()
    conn = sqlite_safe.open_ro(str(path))
    try:
        for sql in (
            f"ATTACH DATABASE '{tmp_path / 'other.db'}' AS other",
            "INSERT INTO urls VALUES(99,'x','x',1,1)",
            "UPDATE urls SET title = 'x'",
            "DELETE FROM urls",
            "CREATE TABLE evil(a)",
            "DROP TABLE urls",
            "PRAGMA query_only = OFF",
            "PRAGMA journal_mode = WAL",
            "VACUUM",
        ):
            with pytest.raises(sqlite3.DatabaseError):
                conn.execute(sql)
        with pytest.raises((AttributeError, sqlite3.Error)):
            conn.load_extension("nothing")
        with pytest.raises(sqlite3.DatabaseError):
            conn.execute("SELECT load_extension('nothing')")
        assert conn.execute("SELECT count(*) FROM urls").fetchone()[0] == 3
    finally:
        conn.close()
    assert path.read_bytes() == before and not (tmp_path / "other.db").exists()
    assert sorted(os.listdir(tmp_path)) == ["History"]


def test_sqlite_safe_text_is_decoded_with_replacement_and_a_view_is_not_a_table(tmp_path):
    path = build(
        tmp_path,
        "odd.db",
        ["CREATE TABLE t(a TEXT)", "CREATE VIEW v AS SELECT a FROM t"],
        [("INSERT INTO t VALUES(CAST(x'61ff62' AS TEXT))", ())],
    )
    conn = sqlite_safe.open_ro(str(path))
    try:
        assert sqlite_safe.tables(conn) == {"t"}
        assert next(sqlite_safe.rows(conn, "SELECT a FROM t")) == {"a": "a\ufffdb"}
    finally:
        conn.close()


def test_sqlite_safe_open_refuses_what_is_not_sqlite_and_stop_interrupts(tmp_path):
    text = tmp_path / "plain"
    text.write_text("hello")
    with pytest.raises(sqlite_safe.NotSqlite):
        sqlite_safe.open_ro(str(text))
    assert sqlite_safe.wal_mode(str(text)) is False
    path = chrome_history(tmp_path)
    conn = sqlite_safe.open_ro(str(path), stop=lambda: True)
    try:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute(
                "WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 100000000) SELECT count(*) FROM c"
            ).fetchall()
    finally:
        conn.close()
