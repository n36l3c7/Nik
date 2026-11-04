"""Safari artifacts: History.db (SQLite) and Downloads/Bookmarks.plist (binary or XML)."""

from __future__ import annotations

import plistlib
import sqlite3
from datetime import datetime, timezone

from fastapi.testclient import TestClient

MAC_EPOCH = datetime(2001, 1, 1, tzinfo=timezone.utc)


def _ms(dt: datetime) -> int:
    return round(dt.replace(tzinfo=timezone.utc).timestamp() * 1000)


def _history_db(path) -> bytes:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE history_items (id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE,
            domain_expansion TEXT, visit_count INTEGER NOT NULL);
        CREATE TABLE history_visits (id INTEGER PRIMARY KEY, history_item INTEGER NOT NULL,
            visit_time REAL NOT NULL, title TEXT, load_successful BOOLEAN DEFAULT 1,
            redirect_source INTEGER NULL UNIQUE, redirect_destination INTEGER NULL UNIQUE);
        INSERT INTO history_items VALUES (1, 'http://bit.ly/x', 'bit', 1), (2, 'https://evil.example/', 'evil', 3);
        """
    )
    t0 = (datetime(2026, 11, 2, 2, 14, tzinfo=timezone.utc) - MAC_EPOCH).total_seconds()
    conn.execute("INSERT INTO history_visits VALUES (10, 1, ?, NULL, 1, NULL, 11)", (t0,))
    conn.execute("INSERT INTO history_visits VALUES (11, 2, ?, 'Evil', 1, 10, NULL)", (t0 + 1.5,))
    conn.commit()
    conn.close()
    return path.read_bytes()


DOWNLOADS = {
    "DownloadHistory": [
        {
            "DownloadEntryURL": "https://evil.example/payload.dmg",
            "DownloadEntryPath": "/Users/jdoe/Downloads/payload.dmg",
            "DownloadEntryProgressBytesSoFar": 10,
            "DownloadEntryProgressTotalToLoad": 10,
            "DownloadEntryDateAddedKey": datetime(2026, 11, 2, 2, 14),
            "DownloadEntryDateFinishedKey": datetime(2026, 11, 2, 2, 15),
        }
    ]
}
BOOKMARKS = {
    "WebBookmarkType": "WebBookmarkTypeList",
    "Children": [
        {"Title": "History", "WebBookmarkType": "WebBookmarkTypeProxy"},
        {
            "Title": "com.apple.ReadingList",
            "WebBookmarkType": "WebBookmarkTypeList",
            "Children": [
                {
                    "WebBookmarkType": "WebBookmarkTypeLeaf",
                    "URLString": "https://www.torproject.org/",
                    "URIDictionary": {"title": "Tor"},
                    "ReadingList": {"DateAdded": datetime(2026, 11, 1, 23, 5)},
                }
            ],
        },
    ],
}


def _upload(client: TestClient, source: str, name: str, data: bytes, browser: str = "safari"):
    return client.post(
        f"/api/incidents/sf/upload?tab=browser&browser={browser}&source={source}",
        files={"file": (name, data)},
    )


def test_safari_history_db_upload(admin: TestClient, tmp_path):
    admin.post("/api/incidents", json={"id": "sf", "os": "macos", "data": {}})
    res = _upload(admin, "history", "History.db", _history_db(tmp_path / "History.db"))
    assert res.status_code == 200, res.text
    assert res.json()["rows"] == 2 and res.json()["format"] == "sqlite"
    slot = admin.get("/api/incidents/sf").json()["data"]["browser"]["browsers"]["safari"]
    target, source = slot["history"]
    assert target["url"] == "https://evil.example/" and target["title"] == "Evil"
    assert target["isRedirect"] is True and target["fromVisitId"] == 10
    assert target["visitTime"] == _ms(datetime(2026, 11, 2, 2, 14)) + 1500
    assert source["isRedirect"] is False and source["visitCount"] == 1
    assert slot["meta"]["history"]["fileName"] == "History.db"


def test_safari_binary_downloads_and_xml_bookmarks(admin: TestClient):
    admin.post("/api/incidents", json={"id": "sf", "os": "macos", "data": {}})
    res = _upload(admin, "downloads", "Downloads.plist", plistlib.dumps(DOWNLOADS, fmt=plistlib.FMT_BINARY))
    assert res.status_code == 200 and res.json()["format"] == "plist", res.text
    res = _upload(admin, "bookmarks", "Bookmarks.plist", plistlib.dumps(BOOKMARKS, fmt=plistlib.FMT_XML))
    assert res.status_code == 200 and res.json()["rows"] == 1, res.text
    slot = admin.get("/api/incidents/sf").json()["data"]["browser"]["browsers"]["safari"]
    (download,) = slot["downloads"]
    assert download["fileName"] == "payload.dmg" and download["state"] == 1
    assert download["startTime"] == _ms(datetime(2026, 11, 2, 2, 14))
    (bookmark,) = slot["bookmarks"]
    assert bookmark["folder"] == "Reading List" and bookmark["name"] == "Tor"
    assert bookmark["dateAdded"] == _ms(datetime(2026, 11, 1, 23, 5))


def test_safari_rejects_mismatched_files(admin: TestClient, tmp_path):
    admin.post("/api/incidents", json={"id": "sf", "data": {}})
    binary = plistlib.dumps(DOWNLOADS, fmt=plistlib.FMT_BINARY)
    assert _upload(admin, "bookmarks", "Downloads.plist", binary).status_code == 400
    assert _upload(admin, "history", "Downloads.plist", binary).status_code == 400
    assert _upload(admin, "history", "History", binary, browser="chrome").status_code == 400
    history = _history_db(tmp_path / "History.db")
    assert _upload(admin, "downloads", "History.db", history).status_code == 400
    assert _upload(admin, "downloads", "bad.plist", b"bplist00garbage" + b"\0" * 40).status_code == 400
