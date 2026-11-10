"""Regenerate the binary plist fixtures used by the frontend unit tests.

Run from the repository root:  python3 frontend/src/parsers/__fixtures__/make_safari_fixtures.py
Python's plistlib writes the same bplist00 format macOS uses.
"""

from __future__ import annotations

import plistlib
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).parent


def utc(*args: int) -> datetime:
    """A naive datetime, which plistlib writes (and reads back) as UTC."""
    return datetime(*args)


TYPES = {
    "ascii": "plain",
    "long": "a string longer than fourteen characters",
    "unicode": "Caffè ☕ Привет",
    "zero": 0,
    "small": 200,
    "medium": 70000,
    "negative": -42,
    "big": 2**40,
    "huge": 2**62,
    "real": 3.5,
    "yes": True,
    "no": False,
    "when": utc(2026, 11, 4, 10, 30, 0),
    "blob": b"\x00\x01\xfe\xff",
    "uid": plistlib.UID(7),
    "nested": {"list": [1, "two", {"three": 3}]},
    "many": list(range(300)),
}

DOWNLOADS = {
    "DownloadHistory": [
        {
            "DownloadEntryIdentifier": "6F1B0C9E-1111-4E2A-9C1D-000000000001",
            "DownloadEntryURL": "https://evil.example/payload.dmg",
            "DownloadEntryPath": "/Users/jdoe/Downloads/payload.dmg",
            "DownloadEntryProgressBytesSoFar": 1048576,
            "DownloadEntryProgressTotalToLoad": 1048576,
            "DownloadEntryDateAddedKey": utc(2026, 11, 2, 2, 14, 0),
            "DownloadEntryDateFinishedKey": utc(2026, 11, 2, 2, 15, 0),
            "DownloadEntryRemoveWhenDoneKey": False,
        },
        {
            "DownloadEntryIdentifier": "6F1B0C9E-1111-4E2A-9C1D-000000000002",
            "DownloadEntryURL": "https://example.com/files/report.pdf?dl=1",
            "DownloadEntryPath": "",
            "DownloadEntryProgressBytesSoFar": 512,
            "DownloadEntryProgressTotalToLoad": 4096,
            "DownloadEntryDateAddedKey": utc(2026, 11, 3, 9, 0, 0),
        },
    ]
}

BOOKMARKS = {
    "Title": "",
    "WebBookmarkType": "WebBookmarkTypeList",
    "WebBookmarkFileVersion": 1,
    "Children": [
        {"Title": "History", "WebBookmarkType": "WebBookmarkTypeProxy", "WebBookmarkIdentifier": "History"},
        {
            "Title": "BookmarksBar",
            "WebBookmarkType": "WebBookmarkTypeList",
            "Children": [
                {
                    "WebBookmarkType": "WebBookmarkTypeLeaf",
                    "URLString": "https://intranet.company.local/",
                    "URIDictionary": {"title": "Intranet"},
                },
                {
                    "Title": "Tools",
                    "WebBookmarkType": "WebBookmarkTypeList",
                    "Children": [
                        {
                            "WebBookmarkType": "WebBookmarkTypeLeaf",
                            "URLString": "https://pastebin.com/u/anon0x",
                            "URIDictionary": {},
                        }
                    ],
                },
            ],
        },
        {"Title": "BookmarksMenu", "WebBookmarkType": "WebBookmarkTypeList", "Children": []},
        {
            "Title": "com.apple.ReadingList",
            "WebBookmarkType": "WebBookmarkTypeList",
            "Children": [
                {
                    "WebBookmarkType": "WebBookmarkTypeLeaf",
                    "URLString": "https://www.torproject.org/download/",
                    "URIDictionary": {"title": "Download Tor Browser"},
                    "ReadingList": {"DateAdded": utc(2026, 11, 1, 23, 5, 0), "PreviewText": "Tor"},
                }
            ],
        },
    ],
}

if __name__ == "__main__":
    for name, value in {"plist-types": TYPES, "safari-downloads": DOWNLOADS, "safari-bookmarks": BOOKMARKS}.items():
        (HERE / f"{name}.bplist").write_bytes(plistlib.dumps(value, fmt=plistlib.FMT_BINARY))
