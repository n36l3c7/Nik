"""Host evidence of before 7.0 leaves the incident document for the tables."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.models import EvidenceMark, EvidenceRecord, EvidenceSource, Incident
from app.evidence import legacy
from app.main import app as fastapi_app
from tests.conftest import make_key

T = 1_700_000_000_000


def old_document() -> dict:
    """An incident as 6.x kept it: the four kinds of host evidence inside ``data``, flags by record id."""
    return {
        "name": "Kept the old way",
        "host": "WKS-042",
        "username": "j.alvarez",
        "os": "Windows",
        "flags": {
            "evt:Security:1842": {
                "key": "evt:Security:1842",
                "section": "eventlogs",
                "flaggedBy": "elena",
                "flaggedAt": "2026-11-01T10:00:00Z",
                "comments": [
                    {"id": "c1", "text": "first logon from outside", "at": "2026-11-01T10:01:00Z", "author": "elena"}
                ],
            },
            "h1": {
                "key": "h1",
                "section": "events",
                "flaggedBy": "elena",
                "flaggedAt": "2026-11-01T10:02:00Z",
                "comments": [],
            },
            "mail-1": {"key": "mail-1", "section": "mail", "flaggedBy": "elena", "flaggedAt": "x", "comments": []},
        },
        "data": {
            "mail": {"messages": []},
            "eventlogs": {
                "channels": {
                    "Security": {
                        "events": [
                            {
                                "id": "evt:Security:1842",
                                "time": T,
                                "eventId": 4624,
                                "channel": "Security",
                                "provider": "Microsoft-Windows-Security-Auditing",
                                "computer": "WKS-042",
                                "recordId": 1842,
                                "level": 0,
                                "data": {"TargetUserName": "admin", "IpAddress": "45.155.205.233"},
                            }
                        ],
                        "meta": {
                            "fileName": "Security.evtx",
                            "importedAt": "2026-11-01T09:00:00Z",
                            "format": "evtx",
                            "total": 9,
                            "kept": 1,
                        },
                    }
                }
            },
            "browser": {
                "browsers": {
                    "chrome": {
                        "activeProfile": "default",
                        "profiles": {
                            "default": {
                                "id": "default",
                                "name": "Default",
                                "history": [
                                    {"id": "h1", "url": "https://example.org/a", "title": "A", "visitTime": T + 1}
                                ],
                                "downloads": [
                                    {
                                        "id": "d1",
                                        "fileName": "a.docm",
                                        "url": "https://example.org/a.docm",
                                        "startTime": T + 2,
                                    }
                                ],
                                "bookmarks": [],
                                "shortcuts": [],
                                "meta": {
                                    "history": {
                                        "fileName": "History",
                                        "importedAt": "2026-11-01T09:10:00Z",
                                        "format": "sqlite",
                                        "rows": 2,
                                        "sha256": "ab" * 32,
                                    }
                                },
                            }
                        },
                    }
                }
            },
            "endpoint": {
                "categories": {
                    "persistence": {
                        "sources": {
                            "runkeys": {
                                "records": [
                                    {
                                        "id": "e1",
                                        "time": None,
                                        "fields": {"name": "MSUpdate", "command": "svc.exe", "kind": "Run key"},
                                    }
                                ],
                                "meta": {
                                    "fileName": "runkeys.csv",
                                    "importedAt": "2026-11-01T09:20:00Z",
                                    "format": "csv",
                                    "rows": 1,
                                },
                            }
                        }
                    }
                }
            },
            "commands": {
                "shells": {
                    "powershell": {
                        "commands": [{"id": "c1", "command": "whoami", "time": None, "lineNo": 1}],
                        "meta": {
                            "history": {"fileName": "ConsoleHost_history.txt", "importedAt": "2026-11-01T09:30:00Z"}
                        },
                    }
                }
            },
        },
    }


def test_an_old_document_is_moved_and_holds_no_host_evidence_any_more(admin):
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    # An API client of before, or a 6.x export imported: the write itself moves what it brings.
    made = client.post("/api/incidents", headers=key, json={"id": "old-1", **old_document()})
    assert made.status_code == 201, made.text
    shown = made.json()
    assert set(shown["data"]) == {"mail"} and set(shown["flags"]) == {"mail-1"}, "the rest of the document is as it was"
    with SessionLocal() as db:
        sources = {
            row.source: row for row in db.scalars(select(EvidenceSource).where(EvidenceSource.incident_id == "old-1"))
        }
        assert set(sources) == {
            "evtx",
            "chrome.history",
            "chrome.downloads",
            "windows.persistence.runkeys",
            "powershell",
        }
        log = sources["evtx"]
        assert (log.legacy, log.read, log.state, log.parser, log.sha256, log.kept) == (
            True,
            "unknown",
            "done",
            "legacy",
            "",
            1,
        )
        assert (log.file_name, log.kind, log.first_ts) == ("Security.evtx", "eventlog", T)
        # What 6.x noted of the file is kept, the hash the browser parsers took included.
        assert sources["chrome.history"].report["legacy"]["sha256"] == "ab" * 32
        assert sources["chrome.history"].profile == "Default" and sources["chrome.downloads"].file_name == "History"
        records = {
            row.key: row for row in db.scalars(select(EvidenceRecord).where(EvidenceRecord.incident_id == "old-1"))
        }
        # An event has the key the 7.0 parser gives it: the log imported again meets it as a duplicate.
        event = records["evtx:WKS-042:Security:1842"]
        assert (event.type, event.event_id, event.channel, event.host, event.ts) == (
            "event",
            4624,
            "Security",
            "WKS-042",
            T,
        )
        assert event.data["TargetUserName"] == "admin" and event.data["provider"].startswith("Microsoft-Windows")
        assert records["legacy:h1"].type == "visit" and records["legacy:h1"].data["browser"] == "chrome"
        assert records["legacy:d1"].type == "download" and records["legacy:e1"].data["category"] == "persistence"
        assert records["legacy:c1"].summary == "whoami" and records["legacy:c1"].kind == "commands"
        # The flags on records are marks now, with what was said about them.
        mark = db.get(EvidenceMark, ("old-1", "evtx:WKS-042:Security:1842"))
        assert mark.flagged and "first logon from outside" in mark.note and mark.updated_by == "elena"
        assert db.get(EvidenceMark, ("old-1", "legacy:h1")).flagged
        assert db.get(EvidenceMark, ("old-1", "mail-1")) is None

    # A PATCH that still writes such data: moved the same way, beside what is already there.
    more = {
        "data": {
            "commands": {
                "shells": {"bash": {"commands": [{"id": "c9", "command": "id", "time": None, "lineNo": 1}], "meta": {}}}
            }
        }
    }
    patched = client.patch("/api/incidents/old-1", headers=key, json=more)
    assert patched.status_code == 200 and "commands" not in patched.json()["data"]
    with SessionLocal() as db:
        assert db.scalars(select(EvidenceRecord).where(EvidenceRecord.key == "legacy:c9")).one().summary == "id"


def test_the_incidents_already_there_are_moved_once_in_the_background(admin):
    with SessionLocal() as db:
        for name in ("sw-a", "sw-b"):
            db.add(Incident(id=name, doc={"id": name, **old_document()}, name=name, os="Windows", host="WKS-042"))
        db.add(Incident(id="sw-c", doc={"id": "sw-c", "name": "nothing to move", "data": {}}, name="sw-c"))
        legacy._keep(db, {})  # the state of another test is not this one's
        db.commit()
    held = legacy.sweep("holder-of-the-test", budget=60)
    assert held["done"] is True and held["moved"] >= 2 and held["records"] >= 10
    with SessionLocal() as db:
        for name in ("sw-a", "sw-b"):
            incident = db.get(Incident, name)
            assert not legacy.holds(incident.doc) and incident.rev >= 1
            assert db.scalars(select(EvidenceSource.id).where(EvidenceSource.incident_id == name)).first()
    # Done is done: a second pass looks at nothing.
    assert legacy.sweep("holder-of-the-test", budget=5)["moved"] == held["moved"]


def test_what_the_old_evidence_named_stays_among_the_indicators_of_the_incident(admin):
    from app.core.models import FoundIndicator

    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    assert client.post("/api/incidents", headers=key, json={"id": "old-ioc", **old_document()}).status_code == 201
    with SessionLocal() as db:
        found = {
            (row.type, row.value)
            for row in db.scalars(select(FoundIndicator).where(FoundIndicator.incident_id == "old-ioc"))
        }
    # The address of the logon event: it was an indicator of the incident in 6.x, and still is.
    assert ("ip", "45.155.205.233") in found
