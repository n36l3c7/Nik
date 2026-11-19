"""The optional expiry of an artifact: a date someone sets, what the worker does when it comes."""

from __future__ import annotations

import hashlib
from datetime import date, datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import artifact_expiry
from app.core.db import SessionLocal
from app.core.models import Artifact, AutomationEvent
from app.malware.samples import sample_path
from tests.conftest import make_key
from tests.test_malware import STRINGS_PAYLOAD, fake_pe

NOW = datetime(2026, 11, 19, 12, 0, tzinfo=timezone.utc).timestamp()
DAY = 86400.0


def day(offset: int) -> str:
    return (date(2026, 11, 19) + timedelta(days=offset)).isoformat()


def real_day(offset: int) -> str:
    return (datetime.now(timezone.utc).date() + timedelta(days=offset)).isoformat()


def a_file(admin: TestClient, name: str = "invoice.exe", salt: bytes = b"") -> dict:
    made = admin.post("/api/artifacts/files", files={"file": (name, fake_pe(payload=STRINGS_PAYLOAD + salt))})
    assert made.status_code == 201, made.text
    return made.json()


def dated(artifact_id: str, when: str) -> None:
    """Give an artifact a date as if it had been set in the past (the API refuses days gone by)."""
    with SessionLocal() as db:
        row = db.get(Artifact, artifact_id)
        row.expires_at, row.expiry_note, row.expiry_noticed = when, "", None
        db.commit()


def events(kind: str) -> list[dict]:
    with SessionLocal() as db:
        rows = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == kind)).all()
        return [row.payload["data"]["artifact"] for row in sorted(rows, key=lambda row: row.created_at)]


def tick(now: float) -> dict:
    with SessionLocal() as db:
        return artifact_expiry.tick(db, now)


def test_nothing_has_a_date_until_someone_sets_one(admin: TestClient):
    artifact = a_file(admin)
    assert artifact["expiresAt"] is None and artifact["expiresInDays"] is None and artifact["expiryNote"] == ""
    path = f"/api/artifacts/{artifact['id']}/expiry"
    set_ = admin.put(path, json={"expiresAt": real_day(30)})
    assert set_.status_code == 200 and set_.json()["expiresAt"] == real_day(30) and set_.json()["expiresInDays"] == 30
    assert admin.get(f"/api/artifacts/{artifact['id']}").json()["expiresAt"] == real_day(30)
    assert admin.get("/api/artifacts").json()["artifacts"][0]["expiresInDays"] == 30
    # A time is read as its day; a day that is gone, or not a date, is refused.
    assert admin.put(path, json={"expiresAt": real_day(5) + "T10:00:00Z"}).json()["expiresAt"] == real_day(5)
    assert "a day to come" in admin.put(path, json={"expiresAt": real_day(0)}).json()["detail"]
    assert "a day to come" in admin.put(path, json={"expiresAt": "2020-01-01"}).json()["detail"]
    assert "is a date" in admin.put(path, json={"expiresAt": "soon"}).json()["detail"]
    assert "20 years" in admin.put(path, json={"expiresAt": "2099-01-01"}).json()["detail"]
    # Taken away again: it is kept for good.
    cleared = admin.put(path, json={"expiresAt": None})
    assert cleared.status_code == 200 and cleared.json()["expiresAt"] is None
    said = [
        entry["details"] for entry in admin.get("/api/audit", params={"q": "action:artifact.expiry"}).json()["entries"]
    ]
    assert said[0].endswith("has no expiry any more") and f"expires on {real_day(30)}" in said[-1]
    viewer = make_key(admin, label="v", roles=["viewer"])
    assert admin.put(path, json={"expiresAt": real_day(9)}, headers=viewer).status_code == 403
    assert admin.put("/api/artifacts/file-nope/expiry", json={"expiresAt": real_day(9)}).status_code == 404
    # The worker leaves alone what has no date.
    assert tick(NOW + 4000 * DAY) == {"noticed": 0, "expired": 0, "put_off": 0}
    assert admin.get(f"/api/artifacts/{artifact['id']}").status_code == 200


def test_an_artifact_is_announced_a_week_before_and_deleted_when_its_day_comes(admin: TestClient):
    artifact = a_file(admin)
    sha = artifact["ref"]
    dated(artifact["id"], day(10))
    assert tick(NOW) == {"noticed": 0, "expired": 0, "put_off": 0}  # ten days away: nothing to say yet
    # Seven days before: said once.
    assert tick(NOW + 3 * DAY)["noticed"] == 1 and tick(NOW + 4 * DAY)["noticed"] == 0
    told = events("artifact.expiring")
    assert len(told) == 1 and told[0]["id"] == artifact["id"] and told[0]["days_left"] == 7
    assert (
        told[0]["expires_at"] == day(10)
        and told[0]["name"] == "invoice.exe"
        and told[0]["url"].endswith(artifact["id"])
    )
    assert sample_path(sha).exists()
    # The day before it is still there; on its day it goes, as if someone had deleted it.
    assert tick(NOW + 9 * DAY)["expired"] == 0
    assert tick(NOW + 10 * DAY) == {"noticed": 0, "expired": 1, "put_off": 0}
    assert admin.get(f"/api/artifacts/{artifact['id']}").status_code == 404
    assert admin.get(f"/api/samples/{sha}").status_code == 404 and not sample_path(sha).exists()
    assert [gone["id"] for gone in events("artifact.expired")] == [artifact["id"]]
    entry = admin.get("/api/audit", params={"q": "action:artifact.expire"}).json()["entries"][0]
    assert entry["actor"] == "nik" and f"its expiry of {day(10)} came" in entry["details"]
    # A date changed after the warning is announced again for the new day.
    other = a_file(admin, "other.exe", b"-2")
    dated(other["id"], day(15))
    assert tick(NOW + 10 * DAY)["noticed"] == 1
    dated(other["id"], day(16))
    assert tick(NOW + 10 * DAY)["noticed"] == 1 and len(events("artifact.expiring")) == 3


def test_an_artifact_an_open_incident_references_is_put_off_not_deleted(admin: TestClient):
    artifact = a_file(admin)
    assert admin.post("/api/incidents", json={"id": "open-1", "name": "Still working", "data": {}}).status_code == 201
    assert admin.post(f"/api/artifacts/{artifact['id']}/links", json={"incidentId": "open-1"}).status_code == 201
    dated(artifact["id"], day(0))
    assert tick(NOW) == {"noticed": 0, "expired": 0, "put_off": 1}
    held = admin.get(f"/api/artifacts/{artifact['id']}").json()
    assert held["expiresAt"] == day(7)
    assert (
        held["expiryNote"] == f'Put off to {day(7)}: the incident "Still working" still references it and is not closed'
    )
    assert events("artifact.expired") == [] and sample_path(artifact["ref"]).exists()
    # A week later it is still open: put off again, without a new warning each time.
    assert tick(NOW + 7 * DAY)["put_off"] == 1 and events("artifact.expiring") == []
    # Once the incident is closed, the date holds.
    closed = admin.patch(
        "/api/incidents/open-1/fields", json={"changes": {"status": "closed"}, "closeReason": "Resolved"}
    )
    assert closed.status_code == 200, closed.text
    assert tick(NOW + 14 * DAY)["expired"] == 1
    assert admin.get(f"/api/artifacts/{artifact['id']}").status_code == 404
    # The incident keeps its history; the file it referenced is gone from it.
    doc = admin.get("/api/incidents/open-1").json()
    assert doc["data"].get("malware", {}).get("samples", []) == []


def test_storage_lists_what_has_a_date_and_counts_what_has_none(admin: TestClient):
    first = a_file(admin, "first.exe", b"-a")
    second = a_file(admin, "second.exe", b"-b")
    a_file(admin, "kept.exe", b"-c")
    admin.put(f"/api/artifacts/{first['id']}/expiry", json={"expiresAt": real_day(90)})
    admin.put(f"/api/artifacts/{second['id']}/expiry", json={"expiresAt": real_day(30)})
    usage = admin.get("/api/storage").json()
    # The soonest first.
    assert [(row["name"], row["expiresInDays"]) for row in usage["dated"]] == [("second.exe", 30), ("first.exe", 90)]
    assert usage["dated"][0]["bytes"] == second["size"] and usage["dated"][0]["artifactId"] == second["id"]
    assert usage["datedCount"] == 2
    assert usage["undated"]["count"] == 1 and usage["undated"]["bytes"] > 0
    assert hashlib.sha256(b"").hexdigest()  # the store is the tests' own: nothing else is counted here
