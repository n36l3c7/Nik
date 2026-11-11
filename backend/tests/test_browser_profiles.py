"""Browser profiles (2.0.0): upload routing, legacy normalization, migration 0003."""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic.config import Config
from fastapi.testclient import TestClient

from alembic import command
from app.browser_profiles import normalize_browser_data, profile_for_upload

HISTORY_CSV = b"url,title,visit_time\nhttps://example.com/,Example,2026-11-04 10:00:00\n"
LEGACY_SLOT = {
    "history": [{"id": "h1", "url": "https://legacy.example/"}],
    "downloads": [],
    "bookmarks": [],
    "shortcuts": [],
    "meta": {"history": {"fileName": "History"}},
}


def _upload(client: TestClient, profile: str | None = None):
    query = "tab=browser&browser=chrome&source=history" + (f"&profile={profile}" if profile else "")
    return client.post(f"/api/incidents/p1/upload?{query}", files={"file": ("history.csv", HISTORY_CSV)})


def test_upload_goes_to_default_or_named_profile(admin: TestClient):
    admin.post("/api/incidents", json={"id": "p1", "data": {}})
    first = _upload(admin)
    assert first.status_code == 200, first.text
    assert first.json()["target"] == "browser/chrome/Default/history"
    assert first.json()["profileId"] == "default"
    work = _upload(admin, "Work")
    again = _upload(admin, "work")  # names match case-insensitively
    assert work.json()["profileId"] == again.json()["profileId"] != "default"

    chrome = admin.get("/api/incidents/p1").json()["data"]["browser"]["browsers"]["chrome"]
    assert chrome["activeProfile"] == "default"
    names = sorted(p["name"] for p in chrome["profiles"].values())
    assert names == ["Default", "Work"]
    for profile in chrome["profiles"].values():
        assert profile["history"][0]["url"] == "https://example.com/"
        assert profile["meta"]["history"]["rows"] == 1


def test_upload_into_a_legacy_document_migrates_it(admin: TestClient):
    # A PATCH stores the document as-is, bypassing create-time normalization.
    admin.post("/api/incidents", json={"id": "p1", "data": {}})
    admin.patch("/api/incidents/p1", json={"data": {"browser": {"browsers": {"chrome": LEGACY_SLOT}}}})
    assert _upload(admin, "Work").status_code == 200
    profiles = admin.get("/api/incidents/p1").json()["data"]["browser"]["browsers"]["chrome"]["profiles"]
    assert profiles["default"]["history"] == LEGACY_SLOT["history"]
    assert {p["name"] for p in profiles.values()} == {"Default", "Work"}


def test_create_and_backup_restore_normalize_legacy_documents(admin: TestClient):
    legacy = {"id": "old", "data": {"browser": {"browsers": {"firefox": LEGACY_SLOT}}}}
    created = admin.post("/api/incidents", json=legacy).json()
    firefox = created["data"]["browser"]["browsers"]["firefox"]
    assert firefox["activeProfile"] == "default"
    assert firefox["profiles"]["default"]["meta"] == LEGACY_SLOT["meta"]

    backup = admin.get("/api/backup/export").json()
    backup["incidents"] = [legacy]
    assert admin.post("/api/backup/import", json=backup).status_code == 200, "restore failed"
    admin.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
    restored = admin.get("/api/incidents/old").json()["data"]["browser"]["browsers"]["firefox"]
    assert restored["profiles"]["default"]["history"] == LEGACY_SLOT["history"]


def test_profile_helpers():
    doc = {"data": {"browser": {"browsers": {"chrome": dict(LEGACY_SLOT), "edge": {"profiles": {}}}}}}
    assert normalize_browser_data(doc) is True
    assert normalize_browser_data(doc) is False  # idempotent
    browsers = doc["data"]["browser"]["browsers"]
    assert browsers["edge"] == {"profiles": {}}
    fresh = {}
    created = profile_for_upload(fresh, "safari", None)
    assert created["id"] == "default" and fresh["safari"]["activeProfile"] == "default"
    named = profile_for_upload(fresh, "safari", "  Personal ")
    assert named["name"] == "Personal" and fresh["safari"]["activeProfile"] == "default"


def test_migration_0003_moves_legacy_slots_into_profiles(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "legacy.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(
            sa.text(
                "CREATE TABLE incidents (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, host VARCHAR NOT NULL,"
                " username VARCHAR NOT NULL, os VARCHAR NOT NULL DEFAULT '', updated_at VARCHAR NOT NULL,"
                " created_at VARCHAR NOT NULL, doc JSON NOT NULL)"
            )
        )
        docs = {
            "a": {"id": "a", "data": {"browser": {"browsers": {"chrome": LEGACY_SLOT}}}},
            "b": {"id": "b", "data": {}},
        }
        for incident_id, doc in docs.items():
            conn.execute(
                sa.text("INSERT INTO incidents VALUES (:id, '', '', '', '', '', '', :doc)"),
                {"id": incident_id, "doc": json.dumps(doc)},
            )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0002_incident_os_column")
    command.upgrade(cfg, "0003_browser_profiles")

    def load(incident_id):
        with engine.connect() as conn:
            row = conn.execute(sa.text("SELECT doc FROM incidents WHERE id = :i"), {"i": incident_id})
            return json.loads(row.scalar())

    chrome = load("a")["data"]["browser"]["browsers"]["chrome"]
    assert chrome["activeProfile"] == "default"
    assert chrome["profiles"]["default"]["name"] == "Default"
    assert chrome["profiles"]["default"]["history"] == LEGACY_SLOT["history"]
    assert load("b") == docs["b"]

    command.downgrade(cfg, "0002_incident_os_column")
    assert load("a")["data"]["browser"]["browsers"]["chrome"]["history"] == LEGACY_SLOT["history"]


def test_get_and_patch_convert_legacy_documents(admin: TestClient):
    admin.post("/api/incidents", json={"id": "p1", "updatedAt": "t1", "data": {}})
    # A plain-JSON PATCH with the old shape is converted before it is stored.
    admin.patch("/api/incidents/p1", json={"data": {"browser": {"browsers": {"chrome": LEGACY_SLOT}}}})
    stored = admin.get("/api/incidents/p1")
    chrome = stored.json()["data"]["browser"]["browsers"]["chrome"]
    assert set(chrome) == {"activeProfile", "profiles"}
    assert chrome["profiles"]["default"]["history"] == LEGACY_SLOT["history"]
    # One write since the incident was created: revision 1.
    assert stored.headers["ETag"] == '"1"'


def test_get_saves_a_converted_legacy_document_once(admin: TestClient):
    from app.core.db import SessionLocal
    from app.core.models import Incident

    admin.post("/api/incidents", json={"id": "p1", "data": {}})
    with SessionLocal() as db:  # simulate a database that skipped migration 0003
        row = db.get(Incident, "p1")
        row.doc = {**row.doc, "data": {"browser": {"browsers": {"edge": LEGACY_SLOT}}}}
        db.commit()
    first = admin.get("/api/incidents/p1").json()
    assert first["data"]["browser"]["browsers"]["edge"]["profiles"]["default"]["meta"] == LEGACY_SLOT["meta"]
    with SessionLocal() as db:
        saved = db.get(Incident, "p1").doc["data"]["browser"]["browsers"]["edge"]
    assert "profiles" in saved and "history" not in saved
