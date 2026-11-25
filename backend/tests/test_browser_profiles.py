"""Browser profiles (2.0.0): legacy normalization, migration 0003."""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic.config import Config
from fastapi.testclient import TestClient

from alembic import command
from app.browser_profiles import normalize_browser_data, profile_for_upload

LEGACY_SLOT = {
    "history": [{"id": "h1", "url": "https://legacy.example/"}],
    "downloads": [],
    "bookmarks": [],
    "shortcuts": [],
    "meta": {"history": {"fileName": "History"}},
}


def moved(incident: str) -> dict:
    """The browser evidence of an incident as the tables hold it: {source: (profile, [keys])}."""
    from sqlalchemy import select

    from app.core.db import SessionLocal
    from app.core.models import EvidenceRecord, EvidenceSource

    with SessionLocal() as db:
        return {
            row.source: (
                row.profile,
                row.legacy,
                sorted(db.scalars(select(EvidenceRecord.key).where(EvidenceRecord.source_id == row.id))),
            )
            for row in db.scalars(select(EvidenceSource).where(EvidenceSource.incident_id == incident))
        }


def test_create_and_backup_restore_move_legacy_documents_to_the_tables(admin: TestClient):
    """A document in the shape of before 2.0.0 (one slot per browser) is read as one of before 7.0:
    its browser evidence leaves the document for the tables, under the profile "Default"."""
    legacy = {"id": "old", "data": {"browser": {"browsers": {"firefox": LEGACY_SLOT}}}}
    created = admin.post("/api/incidents", json=legacy).json()
    assert "browser" not in created["data"]
    assert moved("old") == {"firefox.history": ("Default", True, ["legacy:h1"])}

    # A file exported by a release before 2.0.0 goes the same way when it is imported (it adds: another id).
    backup = admin.get("/api/backup/export").json()
    backup["incidents"] = [{**legacy, "id": "older"}]
    assert admin.post("/api/backup/import", json=backup).status_code == 200, "import failed"
    assert "browser" not in admin.get("/api/incidents/older").json()["data"]
    assert moved("older") == {"firefox.history": ("Default", True, ["legacy:h1"])}


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


def test_a_patch_with_the_old_shape_is_moved_to_the_tables(admin: TestClient):
    admin.post("/api/incidents", json={"id": "p1", "updatedAt": "t1", "data": {}})
    # A plain-JSON PATCH with the old shape is converted, and what it holds leaves the document.
    patched = admin.patch("/api/incidents/p1", json={"data": {"browser": {"browsers": {"chrome": LEGACY_SLOT}}}})
    assert patched.status_code == 200 and "browser" not in patched.json()["data"]
    assert moved("p1") == {"chrome.history": ("Default", True, ["legacy:h1"])}
    stored = admin.get("/api/incidents/p1")
    assert "browser" not in stored.json()["data"]
    # One write since the incident was created: revision 1.
    assert stored.headers["ETag"] == '"1"'


def test_get_moves_a_document_the_upgrade_has_not_reached_yet(admin: TestClient):
    from app.core.db import SessionLocal
    from app.core.models import Incident

    admin.post("/api/incidents", json={"id": "p1", "data": {}})
    with SessionLocal() as db:  # a document as 6.x left it, which the move after the upgrade has not reached
        row = db.get(Incident, "p1")
        row.doc = {**row.doc, "data": {"browser": {"browsers": {"edge": LEGACY_SLOT}}}}
        db.commit()
    first = admin.get("/api/incidents/p1").json()
    assert "browser" not in first["data"]
    assert moved("p1") == {"edge.history": ("Default", True, ["legacy:h1"])}
    with SessionLocal() as db:
        assert "browser" not in db.get(Incident, "p1").doc["data"]
    # Read again: nothing more to move.
    assert admin.get("/api/incidents/p1").json()["data"] == first["data"]
