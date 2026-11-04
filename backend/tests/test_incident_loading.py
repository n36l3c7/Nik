"""Lazy incident loading: the light summary listing and JSON Merge Patch updates."""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from app.routers.incidents import merge_patch

MERGE = {"Content-Type": "application/merge-patch+json"}


def _create(client: TestClient, **doc) -> dict:
    res = client.post("/api/incidents", json={"data": {}, **doc})
    assert res.status_code == 201, res.text
    return res.json()


def test_summary_view_includes_os_without_document_body(admin: TestClient):
    _create(admin, id="s1", name="wks01", host="wks01", os="macos", flags={"k": {"key": "k"}})
    rows = admin.get("/api/incidents?view=summary").json()["incidents"]
    assert rows == [
        {
            "id": "s1", "name": "wks01", "host": "wks01", "username": "", "os": "macos",
            "createdAt": "", "updatedAt": "",
        }
    ]


def test_summary_os_follows_patches(admin: TestClient):
    _create(admin, id="s2", os="windows")
    admin.patch("/api/incidents/s2", json={"os": "linux"})
    row = admin.get("/api/incidents?view=summary").json()["incidents"][0]
    assert row["os"] == "linux"


def test_merge_patch_updates_only_the_sent_subtree(admin: TestClient):
    _create(
        admin,
        id="m1",
        data={
            "browser": {"browsers": {
                "chrome": {"profiles": {
                    "p1": {"history": [{"id": "h1"}], "meta": {"history": {"fileName": "History"}}},
                    "p2": {"history": [{"id": "h9"}]},
                }},
                "firefox": {"profiles": {"p3": {"history": [{"id": "f1"}]}}},
            }},
            "commands": {"shells": {"bash": {"commands": [{"id": "c1"}]}}},
        },
        flags={"a": {"key": "a"}, "b": {"key": "b"}},
    )
    patch = {
        "updatedAt": "2026-11-04T10:00:00.000Z",
        "data": {"browser": {"browsers": {"chrome": {"profiles": {
            "p1": {"history": [{"id": "h2"}], "meta": {"history": None}},
        }}}}},
        "flags": {"a": None, "c": {"key": "c"}},
    }
    res = admin.patch("/api/incidents/m1", headers=MERGE, content=json.dumps(patch))
    assert res.status_code == 200, res.text
    doc = admin.get("/api/incidents/m1").json()
    browsers = doc["data"]["browser"]["browsers"]
    assert browsers["chrome"]["profiles"]["p1"] == {"history": [{"id": "h2"}], "meta": {}}
    assert browsers["chrome"]["profiles"]["p2"] == {"history": [{"id": "h9"}]}
    assert browsers["firefox"] == {"profiles": {"p3": {"history": [{"id": "f1"}]}}}
    assert doc["data"]["commands"]["shells"]["bash"]["commands"] == [{"id": "c1"}]
    assert set(doc["flags"]) == {"b", "c"}
    assert doc["updatedAt"] == "2026-11-04T10:00:00.000Z"


def test_merge_patch_cannot_change_or_drop_the_id(admin: TestClient):
    _create(admin, id="m2")
    res = admin.patch("/api/incidents/m2", headers=MERGE, content=json.dumps({"id": None}))
    assert res.status_code == 200 and res.json()["id"] == "m2"


def test_plain_json_patch_still_replaces_top_level_keys(admin: TestClient):
    _create(admin, id="m3", data={"browser": {"a": 1}, "commands": {"b": 2}})
    admin.patch("/api/incidents/m3", json={"data": {"browser": {"c": 3}}})
    assert admin.get("/api/incidents/m3").json()["data"] == {"browser": {"c": 3}}


def test_merge_patch_rfc7396_examples():
    assert merge_patch({"a": "b"}, {"a": "c"}) == {"a": "c"}
    assert merge_patch({"a": "b"}, {"b": "c"}) == {"a": "b", "b": "c"}
    assert merge_patch({"a": "b"}, {"a": None}) == {}
    assert merge_patch({"a": [{"b": "c"}]}, {"a": [1]}) == {"a": [1]}
    assert merge_patch({"a": {"b": "c"}}, {"a": {"b": "d", "c": None}}) == {"a": {"b": "d"}}
    assert merge_patch(["a"], {"a": "b"}) == {"a": "b"}
    assert merge_patch({"e": None}, {"a": 1}) == {"e": None, "a": 1}
    original = {"a": {"b": 1}}
    merge_patch(original, {"a": {"b": 2}})
    assert original == {"a": {"b": 1}}


def test_migration_adds_and_backfills_the_os_column(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "legacy.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text(
            "CREATE TABLE incidents (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, host VARCHAR NOT NULL,"
            " username VARCHAR NOT NULL, updated_at VARCHAR NOT NULL, created_at VARCHAR NOT NULL,"
            " doc JSON NOT NULL)"
        ))
        conn.execute(
            sa.text("INSERT INTO incidents VALUES ('i1', '', '', '', '', '', :doc)"),
            {"doc": json.dumps({"id": "i1", "os": "linux"})},
        )

    import app.db

    monkeypatch.setattr(app.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0001_baseline")
    command.upgrade(cfg, "0002_incident_os_column")
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT os FROM incidents WHERE id = 'i1'")).scalar() == "linux"


def test_conditional_get_returns_304_while_unchanged(admin: TestClient):
    _create(admin, id="c1", updatedAt="2026-11-04T09:00:00.000Z")
    etag = admin.get("/api/incidents/c1").headers["ETag"]
    assert etag == '"2026-11-04T09:00:00.000Z"'
    hit = admin.get("/api/incidents/c1", headers={"If-None-Match": etag})
    assert hit.status_code == 304 and hit.content == b"" and hit.headers["ETag"] == etag
    admin.patch("/api/incidents/c1", headers=MERGE, content=json.dumps({"updatedAt": "2026-11-04T09:05:00.000Z"}))
    miss = admin.get("/api/incidents/c1", headers={"If-None-Match": etag})
    assert miss.status_code == 200 and miss.json()["updatedAt"] == "2026-11-04T09:05:00.000Z"
    assert admin.get("/api/incidents/nope", headers={"If-None-Match": etag}).status_code == 404
