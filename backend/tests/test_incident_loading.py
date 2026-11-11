"""Lazy incident loading: the light summary listing and JSON Merge Patch updates."""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic.config import Config
from fastapi.testclient import TestClient

from alembic import command
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
            "id": "s1",
            "name": "wks01",
            "host": "wks01",
            "username": "",
            "os": "macos",
            "ticketId": "",
            "severity": None,
            "status": "open",
            "assignee": "",
            "hasMail": False,
            "createdAt": "",
            "updatedAt": "",
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
            "browser": {
                "browsers": {
                    "chrome": {
                        "profiles": {
                            "p1": {"history": [{"id": "h1"}], "meta": {"history": {"fileName": "History"}}},
                            "p2": {"history": [{"id": "h9"}]},
                        }
                    },
                    "firefox": {"profiles": {"p3": {"history": [{"id": "f1"}]}}},
                }
            },
            "commands": {"shells": {"bash": {"commands": [{"id": "c1"}]}}},
        },
        flags={"a": {"key": "a"}, "b": {"key": "b"}},
    )
    patch = {
        "updatedAt": "2026-11-04T10:00:00.000Z",
        "data": {
            "browser": {
                "browsers": {
                    "chrome": {
                        "profiles": {
                            "p1": {"history": [{"id": "h2"}], "meta": {"history": None}},
                        }
                    }
                }
            }
        },
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
        conn.execute(
            sa.text(
                "CREATE TABLE incidents (id VARCHAR PRIMARY KEY, name VARCHAR NOT NULL, host VARCHAR NOT NULL,"
                " username VARCHAR NOT NULL, updated_at VARCHAR NOT NULL, created_at VARCHAR NOT NULL,"
                " doc JSON NOT NULL)"
            )
        )
        conn.execute(
            sa.text("INSERT INTO incidents VALUES ('i1', '', '', '', '', '', :doc)"),
            {"doc": json.dumps({"id": "i1", "os": "linux"})},
        )

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0001_baseline")
    command.upgrade(cfg, "0002_incident_os_column")
    with engine.connect() as conn:
        assert conn.execute(sa.text("SELECT os FROM incidents WHERE id = 'i1'")).scalar() == "linux"


def test_conditional_get_returns_304_while_unchanged(admin: TestClient):
    _create(admin, id="c1", updatedAt="2026-11-04T09:00:00.000Z")
    etag = admin.get("/api/incidents/c1").headers["ETag"]
    assert etag == '"0"'
    hit = admin.get("/api/incidents/c1", headers={"If-None-Match": etag})
    assert hit.status_code == 304 and hit.content == b"" and hit.headers["ETag"] == etag
    admin.patch("/api/incidents/c1", headers=MERGE, content=json.dumps({"updatedAt": "2026-11-04T09:05:00.000Z"}))
    miss = admin.get("/api/incidents/c1", headers={"If-None-Match": etag})
    assert miss.status_code == 200 and miss.json()["updatedAt"] == "2026-11-04T09:05:00.000Z"
    assert admin.get("/api/incidents/nope", headers={"If-None-Match": etag}).status_code == 404


def test_every_write_is_a_new_revision_whoever_makes_it(admin: TestClient):
    """The ETag is the document's revision: it does not depend on what the client sends."""
    created = admin.post("/api/incidents", json={"id": "r1", "data": {}, "updatedAt": "same"})
    assert created.headers["ETag"] == '"0"'
    # A patch that leaves updatedAt alone is still a new version.
    first = admin.patch("/api/incidents/r1", headers=MERGE, content=json.dumps({"host": "a"}))
    assert first.headers["ETag"] == '"1"'
    # A write that does not come from a PATCH (a note through its own endpoint) counts too.
    assert admin.post("/api/incidents/r1/notes", json={"text": "seen"}).status_code == 201
    assert admin.get("/api/incidents/r1").headers["ETag"] == '"2"'


def test_a_stale_writer_is_refused_and_loses_nothing(admin: TestClient):
    """Two analysts on one incident: the second to save is told, instead of erasing the first."""
    _create(admin, id="r2", notes=[])
    etag = admin.get("/api/incidents/r2").headers["ETag"]
    note_a = {"id": "a", "text": "from A"}
    saved = admin.patch(
        "/api/incidents/r2", headers={**MERGE, "If-Match": etag}, content=json.dumps({"notes": [note_a]})
    )
    assert saved.status_code == 200
    # B still holds the first version: its whole-array patch would drop A's note.
    stale = admin.patch(
        "/api/incidents/r2",
        headers={**MERGE, "If-Match": etag},
        content=json.dumps({"notes": [{"id": "b", "text": "from B"}]}),
    )
    assert stale.status_code == 412
    assert admin.get("/api/incidents/r2").json()["notes"] == [note_a]
    # With the current version it goes through.
    retried = admin.patch(
        "/api/incidents/r2",
        headers={**MERGE, "If-Match": saved.headers["ETag"]},
        content=json.dumps({"notes": [note_a, {"id": "b", "text": "from B"}]}),
    )
    assert retried.status_code == 200 and len(retried.json()["notes"]) == 2


def test_writers_read_the_document_under_the_lock(admin: TestClient):
    """A writer that loaded the incident earlier works on what is stored now, not on its old copy."""
    from app.core.db import SessionLocal
    from app.core.locking import lock_incident, relock
    from app.core.models import Incident

    _create(admin, id="r3", host="before")
    with SessionLocal() as db:
        early = db.get(Incident, "r3")
        assert early.doc["host"] == "before"
        admin.patch("/api/incidents/r3", headers=MERGE, content=json.dumps({"host": "after"}))
        assert relock(db, early).doc["host"] == "after"
        assert lock_incident(db, "r3").rev == 1
        assert lock_incident(db, "missing") is None and lock_incident(db, None) is None


def test_status_and_assignee_are_listed_and_filtered(admin: TestClient):
    _create(admin, id="t1", name="one")
    _create(admin, id="t2", name="two", status="in_progress", assignee="Anna")
    _create(admin, id="t3", name="three", status="closed", assignee="anna")
    _create(admin, id="t4", name="four", status="archived")

    def ids(query: str) -> list[str]:
        return sorted(r["id"] for r in admin.get(f"/api/incidents?view=summary&{query}").json()["incidents"])

    rows = {r["id"]: r for r in admin.get("/api/incidents?view=summary").json()["incidents"]}
    assert (rows["t2"]["status"], rows["t2"]["assignee"]) == ("in_progress", "Anna")
    assert rows["t4"]["status"] == "open"  # an unknown status reads as open
    assert ids("status=open") == ["t1", "t4"]
    assert ids("status=closed") == ["t3"]
    assert ids("assignee=ANNA") == ["t2", "t3"]
    assert ids("assignee=") == ["t1", "t4"]
    assert ids("assignee=anna&status=in_progress") == ["t2"]
    assert admin.get("/api/incidents?status=done").status_code == 422

    admin.patch("/api/incidents/t1", json={"status": "closed", "assignee": " anna "})
    assert ids("status=closed") == ["t1", "t3"]
    assert ids("assignee=anna") == ["t1", "t2", "t3"]


def test_user_names_are_listed_for_any_signed_in_caller(admin: TestClient):
    names = admin.get("/api/users/names").json()["names"]
    assert names and all(isinstance(name, str) for name in names)
    assert names == sorted(names, key=str.lower)

    from app.main import app

    assert TestClient(app).get("/api/users/names").status_code == 401
