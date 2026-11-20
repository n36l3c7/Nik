"""The export of content as one file, and its import: it adds, and never deletes or changes.

Before 6.7 the import replaced the server: it emptied the accounts, the
incidents and every row of ``settings``, and whatever the file did not carry
was lost. These tests hold it to the opposite: nothing that is here goes.
"""

from __future__ import annotations

import sqlalchemy as sa
from fastapi.testclient import TestClient

from app.core.db import Base, SessionLocal, engine
from app.core.models import AuditEntry, Incident, Setting, User
from app.core.models import Session as SessionModel


def counts() -> dict[str, int]:
    """The number of rows of every table the models know, whatever a release adds to them."""
    with engine.connect() as conn:
        return {
            table.name: conn.execute(sa.select(sa.func.count()).select_from(table)).scalar()
            for table in Base.metadata.sorted_tables
        }


def test_an_import_adds_what_is_not_here_and_changes_nothing_that_is(admin: TestClient):
    admin.post("/api/users", json={"username": "vera", "password": "another-secret", "roles": ["viewer"]})
    kept = admin.post("/api/incidents", json={"id": "here-1", "name": "As it is on this server"}).json()
    with SessionLocal() as db:
        vera_hash = db.query(User).filter_by(username="vera").one().password_hash
        # What the file knows nothing of: a policy of another release, the secrets of the backups.
        db.add(Setting(id=1, doc={"keywords": ["of this server"]}))
        db.add(Setting(id=5, doc={"signIn": {"secondFactor": "required"}}))
        db.add(Setting(id=20, doc={"passphrase": "kept-encrypted"}))
        db.commit()
    made = admin.post("/api/automation/credentials", json={"name": "kept_key", "kind": "secret", "value": "v"})
    assert made.status_code == 201, made.text

    file = admin.get("/api/backup/export").json()
    file["users"] = [
        {"id": "u-new", "username": "paul", "passwordHash": vera_hash, "roles": ["analyst"]},
        # Here already, under other letters: not touched, whatever the file says of it.
        {"id": "u-vera", "username": "VERA", "passwordHash": "$2b$04$changed", "roles": ["admin"]},
    ]
    file["incidents"] = [
        {"id": "here-1", "name": "As another server had it", "number": 999},
        {"id": "came-1", "name": "Came with the file", "number": 500},
    ]
    file["audit"] = [{"id": "a-new", "at": "2026-01-01T00:00:00+00:00", "actor": "paul", "action": "incident.create"}]
    file["settings"] = {"keywords": ["from the file"]}
    before = counts()
    sessions_before = before["sessions"]

    done = admin.post("/api/backup/import", json=file)
    assert done.status_code == 200, done.text
    assert done.json() == {
        "users": 1,
        "incidents": 1,
        "audit": 1,
        "skipped": {"users": 1, "incidents": 1, "audit": 0},
        "settingsRestored": False,
    }
    after = counts()
    shrunk = {name: (before[name], after[name]) for name in before if after[name] < before[name]}
    assert not shrunk, f"an import must not remove a row of any table: {shrunk}"
    assert after["sessions"] == sessions_before and admin.get("/api/auth/me").status_code == 200

    with SessionLocal() as db:
        vera = db.query(User).filter_by(username="vera").one()
        assert vera.password_hash == vera_hash and vera.roles == ["viewer"]
        assert db.query(User).filter_by(username="paul").one().roles == ["analyst"]
        assert db.get(Setting, 5).doc == {"signIn": {"secondFactor": "required"}}
        assert db.get(Setting, 20).doc == {"passphrase": "kept-encrypted"}
        assert db.get(Setting, 1).doc == {"keywords": ["of this server"]}
        assert db.get(Incident, "here-1").doc["name"] == "As it is on this server"
        assert db.get(Incident, "here-1").number == kept["number"]
        assert db.get(Incident, "came-1").number == 500
        assert db.get(AuditEntry, "a-new") is not None
        assert db.query(SessionModel).count() == sessions_before
        line = db.query(AuditEntry).filter_by(action="backup.import").one().details
    assert line == (
        "Imported a file of content: added 1 of 2 accounts, 1 of 2 incidents, 1 of 1 audit entries; "
        "nothing that was here was changed"
    )
    assert [c["name"] for c in admin.get("/api/automation/credentials").json()["credentials"]] == ["kept_key"]
    # A second time: everything is here already.
    again = admin.post("/api/backup/import", json=file).json()
    assert (again["users"], again["incidents"], again["audit"]) == (0, 0, 0)


def test_the_detection_settings_are_taken_only_by_a_server_that_has_none(admin: TestClient):
    file = admin.get("/api/backup/export").json()
    file["settings"] = {"keywords": ["from the file"]}
    with SessionLocal() as db:
        assert db.get(Setting, 1) is None
    assert admin.post("/api/backup/import", json=file).json()["settingsRestored"] is True
    file["settings"] = {"keywords": ["a second file"]}
    assert admin.post("/api/backup/import", json=file).json()["settingsRestored"] is False
    with SessionLocal() as db:
        assert db.get(Setting, 1).doc == {"keywords": ["from the file"]}


def test_a_file_that_is_not_an_export_changes_nothing(admin: TestClient):
    before = counts()
    for wrong in ({"type": "incident"}, {"type": "backup", "users": []}, {"type": "backup", "users": [{"id": "x"}]}):
        refused = admin.post("/api/backup/import", json=wrong)
        assert refused.status_code == 400, refused.text
    assert counts() == before
