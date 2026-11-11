"""Accounts managed by an admin, sign-in protections, and the audit trail written by the server."""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic.config import Config
from fastapi.testclient import TestClient

from alembic import command
from app.core.audit import describe_patch
from app.main import app as fastapi_app
from tests.conftest import ADMIN, make_key

MERGE = {"Content-Type": "application/merge-patch+json"}


def _user(admin: TestClient, username: str = "anna", password: str = "password1", role: str = "analyst") -> dict:
    res = admin.post("/api/users", json={"username": username, "password": password, "role": role})
    assert res.status_code == 201, res.text
    return res.json()["user"]


def _signed_in(username: str, password: str) -> TestClient:
    client = TestClient(fastapi_app)
    res = client.post("/api/auth/login", json={"username": username, "password": password})
    assert res.status_code == 200, res.text
    return client


def _actions(client: TestClient, **params) -> list[str]:
    return [entry["action"] for entry in client.get("/api/audit", params=params).json()["entries"]]


# --------------------------------------------------------------------------- #
# Account management
# --------------------------------------------------------------------------- #
def test_an_admin_changes_name_role_and_password_of_an_account(admin: TestClient):
    anna = _user(admin)
    session = _signed_in("anna", "password1")
    admin.post("/api/incidents", json={"id": "i1", "data": {}, "assignee": "anna"})

    res = admin.patch(f"/api/users/{anna['id']}", json={"username": "anna.b", "role": "admin"})
    assert res.status_code == 200
    assert res.json()["user"] == {**anna, "username": "anna.b", "role": "admin", "disabled": False}
    # The incidents assigned to the account follow its new name.
    assert admin.get("/api/incidents/i1").json()["assignee"] == "anna.b"
    assert admin.get("/api/incidents?view=summary&assignee=anna.b").json()["total"] == 1
    # A rename or a new role keeps the session; a new password ends it.
    assert session.get("/api/auth/me").json()["user"]["username"] == "anna.b"
    assert admin.patch(f"/api/users/{anna['id']}", json={"password": "another-secret"}).status_code == 200
    assert session.get("/api/auth/me").status_code == 401
    assert (
        TestClient(fastapi_app)
        .post("/api/auth/login", json={"username": "anna.b", "password": "password1"})
        .status_code
        == 401
    )
    _signed_in("anna.b", "another-secret")

    entry = admin.get("/api/audit?q=renamed").json()["entries"][0]
    assert entry["action"] == "user.update" and entry["actor"] == "admin"
    assert "1 assigned incidents follow" in entry["details"] and "role analyst → admin" in entry["details"]


def test_account_changes_are_validated(admin: TestClient):
    anna = _user(admin)
    me = admin.get("/api/auth/me").json()["user"]
    url = f"/api/users/{anna['id']}"
    assert admin.patch(url, json={"username": "  "}).status_code == 400
    assert admin.patch(url, json={"username": "ADMIN"}).json()["detail"] == "Username already exists"
    assert admin.patch(url, json={"role": "root"}).status_code == 400
    assert admin.patch(url, json={"password": "short"}).status_code == 400
    assert admin.patch("/api/users/nope", json={"role": "admin"}).status_code == 404
    # The same name in another case is the account's own: allowed.
    assert admin.patch(url, json={"username": "Anna"}).json()["user"]["username"] == "Anna"
    # Nothing to change: accepted, and not logged.
    before = len(_actions(admin))
    assert admin.patch(url, json={}).status_code == 200
    assert len(_actions(admin)) == before
    # Only admins change accounts.
    analyst = _signed_in("anna", "password1")
    assert analyst.patch(f"/api/users/{me['id']}", json={"role": "analyst"}).status_code == 403


def test_there_is_always_an_admin_that_can_sign_in(admin: TestClient):
    me = admin.get("/api/auth/me").json()["user"]
    for change in ({"role": "analyst"}, {"disabled": True}):
        res = admin.patch(f"/api/users/{me['id']}", json=change)
        assert res.status_code == 400 and "your own account" in res.json()["detail"]
    # Through an admin key there is no "own account": the last admin is still protected.
    key = make_key(admin, label="adm", role="admin")
    k = TestClient(fastapi_app)
    for change in ({"role": "analyst"}, {"disabled": True}):
        res = k.patch(f"/api/users/{me['id']}", headers=key, json=change)
        assert res.status_code == 400 and "at least one admin" in res.json()["detail"]
    _user(admin)
    assert k.delete(f"/api/users/{me['id']}", headers=key).json()["detail"].startswith("There must be")
    # With a second admin the first can be demoted.
    _user(admin, "boss", role="admin")
    assert k.patch(f"/api/users/{me['id']}", headers=key, json={"role": "analyst"}).status_code == 200


def test_a_disabled_account_cannot_sign_in_or_keep_working(admin: TestClient):
    anna = _user(admin)
    session = _signed_in("anna", "password1")
    assert admin.patch(f"/api/users/{anna['id']}", json={"disabled": True}).json()["user"]["disabled"] is True
    assert session.get("/api/incidents").status_code == 401
    res = TestClient(fastapi_app).post("/api/auth/login", json={"username": "anna", "password": "password1"})
    assert res.status_code == 403 and res.json()["detail"] == "This account is disabled"
    # A wrong password on a disabled account says nothing about it.
    wrong = TestClient(fastapi_app).post("/api/auth/login", json={"username": "anna", "password": "nope"})
    assert wrong.status_code == 401
    # It is no longer offered as an assignee, and comes back when enabled.
    assert "anna" not in admin.get("/api/users/names").json()["names"]
    admin.patch(f"/api/users/{anna['id']}", json={"disabled": False})
    _signed_in("anna", "password1")
    assert "anna" in admin.get("/api/users/names").json()["names"]


def test_a_user_changes_their_own_password(admin: TestClient):
    _user(admin)
    here = _signed_in("anna", "password1")
    elsewhere = _signed_in("anna", "password1")
    url = "/api/users/me/password"
    wrong = here.put(url, json={"currentPassword": "nope", "newPassword": "a-new-secret"})
    assert wrong.status_code == 400 and "current password" in wrong.json()["detail"]
    assert here.put(url, json={"currentPassword": "password1", "newPassword": "short"}).status_code == 400
    assert here.put(url, json={"currentPassword": "password1", "newPassword": "a-new-secret"}).status_code == 204
    # This session goes on; the others of the account are over.
    assert here.get("/api/auth/me").status_code == 200
    assert elsewhere.get("/api/auth/me").status_code == 401
    _signed_in("anna", "a-new-secret")
    assert TestClient(fastapi_app).put(url, json={"currentPassword": "x", "newPassword": "y" * 8}).status_code == 401
    assert "user.password" in _actions(admin)


# --------------------------------------------------------------------------- #
# Sign-in protections
# --------------------------------------------------------------------------- #
def test_an_account_is_locked_after_too_many_wrong_passwords(admin: TestClient, monkeypatch):
    from app.routers import auth

    fastapi_app.state.limiter.enabled = False
    try:
        monkeypatch.setattr(auth, "MAX_FAILED_LOGINS", 3)
        anna = _user(admin)
        client = TestClient(fastapi_app)
        for _ in range(3):
            assert client.post("/api/auth/login", json={"username": "anna", "password": "nope"}).status_code == 401
        locked = client.post("/api/auth/login", json={"username": "anna", "password": "password1"})
        assert locked.status_code == 429 and "try again in 5 minutes" in locked.json()["detail"]
        assert "auth.locked" in _actions(admin)
        # An unknown account is answered like a wrong password, however often.
        for _ in range(4):
            assert client.post("/api/auth/login", json={"username": "ghost", "password": "x"}).status_code == 401
        # An admin's password reset unlocks it.
        admin.patch(f"/api/users/{anna['id']}", json={"password": "fresh-secret"})
        _signed_in("anna", "fresh-secret")
    finally:
        fastapi_app.state.limiter.enabled = True


def test_a_good_sign_in_resets_the_count_and_purges_expired_sessions(admin: TestClient, monkeypatch):
    from app.core.db import SessionLocal
    from app.core.models import Session as SessionModel
    from app.core.models import User
    from app.routers import auth

    monkeypatch.setattr(auth, "MAX_FAILED_LOGINS", 3)
    _user(admin)
    client = TestClient(fastapi_app)
    for _ in range(2):
        client.post("/api/auth/login", json={"username": "anna", "password": "nope"})
    with SessionLocal() as db:
        anna = db.scalar(sa.select(User).where(User.username == "anna"))
        assert anna.failed_logins == 2
        db.add(
            SessionModel(token="old", user_id=anna.id, created_at="2020-01-01", expires_at="2020-01-02T00:00:00+00:00")
        )
        db.commit()
    _signed_in("anna", "password1")
    with SessionLocal() as db:
        assert db.scalar(sa.select(User).where(User.username == "anna")).failed_logins == 0
        assert db.get(SessionModel, "old") is None


# --------------------------------------------------------------------------- #
# The audit trail is the server's
# --------------------------------------------------------------------------- #
def test_a_session_is_audited_like_a_key(admin: TestClient):
    """What the browser does is recorded by the server, not reported by the browser."""
    admin.post("/api/incidents", json={"id": "i1", "name": "WKS-01", "host": "WKS-01", "data": {}, "flags": {}})
    flag = {"key": "k1", "title": "evil.exe", "comments": []}
    patches = [
        {"flags": {"k1": flag}},
        {"flags": {"k1": {**flag, "comments": [{"id": "c1", "text": "dropper"}]}}},
        {"notes": [{"id": "n1", "text": "first"}]},
        {"notes": [{"id": "n1", "text": "edited"}]},
        {"status": "closed", "assignee": "admin"},
        {"data": {"browser": {"browsers": {"chrome": {"meta": {"history": {"fileName": "History"}}}}}}},
        {"flags": {"k1": None}, "notes": []},
    ]
    for patch in patches:
        assert admin.patch("/api/incidents/i1", headers=MERGE, content=json.dumps(patch)).status_code == 200
    admin.delete("/api/incidents/i1")

    entries = admin.get("/api/audit?incidentId=i1").json()["entries"]
    assert {entry["actor"] for entry in entries} == {"admin"}
    assert sorted(entry["action"] for entry in entries) == sorted(
        [
            "incident.create",
            "flag.add",
            "flag.comment",
            "note.add",
            "note.update",
            "incident.update",
            "evidence.update",
            "flag.remove",
            "note.remove",
            "incident.delete",
        ]
    )
    details = {entry["action"]: entry["details"] for entry in entries}
    assert details["flag.add"] == "Flagged: evil.exe"
    assert details["incident.update"] == 'Updated assignee, status of "WKS-01"'
    assert details["evidence.update"] == "Updated the evidence of browser: History"


def test_describe_patch_reads_only_the_tabs_the_patch_names():
    old = {"name": "n", "data": {"browser": {"a": 1}, "mail": {"messages": []}}}
    new = {"name": "n", "data": {"browser": {"a": 2}, "mail": {"messages": [1]}}}
    assert describe_patch(old, new, {"data": {"browser": {"a": 2}}}) == [
        ("evidence.update", "Updated the evidence of browser")
    ]
    assert describe_patch(old, new) == [("evidence.update", "Updated the evidence of browser, mail")]
    assert describe_patch(old, old, {"flags": {}}) == []
    # A document with odd shapes is described, not refused.
    assert describe_patch({"flags": [], "notes": "x"}, {"flags": {"k": "odd"}, "notes": [1]}) == [
        ("flag.add", "Flagged: an entry")
    ]


def test_the_log_cannot_be_written_by_hand_and_clearing_it_leaves_a_trace(admin: TestClient):
    forged = admin.post("/api/audit", json={"action": "incident.delete", "details": "it was not me"})
    assert forged.status_code == 400
    exported = admin.post("/api/audit", json={"action": "incident.export", "details": 'Exported incident "x"'})
    assert exported.status_code == 201 and exported.json()["actor"] == "admin"

    assert admin.delete("/api/audit").status_code == 204
    entries = admin.get("/api/audit").json()["entries"]
    assert [entry["action"] for entry in entries] == ["audit.clear"]
    assert entries[0]["actor"] == "admin" and "entries)" in entries[0]["details"]


def test_sign_in_sign_out_keys_and_accounts_are_recorded(admin: TestClient):
    anna = _user(admin)
    key = admin.post("/api/keys", json={"label": "soar"}).json()["apiKey"]
    admin.delete(f"/api/keys/{key['id']}")
    admin.delete(f"/api/users/{anna['id']}")
    session = _signed_in(ADMIN["username"], ADMIN["password"])
    session.post("/api/auth/logout")
    actions = _actions(admin)
    for action in ("auth.login", "auth.logout", "user.create", "user.delete", "apikey.create", "apikey.revoke"):
        assert action in actions, action
    # The first account is recorded too, by its own name.
    first = admin.get("/api/audit?q=first run").json()["entries"]
    assert len(first) == 1 and first[0]["actor"] == "admin"


# --------------------------------------------------------------------------- #
# Settings
# --------------------------------------------------------------------------- #
def test_analysts_change_the_working_settings_admins_the_rest(admin: TestClient):
    _user(admin)
    analyst = _signed_in("anna", "password1")
    current = admin.get("/api/settings").json()
    wanted = {
        **current,
        "iocAllowlist": ["example.org"],
        "report": {**current["report"], "orgName": "Not my call"},
        "mail": {"orgDomains": ["evil.example"], "trustedAuthServers": []},
    }
    saved = analyst.put("/api/settings", json=wanted)
    assert saved.status_code == 200
    assert saved.json()["iocAllowlist"] == ["example.org"]
    # What only an admin decides is left as it was.
    assert saved.json()["report"] == current["report"] and saved.json()["mail"] == current["mail"]
    assert admin.put("/api/settings", json=wanted).json()["report"]["orgName"] == "Not my call"

    entries = admin.get("/api/audit?q=settings").json()["entries"]
    assert [(entry["actor"], entry["details"]) for entry in reversed(entries)] == [
        ("anna", "Changed the settings: iocAllowlist"),
        ("admin", "Changed the settings: mail, report"),
    ]
    # A key with the write scope can save settings; a read-only one cannot.
    k = TestClient(fastapi_app)
    assert k.put("/api/settings", headers=make_key(admin, label="rw"), json=current).status_code == 200
    assert k.put("/api/settings", headers=make_key(admin, label="ro", scopes=["read"]), json=current).status_code == 403


# --------------------------------------------------------------------------- #
# Migration
# --------------------------------------------------------------------------- #
def test_migration_0021_adds_the_account_state(tmp_path, monkeypatch):
    url = "sqlite:///" + str(tmp_path / "old.db").replace("\\", "/")
    engine = sa.create_engine(url)
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE users (id VARCHAR PRIMARY KEY, username VARCHAR NOT NULL)"))
        conn.execute(sa.text("INSERT INTO users VALUES ('u1', 'admin')"))

    import app.core.db

    monkeypatch.setattr(app.core.db, "engine", engine)
    cfg = Config("alembic.ini")
    command.stamp(cfg, "0020_incident_rev")
    command.upgrade(cfg, "0021_user_account_state")
    with engine.connect() as conn:
        row = conn.execute(sa.text("SELECT disabled, failed_logins, locked_until FROM users")).one()
    assert (bool(row[0]), row[1], row[2]) == (False, 0, None)
    command.downgrade(cfg, "0020_incident_rev")
    with engine.connect() as conn:
        assert {c["name"] for c in sa.inspect(conn).get_columns("users")} == {"id", "username"}
