"""Roles as tags: what they grant, how accounts and keys take them, and the
accounts of releases before 4.0."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core import permissions
from app.core.permissions import ALL, ROLE_PERMISSIONS, ROLES, RoleError, clean_roles, permissions_of
from app.main import app as fastapi_app
from tests.conftest import make_key


def _user(admin: TestClient, username: str, **body) -> dict:
    res = admin.post("/api/users", json={"username": username, "password": "password1", **body})
    assert res.status_code == 201, res.text
    return res.json()["user"]


def _signed_in(username: str) -> TestClient:
    client = TestClient(fastapi_app)
    assert client.post("/api/auth/login", json={"username": username, "password": "password1"}).status_code == 200
    return client


# --------------------------------------------------------------------------- #
# The table
# --------------------------------------------------------------------------- #
def test_the_roles_grant_what_the_table_says():
    assert permissions_of(["viewer"]) == {"read"}
    assert permissions_of(["analyst"]) == {"read", "write", "automation.run"}
    assert permissions_of(["playbooks"]) == {"automation.run", "automation.edit", "automation.debug", "lists.manage"}
    assert permissions_of(["connectors"]) == {"connectors.manage"}
    assert permissions_of(["rules"]) == {"rules.manage"}
    assert permissions_of(["audit"]) == {"audit.read"}
    assert permissions_of(["dashboards"]) == {"dashboards.share"}
    assert permissions_of(["admin"]) == ALL
    # Roles add up; an unknown name grants nothing.
    assert permissions_of(["viewer", "audit", "nope"]) == {"read", "audit.read"}
    assert permissions_of([]) == permissions_of(None) == frozenset()
    # What only an admin holds.
    others = set().union(*(ROLE_PERMISSIONS[role] for role in ROLES if role != "admin"))
    assert ALL - others == {"automation.open", "incidents.configure", "content.manage", "admin"}
    # The system account of the automation engine reads and writes inside Nik, nothing else.
    assert ROLE_PERMISSIONS[permissions.SYSTEM_ROLE] == {"read", "write"} and permissions.SYSTEM_ROLE not in ROLES


def test_roles_are_stored_clean():
    assert clean_roles(["admin", "viewer", "viewer"]) == ["viewer", "admin"]  # once each, in the order shown
    for bad in ([], None, "admin", ["root"], ["automation"], [1], ["analyst", ""]):
        with pytest.raises(RoleError):
            clean_roles(bad)
    assert permissions.stored_roles(["analyst", "gone", 3]) == ["analyst"]
    assert permissions.stored_roles(None) == permissions.stored_roles("admin") == []


def test_accounts_of_older_releases_map_onto_roles():
    assert permissions.roles_from_legacy("admin") == ["admin"]
    assert permissions.roles_from_legacy("analyst") == ["analyst"]
    assert permissions.roles_from_legacy(None) == ["analyst"]
    assert permissions.roles_from_legacy("analyst", ["read"]) == ["viewer"]
    assert permissions.roles_from_legacy("analyst", ["read", "write"]) == ["analyst"]
    assert permissions.roles_from_legacy("admin", ["read"]) == ["admin"]
    assert permissions.legacy_role(["rules", "analyst"]) == "analyst"
    assert permissions.legacy_role(["viewer", "admin"]) == "admin"
    assert permissions.legacy_role(["audit"]) == "audit"
    assert permissions.legacy_scopes(["viewer"]) == ["read"]
    assert permissions.legacy_scopes(["analyst", "rules"]) == ["read", "write"]
    assert permissions.legacy_scopes(["admin"]) == ["read", "write", "admin"]
    assert permissions.legacy_scopes(["audit"]) == []


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #
def test_me_answers_with_the_roles_and_what_they_grant(admin: TestClient):
    me = admin.get("/api/auth/me").json()["user"]
    assert me["roles"] == ["admin"] and me["role"] == "admin" and me["permissions"] == sorted(ALL)
    _user(admin, "vera", roles=["viewer", "audit"])
    vera = _signed_in("vera").get("/api/auth/me").json()["user"]
    assert vera["roles"] == ["viewer", "audit"] and vera["role"] == "viewer"
    assert vera["permissions"] == ["audit.read", "read"]


def test_an_account_takes_several_roles_and_they_add_up(admin: TestClient):
    anna = _user(admin, "anna", roles=["analyst", "rules"])
    assert anna["roles"] == ["analyst", "rules"]
    session = _signed_in("anna")
    assert session.get("/api/incidents").status_code == 200
    rule = {"name": "mine", "source": "rule a { condition: true }", "enabled": True}
    assert session.post("/api/yara-rules", json=rule).status_code == 201  # rules.manage, without being an admin
    assert session.get("/api/audit").status_code == 403
    assert session.get("/api/users").status_code == 403

    # A role given or taken away takes effect at the next request, on the same session.
    res = admin.patch(f"/api/users/{anna['id']}", json={"roles": ["viewer", "audit"]})
    assert res.json()["user"]["roles"] == ["viewer", "audit"]
    assert session.get("/api/audit").status_code == 200
    assert session.post("/api/yara-rules", json=rule).status_code == 403
    assert session.post("/api/incidents", json={"id": "i1", "data": {}}).status_code == 403
    assert session.get("/api/incidents").status_code == 200
    entry = admin.get("/api/audit?q=roles").json()["entries"][0]
    assert "roles analyst, rules → viewer, audit" in entry["details"]


def test_an_account_with_a_single_narrow_role_signs_in_and_sees_only_its_part(admin: TestClient):
    _user(admin, "otto", roles=["audit"])
    otto = _signed_in("otto")
    assert otto.get("/api/auth/me").json()["user"]["permissions"] == ["audit.read"]
    assert otto.get("/api/audit").status_code == 200
    assert otto.delete("/api/audit").status_code == 403  # nobody but an admin clears the log
    assert otto.get("/api/incidents").status_code == 403
    assert otto.get("/api/artifacts").status_code == 403
    # What every signed-in account needs to work: the settings, the names, its own password.
    assert otto.get("/api/settings").status_code == 200
    assert otto.get("/api/users/names").status_code == 200
    change = {"currentPassword": "password1", "newPassword": "password2"}
    assert otto.put("/api/users/me/password", json=change).status_code == 204


def test_roles_are_validated_and_only_an_admin_gives_them(admin: TestClient):
    for bad in ([], ["root"], ["automation"], ["analyst", "nope"]):
        res = admin.post("/api/users", json={"username": "x", "password": "password1", "roles": bad})
        assert res.status_code == 400, bad
    anna = _user(admin, "anna")
    assert anna["roles"] == ["analyst"]  # the default
    assert admin.patch(f"/api/users/{anna['id']}", json={"roles": []}).status_code == 400
    assert admin.patch(f"/api/users/{anna['id']}", json={"roles": ["automation"]}).status_code == 400
    session = _signed_in("anna")
    assert session.patch(f"/api/users/{anna['id']}", json={"roles": ["admin"]}).status_code == 403
    assert session.post("/api/users", json={"username": "y", "password": "password1"}).status_code == 403
    assert session.post("/api/keys", json={"label": "mine", "roles": ["admin"]}).status_code == 403


def test_there_is_always_an_admin_and_nobody_removes_their_own(admin: TestClient):
    me = admin.get("/api/auth/me").json()["user"]
    res = admin.patch(f"/api/users/{me['id']}", json={"roles": ["analyst", "rules"]})
    assert res.status_code == 400 and "your own account" in res.json()["detail"]
    # Adding roles to oneself is fine as long as admin stays.
    res = admin.patch(f"/api/users/{me['id']}", json={"roles": ["admin", "analyst"]})
    assert res.status_code == 200 and res.json()["user"]["roles"] == ["analyst", "admin"]
    # Through a key there is no "own account": the last admin is still protected.
    key = make_key(admin, label="adm", roles=["admin"])
    caller = TestClient(fastapi_app)
    res = caller.patch(f"/api/users/{me['id']}", headers=key, json={"roles": ["analyst"]})
    assert res.status_code == 400 and "at least one admin" in res.json()["detail"]
    # An admin among other roles counts as an admin.
    _user(admin, "boss", roles=["viewer", "admin"])
    assert caller.patch(f"/api/users/{me['id']}", headers=key, json={"roles": ["analyst"]}).status_code == 200


def test_the_single_role_of_older_clients_is_still_accepted_and_answered(admin: TestClient):
    old = _user(admin, "old", role="admin")
    assert old["roles"] == ["admin"] and old["role"] == "admin"
    res = admin.patch(f"/api/users/{old['id']}", json={"role": "analyst"})
    assert res.json()["user"]["roles"] == ["analyst"] and res.json()["user"]["role"] == "analyst"
    assert admin.patch(f"/api/users/{old['id']}", json={"role": "root"}).status_code == 400
    # ``roles`` wins when both are sent.
    res = admin.patch(f"/api/users/{old['id']}", json={"role": "admin", "roles": ["viewer"]})
    assert res.json()["user"]["roles"] == ["viewer"]


# --------------------------------------------------------------------------- #
# API keys
# --------------------------------------------------------------------------- #
def test_a_key_takes_roles_like_an_account(admin: TestClient):
    res = admin.post("/api/keys", json={"label": "feed", "roles": ["viewer"]})
    assert res.status_code == 201
    record = res.json()["apiKey"]
    assert record["roles"] == ["viewer"] and record["role"] == "viewer" and record["scopes"] == ["read"]
    key = {"X-API-Key": res.json()["key"]}
    caller = TestClient(fastapi_app)
    assert caller.get("/api/incidents", headers=key).status_code == 200
    assert caller.post("/api/incidents", headers=key, json={"id": "x", "data": {}}).status_code == 403

    rules = make_key(admin, label="rules", roles=["rules"])
    assert caller.get("/api/yara-rules", headers=rules).status_code == 200
    assert caller.get("/api/incidents", headers=rules).status_code == 403

    listed = {k["label"]: k for k in admin.get("/api/keys").json()["keys"]}
    assert listed["rules"]["roles"] == ["rules"] and listed["rules"]["scopes"] == []
    for bad in ([], ["root"], ["automation"]):
        assert admin.post("/api/keys", json={"label": "bad", "roles": bad}).status_code == 400


def test_a_key_request_of_an_older_client_maps_onto_roles(admin: TestClient):
    def roles(**body):
        return admin.post("/api/keys", json={"label": "k", **body}).json()["apiKey"]["roles"]

    assert roles() == ["analyst"]
    assert roles(role="analyst") == ["analyst"]
    assert roles(role="analyst", scopes=["read"]) == ["viewer"]
    assert roles(scopes=["read", "write"]) == ["analyst"]
    assert roles(role="admin") == ["admin"]
    assert roles(role="admin", scopes=["read"]) == ["admin"]


# --------------------------------------------------------------------------- #
# Backup
# --------------------------------------------------------------------------- #
def test_a_backup_carries_the_roles_and_an_older_one_is_read(admin: TestClient):
    _user(admin, "vera", roles=["viewer", "audit"])
    backup = admin.get("/api/backup/export").json()
    by_name = {u["username"]: u for u in backup["users"]}
    assert by_name["vera"]["roles"] == ["viewer", "audit"] and by_name["vera"]["role"] == "analyst"
    assert by_name["admin"]["roles"] == ["admin"] and by_name["admin"]["role"] == "admin"

    # A backup of a release before 4.0 has the single role only.
    for user in backup["users"]:
        del user["roles"]
    by_name["vera"]["role"] = "admin"
    backup["users"].append(
        {"id": "u9", "username": "paul", "passwordHash": by_name["vera"]["passwordHash"], "role": "analyst"}
    )
    assert admin.post("/api/backup/import", json=backup).status_code == 200
    users = {u["username"]: u["roles"] for u in admin.get("/api/users").json()["users"]}
    assert users == {"admin": ["admin"], "vera": ["admin"], "paul": ["analyst"]}


def test_the_admin_who_restores_a_backup_keeps_the_admin_role(admin: TestClient):
    backup = admin.get("/api/backup/export").json()
    backup["users"][0]["roles"] = ["viewer"]
    assert admin.post("/api/backup/import", json=backup).status_code == 200
    assert admin.get("/api/auth/me").json()["user"]["roles"] == ["viewer", "admin"]
