"""The API of connectors and connections: files with their problems, write-only credentials, the test."""

from __future__ import annotations

import io
import json
import re
import zipfile

from fastapi.testclient import TestClient

from app.automation import connector_actions as ca
from app.core import vault
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import Connection
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_automation_engine import edge, node
from tests.test_connector_actions import ACME

BASE = "/api/automation"


def install(admin: TestClient, source: str = ACME) -> dict:
    res = admin.post(f"{BASE}/connectors", json={"source": source})
    assert res.status_code == 201, res.text
    return res.json()


def connect(admin: TestClient, name: str = "Acme production", **body) -> dict:
    payload = {
        "name": name,
        "connector": "acme",
        "config": {"url": "https://desk.example.com/api/"},
        "secrets": {"username": "svc", "password": "s3cret-pass"},
        **body,
    }
    res = admin.post(f"{BASE}/instances", json=payload)
    assert res.status_code == 201, res.text
    return res.json()


def test_a_connector_is_installed_from_its_file_or_refused_with_the_lines(admin: TestClient):
    bad = ACME.replace("version: 2", "version: two").replace(
        "method: POST\n      path: /tickets", "method: SEND\n      path: /tickets"
    )
    wrong_method = bad.splitlines().index("      method: SEND") + 1
    checked = admin.post(f"{BASE}/connectors/check", json={"source": bad}).json()
    assert checked["connector"] is None
    assert [problem["line"] for problem in checked["problems"]] == [3, wrong_method]
    refused = admin.post(f"{BASE}/connectors", json={"source": bad})
    assert refused.status_code == 422 and refused.json()["problems"] == checked["problems"]
    assert (
        refused.json()["detail"].startswith("The file is not a connector: ") and "(line 3)" in refused.json()["detail"]
    )
    assert admin.get(f"{BASE}/connectors").json()["connectors"] == []

    good = admin.post(f"{BASE}/connectors/check", json={"source": ACME}).json()
    assert good["problems"] == [] and good["connector"]["id"] == "acme"
    made = install(admin)
    assert (made["id"], made["name"], made["version"], made["builtin"], made["instances"]) == (
        "acme",
        "Acme Desk",
        2,
        False,
        0,
    )
    assert made["source"] == ACME and made["secrets"] == ["username", "password"] and made["usedBy"] == []
    assert [command["name"] for command in made["commands"]] == ["create-ticket", "get-ticket", "close-and-wait"]
    listed = admin.get(f"{BASE}/connectors").json()["connectors"]
    assert [row["id"] for row in listed] == ["acme"] and "source" not in listed[0]
    assert admin.get(f"{BASE}/connectors/nope").status_code == 404
    # The same file again replaces it; an older version is refused.
    assert (
        admin.post(f"{BASE}/connectors", json={"source": ACME.replace("version: 2", "version: 3")}).status_code == 201
    )
    older = admin.post(f"{BASE}/connectors", json={"source": ACME})
    assert older.status_code == 422 and "Version 3 is installed" in older.json()["detail"]
    actions = [entry["action"] for entry in admin.get("/api/audit").json()["entries"]]
    assert actions.count("connector.install") == 2


def test_credentials_are_written_and_never_read(admin: TestClient):
    install(admin)
    made = connect(admin)
    assert made["config"] == {"url": "https://desk.example.com/api"}  # as it is compared: no trailing slash
    assert made["secrets"] == {"username": True, "password": True} and made["host"] == "desk.example.com"
    assert "s3cret-pass" not in json.dumps(made) and "svc" not in json.dumps(made["secrets"])
    listed = admin.get(f"{BASE}/instances").json()["instances"]
    assert "s3cret-pass" not in json.dumps(listed) and listed[0]["connectorName"] == "Acme Desk"
    with SessionLocal() as db:
        row = db.get(Connection, made["id"])
        assert "s3cret-pass" not in row.secrets  # encrypted at rest
        assert ca.secrets_of(row) == {"username": "svc", "password": "s3cret-pass"}

    # A secret left out is kept, an empty one is removed, a new one replaces.
    url = f"{BASE}/instances/{made['id']}"
    kept = admin.put(url, json={"secrets": {"password": None}}).json()
    assert kept["secrets"] == {"username": True, "password": True}
    changed = admin.put(url, json={"secrets": {"username": "", "password": "another-pass"}}).json()
    assert changed["secrets"] == {"username": False, "password": True}
    with SessionLocal() as db:
        assert ca.secrets_of(db.get(Connection, made["id"])) == {"password": "another-pass"}
    assert (
        admin.put(url, json={"secrets": {"token": "x"}}).json()["detail"] == '"token" is not a secret of this connector'
    )

    # What a connection is asked for is checked.
    for body, sentence in (
        ({"config": {}}, "Url is required"),
        ({"config": {"url": "desk.example.com"}}, "Url is an https:// address"),
        (
            {"config": {"url": "https://x.example.com", "region": "eu"}},
            '"region" is not something this connector asks for',
        ),
        ({"connector": "nope"}, "Connector not found"),
    ):
        res = admin.post(
            f"{BASE}/instances",
            json={"name": "Other", "connector": "acme", "config": {"url": "https://x.example.com"}, **body},
        )
        assert res.status_code in (400, 404) and res.json()["detail"] == sentence, body
    same = admin.post(
        f"{BASE}/instances",
        json={"name": "acme PRODUCTION", "connector": "acme", "config": {"url": "https://x.example.com"}},
    )
    assert same.json()["detail"] == "An instance with this name exists already"
    # The audit log says where a connection points, never what opens it.
    entries = admin.get("/api/audit").json()["entries"]
    created = next(entry for entry in entries if entry["action"] == "connection.create")
    assert created["details"] == 'Made the instance "Acme production" to Acme Desk at desk.example.com'
    assert "pass" not in json.dumps(entries)


def test_the_test_of_a_connection_reaches_its_host_and_nothing_else(admin: TestClient, outside):
    install(admin)
    made = connect(admin)
    outside.host("desk.example.com", "93.184.215.20")
    outside.answer("desk.example.com", 200, {"name": "svc"}, path="/api/me")
    tested = admin.post(f"{BASE}/instances/{made['id']}/test").json()
    assert (tested["ok"], tested["status"], tested["message"]) == (True, 200, "Acme Desk answered 200")
    assert outside.requests[0]["headers"]["Authorization"].startswith("Basic ")
    assert admin.get(f"{BASE}/instances").json()["instances"][0]["lastTest"]["ok"] is True
    # Wrong credentials, a host that is not there: said, never raised. Changing the connection forgets the result.
    outside.answer("desk.example.com", 401, {"error": "no"}, path="/api/me")
    assert admin.post(f"{BASE}/instances/{made['id']}/test").json()["message"] == "Acme Desk answered 401"
    moved = admin.put(f"{BASE}/instances/{made['id']}", json={"config": {"url": "https://gone.example.com"}}).json()
    assert moved["lastTest"] is None and moved["host"] == "gone.example.com"
    failed = admin.post(f"{BASE}/instances/{made['id']}/test").json()
    assert failed["ok"] is False and re.search(r"gone\.example\.com", failed["message"])
    assert admin.post(f"{BASE}/instances/nope/test").status_code == 404


def test_what_a_playbook_uses_cannot_be_removed(admin: TestClient):
    install(admin)
    made = connect(admin)
    playbook_id = admin.post(f"{BASE}/playbooks", json={"name": "Uses Acme"}).json()["id"]
    shape = {
        "nodes": [
            node("start", "trigger", manual=True),
            node("open", "action", action="acme.get-ticket", connection="Acme production", args={"number": "T-1"}),
        ],
        "edges": [edge("start", "open")],
    }
    assert admin.post(f"{BASE}/playbooks/{playbook_id}/versions", json={"graph": shape}).status_code == 201
    assert admin.get(f"{BASE}/connectors/acme").json()["usedBy"] == ["Uses Acme"]
    for url in (f"{BASE}/instances/{made['id']}", f"{BASE}/connectors/acme"):
        res = admin.delete(url)
        assert res.status_code == 409 and res.json()["detail"] == "Used by: Uses Acme"
    # The library of the canvas lists the connections of each connector.
    assert admin.get(f"{BASE}/catalog").json()["instances"] == {
        "acme": [{"id": made["id"], "name": "Acme production", "enabled": True}]
    }
    assert admin.delete(f"{BASE}/playbooks/{playbook_id}").status_code == 204
    # A connector goes with its connections.
    assert admin.delete(f"{BASE}/connectors/acme").status_code == 204
    assert admin.get(f"{BASE}/instances").json()["instances"] == []
    assert admin.get(f"{BASE}/catalog").json()["instances"] == {}


def test_who_builds_playbooks_sees_the_names_of_connections_and_no_more(admin: TestClient):
    install(admin)
    made = connect(admin)
    builder = make_key(admin, label="pb", roles=["playbooks"])
    manager = make_key(admin, label="cn", roles=["connectors"])
    viewer = make_key(admin, label="vi", roles=["viewer"])
    with TestClient(fastapi_app) as other:
        names = other.get(f"{BASE}/instances", headers=builder).json()["instances"]
        assert names == [
            {
                "id": made["id"],
                "name": "Acme production",
                "connector": "acme",
                "connectorName": "Acme Desk",
                "enabled": True,
            }
        ]
        assert other.get(f"{BASE}/instances", headers=viewer).status_code == 403
        assert other.get(f"{BASE}/connectors", headers=builder).status_code == 403
        assert other.post(f"{BASE}/instances/{made['id']}/test", headers=builder).status_code == 403
        full = other.get(f"{BASE}/instances", headers=manager).json()["instances"][0]
        assert full["secrets"] == {"username": True, "password": True}
        # The role Connectors manages them without being an admin.
        assert (
            other.put(f"{BASE}/instances/{made['id']}", json={"name": "Acme prod"}, headers=manager).json()["name"]
            == "Acme prod"
        )


def test_the_samples_are_the_shipped_files_in_a_zip(admin: TestClient):
    res = admin.get(f"{BASE}/connectors/samples")
    assert res.status_code == 200 and res.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(res.content)) as archive:
        names = archive.namelist()
        files = sorted(path.name for path in ca.SEED_DIR.glob("*.yml"))
        # A connector kept as a package goes as its folder.
        folders = sorted(
            f"{path.parent.name}/{item.name}"
            for path in ca.SEED_DIR.glob("*/connector.yml")
            for item in path.parent.iterdir()
        )
        assert names == files + folders and "mail/connector.yml" in names
        for name in (name for name in names if name.endswith(".yml")):
            ca.load(archive.read(name))  # each is a connector that loads


def test_the_secrets_of_automation_follow_a_change_of_the_key(admin: TestClient, monkeypatch):
    install(admin)
    made = connect(admin)
    assert (
        admin.put(f"{BASE}/settings", json={"smtp": {"host": "smtp.example.org", "password": "smtp-pass"}}).status_code
        == 200
    )
    old = settings.SECRET_KEY
    monkeypatch.setattr(settings, "SECRET_KEY", "a-new-secret-key-for-the-test-0123456789")
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [old])
    vault._fernet.cache_clear() if hasattr(vault._fernet, "cache_clear") else None
    assert vault.reencrypt(SessionLocal) >= 2
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    vault._fernet.cache_clear() if hasattr(vault._fernet, "cache_clear") else None
    with SessionLocal() as db:
        # Readable with the new key alone.
        assert ca.secrets_of(db.get(Connection, made["id"]))["password"] == "s3cret-pass"
        from app.automation import outbound

        assert outbound.smtp_settings(db)["password"] == "smtp-pass"


# --------------------------------------------------------------------------- #
# Instances (5.1)                                                             #
# --------------------------------------------------------------------------- #
def test_a_connector_has_instances_and_is_enabled_when_one_is_on(admin: TestClient):
    install(admin)
    listed = admin.get(f"{BASE}/connectors").json()["connectors"][0]
    assert (listed["instances"], listed["instancesOn"], listed["enabled"]) == (0, 0, False)

    # An instance is made under its connector; it is the connection of before, and on.
    body = {"config": {"url": "https://desk.example.com/api"}, "secrets": {"username": "svc", "password": "p"}}
    first = admin.post(f"{BASE}/connectors/acme/instances", json={"name": "Production", **body})
    assert first.status_code == 201, first.text
    assert first.json()["enabled"] is True and first.json()["connector"] == "acme"
    second = admin.post(f"{BASE}/connectors/acme/instances", json={"name": "Test", "enabled": False, **body})
    assert second.status_code == 201 and second.json()["enabled"] is False
    assert admin.post(f"{BASE}/connectors/acme/instances", json={"name": "production", **body}).status_code == 400
    assert admin.post(f"{BASE}/connectors/nope/instances", json={"name": "x", **body}).status_code == 404

    names = [(i["name"], i["enabled"]) for i in admin.get(f"{BASE}/connectors/acme/instances").json()["instances"]]
    assert names == [("Production", True), ("Test", False)]
    assert admin.get(f"{BASE}/connectors/nope/instances").status_code == 404
    listed = admin.get(f"{BASE}/connectors").json()["connectors"][0]
    assert (listed["instances"], listed["instancesOn"], listed["enabled"], listed["instances"]) == (2, 1, True, 2)
    # Who builds playbooks sees which instance is on, to choose one.
    assert {c["name"]: c["enabled"] for c in admin.get(f"{BASE}/instances").json()["instances"]} == {
        "Production": True,
        "Test": False,
    }

    # Turned off: it keeps what it was set up with, and the connector is enabled no more.
    off = admin.put(f"{BASE}/instances/{first.json()['id']}", json={"enabled": False}).json()
    assert off["enabled"] is False and off["secrets"] == {"username": True, "password": True}
    assert off["host"] == "desk.example.com"
    assert admin.get(f"{BASE}/connectors").json()["connectors"][0]["enabled"] is False
    audit = admin.get("/api/audit", params={"q": "action:connection.update"}).json()["entries"]
    assert any("turned off" in entry["details"] for entry in audit)
    with SessionLocal() as db:
        assert ca.enabled_connectors(db) == set()
        db.get(Connection, second.json()["id"]).enabled = True
        db.commit()
        assert ca.enabled_connectors(db) == {"acme"}
        # A node that names no instance takes the only one that is on.
        assert ca.find_connection(db, "acme", "").name == "Test"
        assert ca.find_connection(db, "acme", "Production").enabled is False


# --------------------------------------------------------------------------- #
# A connector as a package: its logo and its README (5.1)                     #
# --------------------------------------------------------------------------- #
SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 8 8"><rect width="8" height="8" fill="#135"/></svg>'
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 40


def test_a_logo_is_an_image_and_nothing_else():
    from app.automation import connector_logo as logo

    assert logo.clean(SVG) == (SVG, "image/svg+xml")
    assert logo.clean(b'<?xml version="1.0"?>\n<!-- made by hand -->\n' + SVG)[1] == "image/svg+xml"
    assert logo.clean(PNG) == (PNG, "image/png")
    inner = b'<svg xmlns="http://www.w3.org/2000/svg"><use href="#a"/><rect fill="url(#g)"/></svg>'
    assert logo.clean(inner)[1] == "image/svg+xml"  # what points inside the file is a drawing still
    for bad, why in (
        (b"", "empty"),
        (b"GIF89a....", "PNG or an SVG"),
        (b"<html><svg></svg></html>", "PNG or an SVG"),
        (b"\xff\xfe\x00not text", "PNG or an SVG"),
        (SVG.replace(b"<rect", b"<script>alert(1)</script><rect"), "not a drawing"),
        (SVG.replace(b"<rect", b"<foreignObject/><rect"), "not a drawing"),
        (SVG.replace(b"<rect", b'<rect onload="x()"'), "event handler"),
        (SVG.replace(b"<rect", b'<a href="javascript:alert(1)"/><rect'), "script address"),
        (SVG.replace(b"<rect", b'<image href="https://evil.example/x.png"/><rect'), "outside the file"),
        (SVG.replace(b'fill="#135"', b'style="fill:url(https://evil.example/a)"'), "outside the file"),
        (b'<!DOCTYPE svg [<!ENTITY x "y">]>' + SVG, "DOCTYPE"),
        (SVG.replace(b"<rect", b"<style>@import 'a.css';</style><rect"), "imported"),
        (b"<svg>" + b" " * (logo.MAX_BYTES + 1) + b"</svg>", "KB at most"),
    ):
        try:
            logo.clean(bad)
        except logo.LogoError as error:
            assert why in error.message, (bad[:40], error.message)
        else:
            raise AssertionError(f"accepted: {bad[:40]!r}")


def test_a_connector_is_given_a_logo_and_everyone_who_reads_sees_it(admin: TestClient):
    install(admin)
    assert admin.get(f"{BASE}/connectors").json()["connectors"][0]["logo"] is None
    assert admin.get(f"{BASE}/connectors/acme/logo").status_code == 404

    bad = admin.put(f"{BASE}/connectors/acme/logo", content=SVG.replace(b"<rect", b"<script/><rect"))
    assert bad.status_code == 400 and "not a drawing" in bad.json()["detail"]
    assert admin.put(f"{BASE}/connectors/acme/logo", content=b"x" * (300 * 1024)).status_code == 413
    assert admin.put(f"{BASE}/connectors/nope/logo", content=SVG).status_code == 404

    made = admin.put(f"{BASE}/connectors/acme/logo", content=SVG)
    assert made.status_code == 200, made.text
    path = made.json()["logo"]
    assert path.startswith("/automation/connectors/acme/logo?v=")
    image = admin.get("/api" + path)
    assert image.status_code == 200 and image.content == SVG
    assert image.headers["content-type"].startswith("image/svg+xml")
    assert "default-src 'none'" in image.headers["content-security-policy"]
    assert image.headers["x-content-type-options"] == "nosniff"
    # A viewer sees the logo (it marks incidents); only who manages connectors changes it.
    viewer = make_key(admin, label="vi", roles=["viewer"])
    with TestClient(fastapi_app) as other:
        assert other.get("/api" + path, headers=viewer).status_code == 200
        assert other.put(f"{BASE}/connectors/acme/logo", content=SVG, headers=viewer).status_code == 403
        assert other.delete(f"{BASE}/connectors/acme/logo", headers=viewer).status_code == 403

    # Another image: another address, so a browser does not show the old one.
    again = admin.put(f"{BASE}/connectors/acme/logo", content=PNG).json()["logo"]
    assert again != path and admin.get("/api" + again).headers["content-type"] == "image/png"
    # A new file of the connector keeps its logo; removing the logo leaves the connector.
    install(admin, ACME.replace("version: 1", "version: 2"))
    assert admin.get(f"{BASE}/connectors/acme").json()["logo"] == again
    assert admin.delete(f"{BASE}/connectors/acme/logo").status_code == 204
    assert admin.get(f"{BASE}/connectors/acme").json()["logo"] is None
    assert admin.delete(f"{BASE}/connectors/acme/logo").status_code == 204


def test_a_shipped_connector_may_be_a_folder_with_its_logo_and_readme(admin: TestClient, tmp_path, monkeypatch):
    folder = tmp_path / "acme"
    folder.mkdir()
    (folder / "connector.yml").write_text(ACME, encoding="utf-8")
    (folder / "logo.svg").write_bytes(SVG)
    (folder / "README.md").write_text("# Acme Desk\n\nHow to get a token.\n", encoding="utf-8")
    (tmp_path / "other.yml").write_text(ACME.replace("id: acme", "id: other"), encoding="utf-8")
    monkeypatch.setattr(ca, "SEED_DIR", tmp_path)

    assert sorted(connector.id for _text, connector in ca.shipped()) == ["acme", "other"]
    assert ca.shipped_extras() == {"acme": {"logo": SVG, "readme": "# Acme Desk\n\nHow to get a token.\n"}}
    with SessionLocal() as db:
        assert ca.seed(db) == 2
        db.commit()
        row = db.get(ca.Connector, "acme")
        assert (bytes(row.logo), row.logo_type, row.readme.startswith("# Acme Desk")) == (SVG, "image/svg+xml", True)
        assert db.get(ca.Connector, "other").logo is None and ca.logo_path(db.get(ca.Connector, "other")) is None
        assert ca.seed(db) == 0
