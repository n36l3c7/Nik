"""The keys of the server on the screen, and changing one (key_rotation.py): asked for by an
administrator, followed to its end, never leaving a secret that neither key reads."""

from __future__ import annotations

import io
import json
import os
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import key_rotation, store_seal
from app.backups import config as backup_config
from app.backups import container, runner
from app.core import keys, store, vault
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import (
    AuditEntry,
    Backup,
    Credential,
    IntegrationKey,
    NetworkCapture,
    Notification,
    Setting,
    User,
    UserFactor,
)
from tests.conftest import ADMIN, make_key
from tests.test_signin import clock, code_now, enrol  # noqa: F401 - clock is a fixture

OLD = "dev-insecure-change-me"
NEW = "the new secret key of the server, long enough"
OLD_STORE = "dev-insecure-store-key-change-me"


@pytest.fixture(autouse=True)
def quick_keys(monkeypatch):
    monkeypatch.setattr(container, "SCRYPT_N", 2**10)


@pytest.fixture()
def server(admin: TestClient, tmp_path, monkeypatch):
    """A signed-in administrator on a server with a store and a backup directory of its own."""
    files = tmp_path / "store"
    files.mkdir()
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(files))
    monkeypatch.setattr(settings, "BACKUP_DIR", str(tmp_path / "backups"))
    (tmp_path / "backups").mkdir()
    monkeypatch.setenv("STORE_SEAL_MBPS", "0")
    return admin


def stored_secrets() -> int:
    """One secret in every place the database keeps one, under the key in use. Returns how many."""
    with SessionLocal() as db:
        admin_id = db.scalars(select(User.id)).first()
        db.add(
            IntegrationKey(id="k1", provider="virustotal", secret=vault.encrypt("vt-key"), hint="-key", updated_at="")
        )
        db.add(
            NetworkCapture(
                id="c" * 32, kind="pcap", file_name="a.pcap", size=1, sha256="", created_at="", created_by="",
                keylog=vault.encrypt("CLIENT_RANDOM 00 11"),
            )
        )  # fmt: skip
        db.add(
            Credential(
                id="d" * 32,
                name="proof",
                kind="secret",
                secret=vault.encrypt("a credential"),
                created_at="",
                updated_at="",
            )
        )
        db.add(
            UserFactor(
                id="f" * 32, user_id=admin_id, kind="totp", secret=vault.encrypt("JBSWY3DPEHPK3PXP"), created_at=""
            )
        )
        db.merge(Setting(id=2, doc={"smtp": {"host": "mail.example.test", "password": vault.encrypt("smtp-password")}}))
        db.commit()
        backup_config.set_passphrase(db, "the first passphrase")
        db.commit()
        backup_config.set_passphrase(db, "the second passphrase")
        db.commit()
        doc = backup_config.read(db)
        doc["destination"] = {"kind": "sftp", "host": "h", "secret": "vault:" + vault.encrypt("an ssh key")}
        backup_config._keep(db, doc)
        db.commit()
        return len(vault.inventory(db))


def change_secret_key(monkeypatch) -> None:
    monkeypatch.setattr(settings, "SECRET_KEY", NEW)
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [OLD])


def snapshot(name: str, secret: str = OLD) -> None:
    """A snapshot taken before an upgrade while no backup passphrase was set: under a key derived from SECRET_KEY."""
    about = {"kind": "upgrade", "name": name, "createdAt": "2026-11-01T00:00:00Z", "nik": "6.7.0"}
    path = runner.file_of(name)
    with open(path, "wb") as out:
        writer = container.Writer(out, container.Key.new(container.SECRET_KEY, secret), about)
        with writer.part("db/schema.json") as part:
            part.write(b'{"engine": "none"}')
        with writer.part("db/users.copy") as part:
            part.write(b"admin\tsecret-row\n" * 5000)
        writer.finish({**about, "label": "Before the upgrade from 6.6.1 to 6.7.0"})
    runner.write_note({**about, "size": path.stat().st_size, "keyFrom": "secret-key", "label": "Before the upgrade"})


def audit(action: str) -> list[AuditEntry]:
    with SessionLocal() as db:
        return list(db.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.at)))


def notices(kind: str) -> list[str]:
    with SessionLocal() as db:
        return [n.text for n in db.scalars(select(Notification).where(Notification.kind == kind))]


# --------------------------------------------------------------------------- #
# The screen                                                                  #
# --------------------------------------------------------------------------- #
def test_the_screen_lists_every_secret_and_never_a_value(server: TestClient, monkeypatch, tmp_path):
    token_file = tmp_path / "analyzer_token"
    token_file.write_text("a-token-kept-in-a-file-0123456789\n")
    monkeypatch.setenv("ANALYZER_TOKEN_FILE", str(token_file))
    monkeypatch.delenv("ANALYZER_TOKEN", raising=False)
    monkeypatch.setenv("SECRET_KEY", "a-secret-key-in-the-environment-0123456789")
    monkeypatch.setenv("DB_PASSWORD", "a-database-password-in-the-environment")
    monkeypatch.setattr(settings, "SECRET_KEY", "a-secret-key-in-the-environment-0123456789")
    key_rotation.note_seen()
    answer = server.get("/api/system/keys")
    assert answer.status_code == 200
    found = answer.json()
    by_name = {entry["name"]: entry for entry in found["keys"]}
    assert list(by_name) == [
        "SECRET_KEY", "STORE_KEY", "AUDIT_KEY", "DB_PASSWORD", "ANALYZER_TOKEN", "CAPA_TOKEN", "DOCVIEW_TOKEN",
        "BROWSER_TOKEN", "PCAP_TOKEN", "SANDBOX_TOKEN", "METRICS_TOKEN",
    ]  # fmt: skip
    assert by_name["SECRET_KEY"]["source"] == "environment" and by_name["ANALYZER_TOKEN"]["source"] == "file"
    assert by_name["STORE_KEY"]["source"] == "default" and by_name["METRICS_TOKEN"]["set"] is False
    assert found["inEnvironment"] == ["SECRET_KEY", "DB_PASSWORD", "SANDBOX_TOKEN"]
    assert found["moveCommand"] == "deploy/secrets.sh move"
    # Each container that holds a key is named, and three keys are changed with a procedure of Nik.
    assert by_name["STORE_KEY"]["holders"] == ["api"] and by_name["SECRET_KEY"]["holders"] == ["api", "automation"]
    assert [name for name, entry in by_name.items() if entry["rotates"]] == ["SECRET_KEY", "STORE_KEY", "AUDIT_KEY"]
    assert by_name["DB_PASSWORD"]["how"].startswith("Change it in PostgreSQL first")
    for name in ("SECRET_KEY", "STORE_KEY"):
        entry = by_name[name]
        assert len(entry["fingerprint"]) == 9 and entry["since"] and entry["rotatedAt"] == ""
        assert entry["rotation"] == {"state": "idle", "last": None} and entry["request"] is None
        assert entry["command"].startswith("deploy/secrets.sh rotate ")
    assert "fingerprint" not in by_name["DB_PASSWORD"]  # a password is not spoken of by a hash of it
    assert by_name["SECRET_KEY"]["fingerprint"] != by_name["STORE_KEY"]["fingerprint"]
    assert found["backupPassphrase"] == {"set": False, "setAt": "", "earlierKept": 0}
    assert found["store"]["state"] in ("starting", "sealed")

    # No value, no part of one, no id of a key: only fingerprints.
    text = answer.text
    for value in (
        "a-secret-key-in-the-environment-0123456789", "a-token-kept-in-a-file-0123456789", OLD_STORE,
        "a-database-password-in-the-environment", "test-sandbox-token",
    ):  # fmt: skip
        assert value not in text and value[:12] not in text and value[-12:] not in text
    assert store.keyring().current.id.hex() not in text and store.keyring().current.wrapping.hex() not in text
    assert vault.key_id(settings.SECRET_KEY).hex() not in text
    fingerprint = by_name["SECRET_KEY"]["fingerprint"].replace("-", "")
    assert fingerprint not in settings.SECRET_KEY and fingerprint not in vault.key_id(settings.SECRET_KEY).hex()


def test_only_an_administrator_reads_the_keys_and_only_a_signed_in_one_asks_for_a_change(server: TestClient):
    analyst = make_key(server, roles=["analyst"])
    admin_key = make_key(server, label="adm", roles=["admin"])
    anybody = TestClient(server.app)
    assert anybody.get("/api/system/keys").status_code == 401
    assert anybody.get("/api/system/keys", headers=analyst).status_code == 403
    assert anybody.get("/api/system/keys", headers=admin_key).status_code == 200
    assert anybody.get("/api/system/keys/SECRET_KEY/rotation", headers=admin_key).status_code == 200
    # An API key alone never asks for a key to be changed: a person does, and says who it is again.
    for method in ("post", "delete"):
        assert getattr(anybody, method)("/api/system/keys/SECRET_KEY/rotation", headers=admin_key).status_code == 401
    assert server.post("/api/system/keys/SECRET_KEY/rotation", json={}).status_code == 400
    wrong = server.post("/api/system/keys/SECRET_KEY/rotation", json={"password": "not the password"})
    assert wrong.status_code == 400 and wrong.json()["detail"] == "The current password is not correct"
    # Nothing was asked for, and a wrong password given here is counted like a failed sign-in.
    assert audit("key.rotate.request") == [] and len(audit("auth.failed")) >= 1
    for name in ("DB_PASSWORD", "ANALYZER_TOKEN", "nonsense"):
        assert server.get(f"/api/system/keys/{name}/rotation").status_code == 404
        assert server.post(f"/api/system/keys/{name}/rotation", json={"password": ADMIN["password"]}).status_code == 404


def test_an_account_with_a_second_factor_gives_a_code_to_ask_for_a_change(server: TestClient, clock):  # noqa: F811
    secret, _codes = enrol(server, clock)
    clock.advance(seconds=30)
    refused = server.post("/api/system/keys/STORE_KEY/rotation", json={"password": ADMIN["password"]})
    assert refused.status_code == 400 and audit("key.rotate.request") == []
    asked = server.post(
        "/api/system/keys/STORE_KEY/rotation", json={"password": ADMIN["password"], "code": code_now(secret, clock)}
    )
    assert asked.status_code == 200, asked.text
    assert asked.json()["command"] == "deploy/secrets.sh rotate store-key" and len(audit("key.rotate.request")) == 1


def test_asking_for_a_change_says_what_it_touches_and_what_to_run(server: TestClient, capsys):
    count = stored_secrets()
    snapshot("nik-upgrade-20261101-000000")
    plan = server.get("/api/system/keys/SECRET_KEY/rotation").json()
    assert plan["total"] == count + 1 and plan["restarts"] == ["api", "automation"]
    assert plan["command"] == "deploy/secrets.sh rotate secret-key"
    what = {item["what"]: item["count"] for item in plan["items"]}
    assert what == {
        "look-up key": 1, "TLS key log of a capture": 1, "credential": 1, "second factor of an account": 1,
        "SMTP password": 1, "backup passphrase": 1, "earlier backup passphrase": 1,
        "key of the backup destination": 1, "snapshot taken before an upgrade (written again, whole)": 1,
    }  # fmt: skip

    assert key_rotation.main(["requested", "SECRET_KEY"]) == 1
    asked = server.post("/api/system/keys/SECRET_KEY/rotation", json={"password": ADMIN["password"]})
    assert asked.status_code == 200
    body = asked.json()
    assert body["request"]["by"] == "admin" and body["total"] == count + 1 and body["command"] == plan["command"]
    said = audit("key.rotate.request")
    assert [(e.actor, e.target) for e in said] == [("admin", "SECRET_KEY")] and f"{count + 1} item(s)" in said[
        0
    ].details
    shown = {e["name"]: e for e in server.get("/api/system/keys").json()["keys"]}
    assert shown["SECRET_KEY"]["request"]["by"] == "admin" and shown["STORE_KEY"]["request"] is None
    # What the script on the host asks the running server.
    capsys.readouterr()
    assert key_rotation.main(["requested", "SECRET_KEY"]) == 0 and "asked for by admin" in capsys.readouterr().out
    assert key_rotation.main(["requested", "STORE_KEY"]) == 1
    assert key_rotation.main(["status", "SECRET_KEY"]) == 0 and capsys.readouterr().out.strip() == "idle"
    # A request is good for a day, and can be withdrawn.
    with SessionLocal() as db:
        assert key_rotation.requested(db, "SECRET_KEY", time.time() + key_rotation.REQUEST_LASTS + 60) is None
    assert server.delete("/api/system/keys/SECRET_KEY/rotation").json() == {"request": None}
    assert key_rotation.main(["requested", "SECRET_KEY"]) == 1 and len(audit("key.rotate.cancel")) == 1

    store.write(store.root() / "one.bin", b"1")
    store.write(store.root() / "two.bin", b"2")
    plan = server.get("/api/system/keys/STORE_KEY/rotation").json()
    assert plan["total"] == 2 and plan["restarts"] == ["api"] and "head" in plan["items"][0]["what"]


def test_a_new_key_is_made_by_the_server_and_goes_to_standard_output_alone(capsys):
    assert key_rotation.main(["new-key"]) == 0
    first = capsys.readouterr()
    assert key_rotation.main(["new-key"]) == 0
    second = capsys.readouterr()
    assert len(first.out.strip()) == 64 and first.out.strip() != second.out.strip() and first.err == ""
    int(first.out.strip(), 16)


# --------------------------------------------------------------------------- #
# Changing SECRET_KEY                                                         #
# --------------------------------------------------------------------------- #
def test_every_place_a_secret_is_stored_is_moved_and_read_back(server: TestClient, monkeypatch):
    count = stored_secrets()
    with SessionLocal() as db:
        assert all(vault.reads_alone(token) for _what, token in vault.inventory(db))
    change_secret_key(monkeypatch)
    with SessionLocal() as db:
        assert not any(vault.reads_alone(token) for _what, token in vault.inventory(db))
    # What reencrypt moves is exactly what the inventory lists: a place added to one is added to the other.
    assert vault.reencrypt(SessionLocal) == count
    with SessionLocal() as db:
        assert len(vault.inventory(db)) == count and all(
            vault.reads_alone(token) for _what, token in vault.inventory(db)
        )


def test_a_change_of_secret_key_is_followed_to_its_end_and_said(server: TestClient, monkeypatch, capsys):
    count = stored_secrets()
    snapshot("nik-upgrade-20261101-000000")
    with SessionLocal() as db:
        db.add(
            Backup(
                id="nik-upgrade-20261101-000000",
                kind="upgrade",
                state="done",
                created_at="2026-11-01T00:00:00Z",
                offsite_state="copied",
            )
        )
        db.commit()
    key_rotation.note_seen()
    before = server.get("/api/system/keys").json()["keys"][0]
    server.post("/api/system/keys/SECRET_KEY/rotation", json={"password": ADMIN["password"]})
    assert key_rotation.secret_pass() == {}  # no earlier key is held: nothing is in progress

    # The host wrote the new key and kept the old one beside it; the server restarted.
    change_secret_key(monkeypatch)
    shown = server.get("/api/system/keys").json()["keys"][0]
    assert shown["rotation"]["state"] == "running" and shown["rotation"]["previousKept"] == 1
    capsys.readouterr()
    assert key_rotation.main(["status", "SECRET_KEY"]) == 0
    assert capsys.readouterr().out == "running\nthe server has not counted yet\n"

    progress = key_rotation.secret_pass()
    assert progress["state"] == "verified" and progress["total"] == count and progress["done"] == count
    assert progress["moved"] == count and progress["snapshots"] == 1 and progress["unreadable"] == {}
    # Everything reads under the new key alone: the old one is no longer needed by the server.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        assert all(vault.decrypt(token) is not None for _what, token in vault.inventory(db))
        assert backup_config.passphrase(db) == "the second passphrase"
        assert vault.decrypt(db.get(Credential, "d" * 32).secret) == "a credential"
        row = db.get(Backup, "nik-upgrade-20261101-000000")
        # The snapshot was written again: its copy off the server, still under the old key, is sent again.
        assert row.offsite_state == "pending" and row.size == runner.file_of(row.id).stat().st_size
    path = runner.file_of("nik-upgrade-20261101-000000")
    manifest = container.walk(open(path, "rb"), container.Secrets(secret_keys=(NEW,)))  # noqa: SIM115
    assert [part["name"] for part in manifest["parts"]] == ["db/schema.json", "db/users.copy"]
    assert manifest["label"] == "Before the upgrade from 6.6.1 to 6.7.0" and container.peek(path)["kind"] == "upgrade"
    with pytest.raises(container.WrongKey):
        container.walk(open(path, "rb"), container.Secrets(secret_keys=(OLD,)))  # noqa: SIM115
    assert runner.read_note("nik-upgrade-20261101-000000")["size"] == path.stat().st_size
    assert not list(path.parent.glob("*" + key_rotation.REKEY))

    said = audit("key.rotate.done")
    assert len(said) == 1 and said[0].target == "SECRET_KEY" and f"the {count} secret(s)" in said[0].details
    assert (
        "read back with it alone" in said[0].details and "Keep it with the backups taken before now" in said[0].details
    )
    assert len(notices("keys.rotated")) == 1
    # The screen: nothing in progress, the key is another, and it says when it changed.
    after = server.get("/api/system/keys").json()["keys"][0]
    assert after["rotation"]["state"] == "idle" and after["rotation"]["last"]["state"] == "verified"
    assert after["fingerprint"] != before["fingerprint"] and after["rotatedAt"] and after["request"] is None
    assert key_rotation.main(["status", "SECRET_KEY"]) == 0 and capsys.readouterr().out.strip() == "idle"
    everything = json.dumps(server.get("/api/system/keys").json()) + said[0].details + notices("keys.rotated")[0]
    assert NEW not in everything and OLD not in everything
    # A pass more: nothing to do, nobody told again.
    assert key_rotation.secret_pass().get("state") == "verified" and len(audit("key.rotate.done")) == 1


def test_a_change_stopped_half_way_leaves_every_secret_readable_and_goes_on(server: TestClient, monkeypatch):
    count = stored_secrets()
    snapshot("nik-upgrade-20261101-000000")
    change_secret_key(monkeypatch)
    reencrypt = vault.reencrypt

    def dies(_session_factory):
        # Half of the secrets are moved in a transaction that never ends: the process is killed.
        with SessionLocal() as db:
            for row in db.scalars(select(IntegrationKey)):
                row.secret = vault._rotated(row.secret) or row.secret
            db.flush()
            raise KeyboardInterrupt

    monkeypatch.setattr(vault, "reencrypt", dies)
    with pytest.raises(KeyboardInterrupt):
        key_rotation.secret_pass()
    monkeypatch.setattr(vault, "reencrypt", reencrypt)
    # Nothing is half-moved, and the server (which holds both keys) reads everything.
    with SessionLocal() as db:
        assert all(vault.decrypt(token) is not None for _what, token in vault.inventory(db))
        assert not any(vault.reads_alone(token) for _what, token in vault.inventory(db))
    assert server.get("/api/system/keys").json()["keys"][0]["rotation"]["state"] == "running"

    # Killed again, this time while the snapshot is written again: the old file is whole, the new one
    # never took its place.
    replace = os.replace
    path = runner.file_of("nik-upgrade-20261101-000000")
    before = path.read_bytes()

    def killed(source, target):
        if str(source).endswith(key_rotation.REKEY):
            raise KeyboardInterrupt
        return replace(source, target)

    monkeypatch.setattr(key_rotation.os, "replace", killed)
    with pytest.raises(KeyboardInterrupt):
        key_rotation.secret_pass(holder="after the first restart", now=time.time() + 300)
    monkeypatch.setattr(key_rotation.os, "replace", replace)
    assert path.read_bytes() == before
    container.walk(open(path, "rb"), container.Secrets(secret_keys=(OLD,)))  # noqa: SIM115 - still under the old key, whole
    # The secrets of the database are under the new key by now; the change is not said to be over.
    with SessionLocal() as db:
        assert all(vault.reads_alone(token) for _what, token in vault.inventory(db))
    assert audit("key.rotate.done") == []
    assert server.get("/api/system/keys").json()["keys"][0]["rotation"]["state"] == "running"
    # What a process killed for good leaves beside the snapshot is written over by the next try.
    (path.parent / (path.name + key_rotation.REKEY)).write_bytes(b"half a file")

    progress = key_rotation.secret_pass(holder="after the second restart", now=time.time() + 600)
    assert progress["state"] == "verified" and progress["total"] == count and progress["snapshots"] == 1
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        assert all(vault.decrypt(token) is not None for _what, token in vault.inventory(db))
    container.walk(open(path, "rb"), container.Secrets(secret_keys=(NEW,)))  # noqa: SIM115
    assert not list(path.parent.glob("*" + key_rotation.REKEY))


def test_what_no_key_reads_was_lost_before_and_is_said_apart(server: TestClient, monkeypatch):
    stored_secrets()
    with SessionLocal() as db:
        # Encrypted under a key nobody kept, in a change done by hand long ago.
        monkeypatch.setattr(settings, "SECRET_KEY", "a key that was lost years ago")
        db.add(IntegrationKey(id="lost", provider="otx", secret=vault.encrypt("gone"), hint="gone", updated_at=""))
        db.commit()
    change_secret_key(monkeypatch)
    progress = key_rotation.secret_pass()
    # It does not keep the change open for ever: it was unreadable before, and is said so.
    assert progress["state"] == "verified" and progress["unreadable"] == {"look-up key": 1}
    assert "1 could be read by no key the server holds, as before the change" in audit("key.rotate.done")[0].details


def test_a_snapshot_under_the_current_key_or_under_the_passphrase_is_left_alone(server: TestClient, monkeypatch):
    snapshot("nik-upgrade-20261101-000000", secret=NEW)
    with SessionLocal() as db:
        backup_config.set_passphrase(db, "a passphrase for the tests")
        db.commit()
        key = runner.snapshot_key(db)
    assert key.spec["from"] == "passphrase"
    path = runner.file_of("nik-upgrade-20261102-000000")
    with open(path, "wb") as out:
        container.Writer(out, key, {"kind": "upgrade", "name": "nik-upgrade-20261102-000000"}).finish({})
    change_secret_key(monkeypatch)
    before = {p.name: p.read_bytes() for p in path.parent.glob("*.nikbak")}
    assert key_rotation._snapshots() == [runner.file_of("nik-upgrade-20261101-000000")]
    assert key_rotation.rekey_snapshot(runner.file_of("nik-upgrade-20261101-000000")) is False
    assert key_rotation.rekey_snapshot(path) is False
    assert {p.name: p.read_bytes() for p in path.parent.glob("*.nikbak")} == before
    # A file that is not a backup, or is damaged, among them does not stop the others.
    (path.parent / "nik-upgrade-20261103-000000.nikbak").write_bytes(b"not a backup")
    assert key_rotation._snapshots() == [runner.file_of("nik-upgrade-20261101-000000")]


def test_a_snapshot_that_cannot_be_read_keeps_the_change_open(server: TestClient, monkeypatch):
    stored_secrets()
    snapshot("nik-upgrade-20261101-000000")
    path = runner.file_of("nik-upgrade-20261101-000000")
    raw = bytearray(path.read_bytes())
    raw[-20] ^= 1
    path.write_bytes(bytes(raw))
    change_secret_key(monkeypatch)
    progress = key_rotation.secret_pass()
    assert progress["state"] == "failed" and progress["failed"][0]["name"] == path.name
    # Why is said in words of the server, by the kind of the error: never the text of the error.
    assert progress["failed"][0]["reason"].startswith("an error of the kind ")
    assert path.read_bytes() == bytes(raw)
    assert key_rotation.main(["status", "SECRET_KEY"]) == 0
    shown = server.get("/api/system/keys").json()["keys"][0]["rotation"]
    assert shown["state"] == "failed" and shown["failed"][0]["name"] == path.name
    # The secrets of the database were moved all the same, and read: only the file is in the way.
    assert progress["done"] == progress["total"]
    path.unlink()
    assert key_rotation.secret_pass()["state"] == "verified"


# --------------------------------------------------------------------------- #
# Changing the store key, on the screen                                       #
# --------------------------------------------------------------------------- #
def test_a_change_of_store_key_is_shown_from_its_start_to_its_end(server: TestClient, monkeypatch, capsys):
    for index in range(5):
        store.write(store.root() / f"{index}.bin", b"evidence %d" % index)
    store_seal.convert_pass()
    key_rotation.note_seen()
    before = server.get("/api/system/keys").json()["keys"][1]
    assert before["name"] == "STORE_KEY" and before["rotation"]["state"] == "idle"
    asked = server.post("/api/system/keys/STORE_KEY/rotation", json={"password": ADMIN["password"]})
    assert asked.status_code == 200, asked.text
    key_rotation.note_seen()  # nothing has changed yet: the request stays
    assert server.get("/api/system/keys").json()["keys"][1]["request"]["by"] == ADMIN["username"]

    monkeypatch.setattr(settings, "STORE_KEY", "the new store key, long enough to be one")
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [OLD_STORE])
    running = server.get("/api/system/keys").json()["keys"][1]
    assert running["rotation"]["state"] == "running" and running["fingerprint"] != before["fingerprint"]
    store_seal.rewrap_pass(budget=0)
    half = server.get("/api/system/keys").json()["keys"][1]["rotation"]
    assert half["state"] == "running" and half["total"] == 5 and half["done"] == 1
    capsys.readouterr()
    key_rotation.main(["status", "STORE_KEY"])
    assert capsys.readouterr().out.splitlines()[:2] == ["running", "1 of 5 under the new key"]
    for _ in range(20):
        if store_seal.rewrap_pass(budget=0).get("state") == "verified":
            break
    verified = server.get("/api/system/keys").json()["keys"][1]["rotation"]
    assert verified["state"] == "verified" and verified["done"] == verified["total"] == 5
    key_rotation.main(["status", "STORE_KEY"])
    assert capsys.readouterr().out.splitlines()[0] == "verified"
    # The host takes the earlier key away and the server restarts: nothing is in progress any more.
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [])
    key_rotation.note_seen()
    after = server.get("/api/system/keys").json()
    entry = after["keys"][1]
    assert (
        entry["rotation"]["state"] == "idle" and entry["rotatedAt"] and entry["fingerprint"] == running["fingerprint"]
    )
    assert after["store"]["keyFingerprint"] == entry["fingerprint"]
    # The request was used, and what is kept of the change names no identifier of a key.
    assert entry["request"] is None
    assert entry["rotation"]["last"]["state"] == "verified" and "to" not in entry["rotation"]["last"]
    assert all(store.read_bytes(store.root() / f"{index}.bin") == b"evidence %d" % index for index in range(5))


# --------------------------------------------------------------------------- #
# A server whose keys are in its environment                                  #
# --------------------------------------------------------------------------- #
def test_a_server_that_keeps_its_keys_in_the_environment_is_told_once(server: TestClient, monkeypatch):
    for name in ("SECRET_KEY", "STORE_KEY", "DB_PASSWORD"):
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    assert key_rotation.tell_environment() is False  # development: no key is given at all
    monkeypatch.setenv("SECRET_KEY", "a-secret-key-in-the-environment-0123456789")
    # A server nobody has an account on yet keeps it for when there is somebody to tell.
    with SessionLocal() as db:
        admin_row = db.scalars(select(User)).one()
        admin_row.disabled = True
        db.commit()
    assert key_rotation.tell_environment() is False and notices("keys.environment") == []
    with SessionLocal() as db:
        db.scalars(select(User)).one().disabled = False
        db.commit()
    assert key_rotation.tell_environment() is True
    assert key_rotation.tell_environment() is False
    told = notices("keys.environment")
    assert len(told) == 1 and "deploy/secrets.sh move" in told[0] and "Nothing changes until you run it" in told[0]
    with SessionLocal() as db:
        assert (
            db.scalars(select(Notification.link).where(Notification.kind == "keys.environment")).one()
            == "/settings/system/keys"
        )


def test_a_server_whose_keys_are_in_files_is_told_nothing(server: TestClient, monkeypatch, tmp_path):
    for name in ("SECRET_KEY", "STORE_KEY", "DB_PASSWORD"):
        path = tmp_path / name.lower()
        path.write_text("k" * 40 + "\n")
        monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv(f"{name}_FILE", str(path))
    assert [keys.source(name) for name in ("SECRET_KEY", "STORE_KEY", "DB_PASSWORD")] == ["file"] * 3
    assert key_rotation.tell_environment() is False and notices("keys.environment") == []


def test_what_a_health_page_can_show(server: TestClient):
    store.write(store.root() / "a.bin", b"evidence")
    store_seal.convert_pass()
    with SessionLocal() as db:
        shown = key_rotation.health(db)
    assert shown == {
        "storeEncrypted": True,
        "storeState": "sealed",
        "storeLeft": {"files": 0, "bytes": 0},
        "storeStuck": 0,
        "damagedFiles": 0,
        "keysInEnvironment": shown["keysInEnvironment"],
        "rotations": {"SECRET_KEY": "idle", "STORE_KEY": "idle", "AUDIT_KEY": "idle"},
        "backupPassphraseSet": False,
    }
    assert io.StringIO(json.dumps(shown)).read()  # plain values: it goes into an answer as it is


def test_the_two_facts_a_health_page_asks_for(server: TestClient):
    with SessionLocal() as db:
        before = key_rotation.store_encryption(db)
    assert before["state"] == "starting" and before["clearRemains"] is True  # nothing was walked yet
    (store.root() / "old.bin").write_bytes(b"from before 6.8")
    with SessionLocal() as db:
        store_seal._update(state=store_seal.CONVERTING, total={"files": 1, "bytes": 15})
        during = key_rotation.store_encryption(db)
    assert during["clearRemains"] is True and during["left"] == {"files": 1, "bytes": 15}
    for _ in range(5):
        if store_seal.convert_pass().get("state") == store_seal.SEALED:
            break
    key_rotation.note_seen()
    with SessionLocal() as db:
        after = key_rotation.store_encryption(db)
        held = key_rotation.keys_state(db)
    assert after["state"] == "sealed" and after["clearRemains"] is False and after["sealedSince"]
    assert after["left"] == {"files": 0, "bytes": 0} and after["stuck"] == 0 and after["damaged"] == 0
    assert [entry["name"] for entry in held][:4] == ["SECRET_KEY", "STORE_KEY", "AUDIT_KEY", "DB_PASSWORD"]
    assert all(entry["source"] in ("file", "environment", "default") for entry in held)
    assert held[0]["since"] and held[0]["rotation"] == "idle" and held[3]["rotation"] is None
    assert held[2]["rotation"] == "idle" and held[2]["since"]  # the audit key: dated, never half-way
    assert not any("fingerprint" in entry for entry in held)
    assert json.dumps([after, held])  # plain values


# --------------------------------------------------------------------------- #
# The key that signs the audit log                                            #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def derived_audit_key(monkeypatch):
    """A server that was given no audit key: the one derived from SECRET_KEY signs."""
    for name in ("AUDIT_KEY", "AUDIT_KEY_FILE", "AUDIT_KEY_PREVIOUS", "AUDIT_KEY_PREVIOUS_FILE"):
        monkeypatch.delenv(name, raising=False)


def write_entries(count: int, action: str = "test.note") -> None:
    from app.core import audit as audit_log

    with SessionLocal() as db:
        for index in range(count):
            audit_log.record(db, "anna", action, f"entry {index}")
        db.commit()


def audit_key_on_screen(server: TestClient) -> dict:
    return {entry["name"]: entry for entry in server.get("/api/system/keys").json()["keys"]}["AUDIT_KEY"]


def test_the_audit_key_is_shown_with_what_each_key_signed(server: TestClient, derived_audit_key, monkeypatch):
    from app.auditlog import key as signing

    write_entries(3)
    key_rotation.note_seen()
    shown = audit_key_on_screen(server)
    assert shown["holders"] == ["api", "automation"] and shown["rotates"] is True
    assert shown["source"] == "default" and shown["set"] is False and shown["derived"] is True
    assert shown["fingerprint"] == signing.current()[0] and shown["fingerprint"].startswith("derived-")
    assert shown["rotation"] == {"state": "idle", "previousKept": 0, "last": None} and shown["since"]
    assert shown["command"] == "deploy/secrets.sh rotate audit-key"
    signed = shown["signed"]
    assert signed["cannotBeChecked"] == 0 and signed["unsigned"] == 0
    assert [(entry["keyId"], entry["current"], entry["known"]) for entry in signed["byKey"]] == [
        (shown["fingerprint"], True, True)
    ]
    assert signed["byKey"][0]["entries"] >= 3

    # The log is given a key of its own: it signs from the next entry, and the derived key is still made.
    monkeypatch.setenv("AUDIT_KEY", "a key of its own for the audit log 0123456789")
    write_entries(2)
    now = audit_key_on_screen(server)
    assert now["source"] == "environment" and now["derived"] is False and now["fingerprint"].startswith("set-")
    by_key = {entry["keyId"]: entry for entry in now["signed"]["byKey"]}
    assert by_key[now["fingerprint"]]["current"] is True and by_key[now["fingerprint"]]["entries"] >= 2
    assert by_key[shown["fingerprint"]] == {**by_key[shown["fingerprint"]], "current": False, "known": True}
    assert now["signed"]["cannotBeChecked"] == 0
    # No key and no part of one is on the screen: an id is twelve digits of a hash of the key.
    text = json.dumps(now)
    assert "a key of its own" not in text and signing.current()[1].hex() not in text

    # The key is changed again and the one before it is not kept: what it signed cannot be checked, and is counted.
    monkeypatch.setenv("AUDIT_KEY", "another key for the audit log 9876543210")
    lost = audit_key_on_screen(server)
    assert lost["signed"]["cannotBeChecked"] == by_key[now["fingerprint"]]["entries"]
    assert [entry["known"] for entry in lost["signed"]["byKey"] if entry["keyId"] == now["fingerprint"]] == [False]
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", "something else,a key of its own for the audit log 0123456789")
    kept = audit_key_on_screen(server)
    assert kept["signed"]["cannotBeChecked"] == 0 and kept["rotation"]["previousKept"] == 2


def test_a_change_of_the_audit_key_is_asked_for_and_said_once_it_happened(
    server: TestClient, derived_audit_key, monkeypatch, capsys
):
    write_entries(2)
    key_rotation.note_seen()
    before = audit_key_on_screen(server)
    assert key_rotation.main(["requested", "AUDIT_KEY"]) == 1
    plan = server.get("/api/system/keys/AUDIT_KEY/rotation").json()
    assert plan["command"] == "deploy/secrets.sh rotate audit-key" and plan["restarts"] == ["api", "automation"]
    assert plan["total"] == 0 and "keeps the key that signed it" in plan["items"][0]["what"]
    assert plan["items"][0]["count"] >= 2
    assert server.post("/api/system/keys/AUDIT_KEY/rotation", json={"password": "wrong"}).status_code in (400, 401, 403)
    asked = server.post("/api/system/keys/AUDIT_KEY/rotation", json={"password": ADMIN["password"]})
    assert asked.status_code == 200 and asked.json()["request"]["by"] == ADMIN["username"]
    capsys.readouterr()
    assert key_rotation.main(["requested", "AUDIT_KEY"]) == 0 and "asked for by admin" in capsys.readouterr().out
    key_rotation.note_seen()  # nothing changed yet: the request stays
    assert audit_key_on_screen(server)["request"]["by"] == ADMIN["username"]
    assert [entry.target for entry in audit("key.rotate.request")] == ["AUDIT_KEY"]
    assert "a new key signs the audit log from the next entry on" in audit("key.rotate.request")[0].details

    # The host wrote a new key and both processes restarted with it.
    monkeypatch.setenv("AUDIT_KEY", "the key the script wrote, 0123456789abcdef")
    key_rotation.note_seen()
    after = audit_key_on_screen(server)
    assert after["request"] is None and after["rotatedAt"] and after["fingerprint"] != before["fingerprint"]
    said = [entry for entry in audit("key.rotate.done") if entry.target == "AUDIT_KEY"]
    assert len(said) == 1 and after["fingerprint"] in said[0].details and before["fingerprint"] in said[0].details
    # The entry that says so is itself signed with the new key, and nothing lost its key.
    assert said[0].key_id == after["fingerprint"] and after["signed"]["cannotBeChecked"] == 0
    assert len(notices("keys.rotated")) == 1
    key_rotation.note_seen()
    assert len([entry for entry in audit("key.rotate.done") if entry.target == "AUDIT_KEY"]) == 1
    # A request for this key is withdrawn like the others.
    server.post("/api/system/keys/AUDIT_KEY/rotation", json={"password": ADMIN["password"]})
    assert server.delete("/api/system/keys/AUDIT_KEY/rotation").json() == {"request": None}
    assert server.get("/api/system/keys/DB_PASSWORD/rotation").status_code == 404


def test_the_end_of_a_change_of_secret_key_does_not_cost_the_audit_log_its_key(
    server: TestClient, derived_audit_key, monkeypatch, capsys
):
    """On a server that signs with the derived key, every entry written before a change of SECRET_KEY
    was signed with a key made from the earlier one. Taking that earlier key away would turn them all
    into entries that cannot be checked: the derived key is carried into AUDIT_KEY_PREVIOUS first."""
    from app.auditlog import key as signing
    from app.auditlog import verifier

    monkeypatch.setattr(settings, "SECRET_KEY", OLD)
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    write_entries(4)
    old_id = signing.current()[0]
    with SessionLocal() as db:
        assert key_rotation.audit_keys_to_carry(db) == []  # no earlier key is held: nothing leaves
        assert key_rotation.plan(db, "SECRET_KEY")["auditKeyDerived"] is True
    change_secret_key(monkeypatch)
    write_entries(2)
    assert signing.current()[0] != old_id and signing.current()[0].startswith("derived-")
    with SessionLocal() as db:
        # While both keys are held everything is checked.
        assert key_rotation.audit_signed(db)["cannotBeChecked"] == 0
        carry = key_rotation.audit_keys_to_carry(db)
    assert carry == ["hex:" + signing.derived(OLD).hex()]
    capsys.readouterr()
    assert key_rotation.main(["audit-carry"]) == 0
    printed = capsys.readouterr()
    assert printed.out == carry[0] + "\n" and printed.err == ""  # the key, on standard output alone

    # What would happen without it: the earlier SECRET_KEY goes, and its entries lose their key.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        lost = key_rotation.audit_signed(db)
    assert lost["cannotBeChecked"] >= 4
    assert [entry["known"] for entry in lost["byKey"] if entry["keyId"] == old_id] == [False]
    assert key_rotation.main(["audit-unchecked"]) == 0 and int(capsys.readouterr().out) == lost["cannotBeChecked"]

    # What the script does: the derived key is written beside the audit keys, then the earlier key goes.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [OLD])
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", carry[0])
    with SessionLocal() as db:
        assert key_rotation.audit_keys_to_carry(db) == []  # carried already: a second run adds nothing
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        kept = key_rotation.audit_signed(db)
    assert kept["cannotBeChecked"] == 0 and all(entry["known"] for entry in kept["byKey"])
    assert key_rotation.main(["audit-unchecked"]) == 0 and capsys.readouterr().out.strip() == "0"
    # And the chain itself agrees: a full walk finds no entry it cannot check.
    from app.auditlog import chain

    with SessionLocal() as db:
        state = chain.verify(db, full=True)
        db.commit()
    assert not state.get("problem") and not (state.get("unchecked") or {})
    assert verifier.fingerprint(signing.derived(OLD)) in signing.known()


@pytest.fixture()
def own_audit_key(monkeypatch):
    """A server that had an audit key of its own from its first entry (asked for before the server)."""
    monkeypatch.setenv("AUDIT_KEY", "a key of its own for the audit log 0123456789")
    monkeypatch.delenv("AUDIT_KEY_PREVIOUS", raising=False)


def test_a_server_with_an_audit_key_of_its_own_carries_nothing_at_a_change_of_secret_key(
    own_audit_key, server: TestClient, monkeypatch
):
    monkeypatch.setattr(settings, "SECRET_KEY", OLD)
    write_entries(3)
    change_secret_key(monkeypatch)
    with SessionLocal() as db:
        assert key_rotation.audit_keys_to_carry(db) == []
        assert key_rotation.plan(db, "SECRET_KEY")["auditKeyDerived"] is False
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        assert key_rotation.audit_signed(db)["cannotBeChecked"] == 0


def test_the_key_of_the_forwarding_certificate_is_moved_by_the_same_change(server: TestClient, monkeypatch):
    """The audit log is forwarded with a client certificate whose key is kept under SECRET_KEY, in the
    settings and in the settings in force (two rows). One list says every place, one pass moves them."""
    from app.auditlog import forward

    monkeypatch.setattr(settings, "SECRET_KEY", OLD)
    with SessionLocal() as db:
        kept = "vault:" + vault.encrypt("-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n")
        db.merge(Setting(id=forward.SETTINGS_ID, doc={"version": 3, "settings": {"host": "siem", "clientKey": kept}}))
        db.merge(
            Setting(id=forward.STATE_ID, doc={"version": 3, "sentHead": {"seq": 7}, "active": {"clientKey": kept}})
        )
        db.commit()
        listed = [what for what, _token in vault.inventory(db)]
    assert listed.count("key of the certificate the audit log is forwarded with") == 2
    assert tuple(row for row, _part in vault.FORWARDING_ROWS) == (forward.SETTINGS_ID, forward.STATE_ID)
    change_secret_key(monkeypatch)
    progress = key_rotation.secret_pass()
    assert progress["state"] == "verified" and progress["moved"] == 2 and progress["done"] == progress["total"] == 2
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        assert all(vault.reads_alone(token) for _what, token in vault.inventory(db))
        assert forward.client_key(db, forward.read(db)).startswith("-----BEGIN PRIVATE KEY-----")
        state = db.get(Setting, forward.STATE_ID).doc
        # Nothing else of the row the sender writes was touched.
        assert state["sentHead"] == {"seq": 7} and state["version"] == 3
        assert forward.client_key(db, forward._active(state)).startswith("-----BEGIN PRIVATE KEY-----")
    # A key named by a credential is not a stored secret of the forwarding: nothing to list.
    with SessionLocal() as db:
        db.merge(Setting(id=forward.SETTINGS_ID, doc={"settings": {"clientKey": "{{ credentials.syslog_key }}"}}))
        db.merge(Setting(id=forward.STATE_ID, doc={"active": None}))
        db.commit()
        assert "key of the certificate the audit log is forwarded with" not in [w for w, _t in vault.inventory(db)]


# --------------------------------------------------------------------------- #
# What the command line prints, and where it refuses to                       #
# --------------------------------------------------------------------------- #
class Terminal(io.StringIO):
    """Standard output when a person runs the command by hand."""

    def isatty(self) -> bool:
        return True


def test_the_status_printed_is_made_of_fixed_words_numbers_and_names():
    assert key_rotation.status_lines({"state": "idle", "total": 5, "done": 5}) == ["idle"]
    assert key_rotation.status_lines({"state": "running"}) == ["running", "the server has not counted yet"]
    assert key_rotation.status_lines({"state": "verified", "total": 7, "done": 7}) == [
        "verified",
        "7 of 7 under the new key",
    ]
    # A state that is not one of the four words is never printed as it is.
    assert key_rotation.status_lines({"state": "hex:00ff a key that was put there"}) == ["idle"]
    lines = key_rotation.status_lines(
        {
            "state": "failed",
            "total": 3,
            "done": 2,
            "failed": [
                {"name": "nik-upgrade-20261101-000000.nikbak", "reason": "an error of the kind WrongKey"},
                {"name": "aa/bb.bin\x1b[31m; rm -rf $HOME", "reason": "the system refused to read or write it (EIO)"},
            ],
        }
    )
    assert lines == [
        "failed",
        "2 of 3 under the new key",
        "failed: nik-upgrade-20261101-000000.nikbak: an error of the kind WrongKey",
        "failed: aa/bb.bin31mrm-rfHOME: the system refused to read or write it (EIO)",
    ]


def test_why_something_failed_is_said_in_words_of_the_server_never_in_those_of_the_error():
    from app.core import sealed

    said = "the text of an error, which may hold anything: hunter2"
    assert store_seal.why(sealed.WrongKey(said)) == "no key the server holds opens it"
    assert store_seal.why(sealed.Damaged(said)) == "it is damaged: it fails its check"
    assert store_seal.why(OSError(5, said)) == "the system refused to read or write it (EIO)"
    assert store_seal.why(OSError(said)) == "the system refused to read or write it"
    assert store_seal.why(ValueError(said)) == "an error of the kind ValueError"
    assert store_seal.why(store.DamagedFile(said)) == "it is damaged: it fails its check"


def test_a_command_that_writes_a_key_refuses_a_terminal(server: TestClient, derived_audit_key, monkeypatch, capsys):
    """new-key, audit-carry and ``auditlog key --derived`` write a key on standard output for a pipe.
    Run by hand in a terminal they write nothing and say where a key goes."""
    import sys

    from app.auditlog import __main__ as audit_command
    from app.auditlog import key as signing

    monkeypatch.setattr(settings, "SECRET_KEY", OLD)
    write_entries(2)
    change_secret_key(monkeypatch)  # an earlier derived key signed entries: there is one to carry
    for run, argv in (
        (key_rotation.main, ["new-key"]),
        (key_rotation.main, ["audit-carry"]),
        (audit_command.main, ["key", "--derived"]),
    ):
        screen = Terminal()
        monkeypatch.setattr(sys, "stdout", screen)
        assert run(argv) == 2, argv
        assert screen.getvalue() == "", argv
    monkeypatch.setattr(sys, "stdout", sys.__stdout__)
    said = capsys.readouterr().err
    assert said.count("is a secret and is not written to a terminal") == 3
    assert signing.derived(OLD).hex() not in said and signing.derived(NEW).hex() not in said
    # Into a pipe or a file they write, as before.
    pipe = io.StringIO()
    monkeypatch.setattr(sys, "stdout", pipe)
    assert key_rotation.main(["new-key"]) == 0 and key_rotation.main(["audit-carry"]) == 0
    assert audit_command.main(["key", "--derived"]) == 0
    monkeypatch.setattr(sys, "stdout", sys.__stdout__)
    written = pipe.getvalue().splitlines()
    assert len(written) == 3 and len(written[0]) == 64
    assert written[1] == "hex:" + signing.derived(OLD).hex() and written[2] == "hex:" + signing.derived(NEW).hex()
    # The commands that print no key are not concerned: a person reads them in a terminal.
    monkeypatch.setattr(sys, "stdout", Terminal())
    assert key_rotation.main(["status", "SECRET_KEY"]) == 0 and key_rotation.main(["audit-unchecked"]) == 0
    assert audit_command.main(["key"]) == 0
    monkeypatch.setattr(sys, "stdout", sys.__stdout__)
