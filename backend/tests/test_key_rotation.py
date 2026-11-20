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
        "SECRET_KEY", "STORE_KEY", "DB_PASSWORD", "ANALYZER_TOKEN", "CAPA_TOKEN", "DOCVIEW_TOKEN", "BROWSER_TOKEN",
        "PCAP_TOKEN", "SANDBOX_TOKEN", "METRICS_TOKEN",
    ]  # fmt: skip
    assert by_name["SECRET_KEY"]["source"] == "environment" and by_name["ANALYZER_TOKEN"]["source"] == "file"
    assert by_name["STORE_KEY"]["source"] == "default" and by_name["METRICS_TOKEN"]["set"] is False
    assert found["inEnvironment"] == ["SECRET_KEY", "DB_PASSWORD", "SANDBOX_TOKEN"]
    assert found["moveCommand"] == "deploy/secrets.sh move"
    # Each container that holds a key is named, and only the two keys that encrypt are changed by Nik.
    assert by_name["STORE_KEY"]["holders"] == ["api"] and by_name["SECRET_KEY"]["holders"] == ["api", "automation"]
    assert [name for name, entry in by_name.items() if entry["rotates"]] == ["SECRET_KEY", "STORE_KEY"]
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
    assert path.read_bytes() == bytes(raw)
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
        "rotations": {"SECRET_KEY": "idle", "STORE_KEY": "idle"},
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
    assert [entry["name"] for entry in held][:3] == ["SECRET_KEY", "STORE_KEY", "DB_PASSWORD"]
    assert all(entry["source"] in ("file", "environment", "default") for entry in held)
    assert held[0]["since"] and held[0]["rotation"] == "idle" and held[2]["rotation"] is None
    assert not any("fingerprint" in entry for entry in held)
    assert json.dumps([after, held])  # plain values
