"""The signed audit log beside the backups and the keys of the server: what a backup says of the log
it holds, the keys of the log that travel with it, the file of heads in the backup directory, and a
restore on a host that has keys of its own."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import Session as OrmSession

from app import key_rotation
from app.auditlog import __main__ as audit_command
from app.auditlog import chain
from app.auditlog import key as signing
from app.backups import container, restore, runner
from app.core import audit
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AuditEntry
from tests.test_backups import PHRASE, T0, backups, quick_keys, set_phrase  # noqa: F401 - fixtures
from tests.test_store_backups import another_host  # noqa: F401 - a fixture

OLD_HOST_KEY = "the audit key of the host the backup was taken on 0123456789"
NEW_HOST_KEY = "the audit key init-env made on the host that restores 9876543210"


def note(count: int = 1) -> None:
    with SessionLocal() as db:
        for index in range(count):
            audit.record(db, "anna", "test.note", f"entry {index}")
        db.commit()


def parts_of(name: str) -> dict[str, bytes]:
    found: dict[str, bytes] = {}
    with open(runner.file_of(name), "rb") as source:
        manifest = container.walk(
            source, container.Secrets(passphrases=(PHRASE,)), lambda part: found.__setitem__(part.name, part.read())
        )
    found["manifest"] = json.dumps(manifest).encode()
    return found


# --------------------------------------------------------------------------- #
# What a backup says of the audit log it holds                                #
# --------------------------------------------------------------------------- #
def test_a_backup_says_where_its_audit_log_ends_and_the_note_carries_it(backups, monkeypatch, capsys):  # noqa: F811
    set_phrase(backups)
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", PHRASE)
    note(3)
    name = runner.take(now=T0)
    manifest = json.loads(parts_of(name)["manifest"])
    head = manifest["auditHead"]
    with SessionLocal() as db:
        entry = db.scalars(sa.select(AuditEntry).where(AuditEntry.seq == head["seq"])).one()
        latest = chain.head(db)[0]
    # The head the backup names is an entry of the log, with its hash and the id of the key that signed it.
    assert head == {"seq": entry.seq, "hash": entry.hash, "keyId": entry.key_id} and head["seq"] >= 3
    assert head["keyId"] == signing.current()[0] and len(head["hash"]) == 64
    # It is in the note beside the file, in clear: what is sent off the server with the backup.
    assert runner.read_note(name)["auditHead"] == head
    assert signing.current()[1].hex() not in json.dumps(runner.read_note(name))
    # The log went on meanwhile (the backup itself is recorded), and still holds that head.
    assert latest > head["seq"]
    capsys.readouterr()
    assert audit_command.main(["verify-audit", "--full", "--head", f"{head['seq']}:{head['hash']}"]) == 0
    assert "The chain holds" in capsys.readouterr().out
    # A head that is not of this log is refused.
    assert audit_command.main(["verify-audit", "--head", f"{head['seq']}:{'0' * 64}"]) == 1
    capsys.readouterr()
    # The operator reads it from the file without restoring anything.
    assert restore.main(["inspect", name]) == 0
    said = capsys.readouterr().err
    assert f"audit log  ends at entry {head['seq']}:{head['hash']} (signed with the key {head['keyId']})" in said
    assert "AUDIT_KEY  not included" in said


def test_the_keys_of_the_audit_log_travel_with_secret_key_and_only_then(backups, monkeypatch, capsys):  # noqa: F811
    set_phrase(backups)
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", PHRASE)
    monkeypatch.setenv("AUDIT_KEY", OLD_HOST_KEY)
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", "an earlier key of that host,hex:00112233445566778899aabbccddeeff")
    note(2)
    without = runner.take(now=T0)
    held = parts_of(without)
    assert "audit-keys" not in held and "secret-key" not in held
    everything = b"".join(held.values())
    assert OLD_HOST_KEY.encode() not in everything and b"an earlier key of that host" not in everything
    assert json.loads(held["manifest"])["includesAuditKeys"] == 0
    assert any("the keys of the audit log" in line for line in json.loads(held["manifest"])["notIncluded"])
    capsys.readouterr()
    assert restore.main(["audit-keys", without]) == 0 and capsys.readouterr().out == ""

    assert backups.put("/api/backups/settings", json={"includeKey": True}).status_code == 200
    name = runner.take(now=T0 + 3600)
    held = parts_of(name)
    assert held["secret-key"] == settings.SECRET_KEY.encode()
    assert held["audit-keys"].decode().splitlines() == [
        OLD_HOST_KEY,
        "an earlier key of that host",
        "hex:00112233445566778899aabbccddeeff",
    ]
    manifest = json.loads(held["manifest"])
    assert manifest["includesAuditKeys"] == 3 and manifest["includesSecretKey"] is True
    # In the note, which is in clear, there is the id of a key and never a key.
    text = json.dumps(runner.read_note(name))
    assert OLD_HOST_KEY not in text and "earlier key" not in text
    capsys.readouterr()
    assert restore.main(["audit-keys", name]) == 0
    printed = capsys.readouterr()
    assert printed.out.splitlines() == [
        f"AUDIT_KEY_PREVIOUS={OLD_HOST_KEY}",
        "AUDIT_KEY_PREVIOUS=an earlier key of that host",
        "AUDIT_KEY_PREVIOUS=hex:00112233445566778899aabbccddeeff",
    ]
    assert restore.main(["inspect", name]) == 0
    assert "AUDIT_KEY  3 key(s) of the audit log included" in capsys.readouterr().err


def test_a_server_that_signs_with_the_derived_key_has_no_other_key_to_carry(backups, monkeypatch, capsys):  # noqa: F811
    for variable in ("AUDIT_KEY", "AUDIT_KEY_PREVIOUS"):
        monkeypatch.delenv(variable, raising=False)
    set_phrase(backups)
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", PHRASE)
    assert backups.put("/api/backups/settings", json={"includeKey": True}).status_code == 200
    name = runner.take(now=T0)
    held = parts_of(name)
    # Whoever has the SECRET_KEY of the backup makes the derived key again: nothing more is needed.
    assert "secret-key" in held and "audit-keys" not in held
    assert restore.main(["inspect", name]) == 0
    assert "AUDIT_KEY  none to include: the log was signed with the key derived from SECRET_KEY" in (
        capsys.readouterr().err
    )
    # While a change of SECRET_KEY is half-way, the key derived from the earlier one travels too.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", ["the secret key before this one, long enough"])
    again = runner.take(now=T0 + 3600)
    assert parts_of(again)["audit-keys"].decode() == "hex:" + signing.derived(settings.SECRET_KEY_PREVIOUS[0]).hex()


# --------------------------------------------------------------------------- #
# The file of heads lives in the backup directory                             #
# --------------------------------------------------------------------------- #
def test_the_file_of_heads_is_not_a_backup_and_nothing_of_the_backups_removes_it(backups):  # noqa: F811
    set_phrase(backups)
    note(2)
    Path(settings.BACKUP_DIR).mkdir(parents=True, exist_ok=True)
    with SessionLocal() as db:
        state = chain.verify(db)
        db.commit()
    assert not state.get("problem")
    heads = Path(settings.BACKUP_DIR) / chain.HEADS_FILE
    assert heads.is_file() and chain.file_head() is not None
    before = heads.read_bytes()
    names = [runner.take(now=T0 + index * 86400) for index in range(3)]
    with SessionLocal() as db:
        runner.sync(db, T0 + 3 * 86400)
        db.commit()
        # Far later, with a retention that keeps one backup: files are removed, never this one.
        from app.backups import config

        kept = config.read(db)
        config._keep(db, {**kept, "retention": {"last": 1, "weeks": 0, "upgrades": 0}})
        db.commit()
        removed = runner.apply_retention(db, T0 + 400 * 86400)
        db.commit()
    assert removed and not runner.file_of(names[0]).exists()
    assert heads.read_bytes().startswith(before)
    listed = [entry["name"] for entry in restore.listing(Path(settings.BACKUP_DIR))]
    assert listed and all(name.startswith("nik-") for name in listed)
    assert runner.clear_partials() == 0 and heads.is_file()
    with SessionLocal() as db:
        from app.core.models import Backup

        assert all(row.id.startswith("nik-") for row in db.scalars(sa.select(Backup)))
    # And the changes of SECRET_KEY, which rewrite snapshots of the directory, do not take it for one.
    assert heads not in key_rotation._snapshots()


# --------------------------------------------------------------------------- #
# A restore on a host with keys of its own                                    #
# --------------------------------------------------------------------------- #
def signed_in(url) -> dict:
    engine = sa.create_engine(url)
    try:
        with OrmSession(engine) as db:
            return key_rotation.audit_signed(db)
    finally:
        engine.dispose()


@pytest.fixture()
def old_host_key(monkeypatch):
    """The host the backup is taken on signs its log with a key of its own."""
    monkeypatch.setenv("AUDIT_KEY", OLD_HOST_KEY)
    monkeypatch.delenv("AUDIT_KEY_PREVIOUS", raising=False)


def test_a_restored_log_is_checked_with_the_keys_that_came_with_the_backup(
    old_host_key,
    another_host,  # noqa: F811
    backups,  # noqa: F811
    monkeypatch,
    capsys,
):
    path, _held, _target, scratch = another_host
    # The host that restores was made by init-env.sh: it has an audit key of its own.
    monkeypatch.setenv("AUDIT_KEY", NEW_HOST_KEY)
    assert restore.main(["restore", str(path)]) == 0
    said = capsys.readouterr().err
    assert "was signed with the keys of the server the backup was taken on" in said
    assert "AUDIT_KEY_PREVIOUS" in said and "never as tampered with" in said

    # The log that came back holds the entry of the restore, written without a session of the server.
    engine = sa.create_engine(scratch.url)
    try:
        with engine.connect() as conn:
            rows = conn.execute(
                sa.text("SELECT actor, seq, target FROM audit_log WHERE action = 'audit.restore'")
            ).all()
    finally:
        engine.dispose()
    assert len(rows) == 1 and rows[0][0] == "server console" and rows[0][1] is None
    assert rows[0][2] == path.name[: -len(".nikbak")]

    # Without the key of the old host its entries cannot be checked here, and are counted as such…
    lost = signed_in(scratch.url)
    old_id = [entry for entry in lost["byKey"] if not entry["known"]]
    assert lost["cannotBeChecked"] > 0 and len(old_id) == 1 and old_id[0]["keyId"].startswith("set-")
    # …and with it, brought into the earlier keys of this host, every one of them is.
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", OLD_HOST_KEY)
    kept = signed_in(scratch.url)
    assert kept["cannotBeChecked"] == 0 and all(entry["known"] for entry in kept["byKey"])


def test_restore_with_the_key_brings_the_keys_of_the_log_from_the_backup(
    old_host_key,
    backups,  # noqa: F811
    monkeypatch,
    capsys,
):
    """What ``deploy/restore.sh --secret-key`` reads from a backup taken with the key included."""
    set_phrase(backups)
    assert backups.put("/api/backups/settings", json={"includeKey": True}).status_code == 200
    note(2)
    name = runner.take(now=T0)
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", PHRASE)
    monkeypatch.setenv("AUDIT_KEY", NEW_HOST_KEY)
    with SessionLocal() as db:
        assert key_rotation.audit_signed(db)["cannotBeChecked"] > 0
    capsys.readouterr()
    assert restore.main(["audit-keys", name]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines == [f"AUDIT_KEY_PREVIOUS={OLD_HOST_KEY}"]
    monkeypatch.setenv("AUDIT_KEY_PREVIOUS", ",".join(line.split("=", 1)[1] for line in lines))
    with SessionLocal() as db:
        assert key_rotation.audit_signed(db)["cannotBeChecked"] == 0
    # A wrong passphrase gives no key.
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", "not the passphrase")
    assert restore.main(["audit-keys", name]) == 1 and capsys.readouterr().out == ""


# --------------------------------------------------------------------------- #
# What the encryption of the store and the changes of keys write in the log   #
# --------------------------------------------------------------------------- #
def test_every_entry_of_the_store_and_of_the_keys_is_chained_and_signed_as_the_servers_own(backups):  # noqa: F811
    """The conversion of the store, its pause, a damaged file, a request to change a key, the end of a
    change: each is written through a session of the server, so each is numbered, linked and signed
    as the server's own, never found later as an entry written outside."""
    from app import store_seal
    from app.core import store as sealed_store

    root = Path(settings.SAMPLE_STORE)
    store_seal.convert_pass(budget=0, sleep=lambda _s: None)  # the conversion starts, and is paused at once
    assert backups.post("/api/storage/encryption", json={"action": "pause"}).status_code == 200
    assert backups.post("/api/storage/encryption", json={"action": "resume"}).status_code == 200
    for _ in range(100):
        if store_seal.convert_pass(sleep=lambda _s: None).get("state") == store_seal.SEALED:
            break
    assert backups.post("/api/storage/encryption", json={"action": "check"}).status_code == 200
    for name in ("SECRET_KEY", "STORE_KEY", "AUDIT_KEY"):
        assert backups.post(f"/api/system/keys/{name}/rotation", json={"password": "supersecret"}).status_code == 200
    assert backups.delete("/api/system/keys/STORE_KEY/rotation").status_code == 200
    target = next(path for path in root.rglob("*.bin") if path.is_file())
    raw = bytearray(target.read_bytes())
    raw[-1] ^= 1
    target.write_bytes(bytes(raw))
    with pytest.raises(OSError):
        sealed_store.read_bytes(target)
    wanted = {
        "store.seal.start", "store.seal.done", "store.seal.check", "store.seal.pause", "store.seal.resume",
        "key.rotate.request", "key.rotate.cancel", "store.damaged",
    }  # fmt: skip
    with SessionLocal() as db:
        rows = list(db.scalars(sa.select(AuditEntry).where(AuditEntry.action.in_(wanted))))
        unlinked = db.scalar(sa.select(sa.func.count()).select_from(AuditEntry).where(AuditEntry.seq.is_(None)))
        outside = db.scalar(sa.select(sa.func.count()).select_from(AuditEntry).where(AuditEntry.origin.is_not(None)))
    assert {row.action for row in rows} == wanted
    current = signing.current()[0]
    for row in rows:
        assert row.seq and row.hash and row.prev_hash and row.mac, row.action
        assert row.key_id == current and row.origin is None, row.action
    assert unlinked == 0 and outside == 0
    with SessionLocal() as db:
        state = chain.verify(db, full=True)
        db.commit()
    assert not state.get("problem") and not (state.get("unchecked") or {})
