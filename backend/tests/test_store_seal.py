"""Sealing a store that was in clear (store_seal.py): resumable, stopped anywhere, never a file
half-written, both forms readable meanwhile, nothing in clear at the end; and changing the store key."""

from __future__ import annotations

import hashlib
import os
import shutil
import time
from collections import namedtuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import preflight, stopped, store_seal
from app.core import sealed, store
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AuditEntry, Notification

MARKER = b"NIK-TEST-PLAINTEXT, a harmless fixture"
OLD_KEY = "dev-insecure-store-key-change-me"
NEW_KEY = "the new store key, long enough to be one"
Disk = namedtuple("Disk", "total used free")


def plenty(_path):
    return Disk(10**12, 0, 10**12)


@pytest.fixture()
def root(client, tmp_path, monkeypatch):
    """A store of its own, on a database of its own; the conversion is not slowed down."""
    folder = tmp_path / "store"
    folder.mkdir()
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(folder))
    monkeypatch.setenv("STORE_SEAL_MBPS", "0")
    return folder


def body(index: int, size: int = 3000) -> bytes:
    return (MARKER + b" %d " % index + hashlib.shake_256(b"%d" % index).digest(size))[:size]


def old_store(root, count: int = 6) -> dict[str, bytes]:
    """A store as a version before 6.8 left it: every kind of file, in clear, read-only."""
    files: dict[str, bytes] = {}
    for index in range(count):
        data = body(index, 1000 + 70_000 * (index % 3))
        files[hashlib.sha256(data).hexdigest() + ".bin"] = data
    mail = b"From: a@example.test\nSubject: " + MARKER + b"\n\nhello\n"
    files[hashlib.sha256(mail).hexdigest() + ".mail"] = mail
    files["_captures/" + "a" * 32 + "/capture.pcap"] = b"\xd4\xc3\xb2\xa1" + body(100)
    files["_captures/" + "a" * 32 + "/log.jsonl"] = b'{"id": 1, "url": "http://example.test/' + MARKER + b'"}\n'
    files["_mailboxes/" + "b" * 32 + "/mailbox.mbox"] = b"From x Thu Jan  1 00:00:00 1970\n" + mail + b"\n"
    files["_previews/" + "c" * 64 + ".json"] = b'{"pages": ["' + MARKER + b'"]}'
    files["_urls/" + "d" * 32 + ".jpg"] = b"\xff\xd8" + body(101)
    files["_flirt/" + "e" * 32 + ".sig"] = b"IDASGN" + body(102)
    files["_capa_rules/" + "f" * 32 + ".yml"] = b"rule: " + MARKER
    files["empty.bin"] = b""
    for name, data in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.chmod(path, 0o444)
    return files


def run(**options) -> dict:
    return store_seal.convert_pass(usage=options.pop("usage", plenty), sleep=lambda _s: None, **options)


def until_sealed(limit: int = 200, **options) -> dict:
    doc = {}
    for _ in range(limit):
        doc = run(**options)
        if doc.get("state") == store_seal.SEALED:
            return doc
    raise AssertionError(f"not sealed after {limit} passes: {doc}")


def in_clear(root) -> list[str]:
    return sorted(
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and not path.read_bytes().startswith(sealed.MAGIC)
    )


def audit(action: str) -> list[AuditEntry]:
    with SessionLocal() as db:
        return list(db.scalars(select(AuditEntry).where(AuditEntry.action == action).order_by(AuditEntry.at)))


def notices(kind: str) -> list[str]:
    with SessionLocal() as db:
        return [
            n.text for n in db.scalars(select(Notification).where(Notification.kind == kind).order_by(Notification.at))
        ]


# --------------------------------------------------------------------------- #
# The conversion                                                              #
# --------------------------------------------------------------------------- #
def test_a_new_server_is_sealed_from_the_start_and_nobody_is_told(admin: TestClient, root):
    doc = run()
    assert doc["state"] == store_seal.SEALED and doc["since"] and doc["converted"] is None
    assert doc["keyId"] == store.keyring().current.id.hex()
    assert notices("store.sealed") == [] and audit("store.seal.done") == []
    shown = admin.get("/api/storage/encryption").json()
    assert shown["state"] == "sealed" and shown["encrypted"] is True and shown["left"] == {"files": 0, "bytes": 0}
    assert shown["keyFingerprint"] == store.keyring().current.fingerprint
    # A file written from now on is sealed, and one in clear is not Nik's.
    store.write(root / "new.bin", b"new")
    assert in_clear(root) == []
    assert store_seal.clear_allowed() is False


def test_an_old_store_is_sealed_file_by_file_and_holds_what_it_held(admin: TestClient, root):
    files = old_store(root)
    total = sum(len(data) for data in files.values())
    assert store_seal.census(root) == {
        "clearFiles": len(files),
        "clearBytes": total,
        "sealedFiles": 0,
        "sealedBytes": 0,
    }
    # The upgrade does not wait: before anything is converted, every file is read as it is.
    for name, data in files.items():
        assert store.read_bytes(root / name) == data

    first = run(budget=0)  # a pass that has no time seals one file all the same
    assert first["state"] == store_seal.CONVERTING and first["done"]["files"] == 1
    assert first["total"] == {"files": len(files), "bytes": total}
    assert len(in_clear(root)) == len(files) - 1
    # While it runs both forms are read, and new files are sealed as they arrive.
    for name, data in files.items():
        assert store.read_bytes(root / name) == data
    store.write(root / "arrived-meanwhile.bin", b"sealed at once")
    shown = admin.get("/api/storage/encryption").json()
    assert shown["state"] == "converting" and shown["encrypted"] is False
    assert shown["left"]["files"] == len(files) - 1 and shown["done"]["files"] == 1

    doc = until_sealed(budget=0)
    assert doc["converted"]["files"] == len(files) and doc["converted"]["bytes"] == total
    # Nothing in clear remains: not a file, not the marker anywhere on the disk.
    assert in_clear(root) == []
    raw = b"".join(path.read_bytes() for path in root.rglob("*") if path.is_file())
    assert MARKER not in raw
    assert store_seal.census(root)["clearFiles"] == 0
    for name, data in files.items():
        assert store.read_bytes(root / name) == data and store.size(root / name) == len(data)
        if os.name == "posix":
            assert (root / name).stat().st_mode & 0o777 == 0o600
    assert not list(root.rglob("*" + store_seal.SEALING))
    # Told once, and written down.
    assert notices("store.sealed") == [
        f"The store of files is encrypted: {len(files)} file(s) were sealed and none is in clear any more."
    ]
    assert [entry.actor for entry in audit("store.seal.start")] == ["system"] and len(audit("store.seal.done")) == 1
    assert f"{len(files)} file(s), {total} bytes in clear" in audit("store.seal.start")[0].details
    shown = admin.get("/api/storage/encryption").json()
    assert shown["state"] == "sealed" and shown["since"] and shown["converted"]["files"] == len(files)
    # A pass more changes nothing.
    assert run()["since"] == doc["since"] and len(notices("store.sealed")) == 1


def test_the_conversion_goes_on_after_a_restart_from_what_the_files_say(root):
    files = old_store(root)
    for _ in range(4):
        run(budget=0)
    done = len(files) - len(in_clear(root))
    assert done == 4
    # The process is gone: nothing it remembered is left but the row and the files themselves.
    store_seal._cursor[0] = 0
    store_seal.forget()
    # (its lease ran out: the one that takes over looks two minutes later)
    doc = until_sealed(budget=0, holder="the process that took over", now=time.time() + 300)
    assert doc["converted"]["files"] == len(files) and in_clear(root) == []
    for name, data in files.items():
        assert store.read_bytes(root / name) == data


@pytest.mark.parametrize("step", ["write", "fsync", "read-back", "compare", "chmod", "replace"])
def test_stopped_at_any_step_a_file_is_whole_in_clear_or_whole_sealed(root, monkeypatch, step):
    data = body(1, 200_000)
    path = root / (hashlib.sha256(data).hexdigest() + ".bin")
    path.write_bytes(data)

    class Stop(Exception):
        pass

    def stop(*_args, **_kwargs):
        raise Stop()

    if step == "write":
        monkeypatch.setattr(sealed.Writer, "close", stop)
    elif step == "fsync":
        monkeypatch.setattr(store_seal.os, "fsync", stop)
    elif step == "read-back":
        monkeypatch.setattr(sealed, "open_sealed", stop)
    elif step == "compare":
        real = sealed.open_sealed

        class Lying:
            def __init__(self, *args):
                self._inner = real(*args)

            def __enter__(self):
                return self

            def __exit__(self, *_exc):
                self._inner.close()

            def read(self, size):
                return self._inner.read(size).replace(b"N", b"M")

        monkeypatch.setattr(sealed, "open_sealed", Lying)
    elif step == "chmod":
        monkeypatch.setattr(store_seal.os, "chmod", stop)
    else:
        monkeypatch.setattr(store_seal.os, "replace", stop)

    with pytest.raises((Stop, sealed.Damaged)):
        store_seal.seal_file(path, path.name, store.keyring(), plenty)
    # The file is as it was, and nothing was left beside it.
    assert path.read_bytes() == data and sorted(p.name for p in root.iterdir()) == [path.name]
    monkeypatch.undo()
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(root))
    assert store_seal.seal_file(path, path.name, store.keyring(), plenty) == len(data)
    assert store.read_bytes(path) == data and path.read_bytes().startswith(sealed.MAGIC)


def test_what_a_killed_process_left_beside_a_file_is_not_taken_for_a_file(root):
    files = old_store(root, count=2)
    name = next(n for n in files if n.endswith(".bin"))
    # Killed in the middle of a file: half a sealed copy beside it. Killed in the middle of a file
    # that was deleted since, and of an upload: what they left has no file beside it.
    (root / (name + store_seal.SEALING)).write_bytes(sealed.MAGIC + b"\x00" * 500)
    (root / ("0" * 64 + ".bin" + store_seal.SEALING)).write_bytes(sealed.MAGIC + b"\x00" * 500)
    (root / "upload.bin.part").write_bytes(b"half an upload")
    doc = until_sealed()
    # The file is sealed from its own content, whatever lay beside it, and nothing lies there now.
    assert store.read_bytes(root / name) == files[name] and not (root / (name + store_seal.SEALING)).exists()
    # The others are neither sealed as files nor counted; once old enough they are removed.
    orphans = [root / ("0" * 64 + ".bin" + store_seal.SEALING), root / "upload.bin.part"]
    assert all(orphan.exists() for orphan in orphans) and doc["converted"]["files"] == len(files)
    old = os.path.getmtime(orphans[1]) - store_seal.LEFTOVER_AFTER - 10
    for leftover in orphans:
        os.utime(leftover, (old, old))
    (root / "again.bin").write_bytes(b"in clear, so that the store is walked again")
    store_seal._update(state="")
    until_sealed()
    assert not any(orphan.exists() for orphan in orphans)


def test_a_file_written_again_or_deleted_while_it_is_sealed_is_left_to_whoever_did(root, monkeypatch):
    data = body(5, 50_000)
    path = root / "_captures" / ("a" * 32) / "log.jsonl"
    path.parent.mkdir(parents=True)
    path.write_bytes(data)
    real = sealed.open_sealed

    def meanwhile(*args):
        # Between the copy and the move, the server wrote the file again (a log that grew).
        store.write(path, b"the newer content")
        return real(*args)

    monkeypatch.setattr(sealed, "open_sealed", meanwhile)
    with pytest.raises(store_seal.Changed):
        store_seal.seal_file(path, store.name_of(path), store.keyring(), plenty)
    assert store.read_bytes(path) == b"the newer content"

    gone = root / "deleted.bin"
    gone.write_bytes(data)

    def deleted(*args):
        store.remove(gone)
        return real(*args)

    monkeypatch.setattr(sealed, "open_sealed", deleted)
    with pytest.raises(store_seal.Changed):
        store_seal.seal_file(gone, "deleted.bin", store.keyring(), plenty)
    # A file somebody deleted does not come back.
    assert not gone.exists() and not gone.with_name(gone.name + store_seal.SEALING).exists()


def test_a_disk_that_is_nearly_full_is_said_and_the_rest_goes_on(admin: TestClient, root):
    files = old_store(root, count=4)
    largest = max(files, key=lambda name: len(files[name]))
    room = sealed.sealed_size(len(files[largest])) + store_seal.ROOM_SPARE - 1  # one byte short for the largest

    def tight(_path):
        return Disk(10**9, 10**9 - room, room)

    doc = {}
    for _ in range(40):
        doc = run(usage=tight)
    # Everything that fits was sealed, file by file; what does not is said, once, and left in clear and whole.
    assert doc["state"] == store_seal.CONVERTING and in_clear(root) == [largest]
    assert (root / largest).read_bytes() == files[largest]
    assert doc["stuckCount"] == 1 and doc["stuck"][0]["name"] == largest
    assert "There is no room on the disk to encrypt it: it needs" in doc["stuck"][0]["reason"]
    told = notices("store.problem")
    assert len(told) == 1 and "1 file(s) of the store could not be encrypted and are still in clear" in told[0]
    assert len(audit("store.seal.stuck")) == 1
    shown = admin.get("/api/storage/encryption").json()
    assert shown["stuckCount"] == 1 and shown["stuck"][0]["name"] == largest and shown["state"] == "converting"
    # It waits before it tries again, and does not fill the log meanwhile.
    assert run(usage=plenty)["state"] == store_seal.CONVERTING and in_clear(root) == [largest]

    # Room was made: at its next try the file is sealed, and the problem is said to be over.
    after = doc["retryAt"] + 1
    doc = until_sealed(now=after)
    assert in_clear(root) == [] and store.read_bytes(root / largest) == files[largest]
    assert notices("store.solved") == ["The files of the store that could not be encrypted now are."]
    assert len(notices("store.problem")) == 1 and len(notices("store.sealed")) == 1


def test_never_more_room_is_needed_than_the_file_being_sealed(root):
    """One file at a time: the store may fill most of the disk."""
    files = old_store(root, count=5)
    largest = max(len(data) for data in files.values())
    asked = []

    def measured(path):
        beside = sum(p.stat().st_size for p in root.rglob("*" + store_seal.SEALING))
        asked.append(beside)
        return Disk(10**9, 0, sealed.sealed_size(largest) + store_seal.ROOM_SPARE)

    until_sealed(usage=measured)
    # Whenever room was asked for, no sealed copy of another file was waiting beside its own.
    assert asked and set(asked) == {0} and in_clear(root) == []


def test_the_conversion_is_paused_and_taken_up_again(admin: TestClient, root):
    files = old_store(root, count=5)
    run(budget=0)
    answer = admin.post("/api/storage/encryption", json={"action": "pause"})
    assert answer.status_code == 200 and answer.json()["state"] == "paused" and answer.json()["pausedBy"] == "admin"
    left = in_clear(root)
    for _ in range(5):
        assert run(budget=0)["state"] == store_seal.PAUSED
    assert in_clear(root) == left
    # Paused or not, the files are read and new ones are sealed.
    assert all(store.read_bytes(root / name) == data for name, data in files.items())
    assert admin.post("/api/storage/encryption", json={"action": "resume"}).json()["state"] == "converting"
    until_sealed(budget=0)
    assert in_clear(root) == []
    assert [entry.actor for entry in audit("store.seal.pause")] == ["admin"] and len(audit("store.seal.resume")) == 1
    # Pausing what is not running changes nothing; an unknown action is refused.
    assert admin.post("/api/storage/encryption", json={"action": "pause"}).json()["state"] == "sealed"
    assert admin.post("/api/storage/encryption", json={"action": "stop"}).status_code == 422
    analyst = TestClient(admin.app)
    assert analyst.post("/api/storage/encryption", json={"action": "pause"}).status_code == 401


def test_a_pause_is_obeyed_between_two_files_of_a_pass(root, monkeypatch):
    """Pressed while a pass is at work, it does not wait for the pass to end."""
    files = old_store(root, count=8)
    monkeypatch.setattr(store_seal, "PAUSE_LOOK", 0.0)
    real = store_seal.seal_file
    sealed_so_far = []

    def sealing(path, name, ring, usage=shutil.disk_usage):
        size = real(path, name, ring, usage)
        sealed_so_far.append(name)
        if len(sealed_so_far) == 3:
            # An administrator presses Pause while the third file is being sealed.
            with SessionLocal() as db:
                store_seal.set_paused(db, True, "admin")
                db.commit()
        return size

    monkeypatch.setattr(store_seal, "seal_file", sealing)
    doc = run(budget=3600)
    assert doc["state"] == store_seal.PAUSED and len(sealed_so_far) == 3
    assert len(in_clear(root)) == len(files) - 3 and doc["done"]["files"] == 3
    with SessionLocal() as db:
        store_seal.set_paused(db, False, "admin")
        db.commit()
    until_sealed()
    assert in_clear(root) == []


def test_only_one_process_converts_at_a_time(root):
    old_store(root, count=3)
    assert run(budget=0, holder="one")["done"]["files"] == 1
    # Another process finds the lease taken and touches nothing.
    assert run(budget=0, holder="two") == {}
    assert len(in_clear(root)) > 0
    until_sealed(holder="one")


def test_a_process_without_the_store_key_converts_nothing(root, monkeypatch):
    old_store(root, count=2)
    monkeypatch.setattr(settings, "STORE_KEY", "")
    assert run() == {}
    assert store_seal.census(root)["sealedFiles"] == 0


def test_a_sealed_store_refuses_a_file_in_clear_until_it_is_checked_again(admin: TestClient, root):
    old_store(root, count=2)
    until_sealed()
    # Put back by hand from a copy made before 6.8 (or by whoever can write to the disk).
    back = root / ("9" * 64 + ".bin")
    back.write_bytes(b"MZ put back by hand")
    with pytest.raises(store.DamagedFile, match="it is in clear"):
        store.read_bytes(back)
    answer = admin.post("/api/storage/encryption", json={"action": "check"})
    assert answer.status_code == 200 and answer.json()["state"] == "starting"
    assert [entry.actor for entry in audit("store.seal.check")] == ["admin"]
    doc = until_sealed()
    assert doc["converted"]["files"] >= 1 and in_clear(root) == []
    assert store.read_bytes(back) == b"MZ put back by hand"


def test_a_sample_in_clear_that_starts_like_a_sealed_file_is_sealed_too(root):
    """Somebody uploaded a sealed file as a sample before 6.8: its first bytes are the magic."""
    data = sealed.MAGIC + b"\x00\x01\x00\x00" + b"\x00" * 4 + body(1, 600)
    path = root / (hashlib.sha256(data).hexdigest() + ".bin")
    path.write_bytes(data)
    other = root / "_captures" / ("a" * 32) / "capture.pcap"
    other.parent.mkdir(parents=True)
    store.write(other, b"really sealed")
    until_sealed()
    assert store.read_bytes(path) == data and path.read_bytes() != data
    assert store.read_bytes(other) == b"really sealed"


def test_a_file_that_cannot_be_read_is_stuck_and_the_others_are_sealed(root, monkeypatch):
    files = old_store(root, count=3)
    bad = next(iter(files))
    real = store_seal.seal_file

    def failing(path, name, ring, usage=shutil.disk_usage):
        if name == bad:
            raise OSError("Input/output error")
        return real(path, name, ring, usage)

    monkeypatch.setattr(store_seal, "seal_file", failing)
    doc = {}
    for _ in range(30):
        doc = run()
    assert in_clear(root) == [bad] and doc["stuck"] == [
        {"name": bad, "reason": "It could not be encrypted: Input/output error"}
    ]
    assert (root / bad).read_bytes() == files[bad]


def test_the_room_of_the_disk_is_noted_for_the_process_that_does_not_see_it(root):
    with SessionLocal() as db:
        assert store_seal.disk_seen(db) is None
    store_seal._note_disk()
    with SessionLocal() as db:
        seen = store_seal.disk_seen(db)
    assert seen["total"] > 0 and 0 <= seen["free"] <= seen["total"] and seen["at"] > 0

    from app.automation import worker

    with SessionLocal() as db:
        now = seen["at"] + 10
        # A process that sees the store measures it; one that does not reads what was noted, while fresh.
        assert worker._store_disk(db, now, shutil.disk_usage).total == shutil.disk_usage(root).total
        settings_key, settings.STORE_KEY = settings.STORE_KEY, ""
        try:
            assert worker._store_disk(db, now, shutil.disk_usage).total == seen["total"]
            assert worker._store_disk(db, now + 7200, shutil.disk_usage) is None
        finally:
            settings.STORE_KEY = settings_key


# --------------------------------------------------------------------------- #
# Changing the store key                                                      #
# --------------------------------------------------------------------------- #
def test_changing_the_store_key_rewraps_every_file_and_proves_it(admin: TestClient, root, monkeypatch):
    files = old_store(root, count=4)
    until_sealed()
    before = {name: (root / name).read_bytes() for name in files}
    old_fingerprint = store.keyring().current.fingerprint
    with SessionLocal() as db:
        assert not store_seal.rewrap_needed(store_seal.read(db))

    monkeypatch.setattr(settings, "STORE_KEY", NEW_KEY)
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [OLD_KEY])
    ring = store.keyring()
    # Before anything is rewrapped the server reads everything, and writes under the new key.
    assert all(store.read_bytes(root / name) == data for name, data in files.items())
    with SessionLocal() as db:
        assert store_seal.rewrap_needed(store_seal.read(db))
    assert store_seal.key_problem() is None  # the earlier key is held: this is a change, not a wrong key

    first = store_seal.rewrap_pass(budget=0)
    assert first["state"] == "running" and first["total"] == len(files) and first["done"] == 1
    assert all(store.read_bytes(root / name) == data for name, data in files.items())
    progress = {}
    for _ in range(50):
        progress = store_seal.rewrap_pass(budget=0)
        if progress.get("state") == "verified":
            break
    assert progress["state"] == "verified" and progress["done"] == progress["total"] == len(files)
    assert progress["verifiedFor"] == ring.current.id.hex() and progress["failed"] == []
    # The content of no file was written again: only its head.
    for name in files:
        raw = (root / name).read_bytes()
        assert (
            raw[sealed.HEADER :] == before[name][sealed.HEADER :]
            and raw[: sealed.HEADER] != before[name][: sealed.HEADER]
        )
        assert sealed.read_head(root / name).key_ids() == [ring.current.id]
    # The earlier key is no longer needed: without it everything opens, and with it alone nothing does.
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [])
    assert all(store.read_bytes(root / name) == data for name, data in files.items())
    with SessionLocal() as db:
        doc = store_seal.read(db)
        assert doc["keyId"] == ring.current.id.hex() and not store_seal.rewrap_needed(doc)
    monkeypatch.setattr(settings, "STORE_KEY", OLD_KEY)
    with pytest.raises(store.WrongKeyFile):
        store.read_bytes(root / next(iter(files)))
    monkeypatch.setattr(settings, "STORE_KEY", NEW_KEY)

    said = audit("store.key.rewrap.done")
    assert len(said) == 1 and ring.current.fingerprint in said[0].details and "opened with it alone" in said[0].details
    assert len(audit("store.key.rewrap.start")) == 1 and len(notices("store.key")) == 1
    shown = admin.get("/api/storage/encryption").json()
    assert shown["keyFingerprint"] == ring.current.fingerprint != old_fingerprint
    # No key, and no part of one, is in what the screen is given or in what was written down.
    everything = (
        admin.get("/api/storage/encryption").text + " ".join(e.details for e in said) + " ".join(notices("store.key"))
    )
    assert NEW_KEY not in everything and OLD_KEY not in everything
    assert ring.current.id.hex() not in everything and ring.current.wrapping.hex() not in everything


def test_a_change_of_store_key_stopped_half_way_goes_on_and_loses_nothing(root, monkeypatch):
    files = old_store(root, count=5)
    until_sealed()
    monkeypatch.setattr(settings, "STORE_KEY", NEW_KEY)
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [OLD_KEY])
    store_seal.rewrap_pass(budget=0)
    store_seal.rewrap_pass(budget=0)
    under_new = [name for name in files if sealed.read_head(root / name).key_ids() == [store.keyring().current.id]]
    assert 0 < len(under_new) < len(files)
    # The server restarts in the middle: every file opens, under one key or the other.
    store_seal.forget()
    assert all(store.read_bytes(root / name) == data for name, data in files.items())
    # Files that arrive meanwhile are under the new key already.
    store.write(root / "arrived.bin", b"new")
    progress = {}
    for _ in range(50):
        progress = store_seal.rewrap_pass(budget=0, holder="after the restart", now=time.time() + 300)
        if progress.get("state") == "verified":
            break
    assert progress["state"] == "verified" and progress["done"] == len(files) + 1
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [])
    assert all(store.read_bytes(root / name) == data for name, data in files.items())


def test_a_file_that_cannot_be_put_under_the_new_key_keeps_the_change_open(admin: TestClient, root, monkeypatch):
    files = old_store(root, count=3)
    until_sealed()
    stranger = root / ("7" * 64 + ".bin")
    with open(stranger, "wb") as out:  # sealed under a key the server never held
        writer = sealed.Writer(out, stranger.name, sealed.StoreKey.derive("a key nobody here ever had, long enough"))
        writer.write(b"unreadable")
        writer.close()
    monkeypatch.setattr(settings, "STORE_KEY", NEW_KEY)
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [OLD_KEY])
    progress = {}
    for _ in range(10):
        progress = store_seal.rewrap_pass()
    assert progress["state"] == "failed" and [entry["name"] for entry in progress["failed"]] == [stranger.name]
    assert "verifiedFor" not in progress
    with SessionLocal() as db:
        assert store_seal.rewrap_needed(store_seal.read(db))
    # Said once; every other file is under the new key and readable; the earlier key is to be kept.
    told = notices("store.problem")
    assert len(told) == 1 and "Keep the earlier store key" in told[0] and len(audit("store.key.rewrap.failed")) == 1
    assert all(store.read_bytes(root / name) == data for name, data in files.items())
    # The file is dealt with (deleted here): the next pass proves the change and ends it.
    stranger.unlink()
    assert store_seal.rewrap_pass()["state"] == "verified"


# --------------------------------------------------------------------------- #
# A store key that is not the one of the store                                #
# --------------------------------------------------------------------------- #
def test_a_store_key_that_is_not_the_one_of_the_store_stops_the_server_and_says_so(root, monkeypatch):
    old_store(root, count=2)
    assert store_seal.key_problem() is None  # nothing sealed yet: any key will do
    until_sealed()
    assert store_seal.key_problem() is None
    right = store.keyring().current.fingerprint

    monkeypatch.setattr(settings, "STORE_KEY", NEW_KEY)
    wrong = store_seal.key_problem()
    assert wrong.startswith("STORE_KEY is not the key the store of files is sealed under")
    assert right in wrong and store.keyring().current.fingerprint in wrong and "Nothing was changed" in wrong
    assert "STORE_KEY_PREVIOUS" in wrong and NEW_KEY not in wrong and OLD_KEY not in wrong
    # What the entrypoint runs: the server stays up and says it, instead of writing files nobody reads later.
    served = []
    monkeypatch.setattr(stopped, "serve", served.append)
    preflight.main(["--store"])
    assert served == [[wrong + "."]]
    # The earlier key given beside the new one is a change of key, not a wrong key.
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [OLD_KEY])
    assert store_seal.key_problem() is None
    preflight.main(["--store"])
    assert len(served) == 1

    # The row says nothing (a volume put back by hand under another database): a file is asked.
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [])
    store_seal._update(keyId="")
    wrong = store_seal.key_problem()
    assert wrong.startswith("STORE_KEY is not the key the files of the store are sealed under") and right in wrong


def test_a_backup_put_back_makes_the_store_this_servers(root, monkeypatch):
    old_store(root, count=2)
    until_sealed()
    # The row of another server came with its database; the files were just sealed under this key.
    store_seal._update(state=store_seal.SEALED, keyId="00" * 8, damaged={"x.bin": {"at": "", "reason": "old"}})
    assert store_seal.key_problem() is not None
    store_seal.after_restore()
    assert store_seal.key_problem() is None
    doc = until_sealed()
    assert doc["keyId"] == store.keyring().current.id.hex() and doc["damaged"] == {}


def test_going_back_to_a_version_before_unseals_every_file(root, capsys):
    files = old_store(root, count=3)
    until_sealed()
    assert store_seal.main(["status"]) == 0
    assert '"clearFiles": 0' in capsys.readouterr().out
    assert store_seal.main(["unseal"]) == 0
    assert f"{len(files)} file(s) are in clear again" in capsys.readouterr().err
    for name, data in files.items():
        assert (root / name).read_bytes() == data
        if os.name == "posix":
            assert (root / name).stat().st_mode & 0o777 == 0o444  # as the workers of a version before read them
    # Started again on this version, the store is sealed again by itself.
    store_seal.forget()
    until_sealed()
    assert in_clear(root) == []


def test_unsealing_needs_the_database_and_touches_nothing_without_it(root, capsys, monkeypatch):
    """A server of this version that started on a store in clear while its row said "sealed" would
    refuse every file of it: the row is written first, or nothing is done."""
    old_store(root, count=2)
    until_sealed()
    before = {path.name: path.read_bytes() for path in root.rglob("*") if path.is_file()}

    def down(**_changes):
        raise ConnectionError("could not translate host name")

    monkeypatch.setattr(store_seal, "_update", down)
    assert store_seal.main(["unseal"]) == 1
    said = capsys.readouterr().err
    assert "the database cannot be reached" in said and "Nothing was changed" in said
    assert {path.name: path.read_bytes() for path in root.rglob("*") if path.is_file()} == before


def test_unsealing_says_which_file_it_could_not_open_and_fails(root, capsys):
    old_store(root, count=2)
    until_sealed()
    victim = next(p for p in root.iterdir() if p.suffix == ".bin")
    raw = bytearray(victim.read_bytes())
    raw[-1] ^= 1
    victim.write_bytes(bytes(raw))
    assert store_seal.main(["unseal"]) == 1
    said = capsys.readouterr().err
    assert f"unseal: {victim.name}:" in said and "1 could not be opened" in said
    assert victim.read_bytes() == bytes(raw)  # left as it was: sealed, and damaged
