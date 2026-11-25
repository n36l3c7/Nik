"""The pool of the backups (7.0): a file of the store named by its SHA-256 is written once, and
every backup that needs it names it. Harmless fixtures only: bytes made here."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest
from sqlalchemy import select

from app.backups import config, container, pool, runner
from app.backups import store as backup_store
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import BackupBlob, BackupBlobRef
from tests.test_backups import PHRASE, T0, audit_lines, backups, quick_keys, rows, set_phrase  # noqa: F401 - fixtures

HOUR = 3600


def put(folder: str, data: bytes, suffix: str = ".bin") -> str:
    """A file of the store named by what it holds. Its SHA-256."""
    sha256 = hashlib.sha256(data).hexdigest()
    place = Path(settings.SAMPLE_STORE) / folder
    place.mkdir(parents=True, exist_ok=True)
    (place / f"{sha256}{suffix}").write_bytes(data)
    return sha256


@pytest.fixture()
def pooled_store(backups):  # noqa: F811
    """The store of the suite, with three files the pool takes: an original, a sample and an e-mail."""
    set_phrase(backups)
    return {
        "original": put("_evidence", os.urandom(300_000)),
        "sample": put("", b"a harmless fixture named by its hash\n" * 500),
        "mail": put("", b"Subject: named by its hash\n\nbody\n", ".mail"),
    }


def blobs(gen: str | None = None) -> dict[str, BackupBlob]:
    with SessionLocal() as db:
        found = db.scalars(select(BackupBlob) if gen is None else select(BackupBlob).where(BackupBlob.gen == gen))
        return {row.sha256: row for row in found}


def pool_files() -> list[str]:
    return sorted(path.name for path in Path(settings.BACKUP_DIR).rglob(f"*{pool.SUFFIX}"))


def manifest_of(name: str) -> dict:
    with open(runner.file_of(name), "rb") as source:
        return container.walk(source, container.Secrets(passphrases=(PHRASE,)))


def test_a_file_named_by_its_hash_is_written_once(pooled_store):
    first = runner.take(by="admin", now=T0)
    (row,) = rows()
    assert (row.state, row.verify_state) == ("done", "passed"), row.error or row.verify
    gen = row.summary["pool"]
    # The fixtures of the suite are not what their names say (aaaa….bin): they stay in the backup.
    assert row.summary["files"] == 6 and row.summary["pooled"] == 3
    assert pool_files() == sorted(f"{sha256}{pool.SUFFIX}" for sha256 in pooled_store.values())
    assert (Path(settings.BACKUP_DIR) / f"pool-{gen}").is_dir()
    manifest = manifest_of(first)
    names = [part["name"] for part in manifest["parts"]]
    assert names[-4:] == [pool.KEY_PART, pool.LIST_PART, backup_store.TAR_PART, backup_store.INDEX_PART]
    assert manifest["store"]["pooled"] == 3 and manifest["store"]["pool"] == gen
    assert set(blobs(gen)) == set(pooled_store.values())
    assert all(blob.verified_at is not None and blob.local for blob in blobs(gen).values()), "new files are read whole"
    checks = " / ".join(row.verify["checks"])
    assert "3 files of the store in the pool" in checks and "3 read whole" in checks
    assert "(3 new in the pool, 0 already there)" in " ".join(audit_lines("backup.run"))

    # The second backup writes none of them again, and is smaller by what the pool holds.
    stamps = {path: path.stat().st_mtime_ns for path in Path(settings.BACKUP_DIR).rglob(f"*{pool.SUFFIX}")}
    second = runner.take(by="admin", now=T0 + HOUR)
    assert {path: path.stat().st_mtime_ns for path in Path(settings.BACKUP_DIR).rglob(f"*{pool.SUFFIX}")} == stamps
    assert runner.file_of(second).stat().st_size < 200_000 < 300_000
    with SessionLocal() as db:
        refs = db.execute(select(BackupBlobRef.backup_id, BackupBlobRef.sha256)).all()
    assert {backup for backup, _sha in refs} == {first, second} and len(refs) == 6


def test_the_files_of_the_pool_come_back_from_it(pooled_store, tmp_path):
    name = runner.take(by="admin", now=T0)
    secrets = container.Secrets(passphrases=(PHRASE,))

    def unpack(target, **options):
        unpacker = backup_store.Unpacker(target, pool_base=runner.directory(), **options)
        with open(runner.file_of(name), "rb") as source:
            reader = container.Reader(source, secrets)
            for part in reader.parts():
                unpacker.take(part)
        return unpacker, unpacker.finish(reader.manifest)

    monkey_root = tmp_path / "restored"
    monkey_root.mkdir()
    unpacker, _checks = unpack(monkey_root)
    assert unpacker.pool_read == 3
    from app.core import store as sealed_store

    original = monkey_root / "_evidence" / f"{pooled_store['original']}.bin"
    held = sealed_store.open(original, f"_evidence/{pooled_store['original']}.bin").read()
    assert hashlib.sha256(held).hexdigest() == pooled_store["original"]
    assert (monkey_root / f"{pooled_store['mail']}.mail").is_file()

    # A file of the pool that was changed is refused, by name; one that is gone too.
    gen = unpacker.pool_gen
    path = pool.blob_path(runner.directory(), gen, pooled_store["sample"])
    data = bytearray(path.read_bytes())
    data[-20] ^= 1
    path.write_bytes(bytes(data))
    with pytest.raises(container.BackupError, match="damaged"):
        unpack(None, read_pool=lambda _sha256: True)
    unpack(None)  # only looked for: it is there
    path.unlink()
    with pytest.raises(container.BackupError, match="pool does not hold"):
        unpack(None)
    # Without the pool the backup says so instead of restoring a store with holes.
    unpacker = backup_store.Unpacker(None)
    with open(runner.file_of(name), "rb") as source:
        reader = container.Reader(source, secrets)
        for part in reader.parts():
            unpacker.take(part)
    with pytest.raises(container.BackupError, match="pool was not given"):
        unpacker.finish(reader.manifest)


def test_a_backup_fails_its_test_when_a_new_file_of_the_pool_is_damaged(pooled_store, monkeypatch):
    real = pool.Target.put

    def damaged(self, sha256, handle):
        done = real(self, sha256, handle)
        if sha256 == pooled_store["original"]:
            path = pool.blob_path(self.base, self.gen, sha256)
            data = bytearray(path.read_bytes())
            data[len(data) // 2] ^= 1
            path.write_bytes(bytes(data))
        return done

    monkeypatch.setattr(pool.Target, "put", damaged)
    runner.take(by="admin", now=T0)
    (row,) = rows()
    assert row.verify_state == "failed" and "damaged" in row.verify["error"]


def test_the_retention_removes_what_no_backup_names_any_more(pooled_store):
    with SessionLocal() as db:
        doc = config.read(db)
        doc["retention"] = {"last": 1, "weeks": 0, "upgrades": 3}
        config._keep(db, doc)
        db.commit()
    runner.take(now=T0)
    # The original is deleted from the store: the next backup does not name it, and once the one
    # that did is gone its file of the pool goes too. The others stay: a kept backup names them.
    (Path(settings.SAMPLE_STORE) / "_evidence" / f"{pooled_store['original']}.bin").unlink()
    second = runner.take(now=T0 + HOUR)
    assert [row.id for row in rows()] == [second]
    assert pool_files() == sorted(f"{pooled_store[key]}{pool.SUFFIX}" for key in ("sample", "mail"))
    assert set(blobs()) == {pooled_store["sample"], pooled_store["mail"]}


def test_another_passphrase_starts_another_pool(pooled_store):
    with SessionLocal() as db:
        doc = config.read(db)
        doc["retention"] = {"last": 1, "weeks": 0, "upgrades": 3}
        config._keep(db, doc)
        db.commit()
    runner.take(now=T0)
    old = rows()[0].summary["pool"]
    with SessionLocal() as db:
        config.set_passphrase(db, "another passphrase for the tests")
        db.commit()
    runner.take(now=T0 + HOUR)
    (row,) = rows()
    new = row.summary["pool"]
    assert new != old and row.verify_state == "passed", row.verify
    # Every file was written again under the new key, and the folder of the old pool is gone with
    # the backup that named it.
    assert len(pool_files()) == 3 and set(blobs()) == set(pooled_store.values())
    assert {blob.gen for blob in blobs().values()} == {new}
    assert not (Path(settings.BACKUP_DIR) / f"pool-{old}").exists()


def test_nothing_is_removed_while_a_backup_is_not_understood(pooled_store):
    first = runner.take(now=T0)
    with SessionLocal() as db:
        db.query(BackupBlobRef).delete()
        db.commit()
        from app.backups import pooled

        done = pooled.collect(db, runner.directory())
        assert done["skipped"] == 1 and done["removed"] == 0
        # The rows come back from the backup's own list, and then the pool is cleaned as usual.
        pooled.sync(db, runner.directory(), config.secrets(db), runner.file_of)
        db.commit()
        assert {ref.backup_id for ref in db.scalars(select(BackupBlobRef))} == {first}
        assert pooled.collect(db, runner.directory()) == {"removed": 0, "bytes": 0, "skipped": 0}
    assert len(pool_files()) == 3


def test_a_file_of_the_pool_is_read_by_the_script_alone(pooled_store, tmp_path):
    """container.py copied out of Nik: the backup gives the key of the pool, and the key a file of it."""
    import shutil
    import subprocess
    import sys

    name = runner.take(by="admin", now=T0)
    gen = rows()[0].summary["pool"]
    alone = tmp_path / "elsewhere"
    alone.mkdir()
    shutil.copy(Path(container.__file__), alone / "container.py")
    env = {**os.environ, "NIK_BACKUP_PASSPHRASE": PHRASE, "PYTHONPATH": ""}
    done = subprocess.run(
        [sys.executable, "container.py", "extract", str(runner.file_of(name)), "out"],
        cwd=alone,
        env=env,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert pooled_store["original"] in (alone / "out" / "store.pool").read_text()
    blob = pool.blob_path(runner.directory(), gen, pooled_store["original"])
    done = subprocess.run(
        [sys.executable, "container.py", "extract", str(blob), "file", "--pool-key", "out/pool-key"],
        cwd=alone,
        env=env,
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stderr
    assert hashlib.sha256((alone / "file" / "blob").read_bytes()).hexdigest() == pooled_store["original"]
    refused = subprocess.run(
        [sys.executable, "container.py", "list", str(blob)], cwd=alone, env=env, capture_output=True, text=True
    )
    assert refused.returncode != 0 and "--pool-key" in refused.stderr
