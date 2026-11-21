"""Backups and the sealed store: a backup holds the files themselves under its passphrase, whatever
they sit under on the disk, and a restore seals each under the store key of the server that restores."""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
from pathlib import Path

import pytest

from app import store_seal
from app.backups import container, database, restore, runner
from app.backups import store as backup_store
from app.core import sealed
from app.core import store as sealed_store
from app.core.config import settings
from app.core.db import SessionLocal
from tests.test_backups import PHRASE, T0, backups, quick_keys, set_phrase  # noqa: F401 - fixtures

OLD_KEY = "dev-insecure-store-key-change-me"
OTHER_KEY = "the store key of another host, long enough"


def plain(root: Path) -> dict[str, bytes]:
    """What every file of a store holds, read through the store (sealed or not)."""
    return {
        path.relative_to(root).as_posix(): sealed_store.open(path, path.relative_to(root).as_posix()).read()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def seal_all(root: Path) -> None:
    for _ in range(100):
        if store_seal.convert_pass(sleep=lambda _s: None).get("state") == store_seal.SEALED:
            return
    raise AssertionError("the store was not sealed")


def held_by(path: Path, phrase: str = PHRASE) -> tuple[dict, dict[str, bytes], list[dict]]:
    """The manifest of a backup, the files of the store it holds, and its index: read with the passphrase alone."""
    files: dict[str, bytes] = {}
    index: list[dict] = []

    def each(part) -> None:
        if part.name == backup_store.TAR_PART:
            with tarfile.open(fileobj=io.BytesIO(part.read()), mode="r:") as tar:
                for member in tar:
                    if member.isreg():
                        files[member.name] = tar.extractfile(member).read()
        elif part.name == backup_store.INDEX_PART:
            index.extend(json.loads(line) for line in part.read().splitlines() if line)

    with open(path, "rb") as source:
        manifest = container.walk(source, container.Secrets(passphrases=(phrase,)), each)
    return manifest, files, index


def test_a_backup_of_a_sealed_store_holds_the_files_themselves(backups, monkeypatch):  # noqa: F811
    root = Path(settings.SAMPLE_STORE)
    before = plain(root)  # as a version before 6.8 left them: in clear
    set_phrase(backups)
    first = runner.take(now=T0)
    seal_all(root)
    assert all(path.read_bytes().startswith(sealed.MAGIC) for path in root.rglob("*") if path.is_file())
    second = runner.take(now=T0 + 3600)

    # Read with the passphrase and nothing else: this process forgets the store key first.
    monkeypatch.setattr(settings, "STORE_KEY", "")
    old_manifest, old_files, old_index = held_by(runner.file_of(first))
    new_manifest, new_files, new_index = held_by(runner.file_of(second))
    monkeypatch.setattr(settings, "STORE_KEY", OLD_KEY)
    # The backup taken before the store was sealed and the one taken after hold the same thing.
    assert new_files == old_files == before
    assert new_index == old_index and new_manifest["store"] == old_manifest["store"]
    assert {entry["path"]: (entry["size"], entry["sha256"]) for entry in new_index} == {
        name: (len(data), hashlib.sha256(data).hexdigest()) for name, data in before.items()
    }
    assert new_manifest["store"] == {"files": len(before), "bytes": sum(len(data) for data in before.values())}
    # Its restore test passed, and proved every file.
    rows = {row["id"]: row for row in backups.get("/api/backups").json()["backups"]}
    assert rows[second]["verifyState"] == "passed"
    assert any("each compared with its checksum" in check for check in rows[second]["verify"]["checks"])
    # Nothing of a sealed file, and no store key, is in the backup.
    raw = runner.file_of(second).read_bytes()
    assert sealed.MAGIC not in raw and OLD_KEY.encode() not in raw


def test_the_store_key_is_never_inside_a_backup_even_with_the_secret_key_included(backups):  # noqa: F811
    set_phrase(backups)
    assert backups.put("/api/backups/settings", json={"includeKey": True}).status_code == 200
    name = runner.take(now=T0)
    parts: dict[str, bytes] = {}
    with open(runner.file_of(name), "rb") as source:
        container.walk(
            source, container.Secrets(passphrases=(PHRASE,)), lambda part: parts.__setitem__(part.name, part.read())
        )
    assert parts["secret-key"] == settings.SECRET_KEY.encode()
    everything = b"".join(parts.values())
    ring = sealed_store.keyring()
    assert OLD_KEY.encode() not in everything and ring.current.wrapping not in everything
    assert "store-key" not in parts


def test_a_backup_does_not_take_what_an_interrupted_write_left(backups):  # noqa: F811
    root = Path(settings.SAMPLE_STORE)
    (root / ("c" * 64 + ".bin.part")).write_bytes(b"half an upload")
    (root / ("a" * 64 + ".bin.sealing")).write_bytes(b"half a conversion")
    (root / "_transfer").mkdir()
    (root / "_transfer" / "nik-artifacts-x.zip").write_bytes(b"an export being made")
    set_phrase(backups)
    name = runner.take(now=T0)
    _manifest, files, _index = held_by(runner.file_of(name))
    assert sorted(files) == sorted(
        n for n in plain(root) if not n.endswith((".part", ".sealing")) and "_transfer" not in n
    )
    assert backups.get("/api/backups").json()["backups"][0]["verifyState"] == "passed"


def test_a_backup_fails_on_a_damaged_file_and_says_which(backups):  # noqa: F811
    root = Path(settings.SAMPLE_STORE)
    seal_all(root)
    victim = root / ("a" * 64 + ".bin")
    raw = bytearray(victim.read_bytes())
    raw[sealed.HEADER + 9] ^= 1
    victim.write_bytes(bytes(raw))
    set_phrase(backups)
    runner.take(now=T0)
    row = backups.get("/api/backups").json()["backups"][0]
    # A backup that left the file out, or carried it damaged, would look whole: it fails instead.
    assert row["state"] == "failed" and "A file of the store cannot be read" in row["error"]
    assert f"{'a' * 64}.bin of the store is damaged" in row["error"]
    assert not list(Path(settings.BACKUP_DIR).glob("*.nikbak"))


@pytest.fixture()
def another_host(backups, tmp_path, monkeypatch):  # noqa: F811
    """A backup of this server, and an empty host with a store key of its own to put it on."""
    root = Path(settings.SAMPLE_STORE)
    held = plain(root)
    seal_all(root)
    store_seal._update(damaged={"gone.bin": {"at": "", "reason": "of the old host"}})
    set_phrase(backups)
    name = runner.take(now=T0)
    target = tmp_path / "restored-store"
    scratch = database.Scratch("scratch", separate_role=False).create()
    monkeypatch.setattr(database, "live_url", lambda: scratch.url)
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(target))
    monkeypatch.setattr(settings, "STORE_KEY", OTHER_KEY)
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", PHRASE)
    yield runner.file_of(name), held, target, scratch
    scratch.drop()


def test_a_restore_on_another_host_needs_the_passphrase_and_not_the_store_key(another_host, capsys):
    path, held, target, _scratch = another_host
    # The store key of the host that was lost is not here, and is not asked for.
    assert OLD_KEY not in (settings.STORE_KEY, *settings.STORE_KEY_PREVIOUS)
    assert restore.main(["restore", str(path)]) == 0
    said = capsys.readouterr().err
    assert "every file of the store was sealed under the store key of this server" in said
    files = [p for p in target.rglob("*") if p.is_file()]
    assert len(files) == len(held) and all(p.read_bytes().startswith(sealed.MAGIC) for p in files)
    ring = sealed.Keyring.of(OTHER_KEY)
    for p in files:
        name = p.relative_to(target).as_posix()
        # Under the store key of this host, bound to its place, holding what the old host held.
        assert sealed.read_head(p).key_ids() == [ring.current.id]
        assert sealed.open_sealed(p, name, ring).read() == held[name]
        with pytest.raises(sealed.WrongKey):
            sealed.open_sealed(p, name, sealed.Keyring.of(OLD_KEY))
    raw = b"".join(p.read_bytes() for p in files)
    assert b"a harmless fixture, not a sample" not in raw


def test_a_backup_taken_before_the_store_was_sealed_is_restored_sealed(backups, tmp_path, monkeypatch, capsys):  # noqa: F811
    """What a 6.7 server took: the files were in clear on its disk. The file is the same thing."""
    root = Path(settings.SAMPLE_STORE)
    held = plain(root)
    assert not any(path.read_bytes().startswith(sealed.MAGIC) for path in root.rglob("*") if path.is_file())
    set_phrase(backups)
    name = runner.take(now=T0)
    target = tmp_path / "restored-store"
    scratch = database.Scratch("scratch", separate_role=False).create()
    try:
        monkeypatch.setattr(database, "live_url", lambda: scratch.url)
        monkeypatch.setattr(settings, "SAMPLE_STORE", str(target))
        monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", PHRASE)
        assert restore.main(["restore", str(runner.file_of(name))]) == 0
        assert plain(target) == held
        assert all(p.read_bytes().startswith(sealed.MAGIC) for p in target.rglob("*") if p.is_file())
        assert "sealed under the store key of this server" in capsys.readouterr().err
    finally:
        scratch.drop()


def test_after_a_restore_the_row_of_the_store_is_this_hosts(another_host):
    """The row that came with the database speaks of the store of the old host; the server that
    starts on it must not take its own store for a stranger's."""
    path, _held, _target, _scratch = another_host
    with SessionLocal() as db:
        before = store_seal.read(db)
    assert before["state"] == store_seal.SEALED and before["keyId"] == sealed.Keyring.of(OLD_KEY).current.id.hex()
    # As it would be at the next start, were nothing done: the store key of this host is not the one written down.
    assert store_seal.key_problem() is not None
    assert restore.main(["restore", str(path)]) == 0
    with SessionLocal() as db:
        doc = store_seal.read(db)
    assert doc["keyId"] == sealed.Keyring.of(OTHER_KEY).current.id.hex() and doc["damaged"] == {}
    assert doc["state"] == "" and store_seal.key_problem() is None
    # Its first look at the store finds every file sealed, and writes it down.
    store_seal.forget()
    assert store_seal.convert_pass(now=T0 + 10**6, holder="the restored server")["state"] == store_seal.SEALED


def test_a_restore_with_a_wrong_passphrase_touches_no_file(another_host, monkeypatch, capsys):
    path, _held, target, _scratch = another_host
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", "not the passphrase")
    assert restore.main(["restore", str(path)]) == 1
    assert "not the passphrase the backup was made with" in capsys.readouterr().err
    assert not target.exists() or not any(target.iterdir())
