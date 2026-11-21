"""Recovery to a moment and the standby: everything that is logic.

The archive volume is a folder of the test, the recovery service is played by
a function that answers the requests as the script does, PostgreSQL's own
functions are replaced by what they would say, and the second host is the
SFTP server of the tests (``sftp_double.py``). What needs a real cluster (the
scripts of ``deploy/db``, a base backup, a replay) is proven by
``.github/scripts/recovery-proof.sh``.
"""

from __future__ import annotations

import base64
import gzip
import io
import json
import os
import socket
import time
import urllib.request
from pathlib import Path

import pytest
from sqlalchemy import select

from app.backups import container, offsite, runner
from app.backups import store as backup_store
from app.core import store
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AuditEntry, Lease, Mail, Notification, RecoveryBase, Sample, StoreCopy
from app.recovery import (
    agent,
    archive,
    config,
    envelope,
    files,
    gate,
    kept,
    layout,
    role,
    scheduler,
    ship,
    standby,
    status,
    tool,
    watch,
)
from app.recovery.remote import Remote

from .sftp_double import SftpDouble
from .test_backups import PHRASE, T0, quick_keys, set_phrase  # noqa: F401 - fixtures

STORE_KEY = "s" * 64
SEG = "0000000100000000000000"


def seg(number: int, timeline: int = 1) -> str:
    return layout.name_of(timeline, number)


@pytest.fixture()
def volume(admin, tmp_path, monkeypatch):
    """A server with an archive volume, a sealed store and a database that says it is PostgreSQL."""
    root = tmp_path / "wal-archive"
    for name in ("wal", "base", "requests", "results", "incoming", "restore"):
        (root / name).mkdir(parents=True)
    monkeypatch.setattr(settings, "WAL_ARCHIVE_DIR", str(root))
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(tmp_path / "store"))
    monkeypatch.setattr(settings, "BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setattr(settings, "STORE_KEY", STORE_KEY)
    (tmp_path / "store").mkdir()
    (tmp_path / "backups").mkdir()
    monkeypatch.setattr(archive, "postgres", lambda db: True)
    monkeypatch.setattr(archive, "database_bytes", lambda db: 10_000_000)
    monkeypatch.setattr(role, "in_recovery", lambda db: False)
    monkeypatch.setattr(ship, "position", lambda db: (seg(9), 9 * layout.SEGMENT_BYTES + 4096))
    monkeypatch.setattr(ship, "close_segment", lambda db: seg(9))
    return root


def segment(root: Path, number: int, timeline: int = 1, at: float | None = None, place: str = "wal") -> Path:
    path = root / place / (seg(number, timeline) + ".gz")
    path.write_bytes(gzip.compress(f"segment {number}".encode() * 50))
    if at is not None:
        os.utime(path, (at, at))
    return path


def base_folder(root: Path, label: str, start: int, end: int | None = None, timeline: int = 1, place: str = "base"):
    end = start if end is None else end
    folder = root / place / label
    folder.mkdir(parents=True)
    manifest = {
        "WAL-Ranges": [
            {
                "Timeline": timeline,
                "Start-LSN": f"0/{start * layout.SEGMENT_BYTES + 40:X}",
                "End-LSN": f"0/{end * layout.SEGMENT_BYTES + 300:X}",
            }
        ]
    }
    (folder / "backup_manifest").write_text(json.dumps(manifest), encoding="utf-8")
    (folder / "base.tar.gz").write_bytes(gzip.compress(b"the data " * 400))
    (folder / "pg_wal.tar.gz").write_bytes(gzip.compress(b"the log " * 40))
    return folder


def archiver(now: float, **changes) -> dict:
    found = {
        "mode": "on", "archived": 5, "lastWal": seg(8), "lastAt": now - 30, "failed": 0, "failedWal": "",
        "failedAt": 0.0, "at": now, "walFiles": 3, "walBytes": 48 * 2**20, "waiting": 0, "timeline": 1,
        "current": seg(9),
    }  # fmt: skip
    return found | changes


def play_agent(root: Path, now: float, fail: str = "", start: int = 3, test: dict | None = None) -> list[str]:
    """What the recovery service does with the requests that wait: a base backup is "taken", a
    pruning done, a test answered with ``test``."""
    handled = []
    (root / "results" / "alive").write_text(str(int(now)), encoding="ascii")
    for request in sorted((root / "requests").glob("*.req")):
        name = request.name[: -len(".req")]
        lines = dict(line.split("=", 1) for line in request.read_text().splitlines() if "=" in line)
        if name.startswith("base-"):
            if fail:
                answer = f"state=failed\nerror={fail}\n"
            else:
                base_folder(root, name, start)
                answer = "state=ok\nbytes=4321\nseconds=2\nverified=1\n"
        elif name.startswith("prune-"):
            removed = 0
            for path in (root / "wal").glob("*.gz"):
                if layout.is_segment(path.name[:24]) and path.name[:24] < lines.get("wal_before", ""):
                    path.unlink()
                    removed += 1
            keep = {line.split("=", 1)[1] for line in request.read_text().splitlines() if line.startswith("keep=")}
            for folder in (root / "base").iterdir():
                if folder.name not in keep:
                    for item in folder.iterdir():
                        item.unlink()
                    folder.rmdir()
            answer = f"state=ok\nsegments={removed}\nbases=0\n"
        else:
            answer = "".join(
                f"{key}={value}\n" for key, value in (test or {"state": "failed", "error": "none"}).items()
            )
        (root / "results" / f"{name}.result").write_text(answer, encoding="utf-8")
        request.unlink()
        handled.append(name)
    return handled


def sealed_file(name: str, data: bytes) -> Path:
    path = store.root() / name
    path.parent.mkdir(parents=True, exist_ok=True)
    store.write(path, data)
    return path


def notices() -> list[tuple[str, str]]:
    with SessionLocal() as db:
        return [(row.kind, row.text) for row in db.scalars(select(Notification).order_by(Notification.at))]


# --------------------------------------------------------------------------- #
# Names of segments, timelines                                                #
# --------------------------------------------------------------------------- #
def test_segment_names_and_positions():
    assert layout.parse("0000000200000001000000FF") == (2, 256 + 255)
    assert layout.name_of(2, 511) == "0000000200000001000000FF"
    assert layout.next_name("0000000100000000000000FF") == "000000010000000100000000"
    assert layout.lsn("1/4008670") == 0x100000000 + 0x4008670
    assert layout.segment_of(1, "0/4008670") == seg(4)
    assert not layout.is_segment("00000002.history") and layout.HISTORY.match("00000002.history")
    with pytest.raises(ValueError):
        layout.parse("nonsense")


def test_a_missing_segment_is_found_and_a_new_timeline_is_not_one():
    assert layout.gap([seg(3), seg(4), seg(5)]) is None
    assert layout.gap([seg(3), seg(5)]) == seg(4)
    assert layout.gap([seg(3), seg(4), seg(4, 2), seg(5, 2)]) is None
    assert layout.gap([]) is None


def test_the_history_of_a_timeline_says_what_is_part_of_its_past(volume):
    (volume / "wal" / "00000002.history.gz").write_bytes(
        gzip.compress(b"1\t0/5000000\tbefore 2026-11-21 10:00:00+00\n")
    )
    history = layout.read_history(2)
    assert history == {1: 0x5000000}
    assert layout.on_history(2, 0x9000000, 2, history)
    assert layout.on_history(1, 0x4000000, 2, history)
    assert not layout.on_history(1, 0x6000000, 2, history), "written on the old timeline after it was left"
    assert layout.read_history(1) == {} and layout.read_history(3) is None
    # Without the file nothing is refused on a guess.
    assert layout.on_history(1, 0x6000000, 3, None)


# --------------------------------------------------------------------------- #
# The settings                                                                #
# --------------------------------------------------------------------------- #
def test_the_settings_have_defaults_and_refuse_what_they_cannot_keep(admin):
    with SessionLocal() as db:
        assert config.read(db)["keepDays"] == 2 and config.read(db)["base"]["every"] == "day"
        changed = config.write(db, {"keepDays": 5, "lagMinutes": 30, "base": {"at": "01:15"}, "name": " nik-a "})
        assert changed == [
            "when the base backups are taken",
            "how far back one can go",
            "the delay that is warned about",
            "the name of this server",
        ]
        db.commit()
        assert config.out(db)["base"]["at"] == "01:15" and config.out(db)["name"] == "nik-a"
        assert config.write(db, {"keepDays": 5}) == []
        for wrong in ({"keepDays": 0}, {"lagMinutes": 1}, {"testEveryHours": "often"}, {"base": {"at": "25:00"}}):
            with pytest.raises(config.ConfigError):
                config.write(db, wrong)


def test_the_routes_of_the_recovery(admin):
    shown = admin.get("/api/recovery").json()
    assert shown["available"] is False and shown["role"] == "primary"
    saved = admin.put("/api/recovery/settings", json={"keepDays": 4})
    assert saved.status_code == 200
    with SessionLocal() as db:
        assert config.read(db)["keepDays"] == 4
        said = [row.details for row in db.scalars(select(AuditEntry).where(AuditEntry.action == "recovery.settings"))]
    assert said == ["Changed the recovery to a moment: how far back one can go"]
    assert admin.put("/api/recovery/settings", json={"keepDays": 400}).status_code == 422
    assert admin.post("/api/recovery/base").status_code == 409, "no archive on this server"
    assert admin.post("/api/recovery/test").status_code == 409


# --------------------------------------------------------------------------- #
# What is kept                                                                #
# --------------------------------------------------------------------------- #
DAY = 86400.0


def test_the_base_backups_of_the_days_one_can_go_back_in_are_kept_and_the_one_before_them():
    bases = [(f"b{day}", T0 - day * DAY) for day in (5, 4, 3, 2, 1, 0)]
    keep, drop = archive.retention(bases, T0 + 3600, 2)
    assert keep == ["b2", "b1", "b0"], "b2 is what a recovery to two days ago starts from"
    assert drop == ["b5", "b4", "b3"]
    assert archive.retention(bases[:1], T0 + 3600, 2) == (["b5"], []), "the only one is never dropped"
    assert archive.retention([], T0, 2) == ([], [])
    keep, drop = archive.retention(bases, T0 + 3600, 1)
    assert keep == ["b1", "b0"] and drop == ["b5", "b4", "b3", "b2"]


# --------------------------------------------------------------------------- #
# The envelope                                                                #
# --------------------------------------------------------------------------- #
def test_a_segment_is_sealed_and_opens_with_the_passphrase_alone(tmp_path):
    source = tmp_path / (seg(4) + ".gz")
    source.write_bytes(gzip.compress(b"everything the database holds " * 1000))
    sealer = envelope.Sealer()
    key = sealer.key(PHRASE, T0)
    assert sealer.key(PHRASE, T0 + 3600) is key, "derived once for the files of the next hours"
    assert sealer.key(PHRASE, T0 + envelope.KEY_LIFE + 1) is not key
    target = tmp_path / "sealed.nikwal"
    envelope.seal_file(source, target, key, {"kind": "wal", "name": seg(4)}, source.name)
    raw = target.read_bytes()
    assert b"everything the database" not in raw and source.read_bytes()[:40] not in raw
    assert container.peek(target)["kind"] == "wal" and container.peek(target)["name"] == seg(4)
    out = tmp_path / "out"
    out.mkdir()
    opener = envelope.Opener(container.Secrets(passphrases=(PHRASE,)))
    with open(target, "rb") as handle:
        envelope.unseal(handle, opener, out, expect="wal")
    assert (out / source.name).read_bytes() == source.read_bytes()
    assert len(opener._derived) == 1
    # A file of another kind, a wrong passphrase and a damaged file leave nothing behind.
    with open(target, "rb") as handle, pytest.raises(container.BackupError, match="not a base"):
        envelope.unseal(handle, opener, out, expect="base")
    (out / source.name).unlink()
    with open(target, "rb") as handle, pytest.raises(container.WrongKey):
        envelope.unseal(handle, container.Secrets(passphrases=("another passphrase",)), out)
    target.write_bytes(raw[:-20] + bytes(20))
    with open(target, "rb") as handle, pytest.raises(container.Damaged):
        envelope.unseal(handle, opener, out)
    assert list(out.iterdir()) == []


def test_the_overhead_of_an_envelope_is_small(tmp_path):
    source = tmp_path / "s.gz"
    source.write_bytes(os.urandom(16_500))  # a segment closed by the timer, compressed
    target = tmp_path / "s.nikwal"
    envelope.seal_file(source, target, envelope.Sealer().key(PHRASE), {"kind": "wal", "name": seg(1)}, "s.gz")
    assert target.stat().st_size - source.stat().st_size < 700


def test_a_changed_passphrase_is_used_after_the_segment_that_carries_the_change():
    change = {"mark": "new", "upTo": seg(7), "earlier": "old"}
    assert envelope.passphrase_for(seg(6), "new one", change, "old one") == "old one"
    assert envelope.passphrase_for(seg(7), "new one", change, "old one") == "old one"
    assert envelope.passphrase_for(seg(8), "new one", change, "old one") == "new one"
    assert envelope.passphrase_for(seg(6), "new one", change, None) == "new one", "no earlier one to go on with"
    assert envelope.passphrase_for(seg(6), "the one", {"mark": "x"}, None) == "the one"
    one, two = envelope.fingerprint("the first passphrase"), envelope.fingerprint("the second passphrase")
    assert one != two and "passphrase" not in one and len(one) == 16


# --------------------------------------------------------------------------- #
# Deleted files are kept                                                      #
# --------------------------------------------------------------------------- #
def test_a_deleted_file_is_kept_until_no_recovery_can_go_back_to_it(volume, monkeypatch):
    name = "a" * 64 + ".bin"
    path = sealed_file(name, b"a harmless fixture")
    monkeypatch.setattr(kept.time, "time", lambda: T0)
    store.remove(path)
    assert not path.exists()
    aside = store.root() / ".kept" / str(int(T0)) / name
    assert aside.is_file()
    assert kept.usage() == {"files": 1, "bytes": aside.stat().st_size, "oldest": int(T0)}
    # A folder goes whole; previews and what a transfer left are really removed.
    sealed_file("_captures/c1/capture.pcap", b"packets")
    sealed_file("_previews/p1.png", b"a page")
    store.remove_tree(store.root() / "_captures" / "c1")
    store.remove(store.root() / "_previews" / "p1.png")
    assert (store.root() / ".kept" / str(int(T0)) / "_captures" / "c1" / "capture.pcap").is_file()
    assert not (store.root() / ".kept" / str(int(T0)) / "_previews").exists()
    # Nothing goes while a recovery can still reach back to before the deletion.
    assert kept.purge(T0 - 10) == 0 and aside.exists()
    assert kept.purge(T0 + 10) == 1 and not aside.exists()
    assert kept.usage()["files"] == 0


def test_without_an_archive_a_deleted_file_is_removed(admin, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(tmp_path / "store"))
    monkeypatch.setattr(settings, "STORE_KEY", STORE_KEY)
    (tmp_path / "store").mkdir()
    path = sealed_file("b" * 64 + ".bin", b"x")
    store.remove(path)
    assert not path.exists() and not (tmp_path / "store" / ".kept").exists()


def test_a_kept_file_comes_back_to_its_place_and_opens(volume, monkeypatch):
    name = "c" * 64 + ".mail"
    path = sealed_file(name, b"Subject: kept\n\nbody\n")
    clock = [T0]
    monkeypatch.setattr(kept.time, "time", lambda: clock[0])
    store.remove(path)
    assert kept.find(name, T0 - 60).parent.name == str(int(T0))
    assert kept.put_back(name, T0 - 60) is True
    assert store.read_bytes(path) == b"Subject: kept\n\nbody\n", "sealed under the path it had: it opens there"
    assert kept.put_back("d" * 64 + ".bin", T0) is False
    # Deleted twice: the copy set aside first after the moment is the file as it was then.
    store.remove(path)
    sealed_file(name, b"written again")
    clock[0] = T0 + 500
    store.remove(path)
    assert kept.find(name, T0 + 100).parent.name == str(int(T0 + 500))
    assert kept.find(name, T0 - 100).parent.name == str(int(T0))


def test_the_backups_and_the_census_of_the_store_know_the_kept_files(volume, monkeypatch):
    from app import storage, store_seal

    sealed_file("e" * 64 + ".bin", b"stays")
    gone = sealed_file("f" * 64 + ".bin", b"deleted")
    monkeypatch.setattr(kept.time, "time", lambda: T0)
    store.remove(gone)
    names = sorted(name for name, _path in store_seal._files(store.root()))
    assert names == ["e" * 64 + ".bin", "f" * 64 + ".bin"], "a kept file is named as it was: it follows a change of key"
    out = io.BytesIO()
    writer = container.Writer(out, container.Key.new(container.PASSPHRASE, PHRASE), {"kind": "full"})
    assert backup_store.pack(writer, store.root()) == {"files": 1, "bytes": 5}, (
        "a backup holds the store, not what was deleted"
    )
    with SessionLocal() as db:
        groups = {group["id"]: group for group in storage.usage(db)["groups"]}
    assert groups["kept"]["files"] == 1 and groups["kept"]["label"] == "Deleted, kept for recovery"


# --------------------------------------------------------------------------- #
# The store beside a database that goes back                                  #
# --------------------------------------------------------------------------- #
def add_rows(**shas) -> None:
    with SessionLocal() as db:
        for sha in shas.get("samples", ()):
            db.add(Sample(sha256=sha, sha1="1" * 40, md5="2" * 32, size=1, created_at=runner.iso(T0), analysis={}))
        for sha in shas.get("mails", ()):
            db.add(Mail(sha256=sha, size=1, created_at=runner.iso(T0), analysis={}))
        db.commit()


def test_after_a_recovery_the_store_is_held_against_the_database(volume, monkeypatch):
    here, deleted, lost = "1" * 64, "2" * 64, "3" * 64
    sealed_file(f"{here}.bin", b"here")
    path = sealed_file(f"{deleted}.bin", b"deleted since")
    monkeypatch.setattr(kept.time, "time", lambda: T0 + 600)
    store.remove(path)
    add_rows(samples=(here, deleted, lost))
    with SessionLocal() as db:
        found = files.reconcile(db, T0)
    assert found["putBack"] == [f"{deleted}.bin"] and found["missing"] == [f"{lost}.bin"] and found["named"] == 3
    assert store.read_bytes(path) == b"deleted since"


def test_the_rows_of_the_copies_follow_the_store(volume):
    one = sealed_file("4" * 64 + ".bin", b"one")
    sealed_file("_captures/c9/log.jsonl", b"{}\n")
    sealed_file("_previews/p.png", b"not copied: made again when asked for")
    (store.root() / "clear.bin").write_bytes(b"in clear: not sent")
    (store.root() / "half.bin.part").write_bytes(b"half")
    with SessionLocal() as db:
        assert files.scan(db, T0) == {"new": 2, "changed": 0, "gone": 0}
        db.commit()
        assert sorted(db.scalars(select(StoreCopy.name))) == ["4" * 64 + ".bin", "_captures/c9/log.jsonl"]
        assert files.scan(db, T0 + 60) == {"new": 0, "changed": 0, "gone": 0}
        assert files.waiting(db) == {
            "files": 2,
            "bytes": sum(r.size for r in db.scalars(select(StoreCopy))),
            "copied": 0,
        }
        # Written again: sent again. Deleted: noted, and its copy is removed only when no
        # recovery can go back to before the deletion.
        for row in db.scalars(select(StoreCopy)):
            row.state = "copied"
        db.commit()
        sealed_file("_captures/c9/log.jsonl", b"{}\n{}\n")
        one.unlink()
        assert files.scan(db, T0 + 120) == {"new": 0, "changed": 1, "gone": 1}
        db.commit()
        assert db.get(StoreCopy, "_captures/c9/log.jsonl").state == "pending"
        assert files.due_removals(db, T0 + 100) == [] and files.due_removals(db, T0 + 130) == ["4" * 64 + ".bin"]
        # Uploaded again after it was deleted: a file of the store again.
        sealed_file("4" * 64 + ".bin", b"one")
        assert files.scan(db, T0 + 180)["changed"] == 1
        assert db.get(StoreCopy, "4" * 64 + ".bin").gone_at is None
        db.commit()
        assert files.send_again(db) == 2


# --------------------------------------------------------------------------- #
# The recovery service                                                        #
# --------------------------------------------------------------------------- #
def test_a_request_is_a_file_and_its_answer_too(volume):
    assert agent.alive(T0) is None and not agent.running(T0)
    agent.ask("base-20261121-033000")
    agent.ask("test-ab12", [("base", "base-20261121-033000"), ("target", "2026-11-21 10:00:00.000000+00")])
    assert (volume / "requests" / "test-ab12.req").read_text() == (
        "base=base-20261121-033000\ntarget=2026-11-21 10:00:00.000000+00\n"
    )
    assert agent.asked("base-20261121-033000") and agent.answer("base-20261121-033000") is None
    for wrong in ("base-../../etc", "rm -rf", "test-UPPER"):
        with pytest.raises(agent.AgentError):
            agent.ask(wrong)
    with pytest.raises(agent.AgentError, match="would not read"):
        agent.ask("test-ab13", [("target", "2026; rm -rf /")])
    assert play_agent(volume, T0) == ["base-20261121-033000", "test-ab12"]
    assert agent.answer("base-20261121-033000") == {"state": "ok", "bytes": "4321", "seconds": "2", "verified": "1"}
    assert agent.alive(T0 + 20) == 20 and agent.running(T0 + 20) and not agent.running(T0 + 500)


# --------------------------------------------------------------------------- #
# The pass of the API process                                                 #
# --------------------------------------------------------------------------- #
def bases() -> list[RecoveryBase]:
    with SessionLocal() as db:
        return list(db.scalars(select(RecoveryBase).order_by(RecoveryBase.created_at)))


def state_of(row_id: int) -> dict:
    with SessionLocal() as db:
        return config.held(db, row_id)


Disk = type("Disk", (), {"total": 100 * 2**30, "free": 50 * 2**30, "used": 50 * 2**30})


def test_the_first_base_backup_is_taken_at_once_and_then_by_the_schedule(volume, monkeypatch):
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0))
    assert archive.tick(T0, usage=lambda _p: Disk) == [], "the recovery service is not there yet: nothing is asked"
    play_agent(volume, T0)
    did = archive.tick(T0 + 5, usage=lambda _p: Disk)
    label = "base-20261120-120005"
    assert did == [f"base:{label}"] and bases()[0].state == "requested"
    assert archive.tick(T0 + 10, usage=lambda _p: Disk) == [], "one at a time"
    play_agent(volume, T0 + 12, start=6)
    assert f"done:{label}" in archive.tick(T0 + 15, usage=lambda _p: Disk)
    row = bases()[0]
    assert row.state == "done" and row.start_wal == seg(6) and row.timeline == 1 and row.facts["verified"] is True
    assert row.size > 0 and row.offsite_state == "", "no second host is set"
    assert state_of(config.ARCHIVE_SETTINGS_ID)["oldest"]["base"] == label
    with SessionLocal() as db:
        said = [e.details for e in db.scalars(select(AuditEntry).where(AuditEntry.action == "recovery.base"))]
    assert said and "replays the log from " + seg(6) in said[0]
    # Nothing more today; the next day at 03:30 UTC the schedule asks for one.
    assert not [x for x in archive.tick(T0 + 3600, usage=lambda _p: Disk) if x.startswith("base:")]
    tomorrow = T0 + 16 * 3600
    play_agent(volume, tomorrow)
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(tomorrow))
    assert [x for x in archive.tick(tomorrow, usage=lambda _p: Disk) if x.startswith("base:")]


def test_a_base_backup_that_fails_is_said_and_tried_again_an_hour_later(volume, monkeypatch):
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0))
    play_agent(volume, T0)
    archive.tick(T0, usage=lambda _p: Disk)
    play_agent(volume, T0 + 5, fail="pg_basebackup: error: no space left on device")
    assert [x for x in archive.tick(T0 + 10, usage=lambda _p: Disk) if x.startswith("failed:")]
    assert bases()[0].state == "failed" and "no space left" in bases()[0].error
    with SessionLocal() as db:
        assert "no space left on device" in watch.problems(db, T0 + 20)["base"]
    play_agent(volume, T0 + 600)
    assert not [x for x in archive.tick(T0 + 600, usage=lambda _p: Disk) if x.startswith("base:")]
    play_agent(volume, T0 + 3700)
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0 + 3700))
    assert [x for x in archive.tick(T0 + 3700, usage=lambda _p: Disk) if x.startswith("base:")]


def test_no_base_backup_is_asked_for_without_room(volume, monkeypatch):
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0))
    play_agent(volume, T0)
    tight = type("Disk", (), {"total": 2**30, "free": 100 * 2**20, "used": 0})
    assert archive.tick(T0, usage=lambda _p: tight) == []
    assert "none is taken until there is room" in state_of(config.ARCHIVE_SETTINGS_ID)["noRoom"]
    with SessionLocal() as db:
        assert "room" in watch.problems(db, T0)
        monkeypatch.setattr(archive.shutil, "disk_usage", lambda _p: tight)
        with pytest.raises(agent.AgentError, match="room"):
            archive.ask_base(db, "admin", T0)


def done_base(label: str, start: int, at: float, root: Path, timeline: int = 1, **more) -> None:
    base_folder(root, label, start, timeline=timeline)
    with SessionLocal() as db:
        db.add(
            RecoveryBase(
                id=label, state="done", created_at=runner.iso(at), finished_at=runner.iso(at), size=4000,
                timeline=timeline, start_wal=seg(start, timeline), requested_by="schedule", local=True,
                facts={"verified": True, "endTimeline": timeline, "endLsn": start * layout.SEGMENT_BYTES + 300},
                offsite={}, **more,
            )
        )  # fmt: skip
        db.commit()


def test_the_retention_drops_old_base_backups_and_the_log_before_the_oldest_kept(volume, monkeypatch):
    now = T0 + 5 * DAY
    for day, start in ((0, 2), (1, 10), (2, 20), (3, 30), (4, 40)):
        done_base(f"base-2026112{day}-033000", start, T0 + day * DAY, volume)
    for number in (1, 5, 19, 20, 21, 45):
        segment(volume, number)
    (volume / "wal" / "00000002.history.gz").write_bytes(gzip.compress(b"1\t0/FF000000\tno reason\n"))
    path = sealed_file("9" * 64 + ".bin", b"deleted long ago")
    monkeypatch.setattr(kept.time, "time", lambda: T0)
    store.remove(path)
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(now, lastWal=seg(45), current=seg(46)))
    play_agent(volume, now)
    did = archive.tick(now, usage=lambda _p: Disk)
    assert [x for x in did if x.startswith("dropped:")] == [
        "dropped:base-20261120-033000",
        "dropped:base-20261121-033000",
    ]
    assert "purged:1" in did, "what was deleted before the oldest moment one can go back to is really removed"
    play_agent(volume, now + 1)
    assert sorted(p.name[:24] for p in (volume / "wal").glob("0000*.gz") if layout.is_segment(p.name[:24])) == [
        seg(20), seg(21), seg(45),
    ]  # fmt: skip
    assert (volume / "wal" / "00000002.history.gz").exists(), "the files of the timelines are kept for ever"
    assert sorted(p.name for p in (volume / "base").iterdir()) == [
        "base-20261122-033000", "base-20261123-033000", "base-20261124-033000",
        "base-20261125-120000",  # the one the schedule asked for in the same pass: never pruned
    ]  # fmt: skip
    assert [row.id for row in bases() if row.state == "done"] == [
        "base-20261122-033000", "base-20261123-033000", "base-20261124-033000",
    ]  # fmt: skip
    oldest = state_of(config.ARCHIVE_SETTINGS_ID)["oldest"]
    assert oldest == {"base": "base-20261122-033000", "at": T0 + 2 * DAY, "wal": seg(20)}


def test_after_going_back_a_base_backup_is_taken_at_once_and_the_abandoned_ones_go(volume, monkeypatch):
    done_base("base-20261120-033000", 2, T0, volume)
    done_base("base-20261121-033000", 9, T0 + DAY, volume)  # taken after the moment the server went back to
    (volume / "wal" / "00000002.history.gz").write_bytes(gzip.compress(b"1\t0/5000000\tbefore the mistake\n"))
    now = T0 + DAY + 3600
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(now, timeline=2, lastWal=seg(5, 2)))
    play_agent(volume, now)
    did = archive.tick(now, usage=lambda _p: Disk)
    assert "off-history:base-20261121-033000" in did
    assert [x for x in did if x.startswith("base:")], "the new timeline needs a base backup of its own"
    assert [row.id for row in bases() if row.state == "done"] == ["base-20261120-033000"]


def test_a_base_backup_found_on_the_disk_with_no_row_is_adopted(volume, monkeypatch):
    base_folder(volume, "base-20261119-033000", 4)
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0))
    play_agent(volume, T0)
    assert "adopted:base-20261119-033000" in archive.tick(T0, usage=lambda _p: Disk)
    assert bases()[0].start_wal == seg(4) and bases()[0].facts["adopted"] is True


# --------------------------------------------------------------------------- #
# The proof                                                                   #
# --------------------------------------------------------------------------- #
def audit_entries(count: int, start: float) -> list[tuple[int, str]]:
    from app.core import audit

    with SessionLocal() as db:
        for number in range(count):
            audit.record(db, "tester", "test.entry", f"entry {number}", target="t")
            db.commit()
        rows = list(db.scalars(select(AuditEntry).where(AuditEntry.action == "test.entry").order_by(AuditEntry.seq)))
        for number, row in enumerate(rows):
            row.at = runner.iso(start + number * 100)
        found = [(row.seq, row.hash) for row in rows]
        db.rollback()
    return found


def test_the_recovery_test_is_asked_for_and_held_against_this_server(volume, monkeypatch):
    done_base("base-20261120-110000", 3, T0 - 3600, volume)
    now = T0
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(now))
    play_agent(volume, now)
    did = archive.tick(now, usage=lambda _p: Disk)
    assert "test-asked:base-20261120-110000" in did
    running = state_of(config.ARCHIVE_SETTINGS_ID)["test"]
    assert running["target"] == now - 30 - archive.TEST_BEFORE_END, "a minute before the last segment archived"
    request = (volume / "requests" / f"test-{running['id']}.req").read_text()
    assert "base=base-20261120-110000\n" in request and "wait=600" in request
    assert f"target={archive.stamp_text(running['target'])}" in request
    with SessionLocal() as db:
        from app.auditlog import chain

        number, hashed = chain.head(db)
    play_agent(volume, now + 5, test={
        "state": "ok", "replayed": running["target"] - 2, "revision": "0052_recovery", "audit_seq": number,
        "audit_hash": hashed, "seconds": 7,
    })  # fmt: skip
    assert "test:passed" in archive.tick(now + 10, usage=lambda _p: Disk)
    proven = state_of(config.ARCHIVE_SETTINGS_ID)["proven"]
    assert proven["state"] == "passed" and proven["base"] == "base-20261120-110000" and proven["auditSeq"] == number
    with SessionLocal() as db:
        said = [e.details for e in db.scalars(select(AuditEntry).where(AuditEntry.action == "recovery.test"))]
    assert said and said[-1].startswith("Recovery proven: base-20261120-110000 and the archive replayed to ")
    # Not again before a day has passed, unless somebody asks.
    play_agent(volume, now + 3600)
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(now + 3600))
    assert not [x for x in archive.tick(now + 3600, usage=lambda _p: Disk) if x.startswith("test-asked")]
    with SessionLocal() as db:
        archive.ask_test_now(db)
        db.commit()
    play_agent(volume, time.time())
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(time.time()))
    assert [x for x in archive.tick(usage=lambda _p: Disk) if x.startswith("test-asked")]


def test_a_recovered_database_that_is_not_this_one_at_that_moment_fails_the_proof(volume):
    from app.auditlog import chain

    entries = audit_entries(4, T0)
    with SessionLocal() as db:
        for seq, _hash in entries:
            row = db.scalars(select(AuditEntry).where(AuditEntry.seq == seq)).one()
            row.at = runner.iso(T0 + (seq - entries[0][0]) * 100)
        db.flush()
        running = {"target": T0 + 250, "base": "base-x"}
        good = {"state": "ok", "replayed": str(T0 + 240), "revision": "r", "audit_seq": str(entries[2][0]),
                "audit_hash": entries[2][1], "seconds": "3"}  # fmt: skip
        assert archive.judge(db, running, good)[0] is True
        # Another hash for the same entry: the log was rewritten on one side.
        ok, why, _facts = archive.judge(db, running, good | {"audit_hash": "0" * 64})
        assert not ok and "is not the same in the recovered database" in why
        # The recovered log stops long before the moment: entries are missing.
        late = {"target": T0 + 2000, "base": "base-x"}
        ok, why, _facts = archive.judge(db, late, good | {"audit_seq": str(entries[0][0]), "audit_hash": entries[0][1]})
        assert not ok and "lacks entries of the audit log made before the moment" in why
        # An entry this server never had.
        ok, why, _facts = archive.judge(db, running, good | {"audit_seq": str(chain.head(db)[0] + 50)})
        assert not ok and "which this server does not have" in why
        assert archive.judge(db, running, good | {"replayed": str(T0 + 900)})[1].startswith(
            "The scratch server replayed past"
        )
        assert archive.judge(db, running, {"state": "failed", "error": "the archive does not reach the moment"}) == (
            False, "the archive does not reach the moment", {"seconds": 0},
        )  # fmt: skip
        assert "holds no database of Nik" in archive.judge(db, running, good | {"revision": ""})[1]
        db.rollback()


def test_a_failed_proof_is_told_and_one_that_never_answers_too(volume, monkeypatch):
    done_base("base-20261120-110000", 3, T0 - 3600, volume)
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0))
    play_agent(volume, T0)
    archive.tick(T0, usage=lambda _p: Disk)
    play_agent(volume, T0 + 5, test={"state": "failed", "error": "the archive does not reach the moment asked for"})
    assert "test:failed" in archive.tick(T0 + 10, usage=lambda _p: Disk)
    with SessionLocal() as db:
        found = watch.problems(db, T0 + 20)
        assert "the archive does not reach the moment" in found["test"]
        assert "problem:test" in watch.record(db, found, T0 + 20)
        db.commit()
    assert ("recovery.problem", notices()[-1][1]) == notices()[-1] and "recovery test" in notices()[-1][1]
    # No answer at all: counted as failed after a quarter of an hour.
    with SessionLocal() as db:
        state = config.held(db, config.ARCHIVE_SETTINGS_ID)
        state["test"] = {"id": "zz", "base": "base-20261120-110000", "target": T0, "askedAt": T0, "state": "running"}
        assert archive.settle_test(db, state, T0 + 60) is None
        assert archive.settle_test(db, state, T0 + archive.TEST_WAIT + 1) == "failed"
        assert "did not answer" in state["tested"]["error"]


# --------------------------------------------------------------------------- #
# The watch                                                                   #
# --------------------------------------------------------------------------- #
def test_an_archive_that_is_stuck_is_told_long_before_the_disk_is_full(volume, monkeypatch):
    stuck = archiver(T0, failedAt=T0 - 10, failedWal=seg(9), lastAt=T0 - 400, walBytes=900 * 2**20, waiting=50)
    monkeypatch.setattr(archive, "archiver", lambda db: stuck)
    play_agent(volume, T0)
    archive.tick(T0, usage=lambda _p: Disk)
    with SessionLocal() as db:
        assert "archive" not in watch.problems(db, T0 + 60), "one failure between two tries is nothing"
    monkeypatch.setattr(archive, "archiver", lambda db: stuck | {"at": T0 + 400})
    archive.tick(T0 + 400, usage=lambda _p: Disk)
    with SessionLocal() as db:
        found = watch.problems(db, T0 + 400)
        assert "50 segments wait (800 MB) and its log takes 900 MB on the disk of the database" in found["archive"]
        assert seg(9) in found["archive"]
        assert watch.record(db, found, T0 + 400) == [f"problem:{name}" for name in found]
        db.commit()
        assert watch.record(db, found, T0 + 460) == [], "told once"
        db.commit()
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0 + 500))
    archive.tick(T0 + 500, usage=lambda _p: Disk)
    with SessionLocal() as db:
        found = watch.problems(db, T0 + 500)
        assert "archive" not in found
        assert "solved:archive" in watch.record(db, found, T0 + 500)
        db.commit()
    assert ("recovery.solved", "PostgreSQL hands its log to the archive again.") in notices()


def test_an_archive_that_is_off_and_a_service_that_is_gone_are_problems(volume, monkeypatch):
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0, mode="off"))
    archive.tick(T0, usage=lambda _p: Disk)
    with SessionLocal() as db:
        assert list(watch.problems(db, T0)) == ["archive-off"]
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0))
    archive.tick(T0 + 5, usage=lambda _p: Disk)
    with SessionLocal() as db:
        assert "service" in watch.problems(db, T0 + 5), "it never answered"
    play_agent(volume, T0 + 10)
    with SessionLocal() as db:
        assert "service" not in watch.problems(db, T0 + 20)
        assert "service" in watch.problems(db, T0 + 10 + watch.SERVICE_AFTER + 1)


# --------------------------------------------------------------------------- #
# The delay of the second host                                                #
# --------------------------------------------------------------------------- #
def test_the_delay_is_the_time_since_the_last_segment_sent_was_closed():
    shipped = {"wal": seg(7), "closedAt": T0}
    end = 8 * layout.SEGMENT_BYTES
    assert ship.delay(None, seg(8), end, T0) == {"seconds": None, "bytes": None, "safeUntil": None}
    # Nothing written since that segment: nothing is behind.
    assert ship.delay(shipped, seg(8), end + 40, T0 + 500) == {"seconds": 0.0, "bytes": 0, "safeUntil": T0 + 500}
    behind = ship.delay(shipped, seg(8), end + 70_000, T0 + 90)
    assert behind == {"seconds": 90.0, "bytes": 70_000, "safeUntil": T0}
    two = ship.delay(shipped, seg(9), end + layout.SEGMENT_BYTES + 5, T0 + 700)
    assert two["seconds"] == 700.0 and two["bytes"] == layout.SEGMENT_BYTES + 5
    # Another timeline since: the time is known, the bytes are not counted across it.
    assert ship.delay(shipped, seg(8, 2), end + 100, T0 + 60) == {"seconds": 60.0, "bytes": None, "safeUntil": T0}


# --------------------------------------------------------------------------- #
# The copies on the second host                                               #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def pair(volume, tmp_path, monkeypatch):
    """The first host with a second one: an SFTP account, a passphrase, the destination set."""
    with SftpDouble(tmp_path / "second-host") as server:
        monkeypatch.setattr(
            offsite.Sftp, "connect", lambda self: socket.create_connection(("127.0.0.1", server.port), 10)
        )
        monkeypatch.setattr(offsite.time, "sleep", lambda _seconds: None)
        yield volume, server


def set_destination(client, server) -> None:
    set_phrase(client)
    saved = client.put(
        "/api/backups/settings",
        json={
            "destination": {
                "kind": "sftp", "host": "second.nik.example", "port": 22, "user": server.user, "auth": "key",
                "secret": server.client_pem, "hostKey": server.host_line, "path": "/nik-copies",
            }
        },
    )  # fmt: skip
    assert saved.status_code == 200, saved.text


def there(server: SftpDouble, folder: str = "") -> list[str]:
    place = server.root / "nik-copies" / "recovery" / folder
    return sorted(path.name for path in place.iterdir()) if place.is_dir() else []


def test_nothing_is_sent_until_a_passphrase_and_a_destination_are_set(volume, admin):
    segment(volume, 3)
    assert ship.ship(T0) == []
    with SessionLocal() as db:
        assert ship.status(db, T0)["on"] is False


def test_the_log_is_sent_in_order_sealed_and_checked(pair, admin):
    volume, server = pair
    set_destination(admin, server)
    for number in (3, 4, 5):
        segment(volume, number, at=T0 + number * 10)
    did = ship.ship(T0 + 100)
    assert did[:1] == ["destination:new"] and [x for x in did if x.startswith("wal:")] == [
        f"wal:{seg(3)}", f"wal:{seg(4)}", f"wal:{seg(5)}",
    ]  # fmt: skip
    assert [name for name in there(server, "wal")] == [f"{seg(n)}.nikwal" for n in (3, 4, 5)]
    raw = (server.root / "nik-copies" / "recovery" / "wal" / f"{seg(4)}.nikwal").read_bytes()
    assert b"segment 4" not in raw and gzip.compress(b"segment 4" * 50)[:30] not in raw
    out = volume / "incoming"
    with open(server.root / "nik-copies" / "recovery" / "wal" / f"{seg(4)}.nikwal", "rb") as handle:
        envelope.unseal(handle, container.Secrets(passphrases=(PHRASE,)), out, expect="wal")
    assert (out / f"{seg(4)}.gz").read_bytes() == (volume / "wal" / f"{seg(4)}.gz").read_bytes()
    state = state_of(config.SHIP_SETTINGS_ID)
    assert state["shipped"]["wal"] == seg(5) and state["shipped"]["closedAt"] == T0 + 50 and state["sent"] == 3
    assert state["link"]["ok"] is True
    # The heartbeat says where the copies are; nothing is sent twice.
    beat = json.loads((server.root / "nik-copies" / "recovery" / "heartbeat.json").read_text())
    assert beat["lastWal"] == seg(5) and beat["generation"] == 1 and beat["archiveTimeout"] == settings.ARCHIVE_TIMEOUT
    assert [x for x in ship.ship(T0 + 105) if x.startswith("wal:")] == []
    segment(volume, 6, at=T0 + 200)
    (volume / "wal" / "00000002.history.gz").write_bytes(gzip.compress(b"1\t0/6000000\tr\n"))
    assert sorted(x for x in ship.ship(T0 + 210) if x.startswith("wal:")) == [f"wal:{seg(6)}", "wal:00000002.history"]
    with SessionLocal() as db:
        seen = ship.status(db, T0 + 260)
    assert seen["on"] and seen["behind"]["seconds"] == 60.0 and seen["where"].endswith("/nik-copies/recovery")


def test_a_base_backup_is_sealed_straight_onto_the_second_host_and_removed_with_the_retention(pair, admin):
    volume, server = pair
    set_destination(admin, server)
    done_base("base-20261120-110000", 3, T0 - 3600, volume, offsite_state="pending")
    did = ship.ship(T0)
    assert "base:base-20261120-110000" in did
    sealed = server.root / "nik-copies" / "recovery" / "base" / "base-20261120-110000.nikbak"
    header = container.peek(sealed)
    assert header["kind"] == "base" and header["startWal"] == seg(3) and header["timeline"] == 1
    assert b"the data" not in sealed.read_bytes()
    out = volume / "restore" / "x"
    out.mkdir()
    with open(sealed, "rb") as handle:
        envelope.unseal(handle, container.Secrets(passphrases=(PHRASE,)), out, expect="base")
    assert sorted(p.name for p in out.iterdir()) == ["backup_manifest", "base.tar.gz", "pg_wal.tar.gz"]
    assert gzip.decompress((out / "base.tar.gz").read_bytes()) == b"the data " * 400
    row = bases()[0]
    assert row.offsite_state == "copied" and row.offsite["bytes"] == sealed.stat().st_size
    with SessionLocal() as db:
        db.get(RecoveryBase, row.id).offsite_state = "delete"
        db.commit()
    assert "base-removed:base-20261120-110000" in ship.ship(T0 + 10)
    assert there(server, "base") == [] and bases() == []


def test_the_files_of_the_store_are_sent_as_they_are_on_the_disk_and_their_removal_is_delayed(pair, admin):
    volume, server = pair
    set_destination(admin, server)
    name = "5" * 64 + ".bin"
    path = sealed_file(name, b"a harmless fixture " * 500)
    sealed_file("_captures/c2/capture.pcap", b"packets")
    assert scheduler.scan(T0) == {"new": 2, "changed": 0, "gone": 0}
    did = ship.ship(T0 + 5)
    assert sorted(x for x in did if x.startswith("store:")) == [f"store:{name}", "store:_captures/c2/capture.pcap"]
    remote_file = server.root / "nik-copies" / "recovery" / "store" / name
    assert remote_file.read_bytes() == path.read_bytes(), "the bytes of the disk: sealed under the store key"
    assert b"harmless fixture" not in remote_file.read_bytes()
    assert (server.root / "nik-copies" / "recovery" / "store" / "_captures" / "c2" / "capture.pcap").is_file()
    with SessionLocal() as db:
        assert db.get(StoreCopy, name).state == "copied" and files.waiting(db)["files"] == 0
    # Deleted here: the copy stays while a recovery can go back to before the deletion.
    done_base("base-20261120-110000", 3, T0 - 3600, volume, offsite_state="copied")
    with SessionLocal() as db:
        state = config.held(db, config.ARCHIVE_SETTINGS_ID)
        state["oldest"] = {"base": "base-20261120-110000", "at": T0 - 3600, "wal": seg(3)}
        config.keep(db, config.ARCHIVE_SETTINGS_ID, state)
        db.commit()
    store.remove(path)
    assert scheduler.scan(T0 + 60)["gone"] == 1
    assert not [x for x in ship.ship(T0 + 65) if x.startswith("store-removed")] and remote_file.exists()
    with SessionLocal() as db:
        state = config.held(db, config.ARCHIVE_SETTINGS_ID)
        state["oldest"]["at"] = T0 + 3600  # the oldest moment one can go back to is now after the deletion
        config.keep(db, config.ARCHIVE_SETTINGS_ID, state)
        db.commit()
    assert f"store-removed:{name}" in ship.ship(T0 + 4000)
    assert not remote_file.exists()
    with SessionLocal() as db:
        assert db.get(StoreCopy, name).removed_at == T0 + 4000


def test_the_log_before_the_oldest_base_backup_on_the_second_host_is_removed_there(pair, admin):
    volume, server = pair
    set_destination(admin, server)
    for number in (3, 4, 5, 6):
        segment(volume, number)
    done_base("base-20261120-110000", 5, T0 - 3600, volume, offsite_state="pending")
    did = ship.ship(T0)
    assert "wal-removed:2" in did
    assert there(server, "wal") == [f"{seg(5)}.nikwal", f"{seg(6)}.nikwal"]


def test_a_second_host_that_cannot_be_reached_is_noted_and_told(pair, admin, monkeypatch):
    volume, server = pair
    set_destination(admin, server)
    segment(volume, 3)

    def refused(self):
        raise offsite.OffsiteError("second.nik.example:22 cannot be reached: timed out")

    monkeypatch.setattr(offsite.Sftp, "connect", refused)
    assert ship.ship(T0) == ["destination:new", "link:down"]
    link = state_of(config.SHIP_SETTINGS_ID)["link"]
    assert link["ok"] is False and link["since"] == T0 and "cannot be reached" in link["error"]
    assert ship.ship(T0 + 300) == ["link:down"]
    assert state_of(config.SHIP_SETTINGS_ID)["link"]["since"] == T0
    assert state_of(config.ROLE_SETTINGS_ID)["asked"]["reachable"] is False
    with SessionLocal() as db:
        assert "link" not in watch.problems(db, T0 + 300)
        found = watch.problems(db, T0 + watch.LINK_AFTER + 1)
        assert "has not been reached since" in found["link"] and "behind" not in found
    monkeypatch.undo()


def test_a_second_host_that_falls_behind_is_told(pair, admin, monkeypatch):
    volume, server = pair
    set_destination(admin, server)
    segment(volume, 3, at=T0)
    ship.ship(T0 + 5)
    with SessionLocal() as db:
        assert "behind" not in watch.problems(db, T0 + 600)
        found = watch.problems(db, T0 + 16 * 60)
        assert found["behind"].startswith("What the second host holds is 16 minutes old (the limit set is 15 minutes)")


def test_a_passphrase_that_changes_is_followed_without_locking_the_standby_out(pair, admin, monkeypatch):
    volume, server = pair
    set_destination(admin, server)
    segment(volume, 3)
    ship.ship(T0)
    first = state_of(config.SHIP_SETTINGS_ID)["seal"]
    assert first == {"mark": envelope.fingerprint(PHRASE)}
    set_phrase(admin, "another passphrase, longer")
    monkeypatch.setattr(ship, "close_segment", lambda db: seg(5))
    for number in (4, 5, 6):
        segment(volume, number)
    ship.ship(T0 + 60)
    seal = state_of(config.SHIP_SETTINGS_ID)["seal"]
    assert seal == {
        "mark": envelope.fingerprint("another passphrase, longer"),
        "upTo": seg(5),
        "earlier": first["mark"],
    }
    folder = server.root / "nik-copies" / "recovery" / "wal"
    old, new = container.Secrets(passphrases=(PHRASE,)), container.Secrets(passphrases=("another passphrase, longer",))
    for number, opens in ((4, old), (5, old), (6, new)):
        container.walk(open(folder / f"{seg(number)}.nikwal", "rb"), opens)
    with pytest.raises(container.WrongKey):
        container.walk(open(folder / f"{seg(6)}.nikwal", "rb"), old)


# --------------------------------------------------------------------------- #
# Which server this is                                                        #
# --------------------------------------------------------------------------- #
def test_a_marker_of_a_later_generation_means_this_server_was_replaced(admin):
    written = role.new_marker(2, "nik-b", T0)
    # What is read from the file: its fields, and whether a key of this server signed it.
    marker = role.read_marker(json.dumps(written).encode())
    assert marker == {**{key: written[key] for key in ("generation", "at", "by", "id")}, "signed": True}
    assert role.read_marker(b"not json") is None and role.read_marker(None) is None
    assert role.read_marker(b'{"generation": "2"}') is None
    assert role.judge({}, None) == "none"
    assert role.judge({"generation": 1}, marker) == "superseded"
    assert role.judge({"generation": 2, "markerId": marker["id"]}, marker) == "own"
    assert role.judge({"generation": 3}, marker) == "none", "an old marker: this server was promoted since"
    with SessionLocal() as db:
        assert role.of(db) == "primary" and role.serving(db) and role.generation(db) == 1
        assert role.note_marker(db, None, T0) == "none"
        db.commit()
        assert role.state(db)["asked"] == {"at": T0, "reachable": True, "verdict": "none"}
        assert role.note_marker(db, marker, T0 + 5) == "superseded"
        db.commit()
        found = role.superseded(db)
        assert found == {"at": T0, "by": "nik-b", "generation": 2, "learnedAt": T0 + 5}
        assert role.of(db) == "superseded" and not role.serving(db)
        lines = role.sentences(found)
        assert lines[0].startswith(
            "This server was replaced on 2026-11-20 12:00 UTC by nik-b: the standby was promoted"
        )
        assert lines[0].endswith("and is the server now.")
        assert "deploy/standby.sh rejoin" in lines[-1]


def test_a_promotion_adds_one_to_the_generation_and_leaves_a_marker(admin):
    with SessionLocal() as db:
        marker = role.promote(db, "nik-b", T0)
        db.commit()
        assert marker["generation"] == 2 and marker["by"] == "nik-b" and len(marker["id"]) == 32
        assert role.generation(db) == 2 and role.state(db)["promotedAt"] == T0
        assert role.judge(role.state(db), marker) == "own"
        again = role.promote(db, "nik-b", T0 + 100)
        assert again["generation"] == 3 and role.judge(role.state(db), marker) == "none"


def test_a_server_that_was_replaced_sends_nothing_more_and_says_so(pair, admin):
    volume, server = pair
    set_destination(admin, server)
    segment(volume, 3)
    ship.ship(T0)
    folder = server.root / "nik-copies" / "recovery"
    (folder / "superseded.json").write_text(json.dumps(role.new_marker(2, "nik-b", T0 + 50)))
    segment(volume, 4)
    assert ship.ship(T0 + 60) == ["superseded"]
    assert f"{seg(4)}.nikwal" not in there(server, "wal")
    with SessionLocal() as db:
        assert role.of(db) == "superseded"
        said = [e.details for e in db.scalars(select(AuditEntry).where(AuditEntry.action == "standby.superseded"))]
    assert said == ["The second host says its standby was promoted: this server was replaced and serves nothing more"]
    assert ship.ship(T0 + 70) == [], "nothing more"
    assert scheduler.stop_if_superseded() is True


def test_a_promoted_server_whose_copies_still_point_at_itself_holds_them(pair, admin):
    volume, server = pair
    set_destination(admin, server)
    with SessionLocal() as db:
        marker = role.promote(db, "nik-b", T0)
        db.commit()
    folder = server.root / "nik-copies" / "recovery"
    folder.mkdir(parents=True)
    (folder / "superseded.json").write_text(json.dumps(marker))
    segment(volume, 3)
    assert ship.ship(T0 + 10) == ["destination:new", "hold:own"]
    assert there(server, "wal") == []
    with SessionLocal() as db:
        assert "still set to go to this host itself" in watch.problems(db, T0 + 20)["copies"]


def test_a_server_recovered_on_a_new_host_goes_on_sending_to_the_second_one(pair, admin):
    volume, server = pair
    set_destination(admin, server)
    with SessionLocal() as db:
        marker = role.promote(db, "nik-new", T0, hold=False)
        db.commit()
    folder = server.root / "nik-copies" / "recovery"
    folder.mkdir(parents=True)
    (folder / "superseded.json").write_text(json.dumps(marker))
    segment(volume, 3)
    assert f"wal:{seg(3)}" in ship.ship(T0 + 10), "its own marker is on the second host, which is not itself"
    assert state_of(config.SHIP_SETTINGS_ID)["hold"] is None


def test_the_second_host_is_asked_when_the_worker_starts(pair, admin, monkeypatch):
    volume, server = pair
    assert scheduler.ask(T0) == "off"
    set_destination(admin, server)
    assert scheduler.ask(T0) == "none"
    assert state_of(config.ROLE_SETTINGS_ID)["asked"]["at"] == T0

    def refused(self):
        raise offsite.OffsiteError("unreachable")

    with monkeypatch.context() as patched:
        patched.setattr(offsite.Sftp, "connect", refused)
        assert scheduler.ask(T0 + 5) == "unreachable"
        assert state_of(config.ROLE_SETTINGS_ID)["asked"] == {"at": T0 + 5, "reachable": False, "error": "unreachable"}
    folder = server.root / "nik-copies" / "recovery"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "superseded.json").write_text(json.dumps(role.new_marker(4, "nik-b", T0)))
    assert scheduler.ask(T0 + 10) == "superseded"
    # The worker then waits: it returns only when it is stopped.
    import threading

    stopping = threading.Event()
    waits = []

    class Stop(threading.Event):
        def wait(self, timeout=None):
            waits.append(timeout)
            if len(waits) >= 3:
                stopping.set()
                self.set()
            return self.is_set()

    scheduler.ask_at_start(Stop())
    assert waits == [10, 10, 10]


# --------------------------------------------------------------------------- #
# The step of the entrypoint                                                  #
# --------------------------------------------------------------------------- #
def ask_gate(port: int, path: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as answer:
            return answer.status, json.loads(answer.read())
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read())


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def test_a_standby_answers_every_request_with_what_it_is():
    port = free_port()
    with gate.Answering("standby", gate.STANDBY, "standby", port=port):
        assert ask_gate(port, "/api/health") == (200, {"status": "standby"})
        status_code, body = ask_gate(port, "/api/incidents")
        assert status_code == 503 and body["stopped"] == {"reason": "standby"}
        assert body["detail"].startswith("This server is the standby: it follows the first host and serves nothing.")
        assert "deploy/standby.sh promote" in body["detail"]
    with pytest.raises(OSError):
        ask_gate(port, "/api/health")


def test_a_standby_follows_until_it_is_promoted(admin, monkeypatch):
    roles = iter([role.STANDBY, role.STANDBY, role.PRIMARY])
    monkeypatch.setattr(gate, "_role", lambda: (next(roles), {}))
    passes = []
    monkeypatch.setattr(standby, "intake", lambda: passes.append(1))
    gate.follow(sleep=lambda _s: None, passes=10)
    assert len(passes) == 2, "two passes as a standby, then it starts"


def test_the_server_waits_a_moment_for_the_answer_of_the_second_host(admin):
    started = time.time()
    with SessionLocal() as db:
        role.note_unreachable(db, "down", started - 100)
        db.commit()
    assert gate.wait_for_the_answer(started, wait=0.05, sleep=lambda _s: None) == "unanswered"
    with SessionLocal() as db:
        role.note_marker(db, None, started + 1)
        db.commit()
    assert gate.wait_for_the_answer(started, wait=5, sleep=lambda _s: None) == "asked"
    with SessionLocal() as db:
        role.note_marker(db, role.read_marker(json.dumps(role.new_marker(2, "nik-b", started)).encode()), started + 2)
        db.commit()
    assert gate.wait_for_the_answer(started, wait=5, sleep=lambda _s: None) == "superseded"
    assert gate._role()[0] == role.SUPERSEDED


# --------------------------------------------------------------------------- #
# A standby takes in what arrives                                             #
# --------------------------------------------------------------------------- #
def inbox_of(tmp_path, monkeypatch) -> Path:
    box = tmp_path / "inbox" / "recovery"
    (box / "wal").mkdir(parents=True)
    monkeypatch.setattr(settings, "STANDBY_INBOX", str(tmp_path / "inbox"))
    return box


def sealed_segment(box: Path, root: Path, number: int, phrase: str = PHRASE, timeline: int = 1) -> None:
    source = segment(root, number, timeline, place="restore")
    target = box / "wal" / f"{seg(number, timeline)}.nikwal"
    key = container.Key.new(container.PASSPHRASE, phrase)
    envelope.seal_file(source, target, key, {"kind": "wal", "name": seg(number, timeline)}, source.name)
    source.unlink()


def test_a_standby_opens_the_log_that_arrives_and_drops_what_it_no_longer_needs(volume, tmp_path, monkeypatch):
    box = inbox_of(tmp_path, monkeypatch)
    assert standby.inbox() == box
    for number in (3, 4, 5, 6):
        sealed_segment(box, volume, number)
    secrets = container.Secrets(passphrases=(PHRASE,))
    did = standby.open_segments(box, secrets, redo=seg(4))
    assert did == {"opened": 3, "waiting": 0, "error": "", "last": seg(6)}, (
        "what is before the restart point is left alone"
    )
    assert sorted(p.name for p in (volume / "incoming").glob("*.gz")) == [f"{seg(n)}.gz" for n in (4, 5, 6)]
    assert gzip.decompress((volume / "incoming" / f"{seg(5)}.gz").read_bytes()) == b"segment 5" * 50
    assert standby.open_segments(box, secrets, redo=seg(4))["opened"] == 0, "opened once"
    assert standby.sweep_incoming(seg(6)) == 2
    assert [p.name for p in (volume / "incoming").glob("*.gz")] == [f"{seg(6)}.gz"]
    # A segment sealed under a passphrase this standby does not know yet waits, and so do the next.
    sealed_segment(box, volume, 7, phrase="the next passphrase")
    sealed_segment(box, volume, 8)
    did = standby.open_segments(box, secrets, redo=seg(6))
    assert did["opened"] == 0 and did["waiting"] == 1 and "not the passphrase" in did["error"]
    both = container.Secrets(passphrases=(PHRASE, "the next passphrase"))
    assert standby.open_segments(box, both, redo=seg(6))["opened"] == 2


def test_a_standby_takes_the_files_of_the_store_and_removes_what_was_removed_for_good(volume, tmp_path, monkeypatch):
    box = inbox_of(tmp_path, monkeypatch)
    name = "6" * 64 + ".bin"
    (box / "store" / "_captures" / "c3").mkdir(parents=True)
    (box / "store" / name).write_bytes(b"sealed bytes of the first host")
    (box / "store" / "_captures" / "c3" / "capture.pcap").write_bytes(b"sealed packets")
    (box / "store" / "half.bin.partial").write_bytes(b"still arriving")
    assert standby.take_store(box) == {"taken": 2, "left": 0}
    assert (store.root() / name).read_bytes() == b"sealed bytes of the first host"
    assert (store.root() / "_captures" / "c3" / "capture.pcap").is_file()
    assert not (box / "store" / name).exists(), "here once, when this process may remove what arrived"
    assert (box / "store" / "half.bin.partial").exists()
    assert standby.take_store(box) == {"taken": 0, "left": 0}
    assert standby.write_have(box) is True
    assert (box / "store.have").read_text() == f"30\t{name}\n"
    with SessionLocal() as db:
        db.add(StoreCopy(name=name, size=30, mtime=1.0, state="copied", seen_at=T0, gone_at=T0, removed_at=T0 + 9))
        db.add(StoreCopy(name="_captures/c3/capture.pcap", size=14, mtime=1.0, state="copied", seen_at=T0, gone_at=T0))
        db.commit()
        assert standby.drop_removed(db) == 1
    assert not (store.root() / name).exists() and (store.root() / "_captures" / "c3" / "capture.pcap").exists()


def test_what_a_standby_already_holds_is_not_sent_again(pair, admin, tmp_path):
    volume, server = pair
    set_destination(admin, server)
    name = "7" * 64 + ".bin"
    path = sealed_file(name, b"the same file on both hosts")
    sealed_file("_captures/c4/log.jsonl", b"{}\n")
    scheduler.scan(T0)
    folder = server.root / "nik-copies" / "recovery"
    folder.mkdir(parents=True)
    (folder / "store.have").write_text(f"{path.stat().st_size}\t{name}\n17\t_captures/c4/log.jsonl\n")
    did = ship.ship(T0 + 5)
    assert "store-there:1" in did and "store:_captures/c4/log.jsonl" in did and f"store:{name}" not in did
    assert not (folder / "store" / name).exists()


def test_what_a_promotion_would_lose_is_said_before_it(admin):
    seen = {
        "replay": {"lastChange": T0 - 200},
        "heartbeat": {"at": T0 - 20, "archiveTimeout": 300},
        "waiting": 1,
    }
    found = status.loss(seen, T0)
    assert found["lines"][0] == "The last change this standby holds was made at 2026-11-20 11:56:40 UTC."
    assert "1 segment(s) of log that arrived are still to be replayed" in found["lines"][1]
    assert "The first host last spoke at 2026-11-20 11:59:40 UTC (20 seconds ago)." in found["lines"]
    assert "at least the 3 minutes before it last spoke" in found["lines"][-1]
    silent = status.loss({"replay": {"lastChange": None}, "heartbeat": None, "waiting": 0}, T0)
    assert (
        silent["lines"][0] == "This standby has replayed no change yet."
        and "cannot say how much" in silent["lines"][-1]
    )


# --------------------------------------------------------------------------- #
# The command line                                                            #
# --------------------------------------------------------------------------- #
def test_a_moment_is_read_as_an_operator_writes_it():
    assert tool.parse_moment("latest") is None and tool.parse_moment(" LATEST ") is None
    assert tool.parse_moment("2026-11-20 12:00:00+00") == T0
    assert tool.parse_moment("2026-11-20 12:00:00") == T0, "without an offset: UTC"
    assert tool.parse_moment("2026-11-20T13:00:00+01:00") == T0
    assert tool.parse_moment("2026-11-20 12:00:00 UTC") == T0
    with pytest.raises(container.BackupError, match="is not a moment"):
        tool.parse_moment("yesterday")


def plan_source(volume, monkeypatch=None) -> dict:
    base_folder(volume, "base-20261120-033000", 3, 3)
    base_folder(volume, "base-20261121-033000", 10, 10)
    os.utime(volume / "base" / "base-20261120-033000" / "backup_manifest", (T0, T0))
    os.utime(volume / "base" / "base-20261121-033000" / "backup_manifest", (T0 + DAY, T0 + DAY))
    for number in range(4, 14):
        segment(volume, number, at=T0 + (number - 3) * 3 * 3600)
    return tool.local_source()


def test_the_base_backup_before_the_moment_is_chosen_and_the_log_must_reach_it(volume):
    source = plan_source(volume)
    found = tool.choose(source, T0 + 5 * 3600)
    assert found["base"]["label"] == "base-20261120-033000" and found["base"]["place"] == "base"
    assert tool.choose(source, T0 + DAY + 3600)["base"]["label"] == "base-20261121-033000"
    latest = tool.choose(source, None)
    assert latest["base"]["label"] == "base-20261121-033000" and latest["newest"] == T0 + 30 * 3600
    with pytest.raises(
        container.BackupError, match="The oldest moment the archive can go back to is 2026-11-20 12:00:00 UTC"
    ):
        tool.choose(source, T0 - 60)
    with pytest.raises(container.BackupError, match="The archive ends at 2026-11-21 18:00:00 UTC"):
        tool.choose(source, T0 + 2 * DAY)
    # A segment missing in the middle: the log can be replayed up to it and no further.
    (volume / "wal" / f"{seg(6)}.gz").unlink()
    source = tool.local_source()
    assert tool.choose(source, T0 + 5 * 3600)["base"]["label"] == "base-20261120-033000"
    with pytest.raises(container.BackupError, match=f"The segment {seg(6)} of the log is missing"):
        tool.choose(source, T0 + 12 * 3600)
    assert tool.choose(source, T0 + DAY + 3600)["base"]["label"] == "base-20261121-033000", (
        "the later one needs none of it"
    )
    with pytest.raises(container.BackupError, match="holds no base backup"):
        tool.choose({"bases": [], "segments": {}, "history": {}, "sealed": False}, None)


def test_the_plan_is_printed_for_the_script(volume, capsys):
    plan_source(volume)
    assert tool.main(["plan", "--to", "2026-11-20 17:00:00+00"]) == 0
    printed = capsys.readouterr()
    assert "label=base-20261120-033000\nplace=base\ntarget=2026-11-20 17:00:00.000000+00\n" in printed.out
    assert "sealed=0" in printed.out and "Base backup: base-20261120-033000" in printed.err
    assert "what was written after that moment is left out" in printed.err
    assert tool.main(["plan", "--to", "latest"]) == 0
    assert "target=\n" in capsys.readouterr().out
    assert tool.main(["plan", "--to", "2030-01-01 00:00:00"]) == 1
    assert "recovery: The archive ends at" in capsys.readouterr().err


def test_what_came_from_the_second_host_is_planned_and_opened(pair, admin, tmp_path, monkeypatch, capsys):
    volume, server = pair
    set_destination(admin, server)
    done_base("base-20261120-110000", 3, T0 - 3600, volume, offsite_state="pending")
    for number in (3, 4, 5):
        segment(volume, number)
    (volume / "wal" / "00000002.history.gz").write_bytes(gzip.compress(b"1\t0/9000000\tr\n"))
    ship.ship(T0)
    # Another host: an empty archive volume, the directory of the copies, the passphrase typed.
    other = tmp_path / "other"
    for name in ("wal", "base", "incoming", "restore"):
        (other / name).mkdir(parents=True)
    monkeypatch.setattr(settings, "WAL_ARCHIVE_DIR", str(other))
    copies = str(server.root / "nik-copies")
    assert tool.main(["plan", "--to", "latest", "--from", copies]) == 0
    printed = capsys.readouterr().out
    assert "label=base-20261120-110000\nplace=restore\n" in printed and "sealed=1" in printed
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", "not the passphrase")
    assert tool.main(["fetch", "--label", "base-20261120-110000", "--from", copies]) == 1
    assert "not the passphrase the backup was made with" in capsys.readouterr().err
    assert list((other / "restore" / "base-20261120-110000").iterdir()) == []
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", PHRASE)
    assert tool.main(["fetch", "--label", "base-20261120-110000", "--from", copies]) == 0
    assert "opened=4" in capsys.readouterr().out
    assert sorted(p.name for p in (other / "restore" / "base-20261120-110000").iterdir()) == [
        "backup_manifest", "base.tar.gz", "pg_wal.tar.gz",
    ]  # fmt: skip
    assert sorted(p.name for p in (other / "incoming").iterdir()) == [
        f"{seg(3)}.gz", f"{seg(4)}.gz", f"{seg(5)}.gz", "00000002.history.gz",
    ]  # fmt: skip
    assert archive.read_manifest("base-20261120-110000", "restore")["startWal"] == seg(3)


def test_the_keys_a_second_host_needs_travel_sealed(admin, monkeypatch, capsys):
    monkeypatch.setenv("DB_PASSWORD", "the database password")
    monkeypatch.setenv("SECRET_KEY", "k" * 64)
    monkeypatch.setenv("STORE_KEY", STORE_KEY)
    monkeypatch.setenv("AUDIT_KEY", "a" * 64)
    monkeypatch.setenv("NIK_TRANSFER_PASSPHRASE", "short")
    assert tool.main(["pack-secrets"]) == 1
    assert "at least 12 characters" in capsys.readouterr().err
    monkeypatch.setenv("NIK_TRANSFER_PASSPHRASE", "carried by the operator")
    assert tool.main(["pack-secrets"]) == 0
    packed = capsys.readouterr().out
    raw = base64.b64decode(packed)
    assert raw.startswith(container.MAGIC) and b"the database password" not in raw and STORE_KEY.encode() not in raw
    monkeypatch.setattr("sys.stdin", io.StringIO(packed))
    assert tool.main(["unpack-secrets"]) == 0
    lines = capsys.readouterr().out.splitlines()
    assert lines == [
        "DB_PASSWORD=the database password", f"SECRET_KEY={'k' * 64}", f"STORE_KEY={STORE_KEY}",
        f"AUDIT_KEY={'a' * 64}",
    ]  # fmt: skip
    monkeypatch.setenv("NIK_TRANSFER_PASSPHRASE", "not what was typed")
    monkeypatch.setattr("sys.stdin", io.StringIO(packed))
    assert tool.main(["unpack-secrets"]) == 1
    assert "not the passphrase" in capsys.readouterr().err


def test_a_promotion_that_is_under_way_holds_the_server_back(volume, capsys):
    assert not standby.promoting() and tool.main(["promoting"]) == 1
    assert standby.mark_promoting(T0) and standby.promoting() and tool.main(["promoting"]) == 0
    waits = []
    gate.wait_for_the_promotion(sleep=waits.append, passes=3)
    assert waits == [1, 1, 1], "the server does not start while the mark is there"
    standby.done_promoting()
    gate.wait_for_the_promotion(sleep=waits.append, passes=3)
    assert waits == [1, 1, 1] and not standby.promoting()
    # A database promoted by hand has no mark and nobody made it the server: the step of the
    # entrypoint tells the two apart by when this server was last promoted.
    assert gate.promoted_since(T0) is False
    with SessionLocal() as db:
        role.promote(db, "nik-b", T0 + 50)
        db.commit()
    assert gate.promoted_since(T0) is True and gate.promoted_since(T0 + 100) is False


def test_a_promoted_standby_becomes_the_server(volume, tmp_path, monkeypatch, capsys):
    box = inbox_of(tmp_path, monkeypatch)
    deleted = sealed_file("9" * 64 + ".bin", b"deleted on the first host, kept on its copies")
    standby.mark_promoting(T0)
    with SessionLocal() as db:
        db.add(Lease(name="backup", holder="the first host", expires_at=time.time() + 100))
        db.add(StoreCopy(name="8" * 64 + ".bin", size=1, mtime=1.0, state="copied", seen_at=T0))
        db.add(StoreCopy(name=deleted.name, size=1, mtime=1.0, state="copied", seen_at=T0, gone_at=T0 + 7))
        config.keep(db, config.SHIP_SETTINGS_ID, {"on": True, "where": "w", "shipped": {"wal": seg(4)}})
        db.commit()
    assert tool.main(["promoted", "--name", "nik-b"]) == 0
    printed = capsys.readouterr().out
    marker = json.loads((box / "superseded.json").read_text())
    assert marker["generation"] == 2 and marker["by"] == "nik-b" and "marker_written=1" in printed
    with SessionLocal() as db:
        assert role.generation(db) == 2 and db.scalars(select(Lease)).all() == []
        assert db.get(StoreCopy, "8" * 64 + ".bin").state == "pending"
        assert "shipped" not in config.held(db, config.SHIP_SETTINGS_ID)
        said = [e.details for e in db.scalars(select(AuditEntry).where(AuditEntry.action == "standby.promote"))]
    assert said and said[0].startswith("This standby was promoted and is the server now (generation 2, as nik-b).")
    assert not standby.promoting(), "from here the server starts"
    # What the first host had deleted is kept here as a deletion is, under the moment it was deleted.
    assert not deleted.exists() and (store.root() / ".kept" / str(int(T0 + 7)) / deleted.name).is_file()


def test_the_status_reads_as_sentences(volume, monkeypatch, capsys):
    done_base("base-20261120-110000", 3, T0 - 3600, volume)
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(time.time()))
    play_agent(volume, time.time())
    archive.tick(usage=lambda _p: Disk)
    assert tool.main(["status"]) == 0
    printed = capsys.readouterr().out
    assert "Role: the server (it serves), generation 1" in printed
    assert "Archive of the log: on, last segment " + seg(8) in printed
    assert "One can go back to any moment from 2026-11-20T11:00:00+00:00" in printed
    assert "Second host: none" in printed
    assert tool.main(["status", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["role"] == "primary"


# --------------------------------------------------------------------------- #
# The screen and the health page                                              #
# --------------------------------------------------------------------------- #
def test_the_screen_is_given_everything_and_no_secret(volume, admin, monkeypatch):
    done_base("base-20261120-110000", 3, T0 - 3600, volume)
    with SessionLocal() as db:
        config.write(db, {"base": {"enabled": False}})  # the day of the test is not the day of the fixture
        db.commit()
    now = time.time()
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(now))
    play_agent(volume, now)
    archive.tick(usage=lambda _p: Disk)
    shown = admin.get("/api/recovery").json()
    assert shown["available"] is True and shown["role"] == "primary" and shown["archive"]["on"] is True
    assert shown["archive"]["lastWal"] == seg(8) and shown["archive"]["timeout"] == settings.ARCHIVE_TIMEOUT
    assert shown["window"]["oldest"].startswith("2026-11-20T11:00:00") and shown["window"]["newest"]
    assert [base["id"] for base in shown["bases"]] == ["base-20261120-110000"]
    assert shown["bases"][0]["verified"] is True and shown["bases"][0]["startWal"] == seg(3)
    assert shown["command"].startswith('deploy/restore.sh --replace --to "20') and shown["command"].endswith('+00"')
    assert shown["disk"]["base"] > 0 and shown["disk"]["steady"] > 0 and shown["service"]["running"] is True
    assert shown["copies"]["on"] is False and shown["settings"]["keepDays"] == 2 and shown["pair"]["generation"] == 1
    asked = admin.post("/api/recovery/test")
    assert asked.status_code == 202
    monkeypatch.setattr(archive.shutil, "disk_usage", lambda _p: Disk)
    taken = admin.post("/api/recovery/base")
    assert taken.status_code == 202 and len(taken.json()["bases"]) == 2
    assert admin.post("/api/recovery/base").status_code == 409, "one at a time"


def test_the_health_page_has_the_rows_of_the_recovery(volume, admin, monkeypatch):
    from app.health import checks, metrics, thresholds

    done_base("base-20261120-110000", 3, T0 - 3600, volume)
    now = time.time()
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(now))
    play_agent(volume, now)
    archive.tick(usage=lambda _p: Disk)
    with SessionLocal() as db:
        rows = {row["id"]: row for row in checks.gather(db, thresholds.read(db), {}, now)}
        text = metrics.render(list(rows.values()))
    assert {
        "disk.archive",
        "recovery.role",
        "recovery.archive",
        "recovery.base",
        "recovery.test",
        "recovery.service",
    } <= set(rows)
    assert rows["recovery.role"]["value"] == "The server" and rows["recovery.role"]["group"] == "Recovery"
    assert rows["recovery.archive"]["state"] == "fine" and rows["recovery.archive"]["value"].startswith("Last segment ")
    assert rows["recovery.base"]["value"].startswith("1 kept, the last ")
    assert rows["recovery.test"]["value"] == "Not yet" and "recovery.copies" not in rows
    for name in ("nik_recovery_archive_ok 1", "nik_server_generation 1", 'nik_server_role{role="primary"} 1',
                 "nik_recovery_service_up 1", 'nik_recovery_archive_bytes{what="base"}'):  # fmt: skip
        assert name in text, name


def test_a_server_without_an_archive_shows_nothing_of_it(admin):
    from app.health import checks, thresholds

    with SessionLocal() as db:
        rows = checks.gather(db, thresholds.read(db), {}, time.time())
    assert not [row for row in rows if row["id"].startswith("recovery.") or row["id"] == "disk.archive"]
    assert archive.tick() == [] and ship.ship() == [] and watch.check() == []


# --------------------------------------------------------------------------- #
# The sealed file given to the process that sends the copies                  #
# --------------------------------------------------------------------------- #
def test_only_a_process_of_this_server_is_given_a_sealed_file_and_never_one_in_clear(volume, admin):
    from app import store_handover

    name = "_captures/c5/capture.pcap"
    path = sealed_file(name, b"packets")
    (store.root() / "clear.bin").write_bytes(b"in clear")
    proof = {store_handover.HEADER: store_handover.token(ship.SEALED_KIND, name)}
    given = admin.get("/api/internal/store-sealed", params={"name": name}, headers=proof)
    assert given.status_code == 200 and given.content == path.read_bytes() and b"packets" not in given.content
    assert admin.get("/api/internal/store-sealed", params={"name": name}).status_code == 404, "no proof"
    other = {store_handover.HEADER: store_handover.token(ship.SEALED_KIND, "another")}
    assert admin.get("/api/internal/store-sealed", params={"name": name}, headers=other).status_code == 404
    for wrong in ("clear.bin", "../outside", ".kept/1/x", "missing.bin"):
        proof = {store_handover.HEADER: store_handover.token(ship.SEALED_KIND, wrong)}
        assert admin.get("/api/internal/store-sealed", params={"name": wrong}, headers=proof).status_code == 404, wrong


def test_the_remote_folders_are_made_and_a_cut_upload_is_resumed(pair, admin, tmp_path):
    volume, server = pair
    set_destination(admin, server)
    source = tmp_path / "big"
    source.write_bytes(os.urandom(300_000))
    with SessionLocal() as db:
        remote = Remote(offsite.open_destination(db))
    server.drop_after = 100_000
    with pytest.raises((offsite.OffsiteError, OSError)), remote.session() as session:
        session.put_file(source, "wal/deep/big.nikwal")
    with remote.session() as session:
        sent = session.put_file(source, "wal/deep/big.nikwal")
        assert sent["bytes"] == 300_000 and session.size("wal/deep/big.nikwal") == 300_000
        assert session.listing("wal/deep") == [("big.nikwal", 300_000)] and session.listing("nothing") == []
        assert session.read_bytes("nothing.json") is None and session.size("nothing") is None
        session.put_bytes("heartbeat.json", b"{}")
        assert session.read_bytes("heartbeat.json") == b"{}"
        assert session.remove("wal/deep/big.nikwal") is True and session.remove("wal/deep/big.nikwal") is False
    assert (server.root / "nik-copies" / "recovery" / "wal" / "deep").is_dir()
