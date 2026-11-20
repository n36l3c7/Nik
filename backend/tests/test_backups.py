"""Backups: the file format, the schedule and the retention, a backup and its restore test,
the notices, the routes. The database is the suite's own (SQLite by default, PostgreSQL in
the ``backend-postgres`` job): what differs between the two is said where it does.

The files of the store are harmless fixtures: bytes made here, never a sample.
"""

from __future__ import annotations

import io
import json
import os
import shutil
import subprocess
import sys
import tracemalloc
from collections import namedtuple
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.backups import config, container, database, policy, runner, scheduler, store, watch
from app.core.config import settings
from app.core.db import SessionLocal, engine
from app.core.models import AuditEntry, Backup, Notification

PHRASE = "a passphrase for the tests"
POSTGRES = engine.dialect.name == "postgresql"
T0 = datetime(2026, 11, 20, 12, 0, tzinfo=timezone.utc).timestamp()
Disk = namedtuple("Disk", "total used free")


@pytest.fixture(autouse=True)
def quick_keys(monkeypatch):
    # The real cost of scrypt is for a real passphrase; here it would only slow every test.
    monkeypatch.setattr(container, "SCRYPT_N", 2**10)


@pytest.fixture()
def backups(admin, tmp_path, monkeypatch):
    """A signed-in administrator on a server with a backup directory and a small store of its own."""
    files = tmp_path / "store"
    (files / "_captures" / "c1").mkdir(parents=True)
    (files / ("a" * 64 + ".bin")).write_bytes(b"a harmless fixture, not a sample\n" * 2000)
    (files / "_captures" / "c1" / "capture.pcap").write_bytes(os.urandom(70_000))
    (files / ("b" * 64 + ".mail")).write_bytes(b"Subject: fixture\n\nbody\n")
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(files))
    monkeypatch.setattr(settings, "BACKUP_DIR", str(tmp_path / "backups"))
    # One backup a day and a late warning: the slots and the ages below are counted from these.
    with SessionLocal() as db:
        kept = {"schedule": dict(DAILY), "retention": {"last": 7, "weeks": 4, "upgrades": 3}, "warnAfterHours": 36}
        config._keep(db, kept)
        db.commit()
    created = admin.post("/api/incidents", json={"name": "Kept in the backup"})
    assert created.status_code == 201, created.text
    return admin


def set_phrase(client, phrase: str = PHRASE) -> None:
    done = client.put("/api/backups/passphrase", json={"passphrase": phrase})
    assert done.status_code == 200, done.text


def rows() -> list[Backup]:
    with SessionLocal() as db:
        return list(db.scalars(select(Backup).order_by(Backup.created_at)))


def audit_lines(action: str) -> list[str]:
    with SessionLocal() as db:
        return [entry.details for entry in db.scalars(select(AuditEntry).where(AuditEntry.action == action))]


# --------------------------------------------------------------------------- #
# The file                                                                    #
# --------------------------------------------------------------------------- #
def write_small(out, phrase: str = PHRASE, source: str = container.PASSPHRASE) -> dict:
    writer = container.Writer(out, container.Key.new(source, phrase), {"kind": "full"})
    with writer.part("db/schema.json") as part:
        part.write(b'{"engine": "none"}')
    with writer.part("text") as part:
        part.write(b"row\n" * 300)  # shrinks: written compressed
    with writer.part("noise") as part:
        part.write(os.urandom(400))  # does not: written as it is
    with writer.part("empty"):
        pass
    return writer.finish({"nik": "test"})


def read_all(data: bytes, phrase: str = PHRASE, **secrets) -> tuple[dict, dict]:
    held = {}
    opened = container.Secrets(passphrases=(phrase,), **secrets)
    manifest = container.walk(io.BytesIO(data), opened, lambda part: held.__setitem__(part.name, part.read()))
    return manifest, held


def test_a_backup_file_gives_back_what_was_written():
    out = io.BytesIO()
    written = write_small(out)
    manifest, held = read_all(out.getvalue())
    assert manifest == written
    assert held["text"] == b"row\n" * 300 and len(held["noise"]) == 400 and held["empty"] == b""
    assert [part["name"] for part in manifest["parts"]] == ["db/schema.json", "text", "noise", "empty"]
    assert manifest["parts"][1]["size"] == 1200
    header = container.read_header(io.BytesIO(out.getvalue()))[0]
    assert header["format"] == 1 and header["cipher"] == "AES-256-GCM" and header["key"]["from"] == "passphrase"
    # Nothing of the content is readable in the file.
    assert b"row\nrow" not in out.getvalue() and b"db/schema.json" not in out.getvalue()


def test_a_wrong_passphrase_is_told_from_a_damaged_file():
    out = io.BytesIO()
    write_small(out)
    with pytest.raises(container.WrongKey, match="not the passphrase"):
        read_all(out.getvalue(), "another passphrase")
    with pytest.raises(container.WrongKey, match="none was given"):
        container.walk(io.BytesIO(out.getvalue()), container.Secrets())


def test_a_snapshot_under_secret_key_needs_that_key():
    out = io.BytesIO()
    write_small(out, "the secret key of the server", container.SECRET_KEY)
    opened = container.Secrets(secret_keys=("an earlier key", "the secret key of the server"))
    assert container.walk(io.BytesIO(out.getvalue()), opened)["nik"] == "test"
    with pytest.raises(container.WrongKey, match="SECRET_KEY"):
        container.walk(io.BytesIO(out.getvalue()), container.Secrets(passphrases=("the secret key of the server",)))


def test_a_byte_changed_anywhere_is_detected():
    out = io.BytesIO()
    write_small(out)
    good = out.getvalue()
    assert len(good) < 2000
    for position in range(len(good)):
        damaged = bytearray(good)
        damaged[position] ^= 0x01
        with pytest.raises(container.BackupError):
            read_all(bytes(damaged))


def test_a_file_cut_short_or_added_to_is_detected():
    out = io.BytesIO()
    write_small(out)
    good = out.getvalue()
    for length in range(len(good)):
        with pytest.raises(container.BackupError):
            read_all(good[:length])
    with pytest.raises(container.Damaged, match="after its end"):
        read_all(good + b"\x00")


def test_chunks_cannot_be_swapped_or_left_out(tmp_path):
    path = tmp_path / "two.nikbak"
    with open(path, "wb") as out:
        writer = container.Writer(out, container.Key.new(container.PASSPHRASE, PHRASE), chunk=64)
        with writer.part("noise") as part:
            part.write(os.urandom(300))
        writer.finish({})
    data = path.read_bytes()
    start = len(container.read_header(io.BytesIO(data))[1])
    size = 5 + 64 + 16
    first, second, rest = data[start : start + size], data[start + size : start + 2 * size], data[start + 2 * size :]
    assert read_all(data)[1]["noise"]
    for changed in (data[:start] + second + first + rest, data[:start] + first + rest, data[:start] + first * 2 + rest):
        with pytest.raises(container.Damaged):
            read_all(changed)


def test_a_large_backup_goes_through_without_being_held_in_memory(tmp_path):
    path = tmp_path / "large.nikbak"
    block = os.urandom(1024 * 1024)
    tracemalloc.start()
    with open(path, "wb") as out:
        writer = container.Writer(out, container.Key.new(container.PASSPHRASE, PHRASE))
        with writer.part("store.tar") as part:
            for _ in range(48):
                part.write(block)
        writer.finish({})
    total = 0
    with open(path, "rb") as source:
        reader = container.Reader(source, container.Secrets(passphrases=(PHRASE,)))
        for part in reader.parts():
            for piece in iter(lambda part=part: part.read(1024 * 1024), b""):
                total += len(piece)
    _now, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert total == 48 * 1024 * 1024 and path.stat().st_size > total
    assert peak < 12 * 1024 * 1024, f"{peak} bytes held to move 48 MB"


def test_the_format_is_read_by_the_script_alone(tmp_path):
    """container.py copied out of Nik, run where Nik is not: it lists and extracts a backup."""
    alone = tmp_path / "elsewhere"
    alone.mkdir()
    shutil.copy(Path(container.__file__), alone / "container.py")
    backup = tmp_path / "small.nikbak"
    with open(backup, "wb") as out:
        write_small(out)
    env = {**os.environ, "NIK_BACKUP_PASSPHRASE": PHRASE, "PYTHONPATH": ""}
    listed = subprocess.run(
        [sys.executable, "container.py", "list", str(backup)], cwd=alone, env=env, capture_output=True, text=True
    )
    assert listed.returncode == 0, listed.stderr
    assert "db/schema.json" in listed.stdout and '"nik": "test"' in listed.stdout
    done = subprocess.run(
        [sys.executable, "container.py", "extract", str(backup), "out"], cwd=alone, env=env, capture_output=True
    )
    assert done.returncode == 0, done.stderr
    assert (alone / "out" / "text").read_bytes() == b"row\n" * 300
    assert json.loads((alone / "out" / "manifest.json").read_text())["nik"] == "test"
    refused = subprocess.run(
        [sys.executable, "container.py", "list", str(backup)],
        cwd=alone,
        env={**env, "NIK_BACKUP_PASSPHRASE": "wrong"},
        capture_output=True,
        text=True,
    )
    assert refused.returncode == 1 and "not the passphrase" in refused.stderr


# --------------------------------------------------------------------------- #
# The schedule and the retention                                              #
# --------------------------------------------------------------------------- #
DAILY = {"enabled": True, "every": "day", "hours": 6, "at": "02:30", "weekday": 6, "timezone": "UTC"}


def at(text: str) -> float:
    return datetime.fromisoformat(text).replace(tzinfo=timezone.utc).timestamp()


def test_the_slots_of_a_schedule():
    now = at("2026-11-20T12:00")  # a Friday
    assert policy.latest_slot(DAILY, now) == at("2026-11-20T02:30")
    assert policy.next_slot(DAILY, now) == at("2026-11-21T02:30")
    weekly = {**DAILY, "every": "week", "weekday": 6}  # Sunday
    assert policy.latest_slot(weekly, now) == at("2026-11-15T02:30")
    assert policy.next_slot(weekly, now) == at("2026-11-22T02:30")
    hours = {**DAILY, "every": "hours", "hours": 6}
    assert policy.latest_slot(hours, now) == at("2026-11-20T08:30")
    assert policy.next_slot(hours, now) == at("2026-11-20T14:30")
    assert policy.latest_slot(hours, at("2026-11-20T01:00")) == at("2026-11-19T20:30")
    rome = {**DAILY, "timezone": "Europe/Rome"}  # UTC+1 in November
    assert policy.latest_slot(rome, now) == at("2026-11-20T01:30")
    assert policy.latest_slot({**DAILY, "enabled": False}, now) is None
    assert policy.next_slot({**DAILY, "enabled": False}, now) is None


def test_a_backup_is_due_once_per_slot_and_tried_again_an_hour_after_a_failure():
    slot = at("2026-11-20T02:30")
    taken = policy.Taken
    yesterday = taken("y", slot - 86400 + 5, "done", "passed")
    assert not policy.due(DAILY, [yesterday], slot - 60)
    assert policy.due(DAILY, [yesterday], slot + 1)
    for state, verify in (("queued", ""), ("running", ""), ("done", "queued"), ("done", "passed")):
        assert not policy.due(DAILY, [yesterday, taken("t", slot + 2, state, verify)], slot + 10), (state, verify)
    failed = taken("f", slot + 2, "failed")
    assert not policy.due(DAILY, [yesterday, failed], slot + 600)
    assert policy.due(DAILY, [yesterday, failed], slot + 2 + 3600)
    bad = taken("b", slot + 2, "done", "failed")
    assert not policy.due(DAILY, [bad], slot + 600) and policy.due(DAILY, [bad], slot + 2 + 3600)
    # A slot that passed before the schedule was set is not owed.
    assert not policy.due(DAILY, [], slot + 100, since=slot + 50)
    assert not policy.due({**DAILY, "enabled": False}, [], slot + 1)


def test_a_slot_is_missed_when_nothing_started_and_the_grace_is_over():
    slot = at("2026-11-20T02:30")
    assert policy.missed(DAILY, [], slot + 3600) is None  # within the grace
    assert policy.missed(DAILY, [], slot + 2 * 3600 + 1) == slot
    started = policy.Taken("f", slot + 30, "failed")  # it started: that is "failed", not "missed"
    assert policy.missed(DAILY, [started], slot + 5 * 3600) is None
    old = policy.Taken("o", slot - 86400, "done", "passed")
    assert policy.missed(DAILY, [old], slot + 5 * 3600) == slot
    assert policy.missed(DAILY, [], slot + 5 * 3600, since=slot + 1) is None
    hourly = {**DAILY, "every": "hours", "hours": 1}
    latest = policy.latest_slot(hourly, slot + 5 * 3600 + 1900)
    assert policy.missed(hourly, [], latest + 1700) is None and policy.missed(hourly, [], latest + 1900) == latest


def test_retention_keeps_the_latest_and_one_a_week():
    now = at("2026-11-20T12:00")
    day = 86400
    good = [policy.Taken(f"d{index}", now - index * day, "done", "passed") for index in range(40)]
    kept, removed = policy.retention(good, now, last=3, weeks=4)
    assert kept[:3] == ["d0", "d1", "d2"]
    weeks = {datetime.fromtimestamp(now - int(name[1:]) * day, timezone.utc).isocalendar()[1] for name in kept}
    assert len(weeks) == 4 and len(kept) == 6  # three latest (one week) and the latest of three weeks before
    assert set(kept) | set(removed) == {entry.id for entry in good} and not set(kept) & set(removed)
    assert policy.retention(good, now, last=3, weeks=0)[0] == ["d0", "d1", "d2"]


def test_retention_never_removes_the_last_good_backup_for_newer_bad_ones():
    now = at("2026-11-20T12:00")
    day = 86400
    taken = [policy.Taken("good", now - 30 * day, "done", "passed")]
    taken += [policy.Taken(f"bad{index}", now - index * day, "done", "failed") for index in range(1, 10)]
    taken += [policy.Taken("broken", now - 12 * day, "failed"), policy.Taken("now", now, "running")]
    kept, removed = policy.retention(taken, now, last=1, weeks=0)
    assert "good" in kept, "the only backup known to restore must stay"
    assert "now" in kept, "a backup being written is never touched"
    # Bad ones do not count as kept backups, and they do not pile up either.
    assert [name for name in kept if name.startswith("bad")] == ["bad1", "bad2"]
    assert "broken" in removed and "bad9" in removed
    # With newer good ones the old good one may go, and old bad ones go with it.
    taken.append(policy.Taken("fresh", now - 60, "done", "passed"))
    kept, removed = policy.retention(taken, now, last=1, weeks=0)
    assert "fresh" in kept and "good" in removed and "bad9" in removed


def test_the_snapshots_before_upgrades_keep_their_own_count():
    taken = [policy.Taken(f"u{index}", 1000 - index, "done", kind="upgrade") for index in range(5)]
    taken.append(policy.Taken("full", 5000, "done", "passed"))
    assert policy.upgrade_retention(taken, 3) == ["u3", "u4"]
    assert policy.retention(taken, 6000, last=1, weeks=0) == (["full"], [])


# --------------------------------------------------------------------------- #
# A backup and its restore test                                               #
# --------------------------------------------------------------------------- #
def test_a_backup_is_written_tested_and_recorded(backups):
    set_phrase(backups)
    name = runner.take(by="admin", now=T0)
    (row,) = rows()
    assert row.id == name == "nik-20261120-120000"
    assert (row.state, row.verify_state, row.kind, row.local) == ("done", "passed", "full", True)
    folder = Path(settings.BACKUP_DIR)
    assert sorted(path.name for path in folder.iterdir()) == [f"{name}.json", f"{name}.nikbak"]
    assert row.size == (folder / f"{name}.nikbak").stat().st_size
    assert row.summary["files"] == 3 and row.summary["rows"] >= 2 and row.summary["keyFrom"] == "passphrase"
    assert row.nik_version == runner.nik_version() and row.nik_version[0].isdigit()
    checks = " / ".join(row.verify["checks"])
    assert "every chunk decrypts" in checks and "3 files of the store" in checks and "rows in" in checks
    assert "an administrator is among its accounts" in checks and "incident(s) are readable" in checks
    # The note beside the file says what it is, in clear, and holds nothing secret.
    note = json.loads((folder / f"{name}.json").read_text())
    assert note["name"] == name and note["verify"]["passed"] is True and note["keyFrom"] == "passphrase"
    assert PHRASE not in json.dumps(note) and settings.SECRET_KEY not in json.dumps(note)
    # The file itself: read with the passphrase, it holds the database, the store and no key.
    manifest = container.walk(open(folder / f"{name}.nikbak", "rb"), container.Secrets(passphrases=(PHRASE,)))
    names = [part["name"] for part in manifest["parts"]]
    assert names[0] == "db/schema.json" and names[-2:] == ["store.tar", "store.index"] and "secret-key" not in names
    assert manifest["includesSecretKey"] is False and manifest["store"] == {
        "files": 3,
        "bytes": row.summary["storeBytes"],
    }
    assert any(".env" in line for line in manifest["notIncluded"])
    assert audit_lines("backup.run") == [
        f"Took the backup {name}: {row.summary['rows']} rows, 3 files, {row.size} bytes"
    ]
    assert audit_lines("backup.verify") == [f"The backup {name} passed its restore test"]
    assert database.leftovers() == []


def test_the_key_goes_inside_only_when_asked_and_never_in_clear(backups):
    set_phrase(backups)
    assert backups.put("/api/backups/settings", json={"includeKey": True}).status_code == 200
    name = runner.take(now=T0)
    data = runner.file_of(name).read_bytes()
    assert settings.SECRET_KEY.encode() not in data
    held = {}
    opened = container.Secrets(passphrases=(PHRASE,))
    manifest = container.walk(io.BytesIO(data), opened, lambda part: held.__setitem__(part.name, part.read(10**6)))
    assert held["secret-key"] == settings.SECRET_KEY.encode() and manifest["includesSecretKey"] is True
    assert "SECRET_KEY included" in audit_lines("backup.run")[0]
    assert "SECRET_KEY is now included" in audit_lines("backup.settings")[-1]


def test_a_backup_that_fails_leaves_nothing_that_looks_like_one(backups, monkeypatch):
    set_phrase(backups)
    folder = Path(settings.BACKUP_DIR)
    folder.mkdir()
    (folder / "nik-20200101-000000.nikbak.partial").write_bytes(b"left by a run that died")

    def breaks(writer, root):
        with writer.part("store.tar") as part:
            part.write(b"half")
            raise OSError("the disk went away")

    monkeypatch.setattr(store, "pack", breaks)
    name = runner.take(now=T0)
    (row,) = rows()
    assert (row.state, row.verify_state) == ("failed", "") and "the disk went away" in row.error
    assert list(folder.iterdir()) == [], "neither the half-written file nor the older partial is left"
    assert audit_lines("backup.run") == [f"The backup {name} failed: the disk went away"]


def test_no_backup_without_a_passphrase(backups):
    assert backups.post("/api/backups/run").status_code == 409
    runner.take(now=T0)
    (row,) = rows()
    assert row.state == "failed" and "No backup passphrase is set" in row.error
    assert not list(Path(settings.BACKUP_DIR).glob("*")) if Path(settings.BACKUP_DIR).exists() else True
    assert scheduler.tick(now=T0 + 86400) == [], "the schedule waits for a passphrase"


def test_a_backup_is_refused_when_the_directory_has_no_room(backups, monkeypatch):
    set_phrase(backups)
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: Disk(10**9, 10**9 - 1000, 1000))
    runner.take(now=T0)
    (row,) = rows()
    assert row.state == "failed" and "nothing was written" in row.error


def test_the_restore_test_fails_a_dump_that_does_not_restore(backups, tmp_path):
    set_phrase(backups)
    path = tmp_path / "nik-20261120-120000.nikbak"
    with open(path, "wb") as out:
        writer = container.Writer(out, container.Key.new(container.PASSPHRASE, PHRASE))
        if POSTGRES:
            table = {"name": "users", "columns": [{"name": "id", "type": "integer", "notnull": True, "default": None}]}
            schema = {"engine": "postgresql", "revision": None, "tables": [table]}
            with writer.part("db/schema.json") as part:
                part.write(json.dumps(schema).encode())
            with writer.part("db/users.copy") as part:
                part.write(b"not a number\n")
            rows_held = {"users": 1}
        else:
            with writer.part("db/schema.json") as part:
                part.write(b'{"engine": "sqlite", "revision": null}')
            with writer.part("db/sqlite") as part:
                part.write(b"this is not a database file" * 100)
            rows_held = {}
        engine_name = "postgresql" if POSTGRES else "sqlite"
        writer.finish({"database": {"engine": engine_name, "revision": None, "rows": rows_held}, "store": None})
    result = runner.check_file(path, container.Secrets(passphrases=(PHRASE,)))
    assert result["passed"] is False and result["error"]
    assert database.leftovers() == [], "the scratch database is dropped when the test fails too"


def test_the_restore_test_fails_when_rows_are_missing(backups, monkeypatch):
    set_phrase(backups)
    real = database.dump

    def one_more(writer, url=None, **options):
        described = real(writer, url, **options)
        described["rows"] = {**described["rows"], "users": described["rows"]["users"] + 1}
        return described

    monkeypatch.setattr(database, "dump", one_more)
    name = runner.take(now=T0)
    (row,) = rows()
    assert (row.state, row.verify_state) == ("done", "failed")
    assert "Not every row came back: users (1 for 2)" in row.verify["error"]
    assert audit_lines("backup.verify") == [f"The backup {name} failed its restore test: {row.verify['error']}"]
    assert database.leftovers() == []


def test_the_restore_test_fails_a_store_that_is_not_what_was_read(backups, monkeypatch):
    set_phrase(backups)
    real = store.pack

    def other_index(writer, root):
        held = real(writer, root)
        return {**held, "files": held["files"] + 1}

    monkeypatch.setattr(store, "pack", other_index)
    runner.take(now=T0)
    (row,) = rows()
    assert row.verify_state == "failed" and "does not hold what its manifest says" in row.verify["error"]


def test_a_scratch_database_cannot_be_the_live_one_and_is_always_dropped(backups):
    live = database.live_url()
    for name in (live.database or "nik", "nik", "postgres", "nik_scratch_", "nik_scratch_zzzzzzzzzzzz", "x; DROP"):
        with pytest.raises(container.BackupError, match="scratch database"):
            database.Scratch(live=live, name=name)
    made = []
    with pytest.raises(RuntimeError), database.Scratch("scratch") as scratch:
        made.append(scratch)
        assert scratch.url.database != live.database and database.SCRATCH_NAME.match(scratch.name)
        if POSTGRES:
            assert scratch.name in database.leftovers()
            # It belongs to a role of its own, which owns nothing of the database Nik runs on.
            assert scratch.role == scratch.name and scratch.url.username != live.username
        else:
            Path(scratch.url.database).write_bytes(b"x")
        raise RuntimeError("the test died")
    assert database.leftovers() == []
    if not POSTGRES:
        assert not Path(made[0].url.database).exists()
    made[0].drop()  # twice does no harm


@pytest.mark.skipif(not POSTGRES, reason="scratch databases left by a killed test exist on PostgreSQL only")
def test_what_a_killed_test_left_is_swept_by_the_next(backups):
    left = database.Scratch("scratch").create()
    other = database.Scratch("rehearsal", separate_role=False).create()
    assert set(database.leftovers()) == {left.name, other.name}
    assert database.sweep("scratch") == 1
    assert database.leftovers() == [other.name], "a rehearsal is not a restore test's to remove"
    other.drop()


@pytest.mark.skipif(not POSTGRES, reason="the schema is described and compared on PostgreSQL only")
def test_what_a_backup_cannot_carry_stops_it_with_its_name(backups):
    set_phrase(backups)
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE VIEW backup_test_view AS SELECT 1 AS one")
    try:
        runner.take(now=T0)
        (row,) = rows()
        assert row.state == "failed" and "the view backup_test_view" in row.error
    finally:
        with engine.begin() as conn:
            conn.exec_driver_sql("DROP VIEW backup_test_view")


def test_a_table_nobody_told_the_backups_about_is_carried_all_the_same(backups):
    """The backup reads what the database holds from the database itself, not from a list of tables
    written here: a table a later release adds (second factors, sessions, …) cannot be left out."""
    set_phrase(backups)
    with engine.begin() as conn:
        conn.exec_driver_sql("CREATE TABLE table_of_a_later_release (id INTEGER PRIMARY KEY, secret VARCHAR(40))")
        conn.exec_driver_sql("INSERT INTO table_of_a_later_release (id, secret) VALUES (1, 'a second factor')")
    try:
        name = runner.take(now=T0)
        (row,) = rows()
        assert (row.state, row.verify_state) == ("done", "passed"), row.error or row.verify
        with open(runner.file_of(name), "rb") as source:
            manifest = container.walk(source, container.Secrets(passphrases=(PHRASE,)))
        assert manifest["database"]["rows"]["table_of_a_later_release"] == 1
        with database.Scratch("scratch", separate_role=False) as scratch:
            loader = database.Loader(scratch.url)
            with open(runner.file_of(name), "rb") as source:
                reader = container.Reader(source, container.Secrets(passphrases=(PHRASE,)))
                for part in reader.parts():
                    loader.take(part)
            loader.finish(reader.manifest)
            import sqlalchemy as sa

            other = sa.create_engine(scratch.url)
            try:
                with other.connect() as conn:
                    kept = conn.exec_driver_sql("SELECT secret FROM table_of_a_later_release").scalar()
            finally:
                other.dispose()
        assert kept == "a second factor"
    finally:
        with engine.begin() as conn:
            conn.exec_driver_sql("DROP TABLE table_of_a_later_release")


def test_the_retention_removes_files_and_never_the_last_good_one(backups):
    set_phrase(backups)
    assert backups.put("/api/backups/settings", json={"retention": {"last": 1, "weeks": 0}}).status_code == 200
    first = runner.take(now=T0)
    second = runner.take(now=T0 + 3600)
    assert [row.id for row in rows()] == [second], "one is kept: the older good one went"
    assert not runner.file_of(first).exists() and not runner.note_of(first).exists()
    assert f"Deleted the backup {first} (the retention)" in audit_lines("backup.delete")
    with SessionLocal() as db:  # a newer one that fails its test does not push the good one out
        db.add(
            Backup(id="nik-20261120-150000", state="done", verify_state="failed", created_at=runner.iso(T0 + 3 * 3600))
        )
        db.commit()
        runner.apply_retention(db, T0 + 4 * 3600)
        db.commit()
    assert second in [row.id for row in rows()] and runner.file_of(second).exists()


def test_the_rows_follow_the_directory(backups):
    set_phrase(backups)
    name = runner.take(now=T0)
    with SessionLocal() as db:  # the table as a database put back from before the backup would have it
        db.query(Backup).delete()
        db.commit()
        runner.sync(db)
        db.commit()
    (row,) = rows()
    assert (row.id, row.state, row.verify_state, row.kind) == (name, "done", "passed", "full")
    assert row.summary["files"] == 3 and row.verify["checks"]
    runner.file_of(name).unlink()
    with SessionLocal() as db:
        runner.sync(db)
        db.commit()
    assert rows() == [], "a backup whose file is gone and has no copy elsewhere is not listed"


def test_a_run_that_died_is_said_to_have_failed(backups):
    set_phrase(backups)
    with SessionLocal() as db:
        runner.start_row(db, "full", "admin", T0, state="running")
        db.commit()
        runner.sync(db, T0 + 10)
        db.commit()
    (row,) = rows()
    assert row.state == "failed" and "stopped while this backup was being written" in row.error


# --------------------------------------------------------------------------- #
# The loop                                                                    #
# --------------------------------------------------------------------------- #
def test_the_schedule_takes_one_backup_per_slot_and_never_two_at_once(backups):
    set_phrase(backups)
    with SessionLocal() as db:  # the schedule and the passphrase were set before the slots below
        doc = config.read(db)
        config._keep(db, {**doc, "scheduleSetAt": 0, "passphraseSetAt": 0})
        db.commit()
    slot = at("2026-11-21T02:30")
    assert scheduler.tick(now=slot - 60) == ["backup:nik-20261121-022900"], "yesterday's slot had no backup yet"
    assert scheduler.tick(now=slot - 30) == []
    # The slot comes. Another process of the server finds the lease taken and does nothing.
    assert scheduler.tick(now=slot + 4, holder="another process") == []
    assert len(rows()) == 1
    assert scheduler.tick(now=slot + 5) == ["backup:nik-20261121-023005"]
    assert scheduler.tick(now=slot + 600) == [] and scheduler.tick(now=slot + 7200) == []
    assert len(rows()) == 2 and all(row.requested_by == "schedule" for row in rows())
    assert scheduler.tick(now=slot + 86400 + 6) == ["backup:nik-20261122-023006"]


def test_back_up_now_and_verify_now_are_done_by_the_loop(backups):
    set_phrase(backups)
    asked = backups.post("/api/backups/run")
    assert asked.status_code == 202 and asked.json()["state"] == "queued"
    name = asked.json()["id"]
    assert backups.post("/api/backups/run").status_code == 409, "one at a time"
    assert scheduler.tick() == [f"backup:{name}"]
    listed = backups.get("/api/backups").json()
    (shown,) = listed["backups"]
    assert (shown["state"], shown["verifyState"], shown["lastGood"], shown["requestedBy"]) == (
        "done",
        "passed",
        True,
        "admin",
    )
    assert shown["restoreCommand"] == f"deploy/restore.sh {name}" and listed["state"]["lastGood"]["id"] == name
    assert listed["state"]["running"] is False and listed["state"]["nextRun"]
    assert listed["state"]["space"] == {"kept": shown["size"], "count": 1, "lastGood": shown["size"]}
    again = backups.post(f"/api/backups/{name}/verify")
    assert again.status_code == 202 and again.json()["verifyState"] == "queued"
    assert backups.get("/api/backups").json()["state"]["running"] is True
    assert scheduler.tick() == [f"verify:{name}"]
    assert len(audit_lines("backup.verify")) == 2
    assert audit_lines("backup.request") == [f"Asked for the backup {name}", f"Asked for the restore test of {name}"]


def test_a_backup_asked_for_from_the_command_line_is_the_same_backup(backups, capsys, monkeypatch):
    from app.backups import now

    assert now.main(wait=0) == 1
    assert "no backup passphrase is set" in capsys.readouterr().err
    set_phrase(backups)
    # It leaves the request, as the screen does; the loop of the server takes the backup.
    monkeypatch.setattr(now.time, "sleep", lambda _seconds: scheduler.tick())
    assert now.main(wait=60) == 0
    said = capsys.readouterr().err
    (row,) = rows()
    assert f"asked for {row.id}" in said and "passed its restore test" in said and "files of the store" in said
    assert (row.state, row.verify_state, row.requested_by) == ("done", "passed", "deploy/backup.sh")
    assert audit_lines("backup.request") == [f"Asked for the backup {row.id}"]
    # One that fails says so, and the script that waits for it exits with 1.
    monkeypatch.setattr(store, "pack", lambda writer, root: (_ for _ in ()).throw(OSError("no such disk")))
    assert now.main(wait=60) == 1
    assert "failed: no such disk" in capsys.readouterr().err


# --------------------------------------------------------------------------- #
# The notices                                                                 #
# --------------------------------------------------------------------------- #
def notices() -> list[tuple[str, str]]:
    with SessionLocal() as db:
        return [(row.kind, row.text) for row in db.scalars(select(Notification).order_by(Notification.at))]


def roomy(_path):
    return Disk(10**12, 10**11, 9 * 10**11)


def test_one_notice_per_problem_and_one_when_it_is_solved(backups, monkeypatch):
    set_phrase(backups)
    with SessionLocal() as db:
        config._keep(db, {**config.read(db), "scheduleSetAt": 0, "passphraseSetAt": T0 - 60})
        db.commit()
    assert watch.check(T0, usage=roomy) == []
    monkeypatch.setattr(store, "pack", lambda writer, root: (_ for _ in ()).throw(OSError("no such disk")))
    runner.take(now=T0 + 10)
    assert watch.check(T0 + 20, usage=roomy) == ["problem:failed"]
    assert watch.check(T0 + 80, usage=roomy) == [], "nothing in between"
    assert watch.check(T0 + 80, holder="the automation worker", usage=roomy) == [], "one process looks at a time"
    assert backups.get("/api/backups").json()["state"]["problems"][0]["id"] == "failed"
    monkeypatch.undo()
    monkeypatch.setattr(container, "SCRYPT_N", 2**10)
    monkeypatch.setattr(settings, "BACKUP_DIR", str(Path(settings.BACKUP_DIR)))
    runner.take(now=T0 + 100)
    assert rows()[-1].verify_state == "passed"
    assert watch.check(T0 + 200, usage=roomy) == ["solved:failed"]
    assert watch.check(T0 + 300, usage=roomy) == []
    told = notices()
    assert [kind for kind, _text in told] == ["backup.problem", "backup.solved"]
    assert "failed: no such disk" in told[0][1] and told[1][1] == "A backup was written again."
    with SessionLocal() as db:
        link = db.scalars(select(Notification.link)).first()
    assert link == "/settings/system/backup"


def test_every_administrator_is_told_and_nobody_else(backups):
    created = backups.post("/api/users", json={"username": "second", "password": "another-secret", "roles": ["admin"]})
    assert created.status_code == 201, created.text
    backups.post("/api/users", json={"username": "reader", "password": "another-secret", "roles": ["analyst"]})
    set_phrase(backups)
    with SessionLocal() as db:
        db.add(Backup(id="nik-20261120-110000", state="failed", error="it broke", created_at=runner.iso(T0)))
        db.commit()
    assert watch.check(T0 + 5, usage=roomy) == ["problem:failed"]
    with SessionLocal() as db:
        assert sorted(db.scalars(select(Notification.username))) == ["admin", "second"]


def test_a_missed_backup_and_an_old_one_are_told(backups):
    set_phrase(backups)
    slot = at("2026-11-21T02:30")
    with SessionLocal() as db:
        config._keep(db, {**config.read(db), "scheduleSetAt": 0, "passphraseSetAt": slot - 86400})
        db.commit()
    assert watch.check(slot + 3600, usage=roomy) == [], "the grace is not over"
    assert watch.check(slot + 3 * 3600, usage=roomy) == ["problem:missed"]
    assert watch.check(slot + 4 * 3600, usage=roomy) == []
    # 36 hours after the passphrase was set there is still no good backup.
    assert watch.check(slot + 13 * 3600, usage=roomy) == ["problem:stale"]
    with SessionLocal() as db:
        problems = watch.problems(db, slot + 13 * 3600, roomy)
    assert "No backup was taken at 2026-11-21 02:30 UTC" in problems["missed"]
    assert "no good backup yet" in problems["stale"]
    runner.take(now=slot + 14 * 3600)
    assert sorted(watch.check(slot + 14 * 3600 + 60, usage=roomy)) == ["solved:missed", "solved:stale"]
    # A good backup that gets old is told too.
    assert watch.check(slot + 14 * 3600 + 37 * 3600, usage=roomy) == ["problem:missed", "problem:stale"]


def test_a_backup_that_fails_its_test_and_a_full_directory_are_told(backups, monkeypatch):
    set_phrase(backups)
    name = runner.take(now=T0)
    # Room for less than two backups the size of the last good one is "nearly full", however large the disk.
    size = runner.file_of(name).stat().st_size
    with SessionLocal() as db:
        assert "disk" not in watch.problems(db, T0 + 5, lambda _path: Disk(10 * size, 8 * size, 2 * size))
        tight = watch.problems(db, T0 + 5, lambda _path: Disk(10 * size, 8 * size, 2 * size - 1))
    assert f"The next backup needs about {size // 2**20} MB." in tight["disk"]
    with SessionLocal() as db:
        row = db.get(Backup, name)
        row.verify_state, row.verify = "failed", {"passed": False, "error": "a row is missing"}
        db.commit()
    full = lambda _path: Disk(10**9, 96 * 10**7, 4 * 10**7)  # noqa: E731
    assert sorted(watch.check(T0 + 10, usage=full)) == ["problem:disk", "problem:verify"]
    with SessionLocal() as db:
        problems = watch.problems(db, T0 + 10, full)
    assert problems["verify"] == f"The backup {name} failed its restore test: a row is missing"
    assert "nearly full: 38 MB free of 953 MB" in problems["disk"]
    assert watch.check(T0 + 70, usage=roomy) == ["solved:disk"]


def test_a_server_with_no_passphrase_is_told_after_a_day(backups):
    assert watch.check(T0, usage=roomy) == []
    later = datetime.now(timezone.utc).timestamp() + 2 * 86400
    assert watch.check(later, usage=roomy) == ["problem:unset"]
    set_phrase(backups)
    with SessionLocal() as db:
        config._keep(db, {**config.read(db), "passphraseSetAt": later, "scheduleSetAt": later})
        db.commit()
    assert watch.check(later + 60, usage=roomy) == ["solved:unset"]
    assert notices()[0][1].startswith("No backup passphrase is set")


# --------------------------------------------------------------------------- #
# The routes                                                                  #
# --------------------------------------------------------------------------- #
def test_what_a_server_starts_with(client):
    assert config.DEFAULTS["schedule"] == {
        "enabled": True,
        "every": "hours",
        "hours": 6,
        "at": "02:30",
        "weekday": 6,
        "timezone": "UTC",
    }
    assert config.DEFAULTS["retention"] == {"last": 8, "weeks": 4, "upgrades": 3}
    assert config.DEFAULTS["warnAfterHours"] == 13 and config.DEFAULTS["includeKey"] is False
    with SessionLocal() as db:
        assert config.read(db)["schedule"] == config.DEFAULTS["schedule"]
    # Every six hours, counted from 02:30: four runs a day.
    day = at("2026-11-20T00:00")
    slots = sorted({policy.latest_slot(config.DEFAULTS["schedule"], day + hour * 3600 + 1800) for hour in range(3, 27)})
    assert [datetime.fromtimestamp(slot, timezone.utc).strftime("%d %H:%M") for slot in slots] == [
        "20 02:30",
        "20 08:30",
        "20 14:30",
        "20 20:30",
        "21 02:30",
    ]


def test_the_settings_are_kept_checked_and_audited(backups):
    first = backups.get("/api/backups").json()
    assert first["settings"]["schedule"] == {**DAILY, "weekday": 6}
    assert first["settings"]["retention"] == {"last": 7, "weeks": 4, "upgrades": 3}
    assert first["settings"]["passphraseSet"] is False and first["state"]["nextRun"] is None
    assert first["backups"] == [] and first["state"]["lastGood"] is None
    sent = {
        "schedule": {"every": "hours", "hours": 4, "at": "01:15", "timezone": "Europe/Rome"},
        "retention": {"last": 10, "weeks": 8},
        "warnAfterHours": 12,
    }
    saved = backups.put("/api/backups/settings", json=sent)
    assert saved.status_code == 200, saved.text
    kept = saved.json()["settings"]
    assert kept["schedule"] == {**DAILY, **sent["schedule"]} and kept["retention"] == {
        "last": 10,
        "weeks": 8,
        "upgrades": 3,
    }
    assert kept["warnAfterHours"] == 12
    assert audit_lines("backup.settings") == [
        "Changed the backups: the schedule, the retention, the age that is warned about"
    ]
    assert backups.put("/api/backups/settings", json=sent).status_code == 200
    assert len(audit_lines("backup.settings")) == 1, "nothing changed, nothing written"
    for wrong, said in (
        ({"schedule": {"every": "month"}}, "every day, every week or every few hours"),
        ({"schedule": {"at": "25:00"}}, "HH:MM"),
        ({"schedule": {"timezone": "Mars/Olympus"}}, "not a time zone"),
        ({"schedule": {"hours": 0}}, "from 1 to 23"),
        ({"retention": {"last": 0}}, "from 1 to 365"),
        ({"warnAfterHours": "soon"}, "whole number"),
        ({"includeKey": "yes"}, "yes or no"),
        ({"destination": {"kind": "ftp"}}, "SFTP server, or nowhere"),
        ({"destination": {"kind": "sftp", "host": "second.example", "user": "nik", "path": "../etc"}}, "is a path"),
        ({"destination": {"kind": "sftp", "host": "bad host", "user": "nik", "path": "b"}}, "a name or an address"),
    ):
        refused = backups.put("/api/backups/settings", json=wrong)
        assert refused.status_code == 422 and said in refused.json()["detail"], (wrong, refused.text)


def test_the_passphrase_is_kept_encrypted_and_never_given_back(backups):
    for weak in ("short", " padded passphrase ", 12345678901234):
        assert backups.put("/api/backups/passphrase", json={"passphrase": weak}).status_code == 422
    set_phrase(backups)
    shown = backups.get("/api/backups")
    assert shown.json()["settings"]["passphraseSet"] is True and shown.json()["settings"]["passphraseReadable"] is True
    assert PHRASE not in shown.text
    with SessionLocal() as db:
        kept = config.read(db)
        assert PHRASE not in json.dumps(kept) and config.passphrase(db) == PHRASE
    # Changed: the earlier one still opens the backups made under it.
    name = runner.take(now=T0)
    set_phrase(backups, "the second passphrase")
    assert PHRASE not in backups.get("/api/backups").text
    with SessionLocal() as db:
        assert config.secrets(db).passphrases == ("the second passphrase", PHRASE)
    assert runner.verify(name) is True
    assert audit_lines("backup.settings") == ["Set the backup passphrase", "Changed the backup passphrase"]
    assert PHRASE not in " ".join(audit_lines("backup.settings"))


def test_the_secrets_of_the_backups_follow_a_change_of_secret_key(backups, monkeypatch):
    from app.core import vault

    set_phrase(backups)
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [settings.SECRET_KEY])
    monkeypatch.setattr(settings, "SECRET_KEY", "a new secret key for the server")
    assert vault.reencrypt(SessionLocal) == 1
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    with SessionLocal() as db:
        assert config.passphrase(db) == PHRASE


def test_deleting_asks_for_the_name_and_twice_for_the_last_good_one(backups):
    set_phrase(backups)
    first = runner.take(now=T0)
    second = runner.take(now=T0 + 3600)
    assert backups.delete(f"/api/backups/{first}").status_code == 422
    assert backups.delete(f"/api/backups/{first}?confirm=nik-wrong").status_code == 422
    assert backups.delete(f"/api/backups/{first}?confirm={first}").json() == {"deleted": first}
    assert not runner.file_of(first).exists() and [row.id for row in rows()] == [second]
    last = backups.delete(f"/api/backups/{second}?confirm={second}")
    assert last.status_code == 409 and "last good backup" in last.json()["detail"]
    assert runner.file_of(second).exists()
    assert backups.delete(f"/api/backups/{second}?confirm={second}&lastGood=true").status_code == 200
    assert rows() == [] and list(Path(settings.BACKUP_DIR).iterdir()) == []
    assert audit_lines("backup.delete") == [f"Deleted the backup {first}", f"Deleted the backup {second}"]
    assert backups.delete(f"/api/backups/{second}?confirm={second}").status_code == 404
    assert backups.delete("/api/backups/..%2Fetc?confirm=x").status_code == 404


def test_a_download_is_the_encrypted_file_and_is_audited(backups):
    set_phrase(backups)
    name = runner.take(now=T0)
    got = backups.get(f"/api/backups/{name}/download")
    assert got.status_code == 200 and got.content == runner.file_of(name).read_bytes()
    assert got.content.startswith(container.MAGIC) and f"{name}.nikbak" in got.headers["content-disposition"]
    assert audit_lines("backup.download") == [f"Downloaded the backup {name}"]
    assert backups.get("/api/backups/nik-20000101-000000/download").status_code == 404


def test_only_an_administrator_reaches_the_backups(backups):
    from tests.conftest import make_key

    for role in ("viewer", "analyst", "audit", "playbooks"):
        key = make_key(backups, label=role, roles=[role])
        backups.cookies.clear()
        assert backups.get("/api/backups", headers=key).status_code == 403
        # The passphrase is a signed-in administrator's to set: a key, whatever its roles, is not one.
        assert backups.put("/api/backups/passphrase", json={"passphrase": PHRASE}, headers=key).status_code == 401
        assert backups.post("/api/backups/run", headers=key).status_code == 403
        login = backups.post("/api/auth/login", json={"username": "admin", "password": "supersecret"})
        assert login.status_code == 200
