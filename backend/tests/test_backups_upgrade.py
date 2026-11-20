"""The snapshot before an upgrade and the rehearsal of the migrations; putting a backup back.

A release that has migrations to run is made here by copying the migrations
of Nik and adding one more after the last: one that works, one that fails,
one that fails on the database itself only. The database is the suite's own,
put at the revision of this version first (SQLite, or PostgreSQL in the
``backend-postgres`` job).
"""

from __future__ import annotations

import json
import os
import shutil
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import sqlalchemy as sa

from app.backups import config, container, database, restore, runner, upgrade
from app.core.config import settings
from app.core.db import SessionLocal, engine
from app.core.models import Setting, User

from .test_backups import POSTGRES, T0, backups, quick_keys, set_phrase  # noqa: F401 - fixtures

BACKEND = Path(database.__file__).resolve().parents[2]
HEAD = database.head_revision()

WORKS = """
import sqlalchemy as sa
from alembic import op

revision = "9001_next_release"
down_revision = "{head}"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table("upgrade_probe", sa.Column("id", sa.Integer, primary_key=True), sa.Column("note", sa.String))
    op.execute("INSERT INTO upgrade_probe (id, note) VALUES (1, 'migrated')")
    {then}


def downgrade():
    op.drop_table("upgrade_probe")
"""
FAILS = 'raise RuntimeError("this migration cannot work")'
# The scratch database of a rehearsal is named for it: this one fails everywhere else.
FAILS_LIVE = (
    'if "nik_rehearsal_" not in str(op.get_bind().engine.url.database): raise RuntimeError("only on the real one")'
)


def table_names() -> set[str]:
    return set(sa.inspect(engine).get_table_names())


def revision_now() -> str | None:
    with engine.connect() as conn:
        if "alembic_version" not in table_names():
            return None
        return conn.execute(sa.text("SELECT version_num FROM alembic_version")).scalar()


@pytest.fixture()
def at_head(backups):  # noqa: F811
    """The suite's database, said to be at the revision of this version, and put back as it was after."""
    before = revision_now()
    had_table = "alembic_version" in table_names()
    with engine.begin() as conn:
        if not had_table:
            conn.execute(sa.text("CREATE TABLE alembic_version (version_num VARCHAR(32) NOT NULL PRIMARY KEY)"))
        conn.execute(sa.text("DELETE FROM alembic_version"))
        conn.execute(sa.text("INSERT INTO alembic_version (version_num) VALUES (:head)"), {"head": HEAD})
    yield backups
    engine.dispose()
    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS upgrade_probe"))
        if had_table:
            conn.execute(sa.text("DELETE FROM alembic_version"))
            if before:
                conn.execute(sa.text("INSERT INTO alembic_version (version_num) VALUES (:rev)"), {"rev": before})
        else:
            conn.execute(sa.text("DROP TABLE alembic_version"))


def release(tmp_path: Path, then: str = "pass") -> Path:
    """A copy of the migrations of Nik with one more: the ``alembic.ini`` of a "next release"."""
    target = tmp_path / "next"
    shutil.copytree(BACKEND / "alembic", target / "alembic", ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copy(BACKEND / "alembic.ini", target / "alembic.ini")
    (target / "alembic" / "versions" / "9001_next_release.py").write_text(WORKS.format(head=HEAD, then=then))
    return target / "alembic.ini"


def snapshots() -> list[Path]:
    return sorted(Path(settings.BACKUP_DIR).glob("nik-upgrade-*.nikbak"))


def test_nothing_happens_when_the_database_is_at_this_version(at_head):
    outcome = upgrade.run()
    assert (outcome.migrated, outcome.snapshot, outcome.before, outcome.after) == (False, "", HEAD, HEAD)
    assert not Path(settings.BACKUP_DIR).exists()
    with SessionLocal() as db:
        assert db.get(Setting, upgrade.SETTINGS_ID).doc["version"] == runner.nik_version()


def test_an_upgrade_takes_a_snapshot_rehearses_and_migrates(at_head, tmp_path):
    with SessionLocal() as db:  # the version that ran here before, as its last start wrote it
        db.add(Setting(id=upgrade.SETTINGS_ID, doc={"version": "6.6.0", "revision": HEAD}))
        db.commit()
    outcome = upgrade.run(release(tmp_path), now=T0)
    assert outcome.migrated and outcome.rehearsed and (outcome.before, outcome.after) == (HEAD, "9001_next_release")
    assert set(outcome.seconds) == {"snapshot", "rehearsal", "migration"}
    assert revision_now() == "9001_next_release" and "upgrade_probe" in table_names()
    (snapshot,) = snapshots()
    assert snapshot.name == "nik-upgrade-20261120-120000.nikbak" == outcome.snapshot + ".nikbak"
    note = json.loads(snapshot.with_suffix(".json").read_text())
    assert note["kind"] == "upgrade" and note["label"] == f"Before the upgrade from 6.6.0 to {runner.nik_version()}"
    assert note["upgrade"] | {"database": "", "python": ""} == {
        "fromVersion": "6.6.0",
        "fromRevision": HEAD,
        "toVersion": runner.nik_version(),
        "toRevision": "9001_next_release",
        "tag": "v6.6.0",
        "database": "",
        "python": "",
        "rehearsed": True,
        "done": True,
    }
    # No passphrase was set: the snapshot is encrypted all the same, under SECRET_KEY, and holds no store.
    assert note["keyFrom"] == "secret-key" and settings.SECRET_KEY.encode() not in snapshot.read_bytes()
    with open(snapshot, "rb") as source:
        manifest = container.walk(source, container.Secrets(secret_keys=(settings.SECRET_KEY,)))
    assert manifest["store"] is None and manifest["database"]["revision"] == HEAD
    assert "store.tar" not in [part["name"] for part in manifest["parts"]]
    assert "upgrade_probe" not in manifest["database"]["rows"], "the snapshot is the database as it was before"
    assert database.leftovers() == []
    with SessionLocal() as db:
        runner.sync(db)  # the server then lists it among its backups
        db.commit()
        doc = db.get(Setting, upgrade.SETTINGS_ID).doc
    assert doc["version"] == runner.nik_version() and doc["revision"] == "9001_next_release"
    listed = at_head.get("/api/backups").json()["backups"]
    assert [(row["kind"], row["label"], row["restoreCommand"]) for row in listed] == [
        ("upgrade", note["label"], f"deploy/rollback.sh {outcome.snapshot}")
    ]
    # The rehearsal restored it: that was its restore test.
    assert listed[0]["verifyState"] == "passed"
    assert "the migrations of the new version ran on the restored copy" in listed[0]["verify"]["checks"]


def test_the_snapshot_uses_the_passphrase_when_one_is_set(at_head, tmp_path):
    set_phrase(at_head)
    outcome = upgrade.run(release(tmp_path), now=T0)
    note = runner.read_note(outcome.snapshot)
    assert note["keyFrom"] == "passphrase" and note["upgrade"]["fromVersion"] == ""
    assert note["label"] == f"Before the upgrade from {HEAD} to {runner.nik_version()}"


def test_a_migration_that_fails_in_rehearsal_leaves_the_database_untouched(at_head, tmp_path):
    with SessionLocal() as db:
        users_before = db.query(User).count()
    with pytest.raises(upgrade.Stopped) as stopped:
        upgrade.run(release(tmp_path, FAILS), now=T0)
    assert stopped.value.stage == "rehearsal"
    assert "fail on a copy of this database" in stopped.value.message
    assert "The database itself was not touched" in stopped.value.message
    assert "this migration cannot work" in stopped.value.output
    assert revision_now() == HEAD and "upgrade_probe" not in table_names()
    with SessionLocal() as db:
        assert db.query(User).count() == users_before
    assert snapshots() == [] and stopped.value.snapshot == "", "nothing changed, so nothing is kept to come back from"
    assert database.leftovers() == []
    # What an anonymous browser is told names no detail of the database.
    body = upgrade.stopped_body(stopped.value)
    assert body["upgrade"] == {"stopped": True, "stage": "rehearsal", "version": runner.nik_version()}
    assert "The data is as it was" in body["detail"] and "cannot work" not in json.dumps(body)
    text = upgrade.explain(stopped.value)
    assert "NIK DID NOT START" in text and "this migration cannot work" in text and "Nothing has to be put back" in text


def test_a_migration_that_fails_on_the_database_itself_keeps_the_snapshot(at_head, tmp_path):
    with pytest.raises(upgrade.Stopped) as stopped:
        upgrade.run(release(tmp_path, FAILS_LIVE), now=T0)
    assert stopped.value.stage == "migration" and "only on the real one" in stopped.value.output
    (snapshot,) = snapshots()
    assert stopped.value.snapshot == snapshot.name[: -len(".nikbak")]
    assert f"The snapshot {stopped.value.snapshot} holds it as it was before" in stopped.value.message
    assert "deploy/rollback.sh" in upgrade.explain(stopped.value)
    if POSTGRES:  # there a migration is one transaction: it left nothing
        assert revision_now() == HEAD and "upgrade_probe" not in table_names()


def test_without_the_rehearsal_the_snapshot_is_still_taken(at_head, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "UPGRADE_REHEARSAL", False)
    with pytest.raises(upgrade.Stopped) as stopped:
        upgrade.run(release(tmp_path, FAILS), now=T0)
    assert stopped.value.stage == "migration" and len(snapshots()) == 1
    for path in Path(settings.BACKUP_DIR).iterdir():
        path.unlink()
    with engine.begin() as conn:
        conn.execute(sa.text("DROP TABLE IF EXISTS upgrade_probe"))
        conn.execute(sa.text("UPDATE alembic_version SET version_num = :head"), {"head": HEAD})
    outcome = upgrade.run(release(tmp_path / "ok"), now=T0)
    assert outcome.migrated and not outcome.rehearsed and set(outcome.seconds) == {"snapshot", "migration"}


def test_a_database_from_a_later_version_is_refused_untouched(at_head):
    with engine.begin() as conn:
        conn.execute(sa.text("UPDATE alembic_version SET version_num = '9999_from_later'"))
    with pytest.raises(upgrade.Stopped) as stopped:
        upgrade.run()
    assert stopped.value.stage == "checks" and "a later version of Nik migrated it" in stopped.value.message
    assert revision_now() == "9999_from_later" and not Path(settings.BACKUP_DIR).exists()


def test_no_room_for_the_snapshot_stops_the_upgrade_before_it_starts(at_head, tmp_path, monkeypatch):
    from collections import namedtuple

    disk = namedtuple("disk", "total used free")
    monkeypatch.setattr(shutil, "disk_usage", lambda _path: disk(10**9, 10**9, 100))
    with pytest.raises(upgrade.Stopped) as stopped:
        upgrade.run(release(tmp_path), now=T0)
    assert stopped.value.stage == "checks" and "The database was not changed" in stopped.value.message
    assert revision_now() == HEAD and snapshots() == []


def test_only_the_latest_snapshots_are_kept(at_head, tmp_path):
    assert at_head.put("/api/backups/settings", json={"retention": {"upgrades": 2}}).status_code == 200
    taken = []
    for index in range(3):
        with engine.begin() as conn:
            conn.execute(sa.text("DROP TABLE IF EXISTS upgrade_probe"))
            conn.execute(sa.text("UPDATE alembic_version SET version_num = :head"), {"head": HEAD})
        taken.append(upgrade.run(release(tmp_path / str(index)), now=T0 + index * 60).snapshot)
    assert [path.name[: -len(".nikbak")] for path in snapshots()] == taken[1:]
    assert not runner.note_of(taken[0]).exists()


@pytest.mark.skipif(not POSTGRES, reason="the lock of the migrations is PostgreSQL's")
def test_no_backup_is_taken_while_the_database_is_migrated(at_head):
    set_phrase(at_head)
    with upgrade._Lock(database.live_url()):
        runner.take(now=T0)
    (row,) = [row for row in at_head.get("/api/backups").json()["backups"]]
    assert row["state"] == "failed" and "being migrated" in row["error"]
    runner.take(now=T0 + 60)
    assert at_head.get("/api/backups").json()["backups"][0]["state"] == "done"


def test_the_server_that_did_not_start_says_so_to_every_request():
    stopped = upgrade.Stopped("rehearsal", "the migrations fail: relation secret_table does not exist")
    server = upgrade.serve_stopped(stopped, port=0)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=5) as health:
            assert health.status == 200 and json.loads(health.read()) == {"status": "upgrade-stopped"}
        for method, path in (("GET", "/api/auth/me"), ("POST", "/api/auth/login"), ("GET", "/api/incidents?x=1")):
            request = urllib.request.Request(
                f"http://127.0.0.1:{port}{path}", method=method, data=b"" if method == "POST" else None
            )
            with pytest.raises(urllib.error.HTTPError) as refused:
                urllib.request.urlopen(request, timeout=5)
            assert refused.value.code == 503
            body = json.loads(refused.value.read())
            assert body["upgrade"]["stopped"] is True and "secret_table" not in json.dumps(body)
    finally:
        server.shutdown()
        server.server_close()


# --------------------------------------------------------------------------- #
# Putting a backup back                                                       #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def elsewhere(backups, tmp_path, monkeypatch):  # noqa: F811
    """A backup of this server, and an empty server to put it on: another database, another store."""
    set_phrase(backups)
    name = runner.take(now=T0)
    source_store = Path(settings.SAMPLE_STORE)
    target_store = tmp_path / "restored-store"
    scratch = database.Scratch("scratch", separate_role=False).create()
    monkeypatch.setattr(database, "live_url", lambda: scratch.url)
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(target_store))
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", "a passphrase for the tests")
    yield runner.file_of(name), source_store, target_store, scratch
    monkeypatch.undo()
    scratch.drop()


def users_in(url) -> list[str]:
    other = sa.create_engine(url)
    try:
        with other.connect() as conn:
            return [row[0] for row in conn.execute(sa.text("SELECT username FROM users"))]
    finally:
        other.dispose()


def test_a_backup_is_restored_on_an_empty_server(elsewhere, capsys):
    path, source_store, target_store, scratch = elsewhere
    assert restore.main(["restore", str(path)]) == 0
    said = capsys.readouterr().err
    assert "The file is whole" in said and "Restoring the database and the store of files" in said
    assert "Now start the stack" in said and "SECRET_KEY the backup" in said
    assert ("nothing to migrate" in said) == (database.about()["revision"] == HEAD)
    assert users_in(scratch.url) == ["admin"]
    # The backup holds its own row as it was while it was written ("running"): not on the restored server.
    other = sa.create_engine(scratch.url)
    with other.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM backups")).scalar() == 0
    other.dispose()
    restored = {
        path.relative_to(target_store).as_posix(): path.read_bytes()
        for path in target_store.rglob("*")
        if path.is_file()
    }
    original = {
        path.relative_to(source_store).as_posix(): path.read_bytes()
        for path in source_store.rglob("*")
        if path.is_file()
    }
    assert restored == original and len(restored) == 3
    # A second time: the server is not empty any more, and nothing is touched without the word for it.
    (target_store / "added-since").write_bytes(b"kept")
    assert restore.main(["restore", str(path)]) == 1
    assert "The database is not empty. Nothing was changed" in capsys.readouterr().err
    assert (target_store / "added-since").exists()
    assert restore.main(["restore", str(path), "--replace"]) == 0
    assert users_in(scratch.url) == ["admin"] and not (target_store / "added-since").exists()


def test_a_store_that_is_not_empty_is_not_written_over(elsewhere, capsys):
    path, _source, target_store, scratch = elsewhere
    target_store.mkdir()
    (target_store / "evidence.bin").write_bytes(b"already here")
    assert restore.main(["restore", str(path)]) == 1
    assert "The store of files" in capsys.readouterr().err and database.about(scratch.url)["empty"]
    assert restore.main(["restore", str(path), "--database-only"]) == 0
    assert users_in(scratch.url) == ["admin"] and [entry.name for entry in target_store.iterdir()] == ["evidence.bin"]


def test_a_restore_needs_the_passphrase_and_a_whole_file(elsewhere, capsys, monkeypatch, tmp_path):
    path, _source, target_store, scratch = elsewhere
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", "not the passphrase at all")
    assert restore.main(["restore", str(path)]) == 1
    assert "not the passphrase the backup was made with" in capsys.readouterr().err
    monkeypatch.delenv("NIK_BACKUP_PASSPHRASE")
    assert restore.main(["restore", str(path)]) == 1
    assert "Without it the backup cannot be read by anyone" in capsys.readouterr().err
    phrase_file = tmp_path / "phrase"
    phrase_file.write_text("a passphrase for the tests\n")
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE_FILE", str(phrase_file))
    damaged = tmp_path / path.name
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0xFF
    damaged.write_bytes(bytes(data))
    assert restore.main(["restore", str(damaged)]) == 1
    assert "damaged" in capsys.readouterr().err
    assert database.about(scratch.url)["empty"] and not target_store.exists(), "verified before anything is touched"
    assert restore.main(["inspect", str(path)]) == 0
    assert "is whole" in capsys.readouterr().err


def test_a_backup_from_a_later_version_is_refused(backups, tmp_path, monkeypatch, capsys):  # noqa: F811
    set_phrase(backups)
    monkeypatch.setattr(runner, "_version", "99.0.0")
    name = runner.take(now=T0)
    monkeypatch.setattr(runner, "_version", None)
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", "a passphrase for the tests")
    assert restore.main(["restore", name]) == 1
    said = capsys.readouterr().err
    assert "made by Nik 99.0.0" in said and "not restored into an earlier version" in said
    assert "Check out v99.0.0" in said and "Nothing was changed" in said


def test_an_older_backup_is_restored_and_migrated_at_the_next_start(elsewhere, capsys, monkeypatch):
    path, _source, _target, _scratch = elsewhere
    monkeypatch.setattr(database, "head_revision", lambda config=None: "9001_next_release")
    assert restore.main(["restore", str(path)]) == 0
    assert "the server migrates it" in capsys.readouterr().err


def test_the_backups_of_a_directory_are_listed_from_their_notes(backups, capsys):  # noqa: F811
    set_phrase(backups)
    name = runner.take(now=T0)
    assert restore.main(["list", settings.BACKUP_DIR]) == 0
    (line,) = capsys.readouterr().out.strip().splitlines()
    fields = line.split("\t")
    assert fields[0] == name and fields[1] == "full" and fields[4] == runner.nik_version()
    assert restore.main(["list", settings.BACKUP_DIR, "--kind", "upgrade"]) == 0
    assert capsys.readouterr().out == ""


def test_the_secret_key_of_a_backup_is_given_only_when_it_holds_one(backups, capsys, monkeypatch):  # noqa: F811
    set_phrase(backups)
    monkeypatch.setenv("NIK_BACKUP_PASSPHRASE", "a passphrase for the tests")
    without = runner.take(now=T0)
    assert restore.main(["secret-key", without]) == 1
    assert "does not hold a SECRET_KEY" in capsys.readouterr().err
    assert backups.put("/api/backups/settings", json={"includeKey": True}).status_code == 200
    with_key = runner.take(now=T0 + 60)
    assert restore.main(["secret-key", with_key]) == 0
    assert capsys.readouterr().out.strip() == f"SECRET_KEY={settings.SECRET_KEY}"
    assert os.environ.get("SECRET_KEY") != "never printed elsewhere"
    with SessionLocal() as db:
        assert config.read(db)["includeKey"] is True


def test_the_automation_worker_waits_for_the_database_to_be_migrated(monkeypatch):
    from app.automation import worker

    waits = []
    revisions = iter([None, "0001_old", database.head_revision()])
    monkeypatch.setattr(database, "about", lambda url=None: {"revision": next(revisions)})
    monkeypatch.setattr(worker._stopping, "wait", lambda seconds: waits.append(seconds))
    worker._wait_for_the_schema()
    assert waits == [5, 5], "it looked again until the revision was the one of its code"


def test_an_error_nobody_expected_does_not_restart_the_container_for_ever(monkeypatch, capsys):
    served = []

    class Server:
        def serve_forever(self):
            served.append(True)

    def breaks():
        raise ValueError("something nobody thought of")

    monkeypatch.setattr(upgrade, "run", breaks)
    monkeypatch.setattr(upgrade, "serve_stopped", lambda stopped: served.append(stopped) or Server())
    upgrade.main()
    assert served[0].stage == "unexpected" and served[1] is True
    said = capsys.readouterr().err
    assert "NIK DID NOT START" in said and "ValueError: something nobody thought of" in said
    assert upgrade.stopped_body(served[0])["detail"].startswith("The upgrade of Nik stopped in a way it did not expect")
