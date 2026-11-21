"""Where the recovery and the work in progress meet: a standby does no work, a promoted server
takes back what the dead host held, the files the two hosts leave for each other are signed, and
the loops of the recovery stop with the others.

The role of the server is what the tests say it is (``role.may_work`` or ``role.of`` replaced):
SQLite is never a standby. What needs a real pair of servers is proven on one, outside the suite.
Every loop here ends by a counter.
"""

from __future__ import annotations

import contextlib
import json
import threading
import time
import uuid

import pytest
from sqlalchemy import select

from app import work
from app.automation import state as automation_state
from app.automation import worker
from app.backups import runner
from app.core import leases, store
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AutomationEvent, Lease, Notification, WorkClaim
from app.health import checks, thresholds
from app.recovery import config, kept, role, scheduler, ship, standby, status, tool, watch

from .test_backups import PHRASE, T0, backups, quick_keys, set_phrase  # noqa: F401 - fixtures
from .test_backups_upgrade import elsewhere  # noqa: F401 - fixture
from .test_recovery import (  # noqa: F401 - fixtures
    inbox_of,
    pair,
    sealed_file,
    seg,
    segment,
    set_destination,
    there,
    volume,
)

NOW = 1_800_000_000.0


@pytest.fixture()
def not_serving(monkeypatch):
    """A server that does not serve: a standby, or one its standby replaced."""
    monkeypatch.setattr(role, "may_work", lambda db, now=None: False)


@pytest.fixture()
def things(client):
    """A kind of work of the tests' own, started again by the rule, and what was started."""
    started: list[str] = []
    work.register(work.Kind("thing", "a thing of the tests", "again", lambda ref, params: started.append(ref), print))
    yield started
    work._KINDS.pop("thing", None)


def leases_held() -> list[str]:
    with SessionLocal() as db:
        return sorted(db.scalars(select(Lease.name)))


class Postgres:
    """A session that says it is one of PostgreSQL, for the one function that asks."""

    class _Bind:
        class dialect:  # noqa: N801 - as SQLAlchemy names it
            name = "postgresql"

    def get_bind(self):
        return self._Bind()

    @contextlib.contextmanager
    def begin_nested(self):
        yield


# --------------------------------------------------------------------------- #
# A standby does no work                                                      #
# --------------------------------------------------------------------------- #
def test_the_role_is_asked_of_the_database_and_the_answer_kept_a_moment(monkeypatch):
    said = ["standby"]
    monkeypatch.setattr(role, "of", lambda db: said[0])
    db = Postgres()
    assert role.may_work(db, now=100.0) is False
    said[0] = "primary"
    assert role.may_work(db, now=100.0 + role.MAY_WORK_KEPT - 0.1) is False, "believed for a few seconds"
    assert role.may_work(db, now=100.0 + role.MAY_WORK_KEPT) is True, "then asked again: a promoted standby works"
    said[0] = "superseded"
    role.forget_may_work()
    assert role.may_work(db, now=200.0) is False, "a server that was replaced does not work either"

    def broken(db):
        raise RuntimeError("no table of settings yet")

    monkeypatch.setattr(role, "of", broken)
    role.forget_may_work()
    assert role.may_work(db, now=300.0) is True, "a database that cannot say is the server"
    monkeypatch.setattr(role, "of", lambda db: "standby")
    assert role.may_work(db, now=300.1) is False, "and that answer was not kept"


def test_no_lease_is_given_on_a_server_that_does_not_serve(client, not_serving):
    with SessionLocal() as db:
        assert leases.take(db, "a-loop", "me", 30, NOW) is False
        assert worker.acquire(db, now=NOW) is False
        assert runner.acquire(db, now=NOW) is False
        assert config.acquire(db, runner.HOLDER, NOW, ship.LEASE) is False
    assert leases_held() == [] and leases.held() == []


def test_a_lease_of_the_recovery_is_one_of_the_leases_of_the_process(client):
    with SessionLocal() as db:
        assert config.acquire(db, runner.HOLDER, NOW, "recovery")
        row = db.get(Lease, "recovery")
        assert row.expires_at == NOW + config.LEASE_SECONDS, "taken for its own, shorter time, in one statement"
    assert ("recovery", runner.HOLDER) in leases.held()
    assert leases.close() == 1 and leases_held() == []
    with SessionLocal() as db:
        # A loop still in the middle of a pass cannot take back what the stopping process gave back.
        assert config.acquire(db, runner.HOLDER, NOW + 1, "recovery") is False
        assert leases.take(db, "recovery", runner.HOLDER, 30, NOW + 1) is False
    leases.starting()
    with SessionLocal() as db:
        assert config.acquire(db, runner.HOLDER, NOW + 2, "recovery")


def test_the_automation_worker_takes_nothing_on_a_server_that_does_not_serve(admin, monkeypatch):
    with SessionLocal() as db:
        db.add(AutomationEvent(id=uuid.uuid4().hex, kind="incident.created", created_at="2026-11-20T12:00:00+00:00"))
        db.commit()
    with monkeypatch.context() as patched:
        patched.setattr(role, "may_work", lambda db, now=None: False)
        assert worker.tick(NOW) == {"runs": 0, "steps": 0}
        with SessionLocal() as db:
            assert db.scalars(select(AutomationEvent.done)).all() == [False], "no event becomes a run"
            assert not automation_state.read(db)["heartbeat"] and db.scalars(select(Lease)).all() == []
        assert work.sweep(NOW) == {"taken_back": [], "started": []}
    # Promoted: the same process goes on, nothing was restarted.
    worker.tick(NOW + 5)
    with SessionLocal() as db:
        assert db.scalars(select(AutomationEvent.id).where(AutomationEvent.done.is_(False))).all() == []
        assert db.get(Lease, worker.LEASE).holder == worker.HOLDER


def test_the_loop_of_the_worker_waits_until_the_server_serves_and_writes_nothing(admin, monkeypatch):
    asked = []

    class Stopping(threading.Event):
        def wait(self, timeout=None):
            asked.append(timeout)
            if len(asked) >= 3:
                self.set()
            return self.is_set()

    monkeypatch.setattr(worker, "_stopping", Stopping())
    monkeypatch.setattr(role, "may_work", lambda db, now=None: False)
    monkeypatch.setattr(worker, "tick", lambda **_: pytest.fail("a pass ran on a server that does not serve"))
    worker.loop()
    assert asked == [5, 5, 5]
    with SessionLocal() as db:
        assert not automation_state.read(db)["heartbeat"] and db.scalars(select(Lease)).all() == []


def test_the_names_of_the_holders_are_made_when_a_process_starts(client):
    """Two hosts run containers with the same names: a holder is a random number, never a name of
    the host, so the worker of the promoted server is never taken for the one that died."""
    from app import store_seal, worker_watch
    from app.enrichment import worker as enrichment

    names = [worker.HOLDER, work.HOLDER, runner.HOLDER, store_seal.HOLDER, worker_watch.HOLDER, enrichment.HOLDER]
    assert len(set(names)) == len(names)
    for name in names:
        assert uuid.UUID(name).version == 4


# --------------------------------------------------------------------------- #
# After a promotion                                                           #
# --------------------------------------------------------------------------- #
def held_elsewhere(ref: str, beat: float) -> None:
    with SessionLocal() as db:
        work.want(db, "thing", ref, now=beat)
        db.flush()
        row = db.get(WorkClaim, ("thing", ref))
        row.state, row.holder, row.beat_at, row.attempts = "held", "an-api-process-of-the-first-host", beat, 1
        db.commit()


def test_a_promoted_server_takes_back_what_the_first_host_held_whatever_its_clock_said(
    volume,  # noqa: F811
    things,
    tmp_path,
    monkeypatch,
    capsys,
):
    inbox_of(tmp_path, monkeypatch)
    standby.mark_promoting(NOW)
    # The clock of the first host ran an hour ahead of this one: by its heartbeat and by its leases
    # the processes that died there look alive for another hour.
    ahead = NOW + 3600
    held_elsewhere("a", ahead)
    with SessionLocal() as db:
        db.add(Lease(name=work.LEASE, holder="the sweeper of the first host", expires_at=ahead + 30))
        db.add(Lease(name=worker.LEASE, holder="the worker of the first host", expires_at=ahead + 30))
        db.commit()
    assert work.sweep(NOW) == {"taken_back": [], "started": []}
    assert worker.tick(NOW) == {"runs": 0, "steps": 0}
    assert tool.main(["promoted", "--name", "nik-b"]) == 0
    capsys.readouterr()
    assert leases_held() == []
    swept = work.sweep(NOW)
    assert swept["taken_back"] == [("thing", "a", "again")], "at the first pass, not an hour later"
    assert swept["started"] == [("thing", "a")] and things == ["a"]
    assert work.sweep(NOW + 1)["taken_back"] == [], "once"


def test_work_held_when_the_database_was_brought_back_is_silent_at_once(things):
    held_elsewhere("a", NOW + 3600)
    held_elsewhere("b", NOW - 5)
    with SessionLocal() as db:
        work.want(db, "thing", "c", now=NOW)
        assert work.orphan_all(db) == 2
        db.commit()
        assert sorted(ref for _kind, ref, _what in work.take_back(db, NOW)) == ["a", "b"]
        assert db.get(WorkClaim, ("thing", "c")).state == "wanted"


# --------------------------------------------------------------------------- #
# The files the two hosts leave for each other are signed                     #
# --------------------------------------------------------------------------- #
def test_a_marker_is_signed_with_a_key_of_its_own_derived_from_the_secret_key(client, monkeypatch):
    marker = role.new_marker(2, "nik-b", T0)
    assert len(marker["mac"]) == 64 and role.signed("marker", marker)
    assert role.read_marker(json.dumps(marker).encode())["signed"] is True
    assert not role.signed("heartbeat", marker), "a marker is not a heartbeat"
    for change in ({"generation": 9}, {"by": "somebody"}, {"at": T0 + 1}, {"id": "0" * 32}, {"mac": ""}):
        assert not role.signed("marker", {**marker, **change}), change
    assert not role.signed("marker", {key: value for key, value in marker.items() if key != "mac"})
    assert settings.SECRET_KEY not in json.dumps(marker) and role._mac_key(settings.SECRET_KEY) != role._mac_key("x")
    # The key was changed on this host since the standby was given it: the earlier one still counts.
    earlier = settings.SECRET_KEY
    monkeypatch.setattr(settings, "SECRET_KEY", "another-secret-key-of-this-server")
    assert not role.signed("marker", marker)
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [earlier])
    assert role.signed("marker", marker)


def test_a_marker_nobody_signed_is_not_obeyed_and_is_told_once(pair, admin):  # noqa: F811
    volume, server = pair  # noqa: F811
    set_destination(admin, server)
    segment(volume, 3)
    ship.ship(T0)
    folder = server.root / "nik-copies" / "recovery"
    forged = {"generation": 7, "at": T0 + 50, "by": "nobody", "id": "f" * 32}
    for written in (forged, {**forged, "mac": "0" * 64}, {**role.new_marker(7, "nobody", T0 + 50), "generation": 8}):
        (folder / "superseded.json").write_text(json.dumps(written))
        segment(volume, 4)
        did = ship.ship(T0 + 60)
        assert "superseded" not in did
        with SessionLocal() as db:
            assert role.of(db) == "primary" and role.state(db)["asked"]["verdict"] == "unsigned"
    assert f"{seg(4)}.nikwal" in there(server, "wal"), "the copies go on"
    assert scheduler.ask(T0 + 61) == "unsigned" and scheduler.stop_if_superseded() is False
    with SessionLocal() as db:
        found = watch.problems(db, T0 + 62)
        assert "is not signed with a key of this server: it is not obeyed" in found["marker"]
        assert watch.record(db, found, T0 + 62) == ["problem:marker"]
        db.commit()
        assert watch.record(db, watch.problems(db, T0 + 120), T0 + 120) == [], "told once"
        db.commit()
        told = [n.text for n in db.scalars(select(Notification).where(Notification.kind == "recovery.problem"))]
        assert len(told) == 1 and "superseded.json" in told[0]
        rows = {row["id"]: row for row in status.rows(db, T0 + 130)}
        assert rows["recovery.role"]["state"] == checks.PROBLEM and "not obeyed" in rows["recovery.role"]["detail"]
    # The same file, signed by a server that holds the key: obeyed.
    (folder / "superseded.json").write_text(json.dumps(role.new_marker(7, "nik-b", T0 + 50)))
    assert ship.ship(T0 + 200) == ["superseded"]
    with SessionLocal() as db:
        assert role.of(db) == "superseded"
        assert "marker" not in watch.problems(db, T0 + 210)


def test_the_heartbeat_is_signed_and_one_that_is_not_is_not_believed(pair, admin):  # noqa: F811
    volume, server = pair  # noqa: F811
    set_destination(admin, server)
    segment(volume, 3)
    ship.ship(T0)
    box = server.root / "nik-copies" / "recovery"
    said = json.loads((box / "heartbeat.json").read_text())
    assert role.signed("heartbeat", said) and standby.read_heartbeat(box)["lastWal"] == seg(3)
    assert standby.heartbeat_refused(box) is False
    (box / "heartbeat.json").write_text(json.dumps({**said, "behindSeconds": 0, "at": T0 + 500}))
    assert standby.read_heartbeat(box) is None and standby.heartbeat_refused(box) is True
    lines = status.loss({"replay": {"lastChange": T0 - 200}, "heartbeat": None, "heartbeatRefused": True}, T0)["lines"]
    assert "it is not signed with a key this host holds, so it is not believed" in lines[-1]
    assert "deploy/standby.sh secrets export" in lines[-1]


# --------------------------------------------------------------------------- #
# The loops of the recovery stop with the others                              #
# --------------------------------------------------------------------------- #
def test_a_shipper_that_is_asked_to_stop_finishes_its_file_and_starts_no_other(pair, admin):  # noqa: F811
    volume, server = pair  # noqa: F811
    set_destination(admin, server)
    for number in (3, 4, 5):
        segment(volume, number)
    sealed_file("7" * 64 + ".bin", b"a file of the store")
    asked = []

    def stopping() -> bool:
        asked.append(1)
        return len(asked) > 1  # asked before each file: the first goes, then the stop is heard

    did = ship.ship(T0, stopping=stopping)
    assert did == ["destination:new", f"wal:{seg(3)}"]
    assert there(server, "wal") == [f"{seg(3)}.nikwal"], "whole, and nothing half sent beside it"
    assert not [name for name in there(server, "wal") if name.endswith(".partial")]
    # The process that starts next goes on from the segment after the last one counted.
    assert [entry for entry in ship.ship(T0 + 10) if entry.startswith("wal:")] == [f"wal:{seg(4)}", f"wal:{seg(5)}"]


def test_the_loops_of_the_recovery_end_when_the_process_is_asked_to_stop(client, monkeypatch):
    flag = threading.Event()
    flag.set()
    monkeypatch.setattr(scheduler, "_stop_flag", lambda: flag)
    monkeypatch.setattr(ship, "ship", lambda **_: pytest.fail("a pass ran after the stop"))
    monkeypatch.setattr(scheduler.archive, "tick", lambda: pytest.fail("a pass ran after the stop"))
    scheduler._loop()
    scheduler._ship_loop()
    assert scheduler._stop_flag is not None and worker._stopping is not flag
    monkeypatch.undo()
    assert scheduler._stop_flag() is worker._stopping, "the flag every loop of the process obeys"


def test_a_request_the_recovery_service_never_answers_does_not_stay_asked_for_ever(volume, monkeypatch):  # noqa: F811
    """A base backup or a recovery test cut by a stop is done again by the service when it is
    back; when it never comes back the row and the test say failed, never "being taken"."""
    from app.core.models import RecoveryBase
    from app.recovery import agent, archive

    from .test_recovery import archiver, done_base

    done_base("base-20261120-110000", 3, T0 - 3600, volume)
    with SessionLocal() as db:
        state = {"since": T0 - 7200}
        archive.ask_test(state, "base-20261120-110000", T0 - 600, T0)
        config.keep(db, config.ARCHIVE_SETTINGS_ID, state)
        db.add(
            RecoveryBase(id="base-20261120-120000", state="requested", created_at=runner.iso(T0), facts={}, offsite={})
        )
        db.commit()
    # The service took both requests and was killed: nothing answers, the request of the base is gone.
    for path in (volume / "requests").iterdir():
        if path.name.startswith("base-"):
            path.unlink()
    assert agent.asked("base-20261120-120000") is False
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(T0 + archive.TEST_WAIT + 5))
    did = archive.tick(
        T0 + archive.TEST_WAIT + 5, usage=lambda _path: type("Disk", (), {"free": 10**12, "total": 10**12})
    )
    assert "failed:base-20261120-120000" in did and "test:failed" in did
    with SessionLocal() as db:
        assert db.get(RecoveryBase, "base-20261120-120000").state == "failed"
        assert "lost the request" in db.get(RecoveryBase, "base-20261120-120000").error
        tested = config.held(db, config.ARCHIVE_SETTINGS_ID)["tested"]
        assert tested["state"] == "failed" and "did not answer" in tested["error"]
        assert "test" in watch.problems(db, T0 + archive.TEST_WAIT + 6)


# --------------------------------------------------------------------------- #
# A database put back with the store left as it is                            #
# --------------------------------------------------------------------------- #
def test_files_deleted_since_a_snapshot_go_back_to_their_places(volume, monkeypatch):  # noqa: F811
    before = sealed_file("1" * 64 + ".bin", b"deleted before the snapshot")
    after = sealed_file("2" * 64 + ".bin", b"deleted after the snapshot")
    again = sealed_file("3" * 64 + ".bin", b"deleted after it, and uploaded again since")
    snapshot = T0
    assert kept.keep(before, snapshot - 100) and kept.keep(after, snapshot + 100) and kept.keep(again, snapshot + 200)
    sealed_file("3" * 64 + ".bin", b"deleted after it, and uploaded again since")
    assert kept.put_back_since(snapshot) == {"back": 1, "stayed": 1}
    assert after.is_file() and not before.exists()
    held = store.root() / ".kept"
    assert (held / str(int(snapshot - 100)) / before.name).is_file(), "what the snapshot did not name stays kept"
    assert (held / str(int(snapshot + 200)) / again.name).is_file(), "a place that is taken is left alone"
    assert not (held / str(int(snapshot + 100))).exists(), "an emptied folder goes"
    # Coming back to a version that knows nothing of kept files: everything goes back, the folder too.
    again.unlink()
    assert kept.put_back_since(0) == {"back": 2, "stayed": 0}
    assert before.is_file() and not held.exists()
    assert kept.put_back_since(0) == {"back": 0, "stayed": 0}


# --------------------------------------------------------------------------- #
# Health: one table, one notice                                               #
# --------------------------------------------------------------------------- #
def test_the_two_new_groups_of_the_health_page_do_not_meet(volume, admin, monkeypatch):  # noqa: F811
    import inspect
    import re

    from app.recovery import archive

    from .test_recovery import archiver, play_agent

    own = set(status.METRICS)
    assert all(name.startswith(("nik_recovery_", "nik_server_")) for name in own)
    written = re.findall(r'^    "(nik_[a-z_]+)": \(', inspect.getsource(checks), re.MULTILINE)
    assert len(written) == len(set(written)) and not own & set(written), "no metric is named twice"
    assert own <= set(checks.METRICS)
    now = time.time()
    monkeypatch.setattr(archive, "archiver", lambda db: archiver(now))
    play_agent(volume, now)
    archive.tick(usage=lambda _path: type("Disk", (), {"free": 10**12, "total": 10**12}))
    with SessionLocal() as db:
        rows = checks.gather(db, thresholds.read(db), {}, now)
    groups = list(dict.fromkeys(row["group"] for row in rows))
    assert groups.index("Queues") < groups.index("Work in progress") < groups.index("Workers")
    assert groups.index("Backups") < groups.index("Recovery") < groups.index("Certificate")
    assert len({row["id"] for row in rows}) == len(rows)
    # What the watch of the recovery tells the administrators about, the health page does not tell again.
    assert not [
        row["id"] for row in rows if row["group"] == "Recovery" and row["notify"] and row["id"] != "disk.archive"
    ]


# --------------------------------------------------------------------------- #
# After going back to a moment                                                #
# --------------------------------------------------------------------------- #
def test_going_back_to_a_named_moment_frees_the_work_and_turns_the_automation_off(
    volume,  # noqa: F811
    things,
    monkeypatch,
    capsys,
):
    from app.backups import database

    # The database of the tests is made without migrations: it is "at the revision of this version".
    monkeypatch.setattr(database, "head_revision", lambda: database.about()["revision"])
    held_elsewhere("a", NOW + 3600)
    with SessionLocal() as db:
        db.add(Lease(name=worker.LEASE, holder="the worker of that moment", expires_at=NOW + 3600))
        db.commit()
        assert automation_state.enabled(db)
    assert tool.main(["after", "--to", "2026-11-20 12:00:00+00", "--label", "base-20261120-110000"]) == 0
    said = "".join(capsys.readouterr())
    assert "the general switch of the automation was turned OFF" in said
    assert "a schedule whose time passed since runs once" in said and "makes it again" in said
    with SessionLocal() as db:
        assert not automation_state.enabled(db) and db.scalars(select(Lease)).all() == []
        assert [ref for _kind, ref, _what in work.take_back(db, NOW)] == ["a"]
        from app.core.models import AuditEntry

        entry = db.scalars(select(AuditEntry).where(AuditEntry.action == "audit.restore")).one()
        assert "The general switch of the automation was turned off by the recovery" in entry.details
    assert worker.tick(NOW) == {"runs": 0, "steps": 0}, "nothing runs until an administrator says so"
    # To the end of the archive (the host died): seconds were lost, and the server goes on.
    with SessionLocal() as db:
        automation_state.write(db, enabled=True)
        db.commit()
    assert tool.main(["after", "--to", "latest", "--label", "base-20261120-110000"]) == 0
    said = "".join(capsys.readouterr())
    assert "turned OFF" not in said and "start again by themselves" in said
    with SessionLocal() as db:
        assert automation_state.enabled(db)


def test_a_database_put_back_alone_gets_back_the_files_deleted_since(elsewhere, capsys, monkeypatch, tmp_path):  # noqa: F811
    """What deploy/rollback.sh does: the snapshot's database in the place of the one that is
    there, the store left as it is. The files deleted since the snapshot are in ``.kept``."""
    from app.backups import restore

    path, _source, target_store, _scratch = elsewhere
    monkeypatch.setattr(settings, "WAL_ARCHIVE_DIR", str(tmp_path / "wal-archive"))
    target_store.mkdir(exist_ok=True)
    (target_store / "evidence.bin").write_bytes(b"already here")
    deleted = target_store / ".kept" / str(int(time.time()) + 100) / ("4" * 64 + ".bin")
    deleted.parent.mkdir(parents=True)
    deleted.write_bytes(b"deleted after the snapshot was taken")
    assert restore.main(["restore", str(path), "--database-only"]) == 0
    said = capsys.readouterr().err
    assert "1 file(s) of the store deleted since the backup was taken were put back in their places" in said
    assert (target_store / ("4" * 64 + ".bin")).read_bytes() == b"deleted after the snapshot was taken"
    assert not (target_store / ".kept").exists() and (target_store / "evidence.bin").exists()
