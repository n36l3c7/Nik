"""The health page: each row against made-up conditions, the day a disk will be full, the
notices (once per problem, once when solved), the thresholds, and the metrics for Prometheus."""

from __future__ import annotations

import json
import re
import time
from collections import namedtuple

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, text, update

from app.auditlog import chain
from app.core import audit
from app.core.config import settings
from app.core.db import SessionLocal, engine
from app.core.models import (
    ArtifactJob,
    AuditEntry,
    AutomationSchedule,
    Connection,
    Connector,
    MirrorJob,
    Notification,
    Playbook,
    Setting,
)
from app.health import checks, metrics, thresholds, watch
from app.main import app as fastapi_app
from tests.conftest import make_key

Disk = namedtuple("Disk", "total used free")
GB = 2**30


@pytest.fixture(autouse=True)
def quiet(monkeypatch, tmp_path):
    """No test asks a web container for its certificate, and each has its own directories."""

    def nobody(host, port):
        raise OSError("no web container in a test")

    monkeypatch.setattr(checks, "tls_dates", nobody)
    (tmp_path / "store").mkdir()
    (tmp_path / "backups").mkdir()
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(tmp_path / "store"))
    monkeypatch.setattr(settings, "BACKUP_DIR", str(tmp_path / "backups"))
    monkeypatch.setattr(checks, "disk_usage", lambda path: Disk(100 * GB, 40 * GB, 60 * GB))


def _rows(now: float | None = None, kept: dict | None = None) -> dict[str, dict]:
    with SessionLocal() as db:
        if kept is None:
            kept = watch._held(db)
        return {row["id"]: row for row in checks.gather(db, thresholds.read(db), kept, now)}


def _pass(now: float) -> list[str]:
    return watch.check(now=now)


def _notices() -> list[tuple[str, str, str]]:
    with SessionLocal() as db:
        return [
            (row.username, row.kind, row.text) for row in db.scalars(select(Notification).order_by(Notification.at))
        ]


# --------------------------------------------------------------------------- #
# The page                                                                    #
# --------------------------------------------------------------------------- #
def test_the_page_has_every_row_and_the_plain_health_check_says_nothing_of_it(admin: TestClient):
    plain = TestClient(fastapi_app).get("/api/health")
    assert plain.status_code == 200 and plain.json() == {"status": "ok"}
    page = admin.get("/api/health/details")
    assert page.status_code == 200, page.text
    body = page.json()
    rows = {row["id"]: row for row in body["rows"]}
    for wanted in (
        "disk.store", "disk.backups", "db.version", "db.size", "db.revision", "clock.skew",
        "queue.artifact_jobs", "queue.url_scans", "queue.uploads", "queue.playbook_steps", "queue.events",
        "queue.schedules", "queue.fetch", "queue.lookups", "queue.mirror", "queue.backup_copies",
        "backup.last", "backup.next", "backup.snapshots", "tls.certificate", "audit.chain", "audit.forwarding",
        "signin.proxies", "signin.second_factor", "server.version",
    ):  # fmt: skip
        assert wanted in rows, wanted
    for row in body["rows"]:
        assert set(row) == {"id", "group", "label", "value", "state", "detail", "link", "since"}
        assert row["state"] in ("fine", "attention", "problem", "unknown") and row["label"] and row["value"]
    assert rows["disk.store"]["value"] == "40% used, 60.0 GB free of 100.0 GB" and rows["disk.store"]["state"] == "fine"
    assert (
        rows["tls.certificate"]["state"] == "unknown"
        and "no web container in a test" in rows["tls.certificate"]["detail"]
    )
    assert rows["audit.forwarding"]["value"] == "Off"
    assert rows["server.version"]["value"].startswith("Nik ")
    # The keys of the server and the encryption of the store are a group of their own.
    assert [row["id"] for row in body["rows"] if row["group"] == "Keys and encryption"] == [
        "keys.state",
        "store.encryption",
    ]
    assert rows["keys.state"]["link"] == "/settings/system/keys"
    assert body["counts"]["fine"] + body["counts"]["attention"] + body["counts"]["problem"] + body["counts"][
        "unknown"
    ] == len(body["rows"])
    assert body["metricsToken"] == {
        "set": False,
        "createdAt": None,
        "createdBy": "",
        "ending": "",
        "environment": False,
    }
    assert {entry["name"] for entry in body["thresholds"]} == set(thresholds.FIELDS)
    # Administrators only; an administrator's key may read it.
    caller = TestClient(fastapi_app)
    assert caller.get("/api/health/details", headers=make_key(admin, label="a", roles=["admin"])).status_code == 200
    assert caller.get("/api/health/details", headers=make_key(admin, label="b", roles=["analyst"])).status_code == 403
    assert caller.get("/api/health/details").status_code == 401


def test_a_check_that_breaks_is_said_and_hides_no_other(admin: TestClient, monkeypatch):
    def broken(db, limits, now):
        raise RuntimeError("the table is gone")

    monkeypatch.setattr(checks, "_queues", broken)
    rows = _rows()
    assert (
        rows["queues.unreadable"]["state"] == "unknown" and "the table is gone" in rows["queues.unreadable"]["detail"]
    )
    assert "disk.store" in rows and "audit.chain" in rows


# --------------------------------------------------------------------------- #
# Disks                                                                       #
# --------------------------------------------------------------------------- #
def test_a_disk_by_how_full_it_is(client: TestClient, monkeypatch):
    for used, state in ((79, "fine"), (80, "attention"), (89, "attention"), (90, "problem"), (100, "problem")):
        monkeypatch.setattr(checks, "disk_usage", lambda path, used=used: Disk(100 * GB, used * GB, (100 - used) * GB))
        row = _rows()["disk.store"]
        assert row["state"] == state, used
        assert ("Free some room" in row["detail"]) == (state != "fine")
    with SessionLocal() as db:
        thresholds.write(db, {"diskAttentionPercent": 50, "diskProblemPercent": 60})
        db.commit()
    monkeypatch.setattr(checks, "disk_usage", lambda path: Disk(100 * GB, 55 * GB, 45 * GB))
    assert _rows()["disk.backups"]["state"] == "attention"

    def gone(path):
        raise FileNotFoundError(2, "No such file or directory")

    monkeypatch.setattr(checks, "disk_usage", gone)
    row = _rows()["disk.store"]
    assert (row["state"], row["value"]) == ("unknown", "Not readable") and "No such file" in row["detail"]


def test_the_day_a_disk_will_be_full_is_read_from_how_it_grew(client: TestClient):
    now = 1_795_000_000.0
    hour = 3600
    # Not enough history: nothing is predicted.
    assert checks.growth([], now) is None
    assert checks.growth([[now - 2 * hour, 10 * GB], [now - hour, 11 * GB], [now, 12 * GB]], now) is None
    # Two days of samples, one an hour, 1 GB a day.
    steady = [[now - (48 - step) * hour, 40 * GB + step * GB / 24] for step in range(49)]
    assert checks.growth(steady, now) == pytest.approx(GB, rel=1e-6)
    # Samples older than a week are not looked at; a disk that empties has a negative rate.
    old = [[now - 30 * 86400, 0.0], *steady]
    assert checks.growth(old, now) == pytest.approx(GB, rel=1e-6)
    assert checks.growth([[at, 90 * GB - used] for at, used in steady], now) < 0
    # 60 GB free at 1 GB a day: full in 60 days, which is fine; at 4 GB a day, in 15: attention; at 12, in 5: a problem.
    for a_day, state, words in (
        (1, "fine", "about 60 days"),
        (4, "attention", "about 15 days"),
        (12, "problem", "about 5 days"),
    ):
        kept = {"disks": {"store": [[at, 40 * GB + (used - 40 * GB) * a_day] for at, used in steady]}}
        row = _rows(now, kept)["disk.store"]
        assert row["state"] == state, a_day
        assert f"It fills by {a_day}.0 GB a day: full in {words} at this rate." in row["detail"]
        numbers = {name: value for name, labels, value in row["metrics"] if labels.get("disk") == "store"}
        assert numbers["nik_disk_full_in_seconds"] == pytest.approx(60 / a_day * 86400, rel=1e-3)
    flat = {"disks": {"store": [[at, 40 * GB] for at, _ in steady]}}
    row = _rows(now, flat)["disk.store"]
    assert row["state"] == "fine" and row["detail"] == "It is not filling."
    assert "nik_disk_full_in_seconds" not in {name for name, _, _ in row["metrics"]}
    # The watch keeps one sample an hour for each disk and for the database, two weeks of them.
    kept: dict = {}
    for step in range(30 * 24):
        rows = [{"metrics": [("nik_disk_used_bytes", {"disk": "store"}, step), ("nik_database_size_bytes", {}, step)]}]
        kept["disks"] = watch.sample(kept, rows, now + step * 1800)
    assert set(kept["disks"]) == {"store", "database"}
    assert len(kept["disks"]["store"]) == watch.SAMPLES_KEPT
    assert kept["disks"]["store"][-1][0] - kept["disks"]["store"][-2][0] == 3600


# --------------------------------------------------------------------------- #
# Queues, workers, the database                                               #
# --------------------------------------------------------------------------- #
def test_a_queue_by_the_age_of_its_oldest_item(client: TestClient):
    now = time.time()
    assert _rows(now)["queue.artifact_jobs"]["value"] == "0 waiting, 0 running"
    with SessionLocal() as db:
        for job_id, status, age in (
            ("j1", "queued", 30),
            ("j2", "queued", 15 * 60),
            ("j3", "running", 5),
            ("j4", "done", 9000),
        ):
            db.add(
                ArtifactJob(
                    id=job_id,
                    kind="analyse",
                    status=status,
                    params={},
                    result={},
                    actor="t",
                    run_id="",
                    depth=0,
                    created_epoch=now - age,
                )
            )
        db.commit()
    row = _rows(now)["queue.artifact_jobs"]
    assert row["value"] == "2 waiting, 1 running, the oldest for 15 minutes" and row["state"] == "attention"
    assert "The API process takes these" in row["detail"]
    assert ("nik_queue_waiting", {"queue": "artifact_jobs"}, 2) in row["metrics"]
    with SessionLocal() as db:
        db.execute(update(ArtifactJob).where(ArtifactJob.id == "j2").values(created_epoch=now - 2 * 3600))
        db.commit()
    assert _rows(now)["queue.artifact_jobs"]["state"] == "problem"
    with SessionLocal() as db:
        db.execute(update(ArtifactJob).values(status="done"))
        db.commit()
    assert _rows(now)["queue.artifact_jobs"]["state"] == "fine"


def test_late_schedules_stuck_fetches_and_changes_that_could_not_be_sent(client: TestClient):
    from app.automation import state

    now = time.time()
    with SessionLocal() as db:
        for name in ("p1", "p2"):
            db.add(Playbook(id=name, name=name, created_at="t", updated_at="t"))
        db.add(Connector(id="c", name="c", source="", created_at="t", updated_at="t"))
        db.flush()
        db.add(AutomationSchedule(playbook_id="p1", node_id="n1", cron="*/5 * * * *", timezone="UTC", next_at=now + 60))
        db.add(
            AutomationSchedule(
                playbook_id="p2", node_id="n1", cron="*/5 * * * *", timezone="UTC", next_at=now - 20 * 60
            )
        )
        for name, status in (
            ("ok", {"state": "ok", "nextAt": now + 30}),
            ("held", {"state": "paused", "nextAt": now - 9000}),
        ):
            db.add(
                Connection(
                    id=name,
                    name=name,
                    connector_id="c",
                    config={},
                    secrets="",
                    enabled=True,
                    fetch_enabled=True,
                    fetch_status=status,
                    created_at="t",
                    updated_at="t",
                )
            )
        db.add(
            MirrorJob(
                id="m1",
                incident_id="i",
                connection_id="ok",
                kind="push",
                payload={},
                attempts=8,
                next_at=now,
                status="failed",
                error="no",
                created_at="t",
                created_by="t",
            )
        )
        db.commit()
    rows = _rows(now)
    assert rows["queue.schedules"]["state"] == "attention"
    assert rows["queue.schedules"]["value"] == "2 set, 1 late, the latest by 20 minutes"
    assert rows["queue.fetch"]["state"] == "attention" and rows["queue.fetch"]["value"] == "2 instances fetch, 1 paused"
    assert rows["queue.mirror"]["state"] == "attention" and "1 could not be sent" in rows["queue.mirror"]["detail"]
    with SessionLocal() as db:
        db.execute(
            update(Connection)
            .where(Connection.id == "ok")
            .values(fetch_status={"state": "ok", "nextAt": now - 2 * 3600})
        )
        db.commit()
    late = _rows(now)["queue.fetch"]
    assert late["state"] == "problem" and "the latest cycle is 2 hours late" in late["value"]
    # With automation stopped on purpose nothing is late: it is stopped, and the page says so.
    with SessionLocal() as db:
        state.write(db, enabled=False)
        db.commit()
    rows = _rows(now)
    assert rows["queue.schedules"]["state"] == "fine" and "automation is stopped" in rows["queue.schedules"]["value"]
    assert rows["queue.playbook_steps"]["value"].startswith("Automation is stopped")


def test_the_automation_worker_by_its_last_sign_of_life(client: TestClient, monkeypatch):
    from app.automation import state

    now = time.time()
    monkeypatch.setattr(settings, "AUTOMATION_WORKER", "container")
    assert _rows(now)["worker.heartbeat"]["state"] == "unknown"
    with SessionLocal() as db:
        state.beat(db, now - 20)
    fresh = _rows(now)["worker.heartbeat"]
    assert (fresh["state"], fresh["value"]) == ("fine", "20 seconds ago")
    stale = _rows(now + 300)["worker.heartbeat"]
    assert stale["state"] == "attention" and stale["value"] == "5 minutes ago"
    monkeypatch.setattr(settings, "AUTOMATION_WORKER", "off")
    assert "worker.heartbeat" not in _rows(now)


def test_the_database_its_connections_its_revision_and_the_clock(client: TestClient, monkeypatch):
    now = time.time()
    facts = {
        "engine": "postgresql", "version": "18.1", "bytes": 5 * GB, "connections": 85, "maxConnections": 100,
        "longest": 20 * 60.0, "poolInUse": 15, "poolSize": 15, "revision": "0049_two_factor",
    }  # fmt: skip
    monkeypatch.setattr(checks, "database_facts", lambda db: facts | {"clock": time.time() - 130})
    monkeypatch.setattr(checks, "head_revision", lambda: "0051_audit_chain")
    rows = _rows(now)
    assert rows["db.version"]["value"] == "PostgreSQL 18.1"
    assert rows["db.size"]["value"] == "5.0 GB" and "cannot be read from here" in rows["db.size"]["detail"]
    assert (rows["db.connections"]["state"], rows["db.connections"]["value"]) == ("attention", "85 of 100 in use")
    assert (
        rows["db.pool"]["state"] == "problem" and "Every connection of the pool is taken" in rows["db.pool"]["detail"]
    )
    assert (rows["db.transactions"]["state"], rows["db.transactions"]["value"]) == ("attention", "20 minutes")
    assert rows["db.revision"]["state"] == "problem"
    assert rows["db.revision"]["value"] == "0049_two_factor, and this version expects 0051_audit_chain"
    assert rows["clock.skew"]["state"] == "problem" and rows["clock.skew"]["value"] == "2 minutes ahead"
    calm = facts | {"connections": 12, "longest": 0.0, "poolInUse": 1, "revision": "0051_audit_chain"}
    monkeypatch.setattr(checks, "database_facts", lambda db: calm | {"clock": time.time()})
    rows = _rows(now)
    for name in ("db.connections", "db.pool", "db.transactions", "db.revision", "clock.skew"):
        assert rows[name]["state"] == "fine", name
    assert rows["clock.skew"]["value"] == "The same" and rows["db.transactions"]["value"] == "None open"


# --------------------------------------------------------------------------- #
# The certificate, the audit log, the sign-in                                 #
# --------------------------------------------------------------------------- #
def test_the_certificate_by_the_days_it_has_left(client: TestClient, monkeypatch):
    now = time.time()
    for days, state, value in (
        (200, "fine", "Expires in 200 days"),
        (30, "attention", "Expires in 30 days"),
        (7, "problem", "Expires in 7 days"),
        (-2, "problem", "Expired 2 days ago"),
    ):
        found = {
            "notAfter": now + days * 86400 + 60,
            "notBefore": now - 86400,
            "subject": "CN=nik.example",
            "selfSigned": True,
        }
        monkeypatch.setattr(checks, "tls_dates", lambda host, port, found=found: found)
        row = _rows(now, {})["tls.certificate"]
        assert row["state"] == state and row["value"].startswith(value), days
        assert row["detail"].startswith("CN=nik.example, self-signed.")
        assert ("Replace nik.crt" in row["detail"]) == (state != "fine")
    # What was read less than an hour ago is not read again; an installation without a web container has no row.
    asked = []
    monkeypatch.setattr(checks, "tls_dates", lambda host, port: asked.append(host) or found)
    kept = {"tls": {"at": now - 600, "found": found}}
    assert _rows(now, kept)["tls.certificate"]["state"] == "problem" and asked == []
    _rows(now, {"tls": {"at": now - 7200, "found": found}})
    assert asked == ["web"]
    monkeypatch.setenv("NIK_WEB_TLS", "")
    assert "tls.certificate" not in _rows(now, {})


def test_the_chain_and_the_forwarding_of_the_audit_log(admin: TestClient):
    now = time.time()
    assert _rows(now)["audit.chain"]["state"] == "unknown"
    assert admin.post("/api/audit/chain/verify", json={}).status_code == 200
    row = _rows(now + 30)["audit.chain"]
    assert row["state"] == "fine" and row["value"].startswith("Holds up to entry ")
    with SessionLocal() as db:
        db.execute(update(AuditEntry).where(AuditEntry.seq == 1).values(details="changed"))
        db.commit()
    assert admin.post("/api/audit/chain/verify", json={"full": True}).json()["problem"]["kind"] == "edited"
    row = _rows(now + 30)["audit.chain"]
    assert (row["state"], row["value"]) == ("problem", "Broken at entry 1")
    assert "The content of entry 1 was changed after it was written" in row["detail"]
    # Forwarding: off is said; on with entries that wait is judged by how long the oldest has waited.
    saved = admin.put(
        "/api/audit/forwarding", json={"enabled": True, "host": "siem.example", "protocol": "tcp", "port": 514}
    )
    assert saved.status_code == 200
    waiting = _rows(time.time() + 60)["audit.forwarding"]
    assert waiting["state"] == "fine" and waiting["value"].startswith("tcp://siem.example:514, not taken up yet: ")
    assert _rows(time.time() + 10 * 60)["audit.forwarding"]["state"] == "attention"
    late = _rows(time.time() + 3600)["audit.forwarding"]
    assert late["state"] == "problem" and "the automation worker sends them" in late["detail"]
    from app.auditlog import forward

    with SessionLocal() as db:
        doc = db.get(Setting, forward.SETTINGS_ID).doc
        db.add(
            Setting(
                id=forward.STATE_ID,
                doc={
                    "version": doc["version"],
                    "active": doc["settings"],
                    "cursor": chain.head(db)[0],
                    "sent": 9,
                    "error": "siem.example:514 cannot be reached: Connection refused",
                    "errorSince": time.time() - 45 * 60,
                },
            )
        )
        db.commit()
    down = _rows(time.time())["audit.forwarding"]
    assert down["state"] == "problem" and down["value"] == "tcp://siem.example:514: 0 waiting"
    assert down["detail"].startswith(
        "siem.example:514 cannot be reached: Connection refused. The entries wait in order"
    )


def test_the_warnings_of_the_sign_in_policy(admin: TestClient, monkeypatch):
    rows = _rows()
    assert rows["signin.proxies"]["state"] == "fine"
    assert rows["signin.second_factor"]["value"] == "0 of 1 have one, not required"
    assert (
        rows["signin.second_factor"]["state"] == "fine" and "A password alone" in rows["signin.second_factor"]["detail"]
    )
    monkeypatch.setenv("FORWARDED_ALLOW_IPS", "*")
    assert admin.put("/api/auth/policy", json={"adminSecondFactor": True}).status_code == 200
    rows = _rows()
    assert rows["signin.proxies"]["state"] == "attention" and "Everybody" in rows["signin.proxies"]["value"]
    assert rows["signin.second_factor"]["state"] == "attention"
    assert rows["signin.second_factor"]["value"] == "0 of 1 have one, required"
    assert rows["signin.second_factor"]["detail"].startswith("admin: asked to set one up")


# --------------------------------------------------------------------------- #
# The notices                                                                 #
# --------------------------------------------------------------------------- #
def test_one_notice_when_a_row_gets_worse_and_one_when_it_is_fine_again(admin: TestClient, monkeypatch):
    admin.post("/api/users", json={"username": "bruno", "password": "password1", "roles": ["admin"]})
    admin.post("/api/users", json={"username": "anna", "password": "password1", "roles": ["analyst"]})
    now = 1_795_000_000.0
    assert _pass(now) == [] and _pass(now + 60) == []

    def full(used: int) -> None:
        monkeypatch.setattr(checks, "disk_usage", lambda path: Disk(100 * GB, used * GB, (100 - used) * GB))

    full(85)
    # Found once is not told: a value that crosses its limit for a moment tells nobody.
    assert _pass(now + 120) == []
    assert sorted(_pass(now + 180)) == ["problem:disk.backups", "problem:disk.store"]
    told = _notices()
    assert sorted(name for name, kind, _ in told) == [
        "admin",
        "admin",
        "bruno",
        "bruno",
    ]  # every administrator, nobody else
    assert {kind for _, kind, _ in told} == {"health.problem"}
    assert "Store of files: 85% used, 15.0 GB free of 100.0 GB." in {text.split(" How fast")[0] for _, _, text in told}
    with SessionLocal() as db:
        assert {row.link for row in db.scalars(select(Notification))} == {"/settings/system/health"}
    # However long it lasts: nothing more.
    for step in range(4, 30):
        assert _pass(now + step * 60) == []
    # Worse: told once more. Back to attention: nothing. Fine again: told it is solved, once.
    full(95)
    assert _pass(now + 2000) == []
    assert sorted(_pass(now + 2060)) == ["problem:disk.backups", "problem:disk.store"]
    full(85)
    assert _pass(now + 2120) == [] and _pass(now + 2180) == []
    full(40)
    assert _pass(now + 2240) == []
    assert sorted(_pass(now + 2300)) == ["solved:disk.backups", "solved:disk.store"]
    assert _pass(now + 2360) == []
    solved = [text for _, kind, text in _notices() if kind == "health.solved"]
    assert "Store of files is fine again: 40% used, 60.0 GB free of 100.0 GB." in solved and len(solved) == 4
    assert len(_notices()) == 12
    # A row that cannot be measured changes nothing and tells nobody.
    full(85)
    _pass(now + 3000)

    def gone(path):
        raise OSError(5, "Input/output error")

    monkeypatch.setattr(checks, "disk_usage", gone)
    assert _pass(now + 3060) == [] and _pass(now + 3120) == []
    full(85)
    assert _pass(now + 3180) == []  # measured again for the first time
    assert sorted(_pass(now + 3240)) == ["problem:disk.backups", "problem:disk.store"]
    # Since when a row is in its state is on the page.
    rows = {row["id"]: row for row in admin.get("/api/health/details").json()["rows"]}
    assert rows["disk.store"]["state"] == "attention" and rows["disk.store"]["since"].startswith("2026-11-")


def test_the_watch_looks_from_one_process_at_a_time(admin: TestClient, monkeypatch):
    now = 1_795_000_000.0
    monkeypatch.setattr(checks, "disk_usage", lambda path: Disk(100 * GB, 95 * GB, 5 * GB))
    assert watch.check(now=now, holder="api") == []
    # The other process (the automation worker runs the same watch) finds the lease taken.
    assert watch.check(now=now + 30, holder="worker") == []
    with SessionLocal() as db:
        assert watch._held(db)["checked"] == now
    assert sorted(watch.check(now=now + 60, holder="api")) == ["problem:disk.backups", "problem:disk.store"]
    # When the first is gone the second takes over, and tells nothing that was told already.
    assert watch.check(now=now + 400, holder="worker") == []
    assert len(_notices()) == 2


def test_a_broken_chain_and_an_expiring_certificate_are_told_and_a_worker_is_not_told_twice(
    admin: TestClient, monkeypatch
):
    now = time.time()
    found = {"notAfter": now + 20 * 86400, "notBefore": now - 86400, "subject": "CN=nik", "selfSigned": False}
    monkeypatch.setattr(checks, "tls_dates", lambda host, port: found)
    with SessionLocal() as db:
        audit.record(db, "anna", "test.entry", "one")
        db.commit()
        db.execute(update(AuditEntry).where(AuditEntry.seq == 1).values(actor="somebody else"))
        db.commit()
        chain.verify(db, full=True)
        db.commit()
    monkeypatch.setattr(settings, "AUTOMATION_WORKER", "container")  # its heartbeat is missing: a row in attention
    _pass(now)
    told = _pass(now + 60)
    assert sorted(told) == ["problem:audit.chain", "problem:tls.certificate"]
    texts = [text for _, _, text in _notices()]
    assert any(text.startswith("Chain: Broken at entry 1. The content of entry 1 was changed") for text in texts)
    assert any(text.startswith("Certificate of the web container: Expires in ") for text in texts)
    # The watch of the workers tells about workers: this one does not repeat it.
    assert not any("worker" in name for name in told)
    # One week before the end the certificate is a problem: told again, once.
    found["notAfter"] = now + 5 * 86400
    with SessionLocal() as db:
        kept = watch._held(db)
        kept["tls"] = {}
        watch._keep(db, kept)
        db.commit()
    _pass(now + 120)
    assert _pass(now + 180) == ["problem:tls.certificate"]


# --------------------------------------------------------------------------- #
# The thresholds                                                              #
# --------------------------------------------------------------------------- #
def test_the_thresholds_are_settings_checked_and_recorded(admin: TestClient):
    for body, words in (
        ({"diskAttentionPercent": 0}, "from 1 to 99"),
        ({"diskAttentionPercent": "80"}, "whole number"),
        ({"diskAttentionPercent": 95}, "not more than"),
        ({"certificateAttentionDays": 3}, "not less than"),
        ({"nope": 1}, "Not a threshold"),
    ):
        refused = admin.put("/api/health/thresholds", json=body)
        assert refused.status_code == 422 and words in refused.json()["detail"], refused.text
    saved = admin.put("/api/health/thresholds", json={"diskAttentionPercent": 30, "queueProblemMinutes": 90})
    assert saved.status_code == 200
    held = {entry["name"]: entry for entry in saved.json()["thresholds"]}
    assert (held["diskAttentionPercent"]["value"], held["diskAttentionPercent"]["default"]) == (30, 80)
    assert {row["id"]: row for row in saved.json()["rows"]}["disk.store"]["state"] == "attention"
    with SessionLocal() as db:
        said = [row.details for row in db.scalars(select(AuditEntry).where(AuditEntry.action == "health.thresholds"))]
    assert said == ["Changed the thresholds of the health page: diskAttentionPercent to 30, queueProblemMinutes to 90"]
    key = make_key(admin, label="adm", roles=["admin"])
    assert TestClient(fastapi_app).put("/api/health/thresholds", headers=key, json={}).status_code == 401


# --------------------------------------------------------------------------- #
# The metrics                                                                 #
# --------------------------------------------------------------------------- #
NAME = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*$")
SAMPLE = re.compile(r"^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{(.*)\})? (\S+)$")
LABEL = re.compile(r'([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\\n]|\\\\|\\"|\\n)*)"(?:,|$)')


def parse(text: str) -> dict[str, dict]:
    """A strict reading of the text exposition format: every sample belongs to a family that was
    announced with its HELP and its TYPE just before, no family comes twice, no sample twice."""
    assert text.endswith("\n")
    families: dict[str, dict] = {}
    current = None
    for line in text.splitlines():
        assert line == line.strip() and line, repr(line)
        if line.startswith("# HELP "):
            name, _, words = line[7:].partition(" ")
            assert NAME.match(name) and words and name not in families, line
            families[name] = {"help": words, "type": None, "samples": {}}
            current = name
            continue
        if line.startswith("# TYPE "):
            name, _, kind = line[7:].partition(" ")
            assert name == current and families[name]["type"] is None, line
            assert kind in ("counter", "gauge", "histogram", "summary", "untyped"), line
            families[name]["type"] = kind
            continue
        assert not line.startswith("#"), line
        found = SAMPLE.match(line)
        assert found, line
        name, labels, value = found.groups()
        float(value)
        assert current is not None and families[current]["type"] is not None, line
        suffixes = {"counter": ("", "_total", "_created"), "histogram": ("_bucket", "_sum", "_count", "_created")}
        allowed = {current + suffix for suffix in suffixes.get(families[current]["type"], ("",))}
        assert name in allowed, f"{name} does not belong to {current}"
        pairs = {}
        rest = labels or ""
        while rest:
            piece = LABEL.match(rest)
            assert piece, line
            assert piece.group(1) not in pairs, line
            pairs[piece.group(1)] = piece.group(2)
            rest = rest[piece.end() :]
        key = (name, tuple(sorted(pairs.items())))
        assert key not in families[current]["samples"], f"twice: {line}"
        families[current]["samples"][key] = float(value)
    return families


@pytest.mark.skipif(engine.dialect.name != "postgresql", reason="what pg_stat_activity and pg_locks say")
def test_the_transaction_of_a_backup_is_not_a_long_transaction(client: TestClient):
    from app.backups.database import MIGRATION_LOCK

    def longest() -> float:
        with SessionLocal() as db:
            return checks.database_facts(db)["longest"]

    assert longest() < 1
    # A dump: one transaction that reads for as long as it takes, holding the lock a dump holds.
    dump = engine.connect()
    other = engine.connect()
    try:
        dump.execute(text("SELECT pg_advisory_xact_lock_shared(:key)"), {"key": MIGRATION_LOCK})
        dump.execute(text("SELECT count(*) FROM users"))
        time.sleep(1.5)
        assert longest() < 1, "the transaction of a backup was counted"
        # Any other transaction left open is what the row is for.
        other.execute(text("SELECT count(*) FROM users"))
        time.sleep(1.2)
        found = longest()
        assert 1 <= found < 60, found
    finally:
        other.close()
        dump.close()
    assert longest() < 1


def test_the_metrics_answer_to_their_token_and_to_nothing_else(admin: TestClient):
    key = make_key(admin, label="adm", roles=["admin"])
    # Nobody without the token: not a signed-in administrator's cookie, not an administrator's key.
    assert admin.get("/api/metrics").status_code == 401
    assert TestClient(fastapi_app).get("/api/metrics", headers=key).status_code == 401
    assert TestClient(fastapi_app).post("/api/health/metrics-token", headers=key).status_code == 401
    made = admin.post("/api/health/metrics-token")
    assert made.status_code == 201
    token = made.json()["token"]
    assert token.startswith("nikm_") and len(token) > 40
    assert made.json()["metricsToken"]["set"] is True and made.json()["metricsToken"]["ending"] == token[-4:]
    # Shown once: kept as a hash, and no route gives it back.
    with SessionLocal() as db:
        kept = db.get(Setting, metrics.SETTINGS_ID).doc
        assert token not in json.dumps(kept) and len(kept["hash"]) == 64
        said = [row.details for row in db.scalars(select(AuditEntry).where(AuditEntry.action == "metrics.token"))]
    assert said == ["Made a scrape token for the metrics"] and token not in admin.get("/api/health/details").text
    scraper = TestClient(fastapi_app)
    refused = scraper.get("/api/metrics")
    assert refused.status_code == 401 and refused.headers["www-authenticate"] == "Bearer"
    for header in ("Bearer nope", f"Basic {token}", token, f"Bearer {token}x", "Bearer "):
        assert scraper.get("/api/metrics", headers={"Authorization": header}).status_code == 401, header
    good = scraper.get("/api/metrics", headers={"Authorization": f"Bearer {token}"})
    assert good.status_code == 200 and good.headers["content-type"].startswith("text/plain")
    # The cookie of a session beside the token changes nothing; the token is no API key.
    assert admin.get("/api/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert scraper.get("/api/health/details", headers={"X-API-Key": token}).status_code == 401
    # A new one replaces it; removed, the route is closed.
    again = admin.post("/api/health/metrics-token").json()["token"]
    assert again != token
    assert scraper.get("/api/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert scraper.get("/api/metrics", headers={"Authorization": f"Bearer {again}"}).status_code == 200
    assert admin.delete("/api/health/metrics-token").json() == {
        "metricsToken": {"set": False, "createdAt": None, "createdBy": "", "ending": "", "environment": False}
    }
    assert scraper.get("/api/metrics", headers={"Authorization": f"Bearer {again}"}).status_code == 401


def test_the_metrics_parse_are_named_by_the_rules_and_name_nobody(admin: TestClient):
    # Things a label must never carry: an account, an incident, a host somebody typed.
    admin.post("/api/users", json={"username": "zelda-the-analyst", "password": "password1", "roles": ["analyst"]})
    admin.post("/api/incidents", json={"name": "Operation Secret Heron", "host": "ws-finance-042"})
    admin.put(
        "/api/audit/forwarding", json={"enabled": True, "host": "siem.private.example", "protocol": "tcp", "port": 514}
    )
    admin.post("/api/audit/chain/verify", json={})
    admin.get("/api/no-such-route-at-all")
    token = admin.post("/api/health/metrics-token").json()["token"]
    with SessionLocal() as db:
        db.add(
            ArtifactJob(
                id="j1",
                kind="analyse",
                status="queued",
                params={},
                result={},
                actor="zelda-the-analyst",
                run_id="",
                depth=0,
                created_epoch=time.time() - 30,
            )
        )
        db.commit()
    text = TestClient(fastapi_app).get("/api/metrics", headers={"Authorization": f"Bearer {token}"}).text
    families = parse(text)
    for forbidden in ("zelda", "Heron", "ws-finance", "siem.private", token):
        assert forbidden not in text, forbidden
    ours = {name: family for name, family in families.items() if name in checks.METRICS or name.startswith("nik_http")}
    # Everything the health page counts is there, named as written down, with its help.
    for name, (kind, words) in checks.METRICS.items():
        if name in families:
            assert (families[name]["type"], families[name]["help"]) == (kind, words), name
    for wanted in (
        "nik_health_state", "nik_disk_used_bytes", "nik_disk_free_bytes", "nik_database_size_bytes",
        "nik_queue_waiting", "nik_queue_oldest_seconds", "nik_playbook_runs", "nik_schedules", "nik_fetch_instances",
        "nik_audit_entries_total", "nik_audit_chain_ok", "nik_audit_forward_backlog", "nik_signin_failures_total",
        "nik_administrators_without_second_factor", "nik_clock_skew_seconds", "nik_info",
        "nik_http_requests_total", "nik_http_request_duration_seconds",
    ):  # fmt: skip
        assert wanted in families or wanted == "nik_playbook_runs", wanted
    # (``key`` is the name of a variable: SECRET_KEY, STORE_KEY, AUDIT_KEY. Never a value.)
    allowed_labels = {"disk", "queue", "worker", "check", "state", "version", "method", "path", "status", "le", "key"}
    for name, family in ours.items():
        assert name.startswith("nik_"), name
        assert (family["type"] == "counter") == name.endswith("_total"), name
        assert not re.search(r"_(ms|milliseconds|minutes|hours|days|kb|mb|gb|percent)(_|$)", name), name
        for (_sample, labels), _value in family["samples"].items():
            assert {key for key, _ in labels} <= allowed_labels, (name, labels)
    samples = {key: value for family in families.values() for key, value in family["samples"].items()}
    assert samples[("nik_queue_waiting", (("queue", "artifact_jobs"),))] == 1
    assert samples[("nik_disk_used_bytes", (("disk", "store"),))] == 40 * GB
    assert samples[("nik_audit_chain_ok", ())] == 1 and samples[("nik_audit_forward_enabled", ())] == 1
    assert samples[("nik_health_state", (("check", "disk.store"),))] == 0
    assert samples[("nik_health_state", (("check", "tls.certificate"),))] == -1
    # A route is named as it is written in the API, with the prefix of its router, never by what was asked.
    paths = {dict(labels).get("path") for (name, labels) in samples if name == "nik_http_requests_total"}
    assert {"/api/users", "/api/incidents", "/api/audit/forwarding", "/api/health/metrics-token"} <= paths
    assert all(path == "unmatched" or path.startswith("/api/") or path.startswith("/docs") for path in paths), paths
    admin.get("/api/incidents/made-up-id")
    again = TestClient(fastapi_app).get("/api/metrics", headers={"Authorization": f"Bearer {token}"}).text
    assert 'path="/api/incidents/{incident_id}"' in again and "made-up-id" not in again
    # A path nobody routed is counted under one label, whatever was asked.
    assert any(
        dict(labels).get("path") == "unmatched" for (name, labels) in samples if name == "nik_http_requests_total"
    )
    # The values of the labels come from fixed sets: the checks, the queues and the disks the code names.
    with SessionLocal() as db:
        rows = checks.gather(db, thresholds.read(db), {})
    known = {row["id"] for row in rows}
    for (name, labels), _value in samples.items():
        if name == "nik_health_state":
            assert dict(labels)["check"] in known


def test_the_text_escapes_what_a_label_holds_and_every_metric_has_its_help():
    rows = [{"metrics": [("nik_info", {"version": 'a"b\\c\nd'}, 1), ("nik_queue_waiting", {"queue": "x"}, 2.5)]}]
    text = metrics.render(rows)
    assert 'nik_info{version="a\\"b\\\\c\\nd"} 1\n' in text and 'nik_queue_waiting{queue="x"} 2.5\n' in text
    parse(text)
    for name, (kind, words) in checks.METRICS.items():
        assert name.startswith("nik_") and kind in ("gauge", "counter") and words.endswith("."), name
        assert (kind == "counter") == name.endswith("_total"), name


# --------------------------------------------------------------------------- #
# The keys and the encryption of the store                                    #
# --------------------------------------------------------------------------- #
def test_the_keys_and_the_encryption_of_the_store(client: TestClient, monkeypatch, tmp_path):
    from app import key_rotation, store_seal
    from app.core import store

    for name in (
        "SECRET_KEY", "STORE_KEY", "DB_PASSWORD", "SANDBOX_TOKEN", "ANALYZER_TOKEN", "CAPA_TOKEN", "DOCVIEW_TOKEN",
        "BROWSER_TOKEN", "PCAP_TOKEN", "METRICS_TOKEN", "AUDIT_KEY", "AUDIT_KEY_PREVIOUS",
    ):  # fmt: skip
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(f"{name}_FILE", raising=False)
    monkeypatch.setenv("STORE_SEAL_MBPS", "0")
    now = time.time()

    # A server nobody gave a key (a development server): nothing to say of the keys; the store not looked at yet.
    rows = _rows(now)
    keys_row, store_row = rows["keys.state"], rows["store.encryption"]
    assert keys_row["group"] == store_row["group"] == "Keys and encryption"
    assert keys_row["state"] == "fine" and keys_row["link"] == "/settings/system/keys"
    assert store_row["state"] == "unknown" and store_row["value"] == "Not looked at yet"
    assert store_row["link"] == "/settings/system/storage"

    # The keys in files: fine. One of them in the environment: attention, with the command that moves them.
    for name in ("SECRET_KEY", "STORE_KEY", "DB_PASSWORD"):
        (tmp_path / name).write_text("k" * 40 + "\n")
        monkeypatch.setenv(f"{name}_FILE", str(tmp_path / name))
    in_files = _rows(now)["keys.state"]
    assert in_files["state"] == "fine" and in_files["value"] == "In files, none in the environment"
    monkeypatch.delenv("DB_PASSWORD_FILE")
    monkeypatch.setenv("DB_PASSWORD", "a-password-in-the-environment")
    in_env = _rows(now)["keys.state"]
    assert in_env["state"] == "attention" and in_env["value"] == "In the environment of the containers"
    assert "deploy/secrets.sh move" in in_env["detail"] and "a-password" not in json.dumps(in_env)
    assert ("nik_keys_in_environment", {}, 1) in in_env["metrics"]
    monkeypatch.delenv("DB_PASSWORD")

    # A change of key that is half-way, then one that failed.
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", ["the key before this one, long enough"])
    half = _rows(now)["keys.state"]
    assert half["state"] == "attention" and half["value"] == "A change of key is half-way"
    assert "SECRET_KEY" in half["detail"] and "holds both keys" in half["detail"]
    assert ("nik_key_rotation_state", {"key": "SECRET_KEY"}, 1) in half["metrics"]
    with SessionLocal() as db:
        key_rotation._write(db, {"secret": {"to": key_rotation.fingerprint("SECRET_KEY"), "state": "failed"}})
        db.commit()
    failed = _rows(now)["keys.state"]
    assert failed["state"] == "attention" and failed["value"] == "A change of key is stopped"
    assert "the earlier key stays where it is and nothing is lost" in failed["detail"]
    assert ("nik_key_rotation_state", {"key": "SECRET_KEY"}, 2) in failed["metrics"]
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", [])
    assert _rows(now)["keys.state"]["state"] == "fine"

    # An entry of the audit log whose key is gone.
    with SessionLocal() as db:
        audit.record(db, "anna", "test.note", "signed with a key that will be lost")
        db.commit()
        db.execute(update(AuditEntry).where(AuditEntry.action == "test.note").values(key_id="set-0123456789ab"))
        db.commit()
    lost = _rows(now)["keys.state"]
    assert lost["state"] == "attention" and lost["value"] == "A key of the audit log is missing"
    assert "1 entries of the audit log cannot be checked" in lost["detail"] and "AUDIT_KEY_PREVIOUS" in lost["detail"]
    assert ("nik_audit_entries_unchecked", {}, 1) in lost["metrics"]

    # The store: being sealed, paused, sealed, then a damaged file and a file that could not be sealed.
    root = store.root()
    for index in range(3):
        (root / f"old-{index}.bin").write_bytes(b"from before 6.8 " * 10)
    with SessionLocal() as db:
        store_seal._update(
            state=store_seal.CONVERTING, total={"files": 3, "bytes": 480}, done={"files": 1, "bytes": 160}
        )
    converting = _rows(now)["store.encryption"]
    assert converting["state"] == "attention" and converting["value"] == "1 of 3 files sealed, 320 bytes still in clear"
    assert "is being sealed while the server is used" in converting["detail"]
    assert ("nik_store_encrypted", {}, 0) in converting["metrics"]
    assert ("nik_store_files_in_clear", {}, 2) in converting["metrics"]
    assert ("nik_store_bytes_in_clear", {}, 320) in converting["metrics"]
    store_seal._update(state="paused", pausedBy="admin")
    paused = _rows(now)["store.encryption"]
    assert paused["state"] == "attention" and "Paused by admin" in paused["detail"]
    store_seal._update(state=store_seal.CONVERTING, pausedBy="")
    for _ in range(10):
        if store_seal.convert_pass().get("state") == store_seal.SEALED:
            break
    sealed_row = _rows(time.time() + 7200)["store.encryption"]
    assert sealed_row["state"] == "fine" and sealed_row["value"] == "Every file is sealed, for 2 hours"
    assert ("nik_store_encrypted", {}, 1) in sealed_row["metrics"]
    assert ("nik_store_files_in_clear", {}, 0) in sealed_row["metrics"]
    store_seal._update(damaged={"old-0.bin": {"at": "2026-11-20T10:00:00Z", "reason": "it failed its check"}})
    damaged = _rows(now)["store.encryption"]
    assert damaged["state"] == "problem" and damaged["value"] == "1 file(s) failed their check"
    assert ("nik_store_files_damaged", {}, 1) in damaged["metrics"]
    store_seal._update(damaged={}, state=store_seal.CONVERTING, stuckCount=2, stuck=[{"name": "a", "reason": "b"}])
    stuck = _rows(now)["store.encryption"]
    assert stuck["state"] == "problem" and stuck["value"] == "2 file(s) stay in clear"
    assert ("nik_store_files_stuck", {}, 2) in stuck["metrics"]
    # Each new metric is written down with its help, like the others.
    for row in (failed, lost, stuck):
        for name, _labels, _value in row["metrics"]:
            assert name in checks.METRICS, name


def test_a_process_that_is_not_given_the_store_reads_its_disk_as_the_backend_measured_it(
    client: TestClient, monkeypatch
):
    """The automation worker looks at the health too, and mounts no store: at the path of the store it
    would measure its own container, and tell the administrators about a disk that is not the store."""
    from app import store_seal

    now = time.time()
    store_seal._update(disk={"total": 200 * GB, "free": 20 * GB, "at": now - 60})
    # The backend sees the store and measures it (40% used, as this file has it everywhere).
    assert _rows(now)["disk.store"]["value"] == "40% used, 60.0 GB free of 100.0 GB"
    # The worker holds no store key: what the backend noted a minute ago, never its own disk.
    monkeypatch.setattr(settings, "STORE_KEY", "")
    measured: list[str] = []

    def never(path):
        measured.append(path)
        return Disk(1 * GB, 0, 1 * GB)

    monkeypatch.setattr(checks, "disk_usage", never)
    rows = _rows(now)
    assert (
        rows["disk.store"]["value"] == "90% used, 20.0 GB free of 200.0 GB" and rows["disk.store"]["state"] == "problem"
    )
    assert ("nik_disk_free_bytes", {"disk": "store"}, 20 * GB) in rows["disk.store"]["metrics"]
    assert settings.SAMPLE_STORE not in measured and settings.BACKUP_DIR in measured
    # The other rows of the keys and of the store are read from the database, in this process as in the other.
    assert rows["keys.state"]["state"] in ("fine", "attention") and rows["store.encryption"]["state"] == "unknown"
    # What was measured long ago is not passed off as now.
    store_seal._update(disk={"total": 200 * GB, "free": 20 * GB, "at": now - 7200})
    old = _rows(now)["disk.store"]
    assert old["state"] == "unknown" and old["value"] == "Not known here"
    assert "is not given the store of files" in old["detail"]
