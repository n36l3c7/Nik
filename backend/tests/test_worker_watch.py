"""The administrators are told when a worker stops answering and when it is back."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import worker_watch
from app.automation import state
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import Notification
from app.main import app as fastapi_app

T0 = 1_800_000_000.0  # 2027-01-15 08:00 UTC


@pytest.fixture()
def configuration(monkeypatch):
    """No worker is configured unless the test says so."""
    for worker in worker_watch.WORKERS:
        if worker.url:
            monkeypatch.setattr(settings, worker.url, "")
    monkeypatch.setattr(settings, "AUTOMATION_WORKER", "inline")

    def configure(**values):
        for name, value in values.items():
            monkeypatch.setattr(settings, name, value)

    return configure


def _account(admin: TestClient, username: str, roles: list[str], disabled: bool = False) -> None:
    res = admin.post("/api/users", json={"username": username, "password": "password1", "roles": roles})
    assert res.status_code == 201, res.text
    if disabled:
        assert admin.patch(f"/api/users/{res.json()['user']['id']}", json={"disabled": True}).status_code == 200


def _record(answers: dict[str, bool], at: float) -> list[str]:
    with SessionLocal() as db:
        told = worker_watch.record(db, answers, at)
        db.commit()
    return told


def _told() -> list[tuple[str, str, str]]:
    with SessionLocal() as db:
        rows = db.scalars(select(Notification).order_by(Notification.at, Notification.username)).all()
        return [(row.username, row.kind, row.text) for row in rows]


def _state(admin: TestClient, worker_id: str) -> dict:
    return next(row for row in admin.get("/api/workers").json()["workers"] if row["id"] == worker_id)


def test_every_admin_is_told_once_when_a_worker_is_down_and_once_when_it_is_back(admin: TestClient, configuration):
    configuration(BROWSER_URL="http://browser:8700")
    _account(admin, "boss", ["viewer", "admin"])
    _account(admin, "anna", ["analyst", "connectors"])
    _account(admin, "gone", ["admin"], disabled=True)

    assert _record({"browser": True}, T0 - 30) == []
    assert _state(admin, "browser")["state"] == "up"

    # It stops answering: not a word until that has lasted two minutes.
    assert _record({"browser": False}, T0) == []
    assert _record({"browser": False}, T0 + 60) == []
    assert _state(admin, "browser")["state"] == "failing" and _told() == []

    assert _record({"browser": False}, T0 + 120) == ["worker.down"]
    told = _told()
    assert [(who, kind) for who, kind, _ in told] == [("admin", "worker.down"), ("boss", "worker.down")]
    assert told[0][2].startswith("The isolated browser has not answered since 2027-01-15 08:00 UTC: addresses cannot")
    found = _state(admin, "browser")
    assert found["state"] == "down" and found["since"].startswith("2027-01-15T08:00:00")
    assert admin.get("/api/notifications").json()["notifications"][0]["link"] == "/settings/system/workers"

    # Still down: nothing more, however long it lasts.
    for later in (150, 180, 600, 870):
        assert _record({"browser": False}, T0 + later) == []
    assert len(_told()) == 2

    # Back: one notice, with how long it was down.
    assert _record({"browser": True}, T0 + 900) == ["worker.back"]
    back = [(who, text) for who, kind, text in _told() if kind == "worker.back"]
    assert back == [
        ("admin", "The isolated browser is answering again: it was down for 15 minutes."),
        ("boss", "The isolated browser is answering again: it was down for 15 minutes."),
    ]
    assert _record({"browser": True}, T0 + 930) == []
    found = _state(admin, "browser")
    assert found["state"] == "up" and found["since"].startswith("2027-01-15T08:15:00") and len(_told()) == 4


def test_a_blip_tells_nobody_and_the_count_starts_again(admin: TestClient, configuration):
    configuration(CAPA_URL="http://capa:8600")
    assert _record({"capa": False}, T0) == []
    assert _record({"capa": False}, T0 + 90) == []
    assert _record({"capa": True}, T0 + 110) == []  # a restart: back before two minutes
    assert _record({"capa": False}, T0 + 130) == []
    # Two minutes from the first check without an answer of this stretch, not of the one before.
    assert _record({"capa": False}, T0 + 240) == []
    assert _record({"capa": False}, T0 + 250) == ["worker.down"]
    assert _told()[0][2].startswith("The capa worker has not answered since 2027-01-15 08:02 UTC")


def test_a_worker_that_is_not_configured_is_not_watched(admin: TestClient, configuration):
    assert worker_watch.watched() == []
    # Whatever is said of it, nothing is kept and nobody is told.
    assert _record({"pcap": False}, T0) == [] and _record({"pcap": False}, T0 + 500) == []
    assert _told() == []
    rows = admin.get("/api/workers").json()["workers"]
    assert [row["id"] for row in rows] == ["automation", "analyzer", "capa", "docview", "browser", "pcap", "sandbox"]
    assert all(row["configured"] is False and row["state"] == "" and row["since"] is None for row in rows)

    # One that was down and is taken out of the configuration is forgotten: no "back" for it later.
    configuration(PCAP_URL="http://pcap:8800")
    _record({"pcap": False}, T0)
    assert _record({"pcap": False}, T0 + 120) == ["worker.down"]
    configuration(PCAP_URL="")
    assert _record({}, T0 + 150) == []
    configuration(PCAP_URL="http://pcap:8800")
    assert _record({"pcap": True}, T0 + 180) == [] and len(_told()) == 1


def test_only_the_configured_analysis_workers_are_asked(configuration, monkeypatch):
    asked = []

    def fake(base: str) -> bool:
        asked.append(base)
        return "sandbox" not in base

    monkeypatch.setattr(worker_watch, "healthy", fake)
    configuration(ANALYZER_URL="http://analyzer:8500", SANDBOX_URL="http://sandbox:8750", AUTOMATION_WORKER="container")
    assert worker_watch.probe() == {"analyzer": True, "sandbox": False}
    assert asked == ["http://analyzer:8500", "http://sandbox:8750"]
    assert [worker.id for worker in worker_watch.watched()] == ["automation", "analyzer", "sandbox"]


def test_the_automation_worker_is_watched_by_its_heartbeat_from_the_api_process(
    admin: TestClient, configuration, monkeypatch
):
    monkeypatch.setattr(worker_watch, "healthy", lambda base: True)
    configuration(AUTOMATION_WORKER="container", DOCVIEW_URL="http://docview:8650")
    with SessionLocal() as db:
        state.beat(db, T0)
    assert worker_watch.check(T0 + 30) == [] and _state(admin, "automation")["state"] == "up"
    # The last heartbeat gets old: the worker is not answering, and after two minutes of that it is down.
    assert worker_watch.check(T0 + 90) == [] and _state(admin, "automation")["state"] == "failing"
    assert worker_watch.check(T0 + 180) == []
    assert worker_watch.check(T0 + 210) == ["worker.down"]
    assert _told()[0][2].startswith("The automation worker has not answered since 2027-01-15 08:01 UTC: playbooks")
    assert _state(admin, "docview")["state"] == "up"
    assert worker_watch.check(T0 + 240) == []
    with SessionLocal() as db:
        state.beat(db, T0 + 3800)
    assert worker_watch.check(T0 + 3810) == ["worker.back"]
    assert _told()[-1][2] == "The automation worker is answering again: it was down for 1 hour 2 minutes."

    # Inline it is a thread of the API process itself, and off there is none: neither is watched.
    for where in ("inline", "off"):
        configuration(AUTOMATION_WORKER=where)
        assert not worker_watch.configured(worker_watch.BY_ID["automation"])


def test_several_api_processes_do_not_each_tell_the_administrators(admin: TestClient, configuration, monkeypatch):
    monkeypatch.setattr(worker_watch, "healthy", lambda base: False)
    configuration(ANALYZER_URL="http://analyzer:8500")
    assert worker_watch.check(T0, holder="one") == []
    # Another process, at the same moments: it does not hold the lease, asks nothing and writes nothing.
    assert worker_watch.check(T0 + 1, holder="two") == []
    assert worker_watch.check(T0 + 120, holder="one") == ["worker.down"]
    assert worker_watch.check(T0 + 121, holder="two") == []
    assert len(_told()) == 1
    # The first process is gone: the other takes over when the lease runs out, and knows what was said.
    taken_over = T0 + 120 + worker_watch.LEASE_SECONDS + 1
    assert worker_watch.check(taken_over, holder="two") == []
    monkeypatch.setattr(worker_watch, "healthy", lambda base: True)
    assert worker_watch.check(taken_over + 30, holder="two") == ["worker.back"]
    assert len(_told()) == 2


def test_how_long_it_was_down_reads_as_a_person_would_say_it():
    assert worker_watch.lasted(20) == "1 minute"
    assert worker_watch.lasted(125) == "2 minutes"
    assert worker_watch.lasted(3600) == "1 hour"
    assert worker_watch.lasted(2 * 3600 + 5 * 60) == "2 hours 5 minutes"


def test_the_health_check_of_a_worker_that_cannot_be_reached_is_an_answer_of_no(monkeypatch):
    def refused(url, timeout):
        raise OSError("connection refused")

    monkeypatch.setattr(worker_watch.urllib.request, "urlopen", refused)
    assert worker_watch.healthy("http://capa:8600") is False


def test_the_state_of_the_workers_is_for_admins(admin: TestClient, configuration):
    _account(admin, "anna", ["analyst"])
    anna = TestClient(fastapi_app)
    assert anna.post("/api/auth/login", json={"username": "anna", "password": "password1"}).status_code == 200
    assert anna.get("/api/workers").status_code == 403
    body = admin.get("/api/workers").json()
    assert body["downAfterSeconds"] == 120 and body["checkedAt"] is None
