"""A server that did not start says so and stays up, for two reasons since 6.8: an upgrade that was
stopped (backups/upgrade.py) and a key that is missing or wrong (stopped.py). Both answer the same
way to the health check, to a scraper of the metrics and to everything else, and the automation
worker waits beside either."""

from __future__ import annotations

import json
import threading
import urllib.error
import urllib.request

import pytest

from app import stopped
from app.automation import worker
from app.backups import upgrade
from app.core.config import settings

SECRET = "a-value-that-must-never-be-in-an-answer-0123456789"


def ask(port: int, path: str, headers: dict[str, str] | None = None) -> tuple[int, str]:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", headers=headers or {})  # noqa: S310
    try:
        with urllib.request.urlopen(request, timeout=5) as answer:  # noqa: S310
            return answer.status, answer.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


@pytest.fixture(params=["keys", "upgrade"])
def stopped_server(request):
    """Each of the two servers that answer in the place of one that did not start, on a free port."""
    if request.param == "keys":
        server = stopped.server(["STORE_KEY is not set. Run deploy/init-env.sh."], port=0)
    else:
        server = upgrade.serve_stopped(
            upgrade.Stopped("rehearsal", f"the reason, with {SECRET}", output=SECRET), port=0
        )
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield request.param, server.server_address[1]
    server.shutdown()
    server.server_close()


def test_a_server_that_did_not_start_answers_one_way_whatever_stopped_it(stopped_server):
    kind, port = stopped_server
    # The health check of the container passes, so that the web container comes up to show the sentence,
    # and its answer says the server is not serving.
    status, body = ask(port, "/api/health")
    assert status == 200 and json.loads(body) == {"status": "stopped" if kind == "keys" else "upgrade-stopped"}
    # Everything else is 503 with one sentence, the same for every path and every caller.
    answers = {
        path: ask(port, path, headers)
        for path, headers in (
            ("/api/ready", None),
            ("/api/incidents", None),
            ("/api/health/details", None),
            ("/api/metrics", None),
            ("/api/metrics", {"Authorization": "Bearer a-scrape-token"}),
            ("/api/internal/store/sample/" + "a" * 64, {"X-Nik-Store": "anything"}),
        )
    }
    assert {status for status, _ in answers.values()} == {503}
    assert len({body for _, body in answers.values()}) == 1
    said = json.loads(next(iter(answers.values()))[1])
    assert said["detail"].startswith("Nik did not start: " if kind == "keys" else "The upgrade of Nik ")
    # A scraper is told the target is down; it is given no metric, and nothing of the reason that
    # only the log of the container holds.
    text = answers["/api/metrics"][1]
    assert "nik_" not in text and "# HELP" not in text and SECRET not in text


def test_the_automation_worker_waits_beside_a_server_that_did_not_start(stopped_server, monkeypatch):
    kind, port = stopped_server
    monkeypatch.setattr(settings, "STORE_API_URL", f"http://127.0.0.1:{port}")
    assert worker.backend_health() == ("stopped" if kind == "keys" else "upgrade-stopped")
    answers = iter([worker.backend_health(), worker.backend_health(), "ok"])
    waits: list[float] = []
    monkeypatch.setattr(worker, "backend_health", lambda: next(answers))
    monkeypatch.setattr(worker._stopping, "wait", lambda seconds: waits.append(seconds))
    worker._wait_for_the_backend()
    assert waits == [5, 5]  # it waited while the backend said it did not start, and went on when it ran


def test_the_automation_worker_does_not_wait_for_a_backend_that_is_not_there(monkeypatch):
    # Not told where the backend is (a development server runs the playbooks itself): nothing to ask.
    monkeypatch.setattr(settings, "STORE_API_URL", "")
    assert worker.backend_health() == ""
    # Told, and nothing answers: the worker runs without it, as it always did.
    monkeypatch.setattr(settings, "STORE_API_URL", "http://127.0.0.1:9")
    assert worker.backend_health() == ""
    waits: list[float] = []
    monkeypatch.setattr(worker._stopping, "wait", lambda seconds: waits.append(seconds))
    worker._wait_for_the_backend()
    assert waits == []


def test_a_running_server_says_ok_and_gives_its_metrics_to_the_token_only(admin):
    from fastapi.testclient import TestClient

    from app.main import app

    assert admin.get("/api/health").json() == {"status": "ok"}
    anonymous = TestClient(app)
    assert anonymous.get("/api/metrics").status_code == 401
    assert admin.get("/api/metrics").status_code == 401  # a session is not the scrape token
