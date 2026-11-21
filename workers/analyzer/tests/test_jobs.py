"""The jobs a worker is doing: what it answers about one it runs, one it finished, and one it does
not know (it was restarted since), and how it stops when it is asked to."""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import given  # noqa: E402
import jobs  # noqa: E402
import server  # noqa: E402

DATA = b"MZ a harmless fixture, never a sample"
SHA = hashlib.sha256(DATA).hexdigest()


class Clock:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


def test_a_job_is_running_then_finished_then_forgotten():
    clock = Clock()
    held = jobs.Jobs(clock=clock)
    assert held.state("code:abc:1") is None and held.count() == 0
    with held.running("code:abc:1") as say:
        clock.now += 42
        assert held.state("code:abc:1") == {"state": "running", "seconds": 42.0, "progress": ""}
        say("decompiling")
        assert held.state("code:abc:1")["progress"] == "decompiling" and held.count() == 1
    clock.now += 5
    # Ended: remembered as finished for a while, so that a question that crosses the answer is not
    # taken for a restart; then forgotten.
    assert held.state("code:abc:1") == {"state": "finished", "seconds": 42.0, "progress": ""}
    assert held.count() == 0
    clock.now += jobs.KEPT + 1
    assert held.state("code:abc:1") is None


def test_a_job_that_fails_is_over_too_and_a_request_without_a_name_is_not_tracked():
    held = jobs.Jobs()
    with pytest.raises(ValueError), held.running("capa:abc:1"):
        raise ValueError("the analysis failed")
    assert held.state("capa:abc:1")["state"] == "finished"
    for name in (None, "", "has a space", "../etc/passwd", "x" * 161):
        with held.running(name) as say:
            say("ignored")
            assert held.count() == 0
    assert len(held._jobs) == 1


def test_what_is_remembered_is_bounded():
    held = jobs.Jobs()
    for number in range(jobs.MAX_KEPT + 50):
        with held.running(f"job:{number}"):
            pass
    with held.running("the-last"):
        assert len(held._jobs) <= jobs.MAX_KEPT + 1
        assert held.state("the-last")["state"] == "running"


def test_the_answer_to_a_question_about_a_job():
    held = jobs.Jobs()
    assert held.answer("/health") is None and held.answer("/jobs/") is None and held.answer("/jobs/a/b") is None
    status, body = held.answer("/jobs/code:abc:1")
    assert status == 404 and body == {"detail": "Unknown job", "unknown": True, "started": held.started}
    with held.running("code:abc:1"):
        status, body = held.answer("/jobs/code:abc:1")
        assert status == 200 and body["state"] == "running"


def test_draining_waits_for_the_jobs_and_no_longer_than_the_grace():
    held = jobs.Jobs()
    said, naps = [], []
    assert jobs.drain(held, 5.0, say=lambda text, flush=False: said.append(text), sleep=naps.append) == 0
    assert said == ["stopped"] and naps == []

    with held.running("code:abc:1"):
        # It ends during the grace: the worker waits for it.
        def nap(seconds: float) -> None:
            naps.append(seconds)
            if len(naps) == 3:
                held._jobs["code:abc:1"]["ended"] = held._clock()

        assert jobs.drain(held, 5.0, say=lambda text, flush=False: said.append(text), sleep=nap) == 0
        assert len(naps) == 3
    with held.running("code:abc:2"):
        naps.clear()
        # It does not: it is cut after the grace, and the worker says how many were.
        assert jobs.drain(held, 1.0, say=lambda text, flush=False: said.append(text), sleep=naps.append) == 1
        assert 4 <= len(naps) <= 6 and said[-1] == "stopped (1 job(s) cut)"


def test_asked_to_stop_the_server_takes_no_new_request():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    serving = threading.Thread(target=httpd.serve_forever, daemon=True)
    serving.start()
    said = []
    jobs.stop_politely(httpd, say=lambda text, flush=False: said.append(text))
    serving.join(10)
    assert not serving.is_alive() and said == ["stopping: no new request is taken"]
    httpd.server_close()


# --------------------------------------------------------------------------- #
# Over HTTP                                                                   #
# --------------------------------------------------------------------------- #
def call(url, method="POST", body=None, token="test-token", job=None):
    data = body if isinstance(body, bytes) else (json.dumps(body).encode() if body is not None else None)
    headers = {"X-Analyzer-Token": token, **({jobs.HEADER: job} if job else {})}
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


@pytest.fixture()
def worker(tmp_path, monkeypatch):
    """The worker, with an analysis that waits until the test lets it go."""
    go, begun = threading.Event(), threading.Event()
    monkeypatch.setattr(server, "TOKEN", "test-token")
    monkeypatch.setattr(server, "GIVEN", given.Given(str(tmp_path / "given"), server.GIVEN.allowed, max_bytes=10**6))
    monkeypatch.setattr(server, "JOBS", jobs.Jobs())

    def analyze(path, **kwargs):
        begun.set()
        assert go.wait(20), "the analysis was never let go"
        return {"read": hashlib.sha256(open(path, "rb").read()).hexdigest()}

    monkeypatch.setattr(server, "analyze", analyze)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", go, begun
    go.set()
    httpd.shutdown()
    httpd.server_close()


def test_the_backend_asks_whether_the_worker_still_has_its_job(worker):
    url, go, begun = worker
    name = f"code:{SHA}:1"
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA) == (200, {})
    answer = {}
    asking = threading.Thread(
        target=lambda: answer.update(result=call(f"{url}/analyze", body={"sha256": SHA}, job=name)), daemon=True
    )
    asking.start()
    assert begun.wait(20)
    # While it runs: the job is there, and says how far it is. It is slow, not gone.
    status, state = call(f"{url}/jobs/{name}", "GET")
    assert status == 200 and state["state"] == "running" and state["progress"] == "disassembling"
    # A question needs the token, like everything but the health check.
    assert call(f"{url}/jobs/{name}", "GET", token="wrong")[0] == 401
    status, health = call(f"{url}/health", "GET", token="")
    assert status == 200 and health["started"] == server.JOBS.started
    # A job it was never given: said at once, not after a timeout.
    status, unknown = call(f"{url}/jobs/code:{'b' * 64}:1", "GET")
    assert status == 404 and unknown["unknown"] is True and unknown["detail"] == "Unknown job"
    assert call(f"{url}/elsewhere", "GET")[0] == 404
    go.set()
    asking.join(20)
    assert answer["result"] == (200, {"read": SHA})
    assert call(f"{url}/jobs/{name}", "GET")[1]["state"] == "finished"


def test_a_worker_that_restarted_knows_neither_the_job_nor_the_file(worker, tmp_path, monkeypatch):
    url, go, begun = worker
    name = f"code:{SHA}:1"
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA) == (200, {})

    def cut_short() -> None:
        try:
            call(f"{url}/analyze", body={"sha256": SHA}, job=name)
        except Exception:  # noqa: BLE001 - the worker goes away under this request: that is the test
            pass

    asking = threading.Thread(target=cut_short, daemon=True)
    asking.start()
    assert begun.wait(20)
    assert call(f"{url}/jobs/{name}", "GET")[1]["state"] == "running"
    # The worker is killed and starts again: its memory and what it was given are gone.
    before = server.JOBS.started
    server.GIVEN.clear()
    restarted = jobs.Jobs()
    restarted.started = before + 60
    monkeypatch.setattr(server, "JOBS", restarted)
    status, unknown = call(f"{url}/jobs/{name}", "GET")
    assert status == 404 and unknown["unknown"] is True and unknown["started"] == before + 60
    # Handed out again under the next name: the worker says what it lacks, is given it, and does the job.
    go.set()
    again = f"code:{SHA}:2"
    status, lacking = call(f"{url}/analyze", body={"sha256": SHA}, job=again)
    assert status == 409 and lacking["missing"] == [f"{SHA}.bin"]
    assert call(f"{url}/files/{SHA}.bin", "PUT", DATA) == (200, {})
    assert call(f"{url}/analyze", body={"sha256": SHA}, job=again) == (200, {"read": SHA})
    assert call(f"{url}/jobs/{again}", "GET")[1]["state"] == "finished"
    assert call(f"{url}/jobs/{name}", "GET")[0] == 404
