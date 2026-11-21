"""Work the API process holds, across a restart: taken back once, started again or failed loudly,
set aside when it keeps being interrupted; and a worker that is slow, restarted or silent.

The clock is the tests' own: a holder "vanishes" when the time of the sweeper is moved past its
last sign of life. Every loop here ends by a counter.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import artifact_jobs, events, mirror, work
from app.automation import worker as automation_worker
from app.core import leases
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import ArtifactJob, AutomationEvent, Job, Lease, MirrorJob, SampleCode, Webhook, WorkClaim
from app.health import checks, thresholds
from app.routers import samples as sample_routes
from app.workers import analyzer, watching
from tests.conftest import make_key
from tests.test_code import WORKER_RESULT
from tests.test_executables import minimal_pe

NOW = 1_800_000_000.0
GONE = NOW + work.STALE_AFTER + 1  # the holder of NOW has not said it is alive for too long


@pytest.fixture()
def things(client: TestClient, monkeypatch):
    """A kind of work of the tests' own, started again by the rule, and what was done with it."""
    seen = {"started": [], "failed": []}

    def start(ref: str, params: dict):
        seen["started"].append((ref, params))
        return False if ref == "nothing-left" else None

    work.register(
        work.Kind(
            "thing", "a thing of the tests", "again", start, lambda db, ref, said: seen["failed"].append((ref, said))
        )
    )
    work.register(
        work.Kind(
            "once",
            "a thing done once",
            "fail",
            lambda ref, params: False,
            lambda db, ref, said: seen["failed"].append((ref, said)),
        )
    )
    yield seen
    work._KINDS.pop("thing", None)
    work._KINDS.pop("once", None)


def claim(kind: str, ref: str) -> WorkClaim:
    with SessionLocal() as db:
        row = db.get(WorkClaim, (kind, ref))
        db.expunge(row)
        return row


def held_by(holder: str, kind: str, ref: str, now: float = NOW) -> None:
    """Another process takes the work at ``now``."""
    mine = work.HOLDER
    work.HOLDER = holder
    try:
        with SessionLocal() as db:
            work.take(db, kind, ref, now)
    finally:
        work.HOLDER = mine


# --------------------------------------------------------------------------- #
# Claims                                                                      #
# --------------------------------------------------------------------------- #
def test_work_is_written_down_taken_and_finished(things):
    with SessionLocal() as db:
        work.want(db, "thing", "a", {"actor": "anna"}, NOW)
        db.commit()
    assert (claim("thing", "a").state, claim("thing", "a").attempts) == ("wanted", 0)
    with work.hold("thing", "a", NOW + 1) as held:
        assert (held.attempts, held.params) == (1, {"actor": "anna"})
        found = claim("thing", "a")
        assert (found.state, found.holder, found.beat_at) == ("held", work.HOLDER, NOW + 1)
        held.progress("half-way")
        assert claim("thing", "a").progress == "half-way"
        # Nobody else takes what is held by a process that is alive.
        with SessionLocal() as db, pytest.raises(work.Taken):
            work.take(db, "thing", "a", NOW + 2)
    done = claim("thing", "a")
    assert (done.state, done.progress, done.attempts) == ("done", "", 1) and done.finished_at
    # A block that says it failed wrote its own end: the work is over.
    with SessionLocal() as db:
        work.want(db, "thing", "b", now=NOW)
        db.commit()
    with work.hold("thing", "b", NOW) as held:
        held.failed = True
    assert claim("thing", "b").state == "failed"


def test_work_whose_thread_was_cut_while_its_process_lives_is_handed_back(things):
    """The database is killed under an analysis: its thread cannot write what it found."""
    with SessionLocal() as db:
        work.want(db, "thing", "cut", now=NOW)
        db.commit()
    # The block raises: nothing of it ended, and the piece is wanted again, due at once, counted.
    with pytest.raises(ConnectionError), work.hold("thing", "cut", NOW):
        raise ConnectionError("terminating connection due to administrator command")
    found = claim("thing", "cut")
    assert (found.state, found.holder, found.beat_at, found.attempts) == ("wanted", "", 0, 1)
    assert found.interrupted_at and "ConnectionError" in found.note
    with SessionLocal() as db:
        assert work.start_wanted(db, NOW + 1) == [("thing", "cut")]
    # The database was still away when the thread ended: the piece stays under the name of this
    # process, which does not speak for what none of its threads does, and hands it back.
    with SessionLocal() as db:
        work.take(db, "thing", "cut", NOW + 2)
        work.want(db, "thing", "alive", now=NOW)
        db.commit()
    with work.hold("thing", "alive", NOW + 2):
        assert work.beat(NOW + 12) == 1
        assert (claim("thing", "alive").beat_at, claim("thing", "alive").state) == (NOW + 12, "held")
        handed = claim("thing", "cut")
        assert (handed.state, handed.holder, handed.attempts) == ("wanted", "", 2)
        assert handed.note == "Its thread ended without finishing it: started again"
    # Cut every time it is tried: set aside by the sweeper, not started a fourth time.
    with SessionLocal() as db:
        work.take(db, "thing", "cut", NOW + 20)
    assert work.beat(NOW + 30) == 0
    with SessionLocal() as db:
        assert work.start_wanted(db, NOW + 31) == []
    assert claim("thing", "cut").state == "aside" and [ref for ref, _said in things["failed"]] == ["cut"]


def test_the_heartbeat_is_of_the_process_and_keeps_what_it_holds(things, monkeypatch):
    with SessionLocal() as db:
        for ref in ("mine", "theirs"):
            work.want(db, "thing", ref, now=NOW)
        db.commit()
        work.take(db, "thing", "mine", NOW)
    held_by("another-process", "thing", "theirs")
    assert work.beat(NOW + 30, strict=False) == 1
    assert (claim("thing", "mine").beat_at, claim("thing", "theirs").beat_at) == (NOW + 30, NOW)
    # A process that is slow and alive is not taken for dead, however long its work takes.
    with SessionLocal() as db:
        assert work.take_back(db, NOW + 30 + work.STALE_AFTER - 1) == [("thing", "theirs", "again")]
        assert claim("thing", "mine").state == "held"


def test_work_whose_holder_vanished_is_taken_back_once_and_started_again(things, monkeypatch):
    with SessionLocal() as db:
        work.want(db, "thing", "a", {"actor": "anna"}, NOW)
        db.commit()
    held_by("a-process-that-dies", "thing", "a")
    with SessionLocal() as db:
        assert work.take_back(db, NOW + work.STALE_AFTER - 1) == []  # it may only be slow
        assert work.take_back(db, GONE) == [("thing", "a", "again")]
        assert work.take_back(db, GONE) == []  # once
    found = claim("thing", "a")
    assert (found.state, found.holder, found.interrupted_at, found.note) == ("wanted", "", GONE, work.INTERRUPTED)
    with SessionLocal() as db:
        assert work.start_wanted(db, GONE) == [("thing", "a")]
        assert work.start_wanted(db, GONE + 1) == []  # the process that started it has its time to take it
    assert things["started"] == [("a", {"actor": "anna"})]
    with work.hold("thing", "a", GONE + 2) as held:
        assert held.attempts == 2
    said = None
    with SessionLocal() as db:
        said = work.describe(db, "thing", "a")
    assert said == {
        "state": "done",
        "attempts": 2,
        "interruptedAt": GONE,
        "resumedAt": GONE + 2,
        "progress": "",
        "note": work.INTERRUPTED,
    }


def test_two_sweepers_do_not_both_take_the_work_back_nor_start_it(things, monkeypatch):
    with SessionLocal() as db:
        work.want(db, "thing", "a", now=NOW)
        db.commit()
    held_by("a-process-that-dies", "thing", "a")
    # One lease: the second process sweeps nothing while the first holds it.
    assert work.sweep(GONE, holder="one") == {"taken_back": [("thing", "a", "again")], "started": [("thing", "a")]}
    assert work.sweep(GONE, holder="two") == {"taken_back": [], "started": []}
    assert len(things["started"]) == 1
    # And were both to look at once (a lease that ran out late), each row changes hands once: here
    # the work that was started and that nobody took in its time is started again, by one of them.
    later = GONE + work.WANTED_GRACE + 1
    with SessionLocal() as one, SessionLocal() as two:
        first, second = work.start_wanted(one, later), work.start_wanted(two, later)
    assert (first, second) == ([("thing", "a")], []) and len(things["started"]) == 2


def test_work_that_is_interrupted_every_time_is_set_aside(things, monkeypatch):
    with SessionLocal() as db:
        work.want(db, "thing", "poison", now=NOW)
        db.commit()
    now = NOW
    done = []
    for number in range(work.MAX_ATTEMPTS):
        held_by(f"process-{number}", "thing", "poison", now)
        now += work.STALE_AFTER + 1
        with SessionLocal() as db:
            done += work.take_back(db, now)
    assert [what for _kind, _ref, what in done] == ["again", "again", "aside"]
    found = claim("thing", "poison")
    assert (found.state, found.attempts) == ("aside", work.MAX_ATTEMPTS)
    assert f"was interrupted {work.MAX_ATTEMPTS} times and is not tried again by itself" in found.note
    assert [ref for ref, _said in things["failed"]] == ["poison"]
    # It is not started again, and nobody takes it; asked for again by a person, it is new.
    with SessionLocal() as db:
        assert work.start_wanted(db, now + 100) == []
        with pytest.raises(work.Taken):
            work.take(db, "thing", "poison", now + 100)
        work.want(db, "thing", "poison", now=now + 200)
        db.commit()
        assert work.take(db, "thing", "poison", now + 201).attempts == 1


def test_what_cannot_be_gone_on_with_fails_and_says_so(things, monkeypatch):
    with SessionLocal() as db:
        work.want(db, "once", "held", now=NOW)
        work.want(db, "once", "never-taken", now=NOW)
        db.commit()
    held_by("a-process-that-dies", "once", "held")
    result = work.sweep(GONE)
    assert result["taken_back"] == [("once", "held", "failed")] and result["started"] == []
    assert (claim("once", "held").state, claim("once", "never-taken").state) == ("failed", "failed")
    assert sorted(ref for ref, _said in things["failed"]) == ["held", "never-taken"]
    assert all(said.startswith("It was interrupted by a restart of the server") for _ref, said in things["failed"])


def test_work_with_nothing_left_to_start_is_over(things):
    with SessionLocal() as db:
        work.want(db, "thing", "nothing-left", now=NOW)
        db.commit()
        assert work.start_wanted(db, NOW + work.WANTED_GRACE + 1) == []
    assert claim("thing", "nothing-left").state == "done" and things["started"] == [("nothing-left", {})]


def test_a_process_that_is_asked_to_stop_hands_its_work_back_at_once(things):
    with SessionLocal() as db:
        work.want(db, "thing", "a", now=NOW)
        work.want(db, "thing", "not-started-yet", now=NOW)
        db.commit()
        work.take(db, "thing", "a", NOW)
    assert work.release_all(NOW + 5) == 1
    found = claim("thing", "a")
    # Wanted, due at once, and the try does not count against the work.
    assert (found.state, found.holder, found.beat_at, found.attempts) == ("wanted", "", 0, 0)
    assert found.interrupted_at == NOW + 5 and claim("thing", "not-started-yet").beat_at == 0
    # The process takes nothing more; the one that starts next takes both without waiting.
    with SessionLocal() as db, pytest.raises(work.Taken):
        work.take(db, "thing", "a", NOW + 6)
    work.starting()
    with SessionLocal() as db:
        assert sorted(work.start_wanted(db, NOW + 6)) == [("thing", "a"), ("thing", "not-started-yet")]


def test_stopping_the_application_gives_back_its_leases_and_its_work(things):
    from app import main

    with SessionLocal() as db:
        assert leases.take(db, "a-loop-of-the-api", work.HOLDER, 120, time.time())
        work.want(db, "thing", "a", now=NOW)
        db.commit()
        work.take(db, "thing", "a", NOW)
    main.on_shutdown()
    with SessionLocal() as db:
        assert db.get(Lease, "a-loop-of-the-api") is None
    assert claim("thing", "a").state == "wanted" and work.stopping() and automation_worker._stopping.is_set()


# --------------------------------------------------------------------------- #
# A worker that is slow, restarted, or silent                                 #
# --------------------------------------------------------------------------- #
class Ticks:
    """A clock that moves a second each time it is read."""

    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        self.now += 1.0
        return self.now


def waiting_call(answers: list, release_after: int | None = None):
    """A call that waits until the worker was asked ``release_after`` times, and what answers the
    asking: each answer of ``answers`` in turn, then the last one for ever."""
    go, asked = threading.Event(), []

    def call():
        assert go.wait(20), "the call was never let go"
        return "the result"

    def asking():
        asked.append(1)
        if release_after is not None and len(asked) >= release_after:
            go.set()
        return answers[min(len(asked), len(answers)) - 1]

    return call, asking, asked, go


QUICK = {"every": 0.005, "grace": 0.0, "sleep": lambda seconds: None}


def test_a_worker_that_is_slow_is_waited_for(client: TestClient):
    said = []
    call, asking, asked, _go = waiting_call([("running", "pass 1"), ("running", "pass 2")], release_after=40)
    result = watching.watched(call, "job", asking, on_progress=said.append, clock=Ticks(), silent=5.0, **QUICK)
    assert result == "the result" and len(asked) >= 40  # forty questions, eight times the silence allowed
    assert said[0] == "pass 1" and said[-1] == "pass 2"


def test_a_worker_that_says_unknown_job_restarted_and_is_not_waited_for(client: TestClient):
    call, asking, asked, go = waiting_call([("running", ""), ("unknown", "")])
    with pytest.raises(watching.WorkerLost, match="restarted"):
        watching.watched(call, "job", asking, clock=Ticks(), **QUICK)
    assert len(asked) == 3  # known once, then unknown twice: no timeout was waited for
    go.set()
    # Within the grace of a request that was just made, "unknown" is only "not yet".
    call, asking, asked, _go = waiting_call([("unknown", ""), ("unknown", ""), ("running", "")], release_after=5)
    assert watching.watched(call, "job", asking, clock=Ticks(), every=0.005, grace=1000.0) == "the result"


def test_a_worker_that_stops_answering_is_lost_after_its_silence(client: TestClient):
    call, asking, asked, go = waiting_call([("running", ""), ("", "")])
    with pytest.raises(watching.WorkerLost, match="did not answer for 10 seconds"):
        watching.watched(call, "job", asking, clock=Ticks(), silent=10.0, **QUICK)
    assert 10 <= len(asked) <= 13
    go.set()


def test_a_connection_that_broke_is_a_restart_only_when_the_worker_says_so(client: TestClient):
    def broken():
        failure = analyzer.AnalyzerError("Cannot reach the worker: connection reset")
        failure.unreachable = True
        raise failure

    # Back up, and it knows nothing of the job: it restarted under it.
    with pytest.raises(watching.WorkerLost):
        watching.watched(broken, "job", lambda: ("unknown", ""), clock=Ticks(), **QUICK)
    # It never comes back: the worker is down, which is what the call said.
    with pytest.raises(analyzer.AnalyzerError, match="Cannot reach the worker"):
        watching.watched(broken, "job", lambda: ("", ""), clock=Ticks(), back_within=5.0, **QUICK)

    # An answer of the worker, even a refusal, is an answer: it is not asked anything.
    def refused():
        raise analyzer.AnalyzerError("rizin did not finish within 600 seconds")

    with pytest.raises(analyzer.AnalyzerError, match="600 seconds"):
        watching.watched(refused, "job", lambda: pytest.fail("asked"), clock=Ticks(), **QUICK)


def test_a_job_the_worker_lost_is_handed_out_again_and_set_aside_the_third_time(things):
    with SessionLocal() as db:
        work.want(db, "thing", "a", now=NOW)
        db.commit()
    names, lost = [], [2]

    def watch(call, job, asking, on_progress=None, **timing):
        names.append(job)
        if lost[0]:
            lost[0] -= 1
            raise watching.WorkerLost("The worker was restarted while it did this: it no longer has the job")
        return call()

    with work.hold("thing", "a", NOW) as held:
        out = watching.handed_out(held, lambda: "the result", "http://w", "X", "t", what="this", watch=watch)
        assert out == "the result" and held.attempts == 3
    # Each handing out has a name of its own: the worker cannot take one for another.
    assert names == ["thing:a:1", "thing:a:2", "thing:a:3"]
    found = claim("thing", "a")
    assert found.state == "done" and found.interrupted_at and found.resumed_at and "restarted" in found.note

    # A file that takes the worker down every time.
    with SessionLocal() as db:
        work.want(db, "thing", "poison", now=NOW)
        db.commit()
    lost[0] = 99
    with work.hold("thing", "poison", NOW) as held, pytest.raises(watching.SetAside, match="stopped 3 times"):
        watching.handed_out(held, lambda: "never", "http://w", "X", "t", what="this", watch=watch)
    assert claim("thing", "poison").state == "aside" and names[3:] == [
        "thing:poison:1",
        "thing:poison:2",
        "thing:poison:3",
    ]


def test_the_request_of_a_job_carries_its_name_and_the_worker_is_asked_by_it(client: TestClient, monkeypatch):
    import io
    import json
    import urllib.error
    import urllib.request

    asked = []

    def opened(request, timeout=None):
        asked.append((request.full_url, dict(request.header_items())))
        if request.full_url.endswith("/jobs/code%3Aabc%3A1"):
            body = json.dumps({"detail": "Unknown job", "unknown": True, "started": 1.0}).encode()
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(body))
        if "/jobs/" in request.full_url:
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, io.BytesIO(b'{"detail": "Not found"}'))
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(urllib.request, "urlopen", opened)
    assert watching.job_name("code", "abc", 1) == "code:abc:1"
    assert watching.ask("http://analyzer.test", "X-Analyzer-Token", "secret", "code:abc:1") == ("unknown", "")
    assert asked[0][1]["X-analyzer-token"] == "secret"
    # A worker of a release before 6.9 does not know the question: it is there, and that is all it
    # says. It is waited for as before, not taken for one that restarted nor for one that is silent.
    assert watching.ask("http://analyzer.test", "X-Analyzer-Token", "secret", "code:abc:2") == ("alive", "")
    call, asking, asked, _go = waiting_call([("alive", "")], release_after=40)
    assert watching.watched(call, "job", asking, clock=Ticks(), silent=5.0, **QUICK) == "the result"
    # No answer at all is something else.
    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=None: (_ for _ in ()).throw(OSError("down")))
    assert watching.ask("http://analyzer.test", "X-Analyzer-Token", "secret", "code:abc:2") == ("", "")
    monkeypatch.setattr(urllib.request, "urlopen", opened)
    # The request of a job says its name; one outside a job says none.
    token = watching.current_job.set("code:abc:1")
    try:
        with pytest.raises(analyzer.AnalyzerError) as failed:
            analyzer.post_worker("http://analyzer.test", "secret", "/analyze", {}, 5)
    finally:
        watching.current_job.reset(token)
    assert asked[-1][1]["X-nik-job"] == "code:abc:1" and failed.value.unreachable is True
    with pytest.raises(analyzer.AnalyzerError):
        analyzer.post_worker("http://analyzer.test", "secret", "/analyze", {}, 5)
    assert "X-nik-job" not in asked[-1][1]


# --------------------------------------------------------------------------- #
# The jobs themselves                                                         #
# --------------------------------------------------------------------------- #
class Later:
    """Stands in for the background tasks of a request whose process dies before they run."""

    def __init__(self) -> None:
        self.tasks = []

    def add_task(self, job, *args) -> None:
        self.tasks.append((job, args))


def test_a_disassembly_whose_api_process_died_is_started_again_and_said_once(admin: TestClient, monkeypatch):
    calls = []
    key = make_key(admin, roles=["analyst"])
    admin.post("/api/incidents", headers=key, json={"id": "c1", "name": "c1", "data": {}})
    uploaded = admin.post("/api/incidents/c1/samples", headers=key, files={"file": ("x.exe", minimal_pe(b"\x90\xc3"))})
    sha = uploaded.json()["sample"]["sha256"]  # no analyzer yet: the upload itself started nothing
    monkeypatch.setattr(settings, "ANALYZER_URL", "http://analyzer.test")
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "secret")
    monkeypatch.setattr(analyzer, "request_code_analysis", lambda sha, signatures: calls.append(sha) or WORKER_RESULT)
    monkeypatch.setattr(work, "thread", lambda job, *args: job(*args))

    # Asked for, and the process dies before the thread of the job even starts.
    with SessionLocal() as db:
        sample_routes._queue_code(db, Later(), sha, "anna")
    now = time.time()
    assert (claim("code", sha).state, calls) == ("wanted", [])
    state = admin.get(f"/api/samples/{sha}/code", headers=key).json()
    assert state["status"] == "queued" and state["work"]["attempts"] == 0
    # Nobody took it: the sweeper of the process that runs starts it.
    with SessionLocal() as db:
        assert work.start_wanted(db, now + 5) == []  # the process that asked has its time to start it
        assert work.start_wanted(db, now + work.WANTED_GRACE + 1) == [("code", sha)]
    assert calls == [sha]
    state = admin.get(f"/api/samples/{sha}/code", headers=key).json()
    assert state["status"] == "done" and state["work"]["state"] == "done"

    # Asked for again; this time the process dies while it waits for the worker.
    with SessionLocal() as db:
        sample_routes._queue_code(db, Later(), sha, "anna")
        db.get(SampleCode, sha).status = "running"
        db.commit()
    held_by("an-api-process-that-dies", "code", sha, now)
    swept = work.sweep(now + work.STALE_AFTER + 1)
    assert swept == {"taken_back": [("code", sha, "again")], "started": [("code", sha)]}
    assert calls == [sha, sha]
    state = admin.get(f"/api/samples/{sha}/code", headers=key).json()
    assert state["status"] == "done" and state["work"]["attempts"] == 2
    assert state["work"]["interruptedAt"] and state["work"]["resumedAt"]
    # ``code.analysed`` once for each analysis that ended: none for the one that was cut.
    with SessionLocal() as db:
        assert len(db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "code.analysed")).all()) == 2


def test_a_disassembly_that_keeps_being_interrupted_fails_with_that_reason(admin: TestClient, monkeypatch):
    key = make_key(admin, roles=["analyst"])
    admin.post("/api/incidents", headers=key, json={"id": "c1", "name": "c1", "data": {}})
    uploaded = admin.post("/api/incidents/c1/samples", headers=key, files={"file": ("x.exe", minimal_pe(b"\xeb\xfe"))})
    sha = uploaded.json()["sample"]["sha256"]
    with SessionLocal() as db:
        db.add(
            SampleCode(
                sha256=sha, summary={}, status="running", requested_at="2026-11-21T10:00:00+00:00", requested_by="anna"
            )
        )
        work.want(db, "code", sha, now=NOW)
        db.commit()
    now = NOW
    for number in range(work.MAX_ATTEMPTS):
        held_by(f"process-{number}", "code", sha, now)
        now += work.STALE_AFTER + 1
        with SessionLocal() as db:
            work.take_back(db, now)
    monkeypatch.setattr(settings, "ANALYZER_URL", "http://analyzer.test")
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "secret")
    with SessionLocal() as db:
        row = db.get(SampleCode, sha)
        assert row.status == "error" and row.error.startswith(
            "Set aside: the disassembly of a file was interrupted 3 times"
        )
        # Said to who waits for it, as any analysis that ends.
        assert len(db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "code.analysed")).all()) == 1
        rows = {found["id"]: found for found in checks.gather(db, thresholds.read(db), {}, now)}
    assert rows["work.aside"]["state"] == "attention" and "1 × the disassembly of a file" in rows["work.aside"]["value"]
    assert admin.get(f"/api/samples/{sha}/code", headers=key).json()["work"]["state"] == "aside"


def test_an_upload_that_was_being_parsed_fails_loudly(admin: TestClient, monkeypatch):
    key = make_key(admin, roles=["analyst"])
    with SessionLocal() as db:
        db.add(Job(id="job-1", kind="upload", status="running", incident_id="inc", created_at="t", updated_at="t"))
        work.want(db, "upload", "job-1", now=NOW)
        db.commit()
    held_by("an-api-process-that-dies", "upload", "job-1")
    assert work.sweep(GONE)["taken_back"] == [("upload", "job-1", "failed")]
    job = admin.get("/api/jobs/job-1", headers=key).json()
    assert job["status"] == "error"
    assert job["error"] == "Interrupted by a restart of the server before the file was parsed: upload the file again."
    assert work.sweep(GONE + 100) == {"taken_back": [], "started": []}  # and it is over


def test_what_a_playbook_asked_about_a_file_goes_back_to_the_queue_and_is_done_once(admin: TestClient, monkeypatch):
    with SessionLocal() as db:
        job = artifact_jobs.ask(db, "remove", {"names": []}, "nik", "run-1", 0, time.time())
        db.commit()
        job_id = job.id
        assert artifact_jobs.take(db) == job_id  # an API process takes it…
    held_by("an-api-process-that-dies", artifact_jobs.KIND, job_id, time.time() - 100)  # …and dies
    with SessionLocal() as db:
        assert db.get(ArtifactJob, job_id).status == "running" and artifact_jobs.take(db) is None
    swept = work.sweep(time.time())
    assert swept == {"taken_back": [(artifact_jobs.KIND, job_id, "again")], "started": [(artifact_jobs.KIND, job_id)]}
    with SessionLocal() as db:
        assert db.get(ArtifactJob, job_id).status == "queued"
    assert artifact_jobs.run_due(threads=False) == 1 and artifact_jobs.run_due(threads=False) == 0
    with SessionLocal() as db:
        job = db.get(ArtifactJob, job_id)
        assert (job.status, job.result) == ("done", {"removed": 0})
    assert claim(artifact_jobs.KIND, job_id).state == "done"


def mirror_job(kind: str, status: str, holder: str | None) -> str:
    with SessionLocal() as db:
        job = MirrorJob(
            id=f"{kind}-{status}"[:32],
            incident_id="inc",
            connection_id="c1",
            kind=kind,
            payload={},
            status=status,
            holder=holder,
            created_at="t",
            next_at=0,
        )
        db.add(job)
        db.commit()
        return job.id


def test_a_change_being_sent_to_a_mirrored_system_when_the_worker_stopped(admin: TestClient):
    update, comment = (
        mirror_job("update", "sending", "a-worker-that-died"),
        mirror_job("comment", "sending", "a-worker-that-died"),
    )
    with SessionLocal() as db:
        ours = MirrorJob(
            id="ours",
            incident_id="inc",
            connection_id="c1",
            kind="comment",
            payload={},
            status="sending",
            holder="me",
            created_at="t",
        )
        db.add(ours)
        db.commit()
        assert mirror.take_back(db, NOW, "me") == 2 and mirror.take_back(db, NOW, "me") == 0
        found = {job.id: job for job in db.scalars(select(MirrorJob))}
        # An update writes the fields as they are: sent again. A comment twice is two comments: not sent again.
        assert (found[update].status, found[update].next_at, found[update].holder) == ("pending", NOW, None)
        assert found[comment].status == "failed"
        assert found[comment].error.startswith("Interrupted by a restart: it is not known whether the comment reached")
        assert found["ours"].status == "sending"  # this worker is sending it now
        rows = {row["id"]: row for row in checks.gather(db, thresholds.read(db), {}, NOW)}
    assert "1 × a comment to a mirrored system that was not sent again" in rows["work.aside"]["value"]
    # A person sends it again from the queue.
    assert admin.post(f"/api/mirror/queue/{comment}/retry").status_code == 200


# --------------------------------------------------------------------------- #
# What leaves with a commit                                                   #
# --------------------------------------------------------------------------- #
def test_a_webhook_hears_of_a_change_only_once_it_is_committed(admin: TestClient, monkeypatch):
    sent = []
    monkeypatch.setattr(events, "_deliver", lambda url, secret, event, data: sent.append((event, data)))

    def delivered(count: int) -> list:
        """What was delivered (each from a thread of its own), once ``count`` are there or a moment passed."""
        for _ in range(200):
            if len(sent) >= count:
                break
            time.sleep(0.01)
        return sorted(sent, key=lambda pair: pair[1]["n"])

    with SessionLocal() as db:
        hook = Webhook(id="h1", url="http://siem.corp/hook", secret="s", events="code.analysed,file.analysed")
        hook.active, hook.created_at, hook.created_by = True, "t", "admin"
        db.add(hook)
        db.commit()
        events.emit_detached(db, "code.analysed", {"n": 1})
        assert sent == []  # not before the change is there
        db.rollback()  # the change did not happen: neither did the event
        db.commit()
        events.emit_detached(db, "code.analysed", {"n": 2})
        events.emit_detached(db, "file.analysed", {"n": 3})
        events.emit_detached(db, "mail.analysed", {"n": 4})  # nobody subscribed
        assert sent == []
        db.commit()
        assert delivered(2) == [("code.analysed", {"n": 2}), ("file.analysed", {"n": 3})]
        db.commit()  # and once
        time.sleep(0.05)
        assert len(sent) == 2


# --------------------------------------------------------------------------- #
# The health page                                                             #
# --------------------------------------------------------------------------- #
def test_the_health_page_says_what_restarts_left_behind(things, monkeypatch):
    def rows(now: float) -> dict:
        with SessionLocal() as db:
            return {row["id"]: row for row in checks.gather(db, thresholds.read(db), {}, now)}

    found = rows(NOW)
    assert [found[name]["state"] for name in ("work.interrupted", "work.aside", "work.silent")] == ["fine"] * 3
    assert found["work.interrupted"]["value"] == "None" and found["work.silent"]["value"] == "0 held, all alive"
    assert all(found[name]["group"] == "Work in progress" for name in ("work.interrupted", "work.aside", "work.silent"))
    # A step that waits for a person told that person when it was interrupted: the row does not tell again.
    assert [found[name]["notify"] for name in ("work.interrupted", "work.aside", "work.silent")] == [False, True, True]
    with SessionLocal() as db:
        work.want(db, "thing", "a", now=NOW)
        db.commit()
    held_by("a-process-that-dies", "thing", "a")
    assert rows(NOW + 10)["work.silent"]["state"] == "fine"
    late = rows(NOW + checks.SILENT_ATTENTION + 1)["work.silent"]
    assert late["state"] == "attention" and late["value"].startswith("1 held, one silent for 2 minutes")
    assert rows(NOW + checks.SILENT_PROBLEM + 1)["work.silent"]["state"] == "problem"
    metrics = {name: value for name, _labels, value in late["metrics"]}
    assert metrics["nik_work_held"] == 1 and metrics["nik_work_silent_seconds"] == checks.SILENT_ATTENTION + 1
    assert {
        "nik_work_held",
        "nik_work_interrupted",
        "nik_work_interrupted_oldest_seconds",
        "nik_work_set_aside",
        "nik_work_silent_seconds",
    } <= set(checks.METRICS)


def test_saying_how_far_the_work_is_never_costs_the_work(things, monkeypatch):
    with SessionLocal() as db:
        work.want(db, "thing", "a", now=NOW)
        db.commit()
    with work.hold("thing", "a", NOW) as held:
        # The database goes away for a moment while the worker is asked how far it is.
        def gone(*args, **kwargs):
            raise ConnectionError("terminating connection due to administrator command")

        monkeypatch.setattr(work, "_update", gone)
        held.progress("reading the packets (1 of 2)")
        monkeypatch.undo()
    assert claim("thing", "a").state == "done"


def test_the_database_going_away_under_a_job_hands_the_job_back(admin: TestClient, monkeypatch):
    from sqlalchemy.exc import OperationalError

    with SessionLocal() as db:
        job = artifact_jobs.ask(db, "remove", {"names": []}, "nik", "run-1", 0, time.time())
        db.commit()
        job_id = job.id
    remove, fell = artifact_jobs._WORK["remove"], []

    def falls_once(db, job, later):
        if not fell:
            fell.append(1)
            raise OperationalError("SELECT 1", {}, Exception("terminating connection due to administrator command"))
        return remove(db, job, later)

    monkeypatch.setitem(artifact_jobs._WORK, "remove", falls_once)
    with pytest.raises(OperationalError):
        artifact_jobs.run_due(threads=False)
    # Not failed "for a reason Nik did not expect": wanted again, and done at the next look.
    with SessionLocal() as db:
        assert (db.get(ArtifactJob, job_id).status, db.get(ArtifactJob, job_id).error) == ("running", None)
    assert (claim(artifact_jobs.KIND, job_id).state, claim(artifact_jobs.KIND, job_id).attempts) == ("wanted", 1)
    assert work.sweep(time.time())["started"] == [(artifact_jobs.KIND, job_id)]
    assert artifact_jobs.run_due(threads=False) == 1
    with SessionLocal() as db:
        assert db.get(ArtifactJob, job_id).status == "done"
