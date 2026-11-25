"""Host evidence given whole (7.0): the upload route and the parameters of 6.x become sources.

The worker is not there in these tests: ``parse._events`` is what it would have sent.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import work
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import Artifact, ArtifactLink, EvidenceRecord, EvidenceSource, Incident, Job
from app.evidence import intake, originals, parse
from app.routers import incidents as incident_routes
from tests.test_evidence_parse import SOURCE, end, record

HISTORY = {"t": "source", "parser": "history", "version": "1", "kind": "commands", "source": "bash"}
SKIP = {"t": "skip", "reason": "record cannot be read", "offset": 100, "length": 10, "lost": 1, "detail": "bad"}
BASH = b"#1700000000\nsudo cat /etc/shadow\nls\n"


@pytest.fixture()
def worker(monkeypatch):
    """A forensics worker that is there: the events it will say, and what it was asked."""
    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    state = {"events": [SOURCE, record(1), record(2), end(2, in_file=2)], "asked": []}

    def fake(sha256, body, job):
        state["asked"].append({"sha256": sha256, **body})
        yield from state["events"]

    monkeypatch.setattr(parse, "_events", fake)
    return state


def make(admin: TestClient, incident_id: str = "u1", **more) -> str:
    assert admin.post("/api/incidents", json={"id": incident_id, "data": {}, **more}).status_code == 201
    return incident_id


def send(admin: TestClient, incident_id: str, query: str, data: bytes, name: str = ".bash_history", **headers):
    return admin.post(f"/api/incidents/{incident_id}/upload?{query}", files={"file": (name, data)}, headers=headers)


def sources_of(incident_id: str) -> list[EvidenceSource]:
    with SessionLocal() as db:
        return list(db.scalars(select(EvidenceSource).where(EvidenceSource.incident_id == incident_id)))


# --------------------------------------------------------------------------- #
# The parameters of 6.x                                                       #
# --------------------------------------------------------------------------- #
CASES = [
    ("eventlogs", {}, "Security.evtx", "", ("eventlog", "evtx", "evtx", ""), "eventlogs/evtx"),
    (
        "eventlogs",
        {},
        "Export.JSON",
        "",
        ("eventlog", "eventlog-json", "nik-eventlogs.json", ""),
        "eventlogs/nik-eventlogs.json",
    ),
    ("commands", {"shell": "powershell"}, "x", "", ("commands", "history", "powershell", ""), "commands/powershell"),
    (
        "browser",
        {"browser": "chrome", "source": "history"},
        "History",
        "",
        ("browser", "browser", "chrome.history", "Default"),
        "browser/chrome/Default/history",
    ),
    (
        "browser",
        {"browser": "firefox", "source": "places", "profile": "Work"},
        "places.sqlite",
        "",
        ("browser", "browser", "firefox.places", "Work"),
        "browser/firefox/Work/places",
    ),
    (
        "endpoint",
        {"category": "persistence", "source": "runkeys"},
        "runkeys.csv",
        "Windows",
        ("endpoint", "endpoint", "windows.persistence.runkeys", ""),
        "endpoint/persistence/runkeys",
    ),
    (
        "endpoint",
        {"category": "persistence", "source": "cron"},
        "crontab",
        "mac",
        ("endpoint", "endpoint", "macos.persistence.cron", ""),
        "endpoint/persistence/cron",
    ),
    (
        "endpoint",
        {"category": "usb", "source": "journal"},
        "usb.csv",
        "linux",
        ("endpoint", "endpoint", "linux.usb.journal", ""),
        "endpoint/usb/journal",
    ),
]


@pytest.mark.parametrize(("tab", "params", "name", "system", "mapped", "target"), CASES)
def test_each_tab_becomes_a_source_with_its_parser_and_the_original_kept(
    admin: TestClient, tab, params, name, system, mapped, target
):
    make(admin, "m1", os=system)
    data = f"the file {tab} {name}".encode()
    with SessionLocal() as db:
        source = intake.take(db, db.get(Incident, "m1"), data, name, tab, params, "tester")
        db.commit()
        kind, parser, source_name, profile = mapped
        assert (source.kind, source.parser, source.source, source.profile) == mapped
        assert (source.state, source.read, source.file_name, source.size) == ("queued", "unknown", name, len(data))
        assert source.already is False and intake.target_of(source) == target
        sha = source.sha256
        assert originals.has(sha)
        artifact = db.get(Artifact, f"hostfile-{sha}")
        assert artifact is not None and db.get(ArtifactLink, (artifact.id, "m1")) is not None
        # The same file sent again is the source the incident has.
        again = intake.take(db, db.get(Incident, "m1"), data, name, tab, params, "tester")
        assert again.id == source.id and again.already is True


@pytest.mark.parametrize(
    ("query", "system", "sentence"),
    [
        ("tab=nope", "", "Unknown tab 'nope'"),
        ("tab=commands", "", "Unknown shell ''."),
        ("tab=commands&shell=nope", "", "Unknown shell 'nope'."),
        ("tab=browser&browser=chrome", "", "Unknown browser/source 'chrome/'."),
        ("tab=browser&browser=chrome&source=places", "", "Unknown browser/source 'chrome/places'."),
        ("tab=endpoint&category=persistence&source=runkeys", "", "Set the incident's operating system first"),
        ("tab=endpoint&category=persistence&source=runkeys", "plan9", "Set the incident's operating system first"),
        ("tab=endpoint&category=persistence&source=cron", "windows", "Unknown category/source 'persistence/cron'"),
    ],
)
def test_parameters_that_name_nothing_are_refused_before_anything_is_kept(admin, worker, query, system, sentence):
    make(admin, "b1", os=system)
    res = send(admin, "b1", query, b"whatever")
    assert res.status_code == 400 and res.json()["detail"].startswith(sentence), res.text
    assert sources_of("b1") == [] and worker["asked"] == []


# --------------------------------------------------------------------------- #
# The synchronous answer                                                      #
# --------------------------------------------------------------------------- #
def test_a_file_read_to_its_end_is_answered_with_the_report_and_changes_no_document(admin, worker, monkeypatch):
    make(admin, "s1", host="WKS")
    said = []
    monkeypatch.setattr(incident_routes, "emit", lambda db, tasks, event, payload: said.append((event, payload)))
    res = send(admin, "s1", "tab=eventlogs", b"ElfFile\x00 one", "Security.evtx")
    assert res.status_code == 200, res.text
    (source,) = sources_of("s1")
    assert res.json() == {
        "target": "eventlogs/evtx",
        "rows": 2,
        "format": "evtx",
        "sourceId": source.id,
        "read": "complete",
        "kept": 2,
        "duplicates": 0,
        "skipped": 0,
        "alreadyImported": False,
        "state": "done",
    }
    assert worker["asked"][0]["parser"] == "evtx" and worker["asked"][0]["source"] == "evtx"
    assert said == [("upload.completed", {"incidentId": "s1", **res.json()})]
    with SessionLocal() as db:
        assert len(db.scalars(select(EvidenceRecord).where(EvidenceRecord.source_id == source.id)).all()) == 2
    document = admin.get("/api/incidents/s1").json()
    assert document["data"] == {} and "eventlogs" not in document
    entry = admin.get("/api/audit?q=action:eventlog.upload").json()["entries"][0]
    assert entry["details"] == "Uploaded Security.evtx → eventlogs/evtx (2 rows)"


def test_a_file_that_lost_something_is_read_in_part(admin, worker):
    make(admin, "s2")
    worker["events"] = [SOURCE, record(1), SKIP, end(1, in_file=2)]
    res = send(admin, "s2", "tab=eventlogs", b"ElfFile\x00 two", "Security.evtx")
    assert res.status_code == 200, res.text
    assert (res.json()["read"], res.json()["kept"], res.json()["skipped"], res.json()["rows"]) == ("partial", 1, 1, 1)


def test_a_file_that_could_not_be_read_is_a_400_with_the_reason_and_stays_kept(admin, worker):
    make(admin, "s3")
    worker["events"] = [{**SKIP, "reason": "not an event log", "detail": "no ElfFile header"}]
    res = send(admin, "s3", "tab=eventlogs", b"MZ not a log", "x.evtx")
    assert res.status_code == 400 and res.json()["detail"] == "not an event log: no ElfFile header"
    (source,) = sources_of("s3")
    assert (source.state, source.read) == ("failed", "failed") and originals.has(source.sha256)


def test_without_a_worker_the_answer_is_503_and_the_file_is_kept(admin, monkeypatch):
    make(admin, "s4")
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    res = send(admin, "s4", "tab=commands&shell=bash", BASH)
    assert res.status_code == 503 and res.json()["detail"] == parse.NOT_CONFIGURED
    (source,) = sources_of("s4")
    assert source.state == "failed" and originals.has(source.sha256)


def test_a_file_sent_again_is_not_read_again(admin, worker):
    make(admin, "s5")
    first = send(admin, "s5", "tab=commands&shell=bash", BASH)
    second = send(admin, "s5", "tab=commands&shell=bash", BASH)
    assert first.json()["alreadyImported"] is False and second.json()["alreadyImported"] is True
    assert second.json()["sourceId"] == first.json()["sourceId"] and second.json()["rows"] == first.json()["rows"]
    assert len(worker["asked"]) == 1 and len(sources_of("s5")) == 1


def test_a_file_that_failed_is_read_again_when_it_is_sent_again(admin, worker, monkeypatch):
    make(admin, "s6")
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    assert send(admin, "s6", "tab=commands&shell=bash", BASH).status_code == 503
    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    res = send(admin, "s6", "tab=commands&shell=bash", BASH)
    assert res.status_code == 200 and res.json()["alreadyImported"] is False and len(sources_of("s6")) == 1


def test_a_reading_another_process_took_is_waited_for(admin, worker, monkeypatch):
    make(admin, "s7")
    monkeypatch.setattr(incident_routes, "POLL", 0.02)

    def taken(kind, ref, now=None):
        threading.Timer(0.2, lambda: parse.read(ref)).start()
        raise work.Taken("held elsewhere")

    monkeypatch.setattr(work, "hold", taken)
    res = send(admin, "s7", "tab=commands&shell=bash", BASH)
    assert res.status_code == 200 and res.json()["read"] == "complete", res.text


def test_a_file_over_the_limit_is_413_and_nothing_is_kept(admin, worker, monkeypatch):
    make(admin, "s8")
    monkeypatch.setattr(settings, "ARTIFACT_MAX_MB", 1)
    res = send(admin, "s8", "tab=commands&shell=bash", b"ls\n" * 400_000)
    assert res.status_code == 413 and "1 MB" in res.json()["detail"]
    assert sources_of("s8") == []


def test_a_store_without_room_is_507(admin, worker, monkeypatch):
    make(admin, "s9")

    def full(needed, what="the file"):
        raise originals.EvidenceError("The store has 1 MB free")

    monkeypatch.setattr(originals, "room", full)
    res = send(admin, "s9", "tab=commands&shell=bash", BASH)
    assert res.status_code == 507 and "1 MB free" in res.json()["detail"]
    assert sources_of("s9") == []


def test_a_retry_with_the_same_key_gets_the_first_answer(admin, worker):
    make(admin, "s10")
    first = send(admin, "s10", "tab=commands&shell=bash", BASH, **{"Idempotency-Key": "once"})
    second = send(admin, "s10", "tab=commands&shell=bash", b"different\n", **{"Idempotency-Key": "once"})
    assert first.status_code == second.status_code == 200 and first.json() == second.json()
    assert len(worker["asked"]) == 1 and len(sources_of("s10")) == 1


# --------------------------------------------------------------------------- #
# The job of async=true                                                       #
# --------------------------------------------------------------------------- #
def job_when(admin: TestClient, job_id: str, status: str) -> dict:
    for _ in range(200):
        job = admin.get(f"/api/jobs/{job_id}").json()
        if job["status"] == status:
            return job
        time.sleep(0.05)
    raise AssertionError(job)


def test_an_async_upload_is_a_job_that_follows_its_source(admin, worker, monkeypatch):
    make(admin, "j1")
    said = []
    monkeypatch.setattr(incident_routes, "emit_now", lambda db, event, payload: said.append((event, payload)))
    res = send(admin, "j1", "tab=commands&shell=zsh&async=true", b"a\nb\nc\n", ".zsh_history")
    assert res.status_code == 202 and res.json()["status"] == "queued"
    job_id = res.json()["jobId"]
    job = job_when(admin, job_id, "done")
    (source,) = sources_of("j1")
    assert job["kind"] == "upload" and job["error"] is None
    assert job["result"] == {
        "target": "commands/zsh",
        "rows": 2,
        "format": "evtx",
        "sourceId": source.id,
        "read": "complete",
        "kept": 2,
        "duplicates": 0,
        "skipped": 0,
        "alreadyImported": False,
        "state": "done",
    }
    for _ in range(100):  # the webhook is told once the reading has ended
        if said:
            break
        time.sleep(0.05)
    assert said and said[0][0] == "upload.completed" and said[0][1]["sourceId"] == source.id
    assert admin.get("/api/audit?q=action:command.upload").json()["entries"][0]["details"].startswith("Uploaded")


def test_an_async_upload_that_could_not_be_read_is_a_job_in_error(admin, worker):
    make(admin, "j2")
    worker["events"] = [{**SKIP, "reason": "not an event log", "detail": "no header"}]
    res = send(admin, "j2", "tab=eventlogs&async=true", b"MZ", "x.evtx")
    job = job_when(admin, res.json()["jobId"], "error")
    assert job["error"] == "not an event log: no header" and job["result"] is None


def test_a_job_says_queued_then_running_while_its_source_is_not_read(admin, worker):
    make(admin, "j3")
    with SessionLocal() as db:
        source = intake.take(db, db.get(Incident, "j3"), BASH, "h", "commands", {"shell": "bash"}, "tester")
        job = Job(
            id="job-3",
            kind="upload",
            status="queued",
            incident_id="j3",
            created_at="t",
            updated_at="t",
            result_json='{"sourceId": "%s", "alreadyImported": false}' % source.id,
        )
        db.add(job)
        db.commit()
        source_id = source.id
    assert admin.get("/api/jobs/job-3").json()["status"] == "queued"
    with SessionLocal() as db:
        db.get(EvidenceSource, source_id).state = "parsing"
        db.commit()
    assert admin.get("/api/jobs/job-3").json()["status"] == "running"


def test_a_job_of_an_older_version_that_was_not_finished_is_an_error_and_a_finished_one_is_left_as_it_was(admin):
    with SessionLocal() as db:
        db.add(Job(id="old-1", kind="upload", status="running", incident_id="x", created_at="t", updated_at="t"))
        db.add(
            Job(
                id="old-2",
                kind="upload",
                status="done",
                incident_id="x",
                created_at="t",
                updated_at="t",
                result_json='{"rows": 3, "target": "commands/bash"}',
            )
        )
        db.commit()
    interrupted = admin.get("/api/jobs/old-1").json()
    assert interrupted["status"] == "error"
    assert (
        interrupted["error"]
        == "Interrupted by a restart of the server before the file was parsed: upload the file again."
    )
    finished = admin.get("/api/jobs/old-2").json()
    assert finished["status"] == "done" and finished["result"] == {"rows": 3, "target": "commands/bash"}
