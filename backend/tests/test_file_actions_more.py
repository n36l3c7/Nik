"""More of the playbook nodes for files: a file from an address, an archive unpacked, a file analysed
as the e-mail or the capture it is, and the events the analyses on workers end with.

The files are harmless: texts, a message written in the tests, a capture built from a few entries,
a minimal PE with two instructions.
"""

# ruff: noqa: E501, F811 (graphs of test playbooks read better on one line; fixtures are imported)

from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient
from sqlalchemy import select

from app import artifact_jobs
from app.automation import egress, worker
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import ArtifactJob, AutomationEvent, NetworkCapture, Sample
from app.events import KNOWN_EVENTS
from app.malware.samples import read_sample
from app.workers import analyzer
from tests.stores import read_only, zip_of  # noqa: F401 - read_only is a fixture
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    T0,
    edge,
    go,
    incident,
    playbook,
    run_of,
    start,
    steps,
    test_actions,
)
from tests.test_capa import RESULT as CAPA_RESULT
from tests.test_code import WORKER_RESULT as CODE_RESULT
from tests.test_executables import minimal_pe
from tests.test_file_actions import (  # noqa: F401 - the workers are fixtures
    act,
    capa_worker,
    chain,
    code_worker,
    done,
    settle,
    upload,
)
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture
from tests.test_network import _pcap
from tests.test_network import workers as capture_workers  # noqa: F401 - a fixture

HOST = "files.example.org"
TOOL = b"#!/bin/sh\necho collected by the tool\n"
TOOL_SHA = hashlib.sha256(TOOL).hexdigest()


def reach(admin: TestClient, playbook_id: str, *hosts: str) -> None:
    put = admin.put(f"/api/automation/playbooks/{playbook_id}/egress", json={"mode": "listed", "hosts": list(hosts)})
    assert put.status_code == 200, put.text


def events(kind: str) -> list[AutomationEvent]:
    with SessionLocal() as db:
        return list(db.scalars(select(AutomationEvent).where(AutomationEvent.kind == kind)))


# --------------------------------------------------------------------------- #
# A file from an address                                                      #
# --------------------------------------------------------------------------- #
def test_a_playbook_downloads_a_file_from_a_host_it_may_reach_and_keeps_it_as_it_came(admin: TestClient, outside):
    incident(admin, "i1")
    outside.host(HOST)
    outside.answer(
        HOST,
        200,
        body=TOOL,
        headers={
            "content-type": "application/x-sh; charset=binary",
            "content-disposition": 'attachment; filename="tool.sh"',
        },
        path="/dl/tool",
    )
    pb = chain(admin, "Downloads", act("get", "nik.download-file", url=f"https://{HOST}/dl/tool?id=7"))

    # Not a host the playbook may reach: nothing is asked.
    refused = go(admin, pb, objectKind="incident", objectId="i1")
    assert steps(refused)["get"]["error"] == f"{HOST} is not among the hosts this playbook may reach"
    assert outside.requests == []
    reach(admin, pb, HOST)

    # A dry run asks nobody and keeps nothing.
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert dry["status"] == "done" and steps(dry)["get"]["request"]["would"] == "download the file"
    assert steps(dry)["get"]["request"]["host"] == HOST and steps(dry)["get"]["output"]["artifact"] == ""
    assert outside.requests == []

    run = go(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"]
    assert steps(run)["get"]["output"] == {
        "artifact": f"file-{TOOL_SHA}",
        "kind": "file",
        "name": "tool.sh",
        "type": "Script with a shebang line",
        "size": len(TOOL),
        "sha256": TOOL_SHA,
        "verdict": "",
        "score": None,
        "tags": [],
        "page": f"/artifact/file-{TOOL_SHA}",
        "linked": True,
        "status": 200,
        "content_type": "application/x-sh",
    }
    # One GET, with no credentials of any kind.
    (sent,) = outside.requests
    assert sent["method"] == "GET" and sent["path"] == "/dl/tool?id=7"
    assert not {name.lower() for name in sent["headers"]} & set(egress.CREDENTIAL_HEADERS)
    assert read_sample(TOOL_SHA) == TOOL
    refs = admin.get("/api/incidents/i1").json()["data"]["malware"]["samples"]
    assert [(ref["fileName"], ref["origin"]) for ref in refs] == [("tool.sh", f'{HOST} (playbook "Downloads")')]
    entry = admin.get("/api/audit?q=action:artifact.download").json()["entries"][0]
    assert entry["actor"] == "nik-automation" and entry["incidentId"] == "i1"
    assert entry["details"].startswith(f"Downloaded the file tool.sh ({TOOL_SHA[:12]}…) from {HOST} (playbook ")


def test_what_a_download_may_not_reach_or_keep_fails_the_step(admin: TestClient, outside, monkeypatch):
    outside.host(HOST)
    outside.host("elsewhere.example.net")
    outside.host("inside.example.org", "10.0.0.8")
    outside.answer(HOST, 302, headers={"location": "https://elsewhere.example.net/x"}, path="/moved")
    outside.answer(HOST, 404, body=b"no such file", path="/gone")
    outside.answer(HOST, 200, body=b"", path="/empty")
    outside.answer(HOST, 200, body=TOOL, path="/ok")

    def huge(method, to, target, _headers, _body):
        if to == HOST and target == "/huge":
            error = egress.EgressError("The answer is larger than 100 MB", sent=True)
            error.too_large = True
            raise error
        return None

    outside.answers.append(huge)
    for url, why in (
        # A redirect is followed only to a host the playbook may reach.
        (f"https://{HOST}/moved", "elsewhere.example.net is not among the hosts this playbook may reach"),
        (f"https://{HOST}/gone", "The other side answered 404: nothing was kept"),
        (f"https://{HOST}/empty", "The other side answered with an empty file: nothing was kept"),
        (
            f"https://{HOST}/huge",
            f"The file is larger than the {settings.SAMPLE_MAX_MB} MB limit of an upload: it was not kept",
        ),
        ("ftp://files.example.org/x", ""),
    ):
        pb = chain(admin, f"Fails {url}", act("get", "nik.download-file", url=url))
        reach(admin, pb, HOST)
        run = go(admin, pb)
        assert run["status"] == "failed" and steps(run)["get"]["error"].startswith(why), steps(run)["get"]["error"]
    # A name that resolves inside the network is reached only when an admin listed that very host:
    # a playbook that may reach any host does not reach it.
    from app.core.models import Playbook

    pb = chain(admin, "Inside", act("get", "nik.download-file", url="https://inside.example.org/x"))
    with SessionLocal() as db:
        db.get(Playbook, pb).egress_mode = "any"
        db.commit()
    run = go(admin, pb)
    assert steps(run)["get"]["error"] == (
        "inside.example.org is an address inside the network: it is reached only when the host is listed"
    )
    assert all(sent["host"] != "inside.example.org" for sent in outside.requests)
    # The data guard judges the address: one that carries an e-mail address is held.
    pb = chain(admin, "Held", act("get", "nik.download-file", url=f"https://{HOST}/ok?for=anna.rossi@contoso.example"))
    reach(admin, pb, HOST)
    run = go(admin, pb)
    assert steps(run)["get"]["error"].startswith("Held back: 1 × e-mail addresses")
    with SessionLocal() as db:
        assert db.scalars(select(Sample)).all() == []


def test_a_download_is_kept_through_the_api_process_when_the_worker_cannot_write(admin: TestClient, outside, read_only):
    outside.host(HOST)
    outside.answer(HOST, 200, body=TOOL, path="/ok")
    pb = chain(admin, "Downloads read-only", act("get", "nik.download-file", url=f"https://{HOST}/ok", name="named.sh"))
    reach(admin, pb, HOST)
    run_id = start(admin, pb)
    worker.drain(T0)
    waiting = run_of(admin, run_id)
    assert steps(waiting)["get"]["status"] == "waiting" and len(outside.requests) == 1
    with SessionLocal() as db:
        assert db.scalars(select(Sample)).all() == []
        (job,) = db.scalars(select(ArtifactJob)).all()
        assert job.kind == "store" and artifact_jobs.carried(db, job.id) == TOOL
    assert read_only() == 1
    worker.drain(T0 + 5)
    run = run_of(admin, run_id)
    assert run["status"] == "done", run["error"]
    # Downloaded once: the step only waited for the file to be kept.
    assert len(outside.requests) == 1
    assert steps(run)["get"]["output"]["name"] == "named.sh" and steps(run)["get"]["output"]["linked"] is False
    assert read_sample(TOOL_SHA) == TOOL
    assert admin.get("/api/audit?q=action:artifact.download").json()["entries"]


# --------------------------------------------------------------------------- #
# An archive Nik holds                                                        #
# --------------------------------------------------------------------------- #
INSIDE = {"logs/app.log": b"10:00 started\n", "notes.txt": b"what was seen\n", "empty.txt": b""}


def test_a_playbook_unpacks_an_archive_nik_holds_into_files_of_the_incident(admin: TestClient, read_only):
    secret = "Open-Sesame-2026"
    archive = zip_of(INSIDE, secret)
    with SessionLocal() as db:
        # The archive is in the store, as an analyst or a connector left it.
        from app.malware import samples
        from app.routers import samples as sample_routes

        real = sample_routes.write_sample
        sample_routes.write_sample = samples.write_sample
        try:
            sample_routes.keep_sample(db, None, archive, "collected.zip", "admin")
            db.commit()
        finally:
            sample_routes.write_sample = real
    held = "file-" + hashlib.sha256(archive).hexdigest()
    incident(admin, "i1")
    nodes = [act("unz", "nik.unpack-artifact", artifact=held, password=secret)]
    pb = chain(admin, "Unpacks", *nodes)

    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert dry["status"] == "done", dry["error"]
    assert [item["name"] for item in steps(dry)["unz"]["output"]["files"]] == ["logs/app.log", "notes.txt"]
    assert steps(dry)["unz"]["request"] == {
        "would": "unpack the archive",
        "artifact": held,
        "files": 2,
        "incident": "i1",
    }
    with SessionLocal() as db:
        assert len(db.scalars(select(Sample)).all()) == 1 and db.scalars(select(ArtifactJob)).all() == []

    run_id = start(admin, pb, objectKind="incident", objectId="i1")
    worker.drain(T0)
    # The worker unpacked in memory and handed the files over; the password went nowhere.
    with SessionLocal() as db:
        jobs = db.scalars(select(ArtifactJob).order_by(ArtifactJob.created_epoch)).all()
        assert [job.params["name"] for job in jobs] == ["app.log", "notes.txt"]
        assert all(job.params["parent"] == [held, "unpacked"] for job in jobs) and secret not in str(jobs[0].params)
    assert steps(run_of(admin, run_id))["unz"]["input"]["args"]["password"] == "•••"
    assert read_only() == 2
    worker.drain(T0 + 5)
    run = run_of(admin, run_id)
    assert run["status"] == "done", run["error"]
    output = steps(run)["unz"]["output"]
    assert output["count"] == 2 and output["artifact"] == held
    assert output["skipped"] == [{"name": "empty.txt", "reason": "It is empty"}]
    assert output["files"][0] == {
        "name": "logs/app.log",
        "type": "ASCII text",
        "size": 14,
        "sha256": hashlib.sha256(INSIDE["logs/app.log"]).hexdigest(),
        "artifact": "file-" + hashlib.sha256(INSIDE["logs/app.log"]).hexdigest(),
    }
    # The run shows a mark where the password was given.
    assert steps(run)["unz"]["input"]["args"]["password"] == "•••"
    shown = admin.get(f"/api/artifacts/{held}").json()
    assert sorted((child["name"], child["relation"]) for child in shown["children"]) == [
        ("app.log", "unpacked"),
        ("notes.txt", "unpacked"),
    ]
    names = {ref["fileName"] for ref in admin.get("/api/incidents/i1").json()["data"]["malware"]["samples"]}
    assert names == {"app.log", "notes.txt"}
    assert (
        admin.get("/api/audit?q=action:artifact.unpack")
        .json()["entries"][0]["details"]
        .startswith("Took 2 file(s) out of the archive collected.zip")
    )

    for args, why in (
        ({"artifact": held, "password": "wrong-one"}, "The password does not open the archive: nothing was unpacked"),
        ({"artifact": held}, "The archive is protected by a password and none was given: nothing was unpacked"),
        ({"artifact": output["files"][1]["artifact"]}, "The file is not a zip archive Nik can read"),
    ):
        failed = go(admin, chain(admin, f"Not {why[:30]}", act("unz", "nik.unpack-artifact", **args)))
        assert failed["status"] == "failed" and steps(failed)["unz"]["error"].startswith(why)
        # The archive is an artifact already and stays one: the step says which.
        assert steps(failed)["unz"]["error"].endswith(f"The archive stays as it is ({args['artifact']})")
        # Typed in the node it is in the playbook; what the run kept of its steps does not repeat it.
        assert "wrong-one" not in str(failed["steps"])


# --------------------------------------------------------------------------- #
# A file analysed as what it is                                               #
# --------------------------------------------------------------------------- #
def test_a_file_that_is_a_message_is_analysed_as_an_e_mail_from_its_page(admin: TestClient, no_dns):
    incident(admin, "i1")
    incident(admin, "i2")
    held = upload(admin, "reported.eml", phishing_message(), incident_id="i1")
    notes = upload(admin, "notes.txt", b"plain notes")
    assert admin.post(f"/api/artifacts/{held}/links", json={"incidentId": "i2"}).status_code == 201
    # The page offers it for a file that is one, read from its first bytes; a list goes by the name.
    assert admin.get(f"/api/artifacts/{held}").json()["analyseAs"] == ["mail"]
    assert admin.get(f"/api/artifacts/{notes}").json()["analyseAs"] == []
    listed = {row["id"]: row["analyseAs"] for row in admin.get("/api/artifacts").json()["artifacts"]}
    assert listed == {held: ["mail"], notes: []}

    made = admin.post(f"/api/artifacts/{held}/analyse-as", json={"as": "mail"})
    assert made.status_code == 201, made.text
    mail = made.json()
    sha256 = held.removeprefix("file-")
    # The e-mail an upload of the same file would have made, in the incidents the file is in, made from the file.
    assert (mail["id"], mail["kind"], mail["verdict"]) == (f"mail-{sha256}", "mail", "phishing")
    assert sorted(item["id"] for item in mail["incidents"]) == ["i1", "i2"]
    shown = admin.get(f"/api/artifacts/{mail['id']}").json()
    assert [(parent["id"], parent["relation"]) for parent in shown["parents"]] == [(held, "analysed")]
    assert admin.get(f"/api/artifacts/{held}").json()["kind"] == "file"  # the file stays what it was
    # Asked twice, nothing is made twice.
    assert admin.post(f"/api/artifacts/{held}/analyse-as", json={"as": "mail"}).json()["id"] == mail["id"]
    assert admin.get("/api/artifacts?kind=mail").json()["total"] == 1
    assert admin.get("/api/audit?q=action:artifact.analyse_as").json()["entries"][0]["details"] == (
        "Analysed the file reported.eml as an e-mail"
    )

    refused = admin.post(f"/api/artifacts/{notes}/analyse-as", json={"as": "mail"})
    assert refused.status_code == 422 and refused.json()["detail"].startswith("It is not an e-mail Nik can read")
    assert admin.post(f"/api/artifacts/{notes}/analyse-as", json={"as": "capture"}).json()["detail"] == (
        "Not a pcap or pcapng file."
    )
    assert admin.post(f"/api/artifacts/{mail['id']}/analyse-as", json={"as": "mail"}).json()["detail"] == (
        "Only a file is analysed as an e-mail or as a capture"
    )
    assert admin.post(f"/api/artifacts/{held}/analyse-as", json={"as": "mail", "incident": "nope"}).status_code == 404


def test_a_file_that_is_a_capture_is_analysed_as_one_under_the_limits_of_a_capture(
    admin: TestClient, capture_workers, monkeypatch
):
    calls, _browser = capture_workers
    incident(admin, "i1")
    held = upload(admin, "session.pcapng", _pcap(), incident_id="i1")
    assert admin.get(f"/api/artifacts/{held}").json()["analyseAs"] == ["capture"]

    with monkeypatch.context() as patch:
        patch.setattr(settings, "PCAP_MAX_MB", 0)
        too_large = admin.post(f"/api/artifacts/{held}/analyse-as", json={"as": "capture"})
    assert too_large.status_code == 413 and too_large.json()["detail"] == "The capture exceeds 0 MB."
    with SessionLocal() as db:
        assert db.scalars(select(NetworkCapture)).all() == []

    made = admin.post(f"/api/artifacts/{held}/analyse-as", json={"as": "capture"})
    assert made.status_code == 201, made.text
    capture = made.json()
    # A capture of its own, analysed by the worker, in the one incident the file is in.
    assert capture["kind"] == "pcap" and capture["name"] == "session.pcapng"
    assert [item["id"] for item in capture["incidents"]] == ["i1"]
    detail = admin.get(f"/api/captures/{capture['ref']}").json()
    assert detail["status"] == "ready" and detail["packets"] == 42
    assert sum(1 for call in calls if call[2] == "/analyze") == 1
    shown = admin.get(f"/api/artifacts/{held}").json()
    assert [(child["id"], child["relation"]) for child in shown["children"]] == [(capture["id"], "analysed")]
    # A file is made a capture once.
    assert admin.post(f"/api/artifacts/{held}/analyse-as", json={"as": "capture"}).json()["id"] == capture["id"]
    assert admin.get("/api/artifacts?kind=pcap").json()["total"] == 1


def test_a_playbook_analyses_a_file_as_an_e_mail_or_a_capture(admin: TestClient, no_dns, capture_workers):
    incident(admin, "i1")
    message = upload(admin, "reported.eml", phishing_message())
    packets = upload(admin, "session.pcapng", _pcap())
    nodes = [
        act("mail", "nik.analyse-artifact", artifact=message, **{"as": "mail"}),
        act("read", "nik.get-analysis", artifact="{{ mail.made }}"),
        act("capture", "nik.analyse-artifact", artifact=packets, **{"as": "capture"}),
        act("found", "nik.get-analysis", artifact="{{ capture.made }}"),
    ]
    pb = chain(admin, "Analyses as", *nodes)
    dry = go(admin, pb, objectKind="incident", objectId="i1", dryRun=True)
    assert steps(dry)["mail"]["request"] == {"would": "analyse the file as mail", "artifact": message, "incident": "i1"}
    assert steps(dry)["mail"]["output"]["made"] == ""

    run = done(admin, pb, objectKind="incident", objectId="i1")
    assert run["status"] == "done", run["error"] or steps(run)
    out = steps(run)
    mail = out["mail"]["output"]
    assert mail["made"] == "mail-" + message.removeprefix("file-") and mail["verdict"] == "phishing"
    assert mail["artifact"] == message and mail["started"] == ["mail"] and mail["finished"] is True
    assert mail["summary"] == f"Analysed as an e-mail: {mail['made']}" and mail["page"] == f"/artifact/{mail['made']}"
    assert out["read"]["output"]["mail"]["sender"] == "service@paypai.com"
    capture = out["capture"]["output"]
    assert capture["made"].startswith("pcap-") and capture["started"] == ["capture"] and capture["finished"] is True
    assert out["found"]["output"]["capture"]["packets"] == 42 and out["found"]["output"]["status"] == "done"
    # Both went to the incident the run works on.
    for made in (mail["made"], capture["made"]):
        assert [item["id"] for item in admin.get(f"/api/artifacts/{made}").json()["incidents"]] == ["i1"]
    entry = admin.get("/api/audit?q=action:artifact.analyse_as").json()["entries"][0]
    assert entry["actor"] == "nik-automation" and '(playbook "Analyses as", run ' in entry["details"]

    for args, why in (
        ({"artifact": packets, "as": "mail"}, "It is not an e-mail Nik can read"),
        ({"artifact": message, "as": "capture"}, "Not a pcap or pcapng file."),
        ({"artifact": mail["made"], "as": "mail"}, "Only a file is analysed as an e-mail or as a capture"),
        ({"artifact": message, "as": "mail", "analysis": "code"}, "Give as or analysis, not both"),
    ):
        failed = done(admin, chain(admin, f"Not {why[:25]} {len(args)}", act("bad", "nik.analyse-artifact", **args)))
        assert failed["status"] == "failed" and steps(failed)["bad"]["error"].startswith(why), steps(failed)["bad"][
            "error"
        ]


# --------------------------------------------------------------------------- #
# The events of the analyses made by workers                                  #
# --------------------------------------------------------------------------- #
def test_the_events_are_offered_to_triggers_and_to_webhooks(admin: TestClient):
    new = {"code.analysed", "capabilities.analysed", "capture.analysed"}
    assert new <= set(admin.get("/api/automation/catalog").json()["events"]) and new <= set(KNOWN_EVENTS)
    hook = admin.post("/api/webhooks", json={"url": "https://siem.example.org/nik", "events": sorted(new)})
    assert hook.status_code == 201, hook.text


def test_the_disassembly_and_capa_say_when_they_end_done_or_failed(
    admin: TestClient, code_worker, capa_worker, monkeypatch
):
    sample = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"))
    sha256 = sample.removeprefix("file-")
    # An upload starts both: each said once that it ended, by reference, with what a condition reads.
    (code,) = events("code.analysed")
    assert (code.object_kind, code.object_id, code.payload["caused_by_run"]) == ("artifact", sample, None)
    data = code.payload["data"]
    assert (
        data["file"]["sha256"] == sha256
        and data["file"]["name"] == "tool.exe"
        and data["file"]["artifact_id"] == sample
    )
    functions = CODE_RESULT["functions"]
    imports = sum(1 for item in functions if item.get("kind") == "import")
    assert data["code"] == {"status": "done", "error": "", "functions": len(functions) - imports, "imports": imports}
    (capa,) = events("capabilities.analysed")
    found = capa.payload["data"]["capabilities"]
    assert (found["status"], found["count"]) == ("done", len(CAPA_RESULT["capabilities"]))
    assert found["names"] == [item["name"] for item in CAPA_RESULT["capabilities"]] and "T1129" in found["attack"]
    # Nothing of the file is in either: no bytes, no pseudo-C.
    assert "void" not in str(code.payload) and "cfg" not in str(code.payload)

    # A failure is said too, with a status a condition can test.
    def down(sha256, signatures):
        raise analyzer.AnalyzerError("Cannot reach the worker: connection refused")

    monkeypatch.setattr(analyzer, "request_code_analysis", down)
    assert admin.post(f"/api/samples/{sha256}/code").status_code == 202
    failed = events("code.analysed")[-1].payload["data"]["code"]
    assert failed["status"] == "error" and failed["error"] == "Cannot reach the worker: connection refused"
    assert len(events("code.analysed")) == 2


def test_a_playbook_waits_for_the_disassembly_and_does_not_start_on_what_it_asked_for(admin: TestClient, code_worker):
    nodes = [
        act("tag", "nik.add-artifact-tags", artifact="{{ trigger.file }}", tags=["{{ trigger.code.status }}"]),
        act("again", "nik.analyse-artifact", artifact="{{ trigger.file.artifact_id }}", analysis="code"),
    ]
    trigger = {
        "event": "code.analysed",
        "manual": True,
        "conditions": {"all": [{"left": "{{ trigger.code.functions }}", "op": "gt", "right": 0}]},
    }
    pb = playbook(
        admin,
        "After the disassembly",
        nodes,
        [edge("start", "tag"), edge("tag", "again")],
        trigger=trigger,
        enabled=True,
    )
    sample = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"))
    for index in range(5):
        worker.drain(T0 + index * 5)
        artifact_jobs.run_due(threads=False)
    # One run, for the upload: the disassembly it asked for said so, and that started nothing.
    runs = admin.get(f"/api/automation/runs?playbook={pb}").json()["runs"]
    assert [(run["trigger"], run["status"]) for run in runs] == [("code.analysed", "done")]
    assert admin.get(f"/api/artifacts/{sample}").json()["tags"] == ["done"]
    assert code_worker.count(sample.removeprefix("file-")) == 2

    # By hand on a file: the same fields are there, as the file is now.
    run = go(admin, pb, T0 + 100, objectKind="artifact", objectId=sample, dryRun=True)
    assert run["status"] == "done", run["error"]
    assert steps(run)["tag"]["output"]["tags"] == ["done"]


def test_the_analysis_of_a_capture_says_when_it_ends_and_a_playbook_waits_for_it(
    admin: TestClient, capture_workers, monkeypatch
):
    from app.workers import previews

    nodes = [
        act(
            "note",
            "nik.add-note",
            text="{{ trigger.capture.name }}: {{ trigger.capture.packets }} packets, {{ trigger.capture.status }}",
        )
    ]
    trigger = {"event": "capture.analysed", "manual": True}
    pb = playbook(admin, "After a capture", nodes, [edge("start", "note")], trigger=trigger, enabled=True)
    incident(admin, "i1")
    capture = upload(admin, "phish.pcapng", _pcap(), "captures", "i1")
    (said,) = events("capture.analysed")
    data = said.payload["data"]
    assert (said.object_id, said.payload["caused_by_run"]) == (capture, None)
    assert data["capture"]["status"] == "ready" and data["capture"]["packets"] == 42
    assert data["capture"]["artifact_id"] == capture and data["capture"]["beacons"] == 1
    assert data["capture"]["name"] == "phish.pcapng" and data["incident"]["id"] == "i1"
    worker.drain(T0)
    (run,) = admin.get(f"/api/automation/runs?playbook={pb}").json()["runs"]
    assert (run["trigger"], run["status"], run["incidentId"]) == ("capture.analysed", "done", "i1")
    notes = admin.get("/api/incidents/i1").json()["notes"]
    assert notes[-1]["text"] == "phish.pcapng: 42 packets, ready"

    # By hand on a capture; and a failure of the worker is an event too.
    by_hand = go(admin, pb, T0 + 50, objectKind="artifact", objectId=capture, dryRun=True)
    assert by_hand["status"] == "done", by_hand["error"]

    def broken(base, header, token, method, path, body, timeout):
        raise previews.WorkerError("tshark could not read the file", 502)

    monkeypatch.setattr(previews, "_call", broken)
    assert admin.post(f"/api/captures/{capture.removeprefix('pcap-')}/reanalyse").status_code == 202
    failed = events("capture.analysed")[-1].payload["data"]["capture"]
    assert failed["status"] == "error" and failed["error"] == "tshark could not read the file"


def test_what_a_playbook_started_on_a_worker_says_which_run_asked(admin: TestClient, capture_workers, code_worker):
    capture = upload(admin, "phish.pcapng", _pcap(), "captures")
    sample = upload(admin, "tool.exe", minimal_pe(b"\x90\xc3"))
    nodes = [
        act("pcap", "nik.analyse-artifact", artifact=capture),
        act("code", "nik.analyse-artifact", artifact=sample, analysis="code"),
    ]
    run_id = start(admin, chain(admin, "Asks the workers", *nodes))
    seen: dict[str, list] = {"capture.analysed": [], "code.analysed": []}
    for index in range(6):
        worker.drain(T0 + index * 5)
        artifact_jobs.run_due(threads=False)
        for kind in seen:
            seen[kind] += [event.payload["caused_by_run"] for event in events(kind) if not event.done]
    assert run_of(admin, run_id)["status"] == "done"
    assert run_id in seen["capture.analysed"] and run_id in seen["code.analysed"]
