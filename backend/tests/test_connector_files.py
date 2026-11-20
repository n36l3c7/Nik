"""A connector's command that keeps a file, and one that sends a file Nik holds.

The other side is the fake outside of the tests: names that resolve and what
answers there. What is checked here is what happens on Nik's side: the file
that comes back is an artifact of the incident the run works on, stored as it
came; the file that leaves was judged by the data guard as an attachment is,
and never leaves when the guard holds it or the store does not have it.
"""

# ruff: noqa: F811 (fixtures are imported)

from __future__ import annotations

import hashlib
import textwrap
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.automation import actions
from app.automation import connector_actions as ca
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import AuditEntry, CommandAnswer, Connection, Playbook
from app.core.security import now_iso
from tests.stores import read_only  # noqa: F401 - a fixture
from tests.test_automation_engine import edge, go, incident, node, playbook, steps

VAULT = textwrap.dedent(
    """\
    name: Vault Intel
    id: vault
    version: 1
    description: Samples kept by Vault Intel.
    configuration:
      - { name: url, type: url, required: true }
      - { name: credentials, type: header, header: x-apikey }
    base_url: "{{ config.url }}"
    more_hosts: [cdn.vault.example]
    commands:
      - name: download
        description: Download a sample.
        arguments: [{ name: hash, type: text, required: true }]
        request: { method: GET, path: "/files/{{ args.hash }}/download", answer: file }
        error: { message: "{{ response.error }}" }
      - name: report
        description: What is known of a hash.
        arguments: [{ name: hash, type: text, required: true }]
        request: { method: GET, path: "/files/{{ args.hash }}" }
        outputs: { verdict: "{{ if(response.stats.malicious >= 3, 'malicious', 'unknown') }}" }
      - name: submit
        description: Submit a sample.
        changes_outside: true
        idempotent: false
        arguments:
          - { name: sample, type: file, required: true }
          - { name: comment, type: text }
        request:
          method: POST
          path: /files
          multipart: { comment: "{{ args.comment }}" }
          files:
            file: { artifact: "{{ args.sample }}" }
        outputs: { id: "{{ response.data.id }}" }
        sample: { id: analysis-0 }
    """
)
HOST = "api.vault.example"
NOW = time.time()  # the jobs a step asks for are taken by the real clock
MALWARE = b"MZ\x90\x00\x03\x00\xff\xfe this is not text \x00\x01\x02 and it stays as it is"
SHA = hashlib.sha256(MALWARE).hexdigest()


@pytest.fixture()
def vault(admin: TestClient, outside):
    """The connector installed, an instance of it, and a playbook that was opened no class of data."""
    outside.host(HOST, "93.184.215.30")
    with SessionLocal() as db:
        ca.install(db, VAULT, "admin")
        connection = Connection(
            id="v" * 32,
            name="Vault",
            connector_id="vault",
            config={"url": f"https://{HOST}/api"},
            key_policy={"cacheHours": 24},  # answers are kept for a day: a file never is
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        ca.store_secrets(connection, {"value": "vault-key-123456"})
        db.add(connection)
        db.commit()
    return SimpleNamespace(admin=admin, outside=outside, playbook=playbook(admin, "Vault desk", [], []))


def step(vault, name: str, opened=(), incident_id: str | None = None, **more) -> actions.Result:
    """A command run as a step of a run of the playbook, which was opened these classes of data."""
    args = more.pop("args")
    with SessionLocal() as db:
        row = db.get(Playbook, vault.playbook)
        row.data_allow = list(opened)
        db.commit()
        call = actions.Call(
            db=db,
            args=args,
            classes=frozenset(),
            arg_classes={},
            dry_run=more.pop("dry_run", False),
            run=SimpleNamespace(id="run-1", incident_id=incident_id, trigger={"playbook": "Vault desk"}),
            playbook=row,
            connection="Vault",
            **more,
        )
        result = ca.run_command("vault", name, call)
        db.commit()
        return result


def audited(action: str) -> list[str]:
    with SessionLocal() as db:
        return [row.details for row in db.scalars(select(AuditEntry).where(AuditEntry.action == action))]


def held(vault) -> bytes:
    """A sample in the store, as an analyst uploaded it."""
    from app.routers import samples as sample_routes

    with SessionLocal() as db:
        sample_routes.keep_sample(db, None, MALWARE, "invoice.exe", "admin")
        db.commit()
    return MALWARE


# --------------------------------------------------------------------------- #
# A file that comes back                                                      #
# --------------------------------------------------------------------------- #
def test_a_downloaded_file_is_an_artifact_of_the_incident_stored_as_it_came(vault):
    admin, outside = vault.admin, vault.outside
    incident(admin, "inc-file")
    outside.answer(
        HOST,
        200,
        body=MALWARE,
        headers={"content-type": "application/x-dosexec", "content-disposition": 'attachment; filename="invoice.exe"'},
        path="/api/files/abc/download",
    )
    result = step(vault, "download", incident_id="inc-file", args={"hash": "abc"})
    # The outputs describe the file; its bytes are nowhere in them.
    assert result.output == {
        "name": "invoice.exe",
        "type": "application/x-dosexec",
        "size": len(MALWARE),
        "sha256": SHA,
        "artifact": f"file-{SHA}",
        "linked": True,
    }
    assert result.classes == {"name": ["attachment_name"], "sha256": ["hash"], "artifact": ["nik_id"]}
    assert result.request["status"] == 200 and result.request["connection"] == "Vault"
    # It is in the store byte for byte, analysed as an uploaded file is, and the incident references it.
    from app.malware.samples import read_sample

    assert read_sample(SHA) == MALWARE
    known = admin.get(f"/api/samples/{SHA}").json()
    assert known["size"] == len(MALWARE) and [item["id"] for item in known["incidents"]] == ["inc-file"]
    assert admin.get(f"/api/artifacts/file-{SHA}").json()["name"] == "invoice.exe"
    assert any("Vault Intel (download)" in line and "run-1" in line for line in audited("connector.file.keep"))
    # The answer of a file command is never a kept answer: asked again, it is fetched again.
    step(vault, "download", incident_id="inc-file", args={"hash": "abc"})
    assert len(outside.requests) == 2
    with SessionLocal() as db:
        assert db.scalars(select(CommandAnswer)).all() == []
    # A command that reads is still kept, and its verdict is an expression that decides.
    outside.answer(HOST, 200, {"stats": {"malicious": 5}}, path="/api/files/abc")
    assert step(vault, "report", args={"hash": "abc"}).output == {"verdict": "malicious"}
    assert step(vault, "report", args={"hash": "abc"}).request["kept"] is True

    # With no incident the file is kept on its own.
    other = b"PK\x03\x04 an archive the vendor protects with a password: stored as it comes"
    outside.answer(HOST, 200, body=other, path="/api/files/zip/download")
    alone = step(vault, "download", args={"hash": "zip"})
    assert (alone.output["linked"], alone.output["name"]) == (False, "download")
    assert read_sample(hashlib.sha256(other).hexdigest()) == other


def test_a_download_follows_a_redirect_only_to_a_host_the_connector_lists(vault):
    outside = vault.outside
    outside.host("cdn.vault.example", "93.184.215.31")
    outside.host("elsewhere.example", "93.184.215.32")
    outside.answer(
        HOST, 302, headers={"location": "https://cdn.vault.example/blob/1?sig=x"}, path="/api/files/abc/download"
    )
    outside.answer("cdn.vault.example", 200, body=MALWARE, path="/blob/1")
    result = step(vault, "download", args={"hash": "abc"})
    assert result.output["sha256"] == SHA and result.request["host"] == "cdn.vault.example"
    first, second = outside.requests
    # The key of the instance went to the instance, and did not follow to the other host.
    assert first["headers"]["x-apikey"] == "vault-key-123456" and "x-apikey" not in second["headers"]
    # A host the connector does not list is not followed to, whatever the answer says.
    outside.answer(HOST, 302, headers={"location": "https://elsewhere.example/blob/2"}, path="/api/files/def/download")
    outside.answer("elsewhere.example", 200, body=b"other bytes", path="/blob/2")
    with pytest.raises(actions.ActionError) as caught:
        step(vault, "download", args={"hash": "def"})
    assert "elsewhere.example is not among the hosts this playbook may reach" in str(caught.value)
    assert [sent["host"] for sent in outside.requests[2:]] == [HOST]
    assert vault.admin.get(f"/api/samples/{hashlib.sha256(b'other bytes').hexdigest()}").status_code == 404


def test_a_file_too_large_or_refused_is_not_kept_and_a_dry_run_fetches_nothing(vault, monkeypatch):
    admin, outside = vault.admin, vault.outside
    # A dry run asks for nothing and stores nothing: the outputs are what a file would be described as.
    dry = step(vault, "download", dry_run=True, args={"hash": "abc"})
    assert outside.requests == [] and admin.get(f"/api/samples/{SHA}").status_code == 404
    assert dry.output == {"name": "", "type": "", "size": 0, "sha256": "", "artifact": "", "linked": False}
    assert (dry.request["path"], dry.request["keeps"], dry.request["dry_run"]) == (
        "/api/files/abc/download",
        "a file, as an artifact",
        True,
    )
    # The other side refuses: the error quotes its answer, and nothing is stored.
    outside.answer(HOST, 404, {"error": "no such sample"}, path="/api/files/abc/download")
    with pytest.raises(actions.ActionError) as caught:
        step(vault, "download", args={"hash": "abc"})
    assert str(caught.value) == "Vault Intel answered 404: no such sample"
    # Larger than an upload may be: refused with the limit, not kept.
    outside.answer(HOST, 200, body=MALWARE, path="/api/files/abc/download")
    monkeypatch.setattr(settings, "SAMPLE_MAX_MB", 0)
    with pytest.raises(actions.ActionError) as caught:
        step(vault, "download", args={"hash": "abc"})
    assert str(caught.value) == "The file is larger than the 0 MB limit of a sample: it was not kept"
    assert admin.get(f"/api/samples/{SHA}").status_code == 404 and audited("connector.file.keep") == []


def test_a_playbook_downloads_a_file_into_the_incident_it_runs_on(vault):
    admin, outside = vault.admin, vault.outside
    incident(admin, "inc-run")
    outside.answer(HOST, 200, body=MALWARE, path="/api/files/abc/download")
    get = node("get", "action", action="vault.download", connection="Vault", args={"hash": "abc"})
    pb = playbook(admin, "Fetches a sample", [get], [edge("start", "get")])
    run = go(admin, pb, objectKind="incident", objectId="inc-run")
    assert run["status"] == "done", run
    assert steps(run)["get"]["output"]["artifact"] == f"file-{SHA}" and steps(run)["get"]["output"]["linked"] is True
    assert steps(run)["get"]["output"]["name"] == "download" and steps(run)["get"]["request"]["status"] == 200
    assert [item["id"] for item in admin.get(f"/api/samples/{SHA}").json()["incidents"]] == ["inc-run"]
    # The library says what the command takes and gives; an argument that is a file is one of its types.
    entries = {entry["id"]: entry for entry in admin.get("/api/automation/catalog").json()["nodes"]}
    assert [argument["type"] for argument in entries["vault.submit"]["arguments"]] == ["file", "text"]
    assert entries["vault.submit"]["changesOutside"] is True and entries["vault.download"]["changesOutside"] is False
    # A command that keeps a file and names no outputs gives what describes the file: "Pick a value" offers that.
    assert [output["name"] for output in entries["vault.download"]["outputs"]] == [
        "name",
        "type",
        "size",
        "sha256",
        "artifact",
        "linked",
    ]


# --------------------------------------------------------------------------- #
# A file that is sent                                                         #
# --------------------------------------------------------------------------- #
def test_a_file_leaves_only_when_the_guard_lets_an_attachment_and_a_sample_leave(vault):
    outside = vault.outside
    held(vault)
    outside.answer(HOST, 200, {"data": {"id": "a-1"}}, path="/api/files")
    submit = {"sample": f"file-{SHA}", "comment": "from the desk"}
    # A playbook that sends no class of data: the file stays, and the step says what was held.
    with pytest.raises(actions.ActionError) as caught:
        step(vault, "submit", args=submit)
    assert str(caught.value).startswith("Held back:")
    judged = caught.value.request["held"]
    assert judged["held"] == ["attachment", "attachment_name", "sample"]
    assert judged["files"] == {"count": 1, "bytes": len(MALWARE)} and judged["counts"]["sample"] == 1
    assert outside.requests == []
    # The names of files alone are not enough: the file itself is an attachment, and a sample.
    with pytest.raises(actions.ActionError):
        step(vault, "submit", opened=["attachment_name", "attachment"], args=submit)
    assert outside.requests == []
    # A node told to send without what is held sends nothing at all: the command is nothing without its file.
    without = step(vault, "submit", held="drop", args=submit)
    assert without.output == {"id": None} and outside.requests == []
    assert "the command was not sent without it" in without.request["notSent"]
    assert without.request["held"]["dropped"] is True and without.request["held"]["held"] == judged["held"]

    # Opened for attachments, their names and samples: it goes, as a part of the form, byte for byte.
    opened = ["attachment", "attachment_name", "sample"]
    sent = step(vault, "submit", opened=opened, args=submit)
    assert sent.output == {"id": "a-1"}
    (request,) = outside.requests
    assert request["method"] == "POST" and request["headers"]["Content-Type"].startswith(
        "multipart/form-data; boundary="
    )
    assert request["headers"]["x-apikey"] == "vault-key-123456"
    head = b'name="file"; filename="invoice.exe"\r\nContent-Type: application/octet-stream\r\n\r\n'
    assert head + MALWARE + b"\r\n" in request["body"] and b'name="comment"\r\n\r\nfrom the desk' in request["body"]
    # The step shows what was judged and what went: the file by its name, size and hash.
    assert sent.request["files"] == [{"name": "invoice.exe", "size": len(MALWARE), "sha256": SHA}]
    assert sent.request["held"]["held"] == [] and sent.request["held"]["files"]["count"] == 1
    assert any("Vault Intel (submit)" in line and SHA[:12] in line for line in audited("connector.file.send"))

    # A dry run sends nothing: it shows the file in place of its bytes, and gives the sample of the command.
    dry = step(vault, "submit", opened=opened, dry_run=True, args=submit)
    assert len(outside.requests) == 1 and dry.output == {"id": "analysis-0"}
    assert dry.request["files"] == [
        {
            "field": "file",
            "name": "invoice.exe",
            "type": "application/octet-stream",
            "size": len(MALWARE),
            "sha256": SHA,
        }
    ]
    # A dry run of a playbook that was not opened the classes says so, as the real run would.
    with pytest.raises(actions.ActionError, match="Held back"):
        step(vault, "submit", dry_run=True, args=submit)


def test_a_file_that_is_not_in_the_store_or_over_the_limit_never_leaves(vault, monkeypatch):
    outside = vault.outside
    everything = ["attachment", "attachment_name", "sample"]
    outside.answer(HOST, 200, {"data": {"id": "a-1"}}, path="/api/files")
    for wrong, said in (
        ("f" * 64, "is not in the store"),
        ("file-" + "f" * 64, "is not in the store"),
        ("mail-" + "f" * 64, "its artifact (file-…) or its SHA-256"),
        ("../../etc/passwd", "its artifact (file-…) or its SHA-256"),
    ):
        with pytest.raises(actions.ActionError) as caught:
            step(vault, "submit", opened=everything, args={"sample": wrong})
        assert said in str(caught.value), wrong
    # The argument left empty on a node that fails on what is missing: the step fails, and says so.
    with pytest.raises(actions.ActionError, match="was not given"):
        step(vault, "submit", opened=everything, args={})
    # Over the limit of an upload, whatever was opened.
    held(vault)
    monkeypatch.setattr(settings, "SAMPLE_MAX_MB", 0)
    with pytest.raises(actions.ActionError, match="larger than the 0 MB limit of a sample: it is not sent"):
        step(vault, "submit", opened=everything, args={"sample": SHA})
    assert outside.requests == []


# --------------------------------------------------------------------------- #
# A store the worker cannot write to                                          #
# --------------------------------------------------------------------------- #
def test_a_file_is_kept_through_the_api_process_when_the_worker_cannot_write_to_the_store(vault, read_only):
    from app import artifact_jobs
    from app.core.models import Sample

    admin, outside = vault.admin, vault.outside
    incident(admin, "inc-ro")
    outside.answer(
        HOST,
        200,
        body=MALWARE,
        headers={"content-type": "application/x-dosexec", "content-disposition": 'attachment; filename="invoice.exe"'},
        path="/api/files/abc/download",
    )
    # The worker downloads, cannot write, and hands the bytes over: the step gives itself back.
    first = step(vault, "download", incident_id="inc-ro", args={"hash": "abc"}, now=NOW)
    assert first.output is None and first.again_at == NOW + artifact_jobs.WAIT_EVERY
    assert first.log == "Waiting for the server to keep the file"
    with SessionLocal() as db:
        assert db.scalars(select(Sample)).all() == []
        (job,) = db.scalars(select(artifact_jobs.ArtifactJob)).all()
        assert (job.kind, job.status, job.run_id) == ("store", "queued", "run-1")
        assert artifact_jobs.carried(db, job.id) == MALWARE
    assert audited("connector.file.keep") == []
    # Looked at again before the API process took it: it still waits, and nothing was downloaded twice.
    again = step(vault, "download", incident_id="inc-ro", args={"hash": "abc"}, now=NOW + 2, state=first.state)
    assert again.again_at == NOW + 4 and len(outside.requests) == 1

    assert read_only() == 1
    done = step(vault, "download", incident_id="inc-ro", args={"hash": "abc"}, now=NOW + 4, state=again.state)
    assert done.output == {
        "name": "invoice.exe",
        "type": "application/x-dosexec",
        "size": len(MALWARE),
        "sha256": SHA,
        "artifact": f"file-{SHA}",
        "linked": True,
    }
    assert done.classes == {"name": ["attachment_name"], "sha256": ["hash"], "artifact": ["nik_id"]}
    assert done.request["status"] == 200 and len(outside.requests) == 1
    from app.malware.samples import read_sample

    assert read_sample(SHA) == MALWARE
    refs = admin.get("/api/incidents/inc-ro").json()["data"]["malware"]["samples"]
    assert [(ref["sha256"], ref["origin"]) for ref in refs] == [(SHA, "Vault Intel (download)")]
    assert audited("connector.file.keep") == [
        f'Kept the file invoice.exe ({SHA[:12]}…) that Vault Intel (download) gave (playbook "Vault desk", run run-1)'
    ]
    with SessionLocal() as db:
        assert db.scalars(select(artifact_jobs.ArtifactJobPart)).all() == []
        # A file is never among the kept answers, handed over or not.
        assert db.scalars(select(CommandAnswer)).all() == []

    # A file the API process does not keep in time fails the step, and says where to look.
    outside.answer(HOST, 200, body=b"another file", path="/api/files/def/download")
    waiting = step(vault, "download", args={"hash": "def"}, now=NOW + 100)
    with pytest.raises(actions.ActionError) as late:
        step(vault, "download", args={"hash": "def"}, now=NOW + 100 + artifact_jobs.WAIT_FOR + 1, state=waiting.state)
    assert late.value.message.startswith("The file was not kept in 10 minutes: see whether the server answers")


def test_a_large_file_crosses_the_database_in_parts(vault, read_only, monkeypatch):
    from app import artifact_jobs

    monkeypatch.setattr(artifact_jobs, "PART_BYTES", 16)
    large = bytes(range(256)) * 3
    vault.outside.answer(HOST, 200, body=large, path="/api/files/big/download")
    waiting = step(vault, "download", args={"hash": "big"}, now=NOW)
    with SessionLocal() as db:
        parts = db.scalars(select(artifact_jobs.ArtifactJobPart).order_by(artifact_jobs.ArtifactJobPart.seq)).all()
        assert len(parts) == 48 and all(len(part.data) == 16 for part in parts)
    assert read_only() == 1
    done = step(vault, "download", args={"hash": "big"}, now=NOW + 2, state=waiting.state)
    from app.malware.samples import read_sample

    assert done.output["sha256"] == hashlib.sha256(large).hexdigest() and read_sample(done.output["sha256"]) == large


# --------------------------------------------------------------------------- #
# An archive to unpack                                                        #
# --------------------------------------------------------------------------- #
COLLECTOR = textwrap.dedent(
    """\
    name: Fetch Desk
    id: fetchdesk
    version: 1
    description: Files an agent collected, handed over as an archive.
    configuration:
      - { name: url, type: url, required: true }
      - { name: credentials, type: header, header: x-apikey }
    base_url: "{{ config.url }}"
    commands:
      - name: fetched-files
        description: Download the files an agent collected, in an archive protected by a password.
        arguments:
          - { name: id, type: text, required: true }
          - { name: password, type: text }
        request:
          method: GET
          path: "/fetched/{{ args.id }}"
          answer: file
          save_as: { name: "fetched-{{ args.id }}.zip" }
          unpack: { format: zip, password: "{{ args.password }}" }
    """
)
DESK = "desk.example"
COLLECTED = {"C/Users/anna/notes.txt": b"what anna wrote\n", "C/Windows/Temp/run.log": b"10:00 started\n10:01 done\n"}
SECRET = "Fetch-2026-secret"


@pytest.fixture()
def collector(vault):
    from tests.stores import zip_of

    vault.outside.host(DESK, "93.184.215.31")
    with SessionLocal() as db:
        ca.install(db, COLLECTOR, "admin")
        connection = Connection(
            id="f" * 32,
            name="Desk",
            connector_id="fetchdesk",
            config={"url": f"https://{DESK}/api"},
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        ca.store_secrets(connection, {"value": "desk-key-123456"})
        db.add(connection)
        db.commit()
    archive = zip_of(COLLECTED, SECRET)
    vault.outside.answer(DESK, 200, body=archive, headers={"content-type": "application/zip"}, path="/api/fetched/7")
    return SimpleNamespace(**vars(vault), archive=archive, sha=hashlib.sha256(archive).hexdigest())


def fetched(collector, password=SECRET, **more) -> actions.Result:
    """The command run as a step, on the instance of the collector."""
    args = {"id": "7", **({"password": password} if password is not None else {})}
    with SessionLocal() as db:
        call = actions.Call(
            db=db,
            args=args,
            classes=frozenset(),
            arg_classes={},
            dry_run=more.pop("dry_run", False),
            run=SimpleNamespace(
                id="run-1", incident_id=more.pop("incident_id", None), trigger={"playbook": "Vault desk"}
            ),
            playbook=db.get(Playbook, collector.playbook),
            connection="Desk",
            **more,
        )
        result = ca.run_command("fetchdesk", "fetched-files", call)
        db.commit()
        return result


def expected_files() -> list[dict]:
    return [
        {
            "name": name,
            "type": "ASCII text",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "artifact": f"file-{hashlib.sha256(data).hexdigest()}",
        }
        for name, data in COLLECTED.items()
    ]


def test_an_archive_is_kept_as_it_came_and_each_file_inside_it_is_an_artifact_of_its_own(collector):
    admin = collector.admin
    incident(admin, "inc-zip")
    result = fetched(collector, incident_id="inc-zip")
    out = result.output
    assert (out["name"], out["type"], out["artifact"]) == ("fetched-7.zip", "application/zip", f"file-{collector.sha}")
    assert out["files"] == expected_files() and out["count"] == 2 and out["skipped"] == []
    assert result.classes["files.name"] == ["attachment_name"] and result.classes["files.artifact"] == ["nik_id"]
    # The archive is in the store byte for byte, still protected; the files inside it are files of the incident.
    from app.malware.samples import read_sample

    assert read_sample(collector.sha) == collector.archive
    for item, data in zip(out["files"], COLLECTED.values(), strict=True):
        assert read_sample(item["sha256"]) == data
    refs = admin.get("/api/incidents/inc-zip").json()["data"]["malware"]["samples"]
    assert [ref["fileName"] for ref in refs] == ["fetched-7.zip", "notes.txt", "run.log"]
    assert refs[1]["origin"] == "fetched-7.zip (Fetch Desk (fetched-files))"
    # Each is shown as taken out of the archive, and the archive shows them.
    shown = admin.get(f"/api/artifacts/file-{collector.sha}").json()
    assert sorted((child["name"], child["relation"]) for child in shown["children"]) == [
        ("notes.txt", "unpacked"),
        ("run.log", "unpacked"),
    ]
    assert audited("connector.file.keep") == [
        f"Kept the file fetched-7.zip ({collector.sha[:12]}…) and the 2 file(s) inside it that Fetch Desk "
        '(fetched-files) gave (playbook "Vault desk", run run-1)'
    ]
    # The password is nowhere in what the step gave or recorded.
    assert SECRET not in str(result.output) and SECRET not in str(result.request)


def test_an_archive_that_does_not_open_fails_the_step_and_nothing_is_kept(collector):
    from app.core.models import Sample

    for password, said in (
        ("guessed-wrong", "The password does not open the archive: nothing was unpacked"),
        (None, "The archive is protected by a password and none was given: nothing was unpacked"),
    ):
        with pytest.raises(actions.ActionError) as failed:
            fetched(collector, password)
        assert failed.value.message == said and failed.value.retry is False
        assert "guessed-wrong" not in failed.value.message and "guessed-wrong" not in str(failed.value.request)
    collector.outside.answer(DESK, 200, body=b"<html>not an archive</html>", path="/api/fetched/7")
    with pytest.raises(actions.ActionError) as failed:
        fetched(collector)
    assert failed.value.message == "The file is not a zip archive Nik can read: nothing was unpacked"
    with SessionLocal() as db:
        db.rollback()
        assert db.scalars(select(Sample)).all() == []


def test_the_password_of_an_archive_is_not_shown_in_a_run_and_a_dry_run_unpacks_nothing(collector):
    from app.core.models import Sample

    with SessionLocal() as db:
        spec = actions.lookup(db, "fetchdesk.fetched-files")
    by_name = {argument["name"]: argument for argument in spec.arguments}
    # The argument the password is read from is marked, and a run keeps a mark in its place.
    assert by_name["password"]["secret"] is True and "secret" not in by_name["id"]
    assert actions.shown_arguments(spec, {"id": "7", "password": SECRET}) == {"id": "7", "password": "•••"}
    assert actions.shown_arguments(spec, {"id": "7", "password": None}) == {"id": "7", "password": None}
    # With no outputs of its own the command says what it gives: the file, and the files inside it.
    outputs = [output["name"] for output in spec.outputs]
    assert outputs == ["name", "type", "size", "sha256", "artifact", "linked", "files", "count", "skipped"]
    assert [item["name"] for item in spec.outputs[6]["shape"]] == [
        "[0].name",
        "[0].type",
        "[0].size",
        "[0].sha256",
        "[0].artifact",
    ]

    dry = fetched(collector, dry_run=True)
    assert dry.output == {
        "name": "",
        "type": "",
        "size": 0,
        "sha256": "",
        "artifact": "",
        "linked": False,
        "files": [],
        "count": 0,
        "skipped": [],
    }
    assert dry.request["keeps"] == "a file, as an artifact"
    assert dry.request["unpacks"] == "the archive: each file inside it, as an artifact"
    assert SECRET not in str(dry.request) and collector.outside.requests == []
    with SessionLocal() as db:
        assert db.scalars(select(Sample)).all() == []


def test_an_archive_is_unpacked_by_the_worker_in_memory_and_kept_by_the_api_process(collector, read_only):
    from app import artifact_jobs

    admin = collector.admin
    incident(admin, "inc-zip")
    waiting = fetched(collector, incident_id="inc-zip", now=NOW)
    assert waiting.again_at is not None
    with SessionLocal() as db:
        jobs = db.scalars(select(artifact_jobs.ArtifactJob).order_by(artifact_jobs.ArtifactJob.created_epoch)).all()
        # The archive first, then what was inside it: no password travels, the files do.
        assert [job.params["name"] for job in jobs] == ["fetched-7.zip", "notes.txt", "run.log"]
        assert jobs[1].params["parent"] == [f"file-{collector.sha}", "unpacked"]
        assert SECRET not in str([job.params for job in jobs]) and SECRET not in str(waiting.state)
    assert read_only() == 3
    done = fetched(collector, incident_id="inc-zip", now=NOW + 2, state=waiting.state)
    assert done.output["files"] == expected_files() and done.output["linked"] is True
    shown = admin.get(f"/api/artifacts/file-{collector.sha}").json()
    assert sorted(child["name"] for child in shown["children"]) == ["notes.txt", "run.log"]
    assert [item["id"] for item in shown["incidents"]] == ["inc-zip"]
    assert len(audited("connector.file.keep")) == 1


def test_a_connector_says_unpack_only_of_an_answer_that_is_a_file():
    kept = [line for line in COLLECTOR.splitlines() if "answer: file" not in line and "save_as" not in line]
    bad = "\n".join(kept)
    with pytest.raises(ca.ConnectorError) as refused:
        ca.load(bad)
    assert any(
        '"unpack" belongs to a request whose answer is a file' in problem.message for problem in refused.value.problems
    )
    with pytest.raises(ca.ConnectorError):
        ca.load(COLLECTOR.replace("format: zip", "format: rar"))


def test_the_password_of_an_archive_may_be_a_stored_credential_of_the_instance(collector):
    """A secret of the instance that names a stored credential is read when the archive is opened,
    and is redacted as every secret of the instance is."""
    admin = collector.admin
    made = admin.post("/api/automation/credentials", json={"name": "fetch_archives", "kind": "secret", "value": SECRET})
    assert made.status_code == 201, made.text
    stored = COLLECTOR.replace(
        "  - { name: credentials, type: header, header: x-apikey }\n",
        "  - { name: credentials, type: header, header: x-apikey }\n  - { name: archive_password, type: secret }\n",
    ).replace('password: "{{ args.password }}"', 'password: "{{ secret.archive_password }}"')
    stored = stored.replace("id: fetchdesk", "id: fetchvault").replace("name: Fetch Desk", "name: Fetch Vault")
    stored = stored.replace("      - { name: password, type: text }\n", "")
    stored += '    outputs: { count: "{{ response.count }}", names: "{{ response.files | pluck(\'name\') }}" }\n'
    assert "secret.archive_password" in stored and "args.password" not in stored
    with SessionLocal() as db:
        ca.install(db, stored, "admin")
        connection = Connection(
            id="e" * 32,
            name="Vault of files",
            connector_id="fetchvault",
            config={"url": f"https://{DESK}/api"},
            created_at=now_iso(),
            updated_at=now_iso(),
        )
        # The instance holds the name of the credential, not its value.
        ca.store_secrets(
            connection, {"value": "desk-key-123456", "archive_password": "{{ credentials.fetch_archives }}"}
        )
        db.add(connection)
        db.commit()
        call = actions.Call(
            db=db,
            args={"id": "7"},
            classes=frozenset(),
            arg_classes={},
            dry_run=False,
            run=SimpleNamespace(id="run-1", incident_id=None, trigger={"playbook": "Vault desk"}),
            playbook=db.get(Playbook, collector.playbook),
            connection="Vault of files",
        )
        result = ca.run_command("fetchvault", "fetched-files", call)
        db.commit()
    # The archive opened with the value the credential has now, which is in nothing the step gave.
    assert result.output == {"count": 2, "names": list(COLLECTED)}
    assert SECRET not in str(result.output) and SECRET not in str(result.request)
    shown = admin.get(f"/api/artifacts/file-{collector.sha}").json()
    assert sorted(child["name"] for child in shown["children"]) == ["notes.txt", "run.log"]
