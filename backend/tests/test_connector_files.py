"""A connector's command that keeps a file, and one that sends a file Nik holds.

The other side is the fake outside of the tests: names that resolve and what
answers there. What is checked here is what happens on Nik's side: the file
that comes back is an artifact of the incident the run works on, stored as it
came; the file that leaves was judged by the data guard as an attachment is,
and never leaves when the guard holds it or the store does not have it.
"""

from __future__ import annotations

import hashlib
import textwrap
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
