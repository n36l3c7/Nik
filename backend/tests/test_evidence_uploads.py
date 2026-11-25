"""Files of host evidence sent in parts (7.0): sessions, parts in order, the original kept once."""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app import work
from app.core.db import SessionLocal
from app.core.models import Artifact, ArtifactLink, EvidenceSource, UploadSession, WorkClaim
from app.evidence import imports, originals, parse, uploads
from app.main import app as fastapi_app
from tests.conftest import make_key


def _client(admin: TestClient, incident: str) -> tuple[TestClient, dict]:
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    client.post("/api/incidents", headers=key, json={"id": incident, "data": {}})
    return client, key


def _open(client, key, incident, data, **extra):
    body = {"incidentId": incident, "fileName": "$MFT", "size": len(data), "params": {"kind": "disk"}, **extra}
    return client.post("/api/uploads", headers=key, json=body)


def _finish_here(monkeypatch):
    """Keep the file in the request's own thread, so the test sees the result at once."""

    def run(upload_id, _params=None):
        with work.hold(uploads.WORK, upload_id):
            uploads.finish(upload_id)
        return True

    monkeypatch.setattr(uploads, "_held_finish", run)
    # The reading of the file is another piece of work (test_evidence_parse.py): not started here.
    monkeypatch.setattr(parse, "start", lambda source_id, _params=None: True)


def test_a_file_sent_in_parts_is_kept_once_and_becomes_a_source(admin, monkeypatch):
    _finish_here(monkeypatch)
    client, key = _client(admin, "up1")
    data = bytes(range(256)) * 40
    sha256 = hashlib.sha256(data).hexdigest()
    r = _open(client, key, "up1", data, sha256=sha256)
    assert r.status_code == 201, r.text
    upload = r.json()["id"]
    assert r.json()["received"] == 0 and r.json()["chunk"] == uploads.CHUNK

    # A part that does not start where the last one ended is refused with what was received.
    r = client.put(f"/api/uploads/{upload}?offset=100", headers=key, content=data[100:200])
    assert r.status_code == 409 and r.json()["received"] == 0

    assert client.put(f"/api/uploads/{upload}?offset=0", headers=key, content=data[:4000]).json() == {"received": 4000}
    # Cut: the client asks how much was received and goes on from there.
    assert client.get(f"/api/uploads/{upload}", headers=key).json()["received"] == 4000
    # Completing before the end is refused.
    assert client.post(f"/api/uploads/{upload}/complete", headers=key).status_code == 409
    client.put(f"/api/uploads/{upload}?offset=4000", headers=key, content=data[4000:])

    r = client.post(f"/api/uploads/{upload}/complete", headers=key)
    assert r.status_code == 202, r.text
    shown = client.get(f"/api/uploads/{upload}", headers=key).json()
    assert shown["state"] == "complete" and shown["sourceId"] and shown["duplicate"] is False

    assert originals.has(sha256)
    assert not uploads.folder_of(upload).exists()  # the parts are gone
    with SessionLocal() as db:
        source = db.get(EvidenceSource, shown["sourceId"])
        assert (source.incident_id, source.kind, source.sha256, source.size, source.state) == (
            "up1",
            "disk",
            sha256,
            len(data),
            "queued",
        )
        assert db.get(Artifact, f"hostfile-{sha256}").size == len(data)
        assert db.get(ArtifactLink, (f"hostfile-{sha256}", "up1")) is not None
        # The reading of the file is wanted in the same transaction as its row.
        assert db.get(WorkClaim, ("evidence-parse", source.id)) is not None

    # The same file again: one original, the same source ("already imported").
    again = _open(client, key, "up1", data).json()["id"]
    client.put(f"/api/uploads/{again}?offset=0", headers=key, content=data)
    client.post(f"/api/uploads/{again}/complete", headers=key)
    second = client.get(f"/api/uploads/{again}", headers=key).json()
    assert second["sourceId"] == shown["sourceId"] and second["duplicate"] is True


def test_a_listing_that_receives_its_file_is_not_a_duplicate(admin, monkeypatch):
    _finish_here(monkeypatch)
    client, key = _client(admin, "up2")
    data = b"listed by an export " * 50
    sha256 = hashlib.sha256(data).hexdigest()
    with SessionLocal() as db:
        db.add(
            EvidenceSource(
                id="listed", incident_id="up2", kind="disk", source="", sha256=sha256, file_name="$MFT",
                size=len(data), state="absent", read="partial", report={}, created_at="2026-01-01T00:00:00Z",
            )
        )  # fmt: skip
        db.commit()
    upload = _open(client, key, "up2", data).json()["id"]
    client.put(f"/api/uploads/{upload}?offset=0", headers=key, content=data)
    client.post(f"/api/uploads/{upload}/complete", headers=key)
    shown = client.get(f"/api/uploads/{upload}", headers=key).json()
    assert shown["state"] == "complete" and shown["sourceId"] != "listed" and shown["duplicate"] is False


def test_a_file_that_is_not_the_one_announced_is_not_kept(admin, monkeypatch):
    _finish_here(monkeypatch)
    client, key = _client(admin, "up2")
    data = b"not what was announced" * 10
    upload = _open(client, key, "up2", data, sha256="0" * 64).json()["id"]
    client.put(f"/api/uploads/{upload}?offset=0", headers=key, content=data)
    client.post(f"/api/uploads/{upload}/complete", headers=key)
    shown = client.get(f"/api/uploads/{upload}", headers=key).json()
    assert shown["state"] == "aborted" and "not the one announced" in shown["error"]
    assert not originals.has(hashlib.sha256(data).hexdigest())


def test_a_session_belongs_to_who_opened_it(admin):
    client, key = _client(admin, "up3")
    upload = _open(client, key, "up3", b"x" * 10).json()["id"]
    with SessionLocal() as db:
        owner = db.get(UploadSession, upload).actor
        assert uploads.mine(db, upload, owner).id == upload
        with pytest.raises(uploads.UploadError) as refused:
            uploads.mine(db, upload, "someone-else")
        assert refused.value.status == 404


def test_limits_and_sections_are_checked(admin, monkeypatch):
    client, key = _client(admin, "up4")
    monkeypatch.setattr(uploads.settings, "EVIDENCE_MAX_MB", 1)
    assert _open(client, key, "up4", b"x" * (2 * 1024 * 1024)).status_code == 413
    body = {"incidentId": "up4", "fileName": "x", "size": 5, "params": {"kind": "nothing"}}
    assert client.post("/api/uploads", headers=key, json=body).status_code == 400
    assert _open(client, key, "nope", b"x").status_code == 404


def test_abandoned_sessions_expire_and_their_parts_go(admin):
    client, key = _client(admin, "up5")
    upload = _open(client, key, "up5", b"y" * 10).json()["id"]
    client.put(f"/api/uploads/{upload}?offset=0", headers=key, content=b"y" * 5)
    assert uploads.folder_of(upload).exists()
    with SessionLocal() as db:
        assert uploads.expire(db, now=10**12) >= 1
        db.commit()
        assert db.get(UploadSession, upload).state == "expired"
    assert not uploads.folder_of(upload).exists()


def _send(client, key, incident, data, file_name, params):
    body = {"incidentId": incident, "fileName": file_name, "size": len(data), "params": params}
    upload = client.post("/api/uploads", headers=key, json=body).json()["id"]
    client.put(f"/api/uploads/{upload}?offset=0", headers=key, content=data)
    client.post(f"/api/uploads/{upload}/complete", headers=key)
    return client.get(f"/api/uploads/{upload}", headers=key).json()


@pytest.mark.parametrize(
    ("kind", "source", "file_name", "expected"),
    [
        ("eventlog", "", "Security.evtx", ("evtx", "evtx")),
        ("eventlog", "evtx", "x.bin", ("evtx", "evtx")),
        ("eventlog", "", "whatever.json", ("eventlog-json", "nik-eventlogs.json")),
        ("eventlog", "", "WHATEVER.JSON", ("eventlog-json", "nik-eventlogs.json")),
        ("eventlog", "nik-eventlogs.json", "log.txt", ("eventlog-json", "nik-eventlogs.json")),
        ("eventlog", "other", "x.evtx", ("", "other")),
        ("commands", "powershell", "second_history.txt", ("history", "powershell")),
        ("commands", "", "second_history.txt", ("", "")),
        ("browser", "chrome", "History", ("browser", "chrome")),
        ("browser", "", "History", ("", "")),
        ("endpoint", "windows.execution.bam", "bam-export.csv", ("endpoint", "windows.execution.bam")),
        ("endpoint", "", "bam-export.csv", ("", "")),
        ("disk", "", "$MFT", ("", "")),
        ("disk", "mft", "$MFT", ("", "mft")),
    ],
)
def test_reader_names_the_parser_and_the_source(kind, source, file_name, expected):
    assert imports.reader(kind, source, file_name) == expected


@pytest.mark.parametrize(
    ("params", "file_name", "parser", "source"),
    [
        ({"kind": "commands", "source": "powershell"}, "second_history.txt", "history", "powershell"),
        (
            {"kind": "endpoint", "source": "windows.execution.bam"},
            "bam-export.csv",
            "endpoint",
            "windows.execution.bam",
        ),
        ({"kind": "eventlog"}, "whatever.json", "eventlog-json", "nik-eventlogs.json"),
        ({"kind": "eventlog"}, "Security.evtx", "evtx", "evtx"),
        ({"kind": "commands"}, "history.txt", "", ""),
    ],
)  # fmt: skip
def test_a_file_sent_in_parts_gets_the_parser_its_section_names(admin, monkeypatch, params, file_name, parser, source):
    _finish_here(monkeypatch)
    client, key = _client(admin, "up3")
    shown = _send(client, key, "up3", f"{file_name} {parser}".encode() * 20, file_name, params)
    assert shown["state"] == "complete", shown
    with SessionLocal() as db:
        row = db.get(EvidenceSource, shown["sourceId"])
        assert (row.parser, row.source) == (parser, source)


def test_an_event_log_sent_twice_without_source_is_one_row(admin, monkeypatch):
    _finish_here(monkeypatch)
    client, key = _client(admin, "up4")
    data = b"an event log " * 50
    first = _send(client, key, "up4", data, "Security.evtx", {"kind": "eventlog"})
    second = _send(client, key, "up4", data, "Security.evtx", {"kind": "eventlog"})
    assert first["duplicate"] is False and second["duplicate"] is True
    assert first["sourceId"] == second["sourceId"]
    with SessionLocal() as db:
        assert db.query(EvidenceSource).filter_by(incident_id="up4").count() == 1


def test_a_file_sent_without_source_is_a_duplicate_of_the_row_the_worker_filled(admin, monkeypatch):
    _finish_here(monkeypatch)
    client, key = _client(admin, "up5")
    data = b"a history the worker recognised " * 30
    first = _send(client, key, "up5", data, "h.txt", {"kind": "commands"})
    with SessionLocal() as db:
        db.get(EvidenceSource, first["sourceId"]).source = "bash"  # written by the worker after reading
        db.commit()
    second = _send(client, key, "up5", data, "h.txt", {"kind": "commands"})
    assert second["duplicate"] is True and second["sourceId"] == first["sourceId"]
    with SessionLocal() as db:
        assert db.query(EvidenceSource).filter_by(incident_id="up5").count() == 1


def test_a_failed_source_is_read_again_when_its_file_is_sent_again(admin, monkeypatch):
    _finish_here(monkeypatch)
    client, key = _client(admin, "up6")
    data = b"a file that failed " * 30
    first = _send(client, key, "up6", data, "Security.evtx", {"kind": "eventlog"})
    with SessionLocal() as db:
        row = db.get(EvidenceSource, first["sourceId"])
        row.state, row.error = "failed", "boom"
        db.commit()
    second = _send(client, key, "up6", data, "Security.evtx", {"kind": "eventlog"})
    assert second["sourceId"] == first["sourceId"] and second["duplicate"] is False
    with SessionLocal() as db:
        row = db.get(EvidenceSource, first["sourceId"])
        assert row.state == "queued" and row.error is None
