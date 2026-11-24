"""Files of host evidence sent in parts (7.0): sessions, parts in order, the original kept once."""

from __future__ import annotations

import hashlib

import pytest
from fastapi.testclient import TestClient

from app import work
from app.core.db import SessionLocal
from app.core.models import Artifact, ArtifactLink, EvidenceSource, UploadSession, WorkClaim
from app.evidence import originals, parse, uploads
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
    assert shown["state"] == "complete" and shown["sourceId"]

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
    assert client.get(f"/api/uploads/{again}", headers=key).json()["sourceId"] == shown["sourceId"]


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
