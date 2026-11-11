"""Artifacts: files, e-mails and captures analysed on their own, then linked to incidents."""

from __future__ import annotations

import hashlib

from fastapi.testclient import TestClient

from app import artifacts
from app.core.db import SessionLocal
from app.core.models import Artifact, ArtifactLink
from app.malware.samples import sample_path
from app.network import store
from tests.conftest import make_key
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture
from tests.test_malware import STRINGS_PAYLOAD, fake_pe
from tests.test_network import _pcap, workers  # noqa: F401 - workers is a fixture


def _incident(client, key, incident_id):
    r = client.post("/api/incidents", headers=key, json={"id": incident_id, "name": incident_id, "data": {}})
    assert r.status_code == 201, r.text


def test_file_analysed_on_its_own_then_linked(admin: TestClient):
    key = make_key(admin, role="analyst")
    data = fake_pe(payload=STRINGS_PAYLOAD)
    sha = hashlib.sha256(data).hexdigest()

    # Not known yet: the lookup an upload does first finds nothing.
    assert admin.get("/api/artifacts/lookup", headers=key, params={"sha256": sha}).json() == {"artifacts": []}

    r = admin.post("/api/artifacts/files", headers=key, files={"file": ("invoice.exe", data)})
    assert r.status_code == 201, r.text
    artifact = r.json()
    assert artifact["id"] == f"file-{sha}" and artifact["kind"] == "file" and artifact["name"] == "invoice.exe"
    assert artifact["incidents"] == [] and artifact["detail"].startswith("PE32")
    assert sample_path(sha).exists()
    # The analysis is the samples API's, with no incident.
    assert admin.get(f"/api/samples/{sha}", headers=key).json()["incidents"] == []

    listed = admin.get("/api/artifacts", headers=key).json()
    assert [a["id"] for a in listed["artifacts"]] == [artifact["id"]]
    assert listed["counts"] == {"file": 1, "mail": 0, "pcap": 0} and listed["total"] == 1
    assert admin.get("/api/artifacts", headers=key, params={"q": "invoice"}).json()["total"] == 1
    assert admin.get("/api/artifacts", headers=key, params={"q": sha[:20]}).json()["total"] == 1
    assert admin.get("/api/artifacts", headers=key, params={"q": "nothing-like-it"}).json()["total"] == 0
    assert admin.get("/api/artifacts", headers=key, params={"linked": "true"}).json()["total"] == 0
    assert admin.get("/api/artifacts", headers=key, params={"mine": "true"}).json()["total"] == 1
    assert (
        admin.get("/api/artifacts/lookup", headers=key, params={"sha256": sha}).json()["artifacts"][0]["id"]
        == (artifact["id"])
    )

    # Linked to an incident, it shows up in the incident's tab and indicators.
    _incident(admin, key, "a1")
    r = admin.post(f"/api/artifacts/{artifact['id']}/links", headers=key, json={"incidentId": "a1"})
    assert r.status_code == 201 and r.json()["incidents"] == [{"id": "a1", "name": "a1"}]
    doc = admin.get("/api/incidents/a1", headers=key).json()
    assert [ref["sha256"] for ref in doc["data"]["malware"]["samples"]] == [sha]
    assert doc["data"]["malware"]["samples"][0]["fileName"] == "invoice.exe"
    assert admin.get("/api/incidents/a1/iocs", headers=key).json()["total"] > 0
    assert admin.get("/api/artifacts", headers=key, params={"linked": "false"}).json()["total"] == 0
    # Linking twice changes nothing.
    assert admin.post(f"/api/artifacts/{artifact['id']}/links", headers=key, json={"incidentId": "a1"}).json()[
        "incidents"
    ] == [{"id": "a1", "name": "a1"}]

    # Unlinked, the artifact stays.
    assert admin.delete(f"/api/artifacts/{artifact['id']}/links/a1", headers=key).status_code == 204
    assert admin.delete(f"/api/artifacts/{artifact['id']}/links/a1", headers=key).status_code == 404
    assert admin.get("/api/incidents/a1", headers=key).json()["data"]["malware"]["samples"] == []
    assert admin.get(f"/api/artifacts/{artifact['id']}", headers=key).json()["incidents"] == []


def test_tags_are_normalised_and_searchable(admin: TestClient):
    key = make_key(admin, role="analyst")
    artifact = admin.post("/api/artifacts/files", headers=key, files={"file": ("a.bin", b"plain text file")}).json()
    r = admin.put(
        f"/api/artifacts/{artifact['id']}/tags", headers=key, json={"tags": ["Emotet", "campaign:q4", "emotet", "no!"]}
    )
    assert r.status_code == 200 and r.json()["tags"] == ["emotet", "campaign:q4"]
    assert admin.get("/api/artifacts", headers=key, params={"tag": "emotet"}).json()["total"] == 1
    assert admin.get("/api/artifacts", headers=key, params={"tag": "emo"}).json()["total"] == 0
    assert admin.get("/api/artifacts", headers=key, params={"q": "campaign"}).json()["total"] == 1
    assert admin.put(f"/api/artifacts/{artifact['id']}/tags", headers=key, json={"tags": []}).json()["tags"] == []


def test_mail_attachment_becomes_a_related_file(admin: TestClient, no_dns):  # noqa: F811
    key = make_key(admin, role="analyst")
    r = admin.post("/api/artifacts/mails", headers=key, files={"file": ("phish.eml", phishing_message())})
    assert r.status_code == 201, r.text
    mail = r.json()
    assert mail["kind"] == "mail" and mail["verdict"] == "phishing" and mail["score"] >= 70
    assert mail["incidents"] == []

    r = admin.post(f"/api/artifacts/{mail['id']}/attachments/0/sample", headers=key)
    assert r.status_code == 201, r.text
    child = r.json()
    assert child["kind"] == "file"
    detail = admin.get(f"/api/artifacts/{mail['id']}", headers=key).json()
    assert [(c["relation"], c["id"]) for c in detail["children"]] == [("attachment", child["id"])]
    assert admin.get(f"/api/artifacts/{child['id']}", headers=key).json()["parents"][0]["id"] == mail["id"]
    assert admin.get("/api/artifacts", headers=key, params={"kind": "mail"}).json()["total"] == 1
    # Only e-mails have attachments.
    assert admin.post(f"/api/artifacts/{child['id']}/attachments/0/sample", headers=key).status_code == 422

    # Deleting the e-mail keeps the file taken out of it.
    assert admin.delete(f"/api/artifacts/{mail['id']}", headers=key).status_code == 204
    assert admin.get(f"/api/artifacts/{mail['id']}", headers=key).status_code == 404
    assert admin.get(f"/api/artifacts/{child['id']}", headers=key).json()["parents"] == []


def test_capture_on_its_own_belongs_to_one_incident_at_most(admin: TestClient, workers):  # noqa: F811
    key = make_key(admin)
    r = admin.post("/api/artifacts/captures", headers=key, files={"file": ("a.pcapng", _pcap())})
    assert r.status_code == 201, r.text
    artifact = r.json()
    capture_id = artifact["ref"]
    assert artifact["kind"] == "pcap" and store.find_capture(capture_id) is not None
    assert admin.get(f"/api/captures/{capture_id}", headers=key).json()["incidentId"] is None

    _incident(admin, key, "n1")
    _incident(admin, key, "n2")
    assert admin.post(f"/api/artifacts/{artifact['id']}/links", headers=key, json={"incidentId": "n1"}).status_code == (
        201
    )
    assert [c["id"] for c in admin.get("/api/incidents/n1", headers=key).json()["data"]["network"]["captures"]] == [
        capture_id
    ]
    assert admin.post(f"/api/artifacts/{artifact['id']}/links", headers=key, json={"incidentId": "n2"}).status_code == (
        409
    )
    assert admin.delete(f"/api/artifacts/{artifact['id']}/links/n1", headers=key).status_code == 204
    assert admin.get("/api/incidents/n1", headers=key).json()["data"]["network"]["captures"] == []
    assert admin.post(f"/api/artifacts/{artifact['id']}/links", headers=key, json={"incidentId": "n2"}).status_code == (
        201
    )


def test_deleting_an_incident_keeps_the_artifacts_another_one_references(admin: TestClient):
    key = make_key(admin)
    _incident(admin, key, "d1")
    _incident(admin, key, "d2")
    shared = admin.post("/api/incidents/d1/samples", headers=key, files={"file": ("shared.bin", b"shared file")})
    shared_sha = shared.json()["sample"]["sha256"]
    admin.post("/api/incidents/d2/samples", headers=key, files={"file": ("shared.bin", b"shared file")})
    only = admin.post("/api/incidents/d1/samples", headers=key, files={"file": ("only.bin", b"only in d1")})
    only_sha = only.json()["sample"]["sha256"]

    assert admin.delete("/api/incidents/d1", headers=key).status_code == 204
    assert admin.get(f"/api/artifacts/file-{only_sha}", headers=key).status_code == 404
    assert not sample_path(only_sha).exists()
    kept = admin.get(f"/api/artifacts/file-{shared_sha}", headers=key).json()
    assert kept["incidents"] == [{"id": "d2", "name": "d2"}] and sample_path(shared_sha).exists()


def test_artifacts_need_a_write_key_and_a_known_id(admin: TestClient):
    read_only = make_key(admin, scopes=["read"])
    assert admin.post("/api/artifacts/files", headers=read_only, files={"file": ("a", b"x")}).status_code == 403
    assert admin.get("/api/artifacts", headers=read_only).status_code == 200
    key = make_key(admin)
    assert admin.get("/api/artifacts/file-nothex", headers=key).status_code == 404
    assert admin.get(f"/api/artifacts/file-{'0' * 64}", headers=key).status_code == 404
    assert admin.post("/api/artifacts/files", headers=key, files={"file": ("a", b"")}).status_code == 400
    assert (
        admin.post("/api/artifacts/files", headers=key, data={"incident": "missing"}, files={"file": ("a", b"x")})
    ).status_code == 404


def test_backfill_registers_what_was_stored_before(admin: TestClient):
    key = make_key(admin)
    _incident(admin, key, "b1")
    sha = admin.post("/api/incidents/b1/samples", headers=key, files={"file": ("old.bin", b"stored earlier")}).json()[
        "sample"
    ]["sha256"]
    # As after an upgrade: the sample and the incident's reference exist, the registry is empty.
    with SessionLocal() as db:
        db.query(ArtifactLink).delete()
        db.query(Artifact).delete()
        db.commit()
    assert artifacts.backfill(SessionLocal) == 1
    assert artifacts.backfill(SessionLocal) == 0
    entry = admin.get(f"/api/artifacts/file-{sha}", headers=key).json()
    assert entry["name"] == "old.bin" and entry["incidents"] == [{"id": "b1", "name": "b1"}]
