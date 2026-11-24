"""The original of host evidence as an artifact (7.0): listed, filtered, kept while an incident holds it."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import delete

from app import storage
from app.core.db import SessionLocal
from app.core.models import ArtifactLink, EvidenceSource
from app.evidence import imports, originals
from tests.test_artifact_expiry import NOW, dated, day, events, tick
from tests.test_bulk import counts, done, states

HELD = "incident(s) hold this file as evidence: remove it from them first"


def a_hostfile(admin: TestClient, incident: str, salt: bytes = b"") -> tuple[str, str]:
    """An original given to an incident: its artifact id and its SHA-256."""
    admin.post("/api/incidents", json={"id": incident, "data": {}})
    data = b"ElfFile\x00" + bytes(range(256)) * 8 + salt
    sha256 = originals.keep_bytes(data)
    with SessionLocal() as db:
        imports.accept(db, incident, sha256, len(data), "Security.evtx", {"kind": "eventlog"}, "tester")
        db.commit()
    return f"hostfile-{sha256}", sha256


def let_go(incident: str) -> None:
    """The incident no longer holds the file: its sources are removed, as removing it from there does."""
    with SessionLocal() as db:
        db.execute(delete(EvidenceSource).where(EvidenceSource.incident_id == incident))
        db.execute(delete(ArtifactLink).where(ArtifactLink.incident_id == incident))
        db.commit()


def test_a_hostfile_is_listed_filtered_and_has_no_verdict(admin: TestClient):
    artifact_id, sha256 = a_hostfile(admin, "hf-list")
    listed = admin.get("/api/artifacts", params={"kind": "hostfile"}).json()
    row = next(item for item in listed["artifacts"] if item["id"] == artifact_id)
    assert row["kind"] == "hostfile" and row["name"] == "Security.evtx" and row["detail"] == "eventlog"
    assert row["size"] > 0 and row["score"] is None and row["verdict"] == ""
    assert [item["id"] for item in row["incidents"]] == ["hf-list"]
    assert all(item["kind"] == "hostfile" for item in listed["artifacts"])
    # The query language knows the kind, and the other kinds do not list it.
    by_query = admin.get("/api/artifacts", params={"q": "kind:hostfile"})
    assert by_query.status_code == 200 and artifact_id in [item["id"] for item in by_query.json()["artifacts"]]
    files = admin.get("/api/artifacts", params={"kind": "file"}).json()["artifacts"]
    assert artifact_id not in [item["id"] for item in files]
    # Its detail: the incidents come from the links.
    one = admin.get(f"/api/artifacts/{artifact_id}").json()
    assert one["ref"] == sha256 and [item["id"] for item in one["incidents"]] == ["hf-list"]


def test_no_route_of_the_other_artifacts_serves_an_original(admin: TestClient):
    """Until its own route and permission exist (evidence.download), nothing gives the bytes out."""
    artifact_id, sha256 = a_hostfile(admin, "hf-download")
    for path in (f"/api/samples/{sha256}/download", f"/api/artifacts/{artifact_id}/download"):
        answer = admin.get(path)
        assert answer.status_code in (404, 405), (path, answer.status_code)
        assert b"ElfFile" not in answer.content


def test_a_hostfile_an_incident_holds_is_not_deleted_and_one_nobody_holds_is(admin: TestClient):
    artifact_id, sha256 = a_hostfile(admin, "hf-del")
    refused = admin.delete(f"/api/artifacts/{artifact_id}")
    assert refused.status_code == 409 and refused.json()["detail"] == f"1 {HELD}"
    assert originals.has(sha256) and admin.get(f"/api/artifacts/{artifact_id}").status_code == 200
    # Two incidents hold the same copy.
    admin.post("/api/incidents", json={"id": "hf-del-2", "data": {}})
    with SessionLocal() as db:
        imports.accept(db, "hf-del-2", sha256, 10, "Security.evtx", {"kind": "eventlog"}, "tester")
        db.commit()
    assert admin.delete(f"/api/artifacts/{artifact_id}").json()["detail"] == f"2 {HELD}"
    let_go("hf-del")
    let_go("hf-del-2")
    assert admin.delete(f"/api/artifacts/{artifact_id}").status_code == 204
    assert not originals.has(sha256) and admin.get(f"/api/artifacts/{artifact_id}").status_code == 404
    audit = admin.get("/api/audit", params={"q": "action:artifact.delete"}).json()["entries"]
    assert any("Deleted hostfile Security.evtx" in entry["details"] for entry in audit)


def test_a_bulk_delete_refuses_the_held_original_and_deletes_the_free_one(admin: TestClient):
    held_id, held_sha = a_hostfile(admin, "hf-bulk-1", b"one")
    free_id, free_sha = a_hostfile(admin, "hf-bulk-2", b"two")
    let_go("hf-bulk-2")
    job = done(admin, "artifacts", "delete", ids=[held_id, free_id], confirm={"typed": "delete 2"})
    assert counts(job) == (1, 0, 1, 0)
    said = states(job)
    assert said[free_id][0] == "done" and said[held_id][0] == "refused" and HELD in said[held_id][1]
    assert originals.has(held_sha) and not originals.has(free_sha)
    # What makes no sense for an original is skipped with a sentence; tags work.
    assert counts(done(admin, "artifacts", "reanalyse", ids=[held_id])) == (0, 1, 0, 0)
    linked = done(admin, "artifacts", "link", {"incident": "hf-bulk-2"}, ids=[held_id])
    assert counts(linked) == (0, 1, 0, 0)
    assert counts(done(admin, "artifacts", "tags", {"add": ["triage"]}, ids=[held_id])) == (1, 0, 0, 0)


def test_a_hostfile_an_incident_holds_never_expires(admin: TestClient):
    held_id, held_sha = a_hostfile(admin, "hf-exp-1", b"three")
    free_id, free_sha = a_hostfile(admin, "hf-exp-2", b"four")
    let_go("hf-exp-2")
    dated(held_id, day(0))
    dated(free_id, day(0))
    # The held one is put off, its incident open or closed alike; the free one goes.
    assert tick(NOW) == {"noticed": 0, "expired": 1, "put_off": 1}
    held = admin.get(f"/api/artifacts/{held_id}").json()
    assert held["expiresAt"] == day(7)
    assert held["expiryNote"] == f"Put off to {day(7)}: 1 incident(s) hold it as evidence"
    assert originals.has(held_sha) and not originals.has(free_sha)
    assert [item["id"] for item in events("artifact.expired")][-1] == free_id
    # A week later it is put off again; once nobody holds it, it expires with its original.
    assert tick(NOW + 7 * 86400.0)["put_off"] == 1
    let_go("hf-exp-1")
    assert tick(NOW + 14 * 86400.0)["expired"] == 1 and not originals.has(held_sha)


def test_the_storage_page_counts_the_originals_under_host_evidence(admin: TestClient, monkeypatch):
    monkeypatch.setattr(storage, "LARGEST", 10_000)  # the store is shared with the other tests
    artifact_id, sha256 = a_hostfile(admin, "hf-store", b"five")
    usage = admin.get("/api/storage").json()
    groups = {group["id"]: group for group in usage["groups"]}
    assert groups["evidence"]["label"] == "Host evidence"
    assert groups["evidence"]["bytes"] >= originals.path_of(sha256).stat().st_size > 0
    assert groups["evidence"]["files"] >= 1
    assert usage["nik"] == sum(group["bytes"] for group in usage["groups"])
    named = {item["artifactId"]: item for item in usage["largest"]}
    assert named[artifact_id]["group"] == "evidence" and named[artifact_id]["name"] == "Security.evtx"
