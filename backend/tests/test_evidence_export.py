"""The export of an incident says what host evidence it held (7.0): the files, their reports, the
flags on records. An import takes that back, and a file given again finds its flags."""

from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.db import SessionLocal
from app.evidence import parse
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_evidence_parse import SOURCE, a_source, end, incident, record, worker_says  # noqa: F401 - fixture


def test_an_export_lists_the_files_and_the_flags_and_an_import_takes_them_back(incident, admin, monkeypatch):  # noqa: F811
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    from app.core.models import EvidenceMark, EvidenceSource
    from app.evidence import browse, imports

    source_id = a_source(incident, b"ElfFile\x00 to be exported")
    skip = {"t": "skip", "reason": "record cannot be read", "offset": 9000, "length": 512, "lost": 1}
    worker_says(monkeypatch, [SOURCE, record(1), record(2), skip, end(2, in_file=3)])
    parse.read(source_id)
    marked = client.put(
        f"/api/incidents/{incident}/evidence/marks",
        headers=key,
        json={"key": "evtx:WKS-042:Security:2", "flagged": True, "note": "look here"},
    )
    assert marked.status_code == 200, marked.text
    exported = client.get(f"/api/incidents/{incident}/evidence/export", headers=key).json()
    (listed,) = exported["sources"]
    assert exported["version"] == browse.EXPORT_VERSION and listed["fileName"] == "Security.evtx"
    assert listed["read"] == "partial" and listed["report"]["reasons"]["record cannot be read"]["lost"] == 1
    assert exported["marks"] == [
        {
            "key": "evtx:WKS-042:Security:2",
            "flagged": True,
            "note": "look here",
            "updatedBy": exported["marks"][0]["updatedBy"],
            "updatedAt": exported["marks"][0]["updatedAt"],
            "summary": "logon 2",
            "type": "event",
            "kind": "eventlog",
            "ts": 1_700_000_002_000,
        }
    ]
    assert "data" not in listed and "records" not in exported, "neither the records nor the originals travel"

    # Imported elsewhere: the file is listed as not here, with what was known of it; the flag waits.
    client.post("/api/incidents", headers=key, json={"id": "ev-imported", "data": {}})
    with SessionLocal() as db:
        assert imports.restore(db, "ev-imported", exported, "tester") == {"sources": 1, "marks": 1}
        db.commit()
        row = db.scalars(select(EvidenceSource).where(EvidenceSource.incident_id == "ev-imported")).one()
        assert (row.state, row.read, row.kept, row.sha256) == ("absent", "partial", 0, listed["sha256"])
        assert row.report["exported"]["kept"] == 2 and "record cannot be read" in row.report["reasons"]
        assert db.get(EvidenceMark, ("ev-imported", "evtx:WKS-042:Security:2")).note == "look here"
    summary = client.get("/api/incidents/ev-imported/evidence/summary", headers=key).json()
    assert summary["kinds"]["eventlog"]["absent"] == 1 and summary["partialUnseen"] == 0
    # The file is given again: it takes the place of its listing, is read, and the flag is on its record.
    with SessionLocal() as db:
        again = imports.accept(
            db, "ev-imported", listed["sha256"], 20, "Security.evtx", {"kind": "eventlog", "source": "evtx"}, "tester"
        )
        db.commit()
        again_id = again.id
        assert again.state == "queued"
    worker_says(monkeypatch, [SOURCE, record(1), record(2), end(2, in_file=2)])
    parse.read(again_id)
    page = client.get("/api/incidents/ev-imported/evidence/records?flagged=true", headers=key).json()
    assert [row["key"] for row in page["records"]] == ["evtx:WKS-042:Security:2"] and page["records"][0][
        "note"
    ] == "look here"
    with SessionLocal() as db:
        assert len(list(db.scalars(select(EvidenceSource).where(EvidenceSource.incident_id == "ev-imported")))) == 1
