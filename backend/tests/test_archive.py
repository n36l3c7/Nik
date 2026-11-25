"""Archiving a closed incident (7.0): read-only, out of the lists, its host evidence out of the database.

The forensics worker is not there: ``parse._events`` is what it would have sent, as in the tests of the
reading. An incident here holds a file read by it (with its original and a flag on a record) and one
source of before 7.0 (no original).
"""

from __future__ import annotations

import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import func, select, update

from app import archive, fetch, mirror
from app.automation import engine, nik_actions, triggers
from app.core import audit  # noqa: F401 - the audit entries are read from the table
from app.core.clock import iso
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import (
    AuditEntry,
    AutomationEvent,
    EvidenceMark,
    EvidenceRecord,
    EvidenceSource,
    Incident,
    WarRoomEntry,
)
from app.evidence import imports, originals, parse
from app.main import app as fastapi_app
from tests.conftest import make_key
from tests.test_automation_engine import (  # noqa: F401 - test_actions is a fixture
    echo,
    edge,
    playbook,
    test_actions,
)
from tests.test_evidence_legacy import old_document
from tests.test_evidence_parse import SOURCE, a_source, end, record, worker_says

INCIDENT = "arc"
KEY = record(1)["key"]
SENTENCE = archive.SENTENCE


@pytest.fixture()
def world(admin, monkeypatch):
    """A closed incident with a file read (2 records, a flag on the first), a source of before 7.0 and
    a file artifact; the client is the admin's."""
    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    started: list[str] = []
    monkeypatch.setattr(parse, "start", lambda source_id, _params=None: started.append(source_id) or True)
    made = admin.post("/api/incidents", json={"id": INCIDENT, **old_document()})
    assert made.status_code == 201, made.text
    source_id = a_source(INCIDENT, b"ElfFile\x00 archive me")
    worker_says(monkeypatch, [SOURCE, record(1), record(2), end(2, in_file=2)])
    parse.read(source_id)
    marked = admin.put(f"/api/incidents/{INCIDENT}/evidence/marks", json={"key": KEY, "flagged": True, "note": "look"})
    assert marked.status_code == 200, marked.text
    artifact = admin.post(
        "/api/artifacts/files", files={"file": ("a.bin", b"MZ\x90\x00 not really", "application/octet-stream")}
    )
    assert artifact.status_code == 201, artifact.text
    return SimpleNamespace(source=source_id, artifact=artifact.json()["id"], started=started)


def close(client: TestClient, incident_id: str = INCIDENT) -> None:
    done = client.patch(f"/api/incidents/{incident_id}", json={"status": "closed"})
    assert done.status_code == 200, done.text


def archive_it(client: TestClient, incident_id: str = INCIDENT):
    close(client, incident_id)
    answer = client.post(f"/api/incidents/{incident_id}/archive")
    assert answer.status_code == 200, answer.text
    return answer.json()


def records_of(source_id: str) -> int:
    with SessionLocal() as db:
        return db.scalar(select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.source_id == source_id))


def legacy_records() -> int:
    with SessionLocal() as db:
        legacy = select(EvidenceSource.id).where(EvidenceSource.incident_id == INCIDENT, EvidenceSource.legacy)
        return db.scalar(select(func.count()).select_from(EvidenceRecord).where(EvidenceRecord.source_id.in_(legacy)))


# --------------------------------------------------------------------------- #
# Archiving                                                                   #
# --------------------------------------------------------------------------- #
def test_an_incident_that_is_not_closed_cannot_be_archived(admin, world):
    refused = admin.post(f"/api/incidents/{INCIDENT}/archive")
    assert refused.status_code == 409 and "closed" in refused.json()["detail"]
    assert admin.get(f"/api/incidents/{INCIDENT}").json()["archivedAt"] is None
    assert records_of(world.source) == 2


def test_an_incident_whose_file_is_being_read_cannot_be_archived(admin, world):
    close(admin)
    with SessionLocal() as db:
        db.get(EvidenceSource, world.source).state = "parsing"
        db.commit()
    refused = admin.post(f"/api/incidents/{INCIDENT}/archive")
    assert refused.status_code == 409 and "being read" in refused.json()["detail"]
    assert records_of(world.source) == 2


def test_archiving_drops_the_records_of_the_files_that_have_an_original_and_keeps_the_rest(admin, world):
    kept = legacy_records()
    assert kept > 0
    shown = archive_it(admin)
    assert shown["archivedAt"] and shown["archivedBy"] == "admin"
    assert shown["done"] == {"files": 1, "records": 2, "kept": 5}
    assert records_of(world.source) == 0
    assert legacy_records() == kept, "what could not come back stays"
    with SessionLocal() as db:
        source = db.get(EvidenceSource, world.source)
        assert (source.state, source.read, source.kept, source.read_count) == ("archived", "complete", 2, 2)
        assert source.report["ended"] is True and originals.has(source.sha256)
        assert db.get(EvidenceMark, (INCIDENT, KEY)).flagged
        old = db.scalars(select(EvidenceSource).where(EvidenceSource.incident_id == INCIDENT, EvidenceSource.legacy))
        assert {row.state for row in old} == {"done"}
        entry = db.scalars(select(AuditEntry).where(AuditEntry.action == "incident.archive")).one()
        assert entry.actor == "admin" and entry.incident_id == INCIDENT
        assert entry.details.startswith("Archived: 2 records of 1 file left the database; 5 files")
        line = db.scalars(
            select(WarRoomEntry).where(
                WarRoomEntry.incident_id == INCIDENT, WarRoomEntry.body["text"].as_string().like("Archived:%")
            )
        ).one()
        assert line.kind == "system" and line.author == "admin"
    # What stays readable.
    for path in (
        f"/api/incidents/{INCIDENT}",
        f"/api/incidents/{INCIDENT}/war-room",
        f"/api/incidents/{INCIDENT}/iocs",
        f"/api/incidents/{INCIDENT}/evidence/sources",
        f"/api/incidents/{INCIDENT}/evidence/summary",
        f"/api/incidents/{INCIDENT}/timers",
    ):
        assert admin.get(path).status_code == 200, path
    assert admin.post(f"/api/incidents/{INCIDENT}/report", json={}).status_code != 409


def test_an_archived_incident_cannot_be_archived_again_nor_a_free_one_taken_out(admin, world):
    archive_it(admin)
    assert admin.post(f"/api/incidents/{INCIDENT}/archive").status_code == 409
    taken = admin.delete(f"/api/incidents/{INCIDENT}/archive")
    assert taken.status_code == 200
    assert admin.delete(f"/api/incidents/{INCIDENT}/archive").status_code == 409
    assert admin.post("/api/incidents/ghost/archive").status_code == 404


def test_going_into_the_archive_and_out_of_it_is_a_new_revision_of_the_incident(admin, world):
    close(admin)
    path = f"/api/incidents/{INCIDENT}"
    before = admin.get(path).headers["ETag"]
    assert admin.get(path, headers={"If-None-Match": before}).status_code == 304
    assert admin.post(f"{path}/archive").status_code == 200
    # Whoever holds the incident open is not told that nothing changed: it is read-only now.
    seen = admin.get(path, headers={"If-None-Match": before})
    assert seen.status_code == 200 and seen.json()["archivedAt"]
    archived = seen.headers["ETag"]
    assert archived != before
    assert admin.delete(f"{path}/archive").status_code == 200
    back = admin.get(path, headers={"If-None-Match": archived})
    assert back.status_code == 200 and back.json()["archivedAt"] is None


# --------------------------------------------------------------------------- #
# Read-only                                                                   #
# --------------------------------------------------------------------------- #
def _file(name: str, data: bytes, kind: str = "application/octet-stream"):
    return {"file": (name, data, kind)}


CASES = {
    "patch": lambda c, w: c.patch(f"/api/incidents/{INCIDENT}", json={"host": "x"}),
    "upsert": lambda c, w: c.post("/api/incidents", json={"id": INCIDENT, "name": "again"}),
    "note-add": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/notes", json={"text": "hi"}),
    "note-edit": lambda c, w: c.patch(f"/api/incidents/{INCIDENT}/notes/n1", json={"text": "x"}),
    "note-delete": lambda c, w: c.delete(f"/api/incidents/{INCIDENT}/notes/n1"),
    "upload": lambda c, w: c.post(
        f"/api/incidents/{INCIDENT}/upload?tab=commands&shell=bash", files=_file("h.txt", b"ls\n", "text/plain")
    ),
    "upload-session": lambda c, w: c.post(
        "/api/uploads", json={"incidentId": INCIDENT, "size": 10, "params": {"kind": "commands"}}
    ),
    "read-again": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/evidence/sources/{w.source}/again"),
    "seen": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/evidence/sources/{w.source}/seen", json={}),
    "remove-source": lambda c, w: c.delete(f"/api/incidents/{INCIDENT}/evidence/sources/{w.source}"),
    "mark": lambda c, w: c.put(f"/api/incidents/{INCIDENT}/evidence/marks", json={"key": KEY, "flagged": False}),
    "war-room": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/war-room", json={"text": "hi"}),
    "task": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/tasks", json={"title": "t"}),
    "fields": lambda c, w: c.patch(f"/api/incidents/{INCIDENT}/fields", json={"changes": {"severity": "high"}}),
    "found-scan": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/iocs/found/scan"),
    "mail": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/mails", files=_file("m.eml", b"Subject: x\r\n\r\nhi")),
    "sample": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/samples", files=_file("s.bin", b"MZ\x90\x00 x")),
    "capture": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/captures", files=_file("c.pcap", b"\xd4\xc3\xb2\xa1")),
    "link": lambda c, w: c.post(f"/api/artifacts/{w.artifact}/links", json={"incidentId": INCIDENT}),
    "unlink": lambda c, w: c.delete(f"/api/artifacts/{w.artifact}/links/{INCIDENT}"),
    "timer": lambda c, w: c.post(f"/api/incidents/{INCIDENT}/timers/time_to_close/start", json={}),
    "mirror": lambda c, w: c.post(
        f"/api/incidents/{INCIDENT}/mirror", json={"instanceId": "x", "mirrorId": "1", "direction": "in"}
    ),
    "artifact-file": lambda c, w: c.post(
        "/api/artifacts/files", data={"incident": INCIDENT}, files=_file("b.bin", b"MZ\x90\x00 y")
    ),
}


@pytest.mark.parametrize("name", sorted(CASES))
def test_every_write_to_an_archived_incident_is_refused(admin, world, name):
    archive_it(admin)
    refused = CASES[name](admin, world)
    assert refused.status_code == 409, (name, refused.status_code, refused.text)
    assert SENTENCE in refused.text, refused.text
    assert admin.get(f"/api/incidents/{INCIDENT}").status_code == 200


def test_the_refusal_says_the_incident_is_archived(admin, world):
    archive_it(admin)
    refused = admin.patch(f"/api/incidents/{INCIDENT}", json={"host": "x"})
    assert refused.json() == {"detail": SENTENCE, "archived": True}
    with SessionLocal() as db:
        assert db.get(Incident, INCIDENT).host == "WKS-042"


def test_an_archived_incident_can_be_deleted(admin, world):
    archive_it(admin)
    assert admin.delete(f"/api/incidents/{INCIDENT}").status_code == 204
    assert admin.get(f"/api/incidents/{INCIDENT}").status_code == 404


# --------------------------------------------------------------------------- #
# The lists and the search                                                    #
# --------------------------------------------------------------------------- #
def test_an_archived_incident_is_out_of_the_lists_and_found_by_a_filter_and_by_the_search(admin, world):
    assert admin.post("/api/incidents", json={"id": "other", "name": "Other one", "data": {}}).status_code == 201
    archive_it(admin)

    def ids(path: str, summary: bool = False) -> list[str]:
        found = admin.get(path).json()["incidents"]
        return sorted(item["id"] for item in found)

    assert ids("/api/incidents") == ["other"]
    assert ids("/api/incidents?view=summary") == ["other"]
    assert ids("/api/incidents?archived=only") == [INCIDENT]
    assert ids("/api/incidents?archived=include") == [INCIDENT, "other"]
    assert admin.get("/api/incidents?archived=nope").status_code == 422
    assert ids("/api/incidents?q=archived:true") == [INCIDENT]
    assert ids("/api/incidents?q=archived:false") == ["other"]
    assert ids("/api/incidents?q=status:closed") == []
    assert ids("/api/incidents?q=status:closed%20archived:true") == [INCIDENT]
    assert admin.get("/api/incidents?q=archived:maybe").status_code == 422
    row = admin.get("/api/incidents?archived=only&view=summary").json()["incidents"][0]
    assert row["archivedAt"] and row["archivedBy"] == "admin"
    assert admin.get("/api/incidents?view=summary").json()["incidents"][0]["archivedAt"] is None
    assert admin.get("/api/incidents?archived=only&view=summary&fields=severity").json()["total"] == 1
    found = admin.get("/api/search?q=Kept the old").json()["incidents"]
    assert [(item["id"], item["archived"]) for item in found] == [(INCIDENT, True)]
    assert [item["archived"] for item in admin.get("/api/search?q=Other").json()["incidents"]] == [False]


# --------------------------------------------------------------------------- #
# Taking it out                                                               #
# --------------------------------------------------------------------------- #
def test_taking_an_incident_out_reads_its_files_again_and_the_flags_are_on_the_records_again(admin, world, monkeypatch):
    archive_it(admin)
    world.started.clear()
    answer = admin.delete(f"/api/incidents/{INCIDENT}/archive")
    assert answer.status_code == 200, answer.text
    assert answer.json()["archivedAt"] is None and answer.json()["done"] == {"reading": 1}
    assert world.started == [world.source], "the reading is started once the change is committed"
    with SessionLocal() as db:
        assert db.get(EvidenceSource, world.source).state == "queued"
        assert db.get(Incident, INCIDENT).archived_at is None
        assert (
            db.scalars(select(AuditEntry).where(AuditEntry.action == "incident.unarchive")).one().incident_id
            == INCIDENT
        )
    assert records_of(world.source) == 0
    worker_says(monkeypatch, [SOURCE, record(1), record(2), end(2, in_file=2)])
    parse.read(world.source)
    assert records_of(world.source) == 2
    with SessionLocal() as db:
        assert db.get(EvidenceSource, world.source).state == "done"
        assert db.get(EvidenceMark, (INCIDENT, KEY)).note == "look"
    # And it is written to again.
    assert admin.post(f"/api/incidents/{INCIDENT}/notes", json={"text": "back"}).status_code == 201
    assert admin.patch(f"/api/incidents/{INCIDENT}", json={"status": "open"}).status_code == 200


def test_a_plaso_export_is_archived_and_read_again_like_any_file_and_a_collection_zip_has_nothing_to_drop(
    admin, world, monkeypatch
):
    plaso = b'{"data_type": "windows:evtx:record"}' + bytes([10])
    sha256 = originals.keep_bytes(plaso)
    zipped = originals.keep_bytes(b"PK" + bytes([3, 4]) + b" a collection")
    with SessionLocal() as db:
        export = imports.accept(
            db, INCIDENT, sha256, len(plaso), "timeline.jsonl", {"kind": "collection", "source": "plaso.jsonl"}, "t"
        )
        zip_row = imports.accept(
            db, INCIDENT, zipped, 20, "triage.zip", {"kind": "collection", "source": "collection.zip"}, "t"
        )
        zip_row.state = "listed"
        db.commit()
        export_id, zip_id = export.id, zip_row.id
    worker_says(
        monkeypatch,
        [
            {**SOURCE, "kind": "collection", "source": "plaso.jsonl"},
            record(5, key="plaso:1", kind="eventlog", source="evtx"),
            record(6, key="plaso:2", kind="eventlog", source="evtx"),
            record(7, key="plaso:3", kind="eventlog", source="evtx"),
            end(3, in_file=3),
        ],
    )
    parse.read(export_id)
    assert records_of(export_id) == 3
    shown = archive_it(admin)
    assert shown["done"] == {"files": 2, "records": 5, "kept": 5}
    assert records_of(export_id) == 0
    with SessionLocal() as db:
        assert db.get(EvidenceSource, export_id).state == "archived"
        assert db.get(EvidenceSource, export_id).kept == 3
        assert db.get(EvidenceSource, zip_id).state == "listed", "the zip row has no records and is left as it is"
    world.started.clear()
    answer = admin.delete(f"/api/incidents/{INCIDENT}/archive")
    assert answer.status_code == 200, answer.text
    assert answer.json()["done"] == {"reading": 2}
    assert set(world.started) == {world.source, export_id}
    worker_says(
        monkeypatch,
        [
            {**SOURCE, "kind": "collection", "source": "plaso.jsonl"},
            record(5, key="plaso:1", kind="eventlog", source="evtx"),
            record(6, key="plaso:2", kind="eventlog", source="evtx"),
            record(7, key="plaso:3", kind="eventlog", source="evtx"),
            end(3, in_file=3),
        ],
    )
    parse.read(export_id)
    assert records_of(export_id) == 3
    with SessionLocal() as db:
        assert db.get(EvidenceSource, export_id).state == "done"
        assert db.get(EvidenceSource, zip_id).state == "listed"


# --------------------------------------------------------------------------- #
# Who may                                                                     #
# --------------------------------------------------------------------------- #
def test_archiving_needs_the_permission(admin, world):
    close(admin)
    analyst = TestClient(fastapi_app)
    key = make_key(admin, label="anna", roles=["analyst"])
    assert analyst.post(f"/api/incidents/{INCIDENT}/archive", headers=key).status_code == 403
    assert analyst.delete(f"/api/incidents/{INCIDENT}/archive", headers=key).status_code == 403
    assert analyst.get("/api/settings/archive", headers=key).status_code == 403
    assert analyst.put("/api/settings/archive", headers=key, json={"enabled": True}).status_code == 403
    # A role that holds the permission (with the right to read, as the screens need).
    other = make_key(admin, label="archivist", roles=["viewer", "archive"])
    assert analyst.post(f"/api/incidents/{INCIDENT}/archive", headers=other).status_code == 200
    assert analyst.get("/api/settings/archive", headers=other).status_code == 200
    assert analyst.delete(f"/api/incidents/{INCIDENT}/archive", headers=other).status_code == 200
    # Its file is read again (here: it is, at once), and the administrators have the permission by default.
    with SessionLocal() as db:
        db.get(EvidenceSource, world.source).state = "done"
        db.commit()
    assert admin.post(f"/api/incidents/{INCIDENT}/archive").status_code == 200
    with SessionLocal() as db:
        by = [row.actor for row in db.scalars(select(AuditEntry).where(AuditEntry.action == "incident.archive"))]
        assert len(by) == 2 and "admin" in by


def test_the_rule_is_set_by_whoever_may_archive(admin):
    shown = admin.get("/api/settings/archive").json()
    assert shown["enabled"] is False and shown["days"] == 180 and shown["defaults"] == {"enabled": False, "days": 180}
    saved = admin.put("/api/settings/archive", json={"enabled": True, "days": 30})
    assert saved.status_code == 200 and (saved.json()["enabled"], saved.json()["days"]) == (True, 30)
    assert admin.put("/api/settings/archive", json={"days": 0}).status_code == 422
    assert admin.put("/api/settings/archive", json={"days": 3651}).status_code == 422
    assert admin.put("/api/settings/archive", json={"enabled": "maybe"}).status_code == 422
    assert admin.put("/api/settings/archive", json={"enabled": False}).json()["days"] == 30
    with SessionLocal() as db:
        assert db.scalars(select(AuditEntry).where(AuditEntry.action == "archive.settings")).all()


# --------------------------------------------------------------------------- #
# The rule                                                                    #
# --------------------------------------------------------------------------- #
def closed_incidents(admin: TestClient, count: int, days_ago: int, prefix: str, now: float) -> list[str]:
    ids = [f"{prefix}{index:03d}" for index in range(count)]
    for incident_id in ids:
        doc = {"id": incident_id, "name": incident_id, "status": "closed", "data": {}}
        assert admin.post("/api/incidents", json=doc).status_code == 201
    with SessionLocal() as db:
        # Oldest first by name: the first is the one closed longest ago.
        for index, incident_id in enumerate(ids):
            when = iso(now - days_ago * 86400 - (count - index) * 60)
            db.execute(update(Incident).where(Incident.id == incident_id).values(closed_at=when))
        db.commit()
    return ids


def archived_ids() -> set[str]:
    with SessionLocal() as db:
        return set(db.scalars(select(Incident.id).where(Incident.archived_at.is_not(None))))


def test_the_rule_does_nothing_while_it_is_off(admin):
    now = time.time()
    closed_incidents(admin, 2, 400, "old", now)
    with SessionLocal() as db:
        assert archive.auto(db, now) == 0
    assert archived_ids() == set()


def test_the_rule_archives_what_was_closed_for_more_than_its_days_and_nothing_else(admin, monkeypatch):
    now = time.time()
    old = closed_incidents(admin, 2, 40, "old", now)
    recent = closed_incidents(admin, 1, 10, "new", now)
    assert admin.post("/api/incidents", json={"id": "open-one", "name": "open", "data": {}}).status_code == 201
    assert admin.put("/api/settings/archive", json={"enabled": True, "days": 30}).status_code == 200
    with SessionLocal() as db:
        assert archive.auto(db, now) == 2
    assert archived_ids() == set(old) and not set(recent) & archived_ids()
    with SessionLocal() as db:
        by = {row.actor for row in db.scalars(select(AuditEntry).where(AuditEntry.action == "incident.archive"))}
        assert by == {"nik"}
        assert archive.auto(db, now) == 0
    # A copy of a server leaves everything as it was restored.
    monkeypatch.setattr(settings, "NIK_COPY", True)
    assert admin.put("/api/settings/archive", json={"days": 5}).status_code == 200
    with SessionLocal() as db:
        assert archive.auto(db, now) == 0


def test_the_rule_archives_fifty_a_pass_oldest_first_and_skips_an_incident_being_read(admin, world):
    now = time.time()
    many = closed_incidents(admin, 52, 100, "bulk", now)
    assert admin.put("/api/settings/archive", json={"enabled": True, "days": 30}).status_code == 200
    # One of them holds a file that is being read: it is left for the next pass.
    source = a_source(many[0], b"ElfFile\x00 being read")
    with SessionLocal() as db:
        db.get(EvidenceSource, source).state = "parsing"
        db.commit()
    with SessionLocal() as db:
        assert archive.auto(db, now) == 50
    assert many[0] not in archived_ids() and len(archived_ids()) == 50
    with SessionLocal() as db:
        db.get(EvidenceSource, source).state = "done"
        db.commit()
    with SessionLocal() as db:
        assert archive.auto(db, now) == 2
    assert set(many) <= archived_ids()


def test_the_rule_is_one_of_the_hourly_housekeeping():
    from app import work

    assert archive.auto in work.hourly


# --------------------------------------------------------------------------- #
# Bulk                                                                        #
# --------------------------------------------------------------------------- #
def test_the_bulk_actions_archive_and_unarchive(admin, world):
    assert admin.post("/api/incidents", json={"id": "open-1", "name": "still open", "data": {}}).status_code == 201
    assert (
        admin.post("/api/incidents", json={"id": "shut-1", "name": "closed one", "status": "closed"}).status_code == 201
    )
    close(admin)

    def ask(action: str, ids: list[str], **more) -> dict:
        answer = admin.post("/api/incidents/bulk", json={"action": action, "ids": ids, **more})
        assert answer.status_code == 200, answer.text
        return {item["ref"]: (item["state"], item["note"]) for item in answer.json()["items"]}

    first = ask("archive", [INCIDENT, "open-1", "shut-1"])
    assert first[INCIDENT][0] == "done" and first["shut-1"][0] == "done"
    assert first["open-1"][0] == "refused" and "closed" in first["open-1"][1]
    assert ask("archive", [INCIDENT])[INCIDENT][0] == "skipped"
    assert archived_ids() == {INCIDENT, "shut-1"} and records_of(world.source) == 0
    # The other bulk actions refuse an archived incident, with the sentence.
    assert ask_set_refused(admin)
    assert ask("delete", ["shut-1"], confirm={"typed": "delete 1"})["shut-1"][0] == "done"
    back = ask("unarchive", [INCIDENT, "open-1"])
    assert back[INCIDENT][0] == "done" and back["open-1"][0] == "skipped"
    assert world.started[-1] == world.source and archived_ids() == set()


def ask_set_refused(admin: TestClient) -> bool:
    answer = admin.post(
        "/api/incidents/bulk", json={"action": "set", "params": {"changes": {"severity": "high"}}, "ids": [INCIDENT]}
    )
    items = answer.json()["items"]
    return answer.status_code == 200 and [(item["state"], item["note"]) for item in items] == [("refused", SENTENCE)]


def test_a_bulk_archive_needs_the_permission(admin, world):
    close(admin)
    key = make_key(admin, label="anna", roles=["analyst"])
    analyst = TestClient(fastapi_app)
    refused = analyst.post("/api/incidents/bulk", headers=key, json={"action": "archive", "ids": [INCIDENT]})
    assert refused.status_code == 403


# --------------------------------------------------------------------------- #
# What does not write to an archived incident by itself                       #
# --------------------------------------------------------------------------- #
@pytest.mark.usefixtures("test_actions")
def test_a_playbook_is_not_started_for_an_archived_incident(admin, world):
    by_hand = playbook(admin, "By hand", [echo("a", "x")], [edge("start", "a")])
    playbook(
        admin, "On update", [echo("a", "x")], [edge("start", "a")], trigger={"event": "incident.updated"}, enabled=True
    )
    assert admin.post("/api/incidents", json={"id": "ctrl", "name": "control", "data": {}}).status_code == 201
    assert admin.patch("/api/incidents/ctrl", json={"host": "h"}).status_code == 200
    assert admin.patch(f"/api/incidents/{INCIDENT}", json={"host": "h2"}).status_code == 200
    archive_it(admin)
    body = {"objectKind": "incident", "objectId": INCIDENT}
    refused = admin.post(f"/api/automation/playbooks/{by_hand}/run", json=body)
    assert refused.status_code == 409 and SENTENCE in refused.text
    assert admin.post(f"/api/automation/playbooks/{by_hand}/run", json={**body, "dryRun": True}).status_code == 201
    assert admin.post(f"/api/automation/playbooks/{by_hand}/run", json={**body, "objectId": "ctrl"}).status_code == 201
    with SessionLocal() as db:
        events = db.scalars(select(AutomationEvent).where(AutomationEvent.kind == "incident.updated")).all()
        mine = [event for event in events if event.object_id == INCIDENT]
        control = [event for event in events if event.object_id == "ctrl"]
        assert mine and control
        for event in mine:
            assert triggers.handle_event(db, event, time.time()) == []
        assert sum(len(triggers.handle_event(db, event, time.time())) for event in control) == len(control)


def test_what_a_step_writes_to_an_archived_incident_fails_with_the_sentence(admin, world):
    archive_it(admin)
    with SessionLocal() as db:
        call = SimpleNamespace(db=db, run=SimpleNamespace(incident_id=INCIDENT))
        with pytest.raises(nik_actions.ActionError) as failed:
            nik_actions._incident(call, None)
        assert str(failed.value) == SENTENCE and failed.value.retry is False
        run = SimpleNamespace(id="r1", dry_run=False, incident_id=INCIDENT, trigger={})
        with pytest.raises(engine.StepFailed) as stopped:
            engine._to_context(db, run, [("File", {"SHA256": "a" * 64})], "run:r1")
        assert SENTENCE in str(stopped.value)


def test_a_fetch_or_a_mirror_skips_an_archived_incident_without_raising(admin, world, monkeypatch):
    close(admin)
    with SessionLocal() as db:
        row = db.get(Incident, INCIDENT)
        row.mirror = {"connection": "c1", "id": "T-1", "direction": "both", "nextAt": 0}
        db.commit()
    now = time.time()
    with SessionLocal() as db:
        assert mirror.due(db, now) == [INCIDENT]
    assert admin.post(f"/api/incidents/{INCIDENT}/archive").status_code == 200
    with SessionLocal() as db:
        assert mirror.due(db, now) == []
    pulled: list[str] = []
    monkeypatch.setattr(mirror, "pull", lambda db, incident, at: pulled.append(incident.id))
    mirror.run_pull(INCIDENT, now)
    assert pulled == []
    # A push queued before the archive sends nothing and writes nothing.
    job = SimpleNamespace(id="j1", connection_id="c1", incident_id=INCIDENT, kind="update", payload={})
    with SessionLocal() as db:
        assert mirror.push(db, job, now) is None
    # What a fetch keeps as evidence of an incident is not kept for an archived one.
    asked: list[str] = []
    runtime = SimpleNamespace(evidence=lambda item: asked.append("asked") or ("m.eml", b"Subject: x\r\n\r\nhi"))
    with SessionLocal() as db:
        assert fetch._evidence(db, runtime, SimpleNamespace(id="k"), {}, INCIDENT) == ""
    assert asked == []
    # The SLA timers do not run for it.
    from app import timers

    with SessionLocal() as db:
        timers.tick(db, now)
        db.commit()
