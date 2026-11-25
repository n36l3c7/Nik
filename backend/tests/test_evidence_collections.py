"""Collections of host evidence (7.0): a triage zip listed, then imported on request; a bare file recognised.

The forensics worker is not there in these tests: what it answers is written here (``FakeWorker``), at the places the
API asks it (``parse._events`` for the lines of a parse and of an unpack, ``collections._post`` for the rest).
"""

from __future__ import annotations

import hashlib
import io
import json
from contextlib import contextmanager
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import work
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import ArtifactRelation, EvidenceMember, EvidenceRecord, EvidenceSource, Incident
from app.evidence import collections, imports, originals, parse, uploads
from app.main import app as fastapi_app
from tests.conftest import make_key

HISTORY = b"whoami\nnet user\n"
EVTX = b"ElfFile\x00 a log of the test"
PROGRAM = b"MZ a program of the test, never run"
CHROME = b"SQLite format 3\x00 a history of the test"
PS = "C/Users/bob/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class FakeWorker:
    """What the worker would answer for the zips and the files of a test."""

    def __init__(self) -> None:
        self.zips: dict[str, list[dict[str, Any]]] = {}  # the sha256 of a zip -> its members
        self.ends: dict[str, dict[str, Any]] = {}
        self.known: dict[str, dict[str, Any]] = {}  # the sha256 of a bare file -> what /recognise says
        self.content: dict[str, bytes] = {}
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def zip(self, data: bytes, members: list[dict[str, Any]], **end: Any) -> str:
        digest = sha(data)
        self.zips[digest] = members
        self.ends[digest] = end
        for member in members:
            self.content[sha(member["data"])] = member["data"]
        return digest

    def events(self, sha256: str, body: dict[str, Any], _job: str, route: str = "/parse"):
        self.calls.append((route, {"sha256": sha256, **body}))
        if route == "/unpack":
            held = self.zips[sha256]
            listed = 0
            for number, member in enumerate(held):
                yield {
                    "t": "member",
                    "n": number,
                    "path": member["path"],
                    "size": len(member["data"]),
                    "sha256": sha(member["data"]),
                    "kind": member.get("kind"),
                    "source": member.get("source"),
                    "parser": member.get("parser"),
                    "executable": bool(member.get("executable")),
                    "kept": bool(member.get("kind")),
                    "host": member.get("host", ""),
                    "username": member.get("username", ""),
                    "profile": member.get("profile", ""),
                    **({"skip": member["skip"]} if member.get("skip") else {}),
                }
                listed += 1
            end = {
                "t": "end",
                "members": listed,
                "bytes": sum(len(member["data"]) for member in held),
                "recognised": sum(1 for m in held if m.get("kind") and not m.get("skip")),
                "skipped": sum(1 for m in held if m.get("skip")),
                "executables": sum(1 for m in held if m.get("executable")),
                "unlisted": 0,
                "password": False,
                "stopped": None,
                "error": None,
                **self.ends[sha256],
            }
            if "cut" in self.ends[sha256]:  # the worker stopped before its last line
                return
            yield end
            return
        # A parse: a source line, a record for each line of the text, the end.
        text = self.content.get(sha256, b"")
        found = [line for line in text.decode("utf-8", "replace").splitlines() if line]
        yield {"t": "source", "parser": body.get("parser") or "history", "version": "1", "kind": body.get("kind")}
        for number, line in enumerate(found):
            yield {
                "t": "r",
                "key": f"h:{sha256[:8]}:{number}",
                "type": "command",
                "ts": None,
                "seq": number,
                "summary": line,
                "data": {"command": line},
                "loc": {},
                "trunc": False,
            }
        yield {"t": "end", "in_file": len(found), "read": len(found), "first_ts": None, "last_ts": None}

    @contextmanager
    def post(self, route: str, sha256: str, body: dict[str, Any], _timeout: float):
        self.calls.append((route, {"sha256": sha256, **body}))
        if route == "/recognise":
            said = self.known.get(sha256) or {"refused": "No parser of Nik reads this file"}
            if "refused" in said or "unknown" in said:
                import urllib.error

                error = urllib.error.HTTPError("http://worker/recognise", 422, "refused", None, io.BytesIO(b"{}"))  # type: ignore[arg-type]
                error.answer = {"detail": said.get("refused") or said.get("unknown"), "refused": "refused" in said}  # type: ignore[attr-defined]
                raise error
            yield io.BytesIO(json.dumps(said).encode())
        elif route == "/member":
            data = self.content.get(body["sha256"])
            if data is None:
                import urllib.error

                error = urllib.error.HTTPError("http://worker/member", 404, "no", None, io.BytesIO(b"{}"))  # type: ignore[arg-type]
                error.answer = {"detail": "The collection holds no such member"}  # type: ignore[attr-defined]
                raise error
            yield io.BytesIO(data)
        else:  # pragma: no cover - a route the tests do not use
            raise AssertionError(route)


@pytest.fixture()
def world(admin, monkeypatch):
    client = TestClient(fastapi_app)
    key = make_key(admin, roles=["analyst"])
    client.post("/api/incidents", headers=key, json={"id": "co1", "data": {}})
    worker = FakeWorker()
    monkeypatch.setattr(settings, "FORENSICS_URL", "http://forensics.test")
    monkeypatch.setattr(parse, "_events", worker.events)
    monkeypatch.setattr(collections, "_post", worker.post)

    def keep_here(upload_id, _params=None):
        with work.hold(uploads.WORK, upload_id):
            uploads.finish(upload_id)
        return True

    def unpack_here(source_id, _params=None):
        with work.hold(imports.UNPACK_WORK, source_id) as claim:
            collections.unpack(source_id, claim)
        return True

    def import_here(source_id, _params=None):
        with work.hold(collections.IMPORT_WORK, source_id) as claim:
            collections.import_members(source_id, claim)
        return True

    def parse_here(source_id, _params=None):
        with work.hold(parse.WORK, source_id) as claim:
            parse.read(source_id, claim)
        return True

    monkeypatch.setattr(uploads, "_held_finish", keep_here)
    monkeypatch.setattr(collections, "start_unpack", unpack_here)
    monkeypatch.setattr(collections, "start_import", import_here)
    monkeypatch.setattr(parse, "start", parse_here)
    return client, key, worker


def send(client, key, data: bytes, name: str, params: dict | None = None, incident: str = "co1") -> dict:
    body = {"incidentId": incident, "fileName": name, "size": len(data), "params": params if params is not None else {}}
    opened = client.post("/api/uploads", headers=key, json=body)
    assert opened.status_code == 201, opened.text
    upload = opened.json()["id"]
    assert client.put(f"/api/uploads/{upload}?offset=0", headers=key, content=data).status_code == 200
    assert client.post(f"/api/uploads/{upload}/complete", headers=key).status_code == 202
    return client.get(f"/api/uploads/{upload}", headers=key).json()


def triage(worker: FakeWorker, **end: Any) -> tuple[bytes, str]:
    zipped = b"PK\x03\x04 a collection of the test " + json.dumps(end).encode()
    chrome = "C/Users/bob/AppData/Local/Google/Chrome/User Data/Profile 1/History"
    archive = "an archive inside the collection: it is not opened (unzip it and send the files)"
    members = [
        {
            "path": "C/Windows/System32/winevt/Logs/Security.evtx",
            "data": EVTX,
            "kind": "eventlog",
            "source": "evtx",
            "parser": "evtx",
            "host": "WKS-1",
        },
        {
            "path": PS,
            "data": HISTORY,
            "kind": "commands",
            "source": "powershell",
            "parser": "history",
            "username": "bob",
        },
        {
            "path": chrome,
            "data": CHROME,
            "kind": "browser",
            "source": "chrome.history",
            "parser": "browser",
            "username": "bob",
            "profile": "Profile 1",
        },
        {"path": "C/Windows/System32/cmd.exe", "data": PROGRAM, "executable": True},
        {"path": "C/Users/bob/notes.txt", "data": b"nothing for Nik"},
        {"path": "C/tools/inner.zip", "data": b"PK inner", "skip": archive},
        {"path": "C/secret.bin", "data": b"x", "skip": "it is encrypted and the password is not known"},
    ]
    digest = worker.zip(zipped, members, **end)
    worker.known[digest] = {"container": "zip", "kind": "collection", "source": "collection.zip"}
    return zipped, digest


def listed(client, key, worker, **end) -> str:
    data, _digest = triage(worker, **end)
    answer = send(client, key, data, "triage.zip", {"kind": "collection"})
    assert answer["state"] == "complete", answer
    return answer["sourceId"]


def members_of(client, key, source_id: str, **query) -> dict:
    found = client.get(f"/api/incidents/co1/evidence/collections/{source_id}", headers=key, params=query)
    assert found.status_code == 200, found.text
    return found.json()


# --------------------------------------------------------------------------- #
# Listing                                                                     #
# --------------------------------------------------------------------------- #
def test_a_zip_is_kept_as_an_original_and_listed_and_nothing_is_imported(world):
    client, key, worker = world
    data, digest = triage(worker)
    answer = send(client, key, data, "triage.zip", {"kind": "collection"})
    assert (answer["kind"], answer["source"], answer["recognised"], answer["duplicate"]) == (
        "collection",
        "collection.zip",
        True,
        False,
    )
    assert originals.has(digest)
    row = client.get(f"/api/incidents/co1/evidence/sources/{answer['sourceId']}", headers=key).json()
    assert (row["kind"], row["source"], row["state"], row["read"]) == (
        "collection",
        "collection.zip",
        "listed",
        "partial",
    )
    assert row["members"]["members"] == 7 and row["members"]["recognised"] == 3 and row["members"]["executables"] == 1
    assert row["members"]["imported"] == 0 and row["inFile"] == 7 and row["skipped"] == 1  # the encrypted one: lost
    reasons = row["report"]["reasons"]
    assert "it is encrypted and the password is not known" in reasons
    assert reasons["it is encrypted and the password is not known"]["examples"][0]["detail"] == "C/secret.bin"
    assert row["report"]["collection"]["importBytes"] == len(EVTX) + len(HISTORY) + len(CHROME)
    # The only source of the incident is the zip: nothing was imported.
    listing = client.get("/api/incidents/co1/evidence/sources", headers=key).json()["sources"]
    assert [item["id"] for item in listing] == [answer["sourceId"]]
    assert (
        "/unpack",
        {"sha256": digest, "fileName": "triage.zip", "total": settings.COLLECTION_MAX_MB * 1024 * 1024},
    ) in [(route, {k: v for k, v in body.items() if k != "name"}) for route, body in worker.calls]


def test_the_members_are_paged_and_filtered(world):
    client, key, worker = world
    source_id = listed(client, key, worker)
    page = members_of(client, key, source_id)
    assert [m["n"] for m in page["members"]] == list(range(7)) and page["total"] == 7 and page["next"] is None
    assert page["counts"] == {
        "all": 7,
        "importable": 3,
        "imported": 0,
        "skipped": 2,
        "executables": 1,
        "unrecognised": 1,
        "byKind": {"browser": 1, "commands": 1, "eventlog": 1},
    }
    first = page["members"][0]
    assert (first["path"], first["fileName"], first["kind"], first["source"], first["host"], first["importable"]) == (
        "C/Windows/System32/winevt/Logs/Security.evtx",
        "Security.evtx",
        "eventlog",
        "evtx",
        "WKS-1",
        True,
    )
    assert first["imported"] is False and first["alreadyImported"] is False and first["sha256"] == sha(EVTX)
    by_name = {m["fileName"]: m for m in page["members"]}
    assert by_name["cmd.exe"]["executable"] and not by_name["cmd.exe"]["importable"]
    assert "archive inside" in by_name["inner.zip"]["skip"] and by_name["notes.txt"]["kind"] is None
    assert by_name["History"]["profile"] == "Profile 1" and by_name["ConsoleHost_history.txt"]["username"] == "bob"
    two = members_of(client, key, source_id, limit=3)
    assert [m["n"] for m in two["members"]] == [0, 1, 2] and two["next"] == "2" and two["total"] == 7
    three = members_of(client, key, source_id, limit=3, cursor=two["next"])
    assert [m["n"] for m in three["members"]] == [3, 4, 5] and three["next"] == "5"
    assert [m["n"] for m in members_of(client, key, source_id, status="importable")["members"]] == [0, 1, 2]
    assert [m["n"] for m in members_of(client, key, source_id, status="executables")["members"]] == [3]
    assert [m["n"] for m in members_of(client, key, source_id, status="skipped")["members"]] == [5, 6]
    assert [m["n"] for m in members_of(client, key, source_id, status="unrecognised")["members"]] == [4]
    assert [m["n"] for m in members_of(client, key, source_id, kind="browser,commands")["members"]] == [1, 2]
    assert [m["n"] for m in members_of(client, key, source_id, q="CHROME")["members"]] == [2]
    for bad in ({"status": "nothing"}, {"kind": "madeup"}, {"cursor": "x"}, {"limit": 100000}):
        assert client.get(
            f"/api/incidents/co1/evidence/collections/{source_id}", headers=key, params=bad
        ).status_code in (400, 422)
    other = client.get("/api/incidents/co1/evidence/collections/nothing", headers=key)
    assert other.status_code == 404


def test_a_collection_that_cannot_be_listed_fails_with_a_sentence_and_can_be_listed_again(world):
    client, key, worker = world
    data = b"PK\x03\x04 not really a zip"
    digest = sha(data)
    worker.zips[digest] = []
    worker.ends[digest] = {"error": "This is not a zip Nik can open (BadZipFile: File is not a zip file)"}
    worker.known[digest] = {"container": "zip", "kind": "collection", "source": "collection.zip"}
    answer = send(client, key, data, "broken.zip", {"kind": "collection"})
    row = client.get(f"/api/incidents/co1/evidence/sources/{answer['sourceId']}", headers=key).json()
    assert row["state"] == "failed" and "not a zip" in row["error"] and row["read"] == "failed"
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{row['id']}/import", headers=key, json={"all": True}
        ).status_code
        == 409
    )
    # The worker is better the next time.
    worker.ends[digest] = {}
    again_content = b"whoami from a listing that worked\n"
    worker.zips[digest] = [
        {"path": PS, "data": again_content, "kind": "commands", "source": "powershell", "parser": "history"}
    ]
    worker.content[sha(again_content)] = again_content
    again = client.post(f"/api/incidents/co1/evidence/sources/{row['id']}/again", headers=key)
    assert again.status_code == 202, again.text
    assert client.get(f"/api/incidents/co1/evidence/sources/{row['id']}", headers=key).json()["state"] == "listed"
    assert members_of(client, key, row["id"])["total"] == 1


def test_a_worker_that_stops_before_the_end_of_the_list_fails_the_collection(world):
    client, key, worker = world
    data, _digest = triage(worker, cut=True)
    answer = send(client, key, data, "cut.zip", {"kind": "collection"})
    row = client.get(f"/api/incidents/co1/evidence/sources/{answer['sourceId']}", headers=key).json()
    assert row["state"] == "failed" and "stopped before the end" in row["error"]


def test_a_collection_listed_in_part_says_so(world):
    client, key, worker = world
    source_id = listed(client, key, worker, unlisted=900, stopped="only the first 20000 members are listed")
    row = client.get(f"/api/incidents/co1/evidence/sources/{source_id}", headers=key).json()
    assert row["read"] == "partial" and row["inFile"] == 907
    assert row["members"]["unlisted"] == 900 and "first 20000" in row["members"]["stopped"]
    assert "the unpacking was cut" in row["report"]["notes"]


# --------------------------------------------------------------------------- #
# Importing                                                                   #
# --------------------------------------------------------------------------- #
def sources_of(client, key) -> dict[str, dict]:
    listing = client.get("/api/incidents/co1/evidence/sources", headers=key).json()["sources"]
    return {item["fileName"]: item for item in listing}


def test_the_chosen_members_become_sources_with_their_originals_and_are_read(world):
    client, key, worker = world
    source_id = listed(client, key, worker)
    chosen = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"members": [1]}
    )
    assert chosen.status_code == 202, chosen.text
    assert chosen.json()["selected"] == 1
    held = sources_of(client, key)
    history = held["ConsoleHost_history.txt"]
    assert (history["kind"], history["source"], history["state"], history["read"], history["kept"]) == (
        "commands",
        "powershell",
        "done",
        "complete",
        2,
    )
    assert (history["collectionId"], history["collectionName"], history["filePath"], history["username"]) == (
        source_id,
        "triage.zip",
        PS,
        "bob",
    )
    assert "Security.evtx" not in held and originals.has(sha(HISTORY)) and not originals.has(sha(EVTX))
    zip_row = client.get(f"/api/incidents/co1/evidence/sources/{source_id}", headers=key).json()
    importing = zip_row["report"]["collection"]["importing"]
    assert (zip_row["state"], zip_row["members"]["imported"], zip_row["kept"]) == ("listed", 1, 1)
    assert (
        importing["total"] == 1 and importing["done"] == 1 and importing["failed"] == 0 and importing["ended"] is True
    )
    page = members_of(client, key, source_id)
    member = page["members"][1]
    assert member["imported"] is True and member["sourceId"] == history["id"] and member["alreadyImported"] is False
    assert page["counts"]["imported"] == 1
    # The rest, by kind: the browser files only.
    done = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/import",
        headers=key,
        json={"all": True, "kinds": ["browser"]},
    )
    assert done.status_code == 202 and done.json()["selected"] == 1
    assert sources_of(client, key)["History"]["profile"] == "Profile 1"
    # All of it: the two already there are "already imported", and the collection is done.
    everything = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"all": True}
    )
    assert everything.status_code == 202 and everything.json()["selected"] == 3
    zip_row = client.get(f"/api/incidents/co1/evidence/sources/{source_id}", headers=key).json()
    assert (
        zip_row["state"] == "done"
        and zip_row["members"]["importing"]["already"] == 2
        and zip_row["members"]["imported"] == 3
    )
    assert len(sources_of(client, key)) == 4  # the zip and three files, none twice
    records = [r for r in _records(history["id"])]
    assert [r.summary for r in records] == ["whoami", "net user"]


def _records(source_id: str) -> list[EvidenceRecord]:
    with SessionLocal() as db:
        return list(
            db.scalars(select(EvidenceRecord).where(EvidenceRecord.source_id == source_id).order_by(EvidenceRecord.seq))
        )


def test_a_file_the_incident_already_holds_is_already_imported(world):
    client, key, worker = world
    # The same file, sent on its own before, in the same section and source.
    sent = send(client, key, HISTORY, "ConsoleHost_history.txt", {"kind": "commands", "source": "powershell"})
    worker.content[sha(HISTORY)] = HISTORY
    source_id = listed(client, key, worker)
    page = members_of(client, key, source_id)
    member = page["members"][1]
    assert member["imported"] is True and member["alreadyImported"] is True and member["sourceId"] == sent["sourceId"]
    started = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"members": [1]}
    )
    assert started.status_code == 202
    after = sources_of(client, key)
    assert len([item for item in after.values() if item["fileName"] == "ConsoleHost_history.txt"]) == 1
    zip_row = client.get(f"/api/incidents/co1/evidence/sources/{source_id}", headers=key).json()
    assert zip_row["members"]["importing"]["already"] == 1
    with SessionLocal() as db:
        assert db.get(EvidenceMember, (source_id, 1)).source_id == sent["sourceId"]


def test_programs_and_files_nik_does_not_read_are_not_imported(world):
    client, key, worker = world
    source_id = listed(client, key, worker)
    for numbers in ([3], [4], [5], [6], [99]):
        refused = client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"members": numbers}
        )
        assert refused.status_code == 409 and "None of the files chosen" in refused.json()["detail"], numbers
    assert (
        client.post(f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={}).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/import",
            headers=key,
            json={"all": True, "members": [0]},
        ).status_code
        == 400
    )
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/import",
            headers=key,
            json={"all": True, "kinds": ["x"]},
        ).status_code
        == 400
    )
    assert len(sources_of(client, key)) == 1
    assert not originals.has(sha(PROGRAM))


def test_an_import_stops_when_the_disk_has_no_room_and_says_so(world, monkeypatch):
    client, key, worker = world
    source_id = listed(client, key, worker)

    def no_room(needed, what="the file"):
        raise originals.EvidenceError("The store has 1 MB free and the file needs 2 MB: nothing was written")

    monkeypatch.setattr(originals, "room", no_room)
    refused = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"all": True}
    )
    assert refused.status_code == 409 and "nothing was written" in refused.json()["detail"]
    assert client.get(f"/api/incidents/co1/evidence/sources/{source_id}", headers=key).json()["state"] == "listed"


def a_zip_of(client, key, worker, files: dict[str, bytes]) -> str:
    """A collection of text files that are read as command histories, whose bytes no other test has kept."""
    members = [
        {
            "path": f"C/Users/u{number}/{name}",
            "data": data,
            "kind": "commands",
            "source": "powershell",
            "parser": "history",
        }
        for number, (name, data) in enumerate(files.items())
    ]
    zipped = b"PK a collection of the test: " + b",".join(name.encode() for name in files)
    digest = worker.zip(zipped, members)
    worker.known[digest] = {"container": "zip", "kind": "collection", "source": "collection.zip"}
    answer = send(client, key, zipped, "own.zip", {"kind": "collection"})
    assert answer["state"] == "complete"
    return answer["sourceId"]


def test_a_member_the_worker_cannot_give_is_counted_as_failed_and_the_others_go_on(world):
    client, key, worker = world
    files = {"a.txt": b"first of the failing test\n", "b.txt": b"second of the failing test\n", "c.txt": b"third one\n"}
    source_id = a_zip_of(client, key, worker, files)
    del worker.content[sha(files["a.txt"])]  # the worker no longer has the first one
    client.post(f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"all": True})
    zip_row = client.get(f"/api/incidents/co1/evidence/sources/{source_id}", headers=key).json()
    importing = zip_row["members"]["importing"]
    assert importing["failed"] == 1 and "no such member" in importing["error"] and importing["done"] == 3
    assert zip_row["members"]["imported"] == 2 and zip_row["state"] == "listed"
    assert sorted(sources_of(client, key)) == ["b.txt", "c.txt", "own.zip"]


def test_deleting_the_collection_keeps_the_files_it_gave(world):
    client, key, worker = world
    source_id = listed(client, key, worker)
    client.post(f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"all": True})
    assert len(sources_of(client, key)) == 4
    removed = client.delete(f"/api/incidents/co1/evidence/sources/{source_id}", headers=key)
    assert removed.status_code == 200 and removed.json() == {"removed": 1}
    held = sources_of(client, key)
    assert sorted(held) == ["ConsoleHost_history.txt", "History", "Security.evtx"]
    assert all(item["collectionId"] is None and item["filePath"] for item in held.values())
    with SessionLocal() as db:
        assert db.scalar(select(EvidenceMember).limit(1)) is None


# --------------------------------------------------------------------------- #
# Analyse                                                                     #
# --------------------------------------------------------------------------- #
def test_a_program_of_the_collection_enters_malware_analysis_when_asked(world):
    client, key, worker = world
    source_id = listed(client, key, worker)
    refused = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/analyse", headers=key, json={"member": 1}
    )
    assert refused.status_code == 409
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/analyse", headers=key, json={"member": 99}
        ).status_code
        == 404
    )
    answer = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/analyse", headers=key, json={"member": 3}
    )
    assert answer.status_code == 201, answer.text
    sample = answer.json()["sample"]
    assert sample["sha256"] == sha(PROGRAM) and sample["fileName"] == "cmd.exe"
    incident = client.get("/api/incidents/co1", headers=key).json()
    assert [item["sha256"] for item in incident["data"]["malware"]["samples"]] == [sha(PROGRAM)]
    with SessionLocal() as db:
        relation = db.scalars(select(ArtifactRelation)).all()
        zipped = db.get(EvidenceSource, source_id).sha256
        assert [(r.parent_id, r.relation) for r in relation] == [(f"hostfile-{zipped}", "extracted")]
    # Nothing of the collection was imported as evidence by it.
    assert len(sources_of(client, key)) == 1


def test_a_wrong_file_from_the_worker_is_not_analysed(world):
    client, key, worker = world
    source_id = listed(client, key, worker)
    worker.content[sha(PROGRAM)] = b"MZ another file"
    answer = client.post(
        f"/api/incidents/co1/evidence/collections/{source_id}/analyse", headers=key, json={"member": 3}
    )
    assert answer.status_code == 502 and "not the one the list names" in answer.json()["detail"]


def test_analysing_needs_the_right_to_write_and_a_member_within_the_sample_limit(world, admin, monkeypatch):
    client, key, worker = world
    source_id = listed(client, key, worker)
    viewer = make_key(admin, roles=["viewer"])
    assert client.get(f"/api/incidents/co1/evidence/collections/{source_id}", headers=viewer).status_code == 200
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/analyse", headers=viewer, json={"member": 3}
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=viewer, json={"all": True}
        ).status_code
        == 403
    )
    monkeypatch.setattr(settings, "SAMPLE_MAX_MB", 0)
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/analyse", headers=key, json={"member": 3}
        ).status_code
        == 413
    )


def test_an_archived_incident_takes_nothing_from_a_collection(world):
    client, key, worker = world
    source_id = listed(client, key, worker)
    with SessionLocal() as db:
        db.get(Incident, "co1").archived_at = "2026-11-01T00:00:00Z"
        db.commit()
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/import", headers=key, json={"all": True}
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/api/incidents/co1/evidence/collections/{source_id}/analyse", headers=key, json={"member": 3}
        ).status_code
        == 409
    )
    data, _digest = triage(worker, extra=1)
    refused = client.post(
        "/api/uploads", headers=key, json={"incidentId": "co1", "fileName": "a.zip", "size": len(data), "params": {}}
    )
    assert refused.status_code == 409
    assert client.get(f"/api/incidents/co1/evidence/collections/{source_id}", headers=key).status_code == 200


# --------------------------------------------------------------------------- #
# A file sent without a section                                               #
# --------------------------------------------------------------------------- #
def test_a_known_bare_file_is_filed_under_what_it_is(world):
    client, key, worker = world
    worker.known[sha(HISTORY)] = {"parser": "history", "version": "1", "kind": "commands", "source": "powershell"}
    worker.content[sha(HISTORY)] = HISTORY
    answer = send(client, key, HISTORY, "ConsoleHost_history.txt", {"kind": "auto"})
    assert (answer["state"], answer["recognised"], answer["kind"], answer["source"]) == (
        "complete",
        True,
        "commands",
        "powershell",
    )
    assert answer["sourceId"]
    row = sources_of(client, key)["ConsoleHost_history.txt"]
    assert (row["id"], row["state"], row["kept"]) == (answer["sourceId"], "done", 2)
    # With no params at all it is the same.
    again = send(client, key, HISTORY, "ConsoleHost_history.txt", None)
    assert again["sourceId"] == answer["sourceId"] and again["duplicate"] is True


def test_a_zip_sent_without_a_section_is_a_collection(world):
    client, key, worker = world
    data, digest = triage(worker)
    worker.known[digest] = {"container": "zip", "kind": "collection", "source": "collection.zip"}
    answer = send(client, key, data, "anything.zip", {"kind": "auto"})
    assert (answer["recognised"], answer["kind"], answer["source"]) == (True, "collection", "collection.zip")
    row = client.get(f"/api/incidents/co1/evidence/sources/{answer['sourceId']}", headers=key).json()
    assert row["state"] == "listed" and row["members"]["recognised"] == 3


def test_a_plaso_export_is_a_source_of_the_collection_section(world):
    client, key, worker = world
    data = b'{"data_type": "fs:stat", "timestamp": 1}\n'
    worker.known[sha(data)] = {"parser": "plaso", "version": "1", "kind": "collection", "source": "plaso.jsonl"}
    answer = send(client, key, data, "timeline.jsonl", {"kind": "collection"})
    assert (answer["kind"], answer["source"], answer["recognised"]) == ("collection", "plaso.jsonl", True)
    row = sources_of(client, key)["timeline.jsonl"]
    assert row["state"] in ("done", "failed", "queued", "parsing") and row["members"] is None
    assert ("/parse", "collection") in [(route, body.get("kind")) for route, body in worker.calls]


def test_a_file_nothing_reads_is_refused_with_a_sentence_and_kept_nowhere(world):
    client, key, worker = world
    sentence = "This is a VHDX disk image. Nik reads files, not disk images. Mount the image and send a zip"
    data = b"vhdxfile" + b"\x00" * 64
    worker.known[sha(data)] = {"refused": sentence}
    answer = send(client, key, data, "disk.vhdx", {"kind": "auto"})
    assert (answer["state"], answer["recognised"], answer["sourceId"], answer["error"]) == (
        "aborted",
        False,
        None,
        sentence,
    )
    assert not originals.has(sha(data)) and sources_of(client, key) == {}
    stranger = b"\x00\x01 nothing Nik reads"
    answer = send(client, key, stranger, "x.dat", {})
    assert (
        answer["recognised"] is False
        and "No parser of Nik reads" in answer["error"]
        and not originals.has(sha(stranger))
    )


def test_a_refused_file_the_store_already_held_is_not_removed(world):
    client, key, worker = world
    kept = originals.keep_bytes(b"held before, and an incident holds it too")
    data = b"held before, and an incident holds it too"
    answer = send(client, key, data, "x.dat", {"kind": "auto"})
    assert answer["recognised"] is False and originals.has(kept)


def test_a_known_bare_file_larger_than_a_file_may_be_is_refused(world, monkeypatch):
    client, key, worker = world
    monkeypatch.setattr(settings, "EVIDENCE_MAX_MB", 0)
    data = b"a history too large for the limit\n"
    worker.known[sha(data)] = {"parser": "history", "version": "1", "kind": "commands", "source": "powershell"}
    answer = send(client, key, data, "ConsoleHost_history.txt", {"kind": "auto"})
    assert answer["recognised"] is False and "larger than the limit" in answer["error"] and answer["sourceId"] is None
    assert not originals.has(sha(data))


def test_the_limit_of_a_file_that_may_be_a_collection_is_the_collection_limit(world, monkeypatch):
    client, key, worker = world
    monkeypatch.setattr(settings, "COLLECTION_MAX_MB", 1)
    monkeypatch.setattr(settings, "EVIDENCE_MAX_MB", 1)
    body = {"incidentId": "co1", "fileName": "a.zip", "size": 2 * 1024 * 1024, "params": {"kind": "auto"}}
    assert client.post("/api/uploads", headers=key, json=body).status_code == 413
    monkeypatch.setattr(settings, "COLLECTION_MAX_MB", 5)
    assert client.post("/api/uploads", headers=key, json=body).status_code == 201
    assert client.post("/api/uploads", headers=key, json={**body, "params": {"kind": "nonsense"}}).status_code == 400


def test_without_a_worker_only_a_zip_is_known(world, monkeypatch):
    client, key, worker = world
    monkeypatch.setattr(settings, "FORENSICS_URL", "")
    answer = send(client, key, b"plain text", "notes.txt", {"kind": "auto"})
    assert answer["recognised"] is False and "not configured" in answer["error"]
    data, _digest = triage(worker)
    zipped = send(client, key, data, "triage.zip", {"kind": "auto"})
    assert zipped["recognised"] is True and zipped["source"] == "collection.zip"
    row = client.get(f"/api/incidents/co1/evidence/sources/{zipped['sourceId']}", headers=key).json()
    assert row["state"] == "failed" and "not configured" in row["error"]


# --------------------------------------------------------------------------- #
# The records a file says are of another section                              #
# --------------------------------------------------------------------------- #
def test_a_record_of_another_section_and_source_than_its_file_is_kept_as_such(world, monkeypatch):
    client, key, worker = world
    data = b'{"data_type": "x"}\n'
    digest = originals.keep_bytes(data)
    with SessionLocal() as db:
        row = imports.accept(
            db, "co1", digest, len(data), "timeline.jsonl", {"kind": "collection", "source": "plaso.jsonl"}, "tester"
        )
        source_id = row.id
        db.commit()

    def said(sha256, body, job, route="/parse"):
        yield {"t": "source", "parser": "plaso", "version": "1", "kind": "collection", "source": "plaso.jsonl"}
        base = {
            "type": "event",
            "ts": 1_700_000_000_000,
            "data": {},
            "loc": {},
            "trunc": False,
            "ioc": [],
            "summary": "s",
        }
        yield {
            **base,
            "t": "r",
            "key": "evtx:WKS:Security:1",
            "seq": 0,
            "k": "eventlog",
            "src": "evtx",
            "channel": "Security",
            "event_id": 4624,
        }
        yield {**base, "t": "r", "key": "plaso:other:1", "seq": 1}
        yield {**base, "t": "r", "key": "plaso:bad:1", "seq": 2, "k": "not-a-section", "src": ""}
        yield {
            **base,
            "t": "r",
            "key": "plaso:browser:1",
            "seq": 3,
            "k": "browser",
            "src": "edge.history",
            "type": "visit",
        }
        yield {"t": "end", "in_file": 4, "read": 4, "first_ts": None, "last_ts": None}

    monkeypatch.setattr(parse, "_events", said)
    parse.read(source_id)
    rows = {r.key: r for r in _records(source_id)}
    assert (rows["evtx:WKS:Security:1"].kind, rows["evtx:WKS:Security:1"].source) == ("eventlog", "evtx")
    assert (rows["plaso:other:1"].kind, rows["plaso:other:1"].source) == ("collection", None)
    assert (rows["plaso:bad:1"].kind, rows["plaso:bad:1"].source) == ("collection", None)
    assert (rows["plaso:browser:1"].kind, rows["plaso:browser:1"].source) == ("browser", "edge.history")

    def count(**query) -> int:
        return client.get("/api/incidents/co1/evidence/records", headers=key, params=query).json()["count"]

    assert count(kind="eventlog") == 1 and count(kind="browser") == 1 and count(kind="collection") == 2
    assert count(source="evtx") == 1 and count(source="edge.history") == 1 and count(source="plaso.jsonl") == 2
    assert count(sourcePrefix="edge") == 1 and count(sourcePrefix="plaso") == 2
    stacked = client.get("/api/incidents/co1/evidence/stack", headers=key, params={"field": "source"}).json()
    assert {item["value"]: item["count"] for item in stacked["values"]} == {
        "evtx": 1,
        "edge.history": 1,
        "plaso.jsonl": 2,
    }
