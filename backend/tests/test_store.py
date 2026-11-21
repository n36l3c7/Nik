"""The files of the store through core/store.py: sealed on the disk, read back whole or in ranges,
refused loudly when they are not what was written, and handed to a process that holds no key."""

from __future__ import annotations

import hashlib
import io
import json
import os
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from fastapi import Request
from fastapi.testclient import TestClient
from sqlalchemy import select

from app import artifact_jobs, store_handover, store_seal
from app.core import sealed, store, vault
from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import ArtifactJob, AuditEntry, Notification
from app.malware import samples
from tests.conftest import make_key
from tests.test_malware import fake_pe

MARKER = b"a harmless fixture, and a marker nobody finds on the disk: NIK-TEST-PLAINTEXT"


@pytest.fixture()
def root(tmp_path, monkeypatch):
    """A store of its own for the test."""
    folder = tmp_path / "store"
    folder.mkdir()
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(folder))
    return folder


def content(size: int, seed: int = 0) -> bytes:
    return (MARKER + hashlib.shake_256(b"%d" % seed).digest(max(0, size - len(MARKER))))[:size]


# --------------------------------------------------------------------------- #
# Writing and reading                                                         #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("size", [0, 1, 100, sealed.CHUNK - 1, sealed.CHUNK, sealed.CHUNK + 1, 3 * sealed.CHUNK + 7])
def test_a_file_is_sealed_on_the_disk_and_comes_back_as_it_was(root, size):
    data, path = content(size), root / "_captures" / "c1" / "capture.pcap"
    path.parent.mkdir(parents=True)
    assert store.write(path, data) == size
    raw = path.read_bytes()
    assert raw.startswith(sealed.MAGIC) and len(raw) == sealed.sealed_size(size)
    assert MARKER not in raw
    assert store.read_bytes(path) == data and store.size(path) == size and store.is_sealed(path)
    assert not path.with_name(path.name + store.PART).exists()
    if os.name == "posix":
        assert path.stat().st_mode & 0o777 == 0o600
    with store.open(path) as handle:
        assert handle.seek(0, os.SEEK_END) == size


def test_it_is_written_in_pieces_and_read_in_pieces(root):
    data = content(5 * sealed.CHUNK + 123)
    pieces = [data[start : start + 70_001] for start in range(0, len(data), 70_001)]
    assert store.write(root / "big.bin", iter(pieces)) == len(data)
    assert b"".join(store.pieces(root / "big.bin", piece=50_000)) == data
    for start, end in (
        (0, 10),
        (sealed.CHUNK - 3, sealed.CHUNK + 3),
        (len(data) - 5, None),
        (100, 100),
        (7, 4 * sealed.CHUNK),
    ):
        assert b"".join(store.pieces(root / "big.bin", start, end)) == data[start:end]
    with store.writing(root / "streamed.bin") as out:
        for piece in pieces:
            out.write(piece)
        assert out.size == len(data)
    assert store.read_text(root / "streamed.bin", "latin-1").encode("latin-1") == data
    store.write_text(root / "t.json", '{"è": 1}')
    assert json.loads(store.read_text(root / "t.json")) == {"è": 1}


def test_a_write_that_fails_leaves_what_was_there_and_nothing_else(root):
    path = root / ("a" * 64 + ".bin")
    store.write(path, b"the first content")

    def pieces():
        yield b"half of the new content"
        raise RuntimeError("the upload broke")

    with pytest.raises(RuntimeError):
        store.write(path, pieces())
    assert store.read_bytes(path) == b"the first content"
    assert sorted(p.name for p in root.iterdir()) == [path.name]
    # Written again: a new key, nothing of the bytes on the disk is the same.
    before = path.read_bytes()
    store.write(path, b"the first content")
    assert (
        path.read_bytes()[sealed.PREFIX :] != before[sealed.PREFIX :] and store.read_bytes(path) == b"the first content"
    )


def test_a_file_is_bound_to_its_place_in_the_store(root):
    one, two = root / ("a" * 64 + ".bin"), root / ("b" * 64 + ".bin")
    store.write(one, b"the evidence of one")
    store.write(two, b"the evidence of the other")
    assert (
        store.name_of(one) == "a" * 64 + ".bin"
        and store.name_of(root / "_captures" / "x" / "log.jsonl") == "_captures/x/log.jsonl"
    )
    # Put in the place of another, by whoever can write to the disk: refused.
    os.replace(two, one)
    with pytest.raises(store.DamagedFile, match="in the place of another"):
        store.read_bytes(one)
    # The whole store moved elsewhere keeps its names.
    moved = root.with_name("moved")
    store.write(two, b"kept")
    root.rename(moved)
    settings.SAMPLE_STORE = str(moved)
    try:
        assert store.read_bytes(moved / two.name) == b"kept"
    finally:
        settings.SAMPLE_STORE = str(root)


# --------------------------------------------------------------------------- #
# What does not open                                                          #
# --------------------------------------------------------------------------- #
def _flip(path, place: int) -> None:
    raw = bytearray(path.read_bytes())
    raw[place] ^= 0x40
    path.write_bytes(bytes(raw))


def test_a_damaged_file_is_refused_named_and_reported_once(client, root):
    reported = []
    store.report_damaged, kept = (lambda name, reason: reported.append((name, reason))), store.report_damaged
    try:
        path = root / ("c" * 64 + ".bin")
        store.write(path, content(3 * sealed.CHUNK))
        _flip(path, sealed.HEADER + sealed.CHUNK + 500)  # in the second chunk
        with store.open(path) as handle:
            assert handle.read(100) == content(3 * sealed.CHUNK)[:100]  # the first chunk is whole
            with pytest.raises(store.DamagedFile) as refused:
                handle.read()
        said = str(refused.value)
        assert said.startswith(f"The file {'c' * 64}.bin of the store is damaged and is not served")
        # What only knows that reading may fail treats it as a file that cannot be read.
        assert isinstance(refused.value, OSError) and isinstance(refused.value, store.SealError)
        with pytest.raises(store.DamagedFile):
            store.read_bytes(path)
        assert [name for name, _ in reported] == [path.name, path.name] and "changed" in reported[0][1]
        # Cut short: refused when it is opened, before a byte is given.
        store.write(path, content(3 * sealed.CHUNK))
        path.write_bytes(path.read_bytes()[: sealed.HEADER + sealed.CHUNK + sealed.TAG])
        with pytest.raises(store.DamagedFile, match="cut short"):
            store.open(path)
    finally:
        store.report_damaged = kept


def test_a_file_under_a_store_key_the_server_does_not_hold_says_so(root, monkeypatch):
    path = root / "f.bin"
    store.write(path, b"sealed under the key of this server")
    monkeypatch.setattr(settings, "STORE_KEY", "another store key, long enough to be one")
    with pytest.raises(store.WrongKeyFile, match="cannot be opened and is not served: it was sealed under a store key"):
        store.read_bytes(path)
    # With the earlier key beside the new one (a change of key in progress) it opens.
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", ["dev-insecure-store-key-change-me"])
    assert store.read_bytes(path) == b"sealed under the key of this server"


def test_the_administrators_are_told_of_a_damaged_file_and_the_audit_log_has_it(admin: TestClient, root):
    analyst = make_key(admin, roles=["analyst"])
    admin.post("/api/incidents", headers=analyst, json={"id": "dmg", "name": "damaged"})
    data = fake_pe(payload=MARKER)
    sha = admin.post("/api/incidents/dmg/samples", headers=analyst, files={"file": ("s.exe", data)}).json()["sample"][
        "sha256"
    ]
    assert admin.get(f"/api/samples/{sha}/download", headers=analyst).status_code == 200
    _flip(samples.sample_path(sha), sealed.HEADER + 40)

    for route in (f"/api/samples/{sha}/download", f"/api/samples/{sha}/strings"):
        answer = admin.get(route, headers=analyst)
        # Never served as if it were fine, and never half of it: a sentence, and a code of its own.
        assert answer.status_code == 500 and answer.json()["code"] == "file_damaged"
        assert answer.json()["detail"].startswith(f"The file {sha}.bin of the store is damaged and is not served")
        assert MARKER not in answer.content
    assert admin.post(f"/api/samples/{sha}/reanalyse", headers=analyst).status_code == 500

    with SessionLocal() as db:
        lines = db.scalars(select(AuditEntry).where(AuditEntry.action == "store.damaged")).all()
        notices = db.scalars(select(Notification).where(Notification.kind == "store.damaged")).all()
    # Once for the file, however many times it was asked for.
    assert len(lines) == 1 and lines[0].actor == "system" and lines[0].target == f"{sha}.bin"
    assert f"The file {sha}.bin of the store is damaged" in lines[0].details
    assert [(n.username, n.link) for n in notices] == [("admin", "/settings/system/storage")]
    assert "Put it back from a backup" in notices[0].text
    shown = admin.get("/api/storage/encryption").json()["damaged"]
    assert [entry["name"] for entry in shown] == [f"{sha}.bin"] and shown[0]["reason"]


def test_a_file_in_clear_is_read_until_the_store_is_sealed_and_refused_after(client, root):
    """A store from before 6.8 is read as it is while it is converted; once every file is sealed, a
    file in clear is not one Nik wrote."""
    path = root / ("d" * 64 + ".bin")
    path.write_bytes(b"MZ, as a version before 6.8 left it")
    assert store.read_bytes(path) == b"MZ, as a version before 6.8 left it" and not store.is_sealed(path)
    assert store.size(path) == 35 and b"".join(store.pieces(path, 4, 6)) == b"as"
    store_seal._update(state=store_seal.SEALED, since="2026-11-20T00:00:00Z")
    store_seal.forget()
    with pytest.raises(store.DamagedFile, match="it is in clear, and every file of this store was sealed"):
        store.read_bytes(path)
    with SessionLocal() as db:
        assert db.scalars(select(AuditEntry).where(AuditEntry.action == "store.damaged")).one().target == path.name


# --------------------------------------------------------------------------- #
# Downloads                                                                   #
# --------------------------------------------------------------------------- #
def test_a_download_is_streamed_with_its_size_and_one_range_is_served(admin: TestClient, root):
    from app.core.files import stored_response
    from app.main import app

    data = content(2 * sealed.CHUNK + 999, seed=7)
    store.write(root / "x.bin", data)

    @app.get("/api/test-only/stored")
    def stored(request: Request):
        return stored_response(
            root / "x.bin", "application/octet-stream", "évidence.bin", range_header=request.headers.get("range")
        )

    try:
        whole = admin.get("/api/test-only/stored")
        assert whole.status_code == 200 and whole.content == data
        assert whole.headers["content-length"] == str(len(data)) and whole.headers["accept-ranges"] == "bytes"
        assert "filename*=UTF-8''%C3%A9vidence.bin" in whole.headers["content-disposition"]
        for sent, start, end in (
            ("bytes=0-9", 0, 10),
            (f"bytes={sealed.CHUNK - 2}-{sealed.CHUNK + 2}", sealed.CHUNK - 2, sealed.CHUNK + 3),
            ("bytes=100-", 100, len(data)),
            ("bytes=-50", len(data) - 50, len(data)),
            (f"bytes=5-{len(data) * 2}", 5, len(data)),
        ):
            part = admin.get("/api/test-only/stored", headers={"Range": sent})
            assert part.status_code == 206 and part.content == data[start:end], sent
            assert part.headers["content-range"] == f"bytes {start}-{end - 1}/{len(data)}"
        assert admin.get("/api/test-only/stored", headers={"Range": f"bytes={len(data)}-"}).status_code == 416
        assert admin.get("/api/test-only/stored", headers={"Range": "lines=1-2"}).status_code == 200
    finally:
        app.router.routes[:] = [
            route for route in app.router.routes if getattr(route, "path", "") != "/api/test-only/stored"
        ]


# --------------------------------------------------------------------------- #
# Deleting                                                                    #
# --------------------------------------------------------------------------- #
def test_deleting_removes_the_file_and_its_key_with_it(root):
    path = root / ("e" * 64 + ".bin")
    store.write(path, b"evidence")
    head = path.read_bytes()[: sealed.HEADER]
    store.remove(path)
    assert not path.exists()
    store.remove(path)  # again: nothing to do
    # The key of the file was in its head and nowhere else: nothing the server keeps opens a copy of the rest.
    assert head not in b"".join(p.read_bytes() for p in root.rglob("*") if p.is_file())
    folder = root / "_captures" / ("f" * 32)
    folder.mkdir(parents=True)
    store.write(folder / "capture.pcap", b"1")
    store.write(folder / "log.jsonl", b"2")
    store.remove_tree(folder)
    assert not folder.exists()


# --------------------------------------------------------------------------- #
# A process that holds no store key                                           #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def keyless(monkeypatch):
    """This process as the automation worker is: no store key, no store, the API to ask."""
    monkeypatch.setattr(settings, "STORE_KEY", "")
    monkeypatch.setattr(settings, "STORE_KEY_PREVIOUS", [])
    return monkeypatch


def test_the_proof_of_a_request_is_good_for_its_file_and_for_two_minutes(monkeypatch):
    sha = "a" * 64
    sent = store_handover.token("sample", sha, now=1000)
    assert store_handover.verify("sample", sha, sent, now=1000)
    assert store_handover.verify("sample", sha, sent, now=1000 + store_handover.GOOD_FOR)
    assert not store_handover.verify("sample", sha, sent, now=1000 + store_handover.GOOD_FOR + 1)
    assert not store_handover.verify("sample", sha, sent, now=1000 - store_handover.GOOD_FOR - 1)
    assert not store_handover.verify("mail", sha, sent, now=1000)
    assert not store_handover.verify("sample", "b" * 64, sent, now=1000)
    for wrong in ("", "1000", "1000.", "x." + "0" * 64, sent[:-1] + ("0" if sent[-1] != "0" else "1"), sent + "0"):
        assert not store_handover.verify("sample", sha, wrong, now=1000)
    # Made under another SECRET_KEY: refused, unless that key is the earlier one of a change in progress.
    monkeypatch.setattr(settings, "SECRET_KEY", "the new key of the server")
    assert not store_handover.verify("sample", sha, sent, now=1000)
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", ["dev-insecure-change-me"])
    assert store_handover.verify("sample", sha, sent, now=1000)
    assert settings.SECRET_KEY not in sent and "dev-insecure-change-me" not in sent


def test_the_api_hands_a_file_only_to_who_proves_it_is_a_process_of_the_server(admin: TestClient, root):
    data = content(sealed.CHUNK + 5, seed=3)
    sha = hashlib.sha256(data).hexdigest()
    samples.write_sample(sha, data)
    samples.write_mail(sha, b"From: a@example.test\n\nhello\n")
    anybody = TestClient(admin.app)
    for headers in (
        {},
        {store_handover.HEADER: "nonsense"},
        {store_handover.HEADER: store_handover.token("mail", sha)},
    ):
        refused = anybody.get(f"/api/internal/store/sample/{sha}", headers=headers)
        # As if the route did not exist: nothing says a file is there.
        assert refused.status_code == 404 and refused.json() == {"detail": "Not Found"}
    # An administrator's session, or a key, is not the proof either.
    assert admin.get(f"/api/internal/store/sample/{sha}").status_code == 404
    assert (
        anybody.get(
            f"/api/internal/store/other/{sha}", headers={store_handover.HEADER: store_handover.token("other", sha)}
        ).status_code
        == 404
    )
    given = anybody.get(
        f"/api/internal/store/sample/{sha}", headers={store_handover.HEADER: store_handover.token("sample", sha)}
    )
    assert given.status_code == 200 and given.content == data and given.headers["content-length"] == str(len(data))
    mail = anybody.get(
        f"/api/internal/store/mail/{sha}", headers={store_handover.HEADER: store_handover.token("mail", sha)}
    )
    assert mail.content == b"From: a@example.test\n\nhello\n"
    missing = "9" * 64
    answer = anybody.get(
        f"/api/internal/store/sample/{missing}",
        headers={store_handover.HEADER: store_handover.token("sample", missing)},
    )
    assert answer.status_code == 404 and answer.json()["detail"] == "The file is not in the store"
    assert "/api/internal/store/{kind}/{ref}" not in json.dumps(admin.get("/api/openapi.json").json())


class _Api(BaseHTTPRequestHandler):
    """What answers in the place of the API process: ``answers`` maps a path to (status, headers, body)."""

    answers: dict = {}
    seen: list = []

    def do_GET(self):  # noqa: N802 - http.server naming
        type(self).seen.append((self.path, self.headers.get(store_handover.HEADER, "")))
        status, headers, body = type(self).answers.get(
            self.path, (404, {}, b'{"detail": "The file is not in the store"}')
        )
        self.send_response(status)
        for name, value in {"Content-Length": str(len(body)), **headers}.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture()
def api_process(keyless):
    _Api.answers, _Api.seen = {}, []
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Api)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    keyless.setattr(settings, "STORE_API_URL", f"http://127.0.0.1:{httpd.server_address[1]}")
    yield _Api
    httpd.shutdown()


def test_a_process_without_the_key_asks_the_api_for_a_sample_and_checks_what_it_gets(api_process):
    data = content(4000, seed=9)
    sha = hashlib.sha256(data).hexdigest()
    api_process.answers[f"/api/internal/store/sample/{sha}"] = (200, {}, data)
    assert not store.local() and not samples.store_writable()
    assert samples.read_sample(sha) == data
    path, proof = api_process.seen[0]
    assert path == f"/api/internal/store/sample/{sha}" and store_handover.verify("sample", sha, proof)
    api_process.answers[f"/api/internal/store/mail/{sha}"] = (200, {}, data)
    assert samples.read_mail(sha) == data

    # Not there: the error every reader of the store already knows.
    with pytest.raises(FileNotFoundError):
        samples.read_sample("0" * 64)
    # Another file than the one asked for is not taken.
    other = hashlib.sha256(b"other").hexdigest()
    api_process.answers[f"/api/internal/store/sample/{other}"] = (200, {}, data)
    with pytest.raises(store_handover.NotServed, match="not the one that was asked for"):
        samples.read_sample(other)
    # The API found it damaged: its sentence comes through.
    api_process.answers[f"/api/internal/store/sample/{sha}"] = (
        500,
        {},
        json.dumps(
            {"detail": f"The file {sha}.bin of the store is damaged and is not served: it was cut short"}
        ).encode(),
    )
    with pytest.raises(store_handover.NotServed, match="is damaged and is not served"):
        samples.read_sample(sha)
    assert issubclass(store_handover.NotServed, OSError)


def test_a_process_without_the_key_and_without_an_api_to_ask_says_so(keyless):
    keyless.setattr(settings, "STORE_API_URL", "")
    with pytest.raises(store_handover.NotServed, match="NIK_STORE_API_URL"):
        samples.read_sample("a" * 64)
    keyless.setattr(settings, "STORE_API_URL", "http://127.0.0.1:9")
    with pytest.raises(store_handover.NotServed, match="could not be asked"):
        samples.read_sample("a" * 64)
    with pytest.raises(store.SealError, match="does not hold the store key"):
        store.keyring()


def test_a_process_without_the_store_asks_the_api_to_delete_and_the_api_does(client, root, monkeypatch):
    sha = hashlib.sha256(b"to delete").hexdigest()
    samples.write_sample(sha, b"to delete")
    samples.write_mail(sha, b"a mail to delete")
    folder = root / "_captures" / ("a" * 32)
    folder.mkdir(parents=True)
    store.write(folder / "capture.pcap", b"a capture to delete")
    kept = root / ("b" * 64 + ".bin")
    store.write(kept, b"kept")

    from app.network import store as captures

    monkeypatch.setattr(settings, "STORE_KEY", "")
    samples.delete_sample(sha)
    samples.delete_mail(sha)
    captures.remove("a" * 32)
    monkeypatch.undo()
    monkeypatch.setattr(settings, "SAMPLE_STORE", str(root))
    # Nothing was touched by the process that asked: it cannot.
    assert samples.sample_path(sha).exists() and folder.exists()
    with SessionLocal() as db:
        asked = db.scalars(
            select(ArtifactJob).where(ArtifactJob.kind == "remove").order_by(ArtifactJob.created_epoch)
        ).all()
        assert [job.params["names"] for job in asked] == [[f"{sha}.bin"], [f"{sha}.mail"], ["_captures/" + "a" * 32]]
    # A file to delete is deleted however late the API process looks.
    assert artifact_jobs.run_due(threads=False, now=asked[0].created_epoch + artifact_jobs.TAKE_WITHIN * 10) == 3
    assert not samples.sample_path(sha).exists() and not samples.mail_path(sha).exists() and not folder.exists()
    assert store.read_bytes(kept) == b"kept"
    with SessionLocal() as db:
        assert {job.status for job in db.scalars(select(ArtifactJob))} == {"done"}


@pytest.mark.parametrize("name", ["../outside.bin", "_captures/../../outside.bin", ".", ""])
def test_a_removal_that_would_leave_the_store_is_not_followed(client, root, name):
    outside = root.parent / "outside.bin"
    outside.write_bytes(b"not a file of the store")
    with SessionLocal() as db:
        job = artifact_jobs.ask(db, "remove", {"names": [name]}, "nik", "", 0, 1000.0)
        db.commit()
        job_id = job.id
    artifact_jobs.run_due(threads=False, now=1000.0)
    with SessionLocal() as db:
        done = db.get(ArtifactJob, job_id)
        assert done.status == "error" and done.error == "The file to delete is not a file of the store"
    assert outside.read_bytes() == b"not a file of the store" and root.is_dir()
    # What the worker itself asks never names a way out.
    store_handover.ask_removal(["../x", "/etc/passwd", ".hidden"])
    with SessionLocal() as db:
        assert db.scalars(select(ArtifactJob).where(ArtifactJob.status == "queued")).all() == []


# --------------------------------------------------------------------------- #
# Bytes that cross the database between two processes                         #
# --------------------------------------------------------------------------- #
def test_bytes_left_in_the_database_for_another_process_are_encrypted(monkeypatch):
    data = MARKER * 10
    sealed_part = vault.seal_bytes(data, b"artifact job parts", b"job:0")
    assert sealed_part.startswith(vault.TRANSIT) and MARKER not in sealed_part and len(sealed_part) == len(data) + 32
    assert vault.open_bytes(sealed_part, b"artifact job parts", b"job:0") == data
    assert vault.seal_bytes(data, b"artifact job parts", b"job:0") != sealed_part  # a nonce of its own each time
    for purpose, bound in ((b"artifact job parts", b"job:1"), (b"something else", b"job:0")):
        with pytest.raises(ValueError, match="cannot be read"):
            vault.open_bytes(sealed_part, purpose, bound)
    changed = bytearray(sealed_part)
    changed[-1] ^= 1
    with pytest.raises(ValueError):
        vault.open_bytes(bytes(changed), b"artifact job parts", b"job:0")
    # What a process of the version before left there in clear, during an upgrade, is taken as it is.
    assert vault.open_bytes(b"MZ in clear", b"artifact job parts", b"job:0") == b"MZ in clear"
    # SECRET_KEY changed while a file was on its way: the earlier key still opens it.
    monkeypatch.setattr(settings, "SECRET_KEY", "the new key of the server")
    with pytest.raises(ValueError):
        vault.open_bytes(sealed_part, b"artifact job parts", b"job:0")
    monkeypatch.setattr(settings, "SECRET_KEY_PREVIOUS", ["dev-insecure-change-me"])
    assert vault.open_bytes(sealed_part, b"artifact job parts", b"job:0") == data


def test_a_file_handed_over_through_the_database_is_never_there_in_clear(client, root):
    data = content(3000, seed=4)
    with SessionLocal() as db:
        job = artifact_jobs.ask(db, "store", {"name": "kept.bin"}, "nik", "", 0, 1000.0, data)
        db.commit()
        rows = db.scalars(
            select(artifact_jobs.ArtifactJobPart).where(artifact_jobs.ArtifactJobPart.job_id == job.id)
        ).all()
        assert rows and all(MARKER not in bytes(row.data) for row in rows)
        assert artifact_jobs.carried(db, job.id) == data
        # A part put under another job, or in another place of the file, does not open.
        other = artifact_jobs.ask(db, "store", {"name": "other.bin"}, "nik", "", 0, 1001.0, content(3000, seed=5))
        db.flush()
        theirs = db.scalars(
            select(artifact_jobs.ArtifactJobPart).where(artifact_jobs.ArtifactJobPart.job_id == other.id)
        ).all()
        theirs[0].data = bytes(rows[0].data)
        db.flush()
        with pytest.raises(artifact_jobs.JobError, match="cannot be read"):
            artifact_jobs.carried(db, other.id)
        db.rollback()


# --------------------------------------------------------------------------- #
# The workers are given what they read                                        #
# --------------------------------------------------------------------------- #
class _Worker(BaseHTTPRequestHandler):
    """An analysis worker as ``given.py`` makes it answer: it holds what it was sent, and names what it lacks."""

    held: dict = {}
    calls: list = []
    refuse_with: tuple | None = None

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_PUT(self):  # noqa: N802
        data = self.rfile.read(int(self.headers["Content-Length"]))
        type(self).calls.append(
            ("PUT", self.path, self.headers.get("X-Analyzer-Token") or self.headers.get("X-Pcap-Token"))
        )
        if type(self).refuse_with:
            return self._send(*type(self).refuse_with)
        type(self).held[self.path[len("/files/") :]] = data
        self._send(200, {})

    def do_POST(self):  # noqa: N802
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).calls.append(("POST", self.path, body))
        wanted = [body["path"]] if "path" in body else [f"{body['sha256']}.bin", *body.get("signatures", [])]
        missing = [name for name in wanted if name not in type(self).held]
        if missing:
            return self._send(409, {"detail": "The worker does not hold these files", "missing": missing})
        self._send(200, {"read": {name: hashlib.sha256(type(self).held[name]).hexdigest() for name in wanted}})

    def log_message(self, *args):
        pass


@pytest.fixture()
def worker():
    _Worker.held, _Worker.calls, _Worker.refuse_with = {}, [], None
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Worker)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}", _Worker
    httpd.shutdown()


def test_the_analyzer_is_sent_the_sample_and_the_signatures_it_lacks_then_asked_again(root, worker, monkeypatch):
    from app.malware import flirt
    from app.workers import analyzer

    url, served = worker
    monkeypatch.setattr(settings, "ANALYZER_URL", url)
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "the-analyzer-token")
    data = content(2 * sealed.CHUNK + 1, seed=11)
    sha = hashlib.sha256(data).hexdigest()
    samples.write_sample(sha, data)
    flirt.write_file("b" * 32, "sig", b"IDASGN a signature")
    signatures = ["_flirt/" + "b" * 32 + ".sig"]

    answer = analyzer.request_code_analysis(sha, signatures)
    # What the worker read is the sample itself, decrypted on its way: never the bytes of the disk.
    assert answer["read"] == {f"{sha}.bin": sha, signatures[0]: hashlib.sha256(b"IDASGN a signature").hexdigest()}
    assert [(kind, path) for kind, path, _ in served.calls] == [
        ("POST", "/analyze"),
        ("PUT", f"/files/{sha}.bin"),
        ("PUT", "/files/_flirt/" + "b" * 32 + ".sig"),
        ("POST", "/analyze"),
    ]
    assert served.calls[1][2] == "the-analyzer-token"
    # It holds them now: the next request sends nothing.
    served.calls.clear()
    analyzer.request_decompile(sha, 4096, signatures)
    assert [(kind, path) for kind, path, _ in served.calls] == [("POST", "/decompile")]

    # A worker that will not take the file: its sentence, as the error of the analysis.
    served.held.clear()
    served.refuse_with = (507, {"detail": "The worker has no room for this file"})
    with pytest.raises(analyzer.AnalyzerError, match="no room for this file"):
        analyzer.request_code_analysis(sha, [])
    # A file the store does not hold is not sent, and the request says so.
    served.refuse_with = None
    with pytest.raises(analyzer.AnalyzerError, match="is not in the store"):
        analyzer.request_code_analysis("0" * 64, [])


def test_a_damaged_sample_is_not_sent_to_a_worker(root, worker, monkeypatch):
    from app.workers import analyzer

    url, served = worker
    monkeypatch.setattr(settings, "ANALYZER_URL", url)
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "t")
    data = content(1000, seed=12)
    sha = hashlib.sha256(data).hexdigest()
    samples.write_sample(sha, data)
    _flip(samples.sample_path(sha), sealed.HEADER + 10)
    with pytest.raises(store.DamagedFile):
        analyzer.request_code_analysis(sha, [])
    assert not served.held


def test_the_capture_worker_is_sent_the_capture_it_lacks(root, worker, monkeypatch):
    from app.core.models import NetworkCapture
    from app.network import service
    from app.network import store as captures

    url, served = worker
    monkeypatch.setattr(settings, "PCAP_URL", url)
    monkeypatch.setattr(settings, "PCAP_TOKEN", "the-pcap-token")
    capture_id = "c" * 32
    data = b"\xd4\xc3\xb2\xa1" + content(5000, seed=13)
    captures.write_capture(capture_id, "pcap", [data])
    row = NetworkCapture(
        id=capture_id, kind="pcap", file_name="a.pcap", size=len(data), sha256="", created_at="", created_by=""
    )
    name = f"_captures/{capture_id}/capture.pcap"
    assert service.rpc(row, "status", {}) == {"read": {name: hashlib.sha256(data).hexdigest()}}
    assert [(kind, path) for kind, path, _ in served.calls] == [
        ("POST", "/rpc"),
        ("PUT", f"/files/{name}"),
        ("POST", "/rpc"),
    ]
    assert served.calls[1][2] == "the-pcap-token"


def test_capa_is_sent_the_rules_with_the_request(client, worker, monkeypatch, root):
    from app.core.models import CapaRule
    from app.malware import capa_rules
    from app.workers import capa

    url, served = worker
    monkeypatch.setattr(settings, "CAPA_URL", url)
    monkeypatch.setattr(settings, "CAPA_TOKEN", "t")
    with SessionLocal() as db:
        db.add(
            CapaRule(
                id="a" * 32,
                name="team rule",
                namespace="",
                scope="",
                source="rule:\n  meta:\n    name: team rule\n",
                enabled=True,
                created_at="1",
                created_by="x",
                updated_at="1",
            )
        )
        db.add(
            CapaRule(
                id="b" * 32,
                name="off",
                namespace="",
                scope="",
                source="rule: off",
                enabled=False,
                created_at="2",
                created_by="x",
                updated_at="2",
            )
        )
        db.commit()
        rules = capa_rules.enabled_sources(db)
        # Saving a rule writes no file; the file a version before 6.8 kept for it goes.
        old = root / "_capa_rules" / ("a" * 32 + ".yml")
        old.parent.mkdir()
        old.write_text("as 6.7 wrote it")
        capa_rules.write_file(db.get(CapaRule, "a" * 32))
        assert not old.exists()
    assert rules == [{"name": "a" * 32 + ".yml", "source": "rule:\n  meta:\n    name: team rule\n"}]
    data = content(900, seed=14)
    sha = hashlib.sha256(data).hexdigest()
    samples.write_sample(sha, data)
    capa.request_capabilities(sha, rules)
    posted = [body for kind, _path, body in served.calls if kind == "POST"]
    assert posted[-1] == {"sha256": sha, "rules": rules}
    assert io.BytesIO(served.held[f"{sha}.bin"]).read() == data


def test_what_a_worker_is_missing_is_read_from_its_answer_only():
    from app.workers import handover

    def error(code):
        return urllib.error.HTTPError("http://w", code, "x", {}, io.BytesIO(b""))

    assert handover.missing_of(error(409), {"missing": ["a.bin", 3, "b.bin"]}) == ["a.bin", "b.bin"]
    assert handover.missing_of(error(409), {"detail": "busy"}) == []
    assert handover.missing_of(error(404), {"missing": ["a.bin"]}) == []
    assert handover.missing_of(error(409), None) == []
