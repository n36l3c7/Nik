"""Artifacts exported from one Nik and imported into another."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pyzipper
from fastapi.testclient import TestClient

from app import artifact_transfer
from app.malware.samples import sample_path
from tests.conftest import make_key
from tests.test_mail import no_dns, phishing_message  # noqa: F401 - no_dns is a fixture
from tests.test_malware import STRINGS_PAYLOAD, fake_pe


def _upload(admin: TestClient) -> tuple[str, bytes]:
    data = fake_pe(payload=STRINGS_PAYLOAD)
    sha = hashlib.sha256(data).hexdigest()
    made = admin.post("/api/artifacts/files", files={"file": ("invoice.exe", data)})
    assert made.status_code == 201, made.text
    assert admin.put(f"/api/artifacts/file-{sha}/tags", json={"tags": ["phishing"]}).status_code == 200
    return sha, data


def _forget(admin: TestClient, artifact_id: str) -> None:
    assert admin.delete(f"/api/artifacts/{artifact_id}").status_code == 204
    assert admin.get(f"/api/artifacts/{artifact_id}").status_code == 404


def test_analyses_travel_without_the_files_unless_asked(admin: TestClient):
    sha, data = _upload(admin)
    artifact_id = f"file-{sha}"
    analysis = admin.get(f"/api/samples/{sha}").json()

    plain = admin.post("/api/artifacts/export", json={"ids": [artifact_id]})
    assert plain.status_code == 200, plain.text
    assert plain.headers["content-disposition"].startswith('attachment; filename="nik-artifacts-')
    archive = zipfile.ZipFile(io.BytesIO(plain.content))
    assert sorted(archive.namelist()) == ["manifest.json", f"records/{artifact_id}.json"]
    manifest = json.loads(archive.read("manifest.json"))
    assert manifest["format"] == "nik-artifacts" and manifest["files"] is False and manifest["password"] is None
    assert manifest["artifacts"][0]["name"] == "invoice.exe" and manifest["artifacts"][0]["tags"] == ["phishing"]
    assert data not in plain.content

    # Without the file the analysis comes back, the sample does not.
    _forget(admin, artifact_id)
    assert not sample_path(sha).exists()
    result = admin.post("/api/artifacts/import", files={"file": ("a.zip", plain.content)})
    assert result.status_code == 200, result.text
    assert result.json() == {"added": 1, "ids": [artifact_id], "existing": 0, "skipped": []}
    back = admin.get(f"/api/artifacts/{artifact_id}").json()
    assert back["name"] == "invoice.exe" and back["tags"] == ["phishing"] and back["detail"].startswith("PE32")
    assert admin.get(f"/api/samples/{sha}").json()["analysis"] == analysis["analysis"]
    assert not sample_path(sha).exists()
    # A second import adds nothing.
    again = admin.post("/api/artifacts/import", files={"file": ("a.zip", plain.content)}).json()
    assert again["added"] == 0 and again["existing"] == 1


def test_files_travel_in_an_encrypted_zip_and_are_checked_on_the_way_in(admin: TestClient):
    sha, data = _upload(admin)
    artifact_id = f"file-{sha}"
    full = admin.post("/api/artifacts/export", json={"ids": [artifact_id], "files": True})
    assert full.status_code == 200 and "with-files" in full.headers["content-disposition"]
    archive = zipfile.ZipFile(io.BytesIO(full.content))
    assert "files.zip" in archive.namelist()
    assert data not in full.content  # never in clear
    inner = pyzipper.AESZipFile(io.BytesIO(archive.read("files.zip")))
    inner.setpassword(b"infected")
    assert inner.read(f"{artifact_id}/sample.bin") == data

    _forget(admin, artifact_id)
    result = admin.post("/api/artifacts/import", files={"file": ("a.zip", full.content)}).json()
    assert result["added"] == 1
    assert sample_path(sha).read_bytes() == data

    # A file that is not the one the artifact is named by is refused.
    _forget(admin, artifact_id)
    forged = io.BytesIO()
    with zipfile.ZipFile(forged, "w") as out:
        for name in ("manifest.json", f"records/{artifact_id}.json"):
            out.writestr(name, archive.read(name))
        swapped = io.BytesIO()
        with pyzipper.AESZipFile(swapped, "w", encryption=pyzipper.WZ_AES) as files:
            files.setpassword(b"infected")
            files.writestr(f"{artifact_id}/sample.bin", b"MZ something else")
        out.writestr("files.zip", swapped.getvalue())
    refused = admin.post("/api/artifacts/import", files={"file": ("a.zip", forged.getvalue())}).json()
    assert refused["added"] == 0 and "SHA-256 mismatch" in refused["skipped"][0]["reason"]
    assert not sample_path(sha).exists()
    assert admin.get(f"/api/artifacts/{artifact_id}").status_code == 404


def test_a_mail_and_its_attachment_keep_their_relation(admin: TestClient, no_dns):  # noqa: F811
    raw = phishing_message()
    mail = admin.post("/api/artifacts/mails", files={"file": ("reported.eml", raw)}).json()
    child = admin.post(f"/api/artifacts/{mail['id']}/attachments/0/sample")
    assert child.status_code == 201, child.text
    ids = [mail["id"], child.json()["id"]]

    exported = admin.post("/api/artifacts/export", json={"ids": ids, "files": True})
    manifest = json.loads(zipfile.ZipFile(io.BytesIO(exported.content)).read("manifest.json"))
    assert [r["relation"] for r in manifest["relations"]] == ["attachment"]
    for artifact_id in ids:
        _forget(admin, artifact_id)

    result = admin.post("/api/artifacts/import", files={"file": ("a.zip", exported.content)}).json()
    assert result["added"] == 2 and result["skipped"] == []
    detail = admin.get(f"/api/artifacts/{mail['id']}").json()
    assert [c["id"] for c in detail["children"]] == [ids[1]]
    assert admin.get(f"/api/mails/{mail['ref']}").status_code == 200


def test_only_an_admin_imports_and_a_strange_archive_is_refused(admin: TestClient):
    sha, _ = _upload(admin)
    analyst = make_key(admin, role="analyst")
    other = TestClient(admin.app)
    exported = other.post("/api/artifacts/export", headers=analyst, json={"ids": [f"file-{sha}"]})
    assert exported.status_code == 200
    denied = other.post("/api/artifacts/import", headers=analyst, files={"file": ("a.zip", exported.content)})
    assert denied.status_code == 403

    assert admin.post("/api/artifacts/import", files={"file": ("a.zip", b"not a zip")}).status_code == 422
    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w") as out:
        out.writestr("manifest.json", json.dumps({"format": "something-else"}))
    assert admin.post("/api/artifacts/import", files={"file": ("a.zip", empty.getvalue())}).status_code == 422
    assert admin.post("/api/artifacts/export", json={"ids": ["file-" + "0" * 64]}).status_code == 404

    bad = io.BytesIO()
    with zipfile.ZipFile(bad, "w") as out:
        out.writestr(
            "manifest.json",
            json.dumps(
                {
                    "format": "nik-artifacts",
                    "version": 1,
                    "artifacts": [{"id": "file-../../etc", "kind": "file", "ref": "../../etc", "name": "x"}],
                }
            ),
        )
    result = admin.post("/api/artifacts/import", files={"file": ("a.zip", bad.getvalue())}).json()
    assert result["added"] == 0 and result["skipped"][0]["reason"] == "not a valid artifact id"


# --------------------------------------------------------------------------- #
# Mailboxes                                                                   #
# --------------------------------------------------------------------------- #
def _mailbox(admin: TestClient) -> dict:
    from tests.test_mailboxes import mbox

    made = admin.post("/api/artifacts/mailboxes", files={"file": ("finance.mbox", mbox())})
    assert made.status_code == 201, made.text
    return admin.get(f"/api/mailboxes/{made.json()['id']}").json()


def test_a_mailbox_travels_with_its_file_and_its_index(admin: TestClient, no_dns):  # noqa: F811
    from app import mailboxes
    from tests.test_mailboxes import mbox

    box = _mailbox(admin)
    artifact_id = box["artifactId"]
    assert admin.put(f"/api/artifacts/{artifact_id}/tags", json={"tags": ["finance"]}).status_code == 200
    before = admin.get(f"/api/mailboxes/{box['id']}/messages", params={"scope": "all"}).json()["messages"]
    # One message imported there: what was imported does not travel as "imported".
    imported = admin.post(f"/api/mailboxes/{box['id']}/import", json={"seqs": [before[0]["seq"]]})
    assert imported.status_code in (200, 202), imported.text

    full = admin.post("/api/artifacts/export", json={"ids": [artifact_id], "files": True})
    assert full.status_code == 200, full.text
    archive = zipfile.ZipFile(io.BytesIO(full.content))
    assert sorted(archive.namelist()) == [
        "files.zip", "manifest.json", f"records/{artifact_id}.json", f"records/{artifact_id}.messages.jsonl",
    ]  # fmt: skip
    entry = json.loads(archive.read("manifest.json"))["artifacts"][0]
    assert entry["kind"] == "mailbox" and entry["files"] == [f"{artifact_id}/mailbox.mbox"]
    assert entry["messages"] == f"records/{artifact_id}.messages.jsonl"
    lines = archive.read(entry["messages"]).splitlines()
    # Every message has its line, the copies of one another too.
    assert len(lines) == box["total"] + box["duplicates"] and json.loads(lines[0])["seq"] == 0
    # The file is in the encrypted zip, not in the clear.
    assert b"From " + b"" not in archive.read("manifest.json") and mbox()[:200] not in full.content

    # Without its file a mailbox is not imported: its index says where messages are in that file.
    plain = admin.post("/api/artifacts/export", json={"ids": [artifact_id]})
    _forget(admin, artifact_id)
    assert admin.get(f"/api/mailboxes/{box['id']}").status_code == 404
    refused = admin.post("/api/artifacts/import", files={"file": ("a.zip", plain.content)}).json()
    assert refused["added"] == 0 and refused["skipped"] == [
        {"name": "finance.mbox", "reason": "a mailbox needs its file: export it with the files"}
    ]
    # With it, it is back as it was: same messages, same conversations, its tags, nothing imported.
    result = admin.post("/api/artifacts/import", files={"file": ("a.zip", full.content)})
    assert result.status_code == 200 and result.json()["added"] == 1, result.text
    back = admin.get(f"/api/mailboxes/{box['id']}").json()
    assert (back["status"], back["total"], back["threads"], back["duplicates"]) == (
        "ready", box["total"], box["threads"], box["duplicates"],
    )  # fmt: skip
    assert back["imported"] == 0 and back["size"] == len(mbox())
    after = admin.get(f"/api/mailboxes/{box['id']}/messages", params={"scope": "all"}).json()["messages"]
    assert [(m["seq"], m["subject"], m["sender"]) for m in after] == [
        (m["seq"], m["subject"], m["sender"]) for m in before
    ]
    assert mailboxes.mbox_path(box["id"]).read_bytes() == mbox()
    shown = admin.get(f"/api/artifacts/{artifact_id}").json()
    assert shown["tags"] == ["finance"] and shown["detail"] == f"0 of {box['total']} messages imported"
    # A message can be read from it again.
    again = admin.post(f"/api/mailboxes/{box['id']}/import", json={"seqs": [after[1]["seq"]]})
    assert again.status_code in (200, 202), again.text
    # Nothing is left behind where archives are taken apart.
    assert list(artifact_transfer.workdir().iterdir()) == []


def test_a_mailbox_whose_index_does_not_fit_its_file_is_refused(admin: TestClient):
    from app import mailboxes

    box = _mailbox(admin)
    artifact_id = box["artifactId"]
    full = admin.post("/api/artifacts/export", json={"ids": [artifact_id], "files": True}).content
    _forget(admin, artifact_id)

    def tampered(change) -> bytes:
        source = zipfile.ZipFile(io.BytesIO(full))
        held = io.BytesIO()
        with zipfile.ZipFile(held, "w") as out:
            for name in source.namelist():
                data = source.read(name)
                if name.endswith(".messages.jsonl"):
                    data = change(data)
                out.writestr(name, data)
        return held.getvalue()

    def reason(data: bytes) -> str:
        answer = admin.post("/api/artifacts/import", files={"file": ("a.zip", data)}).json()
        assert answer["added"] == 0, answer
        return answer["skipped"][0]["reason"]

    def past_the_end(data: bytes) -> bytes:
        lines = data.splitlines()
        first = json.loads(lines[0])
        first["offset"] = 10**9
        return b"\n".join([json.dumps(first).encode(), *lines[1:]]) + b"\n"

    assert reason(tampered(past_the_end)) == "its index does not fit its file"
    assert reason(tampered(lambda data: data + data)) == "its index does not fit its file"  # a message twice
    assert reason(tampered(lambda data: b"{not json\n")) == "its index cannot be read"
    # Refused, nothing of it stays: no row, no file.
    assert admin.get(f"/api/mailboxes/{box['id']}").status_code == 404
    assert not (mailboxes.directory(box["id"]) / "mailbox.mbox").exists()
    assert admin.post("/api/artifacts/import", files={"file": ("a.zip", full)}).json()["added"] == 1
