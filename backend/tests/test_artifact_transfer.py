"""Artifacts exported from one Nik and imported into another."""

from __future__ import annotations

import hashlib
import io
import json
import zipfile

import pyzipper
from fastapi.testclient import TestClient

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
