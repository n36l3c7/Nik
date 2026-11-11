"""Function annotations per sample and admin-uploaded FLIRT signatures."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.config import settings
from app.workers import analyzer
from tests.conftest import make_key
from tests.test_code import WORKER_RESULT, _upload, worker  # noqa: F401 (fixture)
from tests.test_executables import minimal_pe

ENTRY = 0x401000
SIG = b"IDASGN\x0a\x00" + b"\x00" * 64
PAT = b"558BEC83EC10................................................ 00 0000 0020 :0000 _helper\n---\n"


def _disassembled(admin: TestClient, key: dict, incident_id: str) -> str:
    return _upload(admin, key, incident_id, minimal_pe(b"\x55\x89\xe5\xc3"))


def test_annotations_are_shared_audited_and_removed_with_the_sample(admin: TestClient, worker):  # noqa: F811
    key = make_key(admin, role="analyst")
    sha = _disassembled(admin, key, "a1")
    url = f"/api/samples/{sha}/annotations"

    saved = admin.put(f"{url}/{ENTRY}", headers=key, json={"name": " decrypt_config ", "comment": "XOR 0x5A"})
    assert saved.status_code == 200, saved.text
    assert saved.json()["name"] == "decrypt_config" and saved.json()["updatedBy"].startswith("api:")

    # A second incident holding the same file sees the same annotation.
    _upload(admin, key, "a2", minimal_pe(b"\x55\x89\xe5\xc3"))
    assert [a["addr"] for a in admin.get(url, headers=key).json()["annotations"]] == [ENTRY]

    assert admin.put(f"{url}/{0x999999}", headers=key, json={"name": "x"}).status_code == 404
    assert admin.put(f"{url}/{ENTRY}", headers=key, json={"name": "two\nlines"}).status_code == 400
    read_only = make_key(admin, role="analyst", scopes=["read"])
    assert admin.put(f"{url}/{ENTRY}", headers=read_only, json={"name": "x"}).status_code == 403

    # Both fields empty removes it.
    cleared = admin.put(f"{url}/{ENTRY}", headers=key, json={"name": "", "comment": " "})
    assert cleared.status_code == 200 and cleared.json() is None
    assert admin.get(url, headers=key).json()["annotations"] == []
    actions = [e["action"] for e in admin.get("/api/audit", headers=key).json()["entries"]]
    assert actions.count("sample.annotate") == 2

    admin.put(f"{url}/{ENTRY}", headers=key, json={"comment": "keep"})
    assert admin.delete(f"/api/incidents/a1/samples/{sha}", headers=key).status_code == 204
    assert len(admin.get(url, headers=key).json()["annotations"]) == 1  # still held by a2
    assert admin.delete(f"/api/incidents/a2/samples/{sha}", headers=key).status_code == 204
    assert len(admin.get(url, headers=key).json()["annotations"]) == 1  # the sample stays as an artifact
    assert admin.delete(f"/api/artifacts/file-{sha}", headers=key).status_code == 204
    assert admin.get(url, headers=key).status_code == 404


def test_annotations_need_a_disassembly(admin: TestClient):
    key = make_key(admin, role="analyst")
    sha = _disassembled(admin, key, "a3")  # analyzer not configured: no disassembly
    assert admin.put(f"/api/samples/{sha}/annotations/{ENTRY}", headers=key, json={"name": "x"}).status_code == 409


def test_flirt_signatures_are_validated_stored_and_passed_to_the_worker(admin: TestClient, monkeypatch):
    analyst = make_key(admin, role="analyst")
    upload = admin.post("/api/flirt-signatures", data={"name": "  tokio 1.38 "}, files={"file": ("tokio.sig", SIG)})
    assert upload.status_code == 201, upload.text
    sig = upload.json()
    assert sig["name"] == "tokio 1.38" and sig["kind"] == "sig" and sig["size"] == len(SIG)
    stored = Path(settings.SAMPLE_STORE) / "_flirt" / f"{sig['id']}.sig"
    assert stored.read_bytes() == SIG

    pat = admin.post("/api/flirt-signatures", data={"name": "helpers"}, files={"file": ("h.pat", PAT)}).json()
    for name, content in (("bad.sig", b"not a signature"), ("bad.pat", b"hello\n"), ("x.exe", SIG)):
        assert (
            admin.post("/api/flirt-signatures", data={"name": "x"}, files={"file": (name, content)}).status_code == 400
        )
    assert (
        admin.post(
            "/api/flirt-signatures", headers=analyst, data={"name": "x"}, files={"file": ("a.sig", SIG)}
        ).status_code
        == 403
    )

    disabled = admin.put(f"/api/flirt-signatures/{pat['id']}", json={"name": "helpers", "enabled": False})
    assert disabled.status_code == 200 and disabled.json()["enabled"] is False
    assert [s["name"] for s in admin.get("/api/flirt-signatures", headers=analyst).json()["signatures"]] == [
        "tokio 1.38",
        "helpers",
    ]

    sent = []
    monkeypatch.setattr(settings, "ANALYZER_URL", "http://analyzer.test")
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "secret")
    monkeypatch.setattr(
        analyzer, "request_code_analysis", lambda sha, signatures: sent.append(signatures) or WORKER_RESULT
    )
    _disassembled(admin, analyst, "f1")
    assert sent == [[f"_flirt/{sig['id']}.sig"]]  # only the enabled one

    assert admin.delete(f"/api/flirt-signatures/{sig['id']}").status_code == 204
    assert not stored.exists()
    actions = {e["action"] for e in admin.get("/api/audit").json()["entries"]}
    assert {"flirt.add", "flirt.update", "flirt.delete"} <= actions
