"""capa capabilities through the capa worker (the worker is replaced by a stub)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import capa
from app.analyzer import AnalyzerError, WorkerBusy
from app.config import settings
from tests.conftest import make_key
from tests.test_code import _upload
from tests.test_executables import minimal_pe

RESULT = {
    "engine": {"name": "capa", "version": "10.0.0"},
    "format": "pe",
    "arch": "i386",
    "os": "windows",
    "baseAddress": 0x400000,
    "libraryFunctions": 0,
    "capabilities": [
        {
            "name": "link function at runtime on Windows",
            "namespace": "linking/runtime-linking",
            "scope": "instruction",
            "description": "",
            "attack": [{"id": "T1129", "tactic": "Execution", "technique": "Shared Modules", "subtechnique": ""}],
            "mbc": [],
            "addresses": [0x401005],
            "truncated": False,
        }
    ],
}


@pytest.fixture()
def capa_worker(monkeypatch):
    """Configure capa and replace the HTTP call with a recorder."""
    calls = []

    def fake(sha256):
        calls.append(sha256)
        return RESULT

    monkeypatch.setattr(settings, "CAPA_URL", "http://capa.test")
    monkeypatch.setattr(settings, "CAPA_TOKEN", "secret")
    monkeypatch.setattr(capa, "request_capabilities", fake)
    return calls


def test_not_configured(admin: TestClient):
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "k0", minimal_pe(b"\xc3"))
    assert admin.get(f"/api/samples/{sha}/capabilities", headers=key).json() == {"configured": False, "status": "none"}
    assert admin.post(f"/api/samples/{sha}/capabilities", headers=key).status_code == 503


def test_upload_runs_capa_and_stores_the_capabilities(admin: TestClient, capa_worker):
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "k1", minimal_pe(b"\x55\x89\xe5\xc3"))
    assert capa_worker == [sha]  # the background job ran once after the upload

    state = admin.get(f"/api/samples/{sha}/capabilities", headers=key).json()
    assert state["status"] == "done" and state["engine"]["version"] == "10.0.0"
    assert state["capabilities"][0]["attack"][0]["id"] == "T1129"
    assert state["startedAt"] and state["finishedAt"]

    # Re-analyse and the explicit request run it again; read-only keys cannot.
    assert admin.post(f"/api/samples/{sha}/reanalyse", headers=key).status_code == 200
    assert admin.post(f"/api/samples/{sha}/capabilities", headers=key).status_code == 202
    assert capa_worker == [sha, sha, sha]
    read_only = make_key(admin, role="analyst", scopes=["read"])
    assert admin.post(f"/api/samples/{sha}/capabilities", headers=read_only).status_code == 403
    actions = {e["action"] for e in admin.get("/api/audit", headers=key).json()["entries"]}
    assert "sample.capabilities" in actions

    # Removing the last reference removes the capabilities with the sample.
    assert admin.delete(f"/api/incidents/k1/samples/{sha}", headers=key).status_code == 204
    assert admin.get(f"/api/samples/{sha}/capabilities", headers=key).status_code == 404


def test_file_types_capa_does_not_read_are_unsupported(admin: TestClient, capa_worker):
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "k2", b"just a text file, not an executable")
    assert capa_worker == []  # never sent to the worker
    assert admin.get(f"/api/samples/{sha}/capabilities", headers=key).json()["status"] == "unsupported"
    assert admin.post(f"/api/samples/{sha}/capabilities", headers=key).status_code == 422


def test_worker_errors_are_stored_and_a_busy_worker_is_waited_for(admin: TestClient, capa_worker, monkeypatch):
    key = make_key(admin, role="analyst")
    answers = [WorkerBusy("capa is busy"), WorkerBusy("capa is busy"), RESULT]

    def busy_then_done(sha256):
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(capa, "BUSY_RETRY_SECONDS", 0)
    monkeypatch.setattr(capa, "request_capabilities", busy_then_done)
    sha = _upload(admin, key, "k3", minimal_pe(b"\x90\xc3"))
    assert answers == [] and admin.get(f"/api/samples/{sha}/capabilities", headers=key).json()["status"] == "done"

    def failing(sha256):
        raise AnalyzerError("Input file does not appear to be a supported file.")

    monkeypatch.setattr(capa, "request_capabilities", failing)
    admin.post(f"/api/samples/{sha}/capabilities", headers=key)
    state = admin.get(f"/api/samples/{sha}/capabilities", headers=key).json()
    assert state["status"] == "error" and "supported file" in state["error"]
