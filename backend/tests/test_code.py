"""Disassembly through the analyzer worker (the worker is replaced by a stub)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app import analyzer
from app.config import settings
from tests.conftest import make_key
from tests.test_executables import minimal_pe

WORKER_RESULT = {
    "engine": {"name": "rizin", "version": "0.9.1"},
    "info": {"arch": "x86", "bits": 32, "os": "windows"},
    "entry": 0x401000,
    "truncated": False,
    "functions": [
        {
            "addr": 0x401000,
            "name": "entry0",
            "kind": "function",
            "size": 14,
            "blocks": 3,
            "edges": 3,
            "cc": 2,
            "indegree": 0,
            "calls": [{"addr": 0x40100F, "name": "fcn.0040100f", "at": 0x401007}],
            "cfg": {
                "truncated": False,
                "blocks": [
                    {
                        "addr": 0x401000,
                        "size": 7,
                        "jump": 0x40100C,
                        "fail": 0x401007,
                        "ops": [{"addr": 0x401000, "text": "push ebp", "type": "rpush"}],
                    },
                    {
                        "addr": 0x401007,
                        "size": 5,
                        "jump": 0x40100C,
                        "fail": None,
                        "ops": [{"addr": 0x401007, "text": "call fcn.0040100f", "type": "call"}],
                    },
                    {
                        "addr": 0x40100C,
                        "size": 2,
                        "jump": None,
                        "fail": None,
                        "ops": [{"addr": 0x40100D, "text": "ret", "type": "ret"}],
                    },
                ],
            },
        },
        {
            "addr": 0x403000,
            "name": "sym.imp.KERNEL32.dll_VirtualAllocEx",
            "kind": "import",
            "size": 6,
            "blocks": 1,
            "edges": 0,
            "cc": 1,
            "indegree": 1,
            "calls": [],
        },
    ],
}


@pytest.fixture()
def worker(monkeypatch):
    """Configure the analyzer and replace the HTTP call with a recorder."""
    calls = []

    def fake(sha256):
        calls.append(sha256)
        return WORKER_RESULT

    monkeypatch.setattr(settings, "ANALYZER_URL", "http://analyzer.test")
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "secret")
    monkeypatch.setattr(analyzer, "request_code_analysis", fake)
    return calls


def _upload(client: TestClient, key: dict, incident_id: str, payload: bytes) -> str:
    client.post("/api/incidents", headers=key, json={"id": incident_id, "name": incident_id, "data": {}})
    r = client.post(f"/api/incidents/{incident_id}/samples", headers=key, files={"file": ("x.exe", payload)})
    assert r.status_code == 201, r.text
    return r.json()["sample"]["sha256"]


def test_not_configured(admin: TestClient):
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "c0", minimal_pe(b"\x90\xc3"))
    assert admin.get(f"/api/samples/{sha}/code", headers=key).json() == {"configured": False, "status": "none"}
    assert admin.post(f"/api/samples/{sha}/code", headers=key).status_code == 503


def test_upload_queues_the_disassembly_and_stores_the_result(admin: TestClient, worker):
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "c1", minimal_pe(b"\x55\x89\xe5\xc3"))
    assert worker == [sha]  # the background job ran once after the upload

    state = admin.get(f"/api/samples/{sha}/code", headers=key).json()
    assert state["status"] == "done" and state["engine"]["version"] == "0.9.1"
    assert [f["name"] for f in state["functions"]] == ["entry0", "sym.imp.KERNEL32.dll_VirtualAllocEx"]
    assert "cfg" not in state["functions"][0]  # CFGs are fetched per function

    cfg = admin.get(f"/api/samples/{sha}/code/functions/{0x401000}", headers=key).json()
    assert [b["addr"] for b in cfg["blocks"]] == [0x401000, 0x401007, 0x40100C]
    assert admin.get(f"/api/samples/{sha}/code/functions/{0x403000}", headers=key).status_code == 404

    # Running it again on demand is audited; read-only keys cannot start it.
    assert admin.post(f"/api/samples/{sha}/code", headers=key).status_code == 202
    assert worker == [sha, sha]
    read_only = make_key(admin, role="analyst", scopes=["read"])
    assert admin.post(f"/api/samples/{sha}/code", headers=read_only).status_code == 403
    actions = {e["action"] for e in admin.get("/api/audit", headers=key).json()["entries"]}
    assert "sample.disassemble" in actions


def test_worker_errors_are_stored(admin: TestClient, monkeypatch, worker):
    def failing(sha256):
        raise analyzer.AnalyzerError("rizin did not finish within 600 seconds")

    monkeypatch.setattr(analyzer, "request_code_analysis", failing)
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "c2", minimal_pe(b"\xeb\xfe"))
    state = admin.get(f"/api/samples/{sha}/code", headers=key).json()
    assert state["status"] == "error" and "600 seconds" in state["error"]
    assert admin.get(f"/api/samples/{sha}/code/functions/{0x401000}", headers=key).status_code == 404


def test_split_result_keeps_cfgs_apart():
    summary, cfgs = analyzer.split_result(WORKER_RESULT)
    assert list(cfgs) == [str(0x401000)]
    assert all("cfg" not in f for f in summary["functions"])
    assert summary["engine"]["name"] == "rizin" and summary["entry"] == 0x401000
