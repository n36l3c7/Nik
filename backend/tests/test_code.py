"""Disassembly through the analyzer worker (the worker is replaced by a stub)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.workers import analyzer
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
        {
            "addr": 0x40100F,
            "name": "fcn.0040100f",
            "kind": "function",
            "size": 3,
            "blocks": 1,
            "edges": 0,
            "cc": 1,
            "indegree": 1,
            "calls": [],
            "cfg": {"truncated": False, "blocks": []},
        },
    ],
    # The up-front pass decompiled entry0 only (the helper is left for on demand).
    "decompiled": {
        str(0x401000): {
            "code": "void entry0(void)\n{\n    fcn.0040100f();\n    return;\n}",
            "spans": [[0, 4, "t"], [5, 11, "f", 0x401000], [24, 36, "f", 0x40100F], [44, 50, "k"]],
            "truncated": False,
        }
    },
    "decompile": {"engine": "rz-ghidra", "done": 1, "failed": 0, "total": 2, "stopped": "time"},
}

ON_DEMAND = {
    "addr": 0x40100F,
    "engine": "rz-ghidra",
    "code": "undefined4 fcn.0040100f(void)\n{\n    return 0;\n}",
    "spans": [[0, 10, "t"], [11, 23, "f", 0x40100F], [42, 48, "k"], [49, 50, "n"]],
    "truncated": False,
}


@pytest.fixture()
def worker(monkeypatch):
    """Configure the analyzer and replace the HTTP calls with recorders."""
    calls = []

    def fake(sha256, signatures):
        calls.append(sha256)
        return WORKER_RESULT

    def fake_decompile(sha256, addr, signatures):
        calls.append(("decompile", addr))
        return ON_DEMAND

    monkeypatch.setattr(settings, "ANALYZER_URL", "http://analyzer.test")
    monkeypatch.setattr(settings, "ANALYZER_TOKEN", "secret")
    monkeypatch.setattr(analyzer, "request_code_analysis", fake)
    monkeypatch.setattr(analyzer, "request_decompile", fake_decompile)
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
    assert [f["name"] for f in state["functions"]] == [
        "entry0",
        "sym.imp.KERNEL32.dll_VirtualAllocEx",
        "fcn.0040100f",
    ]
    assert "cfg" not in state["functions"][0]  # CFGs are fetched per function
    assert "decompiled" not in state and state["decompile"]["done"] == 1  # stats only, no pseudo-C

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
    def failing(sha256, signatures):
        raise analyzer.AnalyzerError("rizin did not finish within 600 seconds")

    monkeypatch.setattr(analyzer, "request_code_analysis", failing)
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "c2", minimal_pe(b"\xeb\xfe"))
    state = admin.get(f"/api/samples/{sha}/code", headers=key).json()
    assert state["status"] == "error" and "600 seconds" in state["error"]
    assert admin.get(f"/api/samples/{sha}/code/functions/{0x401000}", headers=key).status_code == 404


def test_decompiled_code_is_stored_or_fetched_once_on_demand(admin: TestClient, worker):
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "c3", minimal_pe(b"\x55\x89\xe5\xc3"))
    url = f"/api/samples/{sha}/code/functions/{{}}/decompiled"

    stored = admin.get(url.format(0x401000), headers=key).json()
    assert stored["source"] == "analysis" and stored["engine"] == "rz-ghidra"
    assert stored["code"].startswith("void entry0") and stored["spans"][1] == [5, 11, "f", 0x401000]
    assert ("decompile", 0x401000) not in worker  # no worker call for stored code

    first = admin.get(url.format(0x40100F), headers=key).json()
    assert first["source"] == "on-demand" and "return 0;" in first["code"]
    again = admin.get(url.format(0x40100F), headers=key).json()
    assert again["source"] == "analysis" and again["code"] == first["code"]  # kept after the first time
    assert worker.count(("decompile", 0x40100F)) == 1

    assert admin.get(url.format(0x403000), headers=key).status_code == 404  # imports have no code
    assert admin.get(url.format(0x401001), headers=key).status_code == 404  # not a function start


def test_decompile_errors(admin: TestClient, monkeypatch, worker):
    key = make_key(admin, role="analyst")
    sha = _upload(admin, key, "c4", minimal_pe(b"\x31\xc0\xc3"))
    url = f"/api/samples/{sha}/code/functions/{0x40100F}/decompiled"

    def failing(sha256, addr, signatures):
        raise analyzer.AnalyzerError("The analyzer is busy; try again later")

    monkeypatch.setattr(analyzer, "request_decompile", failing)
    r = admin.get(url, headers=key)
    assert r.status_code == 502 and "busy" in r.json()["detail"]

    monkeypatch.setattr(settings, "ANALYZER_URL", "")
    assert admin.get(url, headers=key).status_code == 503  # nothing stored, no worker
    stored = f"/api/samples/{sha}/code/functions/{0x401000}/decompiled"
    assert admin.get(stored, headers=key).status_code == 200  # stored code needs no worker


def test_split_result_keeps_cfgs_and_pseudo_c_apart():
    summary, functions = analyzer.split_result(WORKER_RESULT)
    assert [f["addr"] for f in functions] == [0x401000, 0x40100F]  # one row per function, imports have none
    assert functions[0]["cfg"]["blocks"] and functions[0]["decompiled"]["code"].startswith("void entry0")
    assert functions[1]["cfg"] == {"truncated": False, "blocks": []} and functions[1]["decompiled"] is None
    assert all("cfg" not in f for f in summary["functions"]) and "decompiled" not in summary
    assert summary["engine"]["name"] == "rizin" and summary["entry"] == 0x401000
    assert summary["decompile"]["engine"] == "rz-ghidra"
