"""Network Analysis: captures, the isolated browser's network log, pcapng and HAR.

The workers are faked here; workers/pcap/ and workers/browser/ test themselves with tshark,
sharkd and Chromium.
"""

from __future__ import annotations

import base64
import io
import json
import struct

import pytest
import pyzipper
from fastapi.testclient import TestClient

from app.core.config import settings
from app.core.db import SessionLocal
from app.core.models import NetworkCapture
from app.network import har, pcapng, store
from app.workers import previews
from tests.conftest import make_key

T0 = 1762765200000.0
ENTRIES = [
    {
        "id": 1,
        "seq": 1,
        "startedAt": T0,
        "method": "GET",
        "url": "https://login-paypa1.example/signin",
        "resourceType": "document",
        "state": "done",
        "request": {"headers": [["User-Agent", "Mozilla/5.0"]]},
        "response": {
            "status": 200,
            "statusText": "OK",
            "serverIp": "203.0.113.10",
            "headers": [["Content-Type", "text/html"], ["Content-Encoding", "gzip"]],
            "mimeType": "text/html",
            "body": base64.b64encode(b"<form method=post action=/post.php>").decode(),
            "bodySize": 35,
        },
        "timing": {"dns": 3, "connect": 10, "ssl": 6, "wait": 40, "receive": 2, "responseStart": 60, "total": 62},
    },
    {
        "id": 2,
        "seq": 2,
        "startedAt": T0 + 2000,
        "method": "POST",
        "url": "https://login-paypa1.example/post.php",
        "resourceType": "document",
        "state": "held",
        "reason": "submission held by Nik",
        "request": {
            "headers": [["Content-Type", "application/x-www-form-urlencoded"]],
            "body": base64.b64encode(b"email=mario%40contoso.it&pass=Winter2026").decode(),
            "bodySize": 40,
        },
    },
]
SUMMARY = {
    "packets": 42,
    "bytes": 9000,
    "first": T0 / 1000,
    "last": T0 / 1000 + 5,
    "protocols": [{"name": "HTTP", "packets": 4}],
    "hosts": [
        {"address": "203.0.113.10", "packets": 30, "bytes": 8000, "public": True},
        {"address": "10.13.37.2", "packets": 30, "bytes": 8000, "public": False},
    ],
    "dns": [{"name": "login-paypa1.example", "answers": ["203.0.113.10"]}],
    "http": [
        {"url": "http://login-paypa1.example/signin", "method": "GET", "host": "login-paypa1.example", "count": 1}
    ],
    "tlsServerNames": [{"name": "cdn.evil.example", "count": 2}],
    "posts": [{"frame": 15, "time": T0 / 1000 + 2, "method": "POST", "url": "http://login-paypa1.example/post.php"}],
    "beacons": [
        {
            "source": "10.0.0.5",
            "destination": "198.51.100.7",
            "port": "443",
            "count": 6,
            "interval": 30.0,
            "jitter": 0.01,
            "first": T0 / 1000,
            "last": T0 / 1000 + 150,
        }
    ],
    "objects": [
        {
            "tap": "eo:http",
            "token": "eo:http_0",
            "frame": 9,
            "host": "x",
            "type": "",
            "name": "a.exe",
            "size": 2,
            "sha256": "a" * 64,
        }
    ],
    "expert": {"Warning": 2},
}


def _pcap() -> bytes:
    return pcapng.build(ENTRIES)


# --------------------------------------------------------------------------- #
# pcapng and HAR                                                              #
# --------------------------------------------------------------------------- #
def _blocks(data: bytes):
    offset = 0
    while offset < len(data):
        kind, length = struct.unpack_from("<II", data, offset)
        yield kind, data[offset + 8 : offset + length - 4]
        offset += length


def test_pcapng_rebuilds_the_session_as_http():
    data = _pcap()
    assert store.capture_format(data) == "pcapng"
    blocks = list(_blocks(data))
    assert blocks[0][0] == 0x0A0D0D0A and b"Reconstructed by Nik" in blocks[0][1]
    packets = [body for kind, body in blocks if kind == 6]
    payload = b"".join(packets)
    assert b"GET /signin HTTP/1.1\r\nHost: login-paypa1.example\r\nUser-Agent: Mozilla/5.0" in payload
    assert b"Content-Encoding" not in payload  # bodies are kept decoded
    assert b"Content-Length: 35" in payload and b"<form method=post" in payload
    assert b"pass=Winter2026" in payload and b"HELD by Nik: never sent" in payload
    assert bytes([203, 0, 113, 10]) in payload  # the real server address
    assert b"\x0clogin-paypa1\x07example\x00" in payload  # the DNS answer, only for the request sent


def test_har_export():
    document = har.build(ENTRIES, "2.17.0", "session")
    first, held = document["log"]["entries"]
    assert document["log"]["version"] == "1.2" and document["log"]["creator"] == {"name": "Nik", "version": "2.17.0"}
    assert first["serverIPAddress"] == "203.0.113.10" and first["timings"]["wait"] == 40
    assert base64.b64decode(first["response"]["content"]["text"]).startswith(b"<form")
    assert held["_nikState"] == "held" and held["response"]["status"] == 0
    assert base64.b64decode(held["request"]["postData"]["text"]).endswith(b"pass=Winter2026")


# --------------------------------------------------------------------------- #
# API with faked workers                                                      #
# --------------------------------------------------------------------------- #
@pytest.fixture()
def workers(monkeypatch):
    calls: list[tuple[str, str, str, dict | None]] = []
    browser = {"entries": [], "closed": False}

    def call(base, header, token, method, path, body, timeout):
        calls.append((base, method, path, body))
        if base == settings.PCAP_URL:
            if path == "/analyze":
                return SUMMARY
            if path == "/close":
                return {}
            if body["method"] == "download":
                return {"name": "a.exe", "mime": "", "data": base64.b64encode(b"MZ" + b"\0" * 64).decode()}
            if body["method"] == "frames":
                return {"result": [{"num": 1, "c": ["1"], "bg": "ffffff", "fg": "000000"}]}
            return {"result": {"ok": body["method"]}}
        if path == "/sessions":
            return {"id": "b" * 32, "url": "", "network": body["network"], "screenshot": ""}
        if path.startswith(f"/sessions/{'b' * 32}/network"):
            since = int(path.split("since=")[1].split("&")[0])
            fresh = [e for e in browser["entries"] if e["seq"] > since]
            return {"cursor": max([since] + [e["seq"] for e in fresh]), "entries": fresh, "closed": browser["closed"]}
        if path.endswith("/action"):
            return {"id": "b" * 32, "releasePosts": body.get("releasePosts")}
        return {}

    monkeypatch.setattr(previews, "_call", call)
    monkeypatch.setattr(settings, "PCAP_URL", "http://pcap:8740")
    monkeypatch.setattr(settings, "BROWSER_URL", "http://browser:8730")
    return calls, browser


def _incident(client, key, incident_id="net1"):
    r = client.post("/api/incidents", headers=key, json={"id": incident_id, "name": incident_id, "data": {}})
    assert r.status_code == 201, r.text


def test_capture_upload_analysis_and_index(admin: TestClient, workers):
    calls, _ = workers
    key = make_key(admin)
    _incident(admin, key)
    assert admin.post("/api/incidents/net1/captures", headers=key, files={"file": ("x.pcap", b"MZ")}).status_code == 422
    r = admin.post("/api/incidents/net1/captures", headers=key, files={"file": ("phish.pcapng", _pcap())})
    assert r.status_code == 201, r.text
    capture_id = r.json()["capture"]["id"]
    detail = admin.get(f"/api/captures/{capture_id}", headers=key).json()
    assert detail["status"] == "ready" and detail["packets"] == 42 and detail["summary"]["beacons"][0]["count"] == 6
    analyze = next(c for c in calls if c[2] == "/analyze")[3]
    assert analyze == {"id": capture_id, "path": f"_captures/{capture_id}/capture.pcapng"}
    doc = admin.get("/api/incidents/net1", headers=key).json()
    ref = doc["data"]["network"]["captures"][0]
    assert (
        ref["fileName"] == "phish.pcapng" and ref["posts"] == 1 and ref["beacons"][0]["destination"] == "198.51.100.7"
    )
    iocs = {(i["type"], i["value"]): i for i in admin.get("/api/incidents/net1/iocs", headers=key).json()["iocs"]}
    assert ("ip", "198.51.100.7") in iocs and ("ip", "10.13.37.2") not in iocs
    assert ("domain", "cdn.evil.example") in iocs and ("sha256", "a" * 64) in iocs
    assert iocs[("url", "http://login-paypa1.example/post.php")]["sources"] == ["network:phish.pcapng"]

    # The worker's read-only calls are proxied; others are refused.
    frames = admin.post(
        f"/api/captures/{capture_id}/rpc", headers=key, json={"method": "frames", "params": {"filter": "http"}}
    )
    assert frames.status_code == 200 and frames.json()["result"][0]["bg"] == "ffffff"
    assert admin.post(f"/api/captures/{capture_id}/rpc", headers=key, json={"method": "load"}).status_code == 422

    # Export Objects: a protected zip, or a sample of the incident.
    zipped = admin.get(f"/api/captures/{capture_id}/objects/download?token=eo:http_0&password=pw", headers=key)
    with pyzipper.AESZipFile(io.BytesIO(zipped.content)) as archive:
        archive.setpassword(b"pw")
        assert archive.read("a.exe").startswith(b"MZ")
    sent = admin.post(
        f"/api/incidents/net1/captures/{capture_id}/objects/sample", headers=key, json={"token": "eo:http_0"}
    )
    assert sent.status_code == 201 and sent.json()["sample"]["fileName"] == "a.exe"

    raw = admin.get(f"/api/captures/{capture_id}/file", headers=key)
    assert raw.content == _pcap()


def test_keylog_is_checked_encrypted_and_sent_to_the_worker(admin: TestClient, workers):
    calls, _ = workers
    key = make_key(admin)
    _incident(admin, key)
    capture_id = admin.post("/api/incidents/net1/captures", headers=key, files={"file": ("a.pcapng", _pcap())}).json()[
        "capture"
    ]["id"]
    bad = admin.put(f"/api/captures/{capture_id}/keylog", headers=key, files={"file": ("k.log", b"hello world\n")})
    assert bad.status_code == 422
    keys = b"# keys\nCLIENT_RANDOM 0011aabb 22ccdd33\n"
    r = admin.put(f"/api/captures/{capture_id}/keylog", headers=key, files={"file": ("sslkeys.log", keys)})
    assert r.status_code == 202 and r.json()["keylog"] is True
    with SessionLocal() as db:
        stored = db.get(NetworkCapture, capture_id).keylog
    assert "CLIENT_RANDOM" not in stored
    assert [c for c in calls if c[2] == "/analyze"][-1][3]["keylog"] == keys.decode()
    assert admin.delete(f"/api/captures/{capture_id}/keylog", headers=key).json()["keylog"] is False


def test_capture_limits_and_removal(admin: TestClient, workers, monkeypatch):
    key = make_key(admin)
    _incident(admin, key)
    monkeypatch.setattr(settings, "PCAP_MAX_MB", 0)
    assert (
        admin.post("/api/incidents/net1/captures", headers=key, files={"file": ("a.pcapng", _pcap())}).status_code
        == 413
    )
    monkeypatch.setattr(settings, "PCAP_MAX_MB", 500)
    capture_id = admin.post("/api/incidents/net1/captures", headers=key, files={"file": ("a.pcapng", _pcap())}).json()[
        "capture"
    ]["id"]
    assert store.find_capture(capture_id) is not None
    # Removed from the incident, the capture stays as an artifact until it is deleted.
    assert admin.delete(f"/api/incidents/net1/captures/{capture_id}", headers=key).status_code == 204
    assert admin.get("/api/incidents/net1", headers=key).json()["data"]["network"]["captures"] == []
    assert admin.get(f"/api/captures/{capture_id}", headers=key).json()["incidentId"] is None
    assert admin.delete(f"/api/artifacts/pcap-{capture_id}", headers=key).status_code == 204
    assert store.find_capture(capture_id) is None
    assert admin.get(f"/api/captures/{capture_id}", headers=key).status_code == 404
    # Deleting the incident deletes the captures only it holds.
    other = admin.post("/api/incidents/net1/captures", headers=key, files={"file": ("b.pcapng", _pcap())}).json()[
        "capture"
    ]
    assert admin.delete("/api/incidents/net1", headers=key).status_code == 204
    assert store.find_capture(other["id"]) is None


def test_isolated_browser_session_becomes_a_capture(admin: TestClient, workers):
    calls, browser = workers
    key = make_key(admin)
    _incident(admin, key, "web1")
    browser["entries"] = [ENTRIES[0]]
    state = admin.post(
        "/api/browser/sessions",
        headers=key,
        json={"url": "https://login-paypa1.example/", "network": True, "incident": "web1"},
    )
    assert state.status_code == 201, state.text
    session = state.json()["id"]
    assert state.json()["captureId"] == session
    ref = admin.get("/api/incidents/web1", headers=key).json()["data"]["network"]["captures"][0]
    assert ref["status"] == "live" and ref["kind"] == "browser" and ref["network"] is True
    assert admin.get("/api/incidents/web1/captures", headers=key).json()["captures"][0]["id"] == session

    browser["entries"] = [ENTRIES[1]]  # the held POST, seen after an action
    admin.post(f"/api/browser/sessions/{session}/action", headers=key, json={"type": "click", "x": 1, "y": 1})
    listing = admin.get(f"/api/captures/{session}/requests", headers=key).json()
    assert [e["state"] for e in listing["entries"]] == ["done", "held"] and listing["live"]
    assert "body" not in listing["entries"][1]["request"]
    full = admin.get(f"/api/captures/{session}/requests/2", headers=key).json()
    assert base64.b64decode(full["request"]["body"]).endswith(b"pass=Winter2026")
    live = admin.get(f"/api/browser/sessions/{session}/network", headers=key).json()
    assert len(live["entries"]) == 2

    released = admin.post(
        f"/api/browser/sessions/{session}/action", headers=key, json={"type": "policy", "releasePosts": True}
    )
    assert released.status_code == 200
    audit = admin.get("/api/audit?q=submissions").json()["entries"]
    assert any("RELEASED" in e["details"] for e in audit)
    assert admin.post(f"/api/captures/{session}/rpc", headers=key, json={"method": "status"}).status_code == 409

    browser["closed"] = True
    assert admin.delete(f"/api/browser/sessions/{session}", headers=key).status_code == 204
    detail = admin.get(f"/api/captures/{session}", headers=key).json()
    assert detail["status"] == "ready" and detail["meta"]["held"][0]["url"].endswith("/post.php")
    with open(store.find_capture(session), "rb") as handle:
        assert b"HELD by Nik" in handle.read()
    document = json.loads(admin.get(f"/api/captures/{session}/har", headers=key).content)
    assert [e["_nikState"] for e in document["log"]["entries"]] == ["done", "held"]
    report = admin.post(
        "/api/incidents/web1/report", headers=key, json={"format": "html", "sections": ["network"], "scope": "all"}
    )
    assert "submissions held, not sent" in report.text and "post.php" in report.text


def test_session_without_incident_keeps_no_log(admin: TestClient, workers):
    key = make_key(admin)
    state = admin.post("/api/browser/sessions", headers=key, json={"url": "https://x.example/"}).json()
    assert "captureId" not in state
    with SessionLocal() as db:
        assert db.get(NetworkCapture, state["id"]) is None
