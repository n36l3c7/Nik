"""The packet capture worker: needs tshark and sharkd (its image has both).

The fixture is a reconstructed browser session (backend app/network/pcapng.py):
a phishing page, an executable download, a credentials POST and six
connections every 30 s to a beacon host.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nik_pcap  # noqa: E402
import server  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "phish.pcapng")
CAPTURE_ID = "c" * 32


@pytest.fixture()
def store(tmp_path, monkeypatch):
    directory = tmp_path / "_captures" / CAPTURE_ID
    directory.mkdir(parents=True)
    shutil.copy(FIXTURE, directory / "capture.pcapng")
    monkeypatch.setattr(server, "SAMPLE_DIR", str(tmp_path))
    yield tmp_path
    nik_pcap.SESSIONS.drop(CAPTURE_ID)


def test_summary_finds_hosts_posts_and_the_beacon():
    summary = nik_pcap.summarize(FIXTURE)
    assert summary["packets"] > 50 and summary["first"] < summary["last"]
    assert {"name": "login-paypa1.example", "answers": ["203.0.113.10"]} in summary["dns"]
    assert summary["posts"][0]["url"] == "http://login-paypa1.example/post.php"
    assert {h["url"]: h["count"] for h in summary["http"]}["http://login-paypa1.example/signin"] == 1
    assert any(h["address"] == "198.51.100.7" for h in summary["hosts"])
    beacon = summary["beacons"][0]
    assert beacon["destination"] == "198.51.100.7" and beacon["count"] == 6 and beacon["interval"] == 30.0
    assert {p["name"] for p in summary["protocols"]} >= {"HTTP", "TCP", "DNS"}


def test_beacon_needs_regular_intervals():
    regular = {("a", "b", "443"): [0, 60, 120, 180, 240, 300]}
    irregular = {("a", "b", "443"): [0, 5, 100, 130, 400, 410]}
    assert nik_pcap.beacons(regular)[0]["interval"] == 60.0
    assert nik_pcap.beacons(irregular) == []
    assert nik_pcap.beacons({("a", "b", "80"): [0, 1, 2, 3, 4, 5]}) == []  # too frequent


def test_objects_are_listed_and_hashed(store):
    path = str(store / "_captures" / CAPTURE_ID / "capture.pcapng")
    found, expert = nik_pcap.objects(CAPTURE_ID, path, None)
    names = {o["name"] for o in found}
    assert {"invoice.exe", "post.php"} <= names
    exe = next(o for o in found if o["name"] == "invoice.exe")
    assert exe["sha256"] == __import__("hashlib").sha256(b"MZ" + b"\0" * 300).hexdigest()
    assert expert  # the reconstruction's comments are Expert Info entries
    data = nik_pcap.download(CAPTURE_ID, path, None, exe["token"])["data"]
    assert data.startswith(b"MZ")


def test_rpc_is_limited_to_safe_methods(store):
    path = str(store / "_captures" / CAPTURE_ID / "capture.pcapng")
    frames = nik_pcap.rpc(CAPTURE_ID, path, None, "frames", {"filter": 'http.request.method == "POST"'})
    assert len(frames) == 1 and "POST /post.php" in frames[0]["c"][6] and frames[0]["bg"]
    tree = nik_pcap.rpc(CAPTURE_ID, path, None, "frame", {"frame": frames[0]["num"]})
    assert tree["bytes"] and any(node.get("fn") == "http" or "Hypertext" in node["l"] for node in tree["tree"])
    with pytest.raises(nik_pcap.CaptureError):
        nik_pcap.rpc(CAPTURE_ID, path, None, "load", {"file": "/etc/passwd"})
    with pytest.raises(nik_pcap.CaptureError):
        nik_pcap.rpc(CAPTURE_ID, path, None, "check", {"filter": "http.reqeust"})
    with pytest.raises(nik_pcap.CaptureError):
        nik_pcap.rpc(CAPTURE_ID, path, None, "tap", {"tap0": "conv:IPv4"})
    # Columns come from the worker, never from the caller (some crash sharkd).
    rows = nik_pcap.rpc(CAPTURE_ID, path, None, "frames", {"limit": 2, "column0": "_ws.col.info:0"})
    assert len(rows[0]["c"]) == 7
    absolute = nik_pcap.rpc(CAPTURE_ID, path, None, "frames", {"limit": 1, "time": "absolute"})
    assert absolute[0]["c"][1].startswith("Nov 10, 2025 09:00:00") and absolute[0]["c"][6]


def test_keylog_is_written_only_while_in_use(monkeypatch, tmp_path):
    monkeypatch.setattr(nik_pcap.tempfile, "tempdir", str(tmp_path))
    nik_pcap.summarize(FIXTURE, "CLIENT_RANDOM 00 11")
    assert list(tmp_path.iterdir()) == []


@pytest.fixture()
def worker(store, monkeypatch):
    monkeypatch.setattr(server, "TOKEN", "test-token")
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()


def _post(url, body, token="test-token"):
    request = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"X-Pcap-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_server(worker):
    body = {"id": CAPTURE_ID, "path": f"_captures/{CAPTURE_ID}/capture.pcapng"}
    assert _post(f"{worker}/analyze", body, token="wrong")[0] == 401
    assert _post(f"{worker}/analyze", {**body, "path": "../../etc/passwd"})[0] == 400
    assert _post(f"{worker}/analyze", {**body, "path": f"_captures/{'d' * 32}/capture.pcapng"})[0] == 400
    status, summary = _post(f"{worker}/analyze", body)
    assert status == 200 and summary["objects"] and summary["beacons"]
    status, result = _post(f"{worker}/rpc", {**body, "method": "status"})
    assert status == 200 and result["result"]["frames"] == summary["packets"]
    exe = next(o for o in summary["objects"] if o["name"] == "invoice.exe")
    status, item = _post(f"{worker}/rpc", {**body, "method": "download", "params": {"token": exe["token"]}})
    assert status == 200 and base64.b64decode(item["data"]).startswith(b"MZ")
    assert _post(f"{worker}/close", {"id": CAPTURE_ID})[0] == 200
