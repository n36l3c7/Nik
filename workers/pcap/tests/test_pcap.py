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

import given  # noqa: E402
import nik_pcap  # noqa: E402
import server  # noqa: E402

FIXTURE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "phish.pcapng")
CAPTURE_ID = "c" * 32


@pytest.fixture()
def store(tmp_path, monkeypatch):
    """A capture on the disk of the test, and a worker that holds nothing yet: what it is given goes
    to a folder of its own (memory in the image), or to its work folder when it is large."""
    directory = tmp_path / "_captures" / CAPTURE_ID
    directory.mkdir(parents=True)
    shutil.copy(FIXTURE, directory / "capture.pcapng")
    (tmp_path / "work").mkdir()
    held = given.Given(
        str(tmp_path / "memory"),
        server.GIVEN.allowed,
        max_bytes=10**8,
        large=str(tmp_path / "work"),
        large_from=10**7,
    )
    monkeypatch.setattr(server, "GIVEN", held)
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


def _give(url, name, data, token="test-token"):
    request = urllib.request.Request(f"{url}/files/{name}", data=data, method="PUT", headers={"X-Pcap-Token": token})
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status
    except urllib.error.HTTPError as exc:
        return exc.code


def test_server(worker):
    name = f"_captures/{CAPTURE_ID}/capture.pcapng"
    body = {"id": CAPTURE_ID, "path": name}
    assert _post(f"{worker}/analyze", body, token="wrong")[0] == 401
    assert _post(f"{worker}/analyze", {**body, "path": "../../etc/passwd"})[0] == 400
    assert _post(f"{worker}/analyze", {**body, "path": f"_captures/{'d' * 32}/capture.pcapng"})[0] == 400
    # The worker does not see the store: it says which capture it lacks, and is given it.
    status, lacking = _post(f"{worker}/analyze", body)
    assert status == 409 and lacking["missing"] == [name]
    assert _post(f"{worker}/rpc", {**body, "method": "status"})[0] == 409
    with open(FIXTURE, "rb") as handle:
        capture = handle.read()
    assert _give(worker, name, capture, token="wrong") == 401
    assert _give(worker, "../../etc/passwd", capture) == 400
    assert _give(worker, f"{'a' * 64}.bin", capture) == 400
    assert _give(worker, name, capture) == 200
    held = server.GIVEN.path(name)
    # A small capture is kept in the folder that is memory in the image, never in the work folder.
    assert held and "memory" in held and not os.listdir(server.GIVEN.large)
    status, summary = _post(f"{worker}/analyze", body)
    assert status == 200 and summary["objects"] and summary["beacons"]
    status, result = _post(f"{worker}/rpc", {**body, "method": "status"})
    assert status == 200 and result["result"]["frames"] == summary["packets"]
    exe = next(o for o in summary["objects"] if o["name"] == "invoice.exe")
    status, item = _post(f"{worker}/rpc", {**body, "method": "download", "params": {"token": exe["token"]}})
    assert status == 200 and base64.b64decode(item["data"]).startswith(b"MZ")
    assert _post(f"{worker}/close", {"id": CAPTURE_ID})[0] == 200
    # Closed: its file is gone from the worker, and the next request asks for it again.
    assert server.GIVEN.path(name) is None and not os.path.exists(held)
    assert _post(f"{worker}/rpc", {**body, "method": "status"})[0] == 409


def test_a_large_capture_goes_to_the_work_folder_and_is_wiped_at_start(worker):
    name = f"_captures/{CAPTURE_ID}/capture.pcapng"
    server.GIVEN.large_from = 100  # anything is "large" here
    with open(FIXTURE, "rb") as handle:
        assert _give(worker, name, handle.read()) == 200
    held = server.GIVEN.path(name)
    assert held.startswith(server.GIVEN.large)
    status, result = _post(f"{worker}/rpc", {"id": CAPTURE_ID, "path": name, "method": "status"})
    assert status == 200 and result["result"]["frames"] > 50
    nik_pcap.SESSIONS.drop(CAPTURE_ID)
    # What a worker that stopped left in clear on its work folder is removed when it starts.
    server.GIVEN.clear()
    assert not os.path.exists(held) and server.GIVEN.path(name) is None


def _fake_tshark(tmp_path, monkeypatch, script: str):
    """Put a shell script in tshark's place."""
    path = tmp_path / "tshark"
    path.write_text("#!/bin/sh\n" + script)
    path.chmod(0o755)
    monkeypatch.setattr(nik_pcap.shutil, "which", lambda name: str(path))


def test_tshark_is_stopped_by_the_clock_even_when_it_prints_nothing(tmp_path, monkeypatch):
    """A dissector that stalls prints no line: the limit cannot wait for one."""
    import time

    _fake_tshark(tmp_path, monkeypatch, "sleep 300 & sleep 300\n")
    monkeypatch.setattr(nik_pcap, "TIMEOUT", 1.0)
    started = time.monotonic()
    with pytest.raises(nik_pcap.CaptureError, match="took more than 1 s"):
        list(nik_pcap._tshark_rows("capture.pcap", None))
    assert time.monotonic() - started < 15


def test_a_flood_of_warnings_does_not_block_tshark(tmp_path, monkeypatch):
    """More warnings than a pipe holds, then a row, then a failure: all three are seen."""
    script = (
        "i=0; while [ $i -lt 4000 ]; do echo 'tshark: a very long warning about a malformed packet ...........' >&2; "
        "i=$((i+1)); done\nprintf 'a\\tb\\n'\necho 'tshark: the last line' >&2\nexit 2\n"
    )
    _fake_tshark(tmp_path, monkeypatch, script)
    rows = []
    with pytest.raises(nik_pcap.CaptureError, match="the last line"):
        for row in nik_pcap._tshark_rows("capture.pcap", None):
            rows.append(row)
    assert len(rows) == 1


def test_a_named_analysis_says_how_far_it_is_and_a_restarted_worker_does_not_know_it(worker, monkeypatch):
    import jobs

    monkeypatch.setattr(server, "JOBS", jobs.Jobs())
    name = f"_captures/{CAPTURE_ID}/capture.pcapng"
    body = {"id": CAPTURE_ID, "path": name}
    with open(FIXTURE, "rb") as handle:
        assert _give(worker, name, handle.read()) == 200
    job = f"capture:{CAPTURE_ID}:1"
    seen, summarize = [], nik_pcap.summarize

    def asked() -> dict:
        request = urllib.request.Request(f"{worker}/jobs/{job}", headers={"X-Pcap-Token": "test-token"})
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return json.loads(exc.read())

    def watched(path, keylog):
        seen.append(asked())  # the backend asks while tshark reads
        return summarize(path, keylog)

    monkeypatch.setattr(nik_pcap, "summarize", watched)
    request = urllib.request.Request(
        f"{worker}/analyze", data=json.dumps(body).encode(), headers={"X-Pcap-Token": "test-token", jobs.HEADER: job}
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        assert response.status == 200 and json.loads(response.read())["objects"]
    assert seen[0]["state"] == "running" and seen[0]["progress"] == "reading the packets (1 of 2)"
    assert asked()["state"] == "finished"
    # Killed and started again: it knows nothing of the job, and holds no capture.
    monkeypatch.setattr(server, "JOBS", jobs.Jobs())
    server.GIVEN.clear()
    assert asked() == {"detail": "Unknown job", "unknown": True, "started": server.JOBS.started}
    status, lacking = _post(f"{worker}/analyze", body)
    assert status == 409 and lacking["missing"] == [name]
    wrong = urllib.request.Request(f"{worker}/jobs/{job}", headers={"X-Pcap-Token": "wrong"})
    with pytest.raises(urllib.error.HTTPError) as refused:
        urllib.request.urlopen(wrong, timeout=30)
    assert refused.value.code == 401
