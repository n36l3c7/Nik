"""URL scans: normalising an address, the verdict, and the API with a faked isolated browser."""

from __future__ import annotations

import base64
import time

import pytest
from fastapi.testclient import TestClient

from app import urlscan
from app.core.config import settings
from app.mail.verify import org_domain
from app.network import store
from app.workers import previews
from tests.conftest import make_key

SESSION = "5" * 32
JPEG = b"\xff\xd8\xff\xe0fake-jpeg"
PHISH = "https://login-paypa1.top/signin?id=8841"


def test_normalise_understands_defanged_text_and_refuses_internal_hosts():
    assert urlscan.normalise("hxxps://Login-Paypa1[.]top/signin#top") == "https://login-paypa1.top/signin"
    assert urlscan.normalise("example.com") == "https://example.com/"
    assert urlscan.normalise("http://example.com:8080/a?b=1") == "http://example.com:8080/a?b=1"
    for bad in ("ftp://example.com/x", "http://10.0.0.5/", "http://localhost/", "https://", "javascript:alert(1)"):
        with pytest.raises(urlscan.UrlError):
            urlscan.normalise(bad)
    assert urlscan.scan_id("https://example.com/") == urlscan.scan_id(urlscan.normalise("EXAMPLE.com"))
    assert urlscan.display("https://login-paypa1.top/signin?id=8841") == "login-paypa1.top/signin"


def _assess(url, final, title, page, chain=(), certificate=None, events=(), own=()):
    return urlscan.assess(url, final, title, page, list(chain), certificate, list(events), list(own), None, now=1e9)


def test_a_credential_page_on_a_lookalike_domain_is_phishing():
    page = {
        "passwordFields": 1,
        "forms": [{"action": "https://collect.paypa1-cdn.top/c", "method": "post", "password": True, "inputs": []}],
    }
    chain = [
        {"url": "https://bit.ly/3xQ9a", "status": 302},
        {"url": "https://track.mailer-cdn.example/c", "status": 302},
        {"url": PHISH, "status": 200},
    ]
    result = _assess(
        "https://bit.ly/3xQ9a",
        PHISH,
        "Log in to your PayPal account",
        page,
        chain,
        {"validFrom": 1e9 - 2 * 86400},
        [{"kind": "download", "text": "download refused: invoice.exe"}],
    )
    ids = {f["id"] for f in result["findings"]}
    assert {"lookalike", "risky-tld", "shortener", "password", "brand", "form-elsewhere", "redirects"} <= ids
    assert {"new-certificate", "download"} <= ids
    assert result["verdict"] == "phishing" and result["score"] == 100
    assert result["findings"][0]["points"] == 40  # the strongest reason first


def test_a_genuine_sign_in_page_is_clean():
    page = {"passwordFields": 1, "forms": [{"action": "https://www.paypal.com/signin", "password": True}]}
    result = _assess("https://www.paypal.com/signin", "https://www.paypal.com/signin", "Log in to PayPal", page)
    assert result == {"findings": [], "score": 0, "verdict": "clean"}
    # A password asked over plain http on an unknown domain is suspicious on its own.
    plain = _assess("http://portal.example.org/", "http://portal.example.org/", "Portal", {"passwordFields": 1})
    assert plain["verdict"] == "suspicious" and {f["id"] for f in plain["findings"]} == {"password", "password-http"}
    # The organisation's own domains are never flagged for asking a password.
    own = _assess(
        "http://sso.contoso.example/", "http://sso.contoso.example/", "", {"passwordFields": 1}, own=["contoso.example"]
    )
    assert own["findings"] == [] and org_domain("sso.contoso.example") == "contoso.example"


@pytest.fixture()
def browser(monkeypatch):
    """A fake isolated browser: one page with a password form, three navigations."""
    calls = []
    entries = [
        {"id": 1, "method": "GET", "url": "https://bit.ly/3xQ9a", "navigation": True, "frame": "main",
         "state": "done", "response": {"status": 302, "serverIp": "67.199.248.10"}},
        {"id": 2, "method": "GET", "url": PHISH, "navigation": True, "frame": "main", "state": "done",
         "response": {"status": 200, "serverIp": "203.0.113.10", "tls": {"validFrom": time.time() - 86400}}},
        {"id": 3, "method": "GET", "url": "https://login-paypa1.top/logo.png", "navigation": False, "frame": "main",
         "state": "done", "response": {"status": 200}},
    ]  # fmt: skip

    def open_session(owner, network, html=None, url=None):
        calls.append(("open", owner, network, url))
        return {"id": SESSION, "url": url}

    def act(owner, session_id, action):
        calls.append(("act", action["type"]))
        return {
            "id": session_id,
            "url": PHISH,
            "title": "Log in to your PayPal account",
            "screenshot": base64.b64encode(JPEG).decode(),
            "events": [],
            "page": {
                "passwordFields": 1,
                "links": 4,
                "scripts": 2,
                "frames": 0,
                "text": "Email Password Log In",
                "forms": [
                    {
                        "action": "https://collect.paypa1-cdn.top/c",
                        "method": "post",
                        "password": True,
                        "inputs": ["text"],
                    }
                ],
            },
        }

    def worker(method, path, body=None):
        calls.append((method, path.split("?")[0]))
        if method == "GET" and path.startswith(f"/sessions/{SESSION}/network"):
            return {"entries": entries, "cursor": 3, "counts": {"total": 3}, "closed": False}
        return {}

    monkeypatch.setattr(settings, "BROWSER_URL", "http://browser:8730")
    monkeypatch.setattr(previews, "open_session", open_session)
    monkeypatch.setattr(previews, "act", act)
    monkeypatch.setattr(previews, "close_session", lambda owner, session_id: calls.append(("close", session_id)))
    monkeypatch.setattr(previews, "_browser", worker)
    return calls


def test_url_scan_lifecycle(admin: TestClient, browser):
    key = make_key(admin)
    admin.post("/api/incidents", headers=key, json={"id": "u1", "name": "u1", "data": {}})

    r = admin.post("/api/artifacts/urls", headers=key, json={"url": "hxxps://bit[.]ly/3xQ9a"})
    assert r.status_code == 201, r.text
    scan = r.json()
    assert (
        scan["known"] is False and scan["url"] == "https://bit.ly/3xQ9a" and scan["artifactId"] == f"url-{scan['id']}"
    )
    # The browser visited it with network access and only looked.
    assert ("open", "api:test", True, "https://bit.ly/3xQ9a") in browser and ("act", "inspect") in browser
    assert ("close", SESSION) in browser

    done = admin.get(f"/api/urls/{scan['id']}", headers=key).json()
    assert done["status"] == "done" and done["verdict"] == "phishing" and done["score"] >= 70
    result = done["result"]
    assert result["finalUrl"] == PHISH and result["title"].startswith("Log in")
    assert [step["url"] for step in result["chain"]] == ["https://bit.ly/3xQ9a", PHISH]
    assert result["forms"][0]["password"] is True and result["serverIp"] == "203.0.113.10"
    assert {"lookalike", "password", "form-elsewhere", "shortener"} <= {f["id"] for f in result["findings"]}
    shot = admin.get(f"/api/urls/{scan['id']}/screenshot", headers=key)
    assert shot.status_code == 200 and shot.content == JPEG and shot.headers["content-type"] == "image/jpeg"

    # An artifact like the others, with the visit's capture as its child.
    artifact = admin.get(f"/api/artifacts/url-{scan['id']}", headers=key).json()
    assert artifact["kind"] == "url" and artifact["name"] == "bit.ly/3xQ9a" and artifact["verdict"] == "phishing"
    assert [(c["relation"], c["id"]) for c in artifact["children"]] == [("session", f"pcap-{SESSION}")]
    assert store.find_capture(SESSION) is not None
    assert admin.get("/api/artifacts", headers=key, params={"kind": "url"}).json()["total"] == 1

    # The same address again is recognised, not visited twice.
    visits = browser.count(("act", "inspect"))
    again = admin.post("/api/artifacts/urls", headers=key, json={"url": "https://bit.ly/3xQ9a", "incident": "u1"})
    assert again.status_code == 201 and again.json()["known"] is True
    assert browser.count(("act", "inspect")) == visits
    # Linked to the incident: its reference and its indicators.
    doc = admin.get("/api/incidents/u1", headers=key).json()
    assert [ref["id"] for ref in doc["data"]["urls"]["scans"]] == [scan["id"]]
    assert doc["data"]["urls"]["scans"][0]["verdict"] == "phishing"
    values = {i["value"] for i in admin.get("/api/incidents/u1/iocs", headers=key).json()["iocs"]}
    assert {"login-paypa1.top", "203.0.113.10"} <= values

    # Scanning again replaces the result and the capture.
    assert admin.post(f"/api/urls/{scan['id']}/rescan", headers=key).status_code == 202
    assert browser.count(("act", "inspect")) == visits + 1
    assert admin.get(f"/api/urls/{scan['id']}", headers=key).json()["status"] == "done"

    # Deleted: the reference, the screenshot and the capture go with it.
    assert admin.delete(f"/api/artifacts/url-{scan['id']}", headers=key).status_code == 204
    assert admin.get(f"/api/urls/{scan['id']}", headers=key).status_code == 404
    assert admin.get("/api/incidents/u1", headers=key).json()["data"]["urls"]["scans"] == []
    assert store.find_capture(SESSION) is None and not urlscan.screenshot_path(scan["id"]).exists()


def test_url_scan_errors(admin: TestClient, monkeypatch):
    key = make_key(admin)
    for bad in ("http://192.168.1.1/admin", "ftp://example.com/", "not a url at all"):
        assert admin.post("/api/artifacts/urls", headers=key, json={"url": bad}).status_code == 422
    assert (
        admin.post("/api/artifacts/urls", headers=key, json={"url": "https://e.com", "incident": "x"}).status_code
        == 404
    )
    read_only = make_key(admin, scopes=["read"])
    assert admin.post("/api/artifacts/urls", headers=read_only, json={"url": "https://example.com"}).status_code == 403

    # Without the isolated browser the address is kept, with the reason it was not visited.
    monkeypatch.setattr(settings, "BROWSER_URL", "")
    scan = admin.post("/api/artifacts/urls", headers=key, json={"url": "https://example.com/x"}).json()
    state = admin.get(f"/api/urls/{scan['id']}", headers=key).json()
    assert state["status"] == "error" and "not configured" in state["error"]
    assert admin.get(f"/api/urls/{scan['id']}/screenshot", headers=key).status_code == 404
    assert admin.get(f"/api/urls/{'0' * 32}", headers=key).status_code == 404
