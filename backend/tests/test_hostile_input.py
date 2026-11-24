"""Evidence built to hurt whoever opens it: bounded parsing, safe names, no outbound fetch."""

from __future__ import annotations

from urllib.parse import unquote

import pytest
from fastapi.testclient import TestClient

from app import report
from app.core import files
from app.core.config import settings
from app.core.db import SessionLocal, after_commit
from app.mail import verify


# --------------------------------------------------------------------------- #
# Uploads
# --------------------------------------------------------------------------- #
def test_an_oversized_evidence_file_is_refused_while_it_is_read(admin: TestClient, monkeypatch):
    admin.post("/api/incidents", json={"id": "h2", "data": {}})
    monkeypatch.setattr(settings, "ARTIFACT_MAX_MB", 1)
    big = {"file": (".bash_history", b"ls\n" * 400_000)}
    res = admin.post("/api/incidents/h2/upload?tab=commands&shell=bash", files=big)
    assert res.status_code == 413 and "1 MB" in res.json()["detail"]

    monkeypatch.setattr(settings, "SAMPLE_MAX_MB", 1)
    sample = admin.post("/api/incidents/h2/samples", files={"file": ("big.bin", b"A" * (1024 * 1024 + 1))})
    assert sample.status_code == 413
    mail = admin.post("/api/incidents/h2/mails", files={"file": ("big.eml", b"A" * (1024 * 1024 + 1))})
    assert mail.status_code == 413


# --------------------------------------------------------------------------- #
# Download names
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    ("name", "ascii_name", "real"),
    [
        ("invoice.pdf", "invoice.pdf", "invoice.pdf"),
        ("Счёт.pdf", "____.pdf", "Счёт.pdf"),
        ('a"b\r\nSet-Cookie: x=1.exe', "a_b__Set-Cookie: x=1.exe", "a_b__Set-Cookie: x=1.exe"),
        ("..\\..\\evil/../x", "_.._evil_.._x", "_.._evil_.._x"),
        # No separator is left, so the dots that remain name nothing.
        # U+202E reverses what follows on screen: "invoice‮fdp.exe" reads "invoiceexe.pdf".
        ("invoice\u202efdp.exe", "invoice_fdp.exe", "invoice_fdp.exe"),
        ("", "download", "download"),
    ],
)
def test_a_download_name_cannot_break_the_header_or_mislead(name, ascii_name, real):
    value = files.attachment_headers(name)["Content-Disposition"]
    plain, _, extended = value.partition("; filename*=UTF-8''")
    assert plain == f'attachment; filename="{ascii_name}"'
    assert unquote(extended) == real
    # Nothing that ends a header or a quoted string survives; the value fits latin-1 (what the server sends).
    assert "\r" not in value and "\n" not in value and value.count('"') == 2
    value.encode("latin-1")


def test_a_sample_downloads_under_a_name_in_any_script(admin: TestClient):
    admin.post("/api/incidents", json={"id": "h3", "data": {}})
    sha = admin.post("/api/incidents/h3/samples", files={"file": ("x.bin", b"MZ" + b"\x00" * 64)}).json()["sample"][
        "sha256"
    ]
    res = admin.get(f"/api/samples/{sha}/download", params={"name": "Счёт\r\nX-Evil: 1.exe"})
    assert res.status_code == 200 and res.content[:2] == b"PK"
    assert "x-evil" not in res.headers
    assert "filename*=UTF-8''" in res.headers["content-disposition"]


# --------------------------------------------------------------------------- #
# Timestamps
# --------------------------------------------------------------------------- #
def test_a_timestamp_no_calendar_holds_is_no_timestamp():
    # A value already stored by an older release must not break the report.
    assert report._ms(9e17) == "—"
    assert report._ms(1655526400000) == "2022-06-18 04:26 UTC"


# --------------------------------------------------------------------------- #
# Mail
# --------------------------------------------------------------------------- #
def test_only_the_first_dkim_signatures_are_verified():
    signature = "DKIM-Signature: v=1; a=rsa-sha256; d=evil.example; s=s{n}; h=from; bh=AAAA; b=AAAA\r\n"
    raw = ("".join(signature.format(n=n) for n in range(40)) + "From: a@evil.example\r\n\r\nbody\r\n").encode()
    asked = []

    def lookup(name):
        asked.append(name)
        return []

    results = verify.verify_dkim(raw, lookup)
    assert len(asked) <= verify.MAX_DKIM_SIGNATURES
    assert len(results) == verify.MAX_DKIM_SIGNATURES + 1
    assert results[-1]["result"] == "none" and "35 more signatures not checked" in results[-1]["detail"]


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def test_the_pdf_renderer_fetches_nothing(monkeypatch):
    pytest.importorskip("weasyprint")
    import socket
    import urllib.request

    attempts = []

    def refuse(*args, **kwargs):
        attempts.append(args)
        raise OSError("no network in this test")

    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(urllib.request.OpenerDirector, "_open", refuse)
    document = (
        '<html><body><img src="http://127.0.0.1:9/logo.png"><img src="file:///etc/passwd">'
        '<link rel="stylesheet" href="http://127.0.0.1:9/x.css"><p>report</p></body></html>'
    )
    assert report.to_pdf(document)[:4] == b"%PDF"
    assert attempts == []


# --------------------------------------------------------------------------- #
# Files and transactions
# --------------------------------------------------------------------------- #
def test_what_cannot_be_rolled_back_waits_for_the_commit(client: TestClient):
    done = []
    with SessionLocal() as db:
        after_commit(db, lambda: done.append("first"))
        db.rollback()
        assert done == []
        db.commit()
        assert done == ["first"]
        # Once: a later commit does not run it again.
        db.commit()
        assert done == ["first"]


def test_the_incident_search_takes_wildcards_literally(admin: TestClient):
    admin.post("/api/incidents", json={"id": "w1", "name": "100% phishing", "data": {}})
    admin.post("/api/incidents", json={"id": "w2", "name": "plain", "data": {}})
    names = lambda q: [row["name"] for row in admin.get("/api/incidents", params={"q": q}).json()["incidents"]]  # noqa: E731
    assert names("%") == ["100% phishing"]
    assert names("_") == []
    assert sorted(names("p")) == ["100% phishing", "plain"]
