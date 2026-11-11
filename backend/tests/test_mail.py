"""Mail Analysis: parsing, authentication, links, attachments, verdict and API."""

from __future__ import annotations

import base64
import io
import zipfile
from email.message import EmailMessage

import pytest
import pyzipper
from fastapi.testclient import TestClient

from app.mail import verify
from app.mail.analyze import analyse_mail
from app.mail.attachments import inspect, passwords_in
from app.mail.content import pressure, remote_images, safe_html
from app.mail.headers import hops, origin_ip, reported_auth, sender
from app.mail.links import analyse, extract, lookalike, unwrap
from app.mail.parse import MailError, decompress_rtf, parse_mail
from tests import cfb
from tests.conftest import make_key

ORG = {"orgDomains": ["contoso.it"], "trustedAuthServers": ["mx.contoso.it"]}


def _encrypted_zip(name: str, data: bytes, password: bytes) -> bytes:
    buffer = io.BytesIO()
    with pyzipper.AESZipFile(buffer, "w", encryption=pyzipper.WZ_AES) as archive:
        archive.setpassword(password)
        archive.writestr(name, data)
    return buffer.getvalue()


def phishing_message() -> bytes:
    m = EmailMessage()
    m["Received"] = (
        "from mx.contoso.it (mx.contoso.it [10.0.0.5]) by mbox.contoso.it with ESMTP; Tue, 10 Nov 2026 09:00:05 +0100"
    )
    m["Authentication-Results"] = (
        "mx.contoso.it; spf=softfail smtp.mailfrom=bounce.evil.top; dkim=none;"
        " dmarc=fail (p=reject) header.from=paypai.com"
    )
    m["Received"] = (
        "from mail.evil.top (mail.evil.top [185.220.101.47]) by mx.contoso.it with ESMTPS id abc;"
        " Tue, 10 Nov 2026 09:00:02 +0100"
    )
    m["From"] = '"PayPal Service" <service@paypai.com>'
    m["Reply-To"] = "refunds@gmail.com"
    m["Return-Path"] = "<x@bounce.evil.top>"
    m["To"] = "mario.rossi@contoso.it"
    m["Subject"] = "URGENTE: il tuo account verrà sospeso"
    m["Date"] = "Tue, 10 Nov 2026 08:59:50 +0100"
    m["Message-ID"] = "<123@evil.top>"
    m.set_content("Verifica il tuo account entro 24 ore: https://bit.ly/abc\nPassword: Fattura2026")
    m.add_alternative(
        '<p>Gentile cliente,</p><p style="font-size:0">random words</p>'
        '<a href="https://login-paypa1.top/x">https://www.paypal.com/signin</a>'
        '<img src="https://trk.evil.top/o.gif?u=mario%40contoso.it" width=1 height=1>'
        "<script>alert(1)</script>",
        subtype="html",
    )
    m.add_attachment(
        _encrypted_zip("fattura.pdf.exe", b"MZ" + b"\0" * 100, b"Fattura2026"),
        "application",
        "zip",
        filename="Fattura.zip",
    )
    inner = EmailMessage()
    inner["From"] = "a@b.example"
    inner["Subject"] = "forwarded"
    inner.set_content("see http://inner.evil.top/")
    m.add_attachment(inner)
    return bytes(m)


@pytest.fixture()
def no_dns(monkeypatch):
    """DMARC p=reject for paypai.com, nothing else; SPF answers softfail."""
    records = {"_dmarc.paypai.com": ["v=DMARC1; p=reject"]}
    monkeypatch.setattr(verify, "txt_lookup", lambda name: records.get(name, []))
    monkeypatch.setattr(
        verify, "verify_spf", lambda ip, mail_from, helo: {"result": "softfail", "detail": "", "domain": "evil.top"}
    )


# --------------------------------------------------------------------------- #
# Parsing                                                                     #
# --------------------------------------------------------------------------- #
def test_parse_eml_bodies_attachments_and_nested_message():
    parsed = parse_mail(phishing_message())
    assert parsed["format"] == "eml"
    assert "Verifica il tuo account" in parsed["text"]
    assert "<script>" in parsed["html"]
    names = [a["name"] for a in parsed["attachments"]]
    assert names == ["Fattura.zip", "attached-message.eml"]
    nested = parsed["attachments"][1]["nested"]
    assert nested["headers"][1] == ["Subject", "forwarded"]


def test_parse_rejects_files_that_are_not_mail():
    with pytest.raises(MailError):
        parse_mail(b"")
    with pytest.raises(MailError):
        parse_mail(b"MZ\x90\x00 not a message")
    with pytest.raises(MailError):
        parse_mail(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\0" * 600)


def test_decompress_rtf_specification_example():
    # MS-OXRTFCP 3.1.1, compressed RTF example.
    data = bytes.fromhex(
        "2d0000002b0000004c5a4675f1c5c7a703000a007263706731323542320af32068656c090020627705b06c647d0a800fa0"
    )
    assert decompress_rtf(data) == b"{\\rtf1\\ansi\\ansicpg1252\\pard hello world}\r\n"


# --------------------------------------------------------------------------- #
# Headers                                                                     #
# --------------------------------------------------------------------------- #
def test_route_sender_and_reported_auth():
    parsed = parse_mail(phishing_message())
    chain = hops(parsed["headers"])
    assert [h["from"] for h in chain] == ["mail.evil.top", "mx.contoso.it"]
    assert chain[1]["delayMs"] == 3000 and not chain[1]["backwards"]
    assert origin_ip(chain, ["contoso.it"]) == "185.220.101.47"
    who = sender(parsed["headers"])
    assert who["from"] == {"name": "PayPal Service", "address": "service@paypai.com", "domain": "paypai.com"}
    assert who["replyTo"][0]["address"] == "refunds@gmail.com"
    assert who["returnPathDomain"] == "bounce.evil.top"
    auth = reported_auth(parsed["headers"], ["mx.contoso.it"])
    dmarc = auth["summary"]["dmarc"]
    assert dmarc == {"result": "fail", "detail": "(p=reject) header.from=paypai.com", "trusted": True}
    assert auth["summary"]["spf"]["result"] == "softfail"


# --------------------------------------------------------------------------- #
# DKIM / DMARC through (fake) DNS                                             #
# --------------------------------------------------------------------------- #
def test_dkim_signature_verified_and_dmarc_aligned():
    import dkim
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    public = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    message = b"From: Billing <billing@news.example.com>\r\nTo: a@contoso.it\r\nSubject: hi\r\n\r\nHello.\r\n"
    signed = dkim.sign(message, b"s1", b"example.com", private, include_headers=[b"from", b"to", b"subject"]) + message
    records = {
        "s1._domainkey.example.com": ["v=DKIM1; k=rsa; p=" + base64.b64encode(public).decode()],
        "_dmarc.example.com": ["v=DMARC1; p=quarantine; adkim=r"],
    }
    result = verify.verify_all(signed, "news.example.com", None, "", "", lambda name: records.get(name, []))
    assert result["dkim"]["result"] == "pass" and result["dkim"]["domain"] == "example.com"
    assert result["dmarc"]["result"] == "pass" and result["dmarc"]["policy"] == "quarantine"
    assert result["spf"]["result"] == "none"

    tampered = signed.replace(b"Hello.", b"Pay me.")
    result = verify.verify_all(tampered, "news.example.com", None, "", "", lambda name: records.get(name, []))
    assert result["dkim"]["result"] == "fail"
    assert result["dmarc"]["result"] == "fail"


def test_dmarc_dns_failure_is_temperror_not_pass():
    def broken(_name):
        raise OSError("timeout")

    result = verify.verify_dmarc("example.com", {"result": "pass", "domain": "example.com"}, [], broken)
    assert result["result"] == "temperror"


# --------------------------------------------------------------------------- #
# Links and body                                                              #
# --------------------------------------------------------------------------- #
def test_lookalikes_and_genuine_domains():
    org = verify.org_domain
    assert lookalike("paypai.com", [], org) == "paypal"
    assert lookalike("login-micros0ft365.com", [], org) == "microsoft"
    assert lookalike("xn--mcrosoft-c2a.com", [], org) == "microsoft"
    assert lookalike("poste-italiane.info", [], org) == "poste"
    assert lookalike("contoso-it.top", ["contoso.it"], org) == "contoso"
    assert lookalike("outlook.office365.com", [], org) is None
    assert lookalike("www.contoso.it", ["contoso.it"], org) is None
    assert lookalike("groups.io", [], org) is None


def test_link_unwrapping_and_findings():
    safelink = "https://eur01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.top%2Fa&data=x&reserved=0"
    assert unwrap(safelink) == ("https://evil.top/a", "Microsoft SafeLinks")
    # Only the gateways' own hosts are unwrapped, not look-alikes containing their names.
    lookalike_gateway = "https://evilsafelinks.protection.outlook.com.evil.top/?url=https%3A%2F%2Fx.top"
    assert unwrap(lookalike_gateway) == (lookalike_gateway, None)
    assert unwrap("https://notgoogle.com/url?q=https://x.top")[1] is None
    assert unwrap("https://www.google.com/url?q=https://x.top") == ("https://x.top", "Google redirect")
    links = extract('<a href="https://login-paypa1.top/x">https://www.paypal.com/signin</a>', "")
    assert [link["url"] for link in links] == ["https://login-paypa1.top/x"]
    found = {f["id"] for f in analyse(links, [], verify.org_domain)[0]["findings"]}
    assert {"text-mismatch", "lookalike", "risky-tld"} <= found


def test_safe_html_strips_active_content_and_reveals_hidden_text():
    html = (
        '<p style="font-size:0">hidden</p><img src="cid:logo"><script>x()</script>'
        '<a href="javascript:alert(1)" onclick="x()">click</a><iframe src="https://x"></iframe>'
        '<form action="https://evil.top"><input name="p"></form>'
        '<span style="color:#fff;background:#0078d4">button</span>'
    )
    cleaned, hidden = safe_html(html, {"logo": ("image/png", b"\x89PNG")})
    assert hidden == 1
    assert "script" not in cleaned and "iframe" not in cleaned and "onclick" not in cleaned
    assert "javascript:" not in cleaned and "<form" not in cleaned and "<input" not in cleaned
    assert 'src="data:image/png;base64,iVBORw=="' in cleaned
    assert remote_images('<img src="https://t.example/o.gif" width="1" height="1">')[0]["tracking"]
    kinds = {p["kind"] for p in pressure("Urgent: unpaid invoice, buy gift cards and keep this confidential")}
    assert kinds == {"urgency", "payment", "gift cards", "secrecy"}


# --------------------------------------------------------------------------- #
# Attachments                                                                 #
# --------------------------------------------------------------------------- #
def test_attachment_findings():
    exe = inspect({"name": "invoice.pdf.exe", "data": b"MZ" + b"\0" * 64}, "")
    assert {f["id"] for f in exe["findings"]} >= {"executable", "double-extension"}
    disguised = inspect({"name": "report.pdf", "data": b"MZ" + b"\0" * 64}, "")
    assert "disguised-executable" in {f["id"] for f in disguised["findings"]}
    assert passwords_in("Allegato protetto. Password: Fattura2026.") == ["Fattura2026"]
    archive = inspect(
        {"name": "f.zip", "data": _encrypted_zip("a.js", b"WScript.Shell", b"Fattura2026")}, "password: Fattura2026"
    )
    assert archive["archive"]["password"] == "Fattura2026"
    assert archive["archive"]["entries"][0]["name"] == "a.js"
    assert {"encrypted-archive", "archive-executable"} <= {f["id"] for f in archive["findings"]}
    plain = io.BytesIO()
    with zipfile.ZipFile(plain, "w") as z:
        z.writestr("notes.txt", "hello")
    assert inspect({"name": "notes.zip", "data": plain.getvalue()}, "")["findings"] == []
    invite = inspect(
        {
            "name": "invite.ics",
            "content_type": "text/calendar",
            "data": b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:Pay\r\nDESCRIPTION:https://cal.evil.top/x\r\n"
            b"END:VEVENT\r\nEND:VCALENDAR\r\n",
        },
        "",
    )
    assert invite["calendar"]["summary"] == "Pay" and invite["calendar"]["urls"] == ["https://cal.evil.top/x"]


# --------------------------------------------------------------------------- #
# Verdict                                                                     #
# --------------------------------------------------------------------------- #
def test_phishing_verdict_with_explained_findings(no_dns):
    result = analyse_mail(phishing_message(), ORG)
    assert result["verdict"] == "phishing" and result["score"] == 100
    ids = {f["id"] for f in result["findings"]}
    assert {"from-lookalike", "dmarc-fail", "reply-to-mismatch", "link-lookalike", "hidden-text"} <= ids
    assert "attachment-encrypted-archive" in ids
    assert result["auth"]["verified"]["dmarc"]["result"] == "fail"
    assert result["originIp"] == "185.220.101.47"
    values = {(i["type"], i["value"]) for i in result["iocs"]}
    assert ("ip", "185.220.101.47") in values and ("url", "https://login-paypa1.top/x") in values
    assert ("url", "http://inner.evil.top/") in values  # from the attached message
    assert "<script>" not in result["body"]["html"]


def test_ordinary_message_is_clean(no_dns):
    m = EmailMessage()
    m["From"] = "Anna <anna@contoso.it>"
    m["To"] = "mario@contoso.it"
    m["Subject"] = "Minutes"
    m["Authentication-Results"] = "mx.contoso.it; spf=pass smtp.mailfrom=contoso.it; dkim=pass; dmarc=pass"
    m.set_content("Here are the minutes of today's meeting.")
    result = analyse_mail(bytes(m), ORG, check_dns=False)
    assert result["verdict"] == "clean" and result["findings"] == []


# --------------------------------------------------------------------------- #
# API                                                                         #
# --------------------------------------------------------------------------- #
def test_mail_api_flow(admin: TestClient, no_dns):
    key = make_key(admin)
    assert admin.post("/api/incidents", headers=key, json={"id": "p1", "name": "p1", "data": {}}).status_code == 201
    settings = admin.get("/api/settings").json()
    r = admin.put("/api/settings", json={**settings, "mail": {"orgDomains": ["Contoso.it."], "trustedAuthServers": []}})
    assert r.status_code == 200 and r.json()["mail"]["orgDomains"] == ["contoso.it"]

    r = admin.post("/api/incidents/p1/mails", headers=key, files={"file": ("phish.eml", phishing_message())})
    assert r.status_code == 201, r.text
    ref = r.json()["message"]
    sha = ref["sha256"]
    assert ref["verdict"] == "phishing" and ref["fileName"] == "phish.eml" and ref["from"] == "service@paypai.com"

    detail = admin.get(f"/api/mails/{sha}", headers=key).json()
    assert detail["analysis"]["verdict"] == "phishing" and detail["incidents"] == [{"id": "p1", "name": "p1"}]
    assert admin.get(f"/api/mails/{sha}/source", headers=key).json()["text"].startswith("Received:")

    chunk = admin.get(f"/api/mails/{sha}/attachments/0/bytes?length=4", headers=key).json()
    assert base64.b64decode(chunk["data"]) == b"PK\x03\x04"
    nested = admin.get(f"/api/mails/{sha}/attachments/1.0/bytes", headers=key)
    assert nested.status_code == 404  # the attached message has no attachments
    archive = admin.get(f"/api/mails/{sha}/attachments/0/download?password=pw", headers=key)
    with pyzipper.AESZipFile(io.BytesIO(archive.content)) as z:
        z.setpassword(b"pw")
        assert z.namelist() == ["Fattura.zip"]

    r = admin.post(f"/api/incidents/p1/mails/{sha}/attachments/0/sample", headers=key)
    assert r.status_code == 201, r.text
    assert r.json()["sample"]["fileName"] == "Fattura.zip"

    summary = admin.get("/api/incidents?view=summary", headers=key).json()["incidents"]
    assert summary[0]["hasMail"] is True
    iocs = admin.get("/api/incidents/p1/iocs", headers=key).json()
    sources = {s for i in iocs.get("iocs", iocs if isinstance(iocs, list) else []) for s in i["sources"]}
    assert "mail:phish.eml" in sources

    report = admin.post(
        "/api/incidents/p1/report", headers=key, json={"format": "html", "sections": ["mails", "evidence"]}
    )
    assert "service@paypai.com" in report.text and "imitates paypal" in report.text and "phish.eml" in report.text

    assert admin.post(f"/api/mails/{sha}/reanalyse", headers=key).json()["verdict"] == "phishing"
    # Removed from the incident, the message stays as an artifact until it is deleted.
    assert admin.delete(f"/api/incidents/p1/mails/{sha}", headers=key).status_code == 204
    assert admin.get(f"/api/mails/{sha}", headers=key).status_code == 200
    assert admin.delete(f"/api/artifacts/mail-{sha}", headers=key).status_code == 204
    assert admin.get(f"/api/mails/{sha}", headers=key).status_code == 404
    assert admin.get("/api/incidents?view=summary", headers=key).json()["incidents"][0]["hasMail"] is False


def test_mail_api_rejects_non_mail(admin: TestClient):
    key = make_key(admin)
    admin.post("/api/incidents", headers=key, json={"id": "p2", "name": "p2", "data": {}})
    r = admin.post("/api/incidents/p2/mails", headers=key, files={"file": ("x.eml", b"MZ\x90\x00binary")})
    assert r.status_code == 422
    assert admin.get("/api/mails/" + "0" * 64, headers=key).status_code == 404


def _utf16(text: str) -> bytes:
    return text.encode("utf-16-le")


def outlook_message() -> bytes:
    """An Outlook .msg: Internet headers, a body, an executable attachment and
    an attached Outlook message that kept no Internet headers."""
    headers = (
        "Received: from mail.evil.top (mail.evil.top [185.220.101.47]) by mx.contoso.it;"
        " Tue, 10 Nov 2026 09:00:02 +0100\r\nFrom: IT Service Desk <it@contoso-it.top>\r\n"
        "Subject: Password reset\r\nDate: Tue, 10 Nov 2026 09:00:00 +0100\r\n\r\n"
    )
    return cfb.build(
        {
            "__properties_version1.0": b"\0" * 32,
            "__substg1.0_007D001F": _utf16(headers),
            "__substg1.0_1000001F": _utf16("Reset your password now: https://contoso-it.top/reset " * 20),
            "__attach_version1.0_#00000000": {
                "__properties_version1.0": b"\0" * 16,
                "__substg1.0_3707001F": _utf16("invoice.pdf.exe"),
                "__substg1.0_37010102": b"MZ" + b"\0" * 5000,
            },
            "__attach_version1.0_#00000001": {
                "__properties_version1.0": b"\0" * 16,
                "__substg1.0_3707001F": _utf16("previous.msg"),
                "__substg1.0_3701000D": {
                    "__properties_version1.0": b"\0" * 24,
                    "__substg1.0_0037001F": _utf16("Old thread"),
                    "__substg1.0_0C1F001F": _utf16("boss@contoso.it"),
                    "__substg1.0_0C1A001F": _utf16("The Boss"),
                    "__substg1.0_1000001F": _utf16("Buy gift cards, I'm in a meeting."),
                },
            },
        }
    )


def test_parse_outlook_msg_with_embedded_message():
    parsed = parse_mail(outlook_message())
    assert parsed["format"] == "msg"
    assert ["Subject", "Password reset"] in parsed["headers"]
    assert parsed["text"].startswith("Reset your password now")
    exe, embedded = parsed["attachments"]
    assert exe["name"] == "invoice.pdf.exe" and len(exe["data"]) == 5002
    assert embedded["name"] == "previous.msg"
    assert ["From", "The Boss <boss@contoso.it>"] in embedded["nested"]["headers"]


def test_outlook_msg_verdict(no_dns):
    result = analyse_mail(outlook_message(), ORG)
    assert result["format"] == "msg" and result["auth"]["verified"] is None  # no original bytes to check DKIM on
    ids = {f["id"] for f in result["findings"]}
    assert {"from-lookalike", "attachment-executable", "attachment-double-extension"} <= ids
    assert result["verdict"] == "phishing"
    nested = result["attachments"][1]["message"]
    assert {p["kind"] for p in nested["body"]["pressure"]} >= {"gift cards", "secrecy"}


def test_exchange_online_results_without_authserv_id():
    hdrs = [
        [
            "Received",
            "from EUR03.prod.protection.outlook.com (10.1.1.1) by AM0PR01MB.eurprd01.prod.outlook.com;"
            " Tue, 10 Nov 2026 09:00:00 +0000",
        ],
        [
            "Authentication-Results",
            "spf=fail (sender IP is 185.220.101.47) smtp.mailfrom=evil.top; dkim=none (message not signed)"
            " header.d=none;dmarc=fail action=quarantine header.from=contoso.it;",
        ],
    ]
    auth = reported_auth(hdrs, ["outlook.com"])
    assert auth["entries"][0]["trusted"] is True
    assert {m: r["result"] for m, r in auth["summary"].items()} == {"spf": "fail", "dkim": "none", "dmarc": "fail"}
    assert reported_auth(hdrs, ["mx.google.com"])["entries"][0]["trusted"] is False
