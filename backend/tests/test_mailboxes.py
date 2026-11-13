"""Mailboxes: reading an mbox, a Maildir archive, conversations, import, incidents."""

from __future__ import annotations

import hashlib
import io
import tarfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import mailboxes
from tests.test_mail import no_dns  # noqa: F401 - a fixture


def message(
    msg_id: str, subject: str, sender: str, date: str, *, reply_to: str = "", body: str = "hello\n", extra: str = ""
) -> bytes:
    headers = [
        f"From: {sender}",
        "To: m.rossi@example.it",
        f"Subject: {subject}",
        f"Date: {date}",
        f"Message-ID: <{msg_id}@example>",
    ]
    if reply_to:
        headers += [f"In-Reply-To: <{reply_to}@example>", f"References: <{reply_to}@example>"]
    if extra:
        headers.append(extra)
    return ("\n".join(headers) + "\n\n" + body).encode()


PHISH_BODY = (
    "Your invoice is overdue. Sign in at http://login-paypa1.top/signin to avoid suspension.\n"
    "From the billing team\n"  # a body line that starts with "From ": escaped in an mbox
)
MESSAGES = [
    message("a1", "Invoice 4471", "billing@invoice-portal.co", "Tue, 10 Nov 2026 08:31:00 +0000", body=PHISH_BODY),
    message("b1", "Budget Q4", "hr@example.it", "Mon, 09 Nov 2026 12:00:00 +0000"),
    message("a2", "Re: Invoice 4471", "m.rossi@example.it", "Wed, 11 Nov 2026 16:48:00 +0000", reply_to="a1"),
    message("a3", "Fwd: Invoice 4471", "l.bianchi@example.it", "Thu, 12 Nov 2026 09:15:00 +0000", reply_to="a1"),
    message("b2", "RE: Budget Q4", "m.rossi@example.it", "Tue, 10 Nov 2026 15:20:00 +0000"),  # no reply headers
    message("a2", "Re: Invoice 4471", "m.rossi@example.it", "Wed, 11 Nov 2026 16:48:00 +0000", reply_to="a1"),  # copy
]


def mbox(messages: list[bytes] = MESSAGES) -> bytes:
    out = b""
    for raw in messages:
        escaped = b"".join(b">" + line if line.startswith(b"From ") else line for line in io.BytesIO(raw))
        out += b"From sender@example Tue Nov 10 08:31:00 2026\n" + escaped + b"\n"
    return out


def test_an_mbox_is_read_in_one_pass_and_each_message_comes_back_as_it_was(tmp_path: Path):
    path = tmp_path / "box.mbox"
    path.write_bytes(mbox())
    found = list(mailboxes.iter_messages(path))
    assert len(found) == len(MESSAGES)
    for original, item in zip(MESSAGES, found, strict=True):
        raw = mailboxes.read_message(path, item["offset"], item["length"])
        assert raw == original.rstrip(b"\n") + b"\n" or raw == original
        assert item["sha256"] == hashlib.sha256(raw).hexdigest()
    first = mailboxes.read_message(path, found[0]["offset"], found[0]["length"])
    assert b"\nFrom the billing team\n" in first and b">From" not in first
    assert mailboxes.describe(found[0]["headers"])["subject"] == "Invoice 4471"
    assert mailboxes.detect(b"From x", "a.mbox") == "mbox" and mailboxes.detect(b"!BDN....", "a.pst") == "pst"
    assert mailboxes.detect(b"PK\x03\x04", "maildir.zip") == "maildir" and mailboxes.detect(b"hello", "a.txt") is None


def test_conversations_follow_the_reply_headers_then_the_subject():
    rows = [{"seq": seq, **mailboxes.describe(raw.split(b"\n\n", 1)[0] + b"\n")} for seq, raw in enumerate(MESSAGES)]
    mailboxes.thread(rows)
    parents = {row["seq"]: row["parent"] for row in rows}
    assert parents[2] == 0 and parents[3] == 0  # two answers to the same message: a fork
    assert parents[4] == 1  # "RE: Budget Q4" with no reply header answers "Budget Q4"
    assert parents[0] is None and parents[1] is None
    assert rows[5]["duplicate_of"] == 2  # the same Message-ID twice
    threads = {row["seq"]: row["thread"] for row in rows}
    assert threads[0] == threads[2] == threads[3] == threads[5] != threads[1] == threads[4]
    assert mailboxes.subject_key("RE: Fwd: Re[2]: R:  Invoice 4471 ") == "invoice 4471"

    gmail = [
        {
            "seq": 0,
            **mailboxes.describe(
                message("g1", "Hello", "a@example.org", "Mon, 09 Nov 2026 12:00:00 +0000", extra="X-GM-THRID: 77")
            ),
        },
        {
            "seq": 1,
            **mailboxes.describe(
                message(
                    "g2", "Something else", "b@example.org", "Mon, 09 Nov 2026 13:00:00 +0000", extra="X-GM-THRID: 77"
                )
            ),
        },
    ]
    mailboxes.thread(gmail)
    assert gmail[0]["thread"] == gmail[1]["thread"]


def test_a_maildir_archive_becomes_an_mbox_without_being_unpacked(tmp_path: Path):
    archive = tmp_path / "maildir.zip"
    with zipfile.ZipFile(archive, "w") as out:
        out.writestr("Maildir/cur/1700000000.M1.host:2,S", MESSAGES[0])
        out.writestr("Maildir/new/1700000001.M2.host", MESSAGES[1])
        out.writestr("Maildir/tmp/ignored", b"not a message")
        out.writestr("../../etc/cur/escape", MESSAGES[2])  # only read, never written to a path
    target = tmp_path / "out.mbox"
    assert mailboxes.maildir_to_mbox(archive, target, 10_000_000) == 3
    found = list(mailboxes.iter_messages(target))
    assert [mailboxes.describe(item["headers"])["subject"] for item in found][:2] == ["Invoice 4471", "Budget Q4"]
    assert mailboxes.read_message(target, found[0]["offset"], found[0]["length"]) == MESSAGES[0]
    assert sorted(p.name for p in tmp_path.iterdir()) == ["maildir.zip", "out.mbox"]

    tarball = tmp_path / "maildir.tgz"
    with tarfile.open(tarball, "w:gz") as out:
        info = tarfile.TarInfo("box/cur/1")
        info.size = len(MESSAGES[1])
        out.addfile(info, io.BytesIO(MESSAGES[1]))
    assert mailboxes.maildir_to_mbox(tarball, tmp_path / "t.mbox", 10_000_000) == 1
    empty = tmp_path / "empty.zip"
    with zipfile.ZipFile(empty, "w") as out:
        out.writestr("readme.txt", b"x")
    with pytest.raises(mailboxes.MailboxError):
        mailboxes.maildir_to_mbox(empty, tmp_path / "e.mbox", 10_000_000)


# --------------------------------------------------------------------------- #
# The API                                                                     #
# --------------------------------------------------------------------------- #
def _upload(admin: TestClient, data: bytes | None = None, name: str = "finance.mbox") -> dict:
    made = admin.post("/api/artifacts/mailboxes", files={"file": (name, data if data is not None else mbox())})
    assert made.status_code == 201, made.text
    return admin.get(f"/api/mailboxes/{made.json()['id']}").json()


def test_a_mailbox_is_indexed_then_messages_are_imported_as_emails(admin: TestClient, no_dns):  # noqa: F811
    box = _upload(admin)
    assert box["status"] == "ready" and box["format"] == "mbox" and box["total"] == 5 and box["duplicates"] == 1
    assert box["threads"] == 2 and box["imported"] == 0 and box["importMax"] == 500
    assert box["topSenders"][0] == {"sender": "m.rossi@example.it", "count": 2}
    artifact = admin.get(f"/api/artifacts/{box['artifactId']}").json()
    assert artifact["kind"] == "mailbox" and artifact["name"] == "finance.mbox"
    assert artifact["detail"] == "0 of 5 messages imported" and artifact["indicator"] is None
    # Nothing is analysed by indexing.
    assert admin.get("/api/artifacts", params={"kind": "mail"}).json()["total"] == 0
    listed = admin.get(f"/api/mailboxes/{box['id']}/messages", params={"scope": "all"}).json()
    assert listed["total"] == 5 and all(m["imported"] is False for m in listed["messages"])
    assert [m["subject"] for m in listed["messages"]][0] == "Fwd: Invoice 4471"  # newest first

    # What a filter would import, with the conversations of its matches.
    plan = admin.post(f"/api/mailboxes/{box['id']}/import", json={"sender": "invoice-portal.co", "dryRun": True}).json()
    assert plan["matches"] == 1 and plan["conversations"] == 1 and plan["withConversations"] == 3
    assert plan["toImport"] == 3 and plan["started"] is False and plan["waiting"] == 0
    alone = admin.post(
        f"/api/mailboxes/{box['id']}/import", json={"sender": "invoice-portal.co", "threads": False, "dryRun": True}
    ).json()
    assert alone["toImport"] == 1

    started = admin.post(f"/api/mailboxes/{box['id']}/import", json={"sender": "invoice-portal.co"}).json()
    assert started["started"] is True
    box = admin.get(f"/api/mailboxes/{box['id']}").json()
    assert box["status"] == "ready" and box["imported"] == 3 and box["progress"]["done"] == 3
    assert sum(box["verdicts"].values()) == 3
    assert admin.get("/api/artifacts", params={"kind": "mail"}).json()["total"] == 3

    # The graph: the imported conversation, whole, with who answers whom.
    shown = admin.get(f"/api/mailboxes/{box['id']}/messages").json()["messages"]
    assert [m["subject"] for m in shown] == ["Fwd: Invoice 4471", "Re: Invoice 4471", "Invoice 4471"]
    root = shown[-1]
    assert root["parent"] is None and [m["parent"] for m in shown[:2]] == [root["seq"], root["seq"]]
    assert all(m["imported"] and m["artifactId"].startswith("mail-") and m["verdict"] for m in shown)
    assert len({m["thread"] for m in shown}) == 1
    # The mailbox keeps its messages together.
    related = admin.get(f"/api/artifacts/{box['artifactId']}").json()
    assert sorted(c["relation"] for c in related["children"]) == ["message"] * 3
    message_bytes = admin.get(f"/api/mails/{shown[-1]['artifactId'][5:]}").json()
    assert message_bytes["subject"] == "Invoice 4471"

    # Asking again imports nothing twice; one message can be imported by its place.
    again = admin.post(
        f"/api/mailboxes/{box['id']}/import", json={"sender": "invoice-portal.co", "dryRun": True}
    ).json()
    assert again["toImport"] == 0 and again["alreadyInNik"] == 3
    other = admin.get(f"/api/mailboxes/{box['id']}/messages", params={"scope": "all", "q": "budget"}).json()["messages"]
    assert len(other) == 2
    one = admin.post(f"/api/mailboxes/{box['id']}/import", json={"seqs": [other[0]["seq"]], "threads": False}).json()
    assert one["toImport"] == 1 and admin.get(f"/api/mailboxes/{box['id']}").json()["imported"] == 4


def test_messages_go_in_an_incident_all_or_chosen_and_only_flagged_ones_give_indicators(admin: TestClient, no_dns):  # noqa: F811
    box = _upload(admin)
    admin.post(f"/api/mailboxes/{box['id']}/import", json={})
    shown = admin.get(f"/api/mailboxes/{box['id']}/messages").json()["messages"]
    assert len(shown) == 5
    flagged = [m for m in shown if m["verdict"] in ("phishing", "suspicious")]
    quiet = [m for m in shown if m["verdict"] == "clean"]
    assert quiet, "the sample mailbox has ordinary mail"

    admin.post("/api/incidents", json={"id": "i1", "name": "i1", "data": {}})
    chosen = admin.post(f"/api/mailboxes/{box['id']}/link", json={"incidentId": "i1", "seqs": [shown[0]["seq"]]})
    assert chosen.status_code == 200 and chosen.json()["linked"] == 1
    assert len(admin.get("/api/incidents/i1").json()["data"]["mail"]["messages"]) == 1
    everything = admin.post(f"/api/mailboxes/{box['id']}/link", json={"incidentId": "i1"}).json()
    assert everything["linked"] == 5
    assert len(admin.get("/api/incidents/i1").json()["data"]["mail"]["messages"]) == 5
    assert admin.post(f"/api/mailboxes/{box['id']}/link", json={"incidentId": "nope"}).status_code == 404

    # Ordinary mail of a mailbox gives no indicators; a flagged message does.
    values = {i["value"] for i in admin.get("/api/incidents/i1/iocs").json()["iocs"]}
    assert "hr@example.it" not in values and "m.rossi@example.it" not in values
    if flagged:
        assert "login-paypa1.top" in values or "http://login-paypa1.top/signin" in values
    only = admin.get(f"/api/mailboxes/{box['id']}/messages", params={"flagged": True}).json()
    assert only["total"] == len(flagged)

    # Removing the mailbox keeps the e-mails imported from it.
    assert admin.delete(f"/api/artifacts/{box['artifactId']}").status_code == 204
    assert admin.get(f"/api/mailboxes/{box['id']}").status_code == 404
    assert not mailboxes.mbox_path(box["id"]).exists()
    assert admin.get("/api/artifacts", params={"kind": "mail"}).json()["total"] == 5


def test_a_maildir_archive_and_a_pst_end_as_the_same_mailbox(admin: TestClient, monkeypatch):
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w") as out:
        for number, raw in enumerate(MESSAGES[:3]):
            out.writestr(f"Maildir/cur/{number}:2,S", raw)
    box = _upload(admin, archive.getvalue(), "maildir.zip")
    assert box["format"] == "maildir" and box["status"] == "ready" and box["total"] == 3

    # A PST is converted by the document worker; here the worker answers with an mbox.
    from app.workers import previews

    seen = {}

    def convert(source, target):
        seen["head"] = Path(source).read_bytes()[:4]
        Path(target).write_bytes(mbox(MESSAGES[:2]))

    monkeypatch.setattr(previews, "convert_pst", convert)
    pst = _upload(admin, b"!BDN" + b"\x00" * 600, "archive.pst")
    assert seen["head"] == b"!BDN" and pst["format"] == "pst" and pst["status"] == "ready" and pst["total"] == 2

    def refuse(source, target):
        raise previews.WorkerError("The document worker is not configured (DOCVIEW_URL): a PST cannot be read.", 503)

    monkeypatch.setattr(previews, "convert_pst", refuse)
    failed = _upload(admin, b"!BDN" + b"\x00" * 600, "other.pst")
    assert failed["status"] == "error" and "PST cannot be read" in failed["error"]

    assert admin.post("/api/artifacts/mailboxes", files={"file": ("notes.txt", b"just text")}).status_code == 422
    empty = _upload(admin, b"From nobody\n", "empty.mbox")
    assert empty["status"] == "error" and "No message found" in empty["error"]


def test_import_takes_five_hundred_at_a_time_and_needs_a_writer(admin: TestClient, no_dns, monkeypatch):  # noqa: F811
    monkeypatch.setattr(mailboxes, "IMPORT_MAX", 2)
    box = _upload(admin)
    plan = admin.post(f"/api/mailboxes/{box['id']}/import", json={"dryRun": True}).json()
    assert plan["toImport"] == 2 and plan["waiting"] == 3
    admin.post(f"/api/mailboxes/{box['id']}/import", json={})
    assert admin.get(f"/api/mailboxes/{box['id']}").json()["imported"] == 2

    from tests.conftest import make_key

    reader = make_key(admin, scopes=["read"])
    other = TestClient(admin.app)
    assert other.get(f"/api/mailboxes/{box['id']}", headers=reader).status_code == 200
    assert other.post(f"/api/mailboxes/{box['id']}/import", headers=reader, json={}).status_code == 403
    assert other.post("/api/artifacts/mailboxes", headers=reader, files={"file": ("a.mbox", mbox())}).status_code == 403
