"""The mail connector (5.1): a native connector, run by Nik's own code over IMAP and SMTP.

The servers are doubles: an IMAP mailbox held in memory and an SMTP server that
keeps what it was given. Nobody ran the connector against a real mailbox.
"""

# ruff: noqa: F811 (fixtures are imported)

from __future__ import annotations

import hashlib
from email.message import EmailMessage
from types import SimpleNamespace

import pytest
from sqlalchemy import func, select

from app.automation import actions, egress, mail_runtime
from app.automation import connector_actions as ca
from app.automation import connectors as files
from app.automation.connector_runtime import CommandError
from app.core.config import settings
from tests.stores import read_only  # noqa: F401 - a fixture

MAIL = next(connector for _text, connector in ca.shipped() if connector.id == "mail")
CONFIG = {
    "imap_host": "imap.acme.example",
    "smtp_host": "smtp.acme.example",
    "sender": "soc@acme.example",
}
SECRETS = {"username": "soc", "password": "app-pass-1234"}


EXE = b"MZ\x90\x00"
EXE_SHA = hashlib.sha256(EXE).hexdigest()
NOTE = b"Wire the amount today.\n"


def message(
    uid: int,
    subject: str,
    sender: str = "anna@partner.example",
    text: str = "Hello",
    attach: bool = False,
    more: tuple = (),
):
    made = EmailMessage()
    made["From"] = f"Anna <{sender}>"
    made["To"] = "soc@acme.example, bruno@acme.example"
    made["Subject"] = subject
    made["Date"] = "Thu, 19 Nov 2026 09:30:00 +0100"
    made["Message-ID"] = f"<m{uid}@partner.example>"
    made.set_content(text)
    if attach:
        made.add_attachment(EXE, maintype="application", subtype="octet-stream", filename="invoice.exe")
    for name, data in more:
        made.add_attachment(data, maintype="application", subtype="octet-stream", filename=name)
    return made.as_bytes()


class Mailbox:
    """An IMAP server of one account, as much of it as the connector uses."""

    def __init__(self):
        self.folders = {
            "INBOX": {
                4: [message(4, "Invoice overdue", text="Please pay.", attach=True), set()],
                7: [message(7, "Re: your ticket", sender="bruno@acme.example"), {"\\Seen"}],
                9: [message(9, "Phishing report", text="<b>Look</b> at this"), set()],
            },
            "Phishing": {},
        }
        self.calls: list[tuple] = []
        self.selected = None
        self.readonly = True
        self.logged_out = False

    # -- what imaplib.IMAP4 offers ------------------------------------------
    def login(self, user, password):
        self.calls.append(("login", user))
        if (user, password) != (SECRETS["username"], SECRETS["password"]):
            raise egress.IMAP_ERROR("LOGIN failed")
        return "OK", [b""]

    def select(self, folder, readonly=False):
        name = folder.strip('"')
        self.calls.append(("select", name, readonly))
        if name not in self.folders:
            return "NO", [b"no such mailbox"]
        self.selected, self.readonly = name, readonly
        return "OK", [str(len(self.folders[name])).encode()]

    def uid(self, command, *args):
        self.calls.append(("uid", command, *args))
        box = self.folders[self.selected]
        if command == "SEARCH":
            found = sorted(box)
            words = list(args)
            while words:
                word = words.pop(0)
                if word == "ALL":
                    continue
                if word == "UNSEEN":
                    found = [uid for uid in found if "\\Seen" not in box[uid][1]]
                elif word == "UID":
                    low = int(words.pop(0).split(":")[0])
                    # As a real server does: "N:*" always gives the last message, also when N is past it.
                    found = [uid for uid in found if uid >= low] or found[-1:]
                elif word in ("FROM", "SUBJECT", "TEXT"):
                    wanted = words.pop(0).strip('"').lower().encode()
                    found = [uid for uid in found if wanted in box[uid][0].lower()]
                elif word == "SINCE":
                    words.pop(0)
            return "OK", [" ".join(str(uid) for uid in found).encode()]
        uid = int(args[0])
        if uid not in box:
            return ("OK", [None]) if command == "FETCH" else ("NO", [b"no such message"])
        if command == "FETCH":
            return "OK", [(f"1 (UID {uid} BODY[] {{{len(box[uid][0])}}}".encode(), box[uid][0]), b")"]
        if command == "STORE":
            assert not self.readonly, "a change in a folder opened to read"
            flags = set(args[2].strip("()").split())
            box[uid][1] = box[uid][1] | flags if args[1].startswith("+") else box[uid][1] - flags
            return "OK", [b""]
        if command == "COPY":
            target = args[1].strip('"')
            if target not in self.folders:
                return "NO", [b"no such mailbox"]
            self.folders[target][max(self.folders[target], default=0) + 1] = [box[uid][0], set()]
            return "OK", [b""]
        raise AssertionError(command)

    def expunge(self):
        self.calls.append(("expunge",))
        box = self.folders[self.selected]
        for uid in [uid for uid, (_raw, flags) in box.items() if "\\Deleted" in flags]:
            del box[uid]
        return "OK", [b""]

    def list(self):
        return "OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "Phishing"', b'() "/" Sent']

    def logout(self):
        self.logged_out = True
        return "BYE", [b""]


class Smtp:
    sent: list = []
    logins: list = []

    def __init__(self, host, port, **_more):
        self.host, self.port = host, port

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def starttls(self, **_more):
        pass

    def login(self, user, password):
        Smtp.logins.append((user, password))
        if password != SECRETS["password"]:
            raise egress.SMTP_AUTH_ERROR(535, b"no")

    def send_message(self, made):
        Smtp.sent.append(made)
        return {}

    def noop(self):
        return 250, b"ok"


@pytest.fixture()
def box(monkeypatch):
    mailbox = Mailbox()
    monkeypatch.setattr(egress.imaplib, "IMAP4_SSL", lambda *args, **kwargs: mailbox)
    monkeypatch.setattr(egress.smtplib, "SMTP", Smtp)
    Smtp.sent, Smtp.logins = [], []
    # A message kept as evidence is analysed: its DNS checks ask nobody here.
    from app.mail import verify

    monkeypatch.setattr(verify, "txt_lookup", lambda name: [])
    monkeypatch.setattr(
        verify, "verify_spf", lambda ip, mail_from, helo: {"result": "none", "detail": "", "domain": ""}
    )
    return mailbox


def runtime(hosts=("partner.example", "acme.example"), config=None, secrets=None):
    policy = egress.Policy(mode="listed", hosts=frozenset(hosts))
    return mail_runtime.MailRuntime(MAIL, {**CONFIG, **(config or {})}, secrets or SECRETS, policy)


def run(name: str, **args):
    return runtime().run(name, args).outputs


def trusted(**more):
    """A runtime whose guard lets everything leave: what the commands do with a message, apart from
    what a playbook may send."""
    mailbox = runtime(**more)
    mailbox.judge = lambda quoted, found: ([], True)
    return mailbox


# --------------------------------------------------------------------------- #
# The file                                                                    #
# --------------------------------------------------------------------------- #
def test_the_mail_connector_is_native_and_names_only_commands_nik_has():
    assert MAIL.native == "mail" and MAIL.base_url == "" and MAIL.verified is False
    assert {command.name for command in MAIL.commands} == set(files.NATIVE["mail"])
    for command in MAIL.commands:
        assert command.request is None and command.steps is None and command.description
        assert command.sample is not None, command.name
    changing = {command.name for command in MAIL.commands if command.changes_outside}
    assert changing == {"send", "reply", "forward", "move", "mark-read", "mark-unread", "delete"}
    # A forward carries the attachments only when it is asked to.
    carried = next(a for a in MAIL.command("forward").arguments if a.name == "attachments")
    assert carried.type == "bool" and carried.default is False and MAIL.version == 3
    # It ships as a package, with its README, and without a logo: it belongs to no product.
    assert set(ca.shipped_extras()["mail"]) == {"readme"}
    assert ca.host_of(MAIL, CONFIG) == "imap.acme.example"
    assert ca.host_of(MAIL, {"smtp_host": "smtp.acme.example"}) == "smtp.acme.example"
    assert ca.host_of(MAIL, {}) is None

    text = next(text for text, connector in ca.shipped() if connector.id == "mail")
    for broken, why in (
        (text.replace("native: mail", "native: mail\nbase_url: https://x.example"), 'no "base_url"'),
        (text.replace("  - name: list-folders", "  - name: empty-trash"), "not a command Nik has"),
        (text.replace("native: mail\n", ""), '"base_url" is missing'),
    ):
        with pytest.raises(files.ConnectorError) as caught:
            files.load(broken)
        assert any(why in problem.message for problem in caught.value.problems), caught.value.problems


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def test_a_mailbox_is_searched_and_a_message_is_read_without_opening_what_is_attached(box):
    found = run("search")
    assert [m["uid"] for m in found["messages"]] == [9, 7, 4] and found["count"] == 3  # the newest first
    assert found["messages"][2]["subject"] == "Invoice overdue" and found["truncated"] is False
    assert [m["uid"] for m in run("search", unseen=True)["messages"]] == [9, 4]
    assert [m["uid"] for m in run("search", subject="invoice")["messages"]] == [4]
    assert [m["uid"] for m in run("search", text="please pay")["messages"]] == [4]
    limited = run("search", limit=1)
    assert [m["uid"] for m in limited["messages"]] == [9] and limited["truncated"] is True

    read = run("get-message", uid=4)
    assert (read["subject"], read["from"], read["date"]) == (
        "Invoice overdue",
        "anna@partner.example",
        "2026-11-19T08:30:00+00:00",
    )
    assert read["to"] == ["soc@acme.example", "bruno@acme.example"] and read["text"].strip() == "Please pay."
    assert read["attachments"] == [
        {
            "name": "invoice.exe",
            "type": "application/octet-stream",
            "size": 4,
            "sha256": hashlib.sha256(b"MZ\x90\x00").hexdigest(),
        }
    ]
    # Reading leaves the mailbox as it was: opened to read, and closed after.
    assert all(call[2] is True for call in box.calls if call[0] == "select") and box.logged_out
    assert run("list-folders") == {"folders": ["INBOX", "Phishing", "Sent"]}

    for name, args, why in (
        ("get-message", {"uid": 99}, "no message with this uid"),
        ("get-message", {"uid": "x"}, "the number of the message"),
        ("get-message", {}, "Needed: uid"),
        ("search", {"folder": "Nowhere"}, 'no folder "Nowhere"'),
        ("search", {"subject": 'a" OR ALL "'}, "not written as a mailbox accepts"),
        ("search", {"folder": "INBOX\r\nDELETE"}, "not written as a mailbox accepts"),
        ("search", {"since": "yesterday"}, '"since" is a date'),
    ):
        with pytest.raises(CommandError) as caught:
            runtime().run(name, args)
        assert why in caught.value.message, (name, caught.value.message)


def test_messages_are_moved_marked_and_deleted(box):
    assert run("mark-read", uid=4) == {"uid": 4, "read": True}
    assert "\\Seen" in box.folders["INBOX"][4][1]
    assert run("mark-unread", uid=4) == {"uid": 4, "read": False}
    assert "\\Seen" not in box.folders["INBOX"][4][1]

    assert run("move", uid=9, to="Phishing") == {"moved": True, "uid": 9, "to": "Phishing"}
    assert sorted(box.folders["INBOX"]) == [4, 7] and len(box.folders["Phishing"]) == 1
    with pytest.raises(CommandError) as caught:
        runtime().run("move", {"uid": 4, "to": "Nowhere"})
    assert "is the folder there" in caught.value.message and 4 in box.folders["INBOX"]

    assert run("delete", uid=7) == {"deleted": True, "uid": 7}
    assert sorted(box.folders["INBOX"]) == [4]
    # A change opens the folder to write; nothing else does.
    writes = [call for call in box.calls if call[0] == "select" and call[2] is False]
    assert len(writes) == 5


# --------------------------------------------------------------------------- #
# Sending                                                                     #
# --------------------------------------------------------------------------- #
def test_a_message_is_sent_only_to_addresses_the_playbook_may_reach(box):
    sent = run("send", to="anna@partner.example, bruno@acme.example", subject="Line one\nLine two", text="Body")
    assert sent["sent"] is True and sent["recipients"] == 2 and sent["message_id"].endswith("@acme.example>")
    (made,) = Smtp.sent
    assert (made["From"], made["To"]) == ("soc@acme.example", "anna@partner.example, bruno@acme.example")
    assert made["Subject"] == "Line one Line two" and made.get_content().strip() == "Body"
    assert Smtp.logins == [("soc", SECRETS["password"])]

    for args, why in (
        ({"to": "eve@elsewhere.example", "subject": "s", "text": "t"}, "elsewhere.example is not among the hosts"),
        ({"to": "not an address", "subject": "s", "text": "t"}, "not an e-mail address"),
        ({"to": "a@acme.example\r\nBcc: x@evil.example", "subject": "s", "text": "t"}, "not an e-mail address"),
        ({"to": [], "subject": "s", "text": "t"}, "Needed: to"),
    ):
        with pytest.raises(CommandError) as caught:
            runtime().run("send", args)
        assert why in caught.value.message, caught.value.message
    assert len(Smtp.sent) == 1

    # An instance that only reads cannot send, and says so; one that only sends cannot read.
    with pytest.raises(CommandError) as caught:
        runtime(config={"smtp_host": ""}).run("send", {"to": "bruno@acme.example", "subject": "s", "text": "t"})
    assert "no SMTP server" in caught.value.message
    with pytest.raises(CommandError) as caught:
        runtime(config={"imap_host": ""}).run("search", {})
    assert "no IMAP server" in caught.value.message
    # A dry run sends nothing and still refuses a recipient the playbook may not reach.
    would = runtime().would_send("send", {"to": "bruno@acme.example"})
    assert would == {"method": "SMTP", "host": "smtp.acme.example", "path": "1 recipient(s)", "dry_run": True}
    with pytest.raises(CommandError):
        runtime().would_send("send", {"to": "eve@elsewhere.example"})
    assert runtime().would_send("search", {})["method"] == "IMAP" and len(Smtp.sent) == 1


def test_a_reply_stays_in_its_conversation_and_a_forward_quotes_the_message(box):
    answered = trusted().run("reply", {"uid": 4, "text": "Paid yesterday."}).outputs
    assert answered["sent"] is True and answered["quoted_held"] == []
    reply = Smtp.sent[-1]
    assert reply["To"] == "anna@partner.example" and reply["Subject"] == "Re: Invoice overdue"
    assert reply["In-Reply-To"] == "<m4@partner.example>" and reply["References"] == "<m4@partner.example>"
    trusted().run("reply", {"uid": 7, "text": "Thanks.", "all": True})
    everyone = Smtp.sent[-1]
    # Everyone it was sent to, but not the mailbox itself; "Re:" is not written twice.
    assert everyone["To"] == "bruno@acme.example" and everyone["Subject"] == "Re: your ticket"

    trusted().run("forward", {"uid": 4, "to": ["bruno@acme.example"], "text": "See below."})
    forwarded = Smtp.sent[-1]
    assert forwarded["Subject"] == "Fwd: Invoice overdue"
    body = forwarded.get_content()
    assert body.startswith("See below.") and "From: anna@partner.example" in body and "Please pay." in body
    # The sender of the message answered is a recipient like any other.
    with pytest.raises(CommandError) as caught:
        trusted(hosts=("acme.example",)).run("reply", {"uid": 4, "text": "x"})
    assert "partner.example is not among the hosts" in caught.value.message
    # With no guard to judge what is taken from the mailbox, nothing of it is sent on, and it is not read.
    sent, calls = len(Smtp.sent), len(box.calls)
    for name, args in (("reply", {"uid": 4, "text": "x"}), ("forward", {"uid": 4, "to": "bruno@acme.example"})):
        with pytest.raises(CommandError) as caught:
            runtime().run(name, args)
        assert "only where the data guard judges what is taken from it" in caught.value.message
    assert (len(Smtp.sent), len(box.calls)) == (sent, calls)
    # A dry run does not read the mailbox: it says that what is quoted is judged when the step runs.
    for name in ("reply", "forward"):
        would = runtime().would_send(name, {"uid": 4, "to": "bruno@acme.example"})
        assert "judged by the data guard when the step runs" in would["note"] and would["dry_run"] is True
    assert len(box.calls) == calls and "note" not in runtime().would_send("send", {"to": "bruno@acme.example"})


# --------------------------------------------------------------------------- #
# For a playbook: the attachments kept, and those a forward carries           #
# --------------------------------------------------------------------------- #
def instance(db) -> None:
    """The Mail connector installed, with the mailbox of the tests as its instance."""
    from app import mapping
    from app.core.models import Connection
    from app.core.security import now_iso

    ca.seed(db)
    db.flush()
    mapping.seed(db)
    row = Connection(
        id="m" * 32, name="SOC mailbox", connector_id="mail", config=dict(CONFIG), fetch_enabled=True,
        created_at=now_iso(), updated_at=now_iso(),
    )  # fmt: skip
    ca.store_secrets(row, SECRETS)
    db.add(row)
    db.commit()


@pytest.fixture()
def desk(admin, box):
    """A playbook that may write to acme.example and sends no class of data, and the instance."""
    from app.core.db import SessionLocal
    from app.core.models import Playbook
    from tests.test_automation_engine import playbook

    with SessionLocal() as db:
        instance(db)
    playbook_id = playbook(admin, "Mail desk", [], [])
    with SessionLocal() as db:
        db.get(Playbook, playbook_id).egress_hosts = ["acme.example"]
        db.commit()
    return SimpleNamespace(admin=admin, box=box, playbook=playbook_id)


# The classes of what a forward quotes of a message: its sender and recipients, its subject, its text.
QUOTED = ("email_address", "subject", "mail_body")


def step(desk, name: str, opened=(), incident: str | None = None, **more) -> actions.Result:
    """A command run as a step of a run of the playbook, which was opened these classes of data."""
    from app.core.db import SessionLocal
    from app.core.models import Playbook

    args = more.pop("args")
    with SessionLocal() as db:
        row = db.get(Playbook, desk.playbook)
        row.data_allow = list(opened)
        db.commit()
        call = actions.Call(
            db=db,
            args=args,
            classes=frozenset(),
            arg_classes={},
            dry_run=more.pop("dry_run", False),
            run=SimpleNamespace(id="run-1", incident_id=incident, trigger={"playbook": "Mail desk"}),
            playbook=row,
            connection="SOC mailbox",
            **more,
        )
        result = ca.run_command("mail", name, call)
        db.commit()
        return result


def test_the_attachments_of_a_message_are_kept_as_files_of_the_incident(desk, monkeypatch):
    from app.core.db import SessionLocal
    from app.core.models import AuditEntry, Sample
    from app.malware.samples import read_sample

    admin, box = desk.admin, desk.box
    box.folders["INBOX"][5] = [
        message(5, "Two files", attach=True, more=(("note.txt", NOTE), ("empty.bin", b""))),
        set(),
    ]
    assert admin.post("/api/incidents", json={"id": "case", "name": "Case", "data": {}}).status_code == 201

    # A dry run reads nothing and keeps nothing: the step gives what an answer looks like.
    dry = step(desk, "get-attachments", args={"uid": 5}, dry_run=True, incident="case")
    assert dry.output == MAIL.command("get-attachments").sample and dry.request["dry_run"] is True
    assert box.calls == []
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Sample)) == 0

    kept = step(desk, "get-attachments", args={"uid": 5}, incident="case")
    found = kept.output
    assert (found["count"], found["stored"], found["truncated"]) == (3, 2, False)
    assert found["artifacts"] == [f"file-{EXE_SHA}", f"file-{hashlib.sha256(NOTE).hexdigest()}"]
    assert found["attachments"][0] == {
        "name": "invoice.exe",
        "type": "application/octet-stream",
        "size": 4,
        "sha256": EXE_SHA,
        "artifact": f"file-{EXE_SHA}",
        "linked": True,
        "note": "",
    }
    # One that holds nothing is listed and not kept.
    empty = found["attachments"][2]
    assert (empty["name"], empty["artifact"], empty["linked"], empty["note"]) == ("empty.bin", "", False, "It is empty")
    # What a later node sends is judged by what it is: a name is a file name, a hash and an id leave.
    assert kept.classes["attachments.name"] == ["attachment_name"] and kept.classes["artifacts"] == ["nik_id"]
    # Stored as the bytes they are, analysed as an upload is, in the incident, and in the audit log.
    assert read_sample(EXE_SHA) == EXE
    detail = admin.get(f"/api/artifacts/file-{EXE_SHA}").json()
    assert detail["name"] == "invoice.exe" and [item["id"] for item in detail["incidents"]] == ["case"]
    refs = admin.get("/api/incidents/case").json()["data"]["malware"]["samples"]
    assert [(ref["fileName"], ref["origin"]) for ref in refs] == [
        ("invoice.exe", "e-mail “Two files”"),
        ("note.txt", "e-mail “Two files”"),
    ]
    with SessionLocal() as db:
        said = db.scalars(select(AuditEntry.details).where(AuditEntry.action == "mail.attachments.keep")).one()
    assert said == 'Kept 2 attachment(s) of the message 5 of INBOX (playbook "Mail desk", run run-1)'
    # The mailbox was read, not changed.
    assert all(call[2] is True for call in box.calls if call[0] == "select")

    # A run that works on no incident keeps the files on their own; one that names an incident uses it.
    alone = step(desk, "get-attachments", args={"uid": 4})
    assert alone.output["attachments"][0]["linked"] is False and alone.output["artifacts"] == [f"file-{EXE_SHA}"]
    assert admin.post("/api/incidents", json={"id": "other", "name": "Other", "data": {}}).status_code == 201
    named = step(desk, "get-attachments", args={"uid": 4, "incident": "other"}, incident="case")
    assert named.output["attachments"][0]["linked"] is True
    both = admin.get(f"/api/artifacts/file-{EXE_SHA}").json()["incidents"]
    assert sorted(item["id"] for item in both) == ["case", "other"]
    assert step(desk, "get-attachments", args={"uid": 9}).output == {
        "attachments": [], "artifacts": [], "count": 0, "stored": 0, "truncated": False,
    }  # fmt: skip

    for args, why in (
        ({"uid": 99}, "no message with this uid"),
        ({"uid": 4, "incident": "nowhere"}, "The incident does not exist"),
        ({}, "Needed: uid"),
    ):
        with pytest.raises(actions.ActionError) as caught:
            step(desk, "get-attachments", args=args)
        assert why in caught.value.message, caught.value.message
    # A message above the limit of an upload is refused, not read by halves.
    with monkeypatch.context() as patch, pytest.raises(actions.ActionError) as caught:
        patch.setattr(settings, "SAMPLE_MAX_MB", 0)
        step(desk, "get-attachments", args={"uid": 4})
    assert "exceeds the 0 MB limit" in caught.value.message

    # More than are looked at: the first fifty, and it says so. With no store at hand, they are described.
    many = tuple((f"part-{number}.bin", bytes([number])) for number in range(mail_runtime.MAX_ATTACHMENTS + 1))
    box.folders["INBOX"][6] = [message(6, "Many", more=many), set()]
    described = runtime().run("get-attachments", {"uid": 6}).outputs
    assert (described["count"], described["stored"], described["truncated"]) == (50, 0, True)
    assert described["attachments"][0]["artifact"] == "" and "no store" in described["attachments"][0]["note"]


def test_a_forward_carries_the_attachments_only_when_the_data_guard_lets_them_leave(desk, monkeypatch):
    box = desk.box
    forward = {"uid": 4, "to": "bruno@acme.example", "text": "See below."}
    quoted = list(QUOTED)  # what a forward quotes is open here: this is about the files

    # As before: asked for nothing more, a forward quotes the text and carries nothing.
    plain = step(desk, "forward", args=forward, opened=quoted)
    assert (plain.output["sent"], plain.output["attachments"], plain.output["attachments_held"]) == (True, 0, 0)
    assert list(Smtp.sent[-1].iter_attachments()) == []

    # A dry run sends nothing and reads nothing.
    calls = len(box.calls)
    dry = step(desk, "forward", args={**forward, "attachments": True}, dry_run=True)
    assert dry.output == MAIL.command("forward").sample and len(Smtp.sent) == 1 and len(box.calls) == calls

    # A playbook that may send no file: the attachment stays, and the step says what was held.
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "attachments": True}, opened=quoted)
    assert caught.value.message.startswith("Held back: 1 × file and attachment names, 1 × attachments.")
    assert caught.value.retry is False and len(Smtp.sent) == 1
    held = caught.value.request["held"]
    assert held["held"] == ["attachment", "attachment_name"] and held["files"] == {"count": 1, "bytes": 4}
    # The names alone are not the files.
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "attachments": True}, opened=[*quoted, "attachment_name"])
    assert caught.value.message.startswith("Held back: 1 × attachments.") and len(Smtp.sent) == 1

    # A node told to send without what is held sends the text alone, and says how many stayed.
    without = step(desk, "forward", args={**forward, "attachments": True}, held="drop", opened=quoted)
    assert (without.output["attachments"], without.output["attachments_held"]) == (0, 1)
    assert without.output["quoted_held"] == []
    assert without.request["held"]["dropped"] is True and "attachments" not in without.request
    assert list(Smtp.sent[-1].iter_attachments()) == [] and "Please pay." in Smtp.sent[-1].get_body().get_content()

    # Opened for the playbook, the file goes as the bytes it is, under its name.
    opened = [*quoted, "attachment_name", "attachment"]
    carried = step(desk, "forward", args={**forward, "attachments": True}, opened=opened)
    assert (carried.output["attachments"], carried.output["attachments_held"]) == (1, 0)
    assert carried.request["attachments"] == 1 and carried.request["held"]["held"] == []
    (part,) = Smtp.sent[-1].iter_attachments()
    assert (part.get_filename(), part.get_content_type()) == ("invoice.exe", "application/octet-stream")
    assert part.get_payload(decode=True) == EXE
    body = Smtp.sent[-1].get_body().get_content()
    assert (
        body.startswith("See below.") and "Please pay." in body and Smtp.sent[-1]["Subject"] == "Fwd: Invoice overdue"
    )
    # A message with nothing attached has nothing to judge.
    nothing = step(desk, "forward", args={**forward, "uid": 9, "attachments": True}, opened=quoted)
    assert nothing.output["attachments"] == 0 and "files" not in nothing.request["held"]
    sent = len(Smtp.sent)

    # A name is read as any text that leaves is: a private address in it is an internal address.
    box.folders["INBOX"][5] = [message(5, "Named", more=(("backup of 10.0.0.5 today.txt", NOTE),)), set()]
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "uid": 5, "attachments": True}, opened=opened)
    assert caught.value.message.startswith("Held back: 1 × internal names and addresses.")
    # A file Nik holds as a sample is a sample, by its hash: it leaves only where samples do.
    step(desk, "get-attachments", args={"uid": 4})
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "attachments": True}, opened=opened)
    assert caught.value.message.startswith("Held back: 1 × samples.")
    assert step(desk, "forward", args={**forward, "attachments": True}, opened=[*opened, "sample"]).output["sent"]
    sent += 1
    assert len(Smtp.sent) == sent

    # What cannot be judged whole is refused, whatever was opened; outside a playbook nothing is carried.
    with monkeypatch.context() as patch, pytest.raises(actions.ActionError) as caught:
        patch.setattr(mail_runtime, "MAX_CARRIED", 3)
        step(desk, "forward", args={**forward, "attachments": True}, opened=[*opened, "sample"])
    assert "more than a mail server takes" in caught.value.message
    many = tuple((f"part-{number}.bin", bytes([number])) for number in range(mail_runtime.MAX_ATTACHMENTS + 1))
    box.folders["INBOX"][6] = [message(6, "Many", more=many), set()]
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "uid": 6, "attachments": True}, opened=opened)
    assert "more than 50 attachments" in caught.value.message
    with pytest.raises(CommandError) as caught:
        runtime().run("forward", {**forward, "attachments": True})
    assert "only where the data guard judges what is taken from it" in caught.value.message
    assert len(Smtp.sent) == sent
    # A recipient is still a destination.
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "to": "eve@elsewhere.example", "attachments": True}, opened=opened)
    assert "elsewhere.example is not among the hosts" in caught.value.message


def test_what_a_forward_and_a_reply_take_from_the_mailbox_is_judged_by_the_data_guard(desk):
    box = desk.box
    forward = {"uid": 4, "to": "bruno@acme.example", "text": "See below."}
    everything = "Held back: 3 × e-mail addresses, 1 × e-mail subjects, 1 × e-mail bodies."

    # A playbook that sends no class of data: the message is read, judged, and nothing is sent.
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args=forward)
    assert caught.value.message.startswith(everything) and caught.value.retry is False
    held = caught.value.request["held"]
    assert held["held"] == ["email_address", "mail_body", "subject"]
    assert held["quoted"] == {
        "parts": ["subject", "from", "to", "date", "text"],
        "held": ["subject", "from", "to", "text"],
    }
    assert Smtp.sent == []
    # The text is not open because its sender and its subject are, nor the other way round.
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args=forward, opened=["email_address", "subject"])
    assert caught.value.message.startswith("Held back: 1 × e-mail bodies.")
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args=forward, opened=["mail_body"])
    assert caught.value.message.startswith("Held back: 3 × e-mail addresses, 1 × e-mail subjects.")
    # With the attachments, one sentence names all that was held, quoted and attached.
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "attachments": True})
    assert caught.value.message.startswith(
        "Held back: 3 × e-mail addresses, 1 × e-mail subjects, 1 × file and attachment names, "
        "1 × e-mail bodies, 1 × attachments."
    )
    assert Smtp.sent == []

    # A dry run reads no mailbox: its step says the quoted message is judged when it runs.
    calls = len(box.calls)
    dry = step(desk, "forward", args=forward, dry_run=True)
    assert dry.output == MAIL.command("forward").sample and dry.output["quoted_held"] == []
    assert "judged by the data guard when the step runs" in dry.request["note"]
    assert len(box.calls) == calls and Smtp.sent == []

    # Opened for the playbook, it goes as it always did.
    whole = step(desk, "forward", args=forward, opened=QUOTED)
    assert whole.output["sent"] is True and whole.output["quoted_held"] == []
    assert whole.request["held"]["held"] == [] and "dropped" not in whole.request["held"]
    body = Smtp.sent[-1].get_content()
    assert Smtp.sent[-1]["Subject"] == "Fwd: Invoice overdue" and body.startswith("See below.")
    for line in (
        "From: anna@partner.example",
        "Subject: Invoice overdue",
        "To: soc@acme.example, bruno@acme.example",
        "Please pay.",
    ):
        assert line in body, line

    # A node told to send without what is held sends what it says itself, and says what stayed.
    without = step(desk, "forward", args=forward, held="drop")
    assert without.output["sent"] is True and without.output["quoted_held"] == ["subject", "from", "to", "text"]
    assert without.request["held"]["dropped"] is True
    made = Smtp.sent[-1]
    body = made.get_content()
    assert made["Subject"] == "Fwd: (subject held back)" and body.startswith("See below.")
    for line in ("From: (held back)", "Subject: (held back)", "To: (held back)", mail_runtime.TEXT_HELD):
        assert line in body, line
    assert "Date: 2026-11-19T08:30:00+00:00" in body
    for kept_back in ("Please pay.", "anna@partner.example", "Invoice overdue", "soc@acme.example"):
        assert kept_back not in body and kept_back not in str(made["Subject"])
    # Each part is judged on its own: the header lines go where they may, the text stays.
    partly = step(desk, "forward", args=forward, held="drop", opened=["email_address", "subject"])
    assert partly.output["quoted_held"] == ["text"]
    body = Smtp.sent[-1].get_content()
    assert "From: anna@partner.example" in body and mail_runtime.TEXT_HELD in body and "Please pay." not in body
    # With the files asked for, a held text does not take them along, nor the other way round.
    opened = ["email_address", "subject", "attachment_name", "attachment"]
    files = step(desk, "forward", args={**forward, "attachments": True}, held="drop", opened=opened)
    assert (files.output["quoted_held"], files.output["attachments"]) == (["text"], 1)
    texts = step(desk, "forward", args={**forward, "attachments": True}, held="drop", opened=QUOTED)
    assert (texts.output["quoted_held"], texts.output["attachments"], texts.output["attachments_held"]) == ([], 0, 1)

    # The text is read as any text that leaves is: a private address in it is an internal address.
    box.folders["INBOX"][10] = [message(10, "Where it is", text="The server is at 10.0.0.5 since Monday."), set()]
    sent = len(Smtp.sent)
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "forward", args={**forward, "uid": 10}, opened=QUOTED)
    assert caught.value.message.startswith("Held back: 1 × internal names and addresses.")
    assert caught.value.request["held"]["quoted"]["held"] == ["text"] and len(Smtp.sent) == sent
    assert step(desk, "forward", args={**forward, "uid": 10}, opened=[*QUOTED, "private_value"]).output["sent"]
    sent += 1

    # An answer repeats the subject of the message it answers, and that is a subject.
    reply = {"uid": 7, "text": "Thanks."}
    with pytest.raises(actions.ActionError) as caught:
        step(desk, "reply", args=reply)
    assert caught.value.message.startswith("Held back: 1 × e-mail subjects.") and len(Smtp.sent) == sent
    assert caught.value.request["held"]["quoted"] == {"parts": ["subject"], "held": ["subject"]}
    answered = step(desk, "reply", args=reply, opened=["subject"])
    assert answered.output["sent"] is True and answered.output["quoted_held"] == []
    assert (Smtp.sent[-1]["Subject"], Smtp.sent[-1]["To"]) == ("Re: your ticket", "bruno@acme.example")
    silent = step(desk, "reply", args=reply, held="drop")
    assert silent.output["quoted_held"] == ["subject"] and silent.request["held"]["dropped"] is True
    made = Smtp.sent[-1]
    # It stays in its conversation, which is told by the Message-ID and not by the subject.
    assert made["Subject"] == "Re: (subject held back)" and made["In-Reply-To"] == "<m7@partner.example>"
    assert made.get_content().strip() == "Thanks."
    dry = step(desk, "reply", args=reply, dry_run=True)
    assert dry.output == MAIL.command("reply").sample and "when the step runs" in dry.request["note"]
    assert len(Smtp.sent) == sent + 2


def test_an_attached_message_and_a_name_that_breaks_a_header_are_carried_as_bytes(box):
    inner = EmailMessage()
    inner["From"], inner["Subject"] = "eve@elsewhere.example", "The original"
    inner.set_content("Click here.")
    made = EmailMessage()
    made["From"], made["To"], made["Subject"] = "anna@partner.example", "soc@acme.example", "Reported"
    made["Message-ID"] = "<m5@partner.example>"
    made.set_content("I got this.")
    made.add_attachment(inner)
    made.add_attachment(b"%PDF-1.7", maintype="application", subtype="pdf", filename="a\tb.pdf")
    box.folders["INBOX"][5] = [made.as_bytes(), set()]

    judged = []
    mailbox = runtime()
    mailbox.judge = lambda quoted, found: judged.append(found) or ([], True)
    assert (
        mailbox.run("forward", {"uid": 5, "to": "bruno@acme.example", "attachments": True}).outputs["attachments"] == 2
    )
    # The guard is given what a file is, never its bytes.
    assert [sorted(item) for item in judged[0]] == [["name", "sha256", "size", "type"]] * 2
    first, second = Smtp.sent[-1].iter_attachments()
    assert first.get_content_type() == "message/rfc822" and first.get_payload(0)["Subject"] == "The original"
    assert (second.get_filename(), second.get_payload(decode=True)) == ("a b.pdf", b"%PDF-1.7")
    # What get-message says of an attached message is what is kept and carried: the bytes of that message.
    described = run("get-message", uid=5)["attachments"][0]
    assert described["type"] == "message/rfc822" and described["size"] == judged[0][0]["size"] > 0
    assert described["sha256"] == judged[0][0]["sha256"]


# --------------------------------------------------------------------------- #
# The test of an instance, and the listener                                   #
# --------------------------------------------------------------------------- #
def test_the_test_of_an_instance_opens_the_mailbox_and_asks_the_smtp_server(box):
    assert runtime().test() == {
        "ok": True,
        "status": 0,
        "message": "The mailbox opened and the smtp server took the credentials",
    }
    refused = runtime(secrets={"username": "soc", "password": "wrong"}).test()
    assert refused["ok"] is False and "refused the user name or the password" in refused["message"]
    neither = runtime(config={"imap_host": "", "smtp_host": ""}).test()
    assert neither == {"ok": False, "status": 0, "message": "This instance has neither an IMAP nor an SMTP server"}
    assert "app-pass-1234" not in str(refused)


def test_the_listener_gives_what_arrived_since_the_last_cycle_oldest_first(box):
    first = {"epoch": 1_795_000_000, "iso": "2026-11-18T00:00:00+00:00"}
    found = runtime().fetch(MAIL.fetch, {"uid": 0}, first, {}, 2)
    assert [item["uid"] for item in found["items"]] == [4, 7] and found["truncated"] is True
    assert found["response"] == {"last_uid": 7, "folder": "INBOX"}
    again = runtime().fetch(MAIL.fetch, {"uid": 7}, first, {}, 50)
    assert [item["uid"] for item in again["items"]] == [9] and again["response"]["last_uid"] == 9
    # Nothing new: the server names its last message all the same, and it is not read twice.
    nothing = runtime().fetch(MAIL.fetch, {"uid": 9}, first, {}, 50)
    assert nothing["items"] == [] and nothing["response"]["last_uid"] == 9
    item = found["items"][0]
    assert item["message_id"] == "<m4@partner.example>" and item["attachments"][0]["name"] == "invoice.exe"


def test_the_last_word_of_a_folder_line_is_read_from_its_end():
    read = mail_runtime._last_word
    assert read('(\\HasNoChildren) "/" "INBOX/Phishing"') == "INBOX/Phishing"
    assert read('() "/" Sent') == "Sent"
    assert read('() "/" "My \\"own\\" folder"') == 'My "own" folder'
    assert read("") == "" and read('"') == ""
    # A line that never closes its quotes, or is made of spaces, costs nothing.
    assert read('() "/" "' + "a" * 5000) == '"' + "a" * 5000
    assert read(" " * 20000 + '"x') is not None


def test_the_listener_makes_each_message_that_arrives_an_incident(admin, box):
    """From the mailbox to the list of incidents: the fetch of an instance, the mapper the connector
    ships with, and the incident marked with what brought it in."""
    from app import fetch
    from app.core.db import SessionLocal
    from app.core.models import Connection, Incident

    with SessionLocal() as db:
        instance(db)
        first = fetch.cycle(db, db.get(Connection, "m" * 32))
        assert (first["fetched"], first["created"]) == (3, 3), first
        assert db.get(Connection, "m" * 32).fetch_state == {"uid": 9}
        # Nothing arrived: nothing is made twice.
        again = fetch.cycle(db, db.get(Connection, "m" * 32))
        assert again["created"] == 0, again
        names = sorted(name for (name,) in db.execute(select(Incident.name)))
    assert names == ["Invoice overdue", "Phishing report", "Re: your ticket"]
    rows = admin.get("/api/incidents?view=summary").json()["incidents"]
    assert {row["source"]["connector"] for row in rows} == {"Mail listener / sender"}
    assert {row["source"]["connection"] for row in rows} == {"SOC mailbox"}
    assert all(row["source"]["logo"] is None and row["number"] for row in rows)

    # A message that arrives afterwards is the only one the next cycle reads.
    box.folders["INBOX"][12] = [message(12, "New alert"), set()]
    with SessionLocal() as db:
        later = fetch.cycle(db, db.get(Connection, "m" * 32))
        assert (later["fetched"], later["created"]) == (1, 1), later
        # An instance turned off is not fetched by the worker.
        db.get(Connection, "m" * 32).enabled = False
        db.commit()
        assert "m" * 32 not in fetch.due(db, 9e12)


def test_a_message_the_listener_read_is_kept_as_an_e_mail_of_its_incident(admin, box, monkeypatch):
    """The Evidence tab of an incident the listener made shows the message it was made from."""
    from app import fetch
    from app.core.db import SessionLocal
    from app.core.models import Connection, FetchedItem, Mail
    from app.malware.samples import read_mail

    def cycle() -> dict:
        with SessionLocal() as db:
            return fetch.cycle(db, db.get(Connection, "m" * 32))

    def by_name() -> dict:
        return {row["name"]: row["id"] for row in admin.get("/api/incidents?view=summary").json()["incidents"]}

    def mails() -> int:
        with SessionLocal() as db:
            return db.scalar(select(func.count()).select_from(Mail))

    def outcomes() -> dict:
        with SessionLocal() as db:
            return {row.item_id: (row.outcome, row.note) for row in db.scalars(select(FetchedItem))}

    with SessionLocal() as db:
        instance(db)
    # One of the messages was uploaded by an analyst before the listener read it.
    known = box.folders["INBOX"][7][0]
    uploaded = admin.post("/api/artifacts/mails", files={"file": ("ticket.eml", known)})
    assert uploaded.status_code == 201 and uploaded.json()["incidents"] == []
    first = cycle()
    assert (first["created"], first["incomplete"]) == (3, 0), first
    assert box.logged_out and all(call[2] is True for call in box.calls if call[0] == "select")
    # The mailbox is opened once more for what is kept, not once for each message.
    assert len([call for call in box.calls if call[0] == "login"]) == 2

    raw = box.folders["INBOX"][4][0]
    sha = hashlib.sha256(raw).hexdigest()
    (ref,) = admin.get(f"/api/incidents/{by_name()['Invoice overdue']}").json()["data"]["mail"]["messages"]
    assert (ref["sha256"], ref["subject"], ref["from"]) == (sha, "Invoice overdue", "anna@partner.example")
    assert (ref["fileName"], ref["importedBy"], ref["format"]) == ("message-4.eml", "connector:mail", "eml")
    # As it was received, with the analysis an uploaded .eml gets, and as an artifact of the incident.
    assert read_mail(sha) == raw
    analysed = admin.get(f"/api/mails/{sha}").json()
    assert analysed["analysis"]["attachments"][0]["name"] == "invoice.exe" and analysed["verdict"]
    assert [item["name"] for item in analysed["incidents"]] == ["Invoice overdue"]
    artifact = admin.get(f"/api/artifacts/mail-{sha}").json()
    assert artifact["kind"] == "mail" and [item["name"] for item in artifact["incidents"]] == ["Invoice overdue"]
    assert mails() == 3
    # The message Nik held already is not analysed twice: it is the analyst's, and now of the incident too.
    held = admin.get(f"/api/mails/{hashlib.sha256(known).hexdigest()}").json()
    assert held["createdBy"] != "connector:mail" and [item["name"] for item in held["incidents"]] == ["Re: your ticket"]

    # A file taken out of it by a playbook afterwards is recorded as taken out of this e-mail.
    from app.core.models import Playbook
    from tests.test_automation_engine import playbook

    playbook_id = playbook(admin, "Mail desk", [], [])
    with SessionLocal() as db:
        call = actions.Call(
            db=db, args={"uid": 4}, classes=frozenset(), arg_classes={}, dry_run=False,
            run=SimpleNamespace(id="run-1", incident_id=by_name()["Invoice overdue"], trigger={}),
            playbook=db.get(Playbook, playbook_id), connection="SOC mailbox",
        )  # fmt: skip
        ca.run_command("mail", "get-attachments", call)
        db.commit()
    assert [(item["relation"], item["id"]) for item in admin.get(f"/api/artifacts/mail-{sha}").json()["children"]] == [
        ("attachment", f"file-{EXE_SHA}")
    ]

    # One a rule drops is not kept; one a rule links is evidence of the incident it was linked to.
    box.folders["INBOX"][13] = [message(13, "Newsletter of the week"), set()]
    box.folders["INBOX"][14] = [message(14, "Phishing report", text="Another one"), set()]
    for body in (
        {
            "name": "Newsletters are noise",
            "when": {"all": [{"left": "{{ item.subject }}", "op": "contains", "right": "Newsletter"}]},
            "action": "drop",
        },
        {
            "name": "Same report, same case",
            "when": {"all": [{"left": "{{ item.subject }}", "op": "eq", "right": "Phishing report"}]},
            "action": "link_to_existing",
            "params": {"same": ["name"], "within_hours": 48},
        },
    ):
        assert admin.post("/api/preprocess-rules", json=body).status_code == 201
    second = cycle()
    assert (second["created"], second["dropped"], second["linked"]) == (0, 1, 1), second
    assert mails() == 4  # the linked one; the dropped one added nothing
    linked = admin.get(f"/api/incidents/{by_name()['Phishing report']}").json()["data"]["mail"]["messages"]
    assert [item["fileName"] for item in linked] == ["message-9.eml", "message-14.eml"]
    dropped = hashlib.sha256(box.folders["INBOX"][13][0]).hexdigest()
    assert admin.get(f"/api/mails/{dropped}").status_code == 404

    # A message above the limit of an upload still becomes an incident, and the item says what is missing.
    box.folders["INBOX"][15] = [message(15, "Too large"), set()]
    with monkeypatch.context() as patch:
        patch.setattr(settings, "SAMPLE_MAX_MB", 0)
        third = cycle()
    assert (third["created"], third["incomplete"]) == (0, 1), third
    outcome, note = outcomes()["<m15@partner.example>15"]
    assert (
        outcome == "incomplete" and note == "The message was not kept as evidence: The message exceeds the 0 MB limit"
    )
    assert "Too large" in by_name() and mails() == 4
    assert "mail" not in admin.get(f"/api/incidents/{by_name()['Too large']}").json()["data"]


# --------------------------------------------------------------------------- #
# A store the worker cannot write to                                          #
# --------------------------------------------------------------------------- #
def test_attachments_are_kept_through_the_api_process_when_the_worker_cannot_write_to_the_store(desk, read_only):
    import time

    from app import artifact_jobs
    from app.core.db import SessionLocal
    from app.core.models import ArtifactJob, AuditEntry, Sample
    from app.malware.samples import read_sample

    admin, box, now = desk.admin, desk.box, time.time()
    box.folders["INBOX"][5] = [
        message(5, "Two files", attach=True, more=(("note.txt", NOTE), ("empty.bin", b""))),
        set(),
    ]
    assert admin.post("/api/incidents", json={"id": "case", "name": "Case", "data": {}}).status_code == 201

    # The worker reads the message and hands the files over: the step gives itself back and keeps what it found.
    waiting = step(desk, "get-attachments", args={"uid": 5}, incident="case", now=now)
    assert waiting.output is None and waiting.again_at == now + artifact_jobs.WAIT_EVERY
    read = len(box.calls)
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Sample)) == 0
        jobs = db.scalars(select(ArtifactJob).order_by(ArtifactJob.created_epoch)).all()
        assert [(job.kind, job.params["name"], job.params["incident"]) for job in jobs] == [
            ("store", "invoice.exe", "case"),
            ("store", "note.txt", "case"),
        ]
        assert db.scalars(select(AuditEntry).where(AuditEntry.action == "mail.attachments.keep")).all() == []
    assert read_only() == 2
    kept = step(desk, "get-attachments", args={"uid": 5}, incident="case", now=now + 2, state=waiting.state)
    found = kept.output
    # The mailbox was not read a second time: the step only waited.
    assert len(box.calls) == read
    assert (found["count"], found["stored"]) == (3, 2)
    assert found["artifacts"] == [f"file-{EXE_SHA}", f"file-{hashlib.sha256(NOTE).hexdigest()}"]
    assert found["attachments"][0]["linked"] is True and found["attachments"][2]["note"] == "It is empty"
    assert kept.classes["attachments.name"] == ["attachment_name"]
    assert read_sample(EXE_SHA) == EXE
    refs = admin.get("/api/incidents/case").json()["data"]["malware"]["samples"]
    assert [(ref["fileName"], ref["origin"]) for ref in refs] == [
        ("invoice.exe", "e-mail “Two files”"),
        ("note.txt", "e-mail “Two files”"),
    ]
    with SessionLocal() as db:
        said = db.scalars(select(AuditEntry.details).where(AuditEntry.action == "mail.attachments.keep")).one()
    assert said == 'Kept 2 attachment(s) of the message 5 of INBOX (playbook "Mail desk", run run-1)'


def test_a_fetched_message_is_kept_through_the_api_process_when_the_worker_cannot_write(admin, box, read_only):
    from app import fetch
    from app.core.db import SessionLocal
    from app.core.models import ArtifactJob, AuditEntry, Connection, FetchedItem, Mail
    from app.malware.samples import read_mail

    with SessionLocal() as db:
        instance(db)
    with SessionLocal() as db:
        first = fetch.cycle(db, db.get(Connection, "m" * 32))
    # The incidents are made; their messages wait for the process that can write them down.
    assert (first["created"], first["incomplete"]) == (3, 0), first
    with SessionLocal() as db:
        assert db.scalar(select(func.count()).select_from(Mail)) == 0
        jobs = db.scalars(select(ArtifactJob)).all()
        assert len(jobs) == 3 and all(job.params["as"] == "mail" and job.params["incident"] for job in jobs)
        assert {row.outcome for row in db.scalars(select(FetchedItem))} == {"created"}
    assert read_only() == 3
    raw = box.folders["INBOX"][4][0]
    sha = hashlib.sha256(raw).hexdigest()
    assert read_mail(sha) == raw
    by_name = {row["name"]: row["id"] for row in admin.get("/api/incidents?view=summary").json()["incidents"]}
    (ref,) = admin.get(f"/api/incidents/{by_name['Invoice overdue']}").json()["data"]["mail"]["messages"]
    assert (ref["sha256"], ref["fileName"], ref["importedBy"]) == (sha, "message-4.eml", "connector:mail")
    artifact = admin.get(f"/api/artifacts/mail-{sha}").json()
    assert [item["name"] for item in artifact["incidents"]] == ["Invoice overdue"]

    # What the API process cannot keep after all is written where the incident is read.
    with SessionLocal() as db:
        from app.automation import mail_evidence
        from app.core.models import Incident

        incident = db.get(Incident, by_name["Invoice overdue"])
        # Not a message: said at once, before any hand-over.
        assert mail_evidence.keep_message(
            db, incident, b"\x00\x01 not a message", "x.eml", "connector:mail"
        ).startswith("The message was not kept as evidence: ")
        artifact_jobs_before = db.scalar(select(func.count()).select_from(ArtifactJob))
        from app import artifact_jobs

        artifact_jobs.Keeper(db, "connector:mail").mail(
            raw, "again.eml", "no-such-incident", report="The message was not kept as evidence"
        )
        db.commit()
        assert db.scalar(select(func.count()).select_from(ArtifactJob)) == artifact_jobs_before + 1
    assert read_only() == 1
    with SessionLocal() as db:
        said = db.scalars(select(AuditEntry.details).where(AuditEntry.action == "evidence.keep")).one()
    assert said == "The message was not kept as evidence: The incident does not exist"
