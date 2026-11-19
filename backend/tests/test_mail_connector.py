"""The mail connector (5.1): a native connector, run by Nik's own code over IMAP and SMTP.

The servers are doubles: an IMAP mailbox held in memory and an SMTP server that
keeps what it was given. Nobody ran the connector against a real mailbox.
"""

from __future__ import annotations

import hashlib
from email.message import EmailMessage

import pytest

from app.automation import connector_actions as ca
from app.automation import connectors as files
from app.automation import egress, mail_runtime
from app.automation.connector_runtime import CommandError

MAIL = next(connector for _text, connector in ca.shipped() if connector.id == "mail")
CONFIG = {
    "imap_host": "imap.acme.example",
    "smtp_host": "smtp.acme.example",
    "sender": "soc@acme.example",
}
SECRETS = {"username": "soc", "password": "app-pass-1234"}


def message(uid: int, subject: str, sender: str = "anna@partner.example", text: str = "Hello", attach: bool = False):
    made = EmailMessage()
    made["From"] = f"Anna <{sender}>"
    made["To"] = "soc@acme.example, bruno@acme.example"
    made["Subject"] = subject
    made["Date"] = "Thu, 19 Nov 2026 09:30:00 +0100"
    made["Message-ID"] = f"<m{uid}@partner.example>"
    made.set_content(text)
    if attach:
        made.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream", filename="invoice.exe")
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
            raise mail_runtime.imaplib.IMAP4.error("LOGIN failed")
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
            raise mail_runtime.smtplib.SMTPAuthenticationError(535, b"no")

    def send_message(self, made):
        Smtp.sent.append(made)
        return {}

    def noop(self):
        return 250, b"ok"


@pytest.fixture()
def box(monkeypatch):
    mailbox = Mailbox()
    monkeypatch.setattr(mail_runtime.imaplib, "IMAP4_SSL", lambda *args, **kwargs: mailbox)
    monkeypatch.setattr(mail_runtime.smtplib, "SMTP", Smtp)
    Smtp.sent, Smtp.logins = [], []
    return mailbox


def runtime(hosts=("partner.example", "acme.example"), config=None, secrets=None):
    policy = egress.Policy(mode="listed", hosts=frozenset(hosts))
    return mail_runtime.MailRuntime(MAIL, {**CONFIG, **(config or {})}, secrets or SECRETS, policy)


def run(name: str, **args):
    return runtime().run(name, args).outputs


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
    run("reply", uid=4, text="Paid yesterday.")
    reply = Smtp.sent[-1]
    assert reply["To"] == "anna@partner.example" and reply["Subject"] == "Re: Invoice overdue"
    assert reply["In-Reply-To"] == "<m4@partner.example>" and reply["References"] == "<m4@partner.example>"
    run("reply", uid=7, text="Thanks.", all=True)
    everyone = Smtp.sent[-1]
    # Everyone it was sent to, but not the mailbox itself; "Re:" is not written twice.
    assert everyone["To"] == "bruno@acme.example" and everyone["Subject"] == "Re: your ticket"

    run("forward", uid=4, to=["bruno@acme.example"], text="See below.")
    forwarded = Smtp.sent[-1]
    assert forwarded["Subject"] == "Fwd: Invoice overdue"
    body = forwarded.get_content()
    assert body.startswith("See below.") and "From: anna@partner.example" in body and "Please pay." in body
    # The sender of the message answered is a recipient like any other.
    with pytest.raises(CommandError) as caught:
        runtime(hosts=("acme.example",)).run("reply", {"uid": 4, "text": "x"})
    assert "partner.example is not among the hosts" in caught.value.message


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
