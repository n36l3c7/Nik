"""Mail as a connector: the commands of ``native: mail``, run by Nik's own code.

A connector file speaks HTTP; a mailbox does not. The mail connector's file
names its commands, their arguments and what they give, as any other, and this
module runs them: SMTP to send, IMAP to read, both opened by ``egress.py`` like everything that
leaves. ``MailRuntime`` has the shape of
``connector_runtime.Runtime`` (``run``, ``would_send``, ``test``, ``fetch``,
``close``), so that a node, the War Room, "Test" and the fetch of an instance
use it without knowing.

What an instance holds (the ``configuration`` of the file):

- ``smtp_host``, ``smtp_port``, ``smtp_security`` (starttls | tls | none), ``sender``
- ``imap_host``, ``imap_port``, ``imap_security`` (tls | starttls | none), ``folder``
- ``ca_pem``; the credentials (``username``, ``password``), used for both

Either half may be left out: an instance that only sends has no IMAP host, and
its reading commands say so.

Rules that hold here:

- The servers are the ones written in the instance: they are reached wherever
  they are, as the SMTP server of 4.x was. A **recipient** is a destination:
  its domain must be among the hosts the playbook may reach.
- A value put in an IMAP command (a folder, a word to search) is quoted, and
  refused when it holds a quote, a backslash or a line break.
- A message is read up to ``MAX_MESSAGE`` bytes and never opened further than
  parsing it: an attachment is described (name, type, size, SHA-256).
- Three things need a message whole, and read it up to the limit of an upload,
  refusing one that is larger: ``get-attachments``, which hands what is
  attached to Nik's store; ``forward`` when it carries the attachments; and
  the listener, which keeps the message it made an incident from. An
  attachment is bytes from end to end: stored, or attached again, never opened.
- What ``forward`` and ``reply`` take from the message in the mailbox leaves
  Nik without having been an argument of the node, so the data guard judges
  it when it is read (``judge``, given by who runs the command for a
  playbook): the subject as a subject, the sender and the recipients quoted
  as e-mail addresses, the text as an e-mail body, the attachments as files.
  A part that is held is not quoted, and the message says so in its place. A
  runtime that was given no judge neither forwards nor answers; one that was
  given no store (``keep``) describes the attachments and keeps none.
- The ``Message-ID`` a reply names (``In-Reply-To``, ``References``) is not
  judged: it is what keeps the answer in its conversation, and it goes only
  to those the message was sent by and to.
- Deleting marks the message deleted and expunges it; the file says the command
  changes something outside, so a playbook asks for approval by default.
"""

from __future__ import annotations

import email
import email.policy
import hashlib
import re
import ssl
from datetime import datetime, timezone
from email.message import EmailMessage
from email.utils import getaddresses, make_msgid, parsedate_to_datetime
from typing import Any

from ..core.config import settings
from . import egress
from .connector_runtime import Answer, CommandError

MAX_RECIPIENTS = 50
MAX_MESSAGE = 2 * 1024 * 1024  # what is read of one message
MAX_TEXT = 20_000  # what a command gives of its text
MAX_FOUND = 200  # messages a search or a fetch reads at most
MAX_ATTACHMENTS = 50  # attachments of one message that are described, kept or carried
MAX_CARRIED = 20 * 1024 * 1024  # what a forward carries: base64 adds a third, and most servers stop at 25 MB
TIMEOUT = 30
# What a message says where the data guard held back a part of the one it quotes.
HELD = "(held back)"
SUBJECT_HELD = "(subject held back)"
TEXT_HELD = "(The text of the message was held back by the data guard.)"
_UNSAFE = re.compile(r'["\\\r\n\x00]')
_TAG = re.compile(r"<[^>]{0,2000}>")
_UID = re.compile(r"UID (\d+)")
_TOKEN = re.compile(r"[A-Za-z0-9!#$&^_.+-]{1,100}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _quoted(value: Any, what: str) -> str:
    """A value as it is written in an IMAP command. Refuses what could end the quotes."""
    text = str(value or "").strip()
    if not text or len(text) > 500 or _UNSAFE.search(text):
        raise CommandError(f"{what} is not written as a mailbox accepts it")
    return f'"{text}"'


def _last_word(line: str) -> str:
    """The name of a folder in a line of LIST: ``(\\HasNoChildren) "/" "INBOX/Phishing"`` → its last
    word, quoted or bare. Read from the end, a character at a time: the line is the server's."""
    text = line.rstrip()
    if not text.endswith('"'):
        return text.rsplit(None, 1)[-1] if text else ""
    at = len(text) - 2
    while at >= 0:
        if text[at] == '"':
            slashes = 0
            while at - 1 - slashes >= 0 and text[at - 1 - slashes] == "\\":
                slashes += 1
            if slashes % 2 == 0:
                break
        at -= 1
    return text[at + 1 : -1].replace('\\"', '"').replace("\\\\", "\\") if at >= 0 else ""


def recipients(value: Any) -> list[str]:
    """Addresses from a list or from a text separated by commas, once each, checked as addresses."""
    items = value if isinstance(value, (list, tuple)) else str(value or "").replace(";", ",").split(",")
    found = list(dict.fromkeys(str(item).strip() for item in items if str(item).strip()))
    for address in found:
        name, _, domain = address.rpartition("@")
        if not name or not egress.clean_host(domain) or any(char in address for char in " \r\n<>,"):
            raise CommandError("A recipient is not an e-mail address")
    return found


def _text_of(message: email.message.EmailMessage) -> str:
    """The text of a message: its plain part, or its HTML with the tags taken out."""
    try:
        body = message.get_body(preferencelist=("plain", "html"))
        content = body.get_content() if body is not None else ""
    except (LookupError, ValueError, AttributeError):
        return ""
    text = content if isinstance(content, str) else ""
    if body is not None and body.get_content_type() == "text/html":
        text = " ".join(_TAG.sub(" ", text).split())
    return text[:MAX_TEXT]


def _addresses(header: Any) -> list[str]:
    return [address for _name, address in getaddresses([str(header or "")]) if address][:MAX_RECIPIENTS]


def _iso(header: Any) -> str:
    try:
        moment = parsedate_to_datetime(str(header))
    except (TypeError, ValueError, IndexError):
        return ""
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat()


def files_of(message: email.message.EmailMessage) -> tuple[list[dict[str, Any]], bool]:
    """What is attached to a message: for each, its name, type, size, SHA-256, its bytes (``data``)
    and whether they could be read (``readable``); and whether there are more than are given. An
    attached message is the bytes of that message, as the mail analysis takes it out."""
    found: list[dict[str, Any]] = []
    for part in message.iter_attachments() if message.is_multipart() else []:
        if len(found) >= MAX_ATTACHMENTS:
            return found, True
        readable = True
        try:
            if part.get_content_type() == "message/rfc822":
                inner = part.get_payload()
                data = inner[0].as_bytes() if isinstance(inner, list) and inner else b""
            elif part.is_multipart():
                data, readable = b"", False  # parts within a part: there is no one file to take
            else:
                data = part.get_payload(decode=True) or b""
        except (ValueError, LookupError, TypeError):
            data, readable = b"", False
        found.append(
            {
                "name": str(part.get_filename() or "")[:300],
                "type": part.get_content_type(),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "data": data,
                "readable": readable,
            }
        )
    return found, False


def _shown(item: dict[str, Any]) -> dict[str, Any]:
    """An attachment as a command describes it: without its bytes."""
    return {key: item[key] for key in ("name", "type", "size", "sha256")}


def describe(raw: bytes, uid: int, folder: str) -> dict[str, Any]:
    """A message as a command gives it: who, what, when, its text and what is attached."""
    message = email.message_from_bytes(raw[:MAX_MESSAGE], policy=email.policy.default)
    attachments = [_shown(item) for item in files_of(message)[0]]
    return {
        "uid": uid,
        "folder": folder,
        "message_id": str(message.get("Message-ID") or "").strip()[:500],
        "subject": " ".join(str(message.get("Subject") or "").split())[:500],
        "from": (_addresses(message.get("From")) or [""])[0],
        "to": _addresses(message.get("To")),
        "cc": _addresses(message.get("Cc")),
        "date": _iso(message.get("Date")),
        "in_reply_to": str(message.get("In-Reply-To") or "").strip()[:500],
        "references": str(message.get("References") or "").strip()[:2000],
        "text": _text_of(message),
        "attachments": attachments,
        "size": len(raw),
        "truncated": len(raw) > MAX_MESSAGE,
    }


class MailRuntime:
    """The commands of the mail connector for one instance."""

    def __init__(self, connector, config: dict[str, Any], secrets: dict[str, str], policy: egress.Policy, **_more):
        self.connector = connector
        self.policy = policy
        self.secrets = {key: str(value) for key, value in (secrets or {}).items() if value}
        self.config = self._config(config or {})
        self.records: list[dict] = []
        self._imap: Any = None
        self._selected: tuple[str, bool] | None = None
        # Given by who runs a command for a playbook (connector_actions.py): the data guard for what
        # a message would quote and carry of another (``judge(quoted, files)`` gives the names of
        # the quoted parts it held and whether the files go), and Nik's store for the files it is
        # asked to keep.
        self.judge: Any = None
        self.keep: Any = None
        self.classes: dict[str, list] = {}  # of the outputs of the command that ran

    def _config(self, given: dict[str, Any]) -> dict[str, Any]:
        out = {}
        for param in self.connector.configuration:
            if param.is_auth or param.type == "secret":
                continue
            value = given.get(param.name)
            out[param.name] = param.default if value in (None, "") else value
        return out

    # ---------------------------------------------------------------- servers --
    def _ca(self) -> str | None:
        return str(self.config.get("ca_pem") or "") or None

    def _smtp_host(self) -> str:
        host = egress.clean_host(str(self.config.get("smtp_host") or ""))
        if not host or not self.config.get("sender"):
            raise CommandError("This instance has no SMTP server and sender: it cannot send")
        return host

    def _imap_host(self) -> str:
        host = egress.clean_host(str(self.config.get("imap_host") or ""))
        if not host:
            raise CommandError("This instance has no IMAP server: it cannot read a mailbox")
        return host

    def _open(self) -> Any:
        if self._imap is not None:
            return self._imap
        host = self._imap_host()
        port = int(self.config.get("imap_port") or 993)
        security = str(self.config.get("imap_security") or "tls")
        record = {"method": "IMAP", "host": host, "path": ""}
        try:
            client = egress.imap_client(host, port, security, self._ca(), TIMEOUT)
            client.login(self.secrets.get("username", ""), self.secrets.get("password", ""))
        except egress.IMAP_ERROR:
            raise CommandError("The IMAP server refused the user name or the password", record=record) from None
        except ssl.SSLError:
            raise CommandError(f"The certificate of {host} could not be verified", record=record) from None
        except OSError:
            raise CommandError(f"The IMAP server {host} could not be reached", retry=True, record=record) from None
        self._imap = client
        return client

    def _select(self, folder: str, *, readonly: bool) -> Any:
        client = self._open()
        status, _data = self._ask(client.select, _quoted(folder, "The folder"), readonly)
        if status != "OK":
            raise CommandError(f'There is no folder "{folder}" in this mailbox')
        self.records.append({"method": "IMAP", "host": self._imap_host(), "path": folder, "status": "ok"})
        self._selected = (folder, readonly)
        return client

    def _ask(self, call, *args):
        try:
            return call(*args)
        except egress.IMAP_ERROR as error:
            raise CommandError(f"The mailbox refused: {str(error)[:200]}") from None
        except OSError:
            raise CommandError("The connection to the mailbox was lost", retry=True) from None

    def _folder(self, args: dict[str, Any]) -> str:
        return str(args.get("folder") or self.config.get("folder") or "INBOX")

    def _uid(self, args: dict[str, Any]) -> int:
        try:
            uid = int(args.get("uid"))
        except (TypeError, ValueError):
            raise CommandError('"uid" is the number of the message in its folder') from None
        if uid <= 0:
            raise CommandError('"uid" is the number of the message in its folder')
        return uid

    def close(self) -> None:
        if self._imap is None:
            return
        client, self._imap, self._selected = self._imap, None, None
        try:
            client.logout()
        except (egress.IMAP_ERROR, OSError):
            pass

    # ---------------------------------------------------------------- reading --
    def _read(self, client: Any, uids: list[int], folder: str) -> list[dict[str, Any]]:
        found = []
        for uid in uids:
            status, data = self._ask(client.uid, "FETCH", str(uid), f"(BODY.PEEK[]<0.{MAX_MESSAGE + 1}>)")
            raw = next((part[1] for part in data or [] if isinstance(part, tuple) and len(part) > 1), None)
            if status == "OK" and isinstance(raw, (bytes, bytearray)):
                found.append(describe(bytes(raw), uid, folder))
        return found

    def _whole(self, client: Any, uid: int) -> bytes:
        """A message as the server holds it, all of it: what is kept or carried must not be cut.
        One above the limit of an upload is refused, not read by halves."""
        most = settings.SAMPLE_MAX_MB * 1024 * 1024
        status, data = self._ask(client.uid, "FETCH", str(uid), f"(BODY.PEEK[]<0.{most + 1}>)")
        raw = next((part[1] for part in data or [] if isinstance(part, tuple) and len(part) > 1), None)
        if status != "OK" or not isinstance(raw, (bytes, bytearray)):
            raise CommandError("There is no message with this uid in the folder")
        if len(raw) > most:
            raise CommandError(f"The message exceeds the {settings.SAMPLE_MAX_MB} MB limit")
        return bytes(raw)

    def _search(self, client: Any, criteria: list[str]) -> list[int]:
        status, data = self._ask(client.uid, "SEARCH", *(criteria or ["ALL"]))
        if status != "OK":
            raise CommandError("The mailbox could not search")
        numbers = (data[0] or b"").split() if data else []
        return sorted(int(number) for number in numbers if number.isdigit())

    def _criteria(self, args: dict[str, Any]) -> list[str]:
        criteria = []
        for key, word in (("from", "FROM"), ("subject", "SUBJECT"), ("text", "TEXT")):
            if args.get(key):
                criteria += [word, _quoted(args[key], f'"{key}"')]
        if args.get("since"):
            try:
                day = datetime.fromisoformat(str(args["since"])[:10])
            except ValueError:
                raise CommandError('"since" is a date: 2026-11-19') from None
            criteria += ["SINCE", day.strftime("%d-%b-%Y")]
        if args.get("unseen"):
            criteria.append("UNSEEN")
        return criteria

    # ---------------------------------------------------------------- sending --
    def _allowed(self, to: list[str]) -> None:
        if not to or len(to) > MAX_RECIPIENTS:
            raise CommandError(f"1 to {MAX_RECIPIENTS} recipients are needed")
        for address in to:
            domain = egress.clean_host(address.rpartition("@")[2]) or ""
            # A recipient is a destination: its domain is among the hosts the playbook may reach.
            if self.policy.mode != "any" and domain not in self.policy.hosts:
                raise CommandError(
                    f"{domain} is not among the hosts this playbook may reach: list it to write to its addresses"
                )

    def _judged(self) -> Any:
        """The guard this runtime was given. Without one, nothing read in the mailbox is sent on."""
        if self.judge is None:
            raise CommandError(
                "A message of the mailbox is forwarded or answered only where the data guard judges "
                "what is taken from it: in a playbook"
            )
        return self.judge

    def _carriable(self, raw: bytes) -> list[dict[str, Any]]:
        """The attachments a forward would carry: all of them, or none. What cannot be judged whole
        (one that could not be read, more than are looked at, more than a server takes) is refused
        with a sentence; the guard decides on the rest."""
        found, more = files_of(email.message_from_bytes(raw, policy=email.policy.default))
        if not found:
            return []
        without = 'forward it with "attachments" off'
        if more:
            raise CommandError(f"The message has more than {MAX_ATTACHMENTS} attachments: {without}")
        if not all(item["readable"] for item in found):
            raise CommandError(f"An attachment of the message could not be read, so it cannot be judged: {without}")
        if sum(item["size"] for item in found) > MAX_CARRIED:
            raise CommandError(
                f"The attachments are more than {MAX_CARRIED // (1024 * 1024)} MB together, "
                f"more than a mail server takes: {without}"
            )
        return found

    @staticmethod
    def _attach(message: EmailMessage, item: dict[str, Any]) -> None:
        """Attach a file as bytes. Its name and type are the sender's words: the name loses what
        could break a header, a type that is not written as one becomes a plain binary."""
        name = " ".join(_CONTROL.sub(" ", item["name"]).split())[:200] or "attachment"
        if item["type"] == "message/rfc822":
            try:
                inner = email.message_from_bytes(item["data"], policy=email.policy.default)
                message.add_attachment(inner, filename=name)
                return
            except (ValueError, LookupError, TypeError):
                pass  # it goes as the bytes it is
        maintype, _, subtype = item["type"].partition("/")
        if maintype in ("message", "multipart") or not (_TOKEN.fullmatch(maintype) and _TOKEN.fullmatch(subtype)):
            maintype, subtype = "application", "octet-stream"
        message.add_attachment(item["data"], maintype=maintype, subtype=subtype, filename=name)

    def _send(
        self,
        to: list[str],
        subject: str,
        text: str,
        headers: dict[str, str] | None = None,
        files: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        host = self._smtp_host()
        port = int(self.config.get("smtp_port") or 587)
        security = str(self.config.get("smtp_security") or "starttls")
        message = EmailMessage()
        message["From"] = str(self.config["sender"])
        message["To"] = ", ".join(to)
        message["Subject"] = " ".join(str(subject or "(no subject)").split())[:300]
        message["Message-ID"] = make_msgid(domain=str(self.config["sender"]).rpartition("@")[2] or None)
        for name, value in (headers or {}).items():
            if value:
                message[name] = " ".join(str(value).split())[:2000]
        message.set_content(str(text or ""))
        for item in files or []:
            self._attach(message, item)
        record = {"method": "SMTP", "host": host, "path": f"{len(to)} recipient(s)"}
        if files:
            record["attachments"] = len(files)
        try:
            client, context = egress.smtp_client(host, port, security, self._ca(), TIMEOUT)
            with client:
                if security == "starttls":
                    client.starttls(context=context)
                if self.secrets.get("username"):
                    client.login(self.secrets["username"], self.secrets.get("password", ""))
                refused = client.send_message(message)
        except egress.SMTP_AUTH_ERROR:
            raise CommandError("The SMTP server refused the user name or the password", record=record) from None
        except egress.SMTP_RECIPIENTS_REFUSED:
            raise CommandError("The SMTP server refused every recipient", record=record) from None
        except ssl.SSLError:
            raise CommandError(f"The certificate of {host} could not be verified", record=record) from None
        except (OSError, egress.SMTP_ERROR):
            # It may have left before the connection broke: the engine does not send it twice by itself.
            raise CommandError(
                f"The SMTP server {host} could not be reached", retry=True, sent=True, record=record
            ) from None
        record.update(status="sent", refused=sorted(refused) if refused else [])
        self.records.append(record)
        return {"sent": True, "recipients": len(to), "message_id": str(message["Message-ID"])}

    def _original(self, args: dict[str, Any]) -> dict[str, Any]:
        folder = self._folder(args)
        found = self._read(self._select(folder, readonly=True), [self._uid(args)], folder)
        if not found:
            raise CommandError("There is no message with this uid in the folder")
        return found[0]

    # --------------------------------------------------------------- commands --
    def run(self, name: str, args: dict[str, Any], state: dict[str, Any] | None = None) -> Answer:
        command = self.connector.command(name)
        if command is None:
            raise CommandError("This command is not in the connector any more")
        args = {**{argument.name: argument.default for argument in command.arguments}, **args}
        missing = [a.name for a in command.arguments if a.required and args.get(a.name) in (None, "", [])]
        if missing:
            raise CommandError("Needed: " + ", ".join(missing))
        self.classes = {}
        try:
            outputs = getattr(self, "_do_" + name.replace("-", "_"))(args)
        finally:
            self.close()
        return Answer(outputs=outputs, records=list(self.records), classes=dict(self.classes))

    def _do_send(self, args: dict[str, Any]) -> dict[str, Any]:
        to = recipients(args.get("to"))
        self._allowed(to)
        return self._send(to, args.get("subject"), args.get("text"))

    def _do_reply(self, args: dict[str, Any]) -> dict[str, Any]:
        judge = self._judged()
        original = self._original(args)
        to = recipients([original["from"], *(original["to"] + original["cc"] if args.get("all") else [])])
        to = [address for address in to if address.lower() != str(self.config.get("sender") or "").lower()] or to
        self._allowed(to)
        # An answer repeats one thing of the message it answers: its subject.
        held, _carry = judge({"subject": (original["subject"], ("subject",))}, [])
        subject = SUBJECT_HELD if "subject" in held else original["subject"]
        subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
        references = " ".join(part for part in (original["references"], original["message_id"]) if part)
        sent = self._send(
            to, subject, args.get("text"), {"In-Reply-To": original["message_id"], "References": references}
        )
        return {**sent, "quoted_held": list(held)}

    def _do_forward(self, args: dict[str, Any]) -> dict[str, Any]:
        judge = self._judged()
        to = recipients(args.get("to"))
        self._allowed(to)
        found: list[dict[str, Any]] = []
        if args.get("attachments"):
            # With what is attached: the message is read whole, and the guard says whether it goes.
            folder, uid = self._folder(args), self._uid(args)
            raw = self._whole(self._select(folder, readonly=True), uid)
            original = describe(raw, uid, folder)
            found = self._carriable(raw)
        else:
            original = self._original(args)
        # Everything the new message repeats of the one in the mailbox, with the class it has there.
        quoted = {
            "subject": (original["subject"], ("subject",)),
            "from": (original["from"], ("email_address",)),
            "to": (original["to"], ("email_address",)),
            "date": (original["date"], ()),
            "text": (original["text"], ("mail_body",)),
        }
        held, carry = judge(quoted, [_shown(item) for item in found])
        files = found if carry else []
        said = {name: HELD if name in held else value for name, (value, _classes) in quoted.items()}
        subject = SUBJECT_HELD if "subject" in held else original["subject"]
        subject = subject if subject.lower().startswith(("fw:", "fwd:")) else f"Fwd: {subject}"
        recipients_said = said["to"] if isinstance(said["to"], str) else ", ".join(said["to"])
        text = (
            f"{args.get('text') or ''}\n\n---------- Forwarded message ----------\n"
            f"From: {said['from']}\nDate: {said['date']}\nSubject: {said['subject']}\n"
            f"To: {recipients_said}\n\n{TEXT_HELD if 'text' in held else original['text']}"
        )
        sent = self._send(to, subject, text.strip(), files=files)
        return {
            **sent,
            "attachments": len(files),
            "attachments_held": len(found) - len(files),
            "quoted_held": list(held),
        }

    def _do_search(self, args: dict[str, Any]) -> dict[str, Any]:
        folder = self._folder(args)
        client = self._select(folder, readonly=True)
        uids = self._search(client, self._criteria(args))
        limit = max(1, min(int(args.get("limit") or 20), MAX_FOUND))
        latest = uids[-limit:][::-1]  # the newest first
        messages = self._read(client, latest, folder)
        for message in messages:
            message["text"] = message["text"][:500]
        return {"messages": messages, "count": len(uids), "truncated": len(uids) > limit}

    def _do_get_message(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._original(args)

    def _do_get_attachments(self, args: dict[str, Any]) -> dict[str, Any]:
        folder, uid = self._folder(args), self._uid(args)
        raw = self._whole(self._select(folder, readonly=True), uid)
        message = email.message_from_bytes(raw, policy=email.policy.default)
        found, more = files_of(message)
        said = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "subject": " ".join(str(message.get("Subject") or "").split())[:500],
            "uid": uid,
            "folder": folder,
        }
        if self.keep is not None and found:
            kept = self.keep(found, said, args.get("incident"))
        else:
            kept = [{"artifact": "", "linked": False, "note": "There is no store to keep it in here"} for _ in found]
        attachments = [{**_shown(item), **entry} for item, entry in zip(found, kept, strict=True)]
        self.classes = {
            "attachments.name": ["attachment_name"],
            "attachments.sha256": ["hash"],
            "attachments.artifact": ["nik_id"],
            "artifacts": ["nik_id"],
        }
        return {
            "attachments": attachments,
            "artifacts": [entry["artifact"] for entry in attachments if entry["artifact"]],
            "count": len(attachments),
            "stored": sum(1 for entry in attachments if entry["artifact"]),
            "truncated": more,
        }

    def _do_move(self, args: dict[str, Any]) -> dict[str, Any]:
        uid, target = self._uid(args), _quoted(args.get("to"), "The folder to move to")
        client = self._select(self._folder(args), readonly=False)
        status, _data = self._ask(client.uid, "COPY", str(uid), target)
        if status != "OK":
            raise CommandError(f"The message could not be copied to {target}: is the folder there?")
        self._ask(client.uid, "STORE", str(uid), "+FLAGS", "(\\Deleted)")
        self._ask(client.expunge)
        return {"moved": True, "uid": uid, "to": str(args.get("to"))}

    def _flag(self, args: dict[str, Any], how: str) -> dict[str, Any]:
        uid = self._uid(args)
        client = self._select(self._folder(args), readonly=False)
        status, _data = self._ask(client.uid, "STORE", str(uid), how, "(\\Seen)")
        if status != "OK":
            raise CommandError("There is no message with this uid in the folder")
        return {"uid": uid, "read": how.startswith("+")}

    def _do_mark_read(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._flag(args, "+FLAGS")

    def _do_mark_unread(self, args: dict[str, Any]) -> dict[str, Any]:
        return self._flag(args, "-FLAGS")

    def _do_delete(self, args: dict[str, Any]) -> dict[str, Any]:
        uid = self._uid(args)
        client = self._select(self._folder(args), readonly=False)
        status, _data = self._ask(client.uid, "STORE", str(uid), "+FLAGS", "(\\Deleted)")
        if status != "OK":
            raise CommandError("There is no message with this uid in the folder")
        self._ask(client.expunge)
        return {"deleted": True, "uid": uid}

    def _do_list_folders(self, _args: dict[str, Any]) -> dict[str, Any]:
        status, data = self._ask(self._open().list)
        if status != "OK":
            raise CommandError("The mailbox did not list its folders")
        names = []
        for line in data or []:
            text = line.decode("utf-8", "replace") if isinstance(line, (bytes, bytearray)) else str(line)
            names.append(_last_word(text))
        self.records.append({"method": "IMAP", "host": self._imap_host(), "path": "LIST", "status": "ok"})
        return {"folders": sorted(name for name in names if name)}

    # ------------------------------------------------------------- the others --
    def would_send(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """What a command would do first, for a dry run: nothing leaves."""
        if name in ("send", "reply", "forward"):
            to = recipients(args.get("to")) if name != "reply" else []
            if to:
                self._allowed(to)
            host = egress.clean_host(str(self.config.get("smtp_host") or "")) or "(no SMTP server)"
            would = {"method": "SMTP", "host": host, "path": f"{len(to)} recipient(s)", "dry_run": True}
            if name != "send":
                # The mailbox is not read for a dry run, so what would be quoted is not known here.
                would["note"] = "What it takes from the message is judged by the data guard when the step runs"
            return would
        host = egress.clean_host(str(self.config.get("imap_host") or "")) or "(no IMAP server)"
        return {"method": "IMAP", "host": host, "path": self._folder(args), "dry_run": True}

    def test(self) -> dict[str, Any]:
        """ "Test the connection": the mailbox takes the credentials, the SMTP server answers. Never raises."""
        said = []
        try:
            if self.config.get("imap_host"):
                self._select(self._folder({}), readonly=True)
                said.append("the mailbox opened")
            if self.config.get("smtp_host"):
                host = self._smtp_host()
                port = int(self.config.get("smtp_port") or 587)
                security = str(self.config.get("smtp_security") or "starttls")
                try:
                    client, context = egress.smtp_client(host, port, security, self._ca(), TIMEOUT)
                    with client:
                        if security == "starttls":
                            client.starttls(context=context)
                        if self.secrets.get("username"):
                            client.login(self.secrets["username"], self.secrets.get("password", ""))
                        client.noop()
                except egress.SMTP_AUTH_ERROR:
                    raise CommandError("The SMTP server refused the user name or the password") from None
                except ssl.SSLError:
                    raise CommandError(f"The certificate of {host} could not be verified") from None
                except (OSError, egress.SMTP_ERROR):
                    raise CommandError(f"The SMTP server {host} could not be reached") from None
                said.append("the SMTP server took the credentials")
            if not said:
                return {"ok": False, "status": 0, "message": "This instance has neither an IMAP nor an SMTP server"}
            return {"ok": True, "status": 0, "message": " and ".join(said).capitalize()}
        except CommandError as error:
            return {"ok": False, "status": 0, "message": error.message}
        finally:
            self.close()

    def evidence(self, item: Any) -> tuple[str, bytes] | None:
        """The message an item of the listener was read from, whole: what is kept as evidence of the
        incident it became. The mailbox stays open from one item to the next, and whoever asks closes
        it at the end of the cycle. None for what is not an item of this listener."""
        try:
            uid, folder = int(item.get("uid")), str(item.get("folder") or "")
        except (AttributeError, TypeError, ValueError):
            return None
        if uid <= 0 or not folder:
            return None
        client = self._imap if self._selected == (folder, True) else self._select(folder, readonly=True)
        return f"message-{uid}.eml", self._whole(client, uid)

    def fetch(
        self,
        spec: Any,
        state: dict[str, Any],
        first: dict[str, Any],
        now: dict[str, Any],
        limit: int,
        since: Any = None,
    ) -> dict:
        """The messages that arrived since the last cycle: those with a uid above ``state.uid``; the
        first time, those since ``first``. ``response.last_uid`` is what the next cycle starts after."""
        folder = self._folder({})
        try:
            client = self._select(folder, readonly=True)
            last = int((state or {}).get("uid") or 0)
            if last > 0:
                uids = [uid for uid in self._search(client, ["UID", f"{last + 1}:*"]) if uid > last]
            else:
                day = datetime.fromtimestamp(float(first.get("epoch") or 0), tz=timezone.utc)
                uids = self._search(client, ["SINCE", day.strftime("%d-%b-%Y")])
            limit = max(1, min(limit, MAX_FOUND))
            taken = uids[:limit]  # the oldest first: the cycle after goes on from the last read
            items = self._read(client, taken, folder)
        finally:
            self.close()
        return {
            "items": items,
            "truncated": len(uids) > len(taken),
            "response": {"last_uid": taken[-1] if taken else last, "folder": folder},
            "status": 0,
            "headers": {},
        }
