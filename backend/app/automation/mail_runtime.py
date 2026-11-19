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
  parsing it: an attachment is described (name, type, size, SHA-256), not kept.
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

from . import egress
from .connector_runtime import Answer, CommandError

MAX_RECIPIENTS = 50
MAX_MESSAGE = 2 * 1024 * 1024  # what is read of one message
MAX_TEXT = 20_000  # what a command gives of its text
MAX_FOUND = 200  # messages a search or a fetch reads at most
TIMEOUT = 30
_UNSAFE = re.compile(r'["\\\r\n\x00]')
_TAG = re.compile(r"<[^>]{0,2000}>")
_UID = re.compile(r"UID (\d+)")


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


def describe(raw: bytes, uid: int, folder: str) -> dict[str, Any]:
    """A message as a command gives it: who, what, when, its text and what is attached."""
    message = email.message_from_bytes(raw[:MAX_MESSAGE], policy=email.policy.default)
    attachments = []
    for part in message.iter_attachments() if message.is_multipart() else []:
        try:
            data = part.get_payload(decode=True) or b""
        except (ValueError, LookupError):
            data = b""
        attachments.append(
            {
                "name": str(part.get_filename() or "")[:300],
                "type": part.get_content_type(),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
        if len(attachments) >= 50:
            break
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
        client, self._imap = self._imap, None
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

    def _send(self, to: list[str], subject: str, text: str, headers: dict[str, str] | None = None) -> dict[str, Any]:
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
        record = {"method": "SMTP", "host": host, "path": f"{len(to)} recipient(s)"}
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
        try:
            outputs = getattr(self, "_do_" + name.replace("-", "_"))(args)
        finally:
            self.close()
        return Answer(outputs=outputs, records=list(self.records))

    def _do_send(self, args: dict[str, Any]) -> dict[str, Any]:
        to = recipients(args.get("to"))
        self._allowed(to)
        return self._send(to, args.get("subject"), args.get("text"))

    def _do_reply(self, args: dict[str, Any]) -> dict[str, Any]:
        original = self._original(args)
        to = recipients([original["from"], *(original["to"] + original["cc"] if args.get("all") else [])])
        to = [address for address in to if address.lower() != str(self.config.get("sender") or "").lower()] or to
        self._allowed(to)
        subject = original["subject"]
        subject = subject if subject.lower().startswith("re:") else f"Re: {subject}"
        references = " ".join(part for part in (original["references"], original["message_id"]) if part)
        return self._send(
            to, subject, args.get("text"), {"In-Reply-To": original["message_id"], "References": references}
        )

    def _do_forward(self, args: dict[str, Any]) -> dict[str, Any]:
        to = recipients(args.get("to"))
        self._allowed(to)
        original = self._original(args)
        subject = original["subject"]
        subject = subject if subject.lower().startswith(("fw:", "fwd:")) else f"Fwd: {subject}"
        quoted = (
            f"{args.get('text') or ''}\n\n---------- Forwarded message ----------\n"
            f"From: {original['from']}\nDate: {original['date']}\nSubject: {original['subject']}\n"
            f"To: {', '.join(original['to'])}\n\n{original['text']}"
        )
        return self._send(to, subject, quoted.strip())

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
            return {"method": "SMTP", "host": host, "path": f"{len(to)} recipient(s)", "dry_run": True}
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

    def fetch(self, spec: Any, state: dict[str, Any], first: dict[str, Any], now: dict[str, Any], limit: int) -> dict:
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
