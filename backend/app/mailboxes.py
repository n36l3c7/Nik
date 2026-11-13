"""Mailboxes: a file of many e-mails kept as one artifact.

Three formats, one store. Whatever is uploaded ends as an mbox in
``SAMPLE_STORE/_mailboxes/<id>/mailbox.mbox``:

- an **mbox** is kept as it is;
- a **Maildir** arrives as a zip or tar archive (``cur/``, ``new/``): its
  messages are written one after the other as an mbox, nothing is unpacked;
- an Outlook **PST** is converted by the isolated document worker (``readpst``).

``index`` then reads the mbox once, line by line (a mailbox can be gigabytes;
it is never held in memory): where each message is, its headers, its SHA-256.
``thread`` joins each message to the one it answers (``In-Reply-To``,
``References``; failing those, Gmail's thread id or the subject) and numbers
the conversations. Nothing is analysed until an analyst imports messages:
each then becomes an e-mail artifact, analysed as an ``.eml`` is.
"""

from __future__ import annotations

import hashlib
import io
import os
import re
import shutil
import tarfile
import zipfile
from email import policy
from email.parser import BytesHeaderParser
from email.utils import getaddresses, parsedate_to_datetime
from pathlib import Path
from typing import Any, BinaryIO, Iterable, Iterator

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession

from .core.config import settings
from .core.models import Mail, Mailbox, MailboxMessage

IMPORT_MAX = 500
HEADERS_MAX = 256 * 1024
MESSAGES_MAX = 500_000
_ID_RE = re.compile(r"[0-9a-f]{32}")
_FROM = re.compile(rb">*From ")
_PREFIX = re.compile(r"^\s*((re|fwd?|fw|r|i|rif|aw|wg|tr|sv|vs)\s*(\[\d+\])?\s*:\s*)+", re.IGNORECASE)
_ATTACHMENT = re.compile(rb"^content-disposition:\s*attachment", re.IGNORECASE)


class MailboxError(ValueError):
    """The file is not a mailbox Nik can read."""


# --------------------------------------------------------------------------- #
# Store                                                                       #
# --------------------------------------------------------------------------- #
def directory(mailbox_id: str) -> Path:
    if not _ID_RE.fullmatch(mailbox_id or ""):
        raise ValueError("Not a mailbox id.")
    path = Path(settings.SAMPLE_STORE) / "_mailboxes" / mailbox_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def mbox_path(mailbox_id: str) -> Path:
    return directory(mailbox_id) / "mailbox.mbox"


def remove(mailbox_id: str) -> None:
    if _ID_RE.fullmatch(mailbox_id or ""):
        shutil.rmtree(Path(settings.SAMPLE_STORE) / "_mailboxes" / mailbox_id, ignore_errors=True)


def detect(head: bytes, name: str = "") -> str | None:
    """``mbox``, ``maildir`` (an archive) or ``pst`` from the first bytes and the name."""
    lower = name.lower()
    if head.startswith(b"!BDN"):
        return "pst"
    if head.startswith(b"PK\x03\x04") or head.startswith(b"\x1f\x8b") or lower.endswith((".tar", ".tgz", ".tar.gz")):
        return "maildir"
    if len(head) >= 512 and head[257:262] == b"ustar":
        return "maildir"
    if head.startswith(b"From "):
        return "mbox"
    return None


# --------------------------------------------------------------------------- #
# Maildir archive -> mbox                                                     #
# --------------------------------------------------------------------------- #
def _maildir_members(path: Path) -> Iterator[tuple[str, BinaryIO, int]]:
    """``(name, stream, size)`` of the messages in a zip or tar archive of a
    Maildir: the files under a ``cur/`` or ``new/`` folder. Nothing is unpacked."""

    def wanted(name: str) -> bool:
        parts = name.replace("\\", "/").split("/")
        return len(parts) >= 2 and parts[-2] in ("cur", "new") and bool(parts[-1])

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                if not info.is_dir() and wanted(info.filename):
                    with archive.open(info) as stream:
                        yield info.filename, stream, info.file_size
        return
    try:
        with tarfile.open(path, "r:*") as archive:
            for member in archive:
                if member.isfile() and wanted(member.name):
                    stream = archive.extractfile(member)
                    if stream is not None:
                        yield member.name, stream, member.size
    except tarfile.TarError as exc:
        raise MailboxError("Not a zip or tar archive of a Maildir.") from exc


def maildir_to_mbox(archive: Path, target: Path, limit_bytes: int) -> int:
    """Write the messages of a Maildir archive one after the other as an mbox
    (``From `` lines of a body are escaped, as mboxrd does). Returns how many."""
    count = written = 0
    with open(target, "wb") as out:
        for _name, stream, size in _maildir_members(archive):
            if size > settings.SAMPLE_MAX_MB * 1024 * 1024:
                continue
            written += size
            if written > limit_bytes:
                raise MailboxError("The messages of the archive exceed the size limit of a mailbox.")
            out.write(b"From MAILER-DAEMON Thu Jan  1 00:00:00 1970\n")
            last = b"\n"
            for line in stream:
                out.write(b">" + line if _FROM.match(line) else line)
                last = line
            out.write(b"\n" if last.endswith(b"\n") else b"\n\n")
            count += 1
            if count >= MESSAGES_MAX:
                break
    if count == 0:
        raise MailboxError("The archive holds no Maildir folder (cur/ or new/).")
    return count


# --------------------------------------------------------------------------- #
# Reading an mbox                                                             #
# --------------------------------------------------------------------------- #
def _unescape(line: bytes) -> bytes:
    """A ``>From `` line of a body back to ``From `` (one ``>`` less)."""
    return line[1:] if line.startswith(b">") and _FROM.match(line) else line


def iter_messages(path: Path) -> Iterator[dict[str, Any]]:
    """Each message of the mbox, read in one pass: ``offset`` and ``length``
    of its bytes in the file (after its ``From `` line), its ``headers``
    (bytes), its ``sha256`` and whether it carries an attachment."""
    with open(path, "rb") as handle:
        position = 0
        start: int | None = None
        end = 0
        blank = True
        digest = hashlib.sha256()
        headers: list[bytes] = []
        in_headers = False
        header_bytes = 0
        attachment = False
        pending = b""  # a trailing blank line belongs to the separator, not to the message

        def finish() -> dict[str, Any]:
            return {
                "offset": start,
                "length": end - start,
                "headers": b"".join(headers),
                "sha256": digest.hexdigest(),
                "attachments": attachment,
            }

        for line in handle:
            if blank and line.startswith(b"From "):
                if start is not None and end > start:  # a "From " line with nothing after it is no message
                    yield finish()
                start = end = position + len(line)
                digest = hashlib.sha256()
                headers, in_headers, header_bytes, attachment, pending = [], True, 0, False, b""
            elif start is not None:
                text = _unescape(line)
                if pending:
                    digest.update(pending)
                    pending = b""
                if text in (b"\n", b"\r\n"):
                    pending = text
                    in_headers = False
                else:
                    digest.update(text)
                    end = position + len(line)
                    if in_headers and header_bytes < HEADERS_MAX:
                        headers.append(text)
                        header_bytes += len(text)
                    elif not attachment and _ATTACHMENT.match(text):
                        attachment = True
            blank = line in (b"\n", b"\r\n")
            position += len(line)
        if start is not None and end > start:
            yield finish()


def read_message(path: Path, offset: int, length: int) -> bytes:
    """The bytes of one message, as ``iter_messages`` hashed them."""
    with open(path, "rb") as handle:
        handle.seek(offset)
        raw = handle.read(length)
    return b"".join(_unescape(line) for line in io.BytesIO(raw))


def _header(message, name: str) -> str:
    try:
        return " ".join(str(message.get(name) or "").split())
    except (ValueError, TypeError, LookupError):
        return ""


def _addresses(message, *names: str) -> list[str]:
    try:
        values = [str(v) for name in names for v in (message.get_all(name) or [])]
        return [address.lower() for _name, address in getaddresses(values) if "@" in address]
    except (ValueError, TypeError, LookupError):
        return []


def _ids(text: str) -> list[str]:
    return [m.lower() for m in re.findall(r"<[^<>\s]{1,300}>", text or "")]


def describe(headers: bytes) -> dict[str, Any]:
    """What the index keeps of a message's headers."""
    message = BytesHeaderParser(policy=policy.compat32).parsebytes(headers)
    sender = _addresses(message, "From")
    date_ms = None
    try:
        when = parsedate_to_datetime(_header(message, "Date"))
        date_ms = int(when.timestamp() * 1000) if when is not None else None
    except (ValueError, TypeError, OverflowError):
        date_ms = None
    try:
        from email.header import decode_header, make_header

        subject = str(make_header(decode_header(_header(message, "Subject"))))
    except (ValueError, LookupError, UnicodeError):
        subject = _header(message, "Subject")
    return {
        "message_id": (_ids(_header(message, "Message-ID")) or [""])[0][:400],
        "in_reply_to": (_ids(_header(message, "In-Reply-To")) or [""])[0],
        "references": _ids(_header(message, "References"))[-20:],
        "gmail_thread": _header(message, "X-GM-THRID")[:40],
        "subject": " ".join(subject.split())[:500],
        "sender": (sender[0] if sender else _header(message, "From"))[:320],
        "recipients": ", ".join(_addresses(message, "To", "Cc")[:8])[:500],
        "date_ms": date_ms,
    }


def subject_key(subject: str) -> str:
    """The subject without its ``Re:`` / ``Fwd:`` prefixes, to tell a conversation by."""
    return _PREFIX.sub("", subject or "").strip().lower()


def thread(rows: list[dict[str, Any]]) -> None:
    """Fill ``parent``, ``thread`` and ``duplicate_of`` of the described
    messages (in file order, each with its ``seq``).

    A message answers the one named by ``In-Reply-To``, else the last of its
    ``References`` that the mailbox holds. With neither, a message whose
    subject starts with ``Re:`` or ``Fwd:`` answers the latest earlier message
    with the same subject. Gmail's thread id joins what it says belongs together."""
    by_id: dict[str, int] = {}
    for row in rows:
        row["parent"], row["duplicate_of"] = None, None
        key = row["message_id"]
        if key and key in by_id:
            row["duplicate_of"] = by_id[key]  # the same message twice (Sent and Inbox)
        elif key:
            by_id[key] = row["seq"]
    index = {row["seq"]: row for row in rows}
    order = sorted((r for r in rows if r["duplicate_of"] is None), key=lambda r: (r["date_ms"] or 0, r["seq"]))
    latest: dict[str, int] = {}
    for row in order:
        candidates = [row["in_reply_to"], *reversed(row["references"])]
        parent = next((by_id[c] for c in candidates if c and c in by_id and by_id[c] != row["seq"]), None)
        key = subject_key(row["subject"])
        if parent is None and key and key != (row["subject"] or "").strip().lower():
            parent = latest.get(key)
        row["parent"] = parent
        if key:
            latest[key] = row["seq"]

    root: dict[int, int] = {}

    def find(seq: int) -> int:
        while root.setdefault(seq, seq) != seq:
            root[seq] = root[root[seq]]
            seq = root[seq]
        return seq

    gmail: dict[str, int] = {}
    for row in order:
        if row["parent"] is not None:
            root[find(row["seq"])] = find(row["parent"])
        if row["gmail_thread"]:
            first = gmail.setdefault(row["gmail_thread"], row["seq"])
            root[find(row["seq"])] = find(first)
    numbers: dict[int, int] = {}
    for row in order:
        row["thread"] = numbers.setdefault(find(row["seq"]), len(numbers) + 1)
    for row in rows:
        if row["duplicate_of"] is not None:
            row["thread"] = index[row["duplicate_of"]].get("thread", 0)


def index(db: OrmSession, mailbox: Mailbox) -> int:
    """Read the stored mbox and (re)build the index of its messages."""
    path = mbox_path(mailbox.id)
    rows: list[dict[str, Any]] = []
    for seq, message in enumerate(iter_messages(path)):
        if seq >= MESSAGES_MAX:
            break
        rows.append({"seq": seq, **{k: message[k] for k in ("offset", "length", "sha256", "attachments")}})
        rows[-1].update(describe(message["headers"]))
    if not rows:
        raise MailboxError("No message found: the file is not an mbox, or it is empty.")
    thread(rows)
    db.execute(delete(MailboxMessage).where(MailboxMessage.mailbox_id == mailbox.id))
    columns = ("seq", "offset", "length", "sha256", "message_id", "parent", "thread", "duplicate_of")
    columns += ("subject", "sender", "recipients", "date_ms", "attachments")
    for start in range(0, len(rows), 1000):
        db.bulk_insert_mappings(
            MailboxMessage,
            [{"mailbox_id": mailbox.id, **{c: row[c] for c in columns}} for row in rows[start : start + 1000]],
        )
    mailbox.total = sum(1 for row in rows if row["duplicate_of"] is None)
    dates = [row["date_ms"] for row in rows if row["date_ms"]]
    mailbox.meta = {
        **(mailbox.meta or {}),
        "threads": len({row["thread"] for row in rows}),
        "from": min(dates) if dates else None,
        "to": max(dates) if dates else None,
        "attachments": sum(1 for row in rows if row["attachments"] and row["duplicate_of"] is None),
        "duplicates": sum(1 for row in rows if row["duplicate_of"] is not None),
    }
    return mailbox.total


# --------------------------------------------------------------------------- #
# What the pages show                                                         #
# --------------------------------------------------------------------------- #
def top_senders(db: OrmSession, mailbox_id: str, limit: int = 8) -> list[dict[str, Any]]:
    rows = db.execute(
        select(MailboxMessage.sender, func.count())
        .where(MailboxMessage.mailbox_id == mailbox_id, MailboxMessage.duplicate_of.is_(None))
        .group_by(MailboxMessage.sender)
        .order_by(func.count().desc())
        .limit(limit)
    ).all()
    return [{"sender": sender, "count": count} for sender, count in rows]


def imported(db: OrmSession, mailbox_id: str) -> dict[str, Mail]:
    """``sha256 -> Mail`` for the messages of the mailbox that are e-mail artifacts."""
    rows = db.scalars(
        select(Mail)
        .join(MailboxMessage, MailboxMessage.sha256 == Mail.sha256)
        .where(MailboxMessage.mailbox_id == mailbox_id)
    ).all()
    return {row.sha256: row for row in rows}


def select_messages(
    db: OrmSession,
    mailbox_id: str,
    *,
    seqs: Iterable[int] | None = None,
    date_from: int | None = None,
    date_to: int | None = None,
    sender: str = "",
    subject: str = "",
    attachments: bool = False,
    whole_threads: bool = False,
) -> list[MailboxMessage]:
    """The messages a filter names (never the second copy of a duplicate),
    with the rest of their conversations when asked, newest first."""
    query = select(MailboxMessage).where(MailboxMessage.mailbox_id == mailbox_id, MailboxMessage.duplicate_of.is_(None))
    if seqs is not None:
        query = query.where(MailboxMessage.seq.in_(list(seqs)[:5000]))
    if date_from is not None:
        query = query.where(MailboxMessage.date_ms >= date_from)
    if date_to is not None:
        query = query.where(MailboxMessage.date_ms <= date_to)
    if sender.strip():
        query = query.where(func.lower(MailboxMessage.sender).contains(sender.strip().lower(), autoescape=True))
    if subject.strip():
        query = query.where(func.lower(MailboxMessage.subject).contains(subject.strip().lower(), autoescape=True))
    if attachments:
        query = query.where(MailboxMessage.attachments.is_(True))
    rows = db.scalars(query).all()
    if whole_threads and rows:
        threads = sorted({row.thread for row in rows})
        found = {row.seq: row for row in rows}
        for start in range(0, len(threads), 500):
            for row in db.scalars(
                select(MailboxMessage).where(
                    MailboxMessage.mailbox_id == mailbox_id,
                    MailboxMessage.duplicate_of.is_(None),
                    MailboxMessage.thread.in_(threads[start : start + 500]),
                )
            ):
                found.setdefault(row.seq, row)
        rows = list(found.values())
    return sorted(rows, key=lambda row: (row.date_ms or 0, row.seq), reverse=True)


def store_size(mailbox_id: str) -> int:
    try:
        return os.path.getsize(mbox_path(mailbox_id))
    except OSError:
        return 0
