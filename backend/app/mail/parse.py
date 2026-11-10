"""Read an e-mail file (``.eml`` or Outlook ``.msg``) into one plain shape.

    {format, headers: [[name, value]], subject, date, message_id,
     text, html, rtf, attachments: [{name, content_type, content_id,
     disposition, data, nested}]}

``.eml`` is RFC 5322 text, read with the standard library. ``.msg`` is an OLE
compound file of MAPI properties, read with ``olefile``: the original
Internet headers (``PR_TRANSPORT_MESSAGE_HEADERS``) when Outlook kept them,
the bodies, and the attachment storages. Outlook often stores only a
compressed RTF body (LZFu, MS-OXRTFCP), decompressed here. An attached
message (``.eml`` or an embedded ``.msg``) is parsed too, as ``nested``.
"""

from __future__ import annotations

import email
import email.policy
import io
import struct
from email.message import EmailMessage
from typing import Any

MAX_DEPTH = 3
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


class MailError(ValueError):
    """The file is not an e-mail Nik can read."""


def _decode(value: Any) -> str:
    try:
        return str(value)
    except Exception:  # noqa: BLE001 - a malformed encoded word
        return value.encode("utf-8", "replace").decode() if isinstance(value, str) else repr(value)


def _header_pairs(message) -> list[list[str]]:
    pairs = []
    for name, value in message.raw_items():
        try:
            text = str(email.policy.default.header_factory(name, value))
        except Exception:  # noqa: BLE001 - keep the raw value of a broken header
            text = str(value)
        pairs.append([name, " ".join(text.split())])
    return pairs


def _part_text(part) -> str:
    try:
        return part.get_content()
    except Exception:  # noqa: BLE001 - unknown charset: decode leniently
        payload = part.get_payload(decode=True) or b""
        return payload.decode(part.get_content_charset() or "utf-8", "replace")


def parse_eml(data: bytes, depth: int = 0) -> dict[str, Any]:
    message: EmailMessage = email.message_from_bytes(data, policy=email.policy.default)
    if not message.keys():
        raise MailError("No e-mail headers found.")
    text = html = None
    attachments = []
    for part in _leaves(message):
        ctype = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        is_body = disposition != "attachment" and not filename and ctype in ("text/plain", "text/html")
        if is_body:
            if ctype == "text/plain" and text is None:
                text = _part_text(part)
            elif ctype == "text/html" and html is None:
                html = _part_text(part)
            continue
        if ctype == "message/rfc822":
            inner = part.get_payload()
            raw = inner[0].as_bytes() if isinstance(inner, list) and inner else b""
        else:
            raw = part.get_payload(decode=True) or b""
        attachments.append(
            _attachment(filename or _default_name(ctype), ctype, part.get("Content-ID"), disposition, raw, depth)
        )
    return {
        "format": "eml",
        "headers": _header_pairs(message),
        "text": text,
        "html": html,
        "rtf": None,
        "attachments": attachments,
    }


def _leaves(message):
    """The parts of a message, not descending into attached messages (an
    attached ``message/rfc822`` is one part, parsed on its own)."""
    if message.get_content_type() == "message/rfc822" or not message.is_multipart():
        yield message
        return
    for part in message.get_payload():
        yield from _leaves(part)


def _default_name(ctype: str) -> str:
    known = {"message/rfc822": "attached-message.eml", "text/calendar": "invite.ics"}
    if ctype in known:
        return known[ctype]
    if ctype.startswith("image/"):
        return "image." + ctype.split("/", 1)[1].split("+", 1)[0]
    return "attachment"


def _attachment(name, ctype, content_id, disposition, data: bytes, depth: int) -> dict[str, Any]:
    nested = None
    lower = (name or "").lower()
    if depth < MAX_DEPTH and (ctype == "message/rfc822" or lower.endswith((".eml", ".msg"))):
        try:
            nested = parse_mail(data, depth + 1)
        except MailError:
            nested = None
    return {
        "name": name or "attachment",
        "content_type": ctype or "application/octet-stream",
        "content_id": (content_id or "").strip("<> ") or None,
        "disposition": disposition or "attachment",
        "data": data,
        "nested": nested,
    }


# --------------------------------------------------------------------------- #
# Outlook .msg                                                                #
# --------------------------------------------------------------------------- #
_RTF_PREBUF = (
    b"{\\rtf1\\ansi\\mac\\deff0\\deftab720{\\fonttbl;}{\\f0\\fnil \\froman \\fswiss \\fmodern \\fscript "
    b"\\fdecor MS Sans SerifSymbolArialTimes New RomanCourier{\\colortbl\\red0\\green0\\blue0\r\n\\par "
    b"\\pard\\plain\\f0\\fs20\\b\\i\\u\\tab\\tx"
)


def decompress_rtf(data: bytes) -> bytes:
    """LZFu (MS-OXRTFCP): Outlook's compressed RTF body."""
    if len(data) < 16:
        raise MailError("Truncated compressed RTF.")
    _comp_size, raw_size, magic, _crc = struct.unpack_from("<IIII", data)
    body = data[16:]
    if magic == 0x414C454D:  # "MELA": stored uncompressed
        return body[:raw_size]
    if magic != 0x75465A4C:  # "LZFu"
        raise MailError("Unknown compressed RTF format.")
    buffer = bytearray(4096)
    buffer[: len(_RTF_PREBUF)] = _RTF_PREBUF
    write = len(_RTF_PREBUF)
    out = bytearray()
    pos = 0
    while pos < len(body) and len(out) < raw_size:
        flags = body[pos]
        pos += 1
        for bit in range(8):
            if pos >= len(body) or len(out) >= raw_size:
                break
            if flags & (1 << bit):
                if pos + 1 >= len(body):
                    break
                token = (body[pos] << 8) | body[pos + 1]
                pos += 2
                offset, length = token >> 4, (token & 0xF) + 2
                if offset == write:  # end marker
                    return bytes(out)
                for i in range(length):
                    byte = buffer[(offset + i) % 4096]
                    out.append(byte)
                    buffer[write] = byte
                    write = (write + 1) % 4096
            else:
                byte = body[pos]
                pos += 1
                out.append(byte)
                buffer[write] = byte
                write = (write + 1) % 4096
    return bytes(out)


def _ole_value(ole, path: list[str], prop: str) -> Any:
    """A MAPI property of a storage: string (001F/001E) or binary (0102)."""
    for kind in ("001F", "001E", "0102"):
        stream = [*path, f"__substg1.0_{prop}{kind}"]
        if ole.exists(stream):
            raw = ole.openstream(stream).read()
            if kind == "001F":
                return raw.decode("utf-16-le", "replace").rstrip("\x00")
            if kind == "001E":
                return raw.decode("cp1252", "replace").rstrip("\x00")
            return raw
    return None


def _msg_from_ole(ole, root: list[str], depth: int) -> dict[str, Any]:
    transport = _ole_value(ole, root, "007D")
    headers: list[list[str]] = []
    if isinstance(transport, str) and transport.strip():
        headers = _header_pairs(email.message_from_string(transport, policy=email.policy.default))
    if not headers:
        # No Internet headers kept (a message composed or saved locally): use
        # the MAPI properties Outlook always has.
        for name, prop in (("Subject", "0037"), ("From", "0C1F"), ("To", "0E04"), ("Cc", "0E03")):
            value = _ole_value(ole, root, prop)
            if isinstance(value, str) and value:
                headers.append([name, value])
        sender_name = _ole_value(ole, root, "0C1A")
        sender = _ole_value(ole, root, "5D01") or _ole_value(ole, root, "0C1F")
        if sender:
            headers = [h for h in headers if h[0] != "From"] + [
                ["From", f"{sender_name} <{sender}>" if sender_name else sender]
            ]
    text = _ole_value(ole, root, "1000")
    html = _ole_value(ole, root, "1013")
    if isinstance(html, bytes):
        html = html.decode("utf-8", "replace")
    rtf = None
    compressed = _ole_value(ole, root, "1009")
    if isinstance(compressed, bytes):
        try:
            rtf = decompress_rtf(compressed).decode("cp1252", "replace")
        except MailError:
            rtf = None

    attachments = []
    for entry in sorted({tuple(e[: len(root) + 1]) for e in ole.listdir(streams=True, storages=True)}):
        name = entry[len(root)] if len(entry) > len(root) else ""
        if list(entry[: len(root)]) != root or not name.startswith("__attach_version1.0_"):
            continue
        path = [*root, name]
        filename = _ole_value(ole, path, "3707") or _ole_value(ole, path, "3704") or "attachment"
        mime = _ole_value(ole, path, "370E")
        cid = _ole_value(ole, path, "3712")
        embedded = [*path, "__substg1.0_3701000D"]
        if ole.exists(embedded):
            nested = _msg_from_ole(ole, embedded, depth + 1) if depth < MAX_DEPTH else None
            attachments.append(
                {
                    "name": filename
                    if isinstance(filename, str) and filename != "attachment"
                    else "attached-message.msg",
                    "content_type": "application/vnd.ms-outlook",
                    "content_id": None,
                    "disposition": "attachment",
                    "data": b"",
                    "nested": nested,
                }
            )
            continue
        data = _ole_value(ole, path, "3701")
        attachments.append(
            _attachment(
                filename if isinstance(filename, str) else "attachment",
                mime if isinstance(mime, str) else "application/octet-stream",
                cid if isinstance(cid, str) else None,
                "inline" if cid else "attachment",
                data if isinstance(data, bytes) else b"",
                depth,
            )
        )
    return {
        "format": "msg",
        "headers": headers,
        "text": text if isinstance(text, str) else None,
        "html": html if isinstance(html, str) else None,
        "rtf": rtf,
        "attachments": attachments,
    }


def parse_msg(data: bytes, depth: int = 0) -> dict[str, Any]:
    import olefile

    try:
        ole = olefile.OleFileIO(io.BytesIO(data))
    except Exception as exc:  # noqa: BLE001 - olefile raises OSError, ValueError, struct.error…
        raise MailError(f"Not an Outlook message: {exc}") from exc
    with ole:
        if not ole.exists("__properties_version1.0"):
            raise MailError("An OLE file, but not an Outlook message.")
        try:
            return _msg_from_ole(ole, [], depth)
        except MailError:
            raise
        except Exception as exc:  # noqa: BLE001 - a damaged compound file
            raise MailError(f"The Outlook message is damaged: {exc}") from exc


def parse_mail(data: bytes, depth: int = 0) -> dict[str, Any]:
    """``.msg`` when the file is OLE, else RFC 5322."""
    if not data:
        raise MailError("The file is empty.")
    if data[:8] == OLE_MAGIC:
        return parse_msg(data, depth)
    head = data[:2048].lstrip()
    if b":" not in head.split(b"\n", 1)[0]:
        raise MailError("Not an e-mail: the file does not start with headers.")
    return parse_eml(data, depth)


def rtf_to_text(rtf: str) -> str:
    """A rough plain-text view of an RTF body (control words dropped)."""
    import re

    text = re.sub(r"\\par[d]?\b", "\n", rtf)
    text = re.sub(r"\{\\\*[^{}]*\}", "", text)
    text = re.sub(r"\\'([0-9a-fA-F]{2})", lambda m: bytes.fromhex(m.group(1)).decode("cp1252", "replace"), text)
    text = re.sub(r"\\[a-zA-Z]+-?\d* ?", "", text)
    text = text.replace("{", "").replace("}", "")
    return re.sub(r"\n{3,}", "\n\n", text).strip()
