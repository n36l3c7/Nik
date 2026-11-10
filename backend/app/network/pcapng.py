"""A pcapng file rebuilt from the isolated browser's network log.

The browser sees every request and response in clear (HTTPS already
decrypted), so its log can be written as HTTP/1.1 over TCP that Wireshark
dissects like captured traffic: a DNS answer per host, a TCP handshake, the
request, the response and a FIN per exchange. The section header says the
file is a reconstruction; it is not what crossed the wire (no TLS, no
HTTP/2 framing, timings from the browser).

``build(entries)`` takes the log entries (``nik_browser`` format) and returns
the file. Standard library only.
"""

from __future__ import annotations

import base64
import ipaddress
import struct
from typing import Any, Iterable
from urllib.parse import urlsplit

CLIENT_IP = "10.13.37.2"
RESOLVER_IP = "10.13.37.1"
CLIENT_MAC = bytes.fromhex("020000000002")
GATEWAY_MAC = bytes.fromhex("020000000001")
MSS = 1400
SECTION_COMMENT = (
    "Reconstructed by Nik from the isolated browser's network log: HTTP shown in clear "
    "(HTTPS decrypted by the browser), not captured on the wire."
)
_DROP_HEADERS = {"content-encoding", "transfer-encoding", "content-length", "connection", "keep-alive"}


# --------------------------------------------------------------------------- #
# Low-level writers                                                           #
# --------------------------------------------------------------------------- #
def _option(code: int, value: bytes) -> bytes:
    padding = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\0" * padding


def _block(block_type: int, body: bytes) -> bytes:
    length = 12 + len(body)
    return struct.pack("<II", block_type, length) + body + struct.pack("<I", length)


def section_header(comment: str = SECTION_COMMENT) -> bytes:
    options = _option(1, comment.encode()) + _option(4, b"Nik") + struct.pack("<HH", 0, 0)
    return _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + options)


def interface_description() -> bytes:
    # Ethernet, no snap length; timestamps in microseconds (the default).
    return _block(0x00000001, struct.pack("<HHI", 1, 0, 0))


def enhanced_packet(time_us: int, frame: bytes, comment: str | None = None) -> bytes:
    body = struct.pack("<IIIII", 0, time_us >> 32, time_us & 0xFFFFFFFF, len(frame), len(frame))
    body += frame + b"\0" * ((-len(frame)) % 4)
    if comment:
        body += _option(1, comment.encode()[:4000]) + struct.pack("<HH", 0, 0)
    return _block(0x00000006, body)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip(src: str, dst: str, protocol: int, payload: bytes) -> bytes:
    """An Ethernet frame with an IPv4 or IPv6 packet around ``payload``."""
    source, destination = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if source.version == 6 or destination.version == 6:
        source = ipaddress.IPv6Address(source) if source.version == 6 else ipaddress.IPv6Address(f"::ffff:{source}")
        destination = destination if destination.version == 6 else ipaddress.IPv6Address(f"::ffff:{destination}")
        header = struct.pack("!IHBB", 6 << 28, len(payload), protocol, 64) + source.packed + destination.packed
        return GATEWAY_MAC + CLIENT_MAC + b"\x86\xdd" + header + payload
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0x4000, 64, protocol, 0, source.packed, destination.packed
    )
    header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
    return GATEWAY_MAC + CLIENT_MAC + b"\x08\x00" + header + payload


def _tcp(src: str, dst: str, sport: int, dport: int, seq: int, ack: int, flags: int, data: bytes = b"") -> bytes:
    segment = struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0)
    return _ip(src, dst, 6, segment + data)


def _udp(src: str, dst: str, sport: int, dport: int, data: bytes) -> bytes:
    return _ip(src, dst, 17, struct.pack("!HHHH", sport, dport, 8 + len(data), 0) + data)


def _dns_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("idna") if not label.isascii() else label.encode()
        out += bytes([len(raw[:63])]) + raw[:63]
    return out + b"\0"


def dns_exchange(transaction: int, host: str, address: str) -> tuple[bytes, bytes]:
    """A DNS query for ``host`` and its answer with ``address``."""
    ipv6 = ipaddress.ip_address(address).version == 6
    qtype = 28 if ipv6 else 1
    question = _dns_name(host) + struct.pack("!HH", qtype, 1)
    query = struct.pack("!HHHHHH", transaction, 0x0100, 1, 0, 0, 0) + question
    answer = (
        struct.pack("!HHHHHH", transaction, 0x8180, 1, 1, 0, 0)
        + question
        + b"\xc0\x0c"
        + struct.pack("!HHIH", qtype, 1, 60, 16 if ipv6 else 4)
        + ipaddress.ip_address(address).packed
    )
    return query, answer


# --------------------------------------------------------------------------- #
# HTTP reconstruction                                                         #
# --------------------------------------------------------------------------- #
def _body(part: dict[str, Any] | None) -> bytes:
    if not part or not part.get("body"):
        return b""
    try:
        return base64.b64decode(part["body"])
    except (ValueError, TypeError):
        return b""


def _headers(pairs: Iterable[Any], body: bytes, note: str | None) -> bytes:
    lines = []
    for pair in pairs or []:
        name, value = str(pair[0]), str(pair[1])
        if name.startswith(":") or name.lower() in _DROP_HEADERS:
            continue
        lines.append(f"{name}: {value}".replace("\r", " ").replace("\n", " "))
    if body:
        lines.append(f"Content-Length: {len(body)}")
    if note:
        lines.append(f"X-Nik-Note: {note}")
    return ("\r\n".join(lines) + "\r\n\r\n").encode("utf-8", "replace")


def http_request(entry: dict[str, Any]) -> bytes:
    parts = urlsplit(entry["url"])
    target = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    request = entry.get("request") or {}
    body = _body(request)
    pairs = list(request.get("headers") or [])
    if not any(str(p[0]).lower() == "host" for p in pairs):
        pairs.insert(0, ["Host", parts.netloc])
    note = "request body not kept (over the size limit)" if request.get("bodyTruncated") else None
    return f"{entry['method']} {target} HTTP/1.1\r\n".encode() + _headers(pairs, body, note) + body


def http_response(entry: dict[str, Any]) -> bytes:
    response = entry.get("response") or {}
    body = _body(response)
    note = "response body not kept (over the size limit)" if response.get("bodyTruncated") else None
    status = int(response.get("status") or 0)
    reason = str(response.get("statusText") or "").replace("\r", " ").replace("\n", " ")
    return f"HTTP/1.1 {status} {reason}\r\n".encode() + _headers(response.get("headers"), body, note) + body


# --------------------------------------------------------------------------- #
# The file                                                                    #
# --------------------------------------------------------------------------- #
def _synthetic_ip(host: str, known: dict[str, str]) -> str:
    """A stable documentation-range address for a host whose real address is unknown."""
    if host not in known:
        index = len([v for v in known.values() if v.startswith("198.18.")]) + 1
        known[host] = f"198.18.{index // 250}.{index % 250 + 1}"
    return known[host]


def _comment(entry: dict[str, Any]) -> str:
    state = entry.get("state")
    text = f"{entry['method']} {entry['url']}"
    if entry["url"].lower().startswith("https://"):
        text += " (HTTPS, shown decrypted)"
    if state == "held":
        text += " | HELD by Nik: never sent"
    elif state == "blocked":
        text += f" | BLOCKED by Nik: {entry.get('reason') or 'not sent'}"
    elif state == "failed":
        text += f" | failed: {entry.get('error') or ''}"
    return text[:4000]


def _emit(out: list[bytes], now: int, frame: bytes, comment: str | None = None, at: int | None = None) -> None:
    out.append(enhanced_packet(at if at is not None else now, frame, comment))


def build(entries: Iterable[dict[str, Any]]) -> bytes:
    """The pcapng of the HTTP(S) entries of a browser session (other schemes are left out)."""
    out = [section_header(), interface_description()]
    addresses: dict[str, str] = {}
    resolved: set[str] = set()
    port, transaction = 49152, 0
    for entry in sorted(entries, key=lambda e: e.get("startedAt") or 0):
        parts = urlsplit(entry.get("url") or "")
        if parts.scheme not in ("http", "https") or not parts.hostname:
            continue
        host = parts.hostname.lower()
        response = entry.get("response") or {}
        server = response.get("serverIp") or addresses.get(host)
        try:
            ipaddress.ip_address(server or "")
        except ValueError:
            server = _synthetic_ip(host, addresses)
        addresses.setdefault(host, server)
        start = int((entry.get("startedAt") or 0) * 1000)
        timing = entry.get("timing") or {}
        t = start
        sent = entry.get("state") in ("done", "failed")

        if sent and host not in resolved:
            try:
                ipaddress.ip_address(host)
            except ValueError:
                transaction = (transaction + 1) & 0xFFFF
                query, answer = dns_exchange(transaction, host, server)
                _emit(out, t, _udp(CLIENT_IP, RESOLVER_IP, 53000 + transaction % 1000, 53, query), at=t)
                _emit(out, t, _udp(RESOLVER_IP, CLIENT_IP, 53, 53000 + transaction % 1000, answer), at=t + 1)
            resolved.add(host)
        port = port + 1 if port < 65000 else 49152
        client, server_port = port, 80
        seq, ack = 1000, 5000
        _emit(out, t, _tcp(CLIENT_IP, server, client, server_port, seq, 0, 0x02), at=t + 2)
        _emit(out, t, _tcp(server, CLIENT_IP, server_port, client, ack, seq + 1, 0x12), at=t + 3)
        seq, ack = seq + 1, ack + 1
        _emit(out, t, _tcp(CLIENT_IP, server, client, server_port, seq, ack, 0x10), at=t + 4)
        request = http_request(entry)
        t = start + 5
        for index in range(0, len(request), MSS):
            chunk = request[index : index + MSS]
            _emit(
                out,
                t,
                _tcp(CLIENT_IP, server, client, server_port, seq, ack, 0x18, chunk),
                _comment(entry) if index == 0 else None,
            )
            seq += len(chunk)
            t += 1
        if response and response.get("status"):
            wait = timing.get("responseStart")
            t = max(t, start + int(wait * 1000)) if isinstance(wait, (int, float)) and wait > 0 else t + 1
            reply = http_response(entry)
            for index in range(0, len(reply), MSS):
                chunk = reply[index : index + MSS]
                _emit(out, t, _tcp(server, CLIENT_IP, server_port, client, ack, seq, 0x18, chunk))
                ack += len(chunk)
                t += 1
            _emit(out, t, _tcp(CLIENT_IP, server, client, server_port, seq, ack, 0x11))
            _emit(out, t, _tcp(server, CLIENT_IP, server_port, client, ack, seq + 1, 0x11), at=t + 1)
        else:
            _emit(out, t, _tcp(CLIENT_IP, server, client, server_port, seq, ack, 0x14))
    return b"".join(out)
