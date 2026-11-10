"""What the headers say: the route, the sender, the authentication results.

- ``hops``: the ``Received`` headers in travel order (the bottom one first),
  each with the sending and receiving host, the IP, the protocol and the
  time, the delay from the previous hop, and a flag when a clock goes back.
- ``sender``: From, Sender, Reply-To, Return-Path, Message-ID domain and
  the client, with the mismatches an analyst looks for.
- ``reported_auth``: SPF, DKIM, DMARC and ARC as the receiving servers wrote
  them in ``Authentication-Results`` (and ``ARC-Authentication-Results``,
  ``Received-SPF``). Only results written by a trusted server (Settings ->
  Mail) can be believed: anyone can put such a header in a message.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from typing import Any

_RECEIVED_FROM = re.compile(r"\bfrom\s+(\S+)(.*?)(?=\bby\b|$)", re.IGNORECASE | re.DOTALL)
_RECEIVED_BY = re.compile(r"\bby\s+(\S+)", re.IGNORECASE)
_RECEIVED_WITH = re.compile(r"\bwith\s+(\S+)", re.IGNORECASE)
_IP = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|(?:IPv6:)?[0-9a-fA-F:]*:[0-9a-fA-F:]+)\]?")


def header_values(headers: list[list[str]], name: str) -> list[str]:
    lower = name.lower()
    return [value for key, value in headers if key.lower() == lower]


def first(headers: list[list[str]], name: str) -> str:
    values = header_values(headers, name)
    return values[0] if values else ""


def _public_ip(text: str) -> str | None:
    for match in _IP.finditer(text):
        candidate = match.group(1).removeprefix("IPv6:")
        try:
            ip = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return str(ip)
    return None


def _when(text: str) -> datetime | None:
    part = text.rsplit(";", 1)[-1].strip() if ";" in text else ""
    if not part:
        return None
    try:
        moment = parsedate_to_datetime(part)
    except (TypeError, ValueError, IndexError):
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def is_private(ip: str | None) -> bool:
    if not ip:
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not address.is_global


def hops(headers: list[list[str]]) -> list[dict[str, Any]]:
    """The Received chain in travel order, with delays and clock anomalies."""
    out: list[dict[str, Any]] = []
    previous: datetime | None = None
    for raw in reversed(header_values(headers, "Received")):
        head = raw.split(";", 1)[0]
        from_match = _RECEIVED_FROM.search(head)
        by_match = _RECEIVED_BY.search(head)
        with_match = _RECEIVED_WITH.search(head)
        moment = _when(raw)
        ip = _public_ip(from_match.group(2)) if from_match else None
        hop = {
            "from": from_match.group(1) if from_match else "",
            "fromDetail": " ".join(from_match.group(2).split())[:200] if from_match else "",
            "by": by_match.group(1).rstrip(";") if by_match else "",
            "with": with_match.group(1).rstrip(";") if with_match else "",
            "ip": ip,
            "privateIp": is_private(ip) if ip else None,
            "time": int(moment.timestamp() * 1000) if moment else None,
            "delayMs": None,
            "backwards": False,
            "raw": raw,
        }
        if moment and previous:
            hop["delayMs"] = int((moment - previous).total_seconds() * 1000)
            hop["backwards"] = hop["delayMs"] < -60_000  # more than a minute: not clock jitter
        if moment:
            previous = moment
        out.append(hop)
    return out


def origin_ip(chain: list[dict[str, Any]], trusted_hosts: list[str]) -> str | None:
    """The sending server's IP: the first public IP seen by a hop, skipping
    hops added by your own servers (whose ``from`` is the previous hop)."""
    trusted = [t.lower() for t in trusted_hosts if t]
    for hop in chain:
        if hop["ip"] and not hop["privateIp"]:
            host = (hop.get("from") or "").lower()
            if any(host == t or host.endswith("." + t) for t in trusted):
                continue
            return hop["ip"]
    return None


def domain_of(address: str) -> str:
    return address.rsplit("@", 1)[-1].lower().strip(">").strip() if "@" in address else ""


def _addresses(value: str) -> list[dict[str, str]]:
    return [{"name": n, "address": a} for n, a in getaddresses([value]) if a]


def sender(headers: list[list[str]]) -> dict[str, Any]:
    from_name, from_address = parseaddr(first(headers, "From"))
    reply_to = _addresses(first(headers, "Reply-To"))
    return_path = parseaddr(first(headers, "Return-Path"))[1]
    message_id = first(headers, "Message-ID")
    message_domain = message_id.strip("<> ").rsplit("@", 1)[-1].lower() if "@" in message_id else ""
    from_domain = domain_of(from_address)
    date = first(headers, "Date")
    try:
        sent = int(parsedate_to_datetime(date).timestamp() * 1000) if date else None
    except (TypeError, ValueError, IndexError):
        sent = None
    return {
        "from": {"name": from_name, "address": from_address, "domain": from_domain},
        "sender": parseaddr(first(headers, "Sender"))[1],
        "replyTo": reply_to,
        "returnPath": return_path,
        "returnPathDomain": domain_of(return_path),
        "messageId": message_id,
        "messageIdDomain": message_domain,
        "to": _addresses(", ".join(header_values(headers, "To"))),
        "cc": _addresses(", ".join(header_values(headers, "Cc"))),
        "subject": first(headers, "Subject"),
        "date": sent,
        "client": first(headers, "X-Mailer") or first(headers, "User-Agent"),
        "originatingIp": _public_ip(first(headers, "X-Originating-IP")),
    }


# --------------------------------------------------------------------------- #
# Authentication-Results (RFC 8601)                                           #
# --------------------------------------------------------------------------- #
_RESULT = re.compile(r"\b(spf|dkim|dmarc|arc)\s*=\s*([a-z]+)([^;]*)", re.IGNORECASE)


def _parse_results(value: str) -> tuple[str, list[dict[str, str]]]:
    head, _, rest = value.partition(";")
    if _RESULT.match(head.strip()):
        # No authserv-id (Exchange Online writes "spf=pass (…); dkim=…").
        authserv, rest = "", value
    else:
        authserv = head.strip().split()[0] if head.strip() else ""
    results = []
    for match in _RESULT.finditer(rest):
        detail = " ".join(match.group(3).split())
        results.append({"method": match.group(1).lower(), "result": match.group(2).lower(), "detail": detail[:300]})
    return authserv.lower(), results


def reported_auth(headers: list[list[str]], trusted_servers: list[str]) -> dict[str, Any]:
    """The receiving servers' verdicts. ``trusted`` tells whether the header
    was written by one of your servers (Settings -> Mail)."""
    trusted = [t.lower() for t in trusted_servers if t]

    def is_trusted(host: str) -> bool:
        host = host.lower().rstrip(".")
        return bool(host) and any(host == t or host.endswith("." + t) for t in trusted)

    # A header without authserv-id is credited to the server that received
    # the message last (the topmost Received header's "by" host).
    received = header_values(headers, "Received")
    last_by = _RECEIVED_BY.search(received[0].split(";", 1)[0]) if received else None
    last_hop = last_by.group(1) if last_by else ""
    entries = []
    for name in ("Authentication-Results", "ARC-Authentication-Results"):
        for value in header_values(headers, name):
            body = re.sub(r"^\s*i=\d+;\s*", "", value) if name.startswith("ARC") else value
            authserv, results = _parse_results(body)
            entries.append(
                {
                    "header": name,
                    "authserv": authserv or last_hop,
                    "trusted": is_trusted(authserv or last_hop),
                    "results": results,
                }
            )
    for value in header_values(headers, "Received-SPF"):
        word = value.split()[0].lower() if value.split() else ""
        entries.append(
            {
                "header": "Received-SPF",
                "authserv": "",
                "trusted": False,
                "results": [{"method": "spf", "result": word, "detail": value[:300]}],
            }
        )
    # The summary prefers a trusted header, then the topmost one (added last,
    # i.e. by the server closest to the mailbox).
    summary: dict[str, dict[str, Any]] = {}
    for entry in sorted(entries, key=lambda e: not e["trusted"]):
        for result in entry["results"]:
            summary.setdefault(
                result["method"],
                {"result": result["result"], "detail": result["detail"], "trusted": entry["trusted"]},
            )
    return {"entries": entries, "summary": summary}
