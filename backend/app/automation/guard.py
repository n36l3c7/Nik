"""The data guard: what a playbook may send out, decided on classes of data.

Every value that is about to leave Nik (the URL, headers and body of a
request, the arguments of a connector command, the text and the recipients of
an e-mail) has **classes**. They come from two places:

1. **Where the value came from.** The fields of a trigger's payload are
   tagged (payloads.py), and the tags travel through ``{{ }}`` rendering,
   filters and scripts (expressions.py): a text built from a sender's address
   is an e-mail address, whatever was done to it.
2. **What it looks like**, as a second net: the final payload is scanned for
   e-mail addresses, private addresses, names under the organisation's own
   domains and allowlisted indicators. The scan can only add classes.

Some classes always leave (a hash, a public indicator, a verdict, an id of
Nik). Every other is **held** unless an admin opened it for the playbook,
behind a warning and a double check. A held value fails the step with a
sentence that says what was held; a node can instead ask to send without it.
Nothing is allowed by default.

The rule of the threat-intelligence look-ups (never send private, allowlisted
or TLP:RED values to the sources) is separate and unchanged: it lives in
``enrichment/`` and no setting here loosens it. A look-up a playbook makes
(``nik.reputation``) passes both: that rule first, then this guard, once for
all the sources. A reputation command a playbook runs as a node of its own is
judged by this guard alone, like any other command.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

# Classes ---------------------------------------------------------------------
ALWAYS = frozenset({"hash", "public_indicator", "verdict", "nik_id"})

# The classes an admin can open, in the order they are shown, with what the double check says.
# ``sensitive`` ones are not offered beside the others. Three of them are whole messages and whole
# files (``apart``): the screen of a playbook offers those apart, to an admin, under a warning of
# their own, because forwarding a message, with or without what is attached to it, needs them.
# TLP:RED data it never offers.
CLASSES: dict[str, dict[str, Any]] = {
    "incident_text": {
        "label": "Incident names and tickets",
        "warning": "The names and ticket numbers of incidents, which often name a host or a person.",
        "sensitive": False,
    },
    "email_address": {
        "label": "E-mail addresses",
        "warning": "Senders and recipients: people of your organisation and those who wrote to them.",
        "sensitive": False,
    },
    "subject": {
        "label": "E-mail subjects",
        "warning": "The subject lines of analysed e-mails.",
        "sensitive": False,
    },
    "private_value": {
        "label": "Internal names and addresses",
        "warning": "Host names, user names, private addresses and names under your own domains.",
        "sensitive": False,
    },
    "allowlisted": {
        "label": "Allowlisted indicators",
        "warning": "Indicators your team marked as known and good: usually your own infrastructure.",
        "sensitive": False,
    },
    "attachment_name": {
        "label": "File and attachment names",
        "warning": "The names of files and attachments, which can hold a person's or a customer's name.",
        "sensitive": False,
    },
    "script_output": {
        "label": "Results of scripts",
        "warning": "What scripts computed from data that had no class of its own.",
        "sensitive": False,
    },
    "mail_body": {
        "label": "E-mail bodies",
        "warning": "The text of e-mails leaves Nik, whatever was written: needed by a playbook that forwards mail.",
        "sensitive": True,
        "apart": True,
    },
    "attachment": {
        "label": "Attachments",
        "warning": "The files attached to e-mails, as they are: documents, images, archives.",
        "sensitive": True,
        "apart": True,
    },
    "sample": {
        "label": "Samples",
        "warning": "Files held as evidence, live malware among them. Whoever receives one receives malware.",
        "sensitive": True,
        "apart": True,
    },
    "tlp_red": {
        "label": "TLP:RED data",
        "warning": "What was marked not to leave the people it was shared with.",
        "sensitive": True,
    },
}
SENSITIVE = frozenset(name for name, meta in CLASSES.items() if meta["sensitive"])

_EMAIL = re.compile(r"[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,24}")
_IPV4 = re.compile(r"(?<![0-9.])(?:\d{1,3}\.){3}\d{1,3}(?![0-9.])")
_HOSTNAME = re.compile(
    r"(?<![A-Za-z0-9-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24}(?![A-Za-z0-9-])"
)
SCAN_LIMIT = 1_000_000
# Addresses that say something of the inside of a network (not the ranges reserved for documentation).
_PRIVATE = tuple(
    ipaddress.ip_network(net)
    for net in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10")
)


@dataclass(frozen=True)
class Context:
    """What the scan needs to know of the organisation: its own domains, its allowlist."""

    internal_domains: frozenset = frozenset()
    allowlisted: Any = None  # a callable (type, value) -> bool, or None

    def is_internal(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        return any(host == domain or host.endswith("." + domain) for domain in self.internal_domains)


@dataclass
class Decision:
    """What the guard says of a payload."""

    classes: frozenset  # everything the payload holds
    held: frozenset  # what may not leave
    counts: dict[str, int] = field(default_factory=dict)  # how many values of each scanned class were found

    @property
    def allowed(self) -> bool:
        return not self.held

    def sentence(self) -> str:
        """What was held back, for the step: fixed words, no value."""
        order = list(CLASSES)
        parts = []
        for name in sorted(self.held, key=lambda held: (order.index(held) if held in order else len(order), held)):
            label = CLASSES.get(name, {}).get("label", name).lower()
            count = self.counts.get(name)
            parts.append(f"{count} × {label}" if count else label)
        return "Held back: " + ", ".join(parts) + ". This playbook may not send them: an admin can open them for it"

    def as_dict(self) -> dict:
        return {"classes": sorted(self.classes), "held": sorted(self.held), "counts": dict(self.counts)}


def _strings(value: Any, budget: list[int]):
    if budget[0] <= 0:
        return
    if isinstance(value, str):
        budget[0] -= len(value)
        yield value[: max(0, budget[0] + len(value))]
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(str(key), budget)
            yield from _strings(item, budget)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _strings(item, budget)


def scan(payload: Any, context: Context) -> dict[str, int]:
    """The classes the content of a payload shows, with how many values of each."""
    found: dict[str, int] = {}

    def add(name: str, count: int = 1) -> None:
        found[name] = found.get(name, 0) + count

    for text in _strings(payload, [SCAN_LIMIT]):
        emails = _EMAIL.findall(text)
        if emails:
            add("email_address", len(emails))
        for match in _IPV4.findall(text):
            try:
                address = ipaddress.ip_address(match)
            except ValueError:
                continue
            if any(address in network for network in _PRIVATE):
                add("private_value")
            elif context.allowlisted and context.allowlisted("ip", match):
                add("allowlisted")
        for host in _HOSTNAME.findall(text):
            if context.is_internal(host):
                add("private_value")
            elif context.allowlisted and context.allowlisted("domain", host.lower()):
                add("allowlisted")
    return found


def check(payload: Any, classes: frozenset, opened: frozenset | set | list, context: Context) -> Decision:
    """Decide on a payload: its classes (from where it came, plus the scan) against what the playbook opened."""
    scanned = scan(payload, context)
    held_classes = frozenset(classes) | frozenset(scanned)
    allowed = ALWAYS | frozenset(opened or ())
    return Decision(classes=held_classes, held=held_classes - allowed, counts=scanned)


def drop(payload: Any, context: Context, opened: frozenset | set | list) -> Any:
    """The payload without what the scan finds and the playbook may not send: a
    held value becomes null, an item of a list that holds one is left out."""
    allowed = ALWAYS | frozenset(opened or ())

    def clean(value: Any) -> tuple[Any, bool]:
        if isinstance(value, dict):
            return {
                key: (None if not ok else item) for key, (item, ok) in ((k, clean(v)) for k, v in value.items())
            }, True
        if isinstance(value, (list, tuple)):
            return [item for item, ok in (clean(item) for item in value) if ok], True
        if isinstance(value, str) and set(scan(value, context)) - allowed:
            return None, False
        return value, True

    cleaned, ok = clean(payload)
    return cleaned if ok else None


def context_from(db) -> Context:
    """The organisation's own domains and allowlist, from the shared settings."""
    from ..iocs import Allowlist
    from ..routers.settings import read_settings

    shared = read_settings(db)
    mail = shared.get("mail") or {}
    domains = frozenset(str(d).lower().strip(".") for d in (mail.get("orgDomains") or []) if str(d).strip("."))
    allowlist = Allowlist(shared.get("iocAllowlist") or [])
    return Context(internal_domains=domains, allowlisted=allowlist.matches)
