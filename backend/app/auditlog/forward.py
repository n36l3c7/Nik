"""Sending the audit log to a syslog receiver, as it is written.

**Who sends.** Not the API process: the backend has no way out of its
networks. As for the copies of the backups, the API process prepares and the
automation worker sends. Here there is nothing to prepare: the audit table
is the queue. The worker keeps a cursor, the number of the last entry the
receiver took, and sends what comes after it, in the order of the chain.
``audit.record`` never waits for it and never knows it exists.

**Two rows of settings, one writer each.** Row 40 is what an administrator
set (``write``, the API process). Row 41 is how things stand (the cursor,
the last error, the settings that are in force), written by the sender
alone. So neither overwrites the other.

**In order, at least once.** Entries leave by batches over one connection.
TCP and TLS give the sender no acknowledgement, so a batch counts as arrived
only when the connection is still up at the next pass, a second later; if
the receiver went away in between, the batch is sent again from the cursor
on a new connection. The receiver can therefore see an entry twice (the
number tells), never an entry before the one it follows. Over UDP a
datagram counts as sent when it left: nothing more can be known.

**A receiver that is down** makes a backlog: the cursor stays, the entries
stay in the table, and the sender tries again after 2, 4, 8 … 60 seconds.
The backlog is bounded only by the table. It is shown on the screen, the
health page tells the administrators when it lasts and when it drained, and
it is sent in order when the receiver is back. While forwarding is on,
nothing removes an entry that was not sent (``chain.trim``).

**The last word.** Changing the settings is itself an audit entry, and the
sender keeps the settings it had until the receiver it had took that entry:
turning the forwarding off, or pointing it elsewhere, is the last thing the
old receiver hears. If that receiver does not take it within
``LAST_WORD_SECONDS``, the change takes effect anyway (otherwise a dead
receiver could never be replaced) and an entry says that it went unheard.

**A log that changed under the sender.** The sender remembers the hash of
the last entry the receiver took, and of a few before it. When the table no
longer holds that entry as it was sent (somebody removed or rewrote entries
that had already left), it says so with an entry (``audit.forward.diverged``)
and sends again from the last entry that is still what the receiver got: the
receiver then holds both what the log said and what it says now, and the
same number twice with different content is what ``verifier.py`` reports.
The highest entry ever taken by the receiver (``sentHead``) is kept apart and
never moved back: the verification of the chain holds the log against it.

**Checkpoints.** Every few minutes (``checkpointMinutes``) a message with
the head of the chain and the number of entries is sent, whether anything
happened or not: a receiver that hears nothing knows the line is cut, and
always holds a recent head to check the log against.

**A new receiver** starts from the first entry of the log, or, when the
settings say ``startFrom: now``, from the entry that records the change.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import ssl
import time
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core import audit, vault
from ..core.models import AuditEntry, Setting
from . import syslog, transport
from .transport import TransportError
from .verifier import ZERO

logger = logging.getLogger("nik.audit")

SETTINGS_ID = 40
STATE_ID = 41
TEST_ID = 43
LEASE = "audit-forward"
ACTOR = "nik"
BATCH = 500
ROUNDS = 10  # batches in one pass over TCP and TLS: five thousand entries a second at most
UDP_PER_PASS = 200  # datagrams in one pass: a receiver on UDP is not flooded
LAST_WORD_SECONDS = 30
TEST_ANSWER_WITHIN = 45
TRAIL_KEPT = 20  # how many of the last confirmed batches the sender remembers the end of
RETRY_MAX = 60
PROTOCOLS = ("tls", "tcp", "udp")
DEFAULT_PORTS = {"tls": 6514, "tcp": 514, "udp": 514}

DEFAULTS: dict[str, Any] = {
    "enabled": False,
    "host": "",
    "port": 6514,
    "protocol": "tls",
    "ca": "",
    "verifyName": True,
    "clientCert": "",
    "clientKey": "",
    "facility": 13,
    "severity": 5,
    "appName": "nik",
    "hostname": "nik",
    "checkpointMinutes": 5,
    "startFrom": "beginning",
    "maxDatagram": 2048,
}
_HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.:-]{0,251}[A-Za-z0-9])?$")
_NAME = re.compile(r"^[\x21-\x7e]+$")
_T = AuditEntry.__table__

# What this process holds between two passes: the connection, and what it sent that is not confirmed.
_connection: transport.Connection | None = None
_connection_key = ""
_unconfirmed: tuple[int, str, int] | None = None  # number, hash, how many messages
_fails = 0
_retry_at = 0.0


class ConfigError(ValueError):
    """What was sent cannot be kept: a sentence for the person who sent it."""


# --------------------------------------------------------------------------- #
# What an administrator sets                                                  #
# --------------------------------------------------------------------------- #
def _doc(db: OrmSession, row_id: int) -> dict[str, Any]:
    row = db.get(Setting, row_id)
    return dict((row.doc if row else None) or {})


def _keep(db: OrmSession, row_id: int, doc: dict[str, Any]) -> None:
    row = db.get(Setting, row_id)
    if row is None:
        db.add(Setting(id=row_id, doc=doc))
        return
    row.doc = doc
    flag_modified(row, "doc")


def read(db: OrmSession) -> dict[str, Any]:
    """The settings as kept, with the defaults where nothing was set."""
    return {**DEFAULTS, **(_doc(db, SETTINGS_ID).get("settings") or {})}


def ready(settings: dict[str, Any]) -> bool:
    return bool(settings.get("host")) and settings.get("protocol") in PROTOCOLS and bool(settings.get("port"))


def destination(settings: dict[str, Any]) -> str:
    """The receiver as it is named everywhere: ``tls://siem.example:6514``."""
    return f"{settings.get('protocol')}://{settings.get('host')}:{settings.get('port')}" if ready(settings) else ""


def _whole(value: Any, low: int, high: int, what: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{what} is a whole number from {low} to {high}")
    return value


def _level(value: Any, names: dict[str, int], what: str) -> int:
    if isinstance(value, str) and value.strip().lower() in names:
        return names[value.strip().lower()]
    return _whole(value, 0, max(names.values()), what)


def _pem(value: Any, what: str) -> str:
    if value is None or value == "":
        return ""
    if not isinstance(value, str) or len(value) > 200_000 or "-----BEGIN CERTIFICATE-----" not in value:
        raise ConfigError(f"{what} is one or more certificates in PEM (-----BEGIN CERTIFICATE-----)")
    text = value.replace("\r\n", "\n").strip() + "\n"
    try:
        ssl.create_default_context(cadata=text)
    except (ssl.SSLError, ValueError):
        raise ConfigError(f"{what} cannot be read as certificates in PEM") from None
    return text


def _clean_key(db: OrmSession, sent: Any, before: str) -> str:
    """The key of the client certificate as it is kept: the name of a stored credential, as
    written; a key pasted, encrypted; nothing sent, what was there."""
    from ..automation import credentials

    if sent is None:
        return before
    if not isinstance(sent, str) or len(sent) > 20_000:
        raise ConfigError("The key of the client certificate is not readable")
    if not sent.strip():
        return ""
    found = credentials.reference(sent)
    if found is not None:
        row = credentials.by_name(db, found.name)
        if row is None:
            raise ConfigError(f"There is no stored credential named {found.name}")
        if row.kind == "pair" or found.part:
            raise ConfigError(
                "The key of the client certificate is a credential of one value: {{ credentials.<name> }}"
            )
        return found.text
    if credentials.mentions(sent):
        raise ConfigError(credentials.HOW)
    if "PRIVATE KEY-----" not in sent:
        raise ConfigError(
            "The key of the client certificate is a private key in PEM, or the name of a stored credential"
        )
    return "vault:" + vault.encrypt(sent.replace("\r\n", "\n").strip() + "\n")


def client_key(db: OrmSession, settings: dict[str, Any]) -> str:
    """The key of the client certificate, in clear, at the moment it is used."""
    from ..automation import credentials

    kept = str(settings.get("clientKey") or "")
    if not kept:
        return ""
    if kept.startswith("vault:"):
        value = vault.decrypt(kept[len("vault:") :])
        if value is None:
            raise TransportError("The key of the client certificate cannot be read any more: enter it again")
        return value
    found = credentials.reference(kept)
    row = credentials.by_name(db, found.name) if found is not None else None
    value = vault.decrypt(row.secret) if row is not None and row.secret else None
    if value is None:
        raise TransportError("The stored credential that holds the key of the client certificate is not there")
    return value


def rekey(row_id: int) -> bool:
    """After ``SECRET_KEY`` was changed (``SECRET_KEY_PREVIOUS`` holds the old one for a start):
    put the key of the client certificate a row keeps under the new key. Each process does it for
    the row it writes: the API process for the settings, the sender for the settings in force.
    Says whether something was rewritten."""
    from ..core.config import settings as app_settings
    from ..core.db import SessionLocal

    if not app_settings.SECRET_KEY_PREVIOUS:
        return False
    with SessionLocal() as db:
        doc = _doc(db, row_id)
        name = "settings" if row_id == SETTINGS_ID else "active"
        held = doc.get(name) if isinstance(doc.get(name), dict) else {}
        kept = str(held.get("clientKey") or "")
        value = vault.decrypt(kept[len("vault:") :]) if kept.startswith("vault:") else None
        if value is None:
            return False
        _keep(db, row_id, {**doc, name: {**held, "clientKey": "vault:" + vault.encrypt(value)}})
        db.commit()
    return True


def clean(db: OrmSession, sent: Any, before: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(sent, dict):
        raise ConfigError("The settings are not readable")
    unknown = set(sent) - set(DEFAULTS)
    if unknown:
        raise ConfigError(f"Not a setting of the forwarding: {', '.join(sorted(unknown))}")
    merged = {**before, **{key: value for key, value in sent.items() if key != "clientKey"}}
    protocol = merged.get("protocol")
    if protocol not in PROTOCOLS:
        raise ConfigError("The audit log is sent over tls, tcp or udp")
    if not isinstance(merged.get("enabled"), bool):
        raise ConfigError("Forwarding is on or off")
    host = str(merged.get("host") or "").strip().lower()
    if host and not _HOST.match(host):
        raise ConfigError("The receiver is a host name or an address")
    if merged["enabled"] and not host:
        raise ConfigError("Name the receiver before turning the forwarding on")
    if (
        "port" not in sent
        and sent.get("protocol")
        and sent["protocol"] != before.get("protocol")
        and not before.get("host")
    ):
        merged["port"] = DEFAULT_PORTS[protocol]
    start = merged.get("startFrom")
    if start not in ("beginning", "now"):
        raise ConfigError("A new receiver gets the log from its beginning, or from now")
    if not isinstance(merged.get("verifyName"), bool):
        raise ConfigError("Checking the name in the certificate is yes or no")
    names = {}
    for key, limit, what in (("appName", 48, "The application name"), ("hostname", 255, "The host name")):
        value = str(merged.get(key) or "").strip()
        if not value or len(value) > limit or not _NAME.match(value):
            raise ConfigError(f"{what} is 1 to {limit} printable ASCII characters without a space")
        names[key] = value
    certificate = _pem(merged.get("clientCert"), "The client certificate") if protocol == "tls" else ""
    key = _clean_key(db, sent.get("clientKey"), str(before.get("clientKey") or "")) if certificate else ""
    if certificate and not key:
        raise ConfigError("A client certificate needs its key: paste it, or name a stored credential")
    return {
        "enabled": merged["enabled"],
        "host": host,
        "port": _whole(merged.get("port"), 1, 65535, "The port of the receiver"),
        "protocol": protocol,
        "ca": _pem(merged.get("ca"), "The CA or certificate of the receiver") if protocol == "tls" else "",
        "verifyName": merged["verifyName"],
        "clientCert": certificate,
        "clientKey": key,
        "facility": _level(merged.get("facility"), syslog.FACILITIES, "The facility"),
        "severity": _level(merged.get("severity"), syslog.SEVERITIES, "The severity"),
        **names,
        "checkpointMinutes": _whole(merged.get("checkpointMinutes"), 1, 1440, "The minutes between two checkpoints"),
        "startFrom": start,
        "maxDatagram": _whole(merged.get("maxDatagram"), 480, 65000, "The largest datagram, in bytes,"),
    }


_WORDS = {
    "enabled": "on or off",
    "host": "the receiver",
    "port": "the port",
    "protocol": "the protocol",
    "ca": "the CA or certificate of the receiver",
    "verifyName": "the check of the name in the certificate",
    "clientCert": "the client certificate",
    "clientKey": "the key of the client certificate",
    "facility": "the facility",
    "severity": "the severity",
    "appName": "the application name",
    "hostname": "the host name",
    "checkpointMinutes": "the time between checkpoints",
    "startFrom": "where a new receiver starts",
    "maxDatagram": "the largest datagram",
}


def write(db: OrmSession, sent: dict[str, Any], actor: str, now: float | None = None) -> list[str]:
    """Keep what was sent (the keys that are there) and record it (the caller commits).
    Returns what changed, in words. The change takes effect once the receiver that was set
    heard of it (the module docstring says how)."""
    before = read(db)
    after = clean(db, sent, before)
    changed = [_WORDS[key] for key in DEFAULTS if after[key] != before[key]]
    if not changed:
        return []
    was, will = destination(before) if before["enabled"] else "", destination(after) if after["enabled"] else ""
    if was and not will:
        sentence = f"Turned off the forwarding of the audit log to {was}"
    elif will and not was:
        sentence = f"Turned on the forwarding of the audit log to {will}"
    elif was != will:
        sentence = f"Pointed the forwarding of the audit log from {was} to {will}"
    else:
        sentence = "Changed the forwarding of the audit log"
    entry = audit.record(
        db, actor, "audit.forward.settings", f"{sentence}: {', '.join(changed)}", target="audit log forwarding"
    )
    doc = _doc(db, SETTINGS_ID)
    _keep(
        db,
        SETTINGS_ID,
        {
            "settings": after,
            "version": int(doc.get("version") or 0) + 1,
            "changeEntry": entry.id,
            "changedAt": time.time() if now is None else now,
        },
    )
    return changed


# --------------------------------------------------------------------------- #
# How things stand                                                            #
# --------------------------------------------------------------------------- #
def _iso(at: Any) -> str | None:
    return datetime.fromtimestamp(float(at), timezone.utc).isoformat() if at else None


def _stamp(text: Any) -> float:
    try:
        return datetime.fromisoformat(str(text)).timestamp()
    except (TypeError, ValueError):
        return 0.0


def _active(state: dict[str, Any]) -> dict[str, Any]:
    held = state.get("active")
    return {**DEFAULTS, **held} if isinstance(held, dict) else dict(DEFAULTS)


def cursor(db: OrmSession) -> tuple[int, str] | None:
    """The highest entry the receiver ever took, as ``(number, hash)``: a head kept by the
    forwarding, never moved back. None when nothing was sent."""
    held = _doc(db, STATE_ID).get("sentHead")
    if isinstance(held, list) and len(held) == 2 and isinstance(held[0], int) and len(str(held[1])) == 64:
        return held[0], str(held[1])
    return None


def unsent_from(db: OrmSession) -> int | None:
    """The number of the first entry that still has to be sent, while forwarding is on."""
    state = _doc(db, STATE_ID)
    active, wanted = _active(state), read(db)
    if active["enabled"] and ready(active):
        return int(state.get("cursor") or 0) + 1
    if wanted["enabled"] and ready(wanted):
        return 1  # turned on, and the sender has not taken it up yet
    return None


def backlog(db: OrmSession, now: float | None = None) -> dict[str, Any]:
    """What waits to be sent: how many entries, and since when the oldest waits."""
    start = unsent_from(db)
    if start is None:
        return {"entries": 0, "oldestAt": None, "seconds": 0.0}
    waiting = db.execute(select(func.count()).select_from(_T).where(_T.c.seq >= start)).scalar() or 0
    oldest = db.execute(select(_T.c.at).where(_T.c.seq >= start).order_by(_T.c.seq).limit(1)).scalar()
    clock = time.time() if now is None else now
    age = max(0.0, clock - _stamp(oldest)) if waiting and _stamp(oldest) else 0.0
    return {"entries": int(waiting), "oldestAt": oldest if waiting else None, "seconds": age}


def out(db: OrmSession, now: float | None = None) -> dict[str, Any]:
    """The settings and the state as the screen shows them: no key, only whether one is set."""
    from ..automation import credentials
    from ..core.config import settings as app_settings

    doc = _doc(db, SETTINGS_ID)
    wanted = read(db)
    kept = str(wanted.pop("clientKey") or "")
    found = credentials.reference(kept)
    wanted["clientKeySet"] = bool(kept)
    wanted["clientKeyCredential"] = found.text if found else ""
    state = _doc(db, STATE_ID)
    active = _active(state)
    pending = int(doc.get("version") or 0) != int(state.get("version") or 0)
    return {
        "settings": wanted,
        "state": {
            "destination": destination(active) if active["enabled"] else "",
            # The settings above were changed and the sender still runs with the ones before.
            "pendingChange": pending,
            "cursor": int(state.get("cursor") or 0),
            "sent": int(state.get("sent") or 0),
            "sentAt": _iso(state.get("sentAt")),
            "error": str(state.get("error") or ""),
            "errorSince": _iso(state.get("errorSince")),
            "checkpointAt": _iso(state.get("checkpointAt")),
            "backlog": backlog(db, now),
            "sends": app_settings.AUTOMATION_WORKER,
        },
        "facilities": syslog.FACILITIES,
        "severities": syslog.SEVERITIES,
        "defaultPorts": DEFAULT_PORTS,
    }


# --------------------------------------------------------------------------- #
# The test asked for from the screen                                          #
# --------------------------------------------------------------------------- #
def ask_test(db: OrmSession, now: float | None = None) -> str:
    """Leave a request for a test of the receiver (the caller commits). Returns its id."""
    request = uuid.uuid4().hex
    _keep(db, TEST_ID, {"request": request, "at": time.time() if now is None else now})
    return request


def test_answer(db: OrmSession, request: str) -> dict[str, Any] | None:
    doc = _doc(db, TEST_ID)
    answer = doc.get("answer")
    return answer if doc.get("request") == request and isinstance(answer, dict) else None


def try_receiver(settings: dict[str, Any], key: str, mark: str, now: float) -> dict[str, Any]:
    """Send one marked test message over a connection of its own and say what the socket said."""
    link = transport.Connection(settings, key)
    try:
        said = link.connect()
        written = link.send([syslog.test_message(mark, now, settings)])
        if link.datagram:
            time.sleep(0.3)
            # A second datagram meets the answer to the first: a port nothing listens on refuses it.
            link.send([syslog.test_message(mark, now, settings)])
            words = (
                f"Two test messages of {written} bytes left for {said['address']}:{said['port']} over UDP. UDP gives "
                "no answer: look for them on the receiver"
            )
        else:
            time.sleep(1.0)
            kept = link.alive()
            words = f"Connected to {said['address']}:{said['port']}"
            if said.get("tls"):
                presented = said.get("subject") or "a certificate"
                words += f" with {said['tls']} ({said.get('cipher')}); the receiver presented {presented}"
                if said.get("notAfter"):
                    words += f", valid until {said['notAfter']}"
            words += f". A test message of {written} bytes was written and the receiver " + (
                "kept the connection open. TCP gives no other answer: look for the message on the receiver"
                if kept
                else "closed the connection after it: it may have refused the message"
            )
            if not kept:
                return {"ok": False, "message": words, "said": said, "mark": mark}
        return {"ok": True, "message": words, "said": said, "mark": mark}
    except TransportError as error:
        return {"ok": False, "message": str(error), "said": link.said, "mark": mark}
    finally:
        link.close()


def _answer_test(now: float) -> bool:
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        doc = _doc(db, TEST_ID)
        if not doc.get("request") or doc.get("answer") or now - float(doc.get("at") or 0) > TEST_ANSWER_WITHIN:
            return False
        settings = read(db)
        try:
            key = client_key(db, settings) if settings.get("clientCert") else ""
            trouble = "" if ready(settings) else "No receiver is set"
        except TransportError as error:
            key, trouble = "", str(error)
    mark = doc["request"][:12]
    if trouble:
        answer = {"ok": False, "message": trouble, "mark": mark}
    else:
        try:
            answer = try_receiver(settings, key, mark, now)
        except Exception as error:  # noqa: BLE001 - the person who asked gets an answer whatever happened
            logger.exception("The test of the syslog receiver failed")
            answer = {"ok": False, "message": f"{type(error).__name__}: {error}"[:500], "mark": mark}
    with SessionLocal() as db:
        row = db.get(Setting, TEST_ID)
        if row is not None and (row.doc or {}).get("request") == doc["request"]:
            row.doc = {**row.doc, "answer": answer}
            flag_modified(row, "doc")
            db.commit()
    return True


# --------------------------------------------------------------------------- #
# One pass                                                                    #
# --------------------------------------------------------------------------- #
def _note(**facts: Any) -> dict[str, Any]:
    """Write facts into the state row, in a transaction of its own. Returns the row as it is then."""
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        doc = {**_doc(db, STATE_ID), **facts}
        _keep(db, STATE_ID, doc)
        db.commit()
    return doc


def _drop_connection() -> None:
    global _connection, _connection_key, _unconfirmed
    if _connection is not None:
        _connection.close()
    _connection, _connection_key, _unconfirmed = None, "", None


def reset() -> None:
    """Forget what this process holds between passes (tests; a process that lost the lease)."""
    global _fails, _retry_at
    _drop_connection()
    _fails, _retry_at = 0, 0.0


def _number_of(db: OrmSession, entry_id: str | None) -> int | None:
    return db.execute(select(_T.c.seq).where(_T.c.id == entry_id)).scalar() if entry_id else None


def _adopt(
    db: OrmSession, doc: dict[str, Any], state: dict[str, Any], clock: float
) -> tuple[dict[str, Any], int | None]:
    """Take up settings that were changed, once the receiver that was set heard of the change.
    Returns the state, and the number sending stops at for now (None: no limit)."""
    version = int(doc.get("version") or 0)
    if version == int(state.get("version") or 0):
        return state, None
    old = _active(state)
    wanted = {**DEFAULTS, **(doc.get("settings") or {})}
    change = _number_of(db, doc.get("changeEntry"))
    old_on = old["enabled"] and ready(old)
    at = int(state.get("cursor") or 0)
    heard = not old_on or (change is not None and at >= change)
    if not heard and change is not None and clock < float(doc.get("changedAt") or 0) + LAST_WORD_SECONDS:
        return state, change  # the old receiver first, up to the entry of the change
    if not heard:
        waiting = db.execute(select(func.count()).select_from(_T).where(_T.c.seq > at)).scalar() or 0
        audit.record(
            db,
            ACTOR,
            "audit.forward.unheard",
            f"The receiver {destination(old)} did not take the last {waiting} entries before the forwarding "
            "was changed, the change among them",
            target="audit log forwarding",
        )
    fresh = {
        "version": version,
        "active": wanted,
        "error": "",
        "errorSince": None,
        "checkpointAt": state.get("checkpointAt") if destination(wanted) == destination(old) else None,
    }
    if destination(wanted) != destination(old) or "cursor" not in state:
        first = db.execute(select(func.min(_T.c.seq))).scalar() or 1
        start = (change - 1) if (wanted["startFrom"] == "now" and change) else first - 1
        held = db.execute(select(_T.c.hash).where(_T.c.seq == start)).scalar() if start > 0 else None
        fresh.update(cursor=max(0, start), cursorHash=held or ZERO, sent=0, sentAt=None, since=clock)
        # Another receiver knows nothing of what the one before took.
        fresh.update(sentHead=None, trail=[])
    state = {**state, **fresh}
    _keep(db, STATE_ID, state)
    db.commit()
    _drop_connection()
    logger.info("Forwarding of the audit log: now %s", destination(wanted) if wanted["enabled"] else "off")
    return state, None


def _still_there(db: OrmSession, seq: int, hashed: str) -> bool:
    """Whether the log still holds entry ``seq`` as it was sent, or says itself that it was removed."""
    if seq <= 0:
        return True
    held = db.execute(select(_T.c.hash).where(_T.c.seq == seq)).scalar()
    if held is not None:
        return held == hashed
    # Not there: removed by a trim when the entry after it still names its hash.
    after = db.execute(select(_T.c.seq, _T.c.prev_hash).where(_T.c.seq > seq).order_by(_T.c.seq).limit(1)).first()
    return after is not None and after[0] == seq + 1 and after[1] == hashed


def _follow_the_log(db: OrmSession, state: dict[str, Any], active: dict[str, Any]) -> dict[str, Any]:
    """Notice a log that no longer holds what was sent, say so, and go back to where it still does."""
    at, held = int(state.get("cursor") or 0), str(state.get("cursorHash") or "")
    if not int(state.get("sent") or 0) or _still_there(db, at, held):
        return state
    trail = [pair for pair in state.get("trail") or [] if isinstance(pair, list) and len(pair) == 2]
    back = next(((seq, hashed) for seq, hashed in reversed(trail) if seq < at and _still_there(db, seq, hashed)), None)
    start, start_hash = back if back is not None else (0, ZERO)
    audit.record(
        db,
        ACTOR,
        "audit.forward.diverged",
        f"Entry {at} is no longer in the log as it was sent to {destination(active)}: entries were removed or "
        f"changed after they were forwarded. The log is sent again from entry {start + 1}; the receiver holds "
        "what it said before",
        target="audit log forwarding",
    )
    state = {**state, "cursor": start, "cursorHash": start_hash, "trail": [pair for pair in trail if pair[0] <= start]}
    _keep(db, STATE_ID, state)
    db.commit()
    _drop_connection()
    logger.warning(
        "Forwarding of the audit log: entry %s is no longer what was sent; sending again from %s", at, start + 1
    )
    return state


def _taken(state: dict[str, Any], seq: int, hashed: str) -> dict[str, Any]:
    """What the state keeps of an entry the receiver took: the head ever sent, and the trail."""
    head = state.get("sentHead")
    facts: dict[str, Any] = {}
    if not (isinstance(head, list) and len(head) == 2 and isinstance(head[0], int) and head[0] >= seq):
        facts["sentHead"] = [seq, hashed]
    trail = [pair for pair in state.get("trail") or [] if isinstance(pair, list) and len(pair) == 2 and pair[0] < seq]
    facts["trail"] = [*trail, [seq, hashed]][-TRAIL_KEPT:]
    return facts


def _rows(db: OrmSession, after: int, upto: int | None, limit: int) -> list[dict[str, Any]]:
    wanted = select(_T).where(_T.c.seq > after).order_by(_T.c.seq).limit(limit)
    if upto is not None:
        wanted = wanted.where(_T.c.seq <= upto)
    return [{**row, "prev": row["prev_hash"]} for row in db.execute(wanted).mappings().all()]


def ship(now: float | None = None, holder: str | None = None) -> list[str]:
    """One pass of the process that has a way out: answer a test that was asked for, take up
    changed settings, confirm what the last pass sent, send what waits, send a checkpoint when
    one is due. Returns what it did."""
    from ..backups import runner
    from ..core.db import SessionLocal
    from . import chain

    global _connection, _connection_key, _unconfirmed, _fails, _retry_at
    clock = time.time() if now is None else now
    did: list[str] = []
    # A test is answered at once, lease or not: a person waits for it.
    if _answer_test(clock):
        did.append("test")
    with SessionLocal() as db:
        if not runner.acquire(db, holder or runner.HOLDER, now, LEASE):
            _drop_connection()
            return did
    with SessionLocal() as db:
        doc, state = _doc(db, SETTINGS_ID), _doc(db, STATE_ID)
        if not doc and not state:
            return did
        state, upto = _adopt(db, doc, state, clock)
        active = _active(state)
        if not active["enabled"] or not ready(active):
            _drop_connection()
            return did
        try:
            key = client_key(db, active) if active.get("clientCert") else ""
        except TransportError as error:
            _failed(state, str(error), clock)
            return did
        state = _follow_the_log(db, state, active)
        position = int(state.get("cursor") or 0)
        seq, held = chain.head(db)
        count = db.execute(select(func.count()).select_from(_T)).scalar() or 0
    fingerprint = hashlib.sha256(json.dumps(active, sort_keys=True).encode()).hexdigest()
    if _connection is None or _connection_key != fingerprint:
        _drop_connection()
        _connection, _connection_key = transport.Connection(active, key), fingerprint
    link = _connection
    try:
        if _unconfirmed is not None:
            # What the last pass wrote arrived if the receiver is still there.
            if link.alive():
                position = _unconfirmed[0]
                state = _note(
                    cursor=position,
                    cursorHash=_unconfirmed[1],
                    sent=int(state.get("sent") or 0) + _unconfirmed[2],
                    sentAt=clock,
                    error="",
                    errorSince=None,
                    **(_taken(state, position, _unconfirmed[1]) if _unconfirmed[2] else {}),
                )
                _fails = 0
                did.append(f"confirmed:{position}")
                _unconfirmed = None
            else:
                # Gone since: what was written is not counted, and is sent again from the cursor.
                _unconfirmed = None
                why = f" ({link.closed_why})" if link.closed_why else ""
                raise TransportError(f"{link.host}:{link.port} closed the connection{why} before it took what was sent")
        if clock < _retry_at:
            return did
        limit = active["maxDatagram"] if link.datagram else None
        last_hash, written = "", 0
        for _round in range(1 if link.datagram else ROUNDS):
            with SessionLocal() as db:
                rows = _rows(db, position, upto, UDP_PER_PASS if link.datagram else BATCH)
            if not rows:
                break
            link.send([syslog.render(row, active, limit) for row in rows])
            position, last_hash, written = int(rows[-1]["seq"]), str(rows[-1]["hash"]), written + len(rows)
        if written:
            did.append(f"sent:{written}")
            if link.datagram:
                state = _note(
                    cursor=position,
                    cursorHash=last_hash,
                    sent=int(state.get("sent") or 0) + written,
                    sentAt=clock,
                    error="",
                    errorSince=None,
                    **_taken(state, position, last_hash),
                )
                _fails = 0
            else:
                _unconfirmed = (position, last_hash, written)
        if seq and clock - float(state.get("checkpointAt") or 0) >= int(active["checkpointMinutes"]) * 60:
            link.send([syslog.checkpoint(seq, held, count, clock, active)])
            state = _note(checkpointAt=clock)
            did.append("checkpoint")
            if not written and not link.datagram:
                # Confirmed like a batch: a receiver that took it is a receiver that is back.
                _unconfirmed = (position, str(state.get("cursorHash") or ZERO), 0)
        if not written and state.get("error") and not link.datagram and _unconfirmed is None:
            # Nothing waits, and the receiver was down: one that accepts a connection is back.
            if not link.open:
                link.connect()
            state = _note(error="", errorSince=None)
            _fails = 0
            did.append("back")
    except TransportError as error:
        _unconfirmed = None
        _failed(state, str(error), clock)
        did.append("failed")
    return did


SHIP_EVERY = 1.0
_shipping = False


def _loop() -> None:
    time.sleep(12)  # let the server start
    while True:
        try:
            ship()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("A pass of the forwarding of the audit log failed")
        time.sleep(SHIP_EVERY)


def start() -> None:
    """Start the loop in the process that has a way out."""
    global _shipping
    if _shipping:
        return
    _shipping = True
    import threading

    try:
        rekey(STATE_ID)
    except Exception:  # noqa: BLE001 - the key is asked again on the screen if it cannot be read
        logger.exception("The key of the client certificate could not be moved to the new SECRET_KEY")

    threading.Thread(target=_loop, name="nik-audit-forward", daemon=True).start()


def _failed(state: dict[str, Any], why: str, clock: float) -> None:
    global _fails, _retry_at
    _fails += 1
    _retry_at = clock + min(RETRY_MAX, 2 ** min(_fails, 6))
    if state.get("error") != why[:480] or not state.get("errorSince"):
        logger.warning("Forwarding of the audit log: %s", why)
    _note(error=why[:480], errorSince=state.get("errorSince") or clock)
