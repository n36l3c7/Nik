"""Which server this is: the one that serves, a standby, or one that was replaced.

**The database says.** A standby is a server whose PostgreSQL is replaying
the log of another (``pg_is_in_recovery()``): nothing can be written to it,
so nothing of Nik may run on it as if it were the server. No variable says
"this is a standby": a variable can be wrong after a promotion, the database
cannot.

**The generation.** Each promotion adds one to a number kept in the database
(it travels with it) and writes a small file beside the copies on the host
that was promoted: ``superseded.json``, with that number, the moment and a
mark of its own. A recovery of the database on another host from those
copies (``deploy/restore.sh --to … --from``) does the same: it too puts a
new server in the place of the old one. The server that was replaced still sends its copies to that
host when it comes back: the process that sends them reads the file first,
and when it names a generation later than its own it writes down that this
server was replaced. From then on the server does not serve: it answers every
request with that sentence (``gate.py``), and its automation worker runs
nothing.

**The file is signed.** Whoever can write in the directory of the copies could
otherwise stop the first host with one small file. The marker carries a MAC
under a key both hosts hold: one derived from ``SECRET_KEY`` with a label of
its own (the standby is given ``SECRET_KEY`` by ``deploy/standby.sh secrets
import``). A marker with no MAC, or with one this server cannot make with the
key it has or one it had (``SECRET_KEY_PREVIOUS``), is never obeyed: it is
written down as such, the administrators are told once, and the health page
shows it. The heartbeat the first host leaves for the standby is signed the
same way, so that what a standby says a promotion would lose cannot be
written by somebody else.

**Nothing works on a server that does not serve.** ``may_work`` is what
every loop of the server asks before it does anything, through the lease it
must take (``core/leases.py``): no lease is given on a standby (its database
cannot be written), nor on a server that was replaced. So no step of a
playbook is taken, no schedule fires, no cycle fetches, no copy leaves and no
work is taken back there, and none of them fills the log trying. They go on
by themselves when the server may serve again (a standby that is promoted:
its processes need no restart for it).

**What this cannot do.** A server that comes back and cannot reach the other
host cannot know it was replaced: it serves. Nothing inside it can tell an
empty network from a dead peer, and a server that stopped whenever the second
host is unreachable would make the standby a second thing whose failure
stops the service. The procedure of the promotion says what the operator
does about it: the old host stays off, or off the network, until it is made
the standby (``deploy/standby.sh rejoin``).
"""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time
import uuid
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from ..core.config import settings
from . import config

PRIMARY, STANDBY, SUPERSEDED = "primary", "standby", "superseded"
MARKER = "superseded.json"
# The answer of the process that has a way out is waited for this long when the server starts.
ASK_WAIT = 45


def in_recovery(db: OrmSession) -> bool:
    """Whether the database is replaying the log of another server (never, on SQLite)."""
    if db.get_bind().dialect.name != "postgresql":
        return False
    return bool(db.execute(text("select pg_is_in_recovery()")).scalar())


def state(db: OrmSession) -> dict[str, Any]:
    return config.held(db, config.ROLE_SETTINGS_ID)


def generation(db: OrmSession) -> int:
    return int(state(db).get("generation") or 1)


def name(db: OrmSession | None = None) -> str:
    """What this server calls itself to the other host: the name set on the screen, the one of
    the environment, or the name of the machine."""
    given = config.read(db).get("name") if db is not None else ""
    return str(given or settings.SERVER_NAME or socket.gethostname())[:120]


def superseded(db: OrmSession) -> dict[str, Any] | None:
    """What replaced this server, or None: ``{"at", "by", "generation"}``."""
    found = state(db).get("superseded")
    return found if isinstance(found, dict) and found.get("generation") else None


def of(db: OrmSession) -> str:
    if in_recovery(db):
        return STANDBY
    return SUPERSEDED if superseded(db) else PRIMARY


def serving(db: OrmSession) -> bool:
    """Whether this server is the one that serves, asked of the database now."""
    return of(db) == PRIMARY


# How long an answer of ``may_work`` is believed: the loops ask every second or so, and the role
# of a server changes a few times in its life.
MAY_WORK_KEPT = 3.0
_may_work: tuple[float, bool] = (0.0, True)
_may_work_lock = threading.Lock()


def may_work(db: OrmSession, now: float | None = None) -> bool:
    """Whether the loops of this process may do anything: False on a standby and on a server that
    was replaced. Asked through ``core/leases.py`` by every loop, so the answer is kept for a few
    seconds. Never raises, and never leaves the session in a failed transaction: a database that
    cannot say (it has no table of settings yet: a new install) is the server."""
    global _may_work
    if db.get_bind().dialect.name != "postgresql":
        return True
    clock = time.monotonic() if now is None else now
    with _may_work_lock:
        at, answer = _may_work
        if at and 0 <= clock - at < MAY_WORK_KEPT:
            return answer
    try:
        with db.begin_nested():
            answer = of(db) == PRIMARY
    except Exception:  # noqa: BLE001 - asked again at the next pass
        answer, clock = True, 0.0
    with _may_work_lock:
        _may_work = (clock, answer)
    return answer


def forget_may_work() -> None:
    """Ask the database again at the next ``may_work`` (the role was just changed; the tests)."""
    global _may_work
    with _may_work_lock:
        _may_work = (0.0, True)


# --------------------------------------------------------------------------- #
# The file a promotion leaves                                                 #
# --------------------------------------------------------------------------- #
MAC_LABEL = b"nik pair files"
UNSIGNED = "unsigned"


def _mac_key(secret: str) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=MAC_LABEL).derive(secret.encode("utf-8"))


def _mac(secret: str, what: str, doc: dict[str, Any]) -> str:
    """The MAC of a small file the two hosts leave for each other: over what the file is (a marker
    is not a heartbeat) and every field but the MAC itself, written one way."""
    body = json.dumps({key: value for key, value in doc.items() if key != "mac"}, sort_keys=True, separators=(",", ":"))
    return hmac.new(_mac_key(secret), f"{what}\n{body}".encode(), hashlib.sha256).hexdigest()


def sign(what: str, doc: dict[str, Any]) -> dict[str, Any]:
    """``doc`` with the MAC this server gives it."""
    return {**doc, "mac": _mac(settings.SECRET_KEY, what, doc)}


def signed(what: str, doc: dict[str, Any]) -> bool:
    """Whether ``doc`` carries a MAC made with the key of this server, or with one it had before."""
    mac = doc.get("mac")
    if not isinstance(mac, str) or not mac:
        return False
    return any(
        hmac.compare_digest(_mac(secret, what, doc), mac)
        for secret in (settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS)
        if secret
    )


def new_marker(generation_now: int, by: str, now: float | None = None) -> dict[str, Any]:
    return sign(
        "marker",
        {
            "generation": int(generation_now),
            "at": time.time() if now is None else now,
            "by": by,
            "id": uuid.uuid4().hex,
        },
    )


def read_marker(raw: bytes | None) -> dict[str, Any] | None:
    """The marker a file holds, or None when it holds none. ``signed`` says whether its MAC is one
    this server can make: a marker that is not signed is never obeyed (``judge``)."""
    if not raw:
        return None
    try:
        found = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(found, dict) or not isinstance(found.get("generation"), int):
        return None
    return {
        "generation": found["generation"],
        "at": float(found.get("at") or 0),
        "by": str(found.get("by") or "")[:120],
        "id": str(found.get("id") or "")[:64],
        "signed": signed("marker", found),
    }


def judge(doc: dict[str, Any], marker: dict[str, Any] | None) -> str:
    """What a marker found on the other host means for the server that keeps ``doc``:
    ``none`` (no marker, or an old one), ``own`` (this server wrote it when it was promoted: the
    copies still point at this host itself), ``superseded``, or ``unsigned``: a marker that would
    replace this server and that no key of this server signed. That one is not obeyed."""
    if marker is None:
        return "none"
    if marker["id"] and marker["id"] == doc.get("markerId"):
        return "own"
    if marker["generation"] <= int(doc.get("generation") or 1):
        return "none"
    return "superseded" if marker.get("signed") else UNSIGNED


def note_marker(db: OrmSession, marker: dict[str, Any] | None, now: float | None = None) -> str:
    """Write down what the other host says of this server (the caller commits). Returns ``judge``."""
    now = time.time() if now is None else now
    doc = state(db)
    verdict = judge(doc, marker)
    doc["asked"] = {"at": now, "reachable": True, "verdict": verdict}
    if verdict == "superseded" and not doc.get("superseded"):
        doc["superseded"] = {
            "at": marker["at"],
            "by": marker["by"],
            "generation": marker["generation"],
            "learnedAt": now,
        }
    config.keep(db, config.ROLE_SETTINGS_ID, doc)
    if verdict == "superseded":
        forget_may_work()
    return verdict


def note_unreachable(db: OrmSession, why: str, now: float | None = None) -> None:
    """The other host could not be asked (the caller commits)."""
    doc = state(db)
    doc["asked"] = {"at": time.time() if now is None else now, "reachable": False, "error": why[:300]}
    config.keep(db, config.ROLE_SETTINGS_ID, doc)


def promote(db: OrmSession, by: str, now: float | None = None, hold: bool = True) -> dict[str, Any]:
    """This server takes the place of another (the caller commits): a standby that was promoted,
    or a new host the database was recovered on from the copies of the old one. Returns the
    marker to leave beside the copies, for the server it replaces to find.

    ``hold``: the copies this server inherits point at its own host (a promoted standby), so it
    sends nothing until an administrator names another destination. A server recovered on a new
    host goes on sending to the second host, which is not itself."""
    now = time.time() if now is None else now
    doc = state(db)
    marker = new_marker(int(doc.get("generation") or 1) + 1, by, now)
    doc.update(
        generation=marker["generation"],
        promotedAt=now,
        promotedBy=by,
        markerId=marker["id"],
        holdCopies=bool(hold),
    )
    doc.pop("superseded", None)
    doc.pop("asked", None)
    config.keep(db, config.ROLE_SETTINGS_ID, doc)
    forget_may_work()
    return marker


def sentences(found: dict[str, Any]) -> list[str]:
    """What the page of a server that was replaced says."""
    from ..backups import runner

    when = runner.iso(float(found.get("at") or 0))[:16].replace("T", " ") + " UTC"
    by = f" by {found['by']}" if found.get("by") else ""
    return [
        f"This server was replaced on {when}{by}: the standby was promoted and is the server now.",
        "It serves nothing, fetches nothing and runs no playbook, so that the two never work at once.",
        "What was written here after the last copy reached the other host is not on it.",
        "To make this host the standby of the new server: deploy/standby.sh rejoin.",
    ]
