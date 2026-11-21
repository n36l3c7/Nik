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

**What this cannot do.** A server that comes back and cannot reach the other
host cannot know it was replaced: it serves. Nothing inside it can tell an
empty network from a dead peer, and a server that stopped whenever the second
host is unreachable would make the standby a second thing whose failure
stops the service. The procedure of the promotion says what the operator
does about it: the old host stays off, or off the network, until it is made
the standby (``deploy/standby.sh rejoin``).
"""

from __future__ import annotations

import json
import socket
import time
import uuid
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from ..core.config import settings
from . import config

PRIMARY, STANDBY, SUPERSEDED = "primary", "standby", "superseded"
MARKER = "superseded.json"
# The answer of the process that has a way out is waited for this long when the server starts.
ASK_WAIT = 45
ASK_FRESH = 600


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
    """Whether this server is the one that serves: the loops that fetch, run playbooks and send
    copies ask before each pass."""
    return of(db) == PRIMARY


# --------------------------------------------------------------------------- #
# The file a promotion leaves                                                 #
# --------------------------------------------------------------------------- #
def new_marker(generation_now: int, by: str, now: float | None = None) -> dict[str, Any]:
    return {
        "generation": int(generation_now),
        "at": time.time() if now is None else now,
        "by": by,
        "id": uuid.uuid4().hex,
    }


def read_marker(raw: bytes | None) -> dict[str, Any] | None:
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
    }


def judge(doc: dict[str, Any], marker: dict[str, Any] | None) -> str:
    """What a marker found on the other host means for the server that keeps ``doc``:
    ``none`` (no marker, or an old one), ``own`` (this server wrote it when it was promoted: the
    copies still point at this host itself) or ``superseded``."""
    if marker is None:
        return "none"
    if marker["id"] and marker["id"] == doc.get("markerId"):
        return "own"
    return "superseded" if marker["generation"] > int(doc.get("generation") or 1) else "none"


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
