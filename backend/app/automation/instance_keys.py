"""Several keys for one instance, and how they take turns.

A source that is asked a lot with a free key runs out of it: an instance may
hold **more than one set of credentials** (its *keys*), and says how they are
used. The first key is what the instance always had (``connections.secrets``);
the others are in ``connections.extra_keys``, encrypted the same way.

How the keys take turns (``mode``):

- ``each``: one request each, in turn;
- ``until_exhausted``: the same key until it is used up, then the next;
- ``least_used``: the key that was used least today;
- ``reserve``: the first key always, another only while the first is used up.

A key is **used up** when it reached the limit set here (requests a minute, a
day), or when the vendor said so (HTTP 429): it is then left alone for a
while. When every key is used up the command waits for the first to come
back, or fails, as the instance says.

An instance may also **keep an answer** for some hours and give it back
without a request: only of commands that change nothing outside.

What is counted is in ``instance_key_uses``; answers kept are in
``command_answers``.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import delete, select
from sqlalchemy.orm import Session as OrmSession

from ..core import vault
from ..core.models import CommandAnswer, Connection, InstanceKeyUse

MODES = ("each", "until_exhausted", "least_used", "reserve")
MAIN = "main"  # the id of the first key: the credentials the instance always had
MAX_KEYS = 20
ID_RE = re.compile(r"^[a-z0-9]{1,16}$")
DEFAULTS: dict[str, Any] = {"mode": "each", "perMinute": 0, "perDay": 0, "whenExhausted": "wait", "cacheHours": 0}
# How long a key the vendor refused for its quota is left alone, when nothing better is known.
REFUSED_SECONDS = 15 * 60
ANSWER_MAX = 200_000  # an answer larger than this is not kept
QUOTA_STATUS = 429


class KeyError_(ValueError):
    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class Key:
    id: str
    name: str
    secrets: dict[str, str]


# --------------------------------------------------------------------------- #
# What an instance holds                                                      #
# --------------------------------------------------------------------------- #
def _number(value: Any, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
        raise KeyError_("A limit is a whole number")
    if not low <= int(value) <= high:
        raise KeyError_(f"A limit is between {low} and {high}")
    return int(value)


def clean_policy(raw: Any) -> dict[str, Any]:
    """How the keys of an instance are used, as it is kept. 0 means "no limit" (or "no cache")."""
    raw = raw if isinstance(raw, dict) else {}
    mode = raw.get("mode", DEFAULTS["mode"])
    if mode not in MODES:
        raise KeyError_("The keys take turns in one of these ways: " + ", ".join(MODES))
    when = raw.get("whenExhausted", DEFAULTS["whenExhausted"])
    if when not in ("wait", "fail"):
        raise KeyError_('When every key is used up a command waits ("wait") or fails ("fail")')
    return {
        "mode": mode,
        "perMinute": _number(raw.get("perMinute", 0), 0, 100_000),
        "perDay": _number(raw.get("perDay", 0), 0, 100_000_000),
        "whenExhausted": when,
        "cacheHours": _number(raw.get("cacheHours", 0), 0, 24 * 365),
    }


def policy_of(connection: Connection) -> dict[str, Any]:
    return {**DEFAULTS, **(connection.key_policy or {})}


def _decrypted(text: str) -> Any:
    if not text:
        return None
    try:
        return json.loads(vault.decrypt(text) or "null")
    except ValueError:
        return None


def extra_keys(connection: Connection) -> list[dict[str, Any]]:
    """The keys beside the first, as they are stored: ``[{id, name, secrets}]``."""
    found = _decrypted(connection.extra_keys or "")
    return [entry for entry in found if isinstance(entry, dict)] if isinstance(found, list) else []


def keys_of(connection: Connection) -> list[Key]:
    """Every key of the instance, in the order they are tried: the first, then the others."""
    main = _decrypted(connection.secrets or "")
    name = str((connection.key_policy or {}).get("mainName") or "Key 1")
    found = [Key(MAIN, name, {k: str(v) for k, v in (main if isinstance(main, dict) else {}).items()})]
    for entry in extra_keys(connection):
        secrets = entry.get("secrets") if isinstance(entry.get("secrets"), dict) else {}
        found.append(
            Key(str(entry.get("id") or ""), str(entry.get("name") or ""), {k: str(v) for k, v in secrets.items()})
        )
    return found


def set_extra_keys(
    connection: Connection, given: list[dict[str, Any]], secret_names: list[str], required: list[str]
) -> None:
    """Replace the keys beside the first with ``given``: ``[{id?, name, secrets?}]``. One that names the id
    of a key that exists keeps the secrets it is not given; a new one needs every required secret. A key
    left out is removed. The caller commits."""
    if len(given) > MAX_KEYS - 1:
        raise KeyError_(f"An instance holds {MAX_KEYS} keys at most")
    before = {entry.get("id"): entry for entry in extra_keys(connection)}
    kept: list[dict[str, Any]] = []
    seen_names = {str((connection.key_policy or {}).get("mainName") or "Key 1").lower()}
    for index, entry in enumerate(given):
        if not isinstance(entry, dict):
            raise KeyError_("A key is {name, secrets}")
        name = str(entry.get("name") or "").strip()[:60] or f"Key {index + 2}"
        if name.lower() in seen_names:
            raise KeyError_(f'Two keys are called "{name}"')
        seen_names.add(name.lower())
        key_id = str(entry.get("id") or "")
        old = before.get(key_id) if key_id else None
        if key_id and old is None:
            raise KeyError_("This key is not of this instance any more")
        secrets = dict((old or {}).get("secrets") or {})
        for field, value in (entry.get("secrets") or {}).items():
            if field not in secret_names:
                raise KeyError_(f'"{field}" is not a credential of this connector')
            if value is None:
                continue  # left out: what is stored stays
            if value == "":
                secrets.pop(field, None)
            else:
                secrets[field] = str(value)[:10_000]
        missing = [field for field in required if not secrets.get(field)]
        if not secrets:
            raise KeyError_(f'The key "{name}" holds no credential')
        if missing:
            raise KeyError_(f'The key "{name}" needs: ' + ", ".join(missing))
        if not key_id:
            key_id = hashlib.sha256(f"{connection.id}:{name}:{time.time_ns()}".encode()).hexdigest()[:12]
        kept.append({"id": key_id, "name": name, "secrets": secrets})
    connection.extra_keys = vault.encrypt(json.dumps(kept)) if kept else ""


# --------------------------------------------------------------------------- #
# Counting                                                                    #
# --------------------------------------------------------------------------- #
def _day(now: float) -> str:
    return datetime.fromtimestamp(now, timezone.utc).strftime("%Y-%m-%d")


def _midnight(now: float) -> float:
    return (int(now) // 86_400 + 1) * 86_400.0


def _use(db: OrmSession, connection_id: str, key_id: str) -> InstanceKeyUse:
    row = db.get(InstanceKeyUse, (connection_id, key_id))
    if row is None:
        row = InstanceKeyUse(connection_id=connection_id, key_id=key_id)
        db.add(row)
        db.flush()
    return row


def _counts(row: InstanceKeyUse | None, now: float) -> tuple[int, int]:
    """(this minute, today) for a key, read at ``now``: a window that passed counts nothing."""
    if row is None:
        return 0, 0
    minute = row.minute_count if row.minute == int(now) // 60 else 0
    day = row.day_count if row.day == _day(now) else 0
    return minute, day


def free_at(row: InstanceKeyUse | None, policy: dict[str, Any], now: float) -> float:
    """When the key can be used: ``now`` or earlier when it can be used at once."""
    if row is None:
        return now
    at = max(now, float(row.exhausted_until or 0))
    minute, day = _counts(row, now)
    if policy["perMinute"] and minute >= policy["perMinute"]:
        at = max(at, (int(now) // 60 + 1) * 60.0)
    if policy["perDay"] and day >= policy["perDay"]:
        at = max(at, _midnight(now))
    return at


def choose(
    db: OrmSession, connection: Connection, now: float, skip: set[str] | None = None
) -> tuple[Key | None, float]:
    """The key the next request of the instance goes with, and 0; or ``(None, seconds)``: every key is used
    up, the first comes back in that many seconds. ``skip`` leaves out keys already tried for this request."""
    policy = policy_of(connection)
    keys = [key for key in keys_of(connection) if key.id not in (skip or set())]
    if not keys:
        return None, 0.0
    uses = {
        row.key_id: row
        for row in db.scalars(select(InstanceKeyUse).where(InstanceKeyUse.connection_id == connection.id))
    }
    ready = [key for key in keys if free_at(uses.get(key.id), policy, now) <= now]
    if not ready:
        return None, max(1.0, min(free_at(uses.get(key.id), policy, now) for key in keys) - now)
    mode = policy["mode"]
    if mode == "each":  # the one that waited longest
        ready.sort(key=lambda key: float(getattr(uses.get(key.id), "last_used", 0) or 0))
        return ready[0], 0.0
    if mode == "least_used":
        ready.sort(
            key=lambda key: (_counts(uses.get(key.id), now)[1], float(getattr(uses.get(key.id), "last_used", 0) or 0))
        )
        return ready[0], 0.0
    if mode == "until_exhausted":
        # The key in use stays in use while it can be used; then the next in order, round again.
        last = max(uses.values(), key=lambda row: float(row.last_used or 0), default=None)
        order = [key.id for key in keys]
        if last is not None and last.key_id in order:
            start = order.index(last.key_id)
            by_id = {key.id: key for key in ready}
            for key_id in order[start:] + order[:start]:
                if key_id in by_id:
                    return by_id[key_id], 0.0
    return ready[0], 0.0  # reserve: the first that can be used, in order


def used(db: OrmSession, connection: Connection, key_id: str, now: float) -> None:
    """Count one request made with a key (the caller commits)."""
    row = _use(db, connection.id, key_id)
    minute, day = _counts(row, now)
    row.minute, row.minute_count = int(now) // 60, minute + 1
    row.day, row.day_count = _day(now), day + 1
    row.total = int(row.total or 0) + 1
    row.last_used = now


def refused(db: OrmSession, connection: Connection, key_id: str, now: float, seconds: float | None = None) -> None:
    """The vendor said this key is used up: leave it alone for a while (the caller commits)."""
    row = _use(db, connection.id, key_id)
    row.exhausted_until = now + (seconds if seconds and seconds > 0 else REFUSED_SECONDS)
    row.refusals = int(row.refusals or 0) + 1


def forget(db: OrmSession, connection_id: str, keep: set[str] | None = None) -> None:
    """Drop what was counted for keys that are gone (all of them when ``keep`` is None)."""
    statement = delete(InstanceKeyUse).where(InstanceKeyUse.connection_id == connection_id)
    if keep is not None:
        statement = statement.where(InstanceKeyUse.key_id.notin_(keep))
    db.execute(statement)


def shown(db: OrmSession, connection: Connection, secret_names: list[str], now: float | None = None) -> dict[str, Any]:
    """The keys of an instance as the page shows them: never a secret, only which are set, what each
    was used for today, and whether it can be used now."""
    now = time.time() if now is None else now
    policy = policy_of(connection)
    uses = {
        row.key_id: row
        for row in db.scalars(select(InstanceKeyUse).where(InstanceKeyUse.connection_id == connection.id))
    }
    chosen, _wait = choose(db, connection, now)
    listed = []
    for key in keys_of(connection):
        row = uses.get(key.id)
        minute, day = _counts(row, now)
        at = free_at(row, policy, now)
        listed.append(
            {
                "id": key.id,
                "name": key.name,
                "secrets": {name: bool(key.secrets.get(name)) for name in secret_names},
                "usedThisMinute": minute,
                "usedToday": day,
                "total": int(getattr(row, "total", 0) or 0),
                "state": "used up"
                if at > now
                else ("in use" if chosen is not None and chosen.id == key.id else "waiting"),
                "freeAt": datetime.fromtimestamp(at, timezone.utc).isoformat(timespec="seconds") if at > now else "",
            }
        )
    return {"keys": listed, "policy": {key: policy[key] for key in DEFAULTS}}


# --------------------------------------------------------------------------- #
# Answers that are kept                                                       #
# --------------------------------------------------------------------------- #
def answer_key(connection: Connection, command: str, args: dict[str, Any]) -> str:
    text = json.dumps([connection.id, command, args], sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def kept_answer(db: OrmSession, connection: Connection, command: str, args: dict[str, Any], now: float) -> dict | None:
    """The answer kept for this command with these arguments, while it is fresh: ``{outputs, context, at}``."""
    hours = policy_of(connection)["cacheHours"]
    if not hours:
        return None
    row = db.get(CommandAnswer, answer_key(connection, command, args))
    if row is None or row.created_epoch < now - hours * 3600:
        return None
    return {"outputs": row.outputs, "context": row.context or [], "at": row.created_epoch}


def keep_answer(
    db: OrmSession, connection: Connection, command: str, args: dict[str, Any], outputs: Any, context: Any, now: float
) -> None:
    """Keep an answer for as long as the instance says (the caller commits). Too large a one is not kept."""
    hours = policy_of(connection)["cacheHours"]
    if not hours:
        return
    try:
        size = len(json.dumps([outputs, context], default=str))
    except (TypeError, ValueError):
        return
    if size > ANSWER_MAX:
        return
    db.execute(
        delete(CommandAnswer).where(
            CommandAnswer.connection_id == connection.id, CommandAnswer.created_epoch < now - hours * 3600
        )
    )
    key = answer_key(connection, command, args)
    row = db.get(CommandAnswer, key)
    if row is None:
        row = CommandAnswer(id=key, connection_id=connection.id, command=command[:120])
        db.add(row)
    row.outputs, row.context, row.created_epoch = outputs, [list(pair) for pair in (context or [])], now


def forget_answers(db: OrmSession, connection_id: str) -> int:
    return db.execute(delete(CommandAnswer).where(CommandAnswer.connection_id == connection_id)).rowcount or 0
