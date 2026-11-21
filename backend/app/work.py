"""Work the API process does outside a request, held so that a restart loses none of it.

The disassembly of a sample, capa, the analysis of a capture, a scan of an
address, an upload being parsed, a mailbox being read, what a playbook asked
about a file: each runs in a thread of an API process, for seconds or for
half an hour, long after the request that asked for it was answered. Until
6.9 that thread was all there was: a process that stopped took the work with
it and left a row saying "running" for ever.

Now every such piece of work has a row of ``work_claims``, by its kind and
the id of what it works on:

- **wanted**: written by ``want`` in the transaction of the request itself,
  so the work exists exactly when its row does, even if the process dies
  before the thread starts;
- **held**: ``hold`` took it; the row says which process (``holder``) and
  that process says it is alive every ``BEAT_EVERY`` seconds (``beat_at``);
- **done** or **failed** when the work ended, **aside** when it was given up.

Nothing else is kept anywhere: the process that goes on with the work after
a stop may be another container, or another host after a promotion.

**What a stop does.** A sweeper, in one API process at a time (a lease),
looks every few seconds:

- a piece that is *held* by a process that has not said it is alive for
  ``STALE_AFTER`` seconds lost its holder. It is taken back, once, by the rule
  of its kind: **started again** from the beginning (an analysis is a function
  of the file: its result replaces itself) or **failed loudly** with the
  sentence "interrupted by a restart" where a person looks for it (what cannot
  be redone: an upload whose bytes were in the memory of the process);
- a piece that is *wanted* and that nobody took is started here.

A process that is asked to stop (``release_all``, at SIGTERM and at exit)
hands back what it holds at once, as wanted: the process that starts next
takes it without waiting, and the try is not counted against the work.

**Poison.** Each taking is counted. Work that was interrupted
``MAX_ATTEMPTS`` times is set aside as failed, with that reason, instead of
being started a fourth time: a file that brings its worker down every time
must not keep doing it. A person can still ask for it again.

A worker that is slow is not a holder that is gone: the heartbeat is of the
process, which beats while its thread waits; whether the *worker* still has
the job is asked of the worker itself (``workers/watching.py``).

**A thread that ends without finishing.** The work may also be cut while its
process lives: the database goes away under it (it is restarted, or killed),
and the thread cannot write what it found. That is an interruption like the
others: the piece is handed back as wanted, counted, and started again. When
the database is the reason, handing back fails as well: the process knows
which pieces its threads really hold, and at its next heartbeat hands back
any it is said to hold and does not.
"""

from __future__ import annotations

import atexit
import logging
import threading
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as OrmSession

from .core import leases
from .core.models import WorkClaim

logger = logging.getLogger("nik.work")

HOLDER = uuid.uuid4().hex
BEAT_EVERY = 10
STALE_AFTER = 45
# A wanted piece is started by the process that wrote it; one nobody took in this long is started by the sweeper.
WANTED_GRACE = 20
MAX_ATTEMPTS = 3
SWEEP_EVERY = 5
KEPT_SECONDS = 7 * 86400
LEASE = "work-sweeper"
LEASE_SECONDS = 30
ACTIVE = ("wanted", "held")
INTERRUPTED = "It was interrupted by a restart of the server"

_started = False
_beating = False
_stopping = threading.Event()
_lock = threading.Lock()
# The pieces a thread of this process is doing now: what the heartbeat speaks for.
_active: set[tuple[str, str]] = set()


class Taken(Exception):
    """Another process holds this piece of work, or it was set aside: it is not done here."""


@dataclass(frozen=True)
class Kind:
    """One kind of work: how it is started again, and where its failure is written.

    ``rule`` is ``again`` (started again from the beginning) or ``fail`` (failed loudly).
    ``start(ref, params)`` starts it in this process and returns at once (False when there is
    nothing to start: what it worked on is gone, or is over); ``fail(db, ref, sentence)`` writes
    the failure on the row a person looks at (the caller commits).
    """

    name: str
    label: str
    rule: str
    start: Callable[[str, dict[str, Any]], bool | None]
    fail: Callable[[OrmSession, str, str], None]


_KINDS: dict[str, Kind] = {}


def register(kind: Kind) -> None:
    _KINDS[kind.name] = kind


def kinds() -> dict[str, Kind]:
    return dict(_KINDS)


def thread(job: Callable[..., None], *args: Any) -> None:
    """Start a piece of work in a thread of its own, as a request does with its background tasks."""
    threading.Thread(target=job, args=args, name="nik-work", daemon=True).start()


def starting() -> None:
    """The process starts (or starts again, in a test): it takes work."""
    _stopping.clear()


def stopping() -> bool:
    """Whether this process was asked to stop: nothing new is taken."""
    return _stopping.is_set()


# --------------------------------------------------------------------------- #
# Wanting, holding, finishing                                                 #
# --------------------------------------------------------------------------- #
def want(db: OrmSession, kind: str, ref: str, params: dict[str, Any] | None = None, now: float | None = None) -> None:
    """Write down that this work is to be done, in the caller's transaction (the caller commits).
    What an earlier try left of the same work goes: this is a new request."""
    now = time.time() if now is None else now
    row = db.get(WorkClaim, (kind, ref))
    if row is None:
        row = WorkClaim(kind=kind, ref=ref)
        db.add(row)
    row.state, row.holder, row.beat_at, row.wanted_at = "wanted", HOLDER, now, now
    row.attempts, row.interrupted_at, row.resumed_at, row.finished_at = 0, None, None, None
    row.progress, row.note, row.params = "", "", dict(params or {})
    db.flush()


class Claim:
    """A piece of work this process holds."""

    def __init__(self, kind: str, ref: str, attempts: int, params: dict[str, Any]) -> None:
        self.kind, self.ref, self.attempts, self.params = kind, ref, attempts, params
        self._said = ""

    def progress(self, text: str) -> None:
        """Say how far the work is (what the screens show beside "running")."""
        text = str(text or "")[:200]
        if text == self._said:
            return
        self._said = text
        try:
            _update(self.kind, self.ref, {"progress": text}, held_by_us=True)
        except Exception:  # noqa: BLE001 - saying how far the work is must never cost the work
            logger.debug("How far the work %s %s is could not be written", self.kind, self.ref)

    def interrupted(self, note: str, now: float | None = None) -> int:
        """The worker lost the job while this process went on: counted as a try, and said. Returns
        how many tries that makes."""
        now = time.time() if now is None else now
        self.attempts += 1
        _update(
            self.kind,
            self.ref,
            {"attempts": self.attempts, "interrupted_at": now, "resumed_at": None, "note": note[:500], "progress": ""},
            held_by_us=True,
        )
        return self.attempts

    def resumed(self, now: float | None = None) -> None:
        _update(self.kind, self.ref, {"resumed_at": time.time() if now is None else now}, held_by_us=True)

    def set_aside(self, note: str) -> None:
        """Give the work up for good: what ``finish`` writes afterwards does not change that."""
        from .core.db import SessionLocal

        with SessionLocal() as db:
            db.execute(
                update(WorkClaim)
                .where(WorkClaim.kind == self.kind, WorkClaim.ref == self.ref, WorkClaim.holder == HOLDER)
                .values(state="aside", note=note[:500], finished_at=time.time(), progress="")
            )
            db.commit()


def _update(kind: str, ref: str, values: dict[str, Any], *, held_by_us: bool) -> int:
    from .core.db import SessionLocal

    with SessionLocal() as db:
        statement = update(WorkClaim).where(WorkClaim.kind == kind, WorkClaim.ref == ref)
        if held_by_us:
            statement = statement.where(WorkClaim.holder == HOLDER, WorkClaim.state == "held")
        changed = db.execute(statement.values(**values)).rowcount
        db.commit()
        return changed


def take(db: OrmSession, kind: str, ref: str, now: float | None = None) -> Claim:
    """Take the work for this process, and commit. Raises ``Taken`` when another process that is
    alive holds it, when it was set aside, or when this process is stopping."""
    now = time.time() if now is None else now
    if stopping():
        raise Taken("The server is stopping")
    row = db.get(WorkClaim, (kind, ref))
    if row is None or row.state in ("done", "failed"):
        # Work that was asked for without being written down (a release before 6.9 in flight), or
        # asked for again after it ended.
        want(db, kind, ref, now=now)
        db.commit()
    alive = now - STALE_AFTER
    resumed = {"resumed_at": now}
    won = db.execute(
        update(WorkClaim)
        .where(
            WorkClaim.kind == kind,
            WorkClaim.ref == ref,
            WorkClaim.attempts < MAX_ATTEMPTS,
            (WorkClaim.state == "wanted") | ((WorkClaim.state == "held") & (WorkClaim.beat_at < alive)),
        )
        .values(state="held", holder=HOLDER, beat_at=now, attempts=WorkClaim.attempts + 1, progress="")
    ).rowcount
    if won:
        db.execute(
            update(WorkClaim)
            .where(WorkClaim.kind == kind, WorkClaim.ref == ref, WorkClaim.interrupted_at.isnot(None))
            .values(**resumed)
        )
    db.commit()
    if not won:
        raise Taken(f"The work {kind} {ref} is held elsewhere, or was set aside")
    row = db.get(WorkClaim, (kind, ref))
    db.refresh(row)
    return Claim(kind, ref, int(row.attempts or 0), dict(row.params or {}))


def finish(kind: str, ref: str, failed: bool = False, note: str = "") -> None:
    """The work ended (done, or failed for a reason of its own): its row says so. A row that was
    handed back or taken by another process meanwhile is left as it is."""
    values = {"state": "failed" if failed else "done", "finished_at": time.time(), "progress": ""}
    if note:
        values["note"] = note[:500]
    _update(kind, ref, values, held_by_us=True)


class hold:  # noqa: N801 - reads as a statement: ``with work.hold("code", sha256) as claim:``
    """Hold a piece of work while the block runs. ``Taken`` is raised on entry when it is not for
    this process. A block that ends is done (or failed, when it says so: ``claim.failed = True``):
    the work wrote its own end, good or bad, where a person reads it. A block that **raises** did
    not: it was cut (the database went away under it), and the piece is handed back to be started
    again, counted as a try. A block cut by the stop of the process finishes nothing: the sweeper
    sees it."""

    def __init__(self, kind: str, ref: str, now: float | None = None) -> None:
        self.kind, self.ref, self.now = kind, ref, now
        self.claim: Claim | None = None

    def __enter__(self) -> Claim:
        from .core.db import SessionLocal

        with SessionLocal() as db:
            self.claim = take(db, self.kind, self.ref, self.now)
        self.claim.failed = False  # type: ignore[attr-defined]
        with _lock:
            _active.add((self.kind, self.ref))
        return self.claim

    def __exit__(self, kind, error, _trace) -> None:
        with _lock:
            _active.discard((self.kind, self.ref))
        if isinstance(error, (SystemExit, KeyboardInterrupt, GeneratorExit)):
            return
        try:
            if error is not None:
                logger.warning("The work %s %s was cut by %s: handed back", self.kind, self.ref, type(error).__name__)
                hand_back(self.kind, self.ref, f"It was cut ({type(error).__name__}) and is started again")
            else:
                finish(self.kind, self.ref, failed=bool(getattr(self.claim, "failed", False)))
        except Exception:  # noqa: BLE001 - the next heartbeat hands it back: this process no longer does it
            logger.warning("The end of the work %s %s could not be written yet", self.kind, self.ref)


def hand_back(kind: str, ref: str, note: str, now: float | None = None) -> int:
    """Give a piece this process holds back, as wanted and due at once: its thread ended without
    finishing it. The try stays counted."""
    return _update(
        kind,
        ref,
        {
            "state": "wanted",
            "holder": "",
            "beat_at": 0,
            "interrupted_at": time.time() if now is None else now,
            "resumed_at": None,
            "progress": "",
            "note": note[:500],
        },
        held_by_us=True,
    )


def describe(db: OrmSession, kind: str, ref: str) -> dict[str, Any] | None:
    """What the screens say of a piece of work beside its own state: how many times it was
    taken, when a restart cut it and when it went on, how far it is. None when nothing is known."""
    row = db.get(WorkClaim, (kind, ref))
    if row is None:
        return None
    return {
        "state": row.state,
        "attempts": int(row.attempts or 0),
        "interruptedAt": row.interrupted_at,
        "resumedAt": row.resumed_at,
        "progress": row.progress or "",
        "note": row.note or "",
    }


def of(row: Any, kind: str, ref: str) -> dict[str, Any] | None:
    """``describe`` for a row that was read from the database, in the session it was read in."""
    from sqlalchemy.orm import object_session

    db = object_session(row) if row is not None else None
    return describe(db, kind, ref) if db is not None else None


# --------------------------------------------------------------------------- #
# The heartbeat of this process                                               #
# --------------------------------------------------------------------------- #
def beat(now: float | None = None, *, strict: bool = True) -> int:
    """Say that this process is alive, on every piece a thread of it is doing; a piece it is said
    to hold and that no thread of it does (the thread ended and could not say so) is handed back.
    Returns how many it spoke for. ``strict`` off: every piece under its name is spoken for (the
    tests that hold a piece without a thread)."""
    from .core.db import SessionLocal

    now = time.time() if now is None else now
    with _lock:
        active = set(_active)
    said = 0
    with SessionLocal() as db:
        held = db.execute(
            select(WorkClaim.kind, WorkClaim.ref).where(WorkClaim.holder == HOLDER, WorkClaim.state == "held")
        ).all()
        for kind, ref in held:
            mine = (WorkClaim.kind == kind) & (WorkClaim.ref == ref) & (WorkClaim.holder == HOLDER)
            if not strict or (kind, ref) in active:
                said += db.execute(
                    update(WorkClaim).where(mine, WorkClaim.state == "held").values(beat_at=now)
                ).rowcount
                continue
            db.execute(
                update(WorkClaim)
                .where(mine, WorkClaim.state == "held")
                .values(
                    state="wanted",
                    holder="",
                    beat_at=0,
                    interrupted_at=now,
                    resumed_at=None,
                    progress="",
                    note="Its thread ended without finishing it: started again",
                )
            )
            logger.warning("Work %s %s is held by this process and no thread does it: handed back", kind, ref)
        db.commit()
    return said


def _beat_loop() -> None:
    while not _stopping.wait(BEAT_EVERY):
        try:
            beat()
        except Exception:  # noqa: BLE001 - the next beat tries again
            logger.exception("The heartbeat of the work in progress failed")


def _beat_thread() -> None:
    global _beating
    with _lock:
        if _beating:
            return
        _beating = True
    atexit.register(release_all)
    threading.Thread(target=_beat_loop, name="nik-work-beat", daemon=True).start()


def release_all(now: float | None = None) -> int:
    """Hand back what this process holds, as wanted and due at once: at a clean stop. The try is
    not counted: the work did nothing wrong. Returns how many. Never raises."""
    from .core.db import SessionLocal

    now = time.time() if now is None else now
    _stopping.set()
    try:
        with SessionLocal() as db:
            handed = db.execute(
                update(WorkClaim)
                .where(WorkClaim.holder == HOLDER, WorkClaim.state == "held")
                .values(
                    state="wanted",
                    holder="",
                    beat_at=0,
                    interrupted_at=now,
                    resumed_at=None,
                    attempts=WorkClaim.attempts - 1,
                    progress="",
                    note="The server was stopped while this ran",
                )
            ).rowcount
            # What this process wrote down and did not start yet is due at once too.
            db.execute(
                update(WorkClaim).where(WorkClaim.holder == HOLDER, WorkClaim.state == "wanted").values(beat_at=0)
            )
            db.commit()
            return handed
    except Exception:  # noqa: BLE001 - stopping anyway: the sweeper finds them in STALE_AFTER seconds
        return 0


def orphan_all(db: OrmSession) -> int:
    """Every process of the server this database comes from is gone: the database was brought
    back to a moment, or is the one a standby replayed and now serves from (the caller commits).
    What they held is silent from now on, whatever the clock of that other host said: the sweeper
    of the server that starts takes each piece back at its first pass, by the rule of its kind,
    instead of waiting for a heartbeat written by another clock to look old. Returns how many."""
    return db.execute(update(WorkClaim).where(WorkClaim.state == "held").values(beat_at=0)).rowcount


# --------------------------------------------------------------------------- #
# The sweeper                                                                 #
# --------------------------------------------------------------------------- #
def _aside_sentence(kind: Kind | None, attempts: int) -> str:
    what = kind.label if kind is not None else "this work"
    return (
        f"Set aside: {what} was interrupted {attempts} times and is not tried again by itself. "
        "It may be what stops the worker; ask for it again to try once more"
    )


def take_back(db: OrmSession, now: float) -> list[tuple[str, str, str]]:
    """Take back the work whose holder is gone, each piece once: (kind, ref, what was done), with
    ``again`` | ``failed`` | ``aside``. Commits piece by piece."""
    found = db.execute(
        select(WorkClaim.kind, WorkClaim.ref).where(WorkClaim.state == "held", WorkClaim.beat_at < now - STALE_AFTER)
    ).all()
    done: list[tuple[str, str, str]] = []
    for name, ref in found:
        # Two sweepers may look at once (a lease that ran out late): the one whose update changes the row has it.
        won = db.execute(
            update(WorkClaim)
            .where(
                WorkClaim.kind == name,
                WorkClaim.ref == ref,
                WorkClaim.state == "held",
                WorkClaim.beat_at < now - STALE_AFTER,
            )
            .values(state="wanted", holder="", beat_at=0, interrupted_at=now, resumed_at=None, progress="")
        ).rowcount
        if not won:
            db.commit()
            continue
        row = db.get(WorkClaim, (name, ref))
        db.refresh(row)
        kind = _KINDS.get(name)
        what = "again"
        if int(row.attempts or 0) >= MAX_ATTEMPTS:
            what, sentence = "aside", _aside_sentence(kind, int(row.attempts or 0))
        elif kind is None or kind.rule == "fail":
            what, sentence = "failed", f"{INTERRUPTED}: it could not be gone on with. Ask for it again"
        if what != "again":
            row.state, row.note, row.finished_at = ("aside" if what == "aside" else "failed"), sentence, now
            if kind is not None:
                try:
                    kind.fail(db, ref, sentence)
                except Exception:  # noqa: BLE001 - the claim says it even when the row could not
                    logger.exception("The failure of %s %s could not be written on its row", name, ref)
        else:
            row.note = INTERRUPTED
        db.commit()
        logger.warning("Work %s %s lost its holder: %s", name, ref, what)
        done.append((name, ref, what))
    return done


def start_wanted(db: OrmSession, now: float) -> list[tuple[str, str]]:
    """Start here the work that is wanted and that nobody took. Returns what was started."""
    if stopping():
        return []
    found = db.execute(
        select(WorkClaim.kind, WorkClaim.ref, WorkClaim.params).where(
            WorkClaim.state == "wanted", WorkClaim.beat_at < now - WANTED_GRACE
        )
    ).all()
    started: list[tuple[str, str]] = []
    for name, ref, params in found:
        kind = _KINDS.get(name)
        if kind is None:
            continue
        tried = db.execute(select(WorkClaim.attempts).where(WorkClaim.kind == name, WorkClaim.ref == ref)).scalar()
        if int(tried or 0) >= MAX_ATTEMPTS:
            # Handed back by its own process as many times as it may be tried: not a fourth time.
            sentence = _aside_sentence(kind, int(tried or 0))
            won = db.execute(
                update(WorkClaim)
                .where(WorkClaim.kind == name, WorkClaim.ref == ref, WorkClaim.state == "wanted")
                .values(state="aside", note=sentence, finished_at=now)
            ).rowcount
            if won:
                kind.fail(db, ref, sentence)
            db.commit()
            continue
        if kind.rule == "fail":
            # Written down and never taken, and nothing to start it from: the process that held its
            # bytes is gone.
            sentence = f"{INTERRUPTED}: it could not be gone on with. Ask for it again"
            won = db.execute(
                update(WorkClaim)
                .where(WorkClaim.kind == name, WorkClaim.ref == ref, WorkClaim.state == "wanted")
                .values(state="failed", note=sentence, finished_at=now, interrupted_at=now)
            ).rowcount
            if won:
                kind.fail(db, ref, sentence)
            db.commit()
            continue
        won = db.execute(
            update(WorkClaim)
            .where(
                WorkClaim.kind == name,
                WorkClaim.ref == ref,
                WorkClaim.state == "wanted",
                WorkClaim.beat_at < now - WANTED_GRACE,
            )
            .values(holder=HOLDER, beat_at=now)
        ).rowcount
        db.commit()
        if not won:
            continue
        try:
            if kind.start(ref, dict(params or {})) is False:
                db.execute(
                    update(WorkClaim)
                    .where(WorkClaim.kind == name, WorkClaim.ref == ref, WorkClaim.state == "wanted")
                    .values(state="done", finished_at=now)
                )
                db.commit()
                continue
            started.append((name, ref))
        except Exception:  # noqa: BLE001 - one piece must not stop the others; it is due again later
            logger.exception("The work %s %s could not be started again", name, ref)
    return started


def prune(db: OrmSession, now: float) -> int:
    gone = db.execute(
        delete(WorkClaim).where(WorkClaim.state.notin_(ACTIVE), WorkClaim.finished_at < now - KEPT_SECONDS)
    ).rowcount
    db.commit()
    return gone


def sweep(now: float | None = None, holder: str = HOLDER) -> dict[str, Any]:
    """One pass of the sweeper, when this process holds its lease."""
    from .core.db import SessionLocal

    now = time.time() if now is None else now
    with SessionLocal() as db:
        if not leases.take(db, LEASE, holder, LEASE_SECONDS, now):
            return {"taken_back": [], "started": []}
        return {"taken_back": take_back(db, now), "started": start_wanted(db, now)}


def facts(db: OrmSession, now: float) -> dict[str, Any]:
    """What the health page says of the work in progress."""
    aside = db.execute(select(WorkClaim.kind, WorkClaim.ref).where(WorkClaim.state == "aside")).all()
    oldest = db.execute(select(WorkClaim.beat_at).where(WorkClaim.state == "held").order_by(WorkClaim.beat_at)).first()
    held = db.execute(select(WorkClaim.kind).where(WorkClaim.state == "held")).all()
    return {
        "aside": [(kind, ref) for kind, ref in aside],
        "held": len(held),
        "silent": max(0.0, now - float(oldest[0])) if oldest else 0.0,
    }


def _loop() -> None:
    pruned = 0.0
    _stopping.wait(5)  # let the API start
    while not _stopping.is_set():
        try:
            sweep()
            if time.time() - pruned > 3600:
                pruned = time.time()
                from .core.db import SessionLocal

                with SessionLocal() as db:
                    prune(db, pruned)
        except Exception:  # noqa: BLE001 - the sweeper must survive a bad pass
            logger.exception("A pass of the sweeper of the work in progress failed")
        _stopping.wait(SWEEP_EVERY)


def start() -> None:
    """Start the sweeper and the heartbeat in this process (the API process: it is the one that can
    start the work again)."""
    global _started
    if _started:
        return
    _started = True
    _beat_thread()
    threading.Thread(target=_loop, name="nik-work-sweeper", daemon=True).start()
