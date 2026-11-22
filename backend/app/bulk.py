"""One action asked of many incidents, artifacts or indicators at once.

A person selects rows of a list, or everything a filter keeps, and asks for
one action on all of them. That is a **bulk job**: a row of ``bulk_jobs`` and
one row of ``bulk_items`` for each thing selected, written in the transaction
of the request.

**Each item goes through what a single change goes through.** An action is a
function of one item (``bulk_incidents.py``, ``bulk_artifacts.py``,
``bulk_indicators.py``) that calls the service function the single action
calls: the same checks, the same audit entry, the same events, the same
mirroring. Nothing here updates many rows with one statement. So a job leaves
one audit entry per item it changed, each ending with the job
(``core/origin.py``), and one entry of its own when it starts and when it ends.

**Each item is its own commit**, and that commit holds the state of the item
too: done, skipped (it was so already, or the action is not for it), refused
(a permission, a rule of the field: with the sentence) or failed. Nothing is
rolled back when an item fails; the others go on. So a job that is cut goes on
from the first item that is still pending, and does nothing twice.

**Small jobs end in the request** (``inlineItems`` items or fewer); larger
ones are work in progress like the others (``work.py``): wanted in the
request's transaction, held with a heartbeat by the process that does it,
taken again by another process after a restart. The loop takes a lease of its
own for the job (``core/leases.py``), so it never runs twice and never on a
server that does not serve, and it looks at the stop flag between two items.

**Selection by query** is resolved to ids when the job is made. The count is
shown first (``plan``) and sent back with the request: a selection that grew
or shrank meanwhile is answered with the count it has now instead of being
acted on. A job holds ``maxItems`` items at most.

**No stampede.** A change made by a job writes the same events as a change
made alone, marked with the job. The job does not write them faster than the
engine reads them: while a playbook waits for an event, before an item that
writes events the job waits while the outbox holds a tick's worth of events
not yet read, or while the server is at its ceiling of active runs
(``Pace``). An engine that is slow is waited for as
long as it moves; one that does not move at all for a minute does not hold a
job for ever: the job goes on, and says that it went on without it.

One job at a time per person and per list.
"""

from __future__ import annotations

import csv
import io
import logging
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import work
from .core import audit, clock, leases, origin
from .core.ids import new_id
from .core.models import ApiKey, AutomationEvent, BulkItem, BulkJob, Run, Setting, User
from .core.permissions import stored_roles
from .core.security import Principal

logger = logging.getLogger("nik.bulk")

SETTINGS_ID = 100
DEFAULTS = {"maxItems": 5000, "inlineItems": 50, "typedAbove": 100}
BOUNDS = {"maxItems": (1, 50_000), "inlineItems": (0, 500), "typedAbove": (1, 50_000)}
KIND = "bulk"
LEASE_SECONDS = 30
KEPT_SECONDS = 30 * 86400
STATES = ("done", "skipped", "refused", "failed")
ENDED = ("done", "cancelled", "failed")
# How many events not yet read the outbox may hold before a job waits: what the worker reads in a tick.
EVENTS_AHEAD = 50
# How long a job waits for an engine that does not move before it goes on without it; and each look.
PATIENCE = 60.0
PACE_STEP = 0.25
# How many runs a "run a playbook on each" keeps unfinished at a time.
RUNS_AHEAD = 20
CSV_COLUMNS = ("item", "name", "result", "note")


class BulkError(Exception):
    """Why a bulk job cannot be made, as a sentence for the person who asked."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message, self.status = message, status


class Skipped(Exception):
    """The item is left as it is: it was so already, or the action is not for it."""


class Refused(Exception):
    """The item may not be changed this way: a permission, a rule. The sentence says which."""


@dataclass(frozen=True)
class Action:
    """One thing that can be done to many items of a list.

    ``apply(db, ref, params, caller)`` does it to one item, in the session it is given and
    without committing; it returns a note for the result ("" for none), or raises ``Skipped`` or
    ``Refused`` with a sentence. An ``HTTPException`` of the service function it calls is a
    refusal too, with the sentence the single action would have answered.

    ``clean(db, params, caller)`` checks what was asked once, before any item, and returns the
    parameters as they are kept (raises ``BulkError``). ``describe(params)`` says the action in
    words. ``plan(db, refs, params, caller)`` says what the confirmation shows beyond the count:
    ``{"applies": n, "notes": [sentence, …]}``. ``whole(db, job, refs, caller)`` is for an action
    that is one piece of work on the whole selection (a check of indicators is one queue): it
    returns ``{ref: (state, note)}`` and no item is applied one by one.
    """

    name: str
    label: str
    permission: str
    apply: Callable[[OrmSession, str, dict[str, Any], Principal], str | None] | None = None
    clean: Callable[[OrmSession, dict[str, Any], Principal], dict[str, Any]] | None = None
    describe: Callable[[dict[str, Any]], str] | None = None
    plan: Callable[[OrmSession, list[str], dict[str, Any], Principal], dict[str, Any]] | None = None
    whole: Callable[[OrmSession, BulkJob, list[str], Principal], dict[str, tuple[str, str]]] | None = None
    # It cannot be undone: asked with the typed confirmation, whatever the number.
    destructive: bool = False
    # Asked with the typed confirmation above ``typedAbove`` items when this says so of its parameters.
    grave: Callable[[dict[str, Any]], bool] | None = None
    # Its changes write events the playbooks read: the job keeps to the pace of the engine.
    events: bool = False
    # The word of the typed confirmation: "delete 12".
    verb: str = ""
    # A limit of its own the job waits behind, besides the pace of the engine (the runs a "run a
    # playbook on each" has unfinished).
    crowded: Callable[[OrmSession], bool] | None = None


@dataclass(frozen=True)
class Listing:
    """A list whose rows can be selected: how a selection becomes items, and what can be done."""

    name: str
    noun: tuple[str, str]  # ("incident", "incidents")
    # (db, caller, ids, query) → [(ref, name)], in the order of the list.
    resolve: Callable[[OrmSession, Principal, list[str] | None, dict[str, Any] | None], list[tuple[str, str]]]
    actions: dict[str, Action] = field(default_factory=dict)

    def add(self, action: Action) -> None:
        self.actions[action.name] = action


_LISTS: dict[str, Listing] = {}


def register(listing: Listing) -> Listing:
    _LISTS[listing.name] = listing
    return listing


def listings() -> dict[str, Listing]:
    """The lists, with their actions (the three modules register themselves when imported)."""
    from . import bulk_artifacts, bulk_incidents, bulk_indicators  # noqa: F401 - they register

    return dict(_LISTS)


def counted(count: int, noun: tuple[str, str]) -> str:
    return f"{count} {noun[0] if count == 1 else noun[1]}"


# --------------------------------------------------------------------------- #
# The setting                                                                 #
# --------------------------------------------------------------------------- #
def config(db: OrmSession) -> dict[str, int]:
    row = db.get(Setting, SETTINGS_ID)
    held = row.doc if row is not None and isinstance(row.doc, dict) else {}
    return {key: int(held.get(key, value)) for key, value in DEFAULTS.items()}


def save_config(db: OrmSession, body: dict[str, Any]) -> dict[str, int]:
    """Keep the setting (the caller commits and writes the audit entry). Raises ``BulkError``."""
    doc = config(db)
    for key, (least, most) in BOUNDS.items():
        if body.get(key) is None:
            continue
        value = body[key]
        if isinstance(value, bool) or not isinstance(value, int) or not least <= value <= most:
            raise BulkError(f"{key} is a whole number between {least} and {most}")
        doc[key] = value
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc=doc))
    else:
        row.doc = doc
        flag_modified(row, "doc")
    return doc


# --------------------------------------------------------------------------- #
# What is asked: the plan, the job                                            #
# --------------------------------------------------------------------------- #
def _asked(
    db: OrmSession, listing: Listing, name: str, params: dict[str, Any] | None, caller: Principal
) -> tuple[Action, dict[str, Any]]:
    action = listing.actions.get(str(name or ""))
    if action is None:
        raise BulkError(f"There is no such action on {listing.noun[1]}: " + ", ".join(sorted(listing.actions)), 422)
    if not caller.has(action.permission):
        raise BulkError("You do not have the permission this needs", 403)
    params = dict(params or {})
    return action, (action.clean(db, params, caller) if action.clean else {})


def _selected(
    db: OrmSession, listing: Listing, caller: Principal, ids: list[str] | None, query: dict[str, Any] | None
) -> list[tuple[str, str]]:
    if (ids is None) == (query is None):
        raise BulkError("Say which: ids, or the query that selects them", 422)
    if ids is not None and not ids:
        raise BulkError("Nothing is selected", 422)
    return listing.resolve(db, caller, list(dict.fromkeys(ids)) if ids is not None else None, query)


def typed_phrase(action: Action, params: dict[str, Any], count: int, cfg: dict[str, int]) -> str | None:
    """What a person types to confirm, when the action asks for it: ``delete 12``."""
    grave = action.destructive or (action.grave is not None and action.grave(params) and count > cfg["typedAbove"])
    return f"{action.verb or action.name} {count}" if grave else None


def plan(
    db: OrmSession,
    list_name: str,
    name: str,
    params: dict[str, Any] | None,
    caller: Principal,
    ids: list[str] | None,
    query: dict[str, Any] | None,
) -> dict[str, Any]:
    """What a bulk action would do, before it is asked for: how many items, how many of them it
    applies to, what it sets in motion, and what must be typed to confirm it."""
    listing = listings()[list_name]
    action, params = _asked(db, listing, name, params, caller)
    items = _selected(db, listing, caller, ids, query)
    cfg = config(db)
    refs = [ref for ref, _name in items]
    extra = action.plan(db, refs, params, caller) if action.plan and len(refs) <= cfg["maxItems"] else {}
    return {
        "list": list_name,
        "action": action.name,
        "label": label_of(listing, action, params, len(refs)),
        "count": len(refs),
        "applies": int(extra.get("applies", len(refs))),
        "notes": list(extra.get("notes") or []),
        "limit": cfg["maxItems"],
        "over": len(refs) > cfg["maxItems"],
        "inline": len(refs) <= cfg["inlineItems"],
        "typed": typed_phrase(action, params, len(refs), cfg),
        "refs": refs,
    }


def label_of(listing: Listing, action: Action, params: dict[str, Any], count: int) -> str:
    said = action.describe(params) if action.describe else action.label
    return f"{said}: {counted(count, listing.noun)}"[:300]


def running_of(db: OrmSession, actor: str, list_name: str) -> BulkJob | None:
    return db.scalar(
        select(BulkJob).where(BulkJob.actor == actor, BulkJob.list == list_name, BulkJob.state == "running").limit(1)
    )


def start(
    db: OrmSession,
    list_name: str,
    name: str,
    params: dict[str, Any] | None,
    caller: Principal,
    ids: list[str] | None,
    query: dict[str, Any] | None,
    confirm: dict[str, Any] | None = None,
    *,
    retry_of: str | None = None,
    now: float | None = None,
) -> BulkJob:
    """Make a job and commit it, with its items and its claim. Raises ``BulkError``."""
    now = time.time() if now is None else now
    listing = listings()[list_name]
    action, params = _asked(db, listing, name, params, caller)
    items = _selected(db, listing, caller, ids, query)
    cfg = config(db)
    confirm = confirm or {}
    if not items:
        raise BulkError(f"No {listing.noun[0]} is selected by that", 422)
    if len(items) > cfg["maxItems"]:
        raise BulkError(
            f"That is {counted(len(items), listing.noun)}: a bulk action takes {cfg['maxItems']} at most. "
            "Narrow the filter and do it in parts",
            422,
        )
    if query is not None and confirm.get("count") != len(items):
        # What the person was shown is not what is there now: they look again before anything is done.
        raise BulkError(
            f"The selection is {counted(len(items), listing.noun)} now, not {confirm.get('count')}: look at it again",
            409,
        )
    phrase = typed_phrase(action, params, len(items), cfg)
    if phrase and retry_of is None and str(confirm.get("typed") or "").strip() != phrase:
        raise BulkError(f'To confirm, type "{phrase}"', 409)
    mine = running_of(db, caller.actor, list_name)
    if mine is not None:
        raise BulkError(
            f"A bulk action of yours on {listing.noun[1]} is still running ({mine.label}): wait for it, or cancel it",
            409,
        )
    prune(db, now)
    job = BulkJob(
        id=new_id(),
        list=list_name,
        action=action.name,
        params=params,
        label=label_of(listing, action, params, len(items)),
        actor=caller.actor,
        selection={"query": query} if query is not None else {"ids": len(items)},
        state="running",
        total=len(items),
        retry_of=retry_of,
        created_at=clock.iso(now),
        updated_at=now,
    )
    db.add(job)
    db.flush()
    db.add_all(
        BulkItem(job_id=job.id, seq=index, ref=ref[:1100], name=name[:300]) for index, (ref, name) in enumerate(items)
    )
    selected = f"the query {query}" if query is not None else "selected one by one"
    audit.record(db, caller.actor, "bulk.start", f"Bulk job {job.id[:8]}: {job.label} ({selected})", target=job.id)
    # Wanted with the job: it exists even if this process stops before the first item.
    work.want(db, KIND, job.id, now=now)
    db.commit()
    return job


def retry(db: OrmSession, job: BulkJob, caller: Principal) -> BulkJob:
    """A new job on what an ended one did not do: its failed items, and those it never reached."""
    if job.state not in ENDED:
        raise BulkError("This job is still running", 409)
    refs = list(
        db.scalars(
            select(BulkItem.ref)
            .where(BulkItem.job_id == job.id, BulkItem.state.in_(("failed", "pending")))
            .order_by(BulkItem.seq)
        )
    )
    if not refs:
        raise BulkError("Nothing of this job failed or was left undone", 409)
    return start(db, job.list, job.action, job.params, caller, refs, None, retry_of=job.id)


def cancel(db: OrmSession, job: BulkJob, actor: str) -> None:
    """Ask a running job to stop (the caller commits): what was done stays."""
    if job.state != "running":
        return
    job.cancel = True
    audit.record(db, actor, "bulk.cancel", f"Asked the bulk job {job.id[:8]} to stop: {job.label}", target=job.id)


def prune(db: OrmSession, now: float) -> int:
    """Forget the jobs that ended more than a month ago, with their items (the caller commits)."""
    old = list(
        db.scalars(
            select(BulkJob.id).where(BulkJob.state.in_(ENDED), BulkJob.updated_at < now - KEPT_SECONDS).limit(200)
        )
    )
    if old:
        db.execute(delete(BulkItem).where(BulkItem.job_id.in_(old)))
        db.execute(delete(BulkJob).where(BulkJob.id.in_(old)))
    return len(old)


# --------------------------------------------------------------------------- #
# Reading a job                                                               #
# --------------------------------------------------------------------------- #
def out(db: OrmSession, job: BulkJob) -> dict[str, Any]:
    pending = job.total - job.done - job.skipped - job.refused - job.failed
    return {
        "id": job.id,
        "list": job.list,
        "action": job.action,
        "params": job.params or {},
        "label": job.label,
        "actor": job.actor,
        "selection": job.selection or {},
        "state": job.state,
        "cancelling": bool(job.cancel and job.state == "running"),
        "total": job.total,
        "done": job.done,
        "skipped": job.skipped,
        "refused": job.refused,
        "failed": job.failed,
        "pending": max(0, pending),
        "note": job.note or "",
        "retryOf": job.retry_of,
        "createdAt": job.created_at,
        "finishedAt": job.finished_at,
        # What restarts did to it (work.py).
        "work": work.describe(db, KIND, job.id),
    }


def items_out(db: OrmSession, job: BulkJob, state: str | None = None, offset: int = 0, limit: int = 200) -> list[dict]:
    wanted = select(BulkItem).where(BulkItem.job_id == job.id)
    if state:
        wanted = wanted.where(BulkItem.state == state)
    rows = db.scalars(wanted.order_by(BulkItem.seq).offset(offset).limit(limit))
    return [{"ref": row.ref, "name": row.name, "state": row.state, "note": row.note} for row in rows]


def _csv_safe(value: str) -> str:
    """A cell a spreadsheet does not read as a formula."""
    return "'" + value if value[:1] in ("=", "+", "-", "@", "\t", "\r") else value


def result_csv(db: OrmSession, job: BulkJob) -> str:
    """What the job did, item by item."""
    text = io.StringIO()
    writer = csv.writer(text, lineterminator="\r\n")
    writer.writerow(CSV_COLUMNS)
    rows = db.execute(
        select(BulkItem.ref, BulkItem.name, BulkItem.state, BulkItem.note)
        .where(BulkItem.job_id == job.id)
        .order_by(BulkItem.seq)
    )
    for ref, name, state, note in rows:
        writer.writerow([_csv_safe(ref), _csv_safe(name), "not done" if state == "pending" else state, _csv_safe(note)])
    return text.getvalue()


# --------------------------------------------------------------------------- #
# Running                                                                     #
# --------------------------------------------------------------------------- #
def caller_of(db: OrmSession, job: BulkJob) -> Principal | None:
    """Who asked for the job, with the roles they hold **now**: a person whose roles were taken
    away while their job ran, or a key that was revoked, does nothing more through it."""
    if job.actor.startswith("api:"):
        for key in db.scalars(select(ApiKey).where(ApiKey.label == job.actor[4:], ApiKey.revoked_at.is_(None))):
            if not key.expires_at or clock.stamp(key.expires_at) > time.time():
                return Principal(kind="apikey", actor=job.actor, roles=stored_roles(key.roles))
        return None
    user = db.scalar(select(User).where(User.username == job.actor))
    if user is None or user.disabled:
        return None
    return Principal(kind="user", actor=user.username, roles=stored_roles(user.roles), user=user)


def _backlog(db: OrmSession) -> int:
    return db.scalar(select(func.count()).select_from(AutomationEvent).where(AutomationEvent.done.is_(False))) or 0


def _active_runs(db: OrmSession) -> int:
    from .automation import engine

    return (
        db.scalar(select(func.count()).select_from(Run).where(Run.status.notin_(engine.FINISHED), Run.debug.is_(False)))
        or 0
    )


def engine_reads(db: OrmSession, now: float) -> bool:
    """Whether a worker is turning events into runs at this moment: only then is there a pace to keep to."""
    from .automation import state
    from .automation import worker as automation_worker
    from .core.config import settings

    if settings.AUTOMATION_WORKER == "off" or not state.enabled(db):
        return False
    return bool(leases.holder_of(db, automation_worker.LEASE, now))


def listens(db: OrmSession) -> bool:
    """Whether a playbook that is on waits for an event. When none does, the events of a job start
    nothing: there is no pace to keep to, and the job is not slowed down for it."""
    from .automation import triggers
    from .core.models import Playbook

    on = select(Playbook).where(Playbook.enabled.is_(True), Playbook.current_version.isnot(None))
    return any(triggers.trigger_config(db, playbook).get("event") for playbook in db.scalars(on))


# How long what ``listens`` said is believed before it is asked again.
LISTENS_FOR = 15.0


class Pace:
    """What keeps a job from writing events faster than the engine reads them.

    Before an item that writes events the job waits while the outbox holds ``EVENTS_AHEAD``
    events not yet read, or while those and the runs in progress together reach the ceiling of
    the server (an event that finds the server at its ceiling starts nothing). While the engine
    moves (the numbers change from one look to the next) it is waited for, however slow. When
    nothing moves for ``PATIENCE`` seconds the job goes on, for good, and says so.
    """

    def __init__(self, pause: Callable[[float], bool] | None = None) -> None:
        self.waited, self.gave_up = 0.0, False
        self._pause = pause or leases.wait
        self._seen: tuple[int, int] | None = None
        self.left = False
        self._listens, self._asked = False, 0.0

    def crowded(self, db: OrmSession, more: Callable[[OrmSession], bool] | None = None) -> bool:
        from .core.config import settings

        ahead, active = _backlog(db), _active_runs(db)
        if (ahead, active) != self._seen:
            # The engine read an event or ended a run since the last look: it is slow, not stopped.
            self._seen, self.waited = (ahead, active), 0.0
        if ahead >= EVENTS_AHEAD or ahead + active >= settings.AUTOMATION_MAX_ACTIVE_RUNS:
            return True
        return bool(more is not None and more(db))

    def wait(
        self,
        db: OrmSession,
        more: Callable[[OrmSession], bool] | None = None,
        now: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> bool:
        """Wait for room. False when the process was asked to stop while waiting. A job that is
        cancelled while it waits stops waiting (``cancelled`` says so, and ``left`` remembers it)."""
        self.left = False
        if self.gave_up or not engine_reads(db, time.time() if now is None else now):
            return True
        if more is None:
            # Events only: they matter when a playbook waits for one (asked again every few seconds).
            if not self._asked or time.monotonic() - self._asked > LISTENS_FOR:
                self._listens, self._asked = listens(db), time.monotonic()
            if not self._listens:
                return True
        while self.crowded(db, more):
            if self.waited >= PATIENCE:
                self.gave_up = True
                return True
            if cancelled is not None and cancelled():
                self.left = True
                return True
            if self._pause(PACE_STEP):
                return False
            self.waited += PACE_STEP
            db.rollback()  # the next look reads what the worker committed meanwhile
        return True


GONE_ON = "The automation engine did not keep up: the job went on without waiting for it"


def _mark(db: OrmSession, job_id: str, seq: int, state: str, note: str) -> None:
    """Write what became of an item, with the count of its job, in the transaction that is open."""
    db.execute(
        update(BulkItem)
        .where(BulkItem.job_id == job_id, BulkItem.seq == seq, BulkItem.state == "pending")
        .values(state=state, note=(note or "")[:400])
    )
    db.execute(
        update(BulkJob)
        .where(BulkJob.id == job_id)
        .values({state: getattr(BulkJob, state) + 1, "updated_at": time.time()})
    )


def _sentence(error: HTTPException) -> str:
    detail = error.detail
    if isinstance(detail, dict):
        detail = detail.get("message") or detail.get("detail") or ""
    return str(detail or "Refused")


def one(db: OrmSession, job: BulkJob, action: Action, seq: int, ref: str, caller: Principal | None) -> str:
    """Do the action to one item and commit it with its state. Returns the state."""
    job_id, params = job.id, dict(job.params or {})
    token = origin.bulk.set(job_id)
    try:
        try:
            if caller is None:
                raise Refused("The account that asked for this may not act any more")
            if not caller.has(action.permission):
                raise Refused("You do not have the permission this needs")
            note = action.apply(db, ref, params, caller) or ""
            state = "done"
            _mark(db, job_id, seq, state, note)
            db.commit()
            return state
        except Skipped as said:
            state, note = "skipped", str(said)
        except Refused as said:
            state, note = "refused", str(said)
        except HTTPException as error:
            # What the single action would have answered: a refusal with its sentence, unless the
            # server itself failed.
            state = "refused" if error.status_code < 500 else "failed"
            note = _sentence(error)
        except Exception as error:  # noqa: BLE001 - one item that fails must not stop the others
            from .core.db import connection_lost

            if connection_lost(error):
                raise  # the database went away: the item is not a bad one, and the job is cut
            logger.exception("Bulk job %s: the action %s failed on an item", job_id, action.name)
            state, note = "failed", f"It failed ({type(error).__name__}): the log of the server has the detail"
        db.rollback()
        _mark(db, job_id, seq, state, note)
        db.commit()
        return state
    finally:
        origin.bulk.reset(token)


def _end(db: OrmSession, job_id: str, state: str, note: str = "") -> None:
    job = db.get(BulkJob, job_id)
    db.refresh(job)
    if job.state != "running":
        return
    job.state, job.finished_at, job.updated_at = state, clock.now_iso(), time.time()
    if note:
        job.note = (f"{job.note} · " if job.note else "") + note
        job.note = job.note[:500]
    left = job.total - job.done - job.skipped - job.refused - job.failed
    words = f"{job.done} done, {job.skipped} skipped, {job.refused} refused, {job.failed} failed"
    if left > 0:
        words += f", {left} not done"
    token = origin.bulk.set(None)
    try:
        audit.record(db, job.actor, "bulk.end", f"Bulk job {job.id[:8]} {state}: {job.label}: {words}", target=job.id)
    finally:
        origin.bulk.reset(token)
    db.commit()


def run(job_id: str, *, pause: Callable[[float], bool] | None = None, items: int | None = None) -> str:
    """Work through the pending items of a job, in their order. Returns why it stopped: ``done``,
    ``cancelled``, ``stopping`` (the process was asked to stop, or may not work here: the job is
    left running for the next one), ``gone`` (there is no such job, or it is over) or ``paused``
    (``items`` of them were done: the tests stop a job in the middle with it)."""
    from .core.db import SessionLocal

    with SessionLocal() as db:
        job = db.get(BulkJob, job_id)
        if job is None or job.state != "running":
            return "gone"
        listing = listings().get(job.list)
        action = listing.actions.get(job.action) if listing else None
        if action is None:
            _end(db, job_id, "failed", "This server does not know the action any more")
            return "done"
        pace, did, runs = Pace(pause), 0, []
        db.info["bulk_runs"] = runs
        if action.whole is not None:
            return _whole(db, job, action)

        def asked_to_stop() -> bool:
            return bool(db.scalar(select(BulkJob.cancel).where(BulkJob.id == job_id)))

        while True:
            if work.stopping() or leases.stopping() or not leases.may_work(db):
                return "stopping"
            db.expire_all()
            job = db.get(BulkJob, job_id)
            if job is None or job.state != "running":
                return "gone"
            if job.cancel:
                done = job.done + job.skipped + job.refused + job.failed
                _end(db, job_id, "cancelled", f"Cancelled after {done} of {job.total}: what was done stays")
                return "cancelled"
            if items is not None and did >= items:
                return "paused"
            item = db.execute(
                select(BulkItem.seq, BulkItem.ref)
                .where(BulkItem.job_id == job_id, BulkItem.state == "pending")
                .order_by(BulkItem.seq)
                .limit(1)
            ).first()
            if item is None:
                _end(db, job_id, "done", GONE_ON if pace.gave_up else "")
                return "done"
            if action.events:
                if not pace.wait(db, action.crowded, cancelled=asked_to_stop):
                    return "stopping"
                if pace.left:
                    continue  # cancelled while it waited: the top of the loop ends the job
            one(db, job, action, item.seq, item.ref, caller_of(db, job))
            did += 1


def _whole(db: OrmSession, job: BulkJob, action: Action) -> str:
    """An action that is one piece of work on the whole selection: done once, in one commit with
    the state of every item. Cut before that commit, nothing of it was kept and it is done again."""
    refs = list(db.scalars(select(BulkItem.ref).where(BulkItem.job_id == job.id).order_by(BulkItem.seq)))
    caller = caller_of(db, job)
    job_id = job.id
    token = origin.bulk.set(job_id)
    try:
        if caller is None or not caller.has(action.permission):
            results = {ref: ("refused", "You do not have the permission this needs") for ref in refs}
        else:
            try:
                results = action.whole(db, job, refs, caller)
            except HTTPException as error:
                db.rollback()
                results = {ref: ("refused", _sentence(error)) for ref in refs}
        counts = dict.fromkeys(STATES, 0)
        rows = db.scalars(select(BulkItem).where(BulkItem.job_id == job_id, BulkItem.state == "pending"))
        for row in rows:
            row.state, note = results.get(row.ref, ("skipped", "Left out"))
            row.note = (note or "")[:400]
            counts[row.state] += 1
        db.execute(
            update(BulkJob)
            .where(BulkJob.id == job_id)
            .values({name: getattr(BulkJob, name) + count for name, count in counts.items()})
        )
        db.commit()
    finally:
        origin.bulk.reset(token)
    _end(db, job_id, "done")
    return "done"


def run_held(job_id: str) -> None:
    """``run`` as work in progress. **Across a restart: gone on with.** The job is taken by the
    process that starts next and goes on from its first pending item; an item whose commit was
    cut left nothing, and is done then. Stopped politely (the server stops, or became a standby),
    the job is given back without counting the try."""
    from .core.db import SessionLocal

    lease = f"bulk-{job_id}"
    try:
        with work.hold(KIND, job_id):
            with SessionLocal() as db:
                mine = leases.take(db, lease, work.HOLDER, LEASE_SECONDS)
            why = "stopping"
            if mine:
                try:
                    with leases.Renewing(lease, work.HOLDER, LEASE_SECONDS):
                        why = run(job_id)
                finally:
                    with SessionLocal() as db:
                        leases.release(db, lease, work.HOLDER)
            if why == "stopping":
                work.give_back(KIND, job_id, "The server was stopped while this ran")
    except work.Taken:
        return


def _start_again(ref: str, _params: dict[str, Any]) -> bool:
    from .core.db import SessionLocal

    with SessionLocal() as db:
        job = db.get(BulkJob, ref)
        if job is None or job.state != "running":
            return False
    work.thread(run_held, ref)
    return True


def _fail(db: OrmSession, ref: str, sentence: str) -> None:
    job = db.get(BulkJob, ref)
    if job is None or job.state != "running":
        return
    job.state, job.finished_at, job.updated_at = "failed", clock.now_iso(), time.time()
    job.note = f"{sentence}. What was done stays: try again on what was not"[:500]


work.register(work.Kind(KIND, "a bulk action", "again", start=_start_again, fail=_fail))


def facts(db: OrmSession) -> dict[str, int]:
    """What the health page says of the bulk jobs."""
    states = dict(db.execute(select(BulkJob.state, func.count()).group_by(BulkJob.state)).all())
    return {"running": int(states.get("running", 0)), "failed": int(states.get("failed", 0))}


def names_of(pairs: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(str(ref), str(name or "")) for ref, name in pairs]
