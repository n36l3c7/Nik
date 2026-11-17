"""The automation worker: the loop that makes runs go.

    python -m app.automation.worker        the `automation` container

One pass (``tick``), every second, while holding the ``automation`` lease so
two workers never both schedule:

1. With the general switch off: nothing, runs keep their state.
2. Events of the outbox become runs (triggers.handle_event).
3. Schedules that are due start their runs.
4. Steps that are due are claimed and executed, a few at a time.
5. Approvals whose wait ended are answered "expired"; runs past their
   deadline fail; a step whose worker died is taken back; old runs go.

The same loop runs as a thread of the API process with
``AUTOMATION_WORKER=inline`` (tests, a single-container install).
"""

from __future__ import annotations

import logging
import shutil
import signal
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from sqlalchemy import delete, insert, or_, select, update
from sqlalchemy.exc import IntegrityError

from ..core.config import settings
from ..core.db import SessionLocal
from ..core.models import Approval, AutomationEvent, Lease, Playbook, Run, RunStep
from . import actions, engine, graph, state, triggers

logger = logging.getLogger("nik.automation")
LEASE = "automation"
LEASE_SECONDS = 30
HOLDER = uuid.uuid4().hex
TICK_SECONDS = 1.0
EVENTS_PER_TICK = 50
EVENT_KEPT_SECONDS = 86400
# The disk that holds the evidence is "low" under this much free space; said once in this long.
STORAGE_LOW_PERCENT = 10
STORAGE_LOW_EVERY = 86400
STORAGE_LOOK_EVERY = 60
_storage_looked = 0.0
_started = False
_stopping = threading.Event()
_in_flight: set[str] = set()


def acquire(db, holder: str = HOLDER, now: float | None = None) -> bool:
    """Take or renew the lease; False while another worker holds it."""
    now = time.time() if now is None else now
    taken = db.execute(
        update(Lease)
        .where(Lease.name == LEASE, or_(Lease.holder == holder, Lease.expires_at < now))
        .values(holder=holder, expires_at=now + LEASE_SECONDS)
    ).rowcount
    if taken:
        db.commit()
        return True
    try:
        db.execute(insert(Lease).values(name=LEASE, holder=holder, expires_at=now + LEASE_SECONDS))
        db.commit()
        return True
    except IntegrityError:
        db.rollback()
        return False


def release(db, holder: str = HOLDER) -> None:
    db.execute(delete(Lease).where(Lease.name == LEASE, Lease.holder == holder))
    db.commit()


# --------------------------------------------------------------------------- #
# One pass                                                                    #
# --------------------------------------------------------------------------- #
def take_events(db, now: float) -> int:
    """Turn the pending events into runs, oldest first."""
    events = db.scalars(
        select(AutomationEvent)
        .where(AutomationEvent.done.is_(False))
        .order_by(AutomationEvent.created_at)
        .limit(EVENTS_PER_TICK)
    ).all()
    started = 0
    for event in events:
        try:
            started += len(triggers.handle_event(db, event, now))
            event.done = True
            event.claimed_at = now
            db.commit()
        except Exception:  # noqa: BLE001 - one bad event must not stop the others
            db.rollback()
            logger.exception("Event %s could not be handled", event.id)
            event = db.get(AutomationEvent, event.id)
            if event is not None:
                event.done = True
                db.commit()
    return started


def claim_steps(db, now: float, limit: int, holder: str = HOLDER) -> list[str]:
    """Mark due steps as running and ours. Another worker's claim is skipped, not waited for."""
    due = or_(RunStep.status == "pending", (RunStep.status == "waiting") & RunStep.next_at.isnot(None))
    stmt = (
        select(RunStep)
        .where(due, RunStep.next_at <= now)
        .order_by(RunStep.next_at, RunStep.run_id, RunStep.seq)  # the same order on every database
        .limit(limit)
        .with_for_update(skip_locked=True)
    )
    claimed = []
    for step in db.scalars(stmt):
        step.status = "running"
        step.claimed_by = holder
        step.claimed_at = now
        claimed.append(step.id)
    db.commit()
    return claimed


def run_step(step_id: str, now: float | None = None) -> None:
    """Execute one claimed step in a session of its own."""
    with SessionLocal() as db:
        step = db.get(RunStep, step_id)
        run = db.get(Run, step.run_id) if step else None
        token = triggers.current_run.set((run.id, int((run.trigger or {}).get("depth") or 0)) if run else None)
        try:
            engine.execute(db, step_id, time.time() if now is None else now)
        except Exception:  # noqa: BLE001
            db.rollback()
            logger.exception("Step %s could not be executed", step_id)
        finally:
            triggers.current_run.reset(token)


def reclaim(db, now: float) -> int:
    """A step whose worker died while it ran: tried again, unless its outcome cannot be known."""
    taken = 0
    lost = db.scalars(select(RunStep).where(RunStep.status == "running", RunStep.claimed_at.isnot(None))).all()
    for step in lost:
        if (step.claimed_at or 0) + (step.timeout_s or 60) + engine.RECLAIM_GRACE >= now:
            continue
        with engine.serial(db):
            run = engine.locked_run(db, step.run_id)
            if run is None or run.status in engine.FINISHED:
                step.status = "skipped"
                continue
            shape = engine.graph_of(db, run)
            node = graph.nodes_of(shape).get(step.node_id) or {}
            action_id = str((node.get("config") or {}).get("action") or "")
            spec = actions.lookup(db, action_id) if step.kind == "action" else None
            if spec is not None and spec.changes_outside and not spec.idempotent:
                engine._fail(
                    db, run, shape, step, "The worker stopped while this ran: outcome unknown", now, retry=False
                )
            else:
                step.status = "pending"
                step.next_at = now
                step.claimed_by = None
        taken += 1
    db.commit()
    return taken


def housekeeping(db, now: float) -> None:
    """Approvals that ran out of time, runs past their deadline, what is too old to keep."""
    for approval in db.scalars(select(Approval).where(Approval.status == "waiting", Approval.expires_at <= now)).all():
        engine.answer(db, approval, "expired", "", "", now)
        db.commit()
    for run_id in db.scalars(select(Run.id).where(Run.status.notin_(engine.FINISHED), Run.deadline < now)).all():
        with engine.serial(db):
            run = engine.locked_run(db, run_id)
            # An approval being waited for stops the clock.
            if run is not None and run.status == "running" and run.deadline < now:
                engine._finish(db, run, "failed", "The run took longer than the playbook allows", now)
        db.commit()
    reclaim(db, now)
    global _storage_looked
    if abs(now - _storage_looked) >= STORAGE_LOOK_EVERY:
        _storage_looked = now
        storage_low(db, now)
    db.execute(
        delete(AutomationEvent).where(
            AutomationEvent.done.is_(True), AutomationEvent.created_at < engine.iso(now - EVENT_KEPT_SECONDS)
        )
    )
    db.commit()


def storage_low(db, now: float, usage=shutil.disk_usage) -> bool:
    """Write ``storage.low`` when the disk of the evidence has less than a tenth
    free, once a day for as long as it stays so. Says whether it did."""
    if now - float(state.read(db).get("storageLowAt") or 0) < STORAGE_LOW_EVERY:
        return False
    try:
        disk = usage(Path(settings.SAMPLE_STORE))
    except OSError:
        return False
    if not disk.total or disk.free * 100 >= disk.total * STORAGE_LOW_PERCENT:
        return False
    triggers.storage_low(db, disk.total, disk.free)
    state.write(db, storageLowAt=now)
    db.commit()
    return True


def prune(db) -> int:
    """Keep the last runs of each playbook; older ones go with their steps."""
    removed = 0
    keep = max(10, settings.AUTOMATION_RUNS_KEPT)
    for playbook_id in db.scalars(select(Playbook.id)).all():
        old = db.scalars(
            select(Run.id)
            .where(Run.playbook_id == playbook_id, Run.status.in_(engine.FINISHED))
            .order_by(Run.started_at.desc())
            .offset(keep)
        ).all()
        if old:
            db.execute(delete(RunStep).where(RunStep.run_id.in_(old)))
            db.execute(delete(Approval).where(Approval.run_id.in_(old)))
            db.execute(delete(Run).where(Run.id.in_(old)))
            removed += len(old)
    db.commit()
    return removed


def tick(now: float | None = None, *, pool: ThreadPoolExecutor | None = None, holder: str = HOLDER) -> dict:
    """One pass of the worker. Without a pool the steps run here, one after the other (tests)."""
    now = time.time() if now is None else now
    done = {"runs": 0, "steps": 0}
    with SessionLocal() as db:
        if not acquire(db, holder, now):
            return done
        if not state.enabled(db):
            return done
        done["runs"] += take_events(db, now)
        done["runs"] += len(triggers.fire_schedules(db, now))
        db.commit()
        housekeeping(db, now)
        # With a pool, only as many as there are free hands: a slow step does not hold the pass.
        free = (
            settings.AUTOMATION_CONCURRENCY * 4 if pool is None else settings.AUTOMATION_CONCURRENCY - len(_in_flight)
        )
        claimed = claim_steps(db, now, free, holder) if free > 0 else []
    done["steps"] = len(claimed)
    if pool is None:
        for step_id in claimed:
            run_step(step_id, now)
        return done
    for step_id in claimed:
        _in_flight.add(step_id)
        pool.submit(run_step, step_id).add_done_callback(lambda _future, done_id=step_id: _in_flight.discard(done_id))
    return done


def drain(now: float | None = None, limit: int = 200) -> int:
    """Call ``tick`` until nothing is due at ``now`` (tests): the number of steps done."""
    total = 0
    for _ in range(limit):
        done = tick(now)
        total += done["steps"]
        if not done["steps"] and not done["runs"]:
            break
    return total


# --------------------------------------------------------------------------- #
# The loop                                                                    #
# --------------------------------------------------------------------------- #
def loop() -> None:
    last_beat = last_prune = 0.0
    with SessionLocal() as db:
        from .nik_actions import system_user

        system_user(db)  # what a playbook changes in Nik is signed with this account
        db.commit()
    with ThreadPoolExecutor(max_workers=settings.AUTOMATION_CONCURRENCY, thread_name_prefix="nik-step") as pool:
        while not _stopping.is_set():
            started = time.time()
            try:
                tick(pool=pool)
                if started - last_beat >= state.HEARTBEAT_EVERY:
                    with SessionLocal() as db:
                        state.beat(db, started)
                    last_beat = started
                if started - last_prune >= 3600:
                    with SessionLocal() as db:
                        prune(db)
                    last_prune = started
            except Exception:  # noqa: BLE001 - the worker must survive a bad pass
                logger.exception("Automation pass failed")
            _stopping.wait(max(0.05, TICK_SECONDS - (time.time() - started)))
    with SessionLocal() as db:
        release(db)


def start_inline() -> None:
    """The loop as a thread of the API process (AUTOMATION_WORKER=inline)."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=loop, name="nik-automation", daemon=True).start()


def main() -> None:
    from ..core.observability import setup_logging

    setup_logging(settings.LOG_LEVEL)
    # SIGTERM: stop claiming, let the steps in flight finish, release the lease.
    signal.signal(signal.SIGTERM, lambda *_: _stopping.set())
    signal.signal(signal.SIGINT, lambda *_: _stopping.set())
    logger.info("Automation worker started")
    loop()
    logger.info("Automation worker stopped")


if __name__ == "__main__":
    main()
