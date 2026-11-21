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

**Stopping and starting again.** Nothing of the worker is kept outside the
database, so the worker that takes over may be another container, or another
host after a promotion.

- *Asked to stop* (SIGTERM: ``docker compose restart``, ``up -d --build``, the
  host shutting down): it claims nothing more, gives the steps and the cycles
  in flight ``STOP_GRACE`` seconds to finish, gives its leases back and exits.
  What is still in flight then stays ``running`` under its name.
- *Killed* (kill -9, the power): nothing is given back. The lease runs out
  ``LEASE_SECONDS`` after its last renewal.
- *Starting*: the worker that holds the lease is the only one there is, so a
  step that is ``running`` under another name lost its worker. It is taken
  back at once, by the rule of ``engine.take_back`` (tried again, or the run
  waits for a person when the step may have changed something outside). The
  same holds for a change to a mirrored system that was being sent
  (``mirror.take_back``).
- A step this worker claimed and no longer runs (its thread died) is found by
  its age, as before.
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

from sqlalchemy import delete, or_, select

from ..core import leases
from ..core.config import settings
from ..core.db import SessionLocal
from ..core.models import Approval, AutomationEvent, Playbook, Run, RunStep
from . import engine, state, triggers

logger = logging.getLogger("nik.automation")
LEASE = "automation"
LEASE_SECONDS = 30
# How long the steps and cycles in flight are given to finish when the worker is asked to stop.
# Compose gives the container a little more (stop_grace_period) before it kills it.
STOP_GRACE = 25.0
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
# The connections a cycle of fetch is running for.
_fetching: set[str] = set()


def acquire(db, holder: str = HOLDER, now: float | None = None) -> bool:
    """Take or renew the lease; False while another worker holds it."""
    return leases.take(db, LEASE, holder, LEASE_SECONDS, now)


def release(db, holder: str = HOLDER) -> None:
    leases.release(db, LEASE, holder)


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
        except Exception as error:  # noqa: BLE001 - one bad event must not stop the others
            from ..core.db import connection_lost

            if connection_lost(error):
                raise  # the database went away: the event is not a bad one, and waits for the next pass
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


def run_step(step_id: str, now: float | None = None, holder: str = HOLDER) -> None:
    """Execute one claimed step in a session of its own."""
    with SessionLocal() as db:
        step = db.get(RunStep, step_id)
        run = db.get(Run, step.run_id) if step else None
        token = triggers.current_run.set((run.id, int((run.trigger or {}).get("depth") or 0)) if run else None)
        try:
            engine.execute(db, step_id, time.time() if now is None else now, holder)
        except Exception:  # noqa: BLE001
            db.rollback()
            logger.exception("Step %s could not be executed", step_id)
        finally:
            triggers.current_run.reset(token)


def reclaim(db, now: float, holder: str = HOLDER, *, threads: bool = False) -> int:
    """Take back the steps whose worker is gone, by the rule of ``engine.take_back``. Returns how
    many. A step is lost when it is ``running`` under the name of another worker (this one holds
    the lease, so there is no other), or under this worker's name without a thread that runs it:
    with a pool of threads (``threads``) that is known for certain a moment after it was claimed
    (its thread ended and could not write, the database had gone away); without one, when the
    step is past its time."""
    taken = 0
    lost = db.scalars(select(RunStep).where(RunStep.status == "running", RunStep.claimed_at.isnot(None))).all()
    # The worker that was asked to stop wrote its name down before it left: a step it left
    # unfinished was cut by the stop, not by a fall of the worker.
    asked = str((state.read(db).get("stopped") or {}).get("holder") or "") if lost else ""
    for step in lost:
        ours = step.claimed_by == holder
        allowed = engine.RECLAIM_GRACE + (0 if threads else (step.timeout_s or 60))
        if ours and (step.id in _in_flight or (step.claimed_at or 0) + allowed >= now):
            continue
        done = engine.take_back(db, step, now, counted=not asked or step.claimed_by != asked)
        db.commit()
        if done in ("again", "interrupted", "failed"):
            logger.warning("Step %s of run %s lost its worker: %s", step.node_id, step.run_id, done)
            taken += 1
    return taken


def housekeeping(db, now: float, holder: str = HOLDER, *, threads: bool = False) -> None:
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
    # Tasks past their time, questions nobody answered, reminders.
    from .. import tasks, timers

    tasks.tick(db, now)
    # SLA timers: what the type of an incident times, and what is past its time.
    timers.tick(db, now)
    from .. import lists

    if lists.prune(db, now):
        db.commit()
    # Artifacts someone gave a date to: the ones about to go are announced, the ones whose day came go.
    from .. import artifact_expiry

    artifact_expiry.tick(db, now)
    # Debug runs are kept a week.
    from . import debugger

    if debugger.prune(db, now):
        db.commit()
    reclaim(db, now, holder, threads=threads)
    from .. import mirror

    mirror.take_back(db, now, holder)
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


def _store_disk(db, now: float, usage):
    """The room of the disk of the evidence: measured here when this process sees the store, else as
    the API process last measured it (the automation container is given neither the store nor its
    key). None when it is not known."""
    from types import SimpleNamespace

    from .. import store_seal
    from ..core import store

    if store.local() or usage is not shutil.disk_usage:
        try:
            return usage(Path(settings.SAMPLE_STORE))
        except OSError:
            return None
    seen = store_seal.disk_seen(db)
    if not seen or now - float(seen.get("at") or 0) > 3600:
        return None
    return SimpleNamespace(total=int(seen.get("total") or 0), free=int(seen.get("free") or 0))


def storage_low(db, now: float, usage=shutil.disk_usage) -> bool:
    """Write ``storage.low`` when the disk of the evidence has less than a tenth
    free, once a day for as long as it stays so. Says whether it did."""
    if now - float(state.read(db).get("storageLowAt") or 0) < STORAGE_LOW_EVERY:
        return False
    disk = _store_disk(db, now, usage)
    if disk is None or not disk.total or disk.free * 100 >= disk.total * STORAGE_LOW_PERCENT:
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
        housekeeping(db, now, holder, threads=pool is not None)
        # With a pool, only as many as there are free hands: a slow step does not hold the pass.
        free = (
            settings.AUTOMATION_CONCURRENCY * 4 if pool is None else settings.AUTOMATION_CONCURRENCY - len(_in_flight)
        )
        claimed = claim_steps(db, now, free, holder) if free > 0 else []
        from .. import fetch

        fetching = [found for found in fetch.due(db, now) if found not in _fetching]
        from .. import mirror

        # Mirrored incidents to read, and what waits to be sent to the other side.
        reading = [found for found in mirror.due(db, now) if f"in:{found}" not in _fetching]
        sending = [found for found in mirror.jobs_due(db, now) if f"out:{found}" not in _fetching]
    done["steps"] = len(claimed)
    if pool is None:
        for step_id in claimed:
            run_step(step_id, now, holder)
        for connection_id in fetching:
            fetch.run(connection_id, now)
        for incident_id in reading:
            mirror.run_pull(incident_id, now)
        for job_id in sending:
            mirror.run_push(job_id, now, holder)
        return done
    for key, work, wanted in (
        *((f"in:{found}", mirror.run_pull, found) for found in reading),
        *((f"out:{found}", lambda job_id: mirror.run_push(job_id, None, holder), found) for found in sending),
    ):
        _fetching.add(key)
        pool.submit(work, wanted).add_done_callback(lambda _future, done_key=key: _fetching.discard(done_key))
    for connection_id in fetching:
        _fetching.add(connection_id)
        pool.submit(fetch.run, connection_id).add_done_callback(
            lambda _future, done_id=connection_id: _fetching.discard(done_id)
        )
    for step_id in claimed:
        _in_flight.add(step_id)
        pool.submit(run_step, step_id, None, holder).add_done_callback(
            lambda _future, done_id=step_id: _in_flight.discard(done_id)
        )
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
    pool = ThreadPoolExecutor(max_workers=settings.AUTOMATION_CONCURRENCY, thread_name_prefix="nik-step")
    try:
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
    finally:
        left = finish_in_flight(pool)
        if left:
            logger.warning(
                "%d step(s) or cycle(s) were still in flight after %d s: the worker that starts next takes them back",
                left,
                int(STOP_GRACE),
            )
        try:
            with SessionLocal() as db:
                if left:
                    # Said for the worker that starts next: these steps were cut by a stop that was asked for.
                    state.write(db, stopped={"holder": HOLDER, "at": time.time()})
                    db.commit()
                release(db)
        except Exception:  # noqa: BLE001 - stopping anyway: the lease runs out by itself
            logger.warning("The lease of the automation worker could not be given back")


def finish_in_flight(pool: ThreadPoolExecutor, grace: float = STOP_GRACE, pause=time.sleep) -> int:
    """Asked to stop: nothing new is started, and what is in flight gets ``grace`` seconds to
    finish. Returns how many steps and cycles were still in flight after that."""
    pool.shutdown(wait=False, cancel_futures=True)
    waited = 0.0
    while (_in_flight or _fetching) and waited < grace:
        pause(0.2)
        waited += 0.2
    return len(_in_flight) + len(_fetching)


def start_inline() -> None:
    """The loop as a thread of the API process (AUTOMATION_WORKER=inline)."""
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=loop, name="nik-automation", daemon=True).start()


def _wait_for_the_schema() -> None:
    """The backend applies the migrations; this process waits for them. A backend that stopped an
    upgrade (backups/upgrade.py) still answers its health check, so that the web page can say what
    happened: the database is then not the one this code expects, and nothing must run on it."""
    from ..backups import database

    said = False
    while not _stopping.is_set():
        try:
            if database.about()["revision"] == database.head_revision():
                return
        except Exception:  # noqa: BLE001 - the database is not there yet: wait as for a migration
            pass
        if not said:
            logger.warning("The database is not at the revision of this version: waiting for the backend to migrate it")
            said = True
        _stopping.wait(5)


# How long a backend that does not answer is waited for at the start of this process, and how often it is asked.
BACKEND_WAIT, BACKEND_PAUSE = 90, 5


def backend_health() -> str:
    """What the backend answers to its health check: ``ok``, the word of a server that did not
    start (``stopped``: a key is missing or wrong, app/stopped.py; ``upgrade-stopped``:
    backups/upgrade.py), or nothing when it does not answer or this process was not told where it is."""
    # Asked where the files of the store are asked: the address of the API container, on the
    # network of the stack. Nothing of this package opens a connection itself but egress.py.
    from .. import store_handover

    return store_handover.backend_health()


def _wait_for_the_backend() -> None:
    """A backend that did not start says so and stays up (a key is missing, or is not the one the
    store is sealed under; an upgrade was stopped): its health check passes, so this container is
    started. Nothing must run beside a server that refused to: no playbook, no copy of a backup,
    no entry sent to syslog as if all were well. This waits until the backend says it runs.

    A backend that does not answer yet is given a moment: after the host or the engine restarts every
    container starts at once, and the backend is still waiting for the database, migrating, or
    about to say that it will not start. One that still does not answer after that is not waited
    for: this worker runs without it, as before. A process that was not told where the backend is
    (a development server) asks nothing."""
    if not settings.STORE_API_URL:
        return
    said, unanswered = False, 0
    while not _stopping.is_set():
        status = backend_health()
        if status == "ok":
            return
        if not status:
            unanswered += 1
            if unanswered * BACKEND_PAUSE >= BACKEND_WAIT:
                logger.warning("The backend does not answer: this worker goes on without it")
                return
            _stopping.wait(BACKEND_PAUSE)
            continue
        unanswered = 0
        if not said:
            logger.warning("The backend says it did not start (%s): waiting. Its log and the page say why", status)
            said = True
        _stopping.wait(5)


def main() -> None:
    from ..core.observability import setup_logging

    setup_logging(settings.LOG_LEVEL)
    # SIGTERM: stop claiming, let the steps in flight finish, release the lease.
    signal.signal(signal.SIGTERM, lambda *_: _stopping.set())
    signal.signal(signal.SIGINT, lambda *_: _stopping.set())
    logger.info("Automation worker started")
    _wait_for_the_schema()
    # A server of a pair asks the second host first whether it was replaced while it was away,
    # and runs nothing if it was (recovery/role.py): this container is the one that can ask.
    from ..recovery import scheduler as recovery_scheduler

    recovery_scheduler.ask_at_start(_stopping)
    _wait_for_the_backend()
    # The copies of the backups off the server leave from here: this container has the way out.
    from ..backups import scheduler as backup_scheduler

    backup_scheduler.start_shipper()
    # So do the copies of the archive of the log and of the store, for the second host.
    recovery_scheduler.start_shipper()
    # So does the audit log, entry by entry, to the syslog receiver an administrator set.
    from ..auditlog import forward as audit_forward

    audit_forward.start()
    # And the health of the server is looked at from here too, for the day the API process is what is stuck.
    from ..health import watch as health_watch

    health_watch.start()
    loop()
    # Every lease this process took (its own, the copies of the backups, the forwarding of the
    # audit log, the watch of the health) is given back: the worker that starts next waits for none.
    leases.release_all()
    logger.info("Automation worker stopped")
    if _in_flight or _fetching:
        # Threads that did not finish in the grace would hold the process until they do: it exits
        # now, and what they were doing is taken back by the worker that starts next.
        import logging as _logging
        import os

        _logging.shutdown()
        os._exit(0)


if __name__ == "__main__":
    main()
