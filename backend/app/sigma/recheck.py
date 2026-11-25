"""Checking the rules again when the evaluator of the worker is not the one that last checked them.

Whether a rule is supported, and why not, is the worker's judgement, and it changes with the worker:
a new version may run what the old one could not (or no longer run what it did). Each row keeps the
version of the evaluator it was checked with (``engine``); a rule with none was never checked (the
worker was not there when it was saved). When the worker says a version that is not a row's, the row is
checked again, 200 at a time, in the background. Detections already stored are not touched: reading a
file again (Analyse again) is what runs the rules anew.

A rule that was never checked and turns out not to be supported is switched off, so that it is not
listed as on while it cannot run; one that was already checked keeps what a person set.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any

from sqlalchemy import func, select

from .. import work
from ..core.db import SessionLocal
from ..core.models import SigmaRule
from . import checking, rules, worker

logger = logging.getLogger("nik.sigma")
_running = threading.Lock()
FIRST_WAIT = 20
RETRY = 60
EVERY = 600


def stale(db: Any, engine: str) -> int:
    """How many rules were not checked with this version of the evaluator."""
    return db.scalar(select(func.count()).select_from(SigmaRule).where(SigmaRule.engine != engine)) or 0


def run_once() -> int:
    """Check again every rule the worker's version did not check. Returns how many were checked; 0 when
    the worker is not there, has no Sigma, or has nothing to do."""
    engine = worker.engine()
    if not engine or not _running.acquire(blocking=False):
        return 0
    done = 0
    try:
        while True:
            with SessionLocal() as db:
                batch = db.execute(
                    select(SigmaRule.id, SigmaRule.source, SigmaRule.engine)
                    .where(SigmaRule.engine != engine)
                    .order_by(SigmaRule.id)
                    .limit(checking.BATCH)
                ).all()
                if not batch:
                    rules.keep_setting(db, "engine", engine)
                    db.commit()
                    return done
                try:
                    _seen, answered = checking.check([source for _id, source, _engine in batch])
                except checking.Unavailable as error:
                    logger.warning("The rules of Sigma were not checked again: %s", error.message)
                    return done
                for (rule_id, _source, before), held in zip(batch, answered, strict=True):
                    row = db.get(SigmaRule, rule_id)
                    if row is not None:
                        _apply(row, held, engine, first=not before)
                rules.bump(db)
                db.commit()
                done += len(batch)
    finally:
        _running.release()


def _apply(row: SigmaRule, held: dict[str, Any], engine: str, first: bool) -> None:
    info = next((rule for rule in held["rules"] if str(rule.get("id")) == row.id), None)
    if info is None or not isinstance(info.get("source"), str):
        reason = held["errors"][0].get("message") if held["errors"] else "The worker found no rule with this id"
        row.supported, row.reason, row.engine = (
            False,
            f"Not a valid rule: {reason}"[:400],
            engine,
        )
    else:
        for key, value in rules.columns(info, engine).items():
            if key != "source":
                setattr(row, key, value)
    if first and not row.supported:
        row.enabled = False


def start() -> None:
    """The loop of a process of the server: now and then, look whether the worker's evaluator changed."""

    def loop() -> None:
        wait = FIRST_WAIT
        while not work.stopping():
            for _second in range(wait):
                if work.stopping():
                    return
                time.sleep(1)
            try:
                run_once()
                wait = EVERY if worker.engine() else RETRY
            except Exception:
                logger.exception("The check of the rules of Sigma failed")
                wait = RETRY
            worker.forget()

    work.thread(loop)
