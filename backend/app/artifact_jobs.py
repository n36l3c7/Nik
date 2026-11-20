"""What playbooks ask to be done with a file, done by the API process.

An analyst who adds a file or presses "Re-analyse" is served by the API
process: it writes to the store of files and it alone is on the network of
the analysis workers. A playbook's steps are taken by the automation worker,
which reads the store read-only and reaches none of those workers. So the
nodes that keep a file or start an analysis (``automation/file_actions.py``)
write what they want as a row of ``artifact_jobs`` (``ask``), and every API
process looks for such rows every few seconds, takes one at a time with an
update that only one of them wins, and does what the interface would have
done:

- ``store``       keep the bytes the row carries as a file or an e-mail
                  artifact, analysed as an upload is;
- ``attachment``  take an attachment out of an e-mail Nik holds and keep it
                  as a file artifact, as "Send to Malware Analysis" does;
- ``analyse``     analyse an artifact again, as "Re-analyse", "Disassemble"
                  and "Run capa" do.

The node meanwhile gives its step back and asks again later: nothing waits
holding a worker. A job says which run asked for it, so that what it sets off
(``file.analysed``, ``mail.analysed``) starts no playbook on its own doing.

Nothing here runs or opens a file. A file is written under its SHA-256 and
read as bytes by the analyses the product already has.
"""

from __future__ import annotations

import logging
import threading
import time
import uuid
from typing import Any

from fastapi import HTTPException
from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as OrmSession

from . import artifacts
from .core import audit
from .core.locking import lock_incident
from .core.models import Artifact, ArtifactJob, Mail, NetworkCapture, Sample, SampleCapa, SampleCode

logger = logging.getLogger("nik.artifacts")

LOOK_EVERY = 2
# A job nobody took in this long is not done any more: the node that asked gave up before.
TAKE_WITHIN = 600
KEPT_SECONDS = 86400
ANALYSES = ("static", "code", "capabilities")
_started = False


class JobError(Exception):
    """A job that cannot be done, with a sentence for the step that asked."""


class _Later:
    """What a route is given as its background tasks: the calls are collected, and started once the
    job is committed, each in a thread of its own (the disassembly of a sample takes minutes)."""

    def __init__(self) -> None:
        self.tasks: list[tuple[Any, tuple]] = []

    def add_task(self, work: Any, *args: Any) -> None:
        self.tasks.append((work, args))

    def start(self, threads: bool) -> None:
        for work, args in self.tasks:
            if threads:
                threading.Thread(target=work, args=args, name="nik-artifact-analysis", daemon=True).start()
            else:
                work(*args)


def ask(
    db: OrmSession,
    kind: str,
    params: dict[str, Any],
    actor: str,
    run_id: str,
    depth: int,
    now: float,
    data: bytes | None = None,
) -> ArtifactJob:
    """Write down what a run asks for (the caller commits)."""
    row = ArtifactJob(
        id=uuid.uuid4().hex,
        kind=kind,
        status="queued",
        params=params,
        data=data,
        result={},
        actor=actor,
        run_id=run_id,
        depth=depth,
        created_epoch=now,
    )
    db.add(row)
    db.flush()
    return row


def take(db: OrmSession, now: float | None = None) -> str | None:
    """Take one job that waits: its id. None when there is none."""
    now = time.time() if now is None else now
    waiting = db.execute(
        select(ArtifactJob.id, ArtifactJob.created_epoch)
        .where(ArtifactJob.status == "queued")
        .order_by(ArtifactJob.created_epoch)
    ).all()
    for job_id, created in waiting:
        late = now - float(created or 0) > TAKE_WITHIN
        # Several API processes look at once: the one whose update changes the row has it.
        values: dict[str, Any] = {"status": "running"}
        if late:
            values = {"status": "error", "error": "It was not taken in time", "data": None, "finished_epoch": now}
        won = db.execute(
            update(ArtifactJob).where(ArtifactJob.id == job_id, ArtifactJob.status == "queued").values(**values)
        ).rowcount
        db.commit()
        if won and not late:
            return job_id
    return None


# --------------------------------------------------------------------------- #
# The work                                                                    #
# --------------------------------------------------------------------------- #
def _incident(db: OrmSession, params: dict[str, Any]):
    wanted = str(params.get("incident") or "")
    incident = lock_incident(db, wanted) if wanted else None
    if wanted and incident is None:
        raise JobError("The incident does not exist")
    return incident


def _keep_file(
    db: OrmSession,
    job: ArtifactJob,
    data: bytes,
    name: str,
    origin: str,
    parent: tuple[str, str] | None,
    later: _Later,
) -> dict[str, Any]:
    """Keep bytes as a file artifact, as an upload does: the static analysis here and now, the
    disassembly and capa started when their workers are there and the sample is new."""
    from .automation import triggers
    from .routers import samples as sample_routes

    incident = _incident(db, job.params)
    known = db.get(Sample, _sha256(data)) is not None
    try:
        row, _ref = sample_routes.keep_sample(db, incident, data, name, job.actor, origin, parent=parent)
    except HTTPException as error:
        raise JobError(str(error.detail)) from None
    if incident is not None:
        triggers.incident_changed(db, incident, "incident.updated", ["data"])
    db.commit()
    if db.get(SampleCode, row.sha256) is None:
        sample_routes._queue_code(db, later, row.sha256, job.actor)
    if db.get(SampleCapa, row.sha256) is None:
        sample_routes._queue_capa(db, later, row, job.actor)
    return {"kind": "file", "ref": row.sha256, "known": known, "linked": incident is not None}


def _store(db: OrmSession, job: ArtifactJob, later: _Later) -> dict[str, Any]:
    from .mail.parse import MailError
    from .routers import mails as mail_routes

    params, data = job.params, bytes(job.data or b"")
    name, origin = str(params.get("name") or ""), str(params.get("origin") or "")
    if params.get("as") != "mail":
        return _keep_file(db, job, data, name, origin, None, later)
    incident = _incident(db, params)
    known = db.get(Mail, _sha256(data)) is not None
    try:
        row, _ref = mail_routes.keep_mail(db, incident, data, name, job.actor)
    except MailError as error:
        raise JobError(f"It is not an e-mail Nik can read: {error}") from None
    if incident is not None:
        from .automation import triggers

        triggers.incident_changed(db, incident, "incident.updated", ["data"])
    return {"kind": "mail", "ref": row.sha256, "known": known, "linked": incident is not None}


def _sha256(data: bytes) -> str:
    import hashlib

    return hashlib.sha256(data).hexdigest()


def attachments_of(items: list[dict[str, Any]], prefix: str = "") -> list[tuple[str, dict[str, Any]]]:
    """Every attachment of a message with its place ("0", "2.0" inside an attached message)."""
    found: list[tuple[str, dict[str, Any]]] = []
    for index, item in enumerate(items or []):
        path = f"{prefix}{index}"
        found.append((path, item))
        nested = item.get("nested") or item.get("message")
        if isinstance(nested, dict):
            found += attachments_of(nested.get("attachments") or [], path + ".")
    return found


def find_attachment(items: list[dict[str, Any]], wanted: str) -> tuple[str, dict[str, Any]] | None:
    """The attachment a node names, by its place or by its file name (the first that has it)."""
    every = attachments_of(items)
    by_place = next((entry for entry in every if entry[0] == wanted), None)
    return by_place or next((entry for entry in every if str(entry[1].get("name") or "") == wanted), None)


def _attachment(db: OrmSession, job: ArtifactJob, later: _Later) -> dict[str, Any]:
    from .mail.parse import MailError, parse_mail
    from .malware.samples import read_mail

    sha256 = str(job.params.get("mail") or "")
    mail = db.get(Mail, sha256)
    if mail is None:
        raise JobError("The e-mail does not exist")
    try:
        parsed = parse_mail(read_mail(sha256))
    except (OSError, ValueError, MailError):
        raise JobError("The stored message cannot be read") from None
    found = find_attachment(parsed.get("attachments") or [], str(job.params.get("attachment") or ""))
    if found is None:
        raise JobError("The e-mail has no attachment with this name")
    item = found[1]
    origin = f"e-mail “{mail.subject[:80]}”" if mail.subject else f"e-mail {sha256[:12]}…"
    parent = (artifacts.artifact_id("mail", sha256), "attachment")
    result = _keep_file(db, job, item.get("data") or b"", str(item.get("name") or ""), origin, parent, later)
    return {**result, "name": str(item.get("name") or "")}


def _analyse_file(db: OrmSession, job: ArtifactJob, row: Artifact, which: str, later: _Later) -> dict[str, Any]:
    from .routers import samples as sample_routes
    from .workers import analyzer, capa

    sample = db.get(Sample, row.ref)
    if sample is None:
        raise JobError("The file does not exist")
    started: list[str] = []
    skipped: list[dict[str, str]] = []
    said = f"{row.name or sample.sha256} ({sample.sha256[:12]}…)"
    if which in ("", "static"):
        try:
            sample_routes.analyse_again(db, sample)
        except (OSError, ValueError):
            raise JobError("The file could not be read from the store") from None
        audit.record(db, job.actor, "sample.reanalyse", f"Re-analysed sample {said}" + str(job.params.get("by") or ""))
        db.commit()
        started.append("static")
    if which in ("", "code"):
        if analyzer.configured():
            sample_routes._queue_code(db, later, sample.sha256, job.actor)
            started.append("code")
        elif which:
            raise JobError("The analyzer worker is not configured (ANALYZER_URL): the file was not disassembled")
        else:
            skipped.append({"analysis": "code", "reason": "The analyzer worker is not configured (ANALYZER_URL)"})
    if which in ("", "capabilities"):
        if not capa.configured():
            why = "The capa worker is not configured (CAPA_URL)"
        elif not capa.supported(sample.type_id):
            why = "capa analyses x86 and x64 PE and ELF files only"
        else:
            why = ""
        if not why:
            sample_routes._queue_capa(db, later, sample, job.actor)
            started.append("capabilities")
        elif which:
            raise JobError(f"{why}: capa was not run")
        else:
            skipped.append({"analysis": "capabilities", "reason": why})
    return {"started": started, "skipped": skipped}


def _analyse(db: OrmSession, job: ArtifactJob, later: _Later) -> dict[str, Any]:
    from .mail.parse import MailError
    from .network import service as captures
    from .routers import mails as mail_routes

    row = db.get(Artifact, str(job.params.get("artifact") or ""))
    if row is None:
        raise JobError("The artifact does not exist")
    which = str(job.params.get("analysis") or "")
    by = str(job.params.get("by") or "")
    if row.kind == "file":
        return _analyse_file(db, job, row, which, later)
    if row.kind == "mail":
        mail = db.get(Mail, row.ref)
        if mail is None:
            raise JobError("The e-mail does not exist")
        try:
            mail_routes.analyse_again(db, mail)
        except (OSError, ValueError, MailError) as error:
            raise JobError(f"The stored message cannot be analysed: {error}") from None
        audit.record(db, job.actor, "mail.reanalyse", f"Re-analysed e-mail {row.ref[:12]}… ({mail.verdict})" + by)
        return {"started": ["mail"], "skipped": []}
    if row.kind == "pcap":
        capture = db.get(NetworkCapture, row.ref)
        if capture is None:
            raise JobError("The capture does not exist")
        if capture.status == "live":
            raise JobError("The browser session is still open: its capture is analysed when it is closed")
        if not captures.configured():
            raise JobError("The packet capture worker is not configured (PCAP_URL): the capture was not analysed")
        audit.record(db, job.actor, "capture.reanalyse", f"Re-analysed capture {capture.file_name}" + by)
        captures.queue_analysis(db, capture, later)
        return {"started": ["capture"], "skipped": []}
    raise JobError("Only a file, an e-mail or a capture is analysed again this way")


_WORK = {"store": _store, "attachment": _attachment, "analyse": _analyse}


def _run(job_id: str, threads: bool) -> None:
    from .automation import triggers
    from .core.db import SessionLocal

    later = _Later()
    with SessionLocal() as db:
        job = db.get(ArtifactJob, job_id)
        if job is None:
            return
        # What the job sets off is caused by the run that asked: no loop starts from it.
        token = triggers.current_run.set((job.run_id, int(job.depth or 0)) if job.run_id else None)
        try:
            result, error = _WORK[job.kind](db, job, later), None
            db.flush()
        except JobError as failed:
            db.rollback()
            result, error = {}, str(failed)
        except Exception:  # noqa: BLE001 - one bad job must not stop the others
            db.rollback()
            logger.exception("The job %s a playbook asked for failed", job_id)
            result, error = {}, "It failed for a reason Nik did not expect: see the server's log"
        finally:
            triggers.current_run.reset(token)
        job = db.get(ArtifactJob, job_id)
        if job is not None:
            job.status, job.error, job.result = ("error" if error else "done"), error, result
            job.data, job.finished_epoch = None, time.time()
        db.commit()
    if not error:
        later.start(threads)


def run_due(limit: int = 20, *, threads: bool = True, now: float | None = None) -> int:
    """Do the jobs that were asked for, one after the other. Returns how many. The analyses a job
    starts on a worker run each in a thread of its own (``threads`` off: here, one by one, for tests)."""
    from .core.db import SessionLocal

    done = 0
    while done < limit:
        with SessionLocal() as db:
            taken = take(db, now)
        if taken is None:
            break
        _run(taken, threads)
        done += 1
    return done


def prune(now: float | None = None) -> int:
    """Drop the jobs made more than a day ago."""
    from .core.db import SessionLocal

    now = time.time() if now is None else now
    with SessionLocal() as db:
        gone = db.execute(delete(ArtifactJob).where(ArtifactJob.created_epoch < now - KEPT_SECONDS)).rowcount
        db.commit()
    return gone


def _loop() -> None:
    time.sleep(15)  # let the API start
    pruned = 0.0
    while True:
        try:
            run_due()
            if time.time() - pruned > 3600:
                pruned = time.time()
                prune()
        except Exception:  # noqa: BLE001 - the loop must survive a bad pass
            logger.exception("Looking for what playbooks asked about files failed")
        time.sleep(LOOK_EVERY)


def start() -> None:
    global _started
    if _started:
        return
    _started = True
    threading.Thread(target=_loop, name="nik-artifact-jobs", daemon=True).start()
