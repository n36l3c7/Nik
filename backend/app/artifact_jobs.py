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

- ``store``       keep the bytes the job carries as a file or an e-mail
                  artifact, analysed as an upload is;
- ``attachment``  take an attachment out of an e-mail Nik holds and keep it
                  as a file artifact, as "Send to Malware Analysis" does;
- ``analyse``     analyse an artifact again, as "Re-analyse", "Disassemble"
                  and "Run capa" do;
- ``convert``     analyse a file artifact as an e-mail or as a capture, as
                  "Analyse as an e-mail" and "Analyse as a capture" do;
- ``remove``      delete files of the store whose artifact the worker deleted
                  (one whose day came): it holds neither the store nor its key.

The node meanwhile gives its step back and asks again later: nothing waits
holding a worker. A job says which run asked for it, so that what it sets off
(``file.analysed``, ``mail.analysed``) starts no playbook on its own doing.

The bytes of a file to keep cross the database, the one thing both
processes reach: in parts of a few megabytes (``artifact_job_parts``), put
together here and deleted once the file is in the store. A file is as large
as an upload at most. Each part is encrypted under a key derived from
``SECRET_KEY``, which both processes hold (``vault.seal_bytes``): the rows, the
write-ahead log of the database and a backup taken at that moment hold no
file in clear.

The same holds for what is kept inside a step without being a node of its
own: the file a command of a connector gives, the attachments of a message,
the message a fetch made an incident from. They go through ``Keeper``: it
writes to the store when this process can (the API process, a server whose
playbooks run in it) and asks for a ``store`` job when it cannot, and says
which jobs the step has to wait for.

**Across a restart: started again.** A job is a row, and so is who does it
(``work.py``, kind ``artifact-job``): written with the row in the transaction
of the step that asks, taken by one API process, which says it is alive while
it works. When that process is gone the job goes back to ``queued`` and is
taken again. Doing a job twice makes nothing twice: a file is kept under its
hash, an e-mail under its own, a capture made from a file under an id worked
out from the file, an analysis replaces itself, a file deleted is deleted. A
job that was interrupted ``work.MAX_ATTEMPTS`` times fails with that reason,
and the step that waits for it fails with it. The bytes a job carries stay in
the database until the job is done, so the process that takes it again has them.

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

from . import artifacts, work
from .core import audit, vault
from .core.locking import lock_incident
from .core.models import (
    Artifact,
    ArtifactJob,
    ArtifactJobPart,
    Incident,
    Mail,
    NetworkCapture,
    Sample,
    SampleCapa,
    SampleCode,
)

logger = logging.getLogger("nik.artifacts")

LOOK_EVERY = 2
# A job nobody took in this long is not done any more: the node that asked gave up before.
TAKE_WITHIN = 600
KEPT_SECONDS = 86400
PART_BYTES = 4 * 1024 * 1024  # the bytes of a file cross the database in parts of this size
PARTS = b"artifact job parts"  # what the key that encrypts those parts is derived for (core/vault.py)
ANALYSES = ("static", "code", "capabilities")
KIND = "artifact-job"
_started = False


class JobError(Exception):
    """A job that cannot be done, with a sentence for the step that asked."""


class _Later:
    """What a route is given as its background tasks: the calls are collected, and started once the
    job is committed, each in a thread of its own (the disassembly of a sample takes minutes)."""

    def __init__(self, cause: tuple[str, int] | None = None) -> None:
        self.tasks: list[tuple[Any, tuple]] = []
        # The run that asked: what an analysis says when it ends (code.analysed, capture.analysed…)
        # is caused by it, so the playbook that asked does not start again on its own doing.
        self.cause = cause

    def add_task(self, work: Any, *args: Any) -> None:
        self.tasks.append((work, args))

    def _caused(self, work: Any, args: tuple) -> None:
        from .automation import triggers

        token = triggers.current_run.set(self.cause)
        try:
            work(*args)
        finally:
            triggers.current_run.reset(token)

    def start(self, threads: bool) -> None:
        for task, args in self.tasks:
            if threads:
                threading.Thread(
                    target=self._caused, args=(task, args), name="nik-artifact-analysis", daemon=True
                ).start()
            else:
                self._caused(task, args)


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
        result={},
        actor=actor,
        run_id=run_id,
        depth=depth,
        created_epoch=now,
    )
    db.add(row)
    db.flush()
    work.want(db, KIND, row.id, now=now)
    for seq, start in enumerate(range(0, len(data or b""), PART_BYTES)):
        part = vault.seal_bytes(data[start : start + PART_BYTES], PARTS, f"{row.id}:{seq}".encode())
        db.add(ArtifactJobPart(job_id=row.id, seq=seq, data=part))
        db.flush()  # one part at a time: the whole file is not sent to the database in one statement
    return row


def carried(db: OrmSession, job_id: str) -> bytes:
    """The bytes a job carries, put together."""
    parts = db.execute(
        select(ArtifactJobPart.seq, ArtifactJobPart.data)
        .where(ArtifactJobPart.job_id == job_id)
        .order_by(ArtifactJobPart.seq)
    )
    try:
        return b"".join(vault.open_bytes(part, PARTS, f"{job_id}:{seq}".encode()) for seq, part in parts)
    except ValueError as error:
        raise JobError(str(error)) from None


def _drop_parts(db: OrmSession, job_id: str) -> None:
    db.execute(delete(ArtifactJobPart).where(ArtifactJobPart.job_id == job_id))


def take(db: OrmSession, now: float | None = None) -> str | None:
    """Take one job that waits: its id. None when there is none."""
    now = time.time() if now is None else now
    waiting = db.execute(
        select(ArtifactJob.id, ArtifactJob.created_epoch, ArtifactJob.kind)
        .where(ArtifactJob.status == "queued")
        .order_by(ArtifactJob.created_epoch, ArtifactJob.id)
    ).all()
    for job_id, created, kind in waiting:
        # A file to delete is deleted however late: no step waits for it, and it must not stay.
        late = kind != "remove" and now - float(created or 0) > TAKE_WITHIN
        # Several API processes look at once: the one whose update changes the row has it.
        values: dict[str, Any] = {"status": "running"}
        if late:
            values = {"status": "error", "error": "It was not taken in time", "finished_epoch": now}
        won = db.execute(
            update(ArtifactJob).where(ArtifactJob.id == job_id, ArtifactJob.status == "queued").values(**values)
        ).rowcount
        if won and late:
            _drop_parts(db, job_id)
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

    params, data = job.params, carried(db, job.id)
    name, origin = str(params.get("name") or ""), str(params.get("origin") or "")
    if params.get("as") != "mail":
        # Taken out of another artifact (an attachment, a file of an archive): said so when that one is there.
        parent = params.get("parent")
        if not (isinstance(parent, list) and len(parent) == 2 and db.get(Artifact, str(parent[0])) is not None):
            parent = None
        return _keep_file(db, job, data, name, origin, (str(parent[0]), str(parent[1])) if parent else None, later)
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
    except (OSError, ValueError, MailError) as error:
        from .core import store

        said = str(error) if isinstance(error, store.SealError) else "The stored message cannot be read"
        raise JobError(said) from None
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


def _convert(db: OrmSession, job: ArtifactJob, later: _Later) -> dict[str, Any]:
    from . import artifact_convert

    row = db.get(Artifact, str(job.params.get("artifact") or ""))
    if row is None:
        raise JobError("The artifact does not exist")
    wanted, incident = str(job.params.get("as") or ""), str(job.params.get("incident") or "")
    try:
        if wanted == "mail":
            made = artifact_convert.as_mail(db, row, job.actor, incident)
        else:
            made = artifact_convert.as_capture(db, row, job.actor, later, incident)
    except artifact_convert.ConvertError as error:
        raise JobError(error.message) from None
    what = "an e-mail" if wanted == "mail" else "a capture"
    said = f"Analysed the file {row.name or row.ref[:12]} as {what}" + str(job.params.get("by") or "")
    audit.record(db, job.actor, "artifact.analyse_as", said)
    # A capture is analysed by its worker from here on; an e-mail was analysed as it was made.
    return {"made": made.id, "started": ["capture" if wanted == "capture" else "mail"], "skipped": []}


def _remove(db: OrmSession, job: ArtifactJob, later: _Later) -> dict[str, Any]:
    """Delete the files and folders of the store the job names. A name that would leave the store
    is not followed."""
    from .core import store

    root = store.root().resolve()
    removed = 0
    for name in job.params.get("names") or []:
        path = (root / str(name)).resolve()
        if root not in path.parents:
            raise JobError("The file to delete is not a file of the store")
        if path.is_dir():
            store.remove_tree(path)
            removed += 1
        elif path.exists():
            store.remove(path)
            removed += 1
    return {"removed": removed}


_WORK = {"store": _store, "attachment": _attachment, "analyse": _analyse, "convert": _convert, "remove": _remove}


def _run(job_id: str, threads: bool) -> None:
    """Do one job this process took, holding it. One another process holds is left alone and goes
    back to waiting."""
    try:
        with work.hold(KIND, job_id):
            _do(job_id, threads)
    except work.Taken:
        from .core.db import SessionLocal

        with SessionLocal() as db:
            db.execute(
                update(ArtifactJob)
                .where(ArtifactJob.id == job_id, ArtifactJob.status == "running")
                .values(status="queued")
            )
            db.commit()


def _fail_job(db: OrmSession, job_id: str, sentence: str) -> None:
    job = db.get(ArtifactJob, job_id)
    if job is None or job.status not in ("queued", "running"):
        return
    job.status, job.error, job.result, job.finished_epoch = "error", sentence, {}, time.time()
    _drop_parts(db, job_id)


def _again(job_id: str, _params: dict[str, Any]) -> bool | None:
    """Put a job whose process is gone back among those that wait: the loop of any API process takes it."""
    from .core.db import SessionLocal

    with SessionLocal() as db:
        job = db.get(ArtifactJob, job_id)
        if job is None or job.status not in ("queued", "running"):
            return False
        job.status = "queued"
        db.commit()
    return None


work.register(work.Kind(KIND, "what a playbook asked about a file", "again", start=_again, fail=_fail_job))


def _do(job_id: str, threads: bool) -> None:
    from .automation import triggers
    from .core.db import SessionLocal

    later = _Later()
    with SessionLocal() as db:
        job = db.get(ArtifactJob, job_id)
        if job is None:
            return
        later.cause = (job.run_id, int(job.depth or 0)) if job.run_id else None
        # What the job sets off is caused by the run that asked: no loop starts from it.
        token = triggers.current_run.set((job.run_id, int(job.depth or 0)) if job.run_id else None)
        try:
            result, error = _WORK[job.kind](db, job, later), None
            db.flush()
        except JobError as failed:
            db.rollback()
            result, error = {}, str(failed)
        except Exception as failed:  # noqa: BLE001 - one bad job must not stop the others
            from .core.db import connection_lost

            if connection_lost(failed):
                raise  # the database went away: the job did nothing wrong, and is done again (work.py)
            db.rollback()
            logger.exception("The job %s a playbook asked for failed", job_id)
            result, error = {}, "It failed for a reason Nik did not expect: see the server's log"
        finally:
            triggers.current_run.reset(token)
        job = db.get(ArtifactJob, job_id)
        if job is not None:
            job.status, job.error, job.result = ("error" if error else "done"), error, result
            job.finished_epoch = time.time()
            _drop_parts(db, job_id)
            if error and job.params.get("report"):
                # Nobody waits for this one (a fetch went on): what went wrong is written where it is read.
                incident = db.get(Incident, str(job.params.get("incident") or ""))
                audit.record(db, job.actor, "evidence.keep", f"{job.params['report']}: {error}", incident)
        db.commit()
    if not error:
        later.start(threads)


def run_due(limit: int = 20, *, threads: bool = True, now: float | None = None) -> int:
    """Do the jobs that were asked for, one after the other. Returns how many. The analyses a job
    starts on a worker run each in a thread of its own (``threads`` off: here, one by one, for tests)."""
    from .core.db import SessionLocal

    done = 0
    while done < limit and not work.stopping():
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
        old = select(ArtifactJob.id).where(ArtifactJob.created_epoch < now - KEPT_SECONDS)
        db.execute(delete(ArtifactJobPart).where(ArtifactJobPart.job_id.in_(old)))
        gone = db.execute(delete(ArtifactJob).where(ArtifactJob.created_epoch < now - KEPT_SECONDS)).rowcount
        db.commit()
    return gone


# --------------------------------------------------------------------------- #
# Keeping a file from inside a step                                           #
# --------------------------------------------------------------------------- #
WAIT_EVERY = 2  # seconds between two looks at the jobs a step waits for
WAIT_FOR = 600  # how long they may take before the step fails


class Keeper:
    """Keeps files for one step of a run, or for a fetch: in the store when this process can write
    to it, through the API process when it cannot. Either way what describes the file is known at
    once (its hash is its name in the store), and ``pending`` says what the step waits for."""

    def __init__(self, db: OrmSession, actor: str, run_id: str = "", depth: int = 0, now: float | None = None):
        from .malware.samples import store_writable

        self.db, self.actor, self.run_id, self.depth = db, actor, run_id, depth
        self.now = time.time() if now is None else now
        self.direct = store_writable()
        self.pending: list[str] = []
        self.audits: list[dict[str, str]] = []  # written when the files are kept: {action, details, incident}

    @classmethod
    def of(cls, call: Any, actor: str) -> Keeper:
        """The keeper of a step: what it asks for says which run asked, and how deep that run is."""
        from .automation import triggers

        cause = triggers.current_run.get()
        run_id = str(getattr(call.run, "id", "") or "")
        return cls(call.db, actor, run_id, cause[1] if cause else 0, call.now or None)

    def _ask(self, params: dict[str, Any], data: bytes) -> None:
        # Asked in order: a file taken out of another is kept after that one.
        stamp = self.now + len(self.pending) * 1e-4
        self.pending.append(ask(self.db, "store", params, self.actor, self.run_id, self.depth, stamp, data).id)

    def file(
        self,
        data: bytes,
        name: str,
        incident_id: str = "",
        origin: str = "",
        parent: tuple[str, str] | None = None,
    ) -> dict[str, Any]:
        """Keep bytes as a file artifact: ``{artifact, sha256, size, type, linked}``. Raises
        ``JobError`` when it cannot be kept (the caller checked the size)."""
        from .parsing.malware import detect_type
        from .routers import samples as sample_routes

        sha256 = _sha256(data)
        said = {"artifact": artifacts.artifact_id("file", sha256), "sha256": sha256, "size": len(data)}
        if not self.direct:
            params = {"name": name, "incident": incident_id, "origin": origin, "parent": list(parent or ())}
            self._ask(params, data)
            return {**said, "type": detect_type(data)["label"], "linked": bool(incident_id)}
        incident = lock_incident(self.db, incident_id) if incident_id else None
        if incident_id and incident is None:
            raise JobError("The incident does not exist")
        try:
            row, _ref = sample_routes.keep_sample(self.db, incident, data, name, self.actor, origin, parent=parent)
        except HTTPException as error:
            raise JobError(str(error.detail)) from None
        return {**said, "type": row.type_label or "", "linked": incident is not None}

    def mail(self, data: bytes, name: str, incident_id: str, report: str = "") -> None:
        """Keep a message as an e-mail artifact of an incident. Raises ``MailError`` for what is not
        a message when it is kept here; handed over, nobody waits, and ``report`` is what is written
        on the incident if it could not be kept."""
        from .routers import mails as mail_routes

        if not self.direct:
            self._ask({"as": "mail", "name": name, "incident": incident_id, "report": report}, data)
            return
        mail_routes.keep_mail(self.db, lock_incident(self.db, incident_id), data, name, self.actor)

    def audit(self, action: str, details: str, incident_id: str = "") -> None:
        """A line of the audit log for what was kept: now when it was, with the files when it is asked for."""
        if self.direct:
            audit.record(
                self.db, self.actor, action, details, self.db.get(Incident, incident_id) if incident_id else None
            )
        else:
            self.audits.append({"action": action, "details": details, "incident": incident_id})

    def waiting(self) -> dict[str, Any] | None:
        """What a step keeps to wait for the files that were asked for (None when none was)."""
        if not self.pending:
            return None
        return {"jobs": list(self.pending), "until": self.now + WAIT_FOR, "audits": self.audits}


def kept(db: OrmSession, waiting: dict[str, Any], actor: str, now: float) -> bool:
    """Whether the files a step asked for are kept. False while they are not; raises ``JobError``
    when one could not be, or when they took too long. Kept, their lines go to the audit log."""
    jobs = [db.get(ArtifactJob, str(job_id)) for job_id in waiting.get("jobs") or []]
    failed = next((job for job in jobs if job is None or job.status == "error"), "none")
    if failed != "none":
        why = failed.error if failed is not None else "what was asked of the server is no longer there"
        raise JobError(f"The file was not kept: {why}")
    if any(job.status != "done" for job in jobs):
        if now < float(waiting.get("until") or 0):
            return False
        raise JobError(
            f"The file was not kept in {WAIT_FOR // 60} minutes: see whether the server answers "
            "(Settings → System → Workers)"
        )
    for line in waiting.get("audits") or []:
        incident = db.get(Incident, str(line.get("incident") or "")) if line.get("incident") else None
        audit.record(db, actor, str(line.get("action")), str(line.get("details")), incident)
    return True


def _loop() -> None:
    time.sleep(15)  # let the API start
    pruned = 0.0
    while not work.stopping():
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
