"""Collections of host evidence (7.0): a triage zip (KAPE, Velociraptor) listed first, imported on request.

A collection comes in through the parts of ``uploads.py`` like any original. Its zip is kept as an original, a source of
kind ``collection`` whose source is ``collection.zip`` (``imports.COLLECTION_ZIP``), and is **unpacked by the forensics
worker** (``workers/forensics/unpack_job.py``; the zip is hostile input and is opened nowhere else). Nothing is imported
by that: the worker lists what the zip holds, and the list is kept in ``evidence_members`` for the person to choose
from.

    state       what the row says
    listing     the worker is unpacking it (work ``evidence-unpack``)
    listed      the list of members is ready; nothing, or part of it, is imported
    importing   the chosen members are being kept and read (work ``evidence-collection``);
    ``report.collection.importing``
                says how far
    failed      the zip could not be listed (not a zip, a worker that is not there): ``error`` says why; read again to
    retry

A member that a parser of the worker reads (``kind`` and ``source`` set, no ``skip``) is **importable**: importing it
keeps its original (pooled by SHA-256 like every original), makes it a source of its own (``collection_id`` the zip's
row,
``file_path`` its path in the zip, the host, the user and the browser profile its place says) through ``imports.accept``
(so a file the incident already holds is "already imported") and has it read, one after the other so that a collection
never keeps the worker from the rest. A program (``executable``) is listed and never imported as evidence: "Analyse"
sends
it to Malware Analysis, as an uploaded sample enters it. Deleting the collection does not delete the sources it gave.

A file dropped without saying what it is (``route``) is asked of the worker: a known file is filed under its section and
source, a zip is a collection, anything else is refused with a sentence (and kept nowhere).
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any, NamedTuple

from sqlalchemy import delete, func, insert, select, update
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import archive, work
from ..core.config import settings
from ..core.db import SessionLocal
from ..core.models import EvidenceMember, EvidenceSource
from ..core.security import now_iso
from ..workers import handover, watching
from . import imports, originals, parse
from .imports import COLLECTION_ZIP as ZIP
from .imports import UNPACK_WORK

logger = logging.getLogger("nik.evidence.collections")

IMPORT_WORK = "evidence-collection"
BATCH = 500
PAGE_MAX = 500
MEMBER_TIMEOUT = 3600
NOT_A_COLLECTION = "This file is not a collection"
NOT_LISTED = "The collection is not listed yet: wait for the list, or read it again when it failed"
STATUSES = ("all", "importable", "imported", "skipped", "executables", "unrecognised")
# The reasons a member listed and not read is not "read in part": the person knows what they are.
KNOWN_NOT_READ = ("an archive inside the collection", "Nik has no reader for")


class CollectionError(Exception):
    """The worker could not be asked, or refused: a sentence for the screen."""


class NoRoom(CollectionError):
    """The disk of the store has no room for what is imported: the next files would not fit either."""


def is_collection(row: EvidenceSource | None) -> bool:
    return row is not None and row.kind == "collection" and row.source == ZIP


# --------------------------------------------------------------------------- #
# The worker                                                                  #
# --------------------------------------------------------------------------- #
def _json_answer(error: urllib.error.HTTPError) -> dict[str, Any]:
    try:
        answer = json.loads(error.read() or b"{}")
    except ValueError:
        return {}
    return answer if isinstance(answer, dict) else {}


@contextmanager
def _post(route: str, sha256: str, body: dict[str, Any], timeout: float) -> Iterator[Any]:
    """``POST`` to the worker about the original ``sha256`` and give the open answer. The original is given to the
    worker when it says it does not hold it, and the request is made again, once."""
    if not parse.configured():
        raise CollectionError(parse.NOT_CONFIGURED)
    url, token = settings.FORENSICS_URL, settings.FORENSICS_TOKEN
    name = f"{sha256}.bin"
    gave = False
    while True:
        request = urllib.request.Request(  # noqa: S310 - operator-configured URL
            f"{url}{route}",
            data=json.dumps({**body, "name": name}).encode("utf-8"),
            method="POST",
            headers={parse.HEADER: token, "Content-Type": "application/json", **watching.headers()},
        )
        try:
            response = urllib.request.urlopen(request, timeout=timeout)  # noqa: S310
        except urllib.error.HTTPError as error:
            answer = _json_answer(error)
            if not gave and handover.missing_of(error, answer):
                gave = True
                try:
                    handover.give(url, parse.HEADER, token, name, originals.path_of(sha256))
                except (handover.NotGiven, originals.EvidenceError) as refused:
                    raise CollectionError(str(refused)) from None
                continue
            error.answer = answer  # type: ignore[attr-defined] - read by the callers that tell refusals apart
            raise
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise CollectionError(
                f"The forensics worker cannot be reached: {getattr(error, 'reason', error)}"
            ) from None
        break
    try:
        yield response
    finally:
        response.close()


class Route(NamedTuple):
    """Where a file dropped without a section goes: ``kind`` and ``source``, or ``sentence`` when nowhere."""

    kind: str
    source: str
    sentence: str = ""


def recognise(sha256: str, file_name: str, head: bytes = b"") -> Route:
    """What a file is, asked of the worker: a zip is a collection, a known file goes to its section and source, anything
    else is refused with the worker's sentence (how to convert a disk image or a ``.plaso`` file, or that no parser
    reads
    it). Without a worker only a zip is known."""
    if not parse.configured():
        if head.startswith((b"PK\x03\x04", b"PK\x05\x06")):
            return Route("collection", ZIP)
        return Route("", "", parse.NOT_CONFIGURED)
    try:
        with _post("/recognise", sha256, {"fileName": file_name}, 150) as response:
            answer = json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        said = getattr(error, "answer", {})
        if error.code == 422:
            return Route("", "", str(said.get("detail") or "No parser of Nik reads this file"))
        return Route("", "", str(said.get("detail") or f"The forensics worker answered {error.code}"))
    except CollectionError as error:
        return Route("", "", str(error))
    except ValueError:
        return Route("", "", "The forensics worker answered something that is not a description of the file")
    kind, source = str(answer.get("kind") or ""), str(answer.get("source") or "")[:60]
    if kind not in imports.KINDS or not source:
        return Route("", "", "No parser of Nik reads this file")
    return Route(kind, source)


# --------------------------------------------------------------------------- #
# Listing: the worker unpacks, the members are kept                           #
# --------------------------------------------------------------------------- #
def _member_row(incident_id: str, collection_id: str, event: dict[str, Any]) -> dict[str, Any] | None:
    def text(name: str, size: int) -> str | None:
        value = event.get(name)
        return value[:size] if isinstance(value, str) and value else None

    number = event.get("n")
    if not isinstance(number, int) or isinstance(number, bool) or number < 0:
        return None
    sha256 = text("sha256", 64)
    kind = text("kind", 16)
    size = event.get("size")
    return {
        "collection_id": collection_id,
        "n": number,
        "incident_id": incident_id,
        "path": str(event.get("path") or "")[:1000],
        "size": int(size) if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else 0,
        "sha256": sha256 if sha256 and originals.SHA256_RE.fullmatch(sha256) else None,
        "kind": kind if kind in imports.KINDS else None,
        "source": text("source", 60) if kind in imports.KINDS else None,
        "parser": text("parser", 40) if kind in imports.KINDS else None,
        "host": str(event.get("host") or "")[:255],
        "username": str(event.get("username") or "")[:255],
        "profile": str(event.get("profile") or "")[:120],
        "executable": bool(event.get("executable")),
        "skip": text("skip", 300),
        "source_id": None,
    }


def work_of(db: OrmSession, row: EvidenceSource) -> dict[str, Any] | None:
    """What the work of a source says while it runs: reading it, listing a collection, importing from one."""
    kind = {
        "queued": imports.PARSE_WORK,
        "parsing": imports.PARSE_WORK,
        "listing": UNPACK_WORK,
        "importing": IMPORT_WORK,
    }
    if row.state not in kind:
        return None
    return work.describe(db, kind[row.state], row.id)


def fetch(zip_sha256: str, sha256: str, path: str, limit: int) -> bytes:
    """One member of a collection, whole, in memory, at most ``limit`` bytes (a program to analyse). Raises
    ``CollectionError``."""
    body = {"sha256": sha256, "path": path, "total": settings.COLLECTION_MAX_MB * 1024 * 1024}
    try:
        with _post("/member", zip_sha256, body, MEMBER_TIMEOUT) as response:
            data = response.read(limit + 1)
    except urllib.error.HTTPError as error:
        said = getattr(error, "answer", {})
        raise CollectionError(str(said.get("detail") or f"The forensics worker answered {error.code}")) from None
    except OSError as error:
        raise CollectionError(f"The member could not be fetched from the worker: {error}") from None
    if len(data) > limit:
        raise CollectionError("The member is larger than the limit")
    return data


def _fail(db: OrmSession, source_id: str, sentence: str) -> None:
    row = db.get(EvidenceSource, source_id)
    if row is not None and row.state in ("listing",):
        row.state, row.read, row.error = "failed", "failed", sentence[:500]
        row.parsed_at = now_iso()


def unpack(source_id: str, claim: work.Claim | None = None) -> None:
    """List what a collection holds: the worker unpacks it, the members are kept, the row says what was found. Run
    held."""
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        if row is None or row.state != "listing" or not is_collection(row):
            return
        if not parse.configured():
            _fail(db, source_id, parse.NOT_CONFIGURED)
            db.commit()
            return
        db.execute(delete(EvidenceMember).where(EvidenceMember.collection_id == source_id))
        row.error = None
        db.commit()
        incident_id, sha256, file_name = row.incident_id, row.sha256, row.file_name
    body = {"fileName": file_name, "total": settings.COLLECTION_MAX_MB * 1024 * 1024}
    job = watching.job_name(UNPACK_WORK, source_id, getattr(claim, "attempts", 1) or 1)
    began = time.monotonic()
    report = parse.Report()
    batch: list[dict[str, Any]] = []
    seen = 0
    ended: dict[str, Any] | None = None
    stopped = ""
    sizes: dict[str, int] = {}

    def flush() -> None:
        if not batch:
            return
        with SessionLocal() as db:
            db.execute(insert(EvidenceMember.__table__), batch)
            db.commit()
        batch.clear()
        if claim is not None:
            claim.progress(f"{seen} members listed")

    try:
        for event in parse._events(sha256, body, job, "/unpack"):  # noqa: SLF001 - the same stream as a parse
            kind = event.get("t")
            if kind == "member":
                member = _member_row(incident_id, source_id, event)
                if member is None:
                    continue
                seen += 1
                batch.append(member)
                if member["skip"]:
                    report.skip({"reason": member["skip"], "lost": 0, "detail": member["path"]})
                if member["kind"] and not member["skip"] and member["sha256"]:
                    sizes[member["sha256"]] = member["size"]
                if len(batch) >= BATCH:
                    flush()
            elif kind == "end":
                ended = event
            elif kind == "skip":
                stopped = str(event.get("detail") or event.get("reason") or "the worker stopped")
        flush()
    except parse.ParseError as error:
        flush()
        stopped = str(error)
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        if row is None:
            return
        if ended is None or ended.get("error"):
            sentence = str((ended or {}).get("error") or f"The worker stopped before the end of the list: {stopped}")
            row.report = {**report.out(False, round(time.monotonic() - began, 1))}
            _fail(db, source_id, sentence)
            db.commit()
            if claim is not None:
                claim.failed = True  # type: ignore[attr-defined]
            return
        counts = _summary(ended, sizes)
        lost = sum(held["count"] for reason, held in report.reasons.items() if not reason.startswith(KNOWN_NOT_READ))
        row.state, row.error, row.parsed_at = "listed", None, now_iso()
        row.parser, row.parser_version = "unpack", "1"
        row.in_file = int(ended.get("members") or 0) + int(ended.get("unlisted") or 0)
        row.read_count, row.kept, row.duplicates = counts["recognised"], 0, 0
        row.skipped, row.notes, row.truncated = lost, 0, 0
        row.read = "partial" if (lost or ended.get("stopped") or ended.get("unlisted")) else "complete"
        if ended.get("stopped"):
            report.note({"reason": "the unpacking was cut", "count": 1, "detail": str(ended["stopped"])})
        if ended.get("password"):
            report.note({"reason": "opened with the password infected", "count": 1})
        row.report = {**report.out(True, round(time.monotonic() - began, 1)), "collection": counts}
        row.seen_by, row.seen_at, row.seen_note = None, None, ""
        from .. import war_room

        war_room.add(
            db, row.incident_id, "system", {"text": sentence_of(row, counts), "evidence": {"source": row.id}}, "nik"
        )
        db.commit()


def _summary(ended: dict[str, Any], sizes: dict[str, int]) -> dict[str, Any]:
    """What the end line of the worker says of the collection, as the screens read it."""

    def number(name: str) -> int:
        value = ended.get(name)
        return int(value) if isinstance(value, int) and not isinstance(value, bool) else 0

    return {
        "members": number("members"),
        "unlisted": number("unlisted"),
        "bytes": number("bytes"),
        "recognised": number("recognised"),
        "skipped": number("skipped"),
        "executables": number("executables"),
        "stopped": str(ended.get("stopped") or "") or None,
        "password": bool(ended.get("password")),
        "limits": ended.get("limits") if isinstance(ended.get("limits"), dict) else {},
        # What importing every member that can be would write to the store (a file once, whatever its copies).
        "importBytes": sum(sizes.values()),
        "imported": 0,
        "importing": None,
    }


def sentence_of(row: EvidenceSource, counts: dict[str, Any]) -> str:
    name = row.file_name or row.sha256[:12]
    files = counts["members"]
    text = f"{name} unpacked: {files} file{'' if files == 1 else 's'}, {counts['recognised']} Nik can read"
    if counts["executables"]:
        text += f", {counts['executables']} program{'' if counts['executables'] == 1 else 's'} (listed, not imported)"
    if counts["unlisted"]:
        text += f"; {counts['unlisted']} more are not listed ({counts['stopped']})"
    return text + ". Choose what to import."


def start_unpack(source_id: str, _params: dict[str, Any] | None = None) -> bool:
    """List the collection in a thread of this process (the request that wanted it committed)."""

    def run() -> None:
        try:
            with work.hold(UNPACK_WORK, source_id) as claim:
                unpack(source_id, claim)
        except work.Taken:
            return

    work.thread(run)
    return True


def again(db: OrmSession, row: EvidenceSource) -> None:
    """List the collection again (it failed, or the worker learnt more): the members and what was imported from it stay
    as sources; the list is made new. The caller commits, then calls ``start_unpack``."""
    db.execute(delete(EvidenceMember).where(EvidenceMember.collection_id == row.id))
    row.state, row.error = "listing", None
    work.want(db, UNPACK_WORK, row.id)


work.register(work.Kind(UNPACK_WORK, "a collection being listed", "again", start=start_unpack, fail=_fail))


# --------------------------------------------------------------------------- #
# Importing                                                                   #
# --------------------------------------------------------------------------- #
def importable(db: OrmSession, source_id: str) -> list[EvidenceMember]:
    """The members the worker reads and nothing refused, in the order of the zip."""
    return list(
        db.scalars(
            select(EvidenceMember)
            .where(
                EvidenceMember.collection_id == source_id,
                EvidenceMember.kind.is_not(None),
                EvidenceMember.skip.is_(None),
                EvidenceMember.executable.is_(False),
                EvidenceMember.sha256.is_not(None),
            )
            .order_by(EvidenceMember.n)
        )
    )


def chosen(db: OrmSession, source_id: str, numbers: list[int] | None, kinds: list[str] | None) -> list[EvidenceMember]:
    """The importable members a request chose: these numbers (None: all of them), of these kinds (None: any)."""
    wanted = set(numbers) if numbers is not None else None
    return [
        member
        for member in importable(db, source_id)
        if (wanted is None or member.n in wanted) and (not kinds or member.kind in kinds)
    ]


def keep_member(zip_sha256: str, sha256: str, size: int, path: str) -> None:
    """The original of a member, in the store: taken from the worker (which kept it when it unpacked, or takes it out of
    the zip again), unless the store has it already. Raises ``NoRoom`` or ``CollectionError``."""
    if originals.has(sha256):
        return
    try:
        originals.room(size, "the file")
    except originals.EvidenceError as error:
        raise NoRoom(str(error)) from None
    try:
        body = {"sha256": sha256, "path": path, "total": settings.COLLECTION_MAX_MB * 1024 * 1024}
        with _post("/member", zip_sha256, body, MEMBER_TIMEOUT) as response:
            originals.keep(iter(lambda: response.read(1024 * 1024), b""), sha256)
    except originals.EvidenceError as error:
        raise CollectionError(str(error)) from None
    except urllib.error.HTTPError as error:
        said = getattr(error, "answer", {})
        raise CollectionError(str(said.get("detail") or f"The forensics worker answered {error.code}")) from None
    except OSError as error:
        raise CollectionError(f"The member could not be fetched from the worker: {error}") from None


def _progress(source_id: str, **values: Any) -> None:
    """What the row says of an import in progress (``report.collection.importing``)."""
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        if row is None:
            return
        report = dict(row.report or {})
        collection = dict(report.get("collection") or {})
        collection["importing"] = {**(collection.get("importing") or {}), **values}
        report["collection"] = collection
        row.report = report
        flag_modified(row, "report")
        db.commit()


def name_of(path: str) -> str:
    return os.path.basename(path.rstrip("/")) or path


def import_members(source_id: str, claim: work.Claim | None = None) -> None:
    """Keep and read the members a request chose, one after the other. Run held (``IMPORT_WORK``)."""
    params = dict(claim.params) if claim is not None else {}
    actor = str(params.get("actor") or "nik")
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        if row is None or row.state != "importing" or not is_collection(row):
            return
        numbers = params.get("members") if isinstance(params.get("members"), list) else None
        kinds = params.get("kinds") if isinstance(params.get("kinds"), list) else None
        todo = [
            (m.n, m.path, m.size, m.sha256, m.kind, m.source, m.host, m.username, m.profile)
            for m in chosen(db, source_id, numbers, kinds)
        ]
        incident_id, zip_sha256, file_name = row.incident_id, row.sha256, row.file_name
    counts = {"total": len(todo), "done": 0, "already": 0, "failed": 0, "current": "", "error": None}
    _progress(source_id, **counts)
    stopped = ""
    for number, path, size, sha256, kind, source, host, username, profile in todo:
        counts["current"] = path
        try:
            with SessionLocal() as db:
                held = imports.is_duplicate(db, incident_id, sha256, name_of(path), {"kind": kind, "source": source})
            if not held:
                keep_member(zip_sha256, sha256, size, path)
            with SessionLocal() as db:
                try:
                    created = imports.accept(
                        db,
                        incident_id,
                        sha256,
                        size,
                        name_of(path),
                        {
                            "kind": kind,
                            "source": source,
                            "host": host,
                            "user": username,
                            "profile": profile,
                            "collectionId": source_id,
                            "filePath": path,
                        },
                        actor,
                    )
                except archive.Archived as refused:
                    stopped = refused.message
                    break
                db.execute(
                    update(EvidenceMember)
                    .where(EvidenceMember.collection_id == source_id, EvidenceMember.n == number)
                    .values(source_id=created.id)
                )
                wanted = created.state == "queued" and not held
                created_id = created.id
                db.commit()
            if held:
                counts["already"] += 1
            elif wanted:
                _read(created_id)
                with SessionLocal() as db:
                    after = db.get(EvidenceSource, created_id)
                    counts["failed"] += int(after is not None and after.state == "failed")
            counts["done"] += 1
        except NoRoom as error:
            counts["failed"] += 1
            counts["done"] += 1
            stopped = str(error)
            break
        except CollectionError as error:
            counts["failed"] += 1
            counts["error"] = str(error)
            counts["done"] += 1
        except Exception as error:  # noqa: BLE001 - one member that cannot be imported does not end the others
            logger.warning("A member of the collection %s could not be imported: %s", source_id, error)
            counts["failed"] += 1
            counts["done"] += 1
            counts["error"] = f"{type(error).__name__}: {str(error)[:200]}"
        _progress(source_id, **counts)
        if claim is not None:
            claim.progress(f"{counts['done']} of {counts['total']} files imported")
    with SessionLocal() as db:
        row = db.get(EvidenceSource, source_id)
        if row is None:
            return
        imported = int(
            db.scalar(
                select(func.count())
                .select_from(EvidenceMember)
                .where(EvidenceMember.collection_id == source_id, EvidenceMember.source_id.is_not(None))
            )
            or 0
        )
        report = dict(row.report or {})
        collection = dict(report.get("collection") or {})
        everything = int(collection.get("recognised") or 0)
        collection["imported"] = imported
        collection["importing"] = {**counts, "current": "", "error": stopped or counts["error"], "ended": True}
        report["collection"] = collection
        row.report = report
        flag_modified(row, "report")
        row.kept = imported
        row.state = "done" if everything and imported >= everything else "listed"
        from .. import war_room

        said = f"{imported} of {everything} files of {file_name} are imported"
        if counts["already"]:
            said += f" ({counts['already']} were already there)"
        if counts["failed"]:
            said += f"; {counts['failed']} could not be imported"
        if stopped:
            said += f"; it stopped: {stopped}"
        war_room.add(db, row.incident_id, "system", {"text": said + ".", "evidence": {"source": row.id}}, "nik")
        db.commit()


def _read(source_id: str) -> None:
    """Read a source that was just made, here and now (one at a time: a collection of a thousand files must not
    fill the worker's slots)."""
    try:
        with work.hold(parse.WORK, source_id) as held:
            parse.read(source_id, held)
    except work.Taken:
        return


def _fail_import(db: OrmSession, source_id: str, sentence: str) -> None:
    row = db.get(EvidenceSource, source_id)
    if row is not None and row.state == "importing":
        row.state = "listed"
        report = dict(row.report or {})
        collection = dict(report.get("collection") or {})
        collection["importing"] = {**(collection.get("importing") or {}), "error": sentence, "ended": True}
        report["collection"] = collection
        row.report = report
        flag_modified(row, "report")


def start_import(source_id: str, _params: dict[str, Any] | None = None) -> bool:
    def run() -> None:
        try:
            with work.hold(IMPORT_WORK, source_id) as claim:
                import_members(source_id, claim)
        except work.Taken:
            return

    work.thread(run)
    return True


work.register(
    work.Kind(IMPORT_WORK, "files of a collection being imported", "again", start=start_import, fail=_fail_import)
)


def want_import(
    db: OrmSession, row: EvidenceSource, numbers: list[int] | None, kinds: list[str] | None, actor: str
) -> int:
    """Ask for the import of the chosen members (the caller commits, then calls ``start_import``). Returns how many
    members the request chose. Raises ``ValueError`` with a sentence when nothing can be imported."""
    if row.state not in ("listed", "done"):
        raise ValueError(NOT_LISTED if row.state in ("listing", "failed") else "This collection is being imported")
    selected = chosen(db, row.id, numbers, kinds)
    if not selected:
        raise ValueError("None of the files chosen can be imported (a program or a file Nik does not read cannot be)")
    needed = sum(
        {
            member.sha256: member.size for member in selected if member.sha256 and not originals.has(member.sha256)
        }.values()
    )
    try:
        originals.room(needed, "the files of the collection")
    except originals.EvidenceError as error:
        raise ValueError(str(error)) from None
    row.state = "importing"
    report = dict(row.report or {})
    collection = dict(report.get("collection") or {})
    collection["importing"] = {
        "total": len(selected),
        "done": 0,
        "already": 0,
        "failed": 0,
        "current": "",
        "error": None,
    }
    report["collection"] = collection
    row.report = report
    flag_modified(row, "report")
    work.want(db, IMPORT_WORK, row.id, {"members": numbers, "kinds": kinds, "actor": actor})
    return len(selected)


# --------------------------------------------------------------------------- #
# What the screens read                                                       #
# --------------------------------------------------------------------------- #
def _shown(member: EvidenceMember, held: dict[tuple[str, str, str], EvidenceSource]) -> dict[str, Any]:
    importable_ = bool(member.kind and not member.skip and not member.executable and member.sha256)
    existing = held.get((member.sha256 or "", member.kind or "", member.source or "")) if importable_ else None
    source_id = member.source_id or (existing.id if existing is not None else None)
    return {
        "n": member.n,
        "path": member.path,
        "fileName": name_of(member.path),
        "size": member.size,
        "sha256": member.sha256,
        "kind": member.kind,
        "source": member.source,
        "parser": member.parser,
        "host": member.host,
        "username": member.username,
        "profile": member.profile,
        "executable": bool(member.executable),
        "skip": member.skip,
        "importable": importable_,
        "imported": source_id is not None,
        "alreadyImported": existing is not None and member.source_id is None,
        "sourceId": source_id,
        "state": (existing.state if existing is not None else None),
    }


def _where(source_id: str, status: str, kinds: list[str], text: str) -> list[Any]:
    m = EvidenceMember
    where: list[Any] = [m.collection_id == source_id]
    readable = [m.kind.is_not(None), m.skip.is_(None), m.executable.is_(False)]
    if status == "importable":
        where += readable
    elif status == "imported":
        where.append(m.source_id.is_not(None))
    elif status == "skipped":
        where.append(m.skip.is_not(None))
    elif status == "executables":
        where.append(m.executable.is_(True))
    elif status == "unrecognised":
        where += [m.kind.is_(None), m.skip.is_(None), m.executable.is_(False)]
    if kinds:
        where.append(m.kind.in_(kinds))
    if text:
        escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        where.append(func.lower(m.path).like(f"%{escaped.lower()}%", escape="\\"))
    return where


def members_page(
    db: OrmSession, row: EvidenceSource, status: str, kinds: list[str], text: str, limit: int, cursor: int | None
) -> dict[str, Any]:
    """One page of the members, in the order of the zip: ``members``, ``next`` (the cursor of the following page, null
    at
    the end), ``total`` of what the filter keeps, and ``counts`` of the whole list."""
    m = EvidenceMember
    where = _where(row.id, status, kinds, text)
    total = int(db.scalar(select(func.count()).select_from(m).where(*where)) or 0)
    query = select(m).where(*where)
    if cursor is not None:
        query = query.where(m.n > cursor)
    found = list(db.scalars(query.order_by(m.n).limit(limit + 1)))
    more = len(found) > limit
    found = found[:limit]
    shas = {member.sha256 for member in found if member.sha256}
    held: dict[tuple[str, str, str], EvidenceSource] = {}
    if shas:
        for source in db.scalars(
            select(EvidenceSource).where(
                EvidenceSource.incident_id == row.incident_id,
                EvidenceSource.sha256.in_(shas),
                EvidenceSource.state != imports.ABSENT,
                EvidenceSource.id != row.id,
            )
        ):
            held.setdefault((source.sha256, source.kind, source.source), source)
    return {
        "members": [_shown(member, held) for member in found],
        "next": str(found[-1].n) if more and found else None,
        "total": total,
        "counts": counts_of(db, row),
    }


def counts_of(db: OrmSession, row: EvidenceSource) -> dict[str, Any]:
    m = EvidenceMember
    scope = m.collection_id == row.id
    readable = (m.kind.is_not(None), m.skip.is_(None), m.executable.is_(False))

    def count(*where: Any) -> int:
        return int(db.scalar(select(func.count()).select_from(m).where(scope, *where)) or 0)

    by_kind = {
        kind: int(n)
        for kind, n in db.execute(
            select(m.kind, func.count()).where(scope, *readable).group_by(m.kind).order_by(m.kind)
        )
    }
    return {
        "all": count(),
        "importable": count(*readable),
        "imported": count(m.source_id.is_not(None)),
        "skipped": count(m.skip.is_not(None)),
        "executables": count(m.executable.is_(True)),
        "unrecognised": count(m.kind.is_(None), m.skip.is_(None), m.executable.is_(False)),
        "byKind": by_kind,
    }


def member_of(db: OrmSession, row: EvidenceSource, number: int) -> EvidenceMember | None:
    return db.get(EvidenceMember, (row.id, number))


def clear_members(db: OrmSession, source_id: str) -> None:
    """Forget the list of a collection (it is being removed); the sources it gave are untouched except that they no
    longer
    name it."""
    db.execute(update(EvidenceSource).where(EvidenceSource.collection_id == source_id).values(collection_id=None))
    db.execute(delete(EvidenceMember).where(EvidenceMember.collection_id == source_id))
