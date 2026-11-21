"""Artifacts out of one Nik and into another.

An export is a zip:

- ``manifest.json``: what the archive holds (``format: nik-artifacts``), the
  artifacts as the registry lists them, and how they relate to each other;
- ``records/<artifact id>.json``: the analysis as stored (the sample's, the
  e-mail's, the capture's summary, the scan's result), or what a mailbox is;
- ``records/<mailbox id>.messages.jsonl``: the index of a mailbox, a message
  a line (where it is in the file, its headers, its conversation);
- ``files.zip``, only when asked for: the original files, in an AES-encrypted
  zip with the password ``infected``, as malware is exchanged. The files are
  live malware: the choice is made at each export and defaults to no.

An import adds the artifacts the server does not have yet. A file is stored
only if its SHA-256 is the one its artifact is named by; nothing is run, and
no analysis is started: the analyses come with the archive.

A mailbox travels with its file or not at all: its index says where each
message is in that file, so without it there is nothing to read. Its file is
copied in pieces, never held in memory, and its index must fit it.

**What protects an export.** Nothing but who holds it: it is made for another
server to read, so it is not sealed under the store key of this one, and the
password of ``files.zip`` is the one everybody knows. While it is being put
together or taken apart on this server it is a sealed file of the store like
any other (``_transfer/``): the files it holds are never in clear on the disk
here. Once downloaded it is the business of whoever downloaded it.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Iterable

import pyzipper
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import artifacts, mailboxes
from . import urlscan as urlscan_store
from .core import store
from .core.config import settings
from .core.models import (
    Artifact,
    ArtifactRelation,
    Mail,
    Mailbox,
    MailboxMessage,
    NetworkCapture,
    Sample,
    UrlScan,
)
from .malware import samples as sample_store
from .network import store as capture_store

FORMAT = "nik-artifacts"
VERSION = 1
PASSWORD = "infected"
MAX_ARTIFACTS = 500
MAX_RECORD_BYTES = 30 * 1024 * 1024
FILES = "files.zip"

_SAMPLE = ("sha256", "sha1", "md5", "size", "type_id", "type_label", "entropy", "created_at", "created_by", "analysis")
_MAIL = (
    "sha256",
    "format",
    "size",
    "subject",
    "sender",
    "sent_at",
    "verdict",
    "score",
    "created_at",
    "created_by",
    "analysis",
)
# Not the TLS key log (a secret, stored encrypted under this server's key) nor the incident.
_CAPTURE = (
    "id",
    "kind",
    "file_name",
    "size",
    "sha256",
    "status",
    "error",
    "packets",
    "first_ms",
    "last_ms",
    "created_at",
    "created_by",
    "meta",
    "summary",
)
_SCAN = (
    "id",
    "url",
    "host",
    "status",
    "error",
    "verdict",
    "score",
    "created_at",
    "created_by",
    "scanned_at",
    "capture_id",
    "result",
)
_MAILBOX = ("id", "file_name", "format", "size", "status", "error", "total", "created_at", "created_by", "meta")
_MESSAGE = (
    "seq",
    "offset",
    "length",
    "sha256",
    "message_id",
    "parent",
    "thread",
    "duplicate_of",
    "subject",
    "sender",
    "recipients",
    "date_ms",
    "attachments",
)
_MODELS = {
    "file": (Sample, _SAMPLE),
    "mail": (Mail, _MAIL),
    "pcap": (NetworkCapture, _CAPTURE),
    "url": (UrlScan, _SCAN),
    "mailbox": (Mailbox, _MAILBOX),
}
MAILBOX_FILE = "mailbox.mbox"
CHUNK = 1024 * 1024


class _Sealing:
    """What a zip is written to when it goes into a sealed file: it is written from start to end,
    never sought back into (the zip formats allow it), and is never in clear on the disk."""

    def __init__(self, out) -> None:
        self._out = out

    def write(self, data) -> int:
        return self._out.write(data)

    def flush(self) -> None:
        return None


def workdir() -> Path:
    """Where an archive is put together and taken apart: on the disk of the store, because a mailbox
    does not fit in the memory a temporary directory may be. What is written there is sealed."""
    path = Path(settings.SAMPLE_STORE) / "_transfer"
    path.mkdir(parents=True, exist_ok=True)
    return path


def files_limit(rows: Iterable[Artifact]) -> int:
    """How many bytes of files one export may hold: twice an upload, and a mailbox when there is one."""
    limit = settings.ARTIFACT_MAX_MB * 2
    if any(row.kind == "mailbox" for row in rows):
        limit += settings.MAILBOX_MAX_MB
    return limit * 1024 * 1024


class TransferError(ValueError):
    """The archive is not one Nik can read."""


# --------------------------------------------------------------------------- #
# Export                                                                      #
# --------------------------------------------------------------------------- #
def _files_of(row: Artifact) -> list[tuple[Path, str]]:
    """The stored files of an artifact as ``(path, name in files.zip)``."""
    found: list[tuple[Path, str]] = []
    if row.kind == "file":
        found.append((sample_store.sample_path(row.ref), f"{row.id}/sample.bin"))
    elif row.kind == "mail":
        found.append((sample_store.mail_path(row.ref), f"{row.id}/message.mail"))
    elif row.kind == "pcap":
        capture = capture_store.find_capture(row.ref)
        if capture is not None:
            found.append((capture, f"{row.id}/{capture.name}"))
        log = Path(settings.SAMPLE_STORE) / "_captures" / row.ref / "log.jsonl"
        found.append((log, f"{row.id}/log.jsonl"))
    elif row.kind == "url":
        found.append((urlscan_store.screenshot_path(row.ref), f"{row.id}/screenshot.jpg"))
        found.append((urlscan_store.scripts_path(row.ref), f"{row.id}/scripts.json"))
    elif row.kind == "mailbox":
        found.append((mailboxes.mbox_path(row.ref), f"{row.id}/{MAILBOX_FILE}"))
    return [(path, name) for path, name in found if path.is_file()]


def _summary(row: Artifact) -> dict[str, Any]:
    return {
        "id": row.id,
        "kind": row.kind,
        "ref": row.ref,
        "name": row.name,
        "verdict": row.verdict,
        "score": row.score,
        "detail": row.detail,
        "size": row.size,
        "tags": list(row.tags or []),
        "createdAt": row.created_at,
        "createdBy": row.created_by,
    }


def export_archive(db: OrmSession, rows: list[Artifact], with_files: bool, now: str, version: str) -> Path:
    """Write the archive to a temporary file of the store, sealed, and return its path (the caller
    serves it with ``stored_response`` and removes it)."""
    ids = {row.id for row in rows}
    relations = [
        {"parent": r.parent_id, "child": r.child_id, "relation": r.relation, "createdAt": r.created_at}
        for r in db.scalars(select(ArtifactRelation).where(ArtifactRelation.parent_id.in_(ids)))
        if r.child_id in ids
    ]
    handle, name = tempfile.mkstemp(prefix="nik-artifacts-", suffix=".zip", dir=workdir())
    os.close(handle)
    path = Path(name)
    inner = Path(name + ".files")
    try:
        entries = []
        with (
            store.writing(path) as sealed_out,
            zipfile.ZipFile(_Sealing(sealed_out), "w", compression=zipfile.ZIP_DEFLATED) as archive,
        ):
            packed: set[str] = set()
            if with_files:
                with (
                    store.writing(inner) as sealed_inner,
                    pyzipper.AESZipFile(
                        _Sealing(sealed_inner), "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
                    ) as files,
                ):
                    files.setpassword(PASSWORD.encode())
                    for row in rows:
                        for source, target in _files_of(row):
                            with files.open(target, "w", force_zip64=True) as packed_file:
                                for piece in store.pieces(source):
                                    packed_file.write(piece)
                            packed.add(target)
            for row in rows:
                if row.kind not in _MODELS:
                    continue
                model, columns = _MODELS[row.kind]
                record = db.get(model, row.ref)
                entry = _summary(row)
                entry["files"] = sorted(target for target in packed if target.startswith(f"{row.id}/"))
                if record is not None:
                    archive.writestr(
                        f"records/{row.id}.json", json.dumps({c: getattr(record, c) for c in columns}, default=str)
                    )
                    entry["record"] = f"records/{row.id}.json"
                    if row.kind == "mailbox":
                        entry["messages"] = _write_messages(db, archive, row)
                entries.append(entry)
            manifest = {
                "format": FORMAT,
                "version": VERSION,
                "nik": version,
                "exportedAt": now,
                "files": bool(with_files),
                "password": PASSWORD if with_files else None,
                "artifacts": entries,
                "relations": relations,
            }
            archive.writestr("manifest.json", json.dumps(manifest, indent=2))
            if with_files:
                # Stored, not deflated again: it is compressed and encrypted already.
                listed = zipfile.ZipInfo(FILES)
                listed.compress_type = zipfile.ZIP_STORED
                with archive.open(listed, "w", force_zip64=True) as out:
                    for piece in store.pieces(inner):
                        out.write(piece)
        return path
    except BaseException:
        path.unlink(missing_ok=True)
        raise
    finally:
        inner.unlink(missing_ok=True)


def _write_messages(db: OrmSession, archive: zipfile.ZipFile, row: Artifact) -> str:
    """The index of a mailbox, a message a line, written as it is read."""
    name = f"records/{row.id}.messages.jsonl"
    found = db.execute(
        select(*(getattr(MailboxMessage, column) for column in _MESSAGE))
        .where(MailboxMessage.mailbox_id == row.ref)
        .order_by(MailboxMessage.seq)
        .execution_options(yield_per=5000)
    )
    with archive.open(name, "w", force_zip64=True) as out:
        for values in found:
            out.write(json.dumps(dict(zip(_MESSAGE, values, strict=True))).encode() + b"\n")
    return name


# --------------------------------------------------------------------------- #
# Import                                                                      #
# --------------------------------------------------------------------------- #
def _json(archive: zipfile.ZipFile, name: str, limit: int = MAX_RECORD_BYTES) -> Any:
    try:
        info = archive.getinfo(name)
    except KeyError:
        raise TransferError(f"The archive has no {name}.") from None
    if info.file_size > limit:
        raise TransferError(f"{name} is too large.")
    try:
        return json.loads(archive.read(name))
    except ValueError:
        raise TransferError(f"{name} is not JSON.") from None


def _read_file(
    files: pyzipper.AESZipFile | None, names: Iterable[str], suffixes: tuple[str, ...]
) -> tuple[str, bytes] | None:
    """The first listed file with one of the suffixes, within the upload limit."""
    if files is None:
        return None
    for name in names:
        if not name.endswith(suffixes):
            continue
        try:
            info = files.getinfo(name)
        except KeyError:
            continue
        if info.file_size > settings.ARTIFACT_MAX_MB * 1024 * 1024:
            raise TransferError(f"{name} exceeds the {settings.ARTIFACT_MAX_MB} MB limit.")
        return name, files.read(name)
    return None


def _columns(record: Any, columns: tuple[str, ...], kind: str) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise TransferError(f"The record of a {kind} is not an object.")
    values = {c: record.get(c) for c in columns}
    for key in ("analysis", "meta", "summary", "result"):
        if key in values and not isinstance(values[key], dict):
            values[key] = {}
    return values


def _whole(value: Any, low: int = 0, high: int = 2**62) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        return None
    return value


def _restore_mailbox(
    db: OrmSession, archive: zipfile.ZipFile, entry: dict[str, Any], record: Any, files, names: list[str], actor: str
) -> str | None:
    """Add a mailbox: its file, copied in pieces, and its index, which must fit the file."""
    ref = entry["ref"]
    values = _columns(record, _MAILBOX, "mailbox")
    listed = next((name for name in names if name.endswith(f"/{MAILBOX_FILE}")), None)
    if files is None or listed is None:
        return "a mailbox needs its file: export it with the files"
    try:
        info = files.getinfo(listed)
    except KeyError:
        return "a mailbox needs its file: export it with the files"
    limit = settings.MAILBOX_MAX_MB * 1024 * 1024
    if info.file_size > limit:
        return f"its file exceeds the {settings.MAILBOX_MAX_MB} MB limit"
    index = str(entry.get("messages") or "")
    if index != f"records/mailbox-{ref}.messages.jsonl" or index not in archive.namelist():
        return "its index is not in the archive"
    target = mailboxes.mbox_path(ref)
    try:
        size = 0
        with files.open(listed) as source, store.writing(target) as out:
            while chunk := source.read(CHUNK):
                size += len(chunk)
                if size > limit:
                    raise TransferError(f"its file exceeds the {settings.MAILBOX_MAX_MB} MB limit")
                out.write(chunk)
        rows, seen = [], set()
        with archive.open(index) as lines:
            for line in lines:
                if len(rows) >= mailboxes.MESSAGES_MAX:
                    raise TransferError("its index holds too many messages")
                try:
                    message = json.loads(line)
                except ValueError:
                    raise TransferError("its index cannot be read") from None
                if not isinstance(message, dict):
                    raise TransferError("its index cannot be read")
                seq, offset, length = (_whole(message.get(key)) for key in ("seq", "offset", "length"))
                # Every message must be inside the file that came with it, and be there once.
                if None in (seq, offset, length) or seq in seen or offset + length > size:
                    raise TransferError("its index does not fit its file")
                seen.add(seq)
                rows.append(
                    {
                        "mailbox_id": ref,
                        "seq": seq,
                        "offset": offset,
                        "length": length,
                        "sha256": str(message.get("sha256") or "")[:64],
                        "message_id": str(message.get("message_id") or "")[:400],
                        "parent": _whole(message.get("parent")),
                        "thread": _whole(message.get("thread")) or 0,
                        "duplicate_of": _whole(message.get("duplicate_of")),
                        "subject": str(message.get("subject") or "")[:500],
                        "sender": str(message.get("sender") or "")[:320],
                        "recipients": str(message.get("recipients") or "")[:500],
                        "date_ms": _whole(message.get("date_ms"), -(2**62)),
                        "attachments": bool(message.get("attachments")),
                    }
                )
    except (TransferError, RuntimeError, OSError) as error:
        mailboxes.remove(ref)
        return str(error) if isinstance(error, TransferError) else "its file cannot be read from the archive"
    meta = values.get("meta") if isinstance(values.get("meta"), dict) else {}
    # What was imported from it there is not imported here: the count starts again.
    meta = {key: value for key, value in meta.items() if key not in ("imported", "verdicts", "progress")}
    db.add(
        Mailbox(
            id=ref,
            file_name=str(values.get("file_name") or entry.get("name") or "")[:255],
            format=str(values.get("format") or "mbox")[:16],
            size=size,
            status="ready",
            error=None,
            # Its messages without the copies of one another, as it counted them: never more than it holds.
            total=min(len(rows), _whole(values.get("total"), 0, len(rows)) or len(rows)),
            created_at=str(values.get("created_at") or entry.get("createdAt") or ""),
            created_by=str(values.get("created_by") or actor),
            meta=meta,
        )
    )
    db.flush()
    for start in range(0, len(rows), 2000):
        db.bulk_insert_mappings(MailboxMessage, rows[start : start + 2000])
    db.flush()
    artifact = artifacts.register_mailbox(db, db.get(Mailbox, ref))
    artifacts.set_tags(db, artifact, entry.get("tags") or [])
    return None


def _restore(db: OrmSession, entry: dict[str, Any], record: Any, files, names: list[str], actor: str) -> str | None:
    """Add one artifact. Returns why it was skipped, or None when it was added."""
    kind, ref = entry["kind"], entry["ref"]
    model, columns = _MODELS[kind]
    values = _columns(record, columns, kind)
    if kind in ("file", "mail"):
        values["sha256"] = ref
        blob = _read_file(files, names, (".bin",) if kind == "file" else (".mail",))
        if blob is not None:
            if hashlib.sha256(blob[1]).hexdigest() != ref:
                return "its file is not the one it is named by (SHA-256 mismatch)"
            (sample_store.write_sample if kind == "file" else sample_store.write_mail)(ref, blob[1])
            values["size"] = len(blob[1])
    elif kind == "pcap":
        blob = _read_file(files, names, (".pcap", ".pcapng", ".gz"))
        log = _read_file(files, names, ("log.jsonl",))
        if blob is None and log is None:
            return "a capture needs its file: export it with the files"
        values["id"] = ref
        if blob is not None:
            ext = blob[0].rsplit(".", 1)[-1]
            if capture_store.capture_format(blob[1][:8]) != ext:
                return "its file is not a packet capture"
            capture_store.write_capture(ref, ext, [blob[1]])
        if log is not None:
            store.write(capture_store.directory(ref) / "log.jsonl", log[1])
        # A session that was live when exported is over here.
        if values.get("status") in ("live", "indexing"):
            values["status"] = "ready" if values.get("summary") else "stored"
    else:
        values["id"] = ref
        shot = _read_file(files, names, (".jpg",))
        if shot is not None:
            store.write(urlscan_store.screenshot_path(ref), shot[1])
        code = _read_file(files, names, ("scripts.json",))
        if code is not None:
            store.write(urlscan_store.scripts_path(ref), code[1])
        if values.get("status") not in ("done", "error"):
            values["status"], values["error"] = "error", "Imported before the scan had finished."
    required = {"file": ("sha1", "md5", "size"), "mail": ("size",), "pcap": (), "url": ("url",)}[kind]
    if any(values.get(name) in (None, "") for name in required):
        return "its record is incomplete"
    for key in ("created_at", "created_by"):
        values[key] = str(values.get(key) or (entry.get("createdAt") if key == "created_at" else actor))
    if db.get(model, ref) is None:
        db.add(model(**{k: v for k, v in values.items() if v is not None or k in ("error", "sent_at", "capture_id")}))
        db.flush()
    row = db.get(model, ref)
    register = {
        "file": artifacts.register_file,
        "mail": artifacts.register_mail,
        "pcap": artifacts.register_capture,
        "url": artifacts.register_url,
    }[kind]
    artifact = register(db, row, str(entry.get("name") or "")) if kind in ("file", "mail") else register(db, row)
    artifacts.set_tags(db, artifact, entry.get("tags") or [])
    return None


def import_archive(db: OrmSession, path: Path, actor: str) -> dict[str, Any]:
    """Add the archive's artifacts that the server does not have. Returns
    ``{added, existing, skipped: [{name, reason}]}``."""
    opened = store.open(path)
    try:
        archive = zipfile.ZipFile(opened)
    except zipfile.BadZipFile:
        opened.close()
        raise TransferError("Not a zip archive.") from None
    with opened, archive:
        manifest = _json(archive, "manifest.json", 20 * 1024 * 1024)
        if not isinstance(manifest, dict) or manifest.get("format") != FORMAT:
            raise TransferError("Not an artifact export of Nik.")
        if manifest.get("version") != VERSION:
            raise TransferError(f"Version {manifest.get('version')} of the export is not understood.")
        entries = manifest.get("artifacts")
        if not isinstance(entries, list) or len(entries) > MAX_ARTIFACTS:
            raise TransferError(f"The archive must list at most {MAX_ARTIFACTS} artifacts.")
        files = inner_file = None
        inner = Path(str(path) + ".files")
        if FILES in archive.namelist():
            # To the disk, in pieces and sealed: with a mailbox in it, it does not fit in memory.
            with archive.open(FILES) as source, store.writing(inner) as out:
                while chunk := source.read(CHUNK):
                    out.write(chunk)
            inner_file = store.open(inner)
            files = pyzipper.AESZipFile(inner_file)
            files.setpassword(PASSWORD.encode())
        added, existing, skipped = [], 0, []
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            kind, ref, name = entry.get("kind"), str(entry.get("ref") or ""), str(entry.get("name") or "")[:255]
            artifact_id = f"{kind}-{ref}"
            if kind not in _MODELS or not artifacts.is_artifact_id(artifact_id) or entry.get("id") != artifact_id:
                skipped.append({"name": name or artifact_id[:40], "reason": "not a valid artifact id"})
                continue
            if db.get(Artifact, artifact_id) is not None:
                existing += 1
                continue
            listed = [n for n in entry.get("files") or [] if isinstance(n, str) and n.startswith(f"{artifact_id}/")]
            try:
                record = _json(archive, f"records/{artifact_id}.json")
                if kind == "mailbox":
                    reason = _restore_mailbox(db, archive, entry, record, files, listed, actor)
                else:
                    reason = _restore(db, entry, record, files, listed, actor)
            except TransferError as exc:
                reason = str(exc)
            except RuntimeError:  # a wrong password or a damaged entry of files.zip
                reason = "its file cannot be read from the archive"
            if reason:
                db.rollback()
                skipped.append({"name": name or artifact_id[:40], "reason": reason})
            else:
                db.commit()
                added.append(artifact_id)
        for relation in manifest.get("relations") or []:
            if (
                isinstance(relation, dict)
                and db.get(Artifact, str(relation.get("parent"))) is not None
                and db.get(Artifact, str(relation.get("child"))) is not None
            ):
                artifacts.relate(db, relation["parent"], relation["child"], str(relation.get("relation") or "")[:40])
        db.commit()
        if files is not None:
            files.close()
            inner_file.close()
        inner.unlink(missing_ok=True)
    return {"added": len(added), "ids": added, "existing": existing, "skipped": skipped}
