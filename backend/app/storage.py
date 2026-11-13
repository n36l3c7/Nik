"""What is on the disk of the file store, and what Nik keeps there.

``usage`` answers the Storage page: the size of the disk that holds
``SAMPLE_STORE``, how much of it is free, and how Nik's own files share the
used part (samples, e-mails, packet captures, mailboxes, ...), with the
largest objects first: those are what to delete when room is needed.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session as OrmSession

from .core.config import settings
from .core.models import Artifact

# id, label, what it is. The order is the order of the page.
GROUPS: tuple[tuple[str, str, str], ...] = (
    ("mailboxes", "Mailboxes", "The mbox files kept to import more messages later."),
    ("captures", "Packet captures", "The pcap files and their logs."),
    ("samples", "Files", "The files analysed, as they were uploaded."),
    ("mails", "E-mails", "The .eml and .msg analysed, and the messages imported from mailboxes."),
    ("previews", "Document previews", "Pages rendered from attachments: made again when needed."),
    ("urls", "URL screenshots", "The pictures of the pages visited."),
    ("rules", "Rules and signatures", "capa rules and FLIRT signatures added by admins."),
    ("database", "Database", "Incidents, analyses, indicators, the audit log."),
)
_FOLDERS = {
    "_mailboxes": "mailboxes",
    "_captures": "captures",
    "_previews": "previews",
    "_urls": "urls",
    "_flirt": "rules",
    "_capa_rules": "rules",
}
_SUFFIXES = {".bin": "samples", ".mail": "mails"}
# The kind of artifact behind an object of a group, to name and open it.
_KINDS = {"mailboxes": "mailbox", "captures": "pcap", "samples": "file", "mails": "mail"}
LARGEST = 10


def _tree_size(path: str) -> tuple[int, int]:
    """Bytes and files under a folder; what cannot be read counts for nothing."""
    size = files = 0
    for root, _dirs, names in os.walk(path, onerror=lambda _error: None):
        for name in names:
            try:
                size += os.lstat(os.path.join(root, name)).st_size
                files += 1
            except OSError:
                continue
    return size, files


def _database_size(db: OrmSession) -> int:
    bind = db.get_bind()
    try:
        if bind.dialect.name == "postgresql":
            return int(db.execute(text("SELECT pg_database_size(current_database())")).scalar() or 0)
        if bind.dialect.name == "sqlite" and bind.url.database and bind.url.database != ":memory:":
            return os.path.getsize(bind.url.database)
    except (OSError, ValueError):
        pass
    return 0


def usage(db: OrmSession) -> dict[str, Any]:
    root = Path(settings.SAMPLE_STORE)
    root.mkdir(parents=True, exist_ok=True)
    disk = shutil.disk_usage(root)
    # Used is what cannot be written any more: with reserved blocks or a quota
    # that is more than the files add up to, and it is what matters here.
    used = disk.total - disk.free
    totals = {group: {"bytes": 0, "files": 0} for group, _label, _about in GROUPS}
    totals["other"] = {"bytes": 0, "files": 0}
    objects: list[tuple[int, str, str]] = []  # size, group, ref

    def add(group: str, size: int, files: int, ref: str = "") -> None:
        totals[group]["bytes"] += size
        totals[group]["files"] += files
        if ref and group in _KINDS:
            objects.append((size, group, ref))

    with os.scandir(root) as entries:
        for entry in entries:
            try:
                if entry.is_dir(follow_symlinks=False):
                    group = _FOLDERS.get(entry.name, "other")
                    if group in ("mailboxes", "captures"):
                        # One folder per object.
                        with os.scandir(entry.path) as children:
                            for child in children:
                                if child.is_dir(follow_symlinks=False):
                                    add(group, *_tree_size(child.path), ref=child.name)
                                else:
                                    add(group, child.stat(follow_symlinks=False).st_size, 1)
                    else:
                        add(group, *_tree_size(entry.path))
                else:
                    stem, suffix = os.path.splitext(entry.name)
                    add(_SUFFIXES.get(suffix, "other"), entry.stat(follow_symlinks=False).st_size, 1, ref=stem)
            except OSError:
                continue

    totals["database"]["bytes"] = _database_size(db)
    largest = []
    for size, group, ref in sorted(objects, reverse=True)[:LARGEST]:
        artifact_id = f"{_KINDS[group]}-{ref}"
        row = db.get(Artifact, artifact_id)
        largest.append(
            {
                "group": group,
                "bytes": size,
                "name": row.name if row else ref,
                "artifactId": artifact_id if row else None,
                "createdAt": row.created_at if row else None,
            }
        )
    groups = [
        {"id": group, "label": label, "about": about, **totals[group]}
        for group, label, about in GROUPS
        if totals[group]["bytes"] or group != "rules"
    ]
    if totals["other"]["bytes"]:
        groups.append(
            {"id": "other", "label": "Other files of Nik", "about": "Files in the store Nik has no name for."}
            | totals["other"]
        )
    nik = sum(group["bytes"] for group in groups)
    return {
        "disk": {"total": disk.total, "used": used, "free": disk.free},
        "nik": nik,
        # What else fills the disk: the system, container images, other software.
        "elsewhere": max(0, used - nik),
        "groups": groups,
        "largest": largest,
        "limits": {"mailboxMb": settings.MAILBOX_MAX_MB, "pstMb": settings.PST_MAX_MB, "pcapMb": settings.PCAP_MAX_MB},
    }
