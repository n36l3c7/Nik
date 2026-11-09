"""FLIRT signature files uploaded by admins, kept in the sample store.

The analyzer worker sees the sample store read-only, so the files are stored
under ``<SAMPLE_STORE>/_flirt/<id>.<sig|pat>`` and passed to it as relative
paths. Only the format is checked here (the ``IDASGN`` magic of a compiled
.sig, the line layout of a .pat): rizin parses them, inside the worker.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .models import FlirtSignature
from .samples import store_dir

MAX_BYTES = 32 * 1024 * 1024
SIG_MAGIC = b"IDASGN"
FOLDER = "_flirt"
_ID_RE = re.compile(r"^[0-9a-f]{32}$")
# A .pat line: leading bytes (hex or '..'), CRC length and value, function size, then names.
_PAT_LINE = re.compile(rb"^[0-9A-Fa-f.]{2,128} [0-9A-Fa-f]{2} [0-9A-Fa-f]{4} [0-9A-Fa-f]{4,8} :")


class SignatureError(ValueError):
    """The uploaded file is not a FLIRT signature Nik can use."""


def kind_of(file_name: str, data: bytes) -> str:
    """'sig' or 'pat' after checking the content matches the extension."""
    extension = Path(file_name or "").suffix.lower()
    if not data:
        raise SignatureError("The file is empty.")
    if len(data) > MAX_BYTES:
        raise SignatureError(f"The file exceeds the {MAX_BYTES // (1024 * 1024)} MB signature limit.")
    if extension == ".sig":
        if not data.startswith(SIG_MAGIC):
            raise SignatureError("Not a compiled FLIRT signature (missing the IDASGN header).")
        return "sig"
    if extension == ".pat":
        first = next((line for line in data.splitlines() if line.strip()), b"")
        if not _PAT_LINE.match(first) or b"---" not in data:
            raise SignatureError("Not a FLIRT pattern file (unexpected line layout).")
        return "pat"
    raise SignatureError("Upload a .sig or .pat file.")


def relative_path(row: FlirtSignature) -> str:
    """The path the worker resolves against its read-only view of the store."""
    return f"{FOLDER}/{row.id}.{row.kind}"


def _absolute(signature_id: str, kind: str) -> Path:
    if not _ID_RE.match(signature_id) or kind not in ("sig", "pat"):
        raise ValueError("Invalid signature identifier.")
    folder = store_dir() / FOLDER
    folder.mkdir(exist_ok=True)
    return folder / f"{signature_id}.{kind}"


def write_file(signature_id: str, kind: str, data: bytes) -> None:
    """Store the file read-only for everyone (the worker runs as another user)."""
    path = _absolute(signature_id, kind)
    tmp = path.with_suffix(".part")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o444)
    tmp.replace(path)


def delete_file(row: FlirtSignature) -> None:
    path = _absolute(row.id, row.kind)
    if path.exists():
        os.chmod(path, 0o640)
        path.unlink()


def enabled_paths(db: OrmSession) -> list[str]:
    """Relative paths of the enabled signatures, oldest first, for the worker."""
    rows = db.scalars(
        select(FlirtSignature).where(FlirtSignature.enabled.is_(True)).order_by(FlirtSignature.created_at)
    ).all()
    return [relative_path(row) for row in rows]
