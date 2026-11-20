"""Uploads read within a limit, and downloads named safely.

File names in Nik come from evidence: an attachment of a phishing mail, an
object carved out of a capture, a sample as the attacker called it. They are
shown, and offered back as downloads, but never trusted.
"""

from __future__ import annotations

import re
from urllib.parse import quote

from fastapi import HTTPException, UploadFile
from fastapi.responses import StreamingResponse

CHUNK = 1024 * 1024
# Path separators, quotes, control characters, and the Unicode marks that
# reorder the text of a name (the "exe.fdp" → "pdf.exe" trick).
_UNSAFE = re.compile(r'[\\/"\x00-\x1f\x7f\u200e\u200f\u202a-\u202e\u2066-\u2069]')


async def read_upload(file: UploadFile, max_mb: int, what: str = "file") -> bytes:
    """The uploaded file's bytes, refused with 413 as soon as it passes ``max_mb``.

    The limit is enforced while reading, so an oversized upload is dropped
    after ``max_mb`` megabytes instead of being held whole in memory first.
    """
    limit = max_mb * 1024 * 1024
    chunks, size = [], 0
    while chunk := await file.read(CHUNK):
        size += len(chunk)
        if size > limit:
            raise HTTPException(status_code=413, detail=f"The {what} exceeds the {max_mb} MB limit.")
        chunks.append(chunk)
    return b"".join(chunks)


def safe_name(name: str | None, fallback: str = "download", limit: int = 200) -> str:
    """A file name with nothing in it that a path, a header or a reader could misread."""
    clean = _UNSAFE.sub("_", str(name or "")).strip(" .")[:limit]
    return clean or fallback


def attachment_headers(name: str) -> dict[str, str]:
    """``Content-Disposition`` for a download called ``name`` (already ``safe_name``d or not).

    The plain ``filename`` is ASCII for old clients; ``filename*`` (RFC 5987)
    carries the real name, so a Cyrillic or Chinese attachment downloads under
    its own name instead of failing to encode.
    """
    clean = safe_name(name)
    ascii_name = clean.encode("ascii", "replace").decode("ascii").replace("?", "_")
    return {"Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(clean, safe='')}"}


_RANGE = re.compile(r"^bytes=(\d*)-(\d*)$")


def stored_response(
    path,
    media_type: str,
    filename: str | None = None,
    headers: dict[str, str] | None = None,
    range_header: str | None = None,
) -> StreamingResponse:
    """A file of the store as a download: decrypted as it is sent, a piece at a time, never whole in
    memory. Opening it here checks its head and its end, so a file that is damaged is refused with an
    answer of its own (``store.Damaged``) before anything is sent. One range (``Range: bytes=a-b``)
    is served by decrypting the chunks that hold it.
    """
    from . import store

    with store.open(path) as handle:
        handle.seek(0, 2)
        size = handle.tell()
    sent = {"Accept-Ranges": "bytes", **(attachment_headers(filename) if filename else {}), **(headers or {})}
    start, end, status_code = 0, size, 200
    match = _RANGE.match((range_header or "").strip())
    if match and (match.group(1) or match.group(2)):
        if match.group(1):
            start = int(match.group(1))
            end = min(size, int(match.group(2)) + 1) if match.group(2) else size
        else:
            start = max(0, size - int(match.group(2)))
        if start >= size or end <= start:
            raise HTTPException(status_code=416, detail="The range asked for is not in the file.")
        status_code = 206
        sent["Content-Range"] = f"bytes {start}-{end - 1}/{size}"
    sent["Content-Length"] = str(end - start)
    return StreamingResponse(
        store.pieces(path, start, end, CHUNK), status_code=status_code, media_type=media_type, headers=sent
    )
