"""Files of the network captures: ``SAMPLE_STORE/_captures/<id>/``.

- ``capture.<pcap|pcapng|gz>``: the capture, read-only for everyone (0o444)
  so the packet capture worker reads it through its read-only mount;
- ``log.jsonl``: an isolated browser session's network log, one entry per
  line; a later line for the same ``id`` replaces the earlier one (an entry
  changes until its request ends). Readable by the backend only.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any, Iterable

from ..core.config import settings

STORE_MODE = 0o444
_ID = re.compile(r"^[0-9a-f]{32}$")

# Magic bytes of the formats the worker reads, and the extension each is stored with.
MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x0a\x0d\x0d\x0a", "pcapng"),
    (b"\xd4\xc3\xb2\xa1", "pcap"),
    (b"\xa1\xb2\xc3\xd4", "pcap"),
    (b"\x4d\x3c\xb2\xa1", "pcap"),  # nanosecond resolution
    (b"\xa1\xb2\x3c\x4d", "pcap"),
    (b"\x1f\x8b", "gz"),
)


def is_capture_id(value: str) -> bool:
    return bool(_ID.match(value or ""))


def capture_format(head: bytes) -> str | None:
    """``pcap``, ``pcapng`` or ``gz`` from the first bytes, or None."""
    return next((ext for magic, ext in MAGIC if head.startswith(magic)), None)


def directory(capture_id: str) -> Path:
    if not is_capture_id(capture_id):
        raise ValueError("Not a capture id.")
    path = Path(settings.SAMPLE_STORE) / "_captures" / capture_id
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, 0o755)
    os.chmod(path.parent, 0o755)
    return path


def capture_path(capture_id: str, ext: str) -> Path:
    return directory(capture_id) / f"capture.{ext}"


def relative_path(capture_id: str, ext: str) -> str:
    """The path the packet capture worker opens (relative to the sample store)."""
    return f"_captures/{capture_id}/capture.{ext}"


def seal(part: Path, path: Path) -> Path:
    """Make a finished file read-only and give it its final name."""
    os.chmod(part, STORE_MODE)
    part.replace(path)
    return path


def write_capture(capture_id: str, ext: str, chunks: Iterable[bytes]) -> Path:
    path = capture_path(capture_id, ext)
    part = path.with_suffix(".part")
    with open(part, "wb") as handle:
        for chunk in chunks:
            handle.write(chunk)
    return seal(part, path)


def find_capture(capture_id: str) -> Path | None:
    folder = Path(settings.SAMPLE_STORE) / "_captures" / capture_id
    for ext in ("pcapng", "pcap", "gz"):
        if (folder / f"capture.{ext}").is_file():
            return folder / f"capture.{ext}"
    return None


def remove(capture_id: str) -> None:
    if not is_capture_id(capture_id):
        return
    folder = Path(settings.SAMPLE_STORE) / "_captures" / capture_id
    if folder.is_dir():
        for item in folder.iterdir():
            os.chmod(item, stat.S_IRUSR | stat.S_IWUSR)
        shutil.rmtree(folder, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Browser session logs                                                        #
# --------------------------------------------------------------------------- #
def append_log(capture_id: str, entries: list[dict[str, Any]]) -> None:
    if not entries:
        return
    with open(directory(capture_id) / "log.jsonl", "a", encoding="utf-8") as handle:
        for entry in entries:
            handle.write(json.dumps(entry, separators=(",", ":")) + "\n")


def read_log(capture_id: str) -> list[dict[str, Any]]:
    """The entries of a session log, latest version of each, in request order."""
    path = Path(settings.SAMPLE_STORE) / "_captures" / capture_id / "log.jsonl"
    if not is_capture_id(capture_id) or not path.is_file():
        return []
    entries: dict[int, dict[str, Any]] = {}
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            entries[entry["id"]] = entry
    return [entries[key] for key in sorted(entries)]


def light(entry: dict[str, Any]) -> dict[str, Any]:
    """An entry without its bodies (the request list)."""
    out = {k: v for k, v in entry.items() if k not in ("request", "response", "frames")}
    for part in ("request", "response"):
        if entry.get(part):
            out[part] = {k: v for k, v in entry[part].items() if k not in ("body", "headers")}
    if entry.get("frames") is not None:
        out["frameCount"] = len(entry["frames"])
    return out
