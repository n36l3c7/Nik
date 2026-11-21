"""Where things are in the archive volume, and the names PostgreSQL gives its segments.

The archive volume (``WAL_ARCHIVE_DIR``, ``/app/wal-archive`` in the stack)::

    wal/<segment>.gz        the log, as this server archived it (deploy/db/wal-archive.sh)
    wal/<n>.history.gz      one small file for each timeline after the first
    base/<label>/           a base backup: base.tar.gz, pg_wal.tar.gz, backup_manifest
    requests/, results/     what the backend asks of the recovery service, and its answers
    incoming/<segment>.gz   segments that came from another host, opened (a standby, a restore)
    restore/<label>/        a base backup that came from another host, opened
    scratch/                the scratch server of the recovery test, while it runs

On the second host, under the directory of the copies (``recovery/``)::

    base/<label>.nikbak     a base backup, sealed under the backup passphrase
    wal/<segment>.nikwal    a segment, sealed the same way
    store/<path>            a file of the store, as it is on the disk (sealed under the store key)
    heartbeat.json          what the first host last said of itself
    superseded.json         written when the standby was promoted

**Segments.** A segment is 16 MB of log and its name is 24 hexadecimal
digits: the timeline (8), then the position (16). A recovery or a promotion
starts a new timeline; names of a later timeline sort after those of an
earlier one, and inside a timeline in the order they were written.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..core.config import settings

SEGMENT_BYTES = 16 * 1024 * 1024
_PER_ID = 0x100000000 // SEGMENT_BYTES
SEGMENT = re.compile(r"^[0-9A-F]{24}$")
HISTORY = re.compile(r"^[0-9A-F]{8}\.history$")
LABEL = re.compile(r"^base-\d{8}-\d{6}$")
GZ = ".gz"
WAL_SUFFIX = ".nikwal"
REMOTE = "recovery"


def root() -> Path | None:
    """The archive volume, or None on a server that has none (a development server, the tests)."""
    return Path(settings.WAL_ARCHIVE_DIR) if settings.WAL_ARCHIVE_DIR else None


def available() -> bool:
    found = root()
    return found is not None and (found / "wal").is_dir()


def folder(name: str) -> Path:
    found = root()
    if found is None:
        raise FileNotFoundError("This server has no archive volume")
    return found / name


def is_segment(name: str) -> bool:
    return bool(SEGMENT.match(name))


def parse(name: str) -> tuple[int, int]:
    """The timeline of a segment and its number on that timeline."""
    if not is_segment(name):
        raise ValueError(f"{name} is not the name of a segment")
    return int(name[:8], 16), int(name[8:16], 16) * _PER_ID + int(name[16:], 16)


def name_of(timeline: int, number: int) -> str:
    return f"{timeline:08X}{number // _PER_ID:08X}{number % _PER_ID:08X}"


def lsn(text: str) -> int:
    """A position in the log as PostgreSQL writes it (``0/4008670``), as a number of bytes."""
    high, _slash, low = str(text).partition("/")
    return int(high, 16) * 0x100000000 + int(low, 16)


def segment_of(timeline: int, position: str | int) -> str:
    """The segment that holds a position of the log."""
    value = lsn(position) if isinstance(position, str) else int(position)
    return name_of(timeline, value // SEGMENT_BYTES)


def next_name(name: str) -> str:
    timeline, number = parse(name)
    return name_of(timeline, number + 1)


def local_segments(*folders: str) -> dict[str, Path]:
    """The segments the archive volume holds, by name: ``wal/`` first, then ``incoming/``."""
    found: dict[str, Path] = {}
    for name in folders or ("wal", "incoming"):
        try:
            place = folder(name)
            entries = sorted(place.iterdir()) if place.is_dir() else []
        except OSError:
            continue
        for path in entries:
            if path.name.endswith(GZ) and is_segment(path.name[: -len(GZ)]):
                found.setdefault(path.name[: -len(GZ)], path)
    return found


def histories(*folders: str) -> dict[str, Path]:
    """The files that describe the timelines (``00000002.history``), by name."""
    found: dict[str, Path] = {}
    for name in folders or ("wal", "incoming"):
        try:
            place = folder(name)
            entries = sorted(place.iterdir()) if place.is_dir() else []
        except OSError:
            continue
        for path in entries:
            if path.name.endswith(GZ) and HISTORY.match(path.name[: -len(GZ)]):
                found.setdefault(path.name[: -len(GZ)], path)
    return found


def gap(names: list[str]) -> str | None:
    """The first segment missing from a sorted run of names of one timeline, or None when each
    follows the one before. A change of timeline is not a gap: the history file says where the
    new one starts."""
    for before, after in zip(names, names[1:], strict=False):
        if before[:8] == after[:8] and after != next_name(before):
            return next_name(before)
    return None


def read_history(timeline: int, *folders: str) -> dict[int, int] | None:
    """What the history file of a timeline says: for each timeline it descends from, the position
    at which the next one left it. None when the archive does not hold the file (timeline 1 has
    none, and descends from nothing)."""
    import gzip

    if timeline <= 1:
        return {}
    path = histories(*folders).get(f"{timeline:08X}.history")
    if path is None:
        return None
    found: dict[int, int] = {}
    try:
        with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                pieces = line.split()
                if len(pieces) >= 2 and pieces[0].isdigit() and "/" in pieces[1]:
                    found[int(pieces[0])] = lsn(pieces[1])
    except (OSError, ValueError, EOFError):
        return None
    return found


def on_history(timeline: int, position: int, current: int, history: dict[int, int] | None) -> bool:
    """Whether a position of the log on ``timeline`` is part of the past of the timeline
    ``current``: on it, or on one it descends from, before the point where that one was left."""
    if timeline == current:
        return True
    if history is None:
        return timeline < current  # the file is not there to say: not refused on a guess
    return timeline in history and position <= history[timeline]
