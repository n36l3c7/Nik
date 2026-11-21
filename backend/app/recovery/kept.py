"""A file that is deleted is kept for as long as a recovery could still need it.

The files of the store are not in the log of PostgreSQL. Bringing the
database back to a moment brings back rows that name files; a file deleted
since (an artifact that expired, a sample an analyst removed) would be named
and not there. So on a server that archives its log a deletion does not
remove the file: it moves it into ``.kept/<when>/<its path>`` of the store
(a rename on the same disk: nothing is copied), and it is really removed
when no recovery can reach back to before its deletion (``purge``, called by
the loop of ``archive.py`` with the oldest moment one can go back to).

A recovery puts back the files the database names again (``put_back``) and
reports, by name, those that are neither in the store nor here.

**The cost.** What is deleted goes on taking its room for the days one can
go back (two, unless set otherwise): the Storage page counts it on a line of
its own.

A kept file is still sealed under the store key, bound to the path it had:
it is moved back to that path and nowhere else. The conversion of a store
and the change of the store key reach the kept files as they reach the
others (``store_seal._files``), so one that comes back opens.

Previews and what an interrupted transfer left are not kept: the first are
made again when asked for, the second were never files of the store.
"""

from __future__ import annotations

import contextlib
import logging
import os
import shutil
import time
from pathlib import Path

from ..core.config import settings

logger = logging.getLogger("nik.recovery")

KEPT = ".kept"
NOT_KEPT = ("_previews/", "_transfer/")
LEFTOVERS = (".part", ".sealing")


def enabled() -> bool:
    """On a server that has an archive of its log: without one there is no moment to go back to."""
    return bool(settings.WAL_ARCHIVE_DIR)


def _root() -> Path:
    return Path(settings.SAMPLE_STORE)


def _name(path: Path) -> str | None:
    try:
        return path.resolve().relative_to(_root().resolve()).as_posix()
    except ValueError:
        return None


def real_name(name: str) -> str:
    """The path a file of the store is sealed under: what it was before it was set aside."""
    pieces = name.split("/")
    return "/".join(pieces[2:]) if len(pieces) > 2 and pieces[0] == KEPT else name


def keep(path: str | os.PathLike, now: float | None = None) -> bool:
    """Set a file or a folder of the store aside instead of deleting it. False when it is not kept
    (the caller then deletes it): no archive, a file that is not worth keeping, or a disk that
    refused the move."""
    if not enabled():
        return False
    path = Path(path)
    name = _name(path)
    if name is None or name in ("", ".") or name.startswith(KEPT) or name.endswith(LEFTOVERS):
        return False
    if (name + "/").startswith(NOT_KEPT):
        return False
    stamp = int(time.time() if now is None else now)
    target = _root() / KEPT / str(stamp) / name
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            # Deleted twice in one second under one name: the first copy is the older content.
            return False
        os.replace(path, target)
        return True
    except OSError as error:
        logger.warning("A deleted file could not be kept for recovery (%s): it is removed", error)
        return False


def _stamps() -> list[tuple[int, Path]]:
    folder = _root() / KEPT
    found = []
    try:
        entries = list(folder.iterdir()) if folder.is_dir() else []
    except OSError:
        return []
    for entry in entries:
        if entry.name.isdigit() and entry.is_dir():
            found.append((int(entry.name), entry))
    return sorted(found)


def purge(before: float) -> int:
    """Really remove what was deleted before ``before``. Returns how many deletions went."""
    removed = 0
    for stamp, folder in _stamps():
        if stamp < before:
            shutil.rmtree(folder, ignore_errors=True)
            removed += int(not folder.exists())
    return removed


def usage() -> dict[str, int]:
    """How much the kept files take, and since when the oldest is kept."""
    files = size = 0
    stamps = _stamps()
    for _stamp, folder in stamps:
        for parent, _folders, names in os.walk(folder, onerror=lambda _error: None):
            for name in names:
                with contextlib.suppress(OSError):
                    size += os.lstat(os.path.join(parent, name)).st_size
                    files += 1
    return {"files": files, "bytes": size, "oldest": stamps[0][0] if stamps else 0}


def find(name: str, moment: float) -> Path | None:
    """The kept copy of ``name`` to put back for a recovery to ``moment``: the one set aside
    first after that moment (the file as it was then), else the latest one there is."""
    found = [(stamp, folder / name) for stamp, folder in _stamps() if (folder / name).exists()]
    if not found:
        return None
    after = [entry for entry in found if entry[0] >= moment - 1]
    return (after[0] if after else found[-1])[1]


def put_back(name: str, moment: float) -> bool:
    """Move the kept copy of a file (or of a folder) back to its place. False when there is none."""
    source = find(name, moment)
    if source is None:
        return False
    target = _root() / name
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            return True
        os.replace(source, target)
        return True
    except OSError as error:
        logger.warning("The kept copy of %s could not be put back: %s", name, error)
        return False
