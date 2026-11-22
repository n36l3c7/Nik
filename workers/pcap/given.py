"""The files a worker is given to work on, and the secret it is started with.

The store of files is sealed and no worker sees it: a worker parses hostile
files and is the likeliest thing to be subverted, so it holds neither the
store nor its key. The backend sends the bytes a job needs:

    PUT /files/<name>     the body is the file; the same token as every request

and a request that names a file the worker does not hold is answered
``409 {"missing": [names]}``: the backend sends those and asks again.

What is given is kept in a folder of the worker's own for as long as it is
used: a file nobody asked for during ``idle`` seconds is deleted, the least
recently used go first when room is needed, and everything is deleted when
the worker starts. ``<64 hex>.bin`` is a sample: its SHA-256 must be its
name, or it is refused.

This file is the same in every worker that is given files (analyzer, capa,
pcap): each image is built from its own folder and holds its own copy.
Standard library only.
"""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import threading
import time

PIECE = 1024 * 1024
_SAMPLE = re.compile(r"^([0-9a-f]{64})\.bin$")


def secret(name: str) -> str:
    """The secret called ``name``: the content of the file ``<name>_FILE`` names when it holds
    something (a mounted secret), else the variable itself. Never both."""
    value = os.environ.get(name, "")
    path = os.environ.get(f"{name}_FILE", "").strip()
    if not path:
        return value
    try:
        with open(path, encoding="utf-8") as handle:
            held = handle.read(65536).strip("\r\n")
    except OSError as error:
        raise SystemExit(
            f"{name}_FILE names {path}, which cannot be read ({error.strerror}): refusing to start."
        ) from None
    if held and value:
        raise SystemExit(f"{name} is given twice, in the file named by {name}_FILE and in the environment: keep one.")
    return held or value


class Refused(Exception):
    """A file that is not taken: the status to answer with, and why."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status, self.detail = status, detail


class Given:
    """The folder of what the backend gave.

    ``allowed`` are the patterns a name must match in full. ``large`` is a
    second folder, on a disk, for a file of more than ``large_from`` bytes
    (a capture too big for memory); without it everything is in ``folder``.
    """

    def __init__(
        self,
        folder: str,
        allowed: tuple[re.Pattern, ...],
        max_bytes: int,
        idle: float = 900.0,
        large: str | None = None,
        large_from: int = 0,
    ) -> None:
        self.folder, self.allowed, self.max_bytes, self.idle = folder, allowed, max_bytes, idle
        self.large, self.large_from = large, large_from
        self._lock = threading.Lock()
        self._used: dict[str, float] = {}
        self._busy: dict[str, int] = {}

    # -- where --------------------------------------------------------------- #
    def _folders(self) -> list[str]:
        return [self.folder] + ([self.large] if self._large_usable() else [])

    def _large_usable(self) -> bool:
        return bool(self.large) and os.path.isdir(self.large) and os.access(self.large, os.W_OK | os.X_OK)

    def _valid(self, name: str) -> bool:
        return isinstance(name, str) and any(pattern.fullmatch(name) for pattern in self.allowed)

    def _find(self, name: str) -> str | None:
        for folder in self._folders():
            root = os.path.realpath(os.path.join(folder, "files"))
            path = os.path.realpath(os.path.join(root, name))
            # The name was matched against the allowed patterns; the file must also be inside the
            # folder once links are followed, so nothing outside it is ever handed to a parser.
            if path.startswith(root + os.sep) and os.path.isfile(path):
                return path
        return None

    def clear(self) -> None:
        """Nothing a stopped worker left is kept: at start the folders are emptied."""
        for folder in [self.folder] + ([self.large] if self.large else []):
            for part in ("files", "incoming"):
                shutil.rmtree(os.path.join(folder, part), ignore_errors=True)
        self._used.clear()

    # -- reading -------------------------------------------------------------- #
    def path(self, name: str) -> str | None:
        """Where the file is, or None when the worker does not hold it. Asking marks it as used."""
        if not self._valid(name):
            return None
        with self._lock:
            found = self._find(name)
            if found is not None:
                self._used[name] = time.monotonic()
            return found

    def missing(self, names: list[str]) -> list[str]:
        return [name for name in names if self.path(name) is None]

    def hold(self, names: list[str]):
        """While the block runs, these files are not deleted to make room nor for being idle."""
        given = self

        class _Held:
            def __enter__(self) -> None:
                with given._lock:
                    for name in names:
                        given._busy[name] = given._busy.get(name, 0) + 1

            def __exit__(self, *_exc) -> None:
                with given._lock:
                    for name in names:
                        given._busy[name] -= 1
                        if not given._busy[name]:
                            del given._busy[name]
                        given._used[name] = time.monotonic()

        return _Held()

    # -- taking --------------------------------------------------------------- #
    def _held_bytes(self) -> list[tuple[float, str, str, int]]:
        found = []
        for folder in self._folders():
            root = os.path.join(folder, "files")
            for base, _dirs, names in os.walk(root):
                for file_name in names:
                    path = os.path.join(base, file_name)
                    name = os.path.relpath(path, root).replace(os.sep, "/")
                    try:
                        found.append((self._used.get(name, 0.0), name, path, os.path.getsize(path)))
                    except OSError:
                        continue
        return found

    def _delete(self, name: str, path: str) -> None:
        try:
            os.unlink(path)
        except OSError:
            pass
        self._used.pop(name, None)

    def _make_room(self, folder: str, size: int) -> None:
        held = sorted(self._held_bytes())
        total = sum(entry[3] for entry in held)
        for _used, name, path, length in held:
            if total + size <= self.max_bytes:
                break
            if name in self._busy:
                continue
            self._delete(name, path)
            total -= length
        if total + size > self.max_bytes:
            raise Refused(507, "The worker has no room for this file: the files it works on fill what it may hold")
        os.makedirs(folder, exist_ok=True)
        free = shutil.disk_usage(folder).free
        if free < size + PIECE:
            raise Refused(
                507, f"The worker has no room for this file: it is {size} bytes and {free} are free where it works"
            )

    def take(self, name: str, stream, length: int) -> None:
        """Read ``length`` bytes of ``stream`` as the file ``name``."""
        if not self._valid(name):
            raise Refused(400, "Not a file this worker is given")
        if length < 0 or length > self.max_bytes:
            raise Refused(413, "The file is larger than what the worker may hold")
        folder = self.large if self._large_usable() and length > self.large_from else self.folder
        with self._lock:
            self._make_room(folder, length)
        incoming = os.path.join(folder, "incoming")
        os.makedirs(incoming, exist_ok=True)
        part = os.path.join(incoming, f"{os.getpid()}-{threading.get_ident()}-{time.monotonic_ns()}")
        digest = hashlib.sha256()
        try:
            with open(part, "wb") as out:
                left = length
                while left > 0:
                    piece = stream.read(min(PIECE, left))
                    if not piece:
                        raise Refused(400, "The file stopped before its end")
                    digest.update(piece)
                    out.write(piece)
                    left -= len(piece)
            sample = _SAMPLE.fullmatch(name)
            if sample and sample.group(1) != digest.hexdigest():
                raise Refused(422, "The file is not the one its name says: its SHA-256 is another")
            root = os.path.realpath(os.path.join(folder, "files"))
            target = os.path.realpath(os.path.join(root, name))
            if not target.startswith(root + os.sep):
                raise Refused(400, "Not a file this worker is given")
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with self._lock:
                stale = self._find(name)
                if stale is not None and stale != target:
                    self._delete(name, stale)
                os.replace(part, target)
                self._used[name] = time.monotonic()
        finally:
            if os.path.exists(part):
                os.unlink(part)

    def drop(self, name: str) -> None:
        with self._lock:
            found = self._find(name) if self._valid(name) else None
            if found is not None:
                self._delete(name, found)

    def drop_prefix(self, prefix: str) -> None:
        """Delete every file whose name starts with ``prefix`` (the files of one capture)."""
        with self._lock:
            for _used, name, path, _length in self._held_bytes():
                if name.startswith(prefix) and name not in self._busy:
                    self._delete(name, path)

    def expire(self) -> None:
        """Delete what nobody asked for during ``idle`` seconds."""
        now = time.monotonic()
        with self._lock:
            for _used, name, path, _length in self._held_bytes():
                if name not in self._busy and now - self._used.get(name, 0.0) > self.idle:
                    self._delete(name, path)


def take_request(handler, given: Given, authorized: bool) -> None:
    """Answer ``PUT /files/<name>`` on a ``BaseHTTPRequestHandler`` that has ``_send``."""
    if not handler.path.startswith("/files/"):
        return handler._send(404, {"detail": "Not found"})
    if not authorized:
        return handler._send(401, {"detail": "Missing or wrong token"})
    try:
        length = int(handler.headers.get("Content-Length", ""))
    except ValueError:
        return handler._send(411, {"detail": "The size of the file must be said (Content-Length)"})
    try:
        given.take(handler.path[len("/files/") :], handler.rfile, length)
    except Refused as refused:
        # What was not read of the body must not be taken for the next request.
        handler.close_connection = True
        return handler._send(refused.status, {"detail": refused.detail})
    return handler._send(200, {})
