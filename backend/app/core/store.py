"""Reading and writing the files of the store: everything on the disk is sealed.

Whatever Nik keeps under ``SAMPLE_STORE`` (samples, e-mails, captures and
their logs, mailboxes, previews, screenshots, rule files) goes through this
module and nothing opens a path of the store by itself. A file is written
sealed (``core/sealed.py``) under the store key of the server, beside its
place and then moved there, so a file is whole or absent; it is read through
a reader that decrypts the chunks asked for and checks each one.

**The name.** A sealed file is bound to its path inside the store: the same
bytes under another name do not open.

**Files from before 6.8** are in clear until the conversion reaches them
(``app/store_seal.py``). ``open`` reads both forms while that runs. Once the
whole store is sealed, a file found in clear is not one Nik wrote: it is
refused like a damaged one (``clear_allowed`` says which time it is).

**A file that does not open** (changed, cut short, moved, or sealed under a
key this server does not hold) raises ``sealed.Damaged`` or
``sealed.WrongKey``, never returns bytes, and is reported through
``report_damaged`` (the audit log and a notice to the administrators).

**A process without the store key** (the automation worker) reads nothing
here: ``local()`` is false and it asks the API process (``app/store_handover.py``).
"""

from __future__ import annotations

import contextlib
import io
import os
import shutil
import threading
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import BinaryIO

from . import sealed
from .config import settings
from .sealed import Damaged, SealError, WrongKey  # noqa: F401 - what callers catch

PART = ".part"
PIECE = 1024 * 1024
# Readable by the server alone: no other user of the host or of a container needs a sealed file.
MODE = 0o600

# Set by app/store_seal.py: whether files in clear may still be in the store (the conversion of a
# store from before 6.8 has not finished), and what is done when a file does not open.
clear_allowed: Callable[[], bool] = lambda: True  # noqa: E731
report_damaged: Callable[[str, str], None] = lambda name, reason: None  # noqa: E731

_ring: tuple[tuple[str, tuple[str, ...]], sealed.Keyring] | None = None
_ring_lock = threading.Lock()


def local() -> bool:
    """Whether this process holds the store key: it reads and writes the store itself."""
    return bool(settings.STORE_KEY)


def keyring() -> sealed.Keyring:
    global _ring
    given = (settings.STORE_KEY, tuple(settings.STORE_KEY_PREVIOUS))
    with _ring_lock:
        if _ring is None or _ring[0] != given:
            if not given[0]:
                raise SealError("This process does not hold the store key")
            _ring = (given, sealed.Keyring.of(*given))
        return _ring[1]


def root() -> Path:
    return Path(settings.SAMPLE_STORE)


def name_of(path: str | os.PathLike) -> str:
    """The name a file is sealed under: its path inside the store, with forward slashes."""
    path = Path(path)
    try:
        return path.resolve().relative_to(root().resolve()).as_posix()
    except ValueError:
        return path.name


class DamagedFile(Damaged, OSError):
    """A file of the store that is not what Nik wrote. Also an ``OSError``: what only knows that a
    file may fail to be read treats it as one that cannot be, and what shows the reason has it."""


class WrongKeyFile(WrongKey, OSError):
    """A file of the store sealed under a store key this server does not hold."""


def _damaged(name: str, error: SealError) -> SealError:
    """The error raised for a file that does not open: it names the file, and the administrators
    are told (``report_damaged``)."""
    if isinstance(error, (DamagedFile, WrongKeyFile)):
        return error
    try:
        report_damaged(name, str(error))
    except Exception:  # noqa: BLE001 - telling must not hide the failure itself
        pass
    if isinstance(error, WrongKey):
        return WrongKeyFile(f"The file {name} of the store cannot be opened and is not served: {error}")
    return DamagedFile(f"The file {name} of the store is damaged and is not served: {error}")


class _Reader(sealed.Reader):
    """A sealed file of the store being read: a chunk that does not open is reported, with its name."""

    def _load(self, number: int) -> bytes:
        try:
            return super()._load(number)
        except Damaged as error:
            raise _damaged(self.name, error) from None


def is_sealed(path: str | os.PathLike) -> bool:
    with io.open(path, "rb") as handle:
        return sealed.is_sealed(handle.read(len(sealed.MAGIC)))


def open(path: str | os.PathLike, name: str | None = None) -> BinaryIO:  # noqa: A001 - used as store.open
    """The content of a file of the store, open for reading: sought and read like any file."""
    path = Path(path)
    name = name_of(path) if name is None else name
    ring = keyring()
    raw = io.open(path, "rb")
    try:
        head = raw.read(len(sealed.MAGIC))
        if not sealed.is_sealed(head):
            if not clear_allowed():
                raise Damaged("it is in clear, and every file of this store was sealed")
            raw.seek(0)
            return raw
        return io.BufferedReader(_Reader(raw, name, ring), buffer_size=sealed.CHUNK)
    except SealError as error:
        raw.close()
        raise _damaged(name, error) from None
    except BaseException:
        raw.close()
        raise


def read_bytes(path: str | os.PathLike) -> bytes:
    name = name_of(path)
    with open(path, name) as handle:
        return handle.read()


def read_text(path: str | os.PathLike, encoding: str = "utf-8") -> str:
    return read_bytes(path).decode(encoding)


def size(path: str | os.PathLike) -> int:
    """How many bytes of content the file holds (not what it takes on the disk)."""
    with io.open(path, "rb") as handle:
        head = handle.read(sealed.HEADER)
        total = os.fstat(handle.fileno()).st_size
    if not sealed.is_sealed(head):
        return total
    return sealed.plain_size(total, sealed.parse_head(head).chunk)


def pieces(path: str | os.PathLike, start: int = 0, end: int | None = None, piece: int = PIECE) -> Iterator[bytes]:
    """The content from ``start`` to ``end`` (not included), a piece at a time: what a download streams."""
    name = name_of(path)
    with open(path, name) as handle:
        handle.seek(start)
        left = None if end is None else max(0, end - start)
        while left is None or left > 0:
            data = handle.read(piece if left is None else min(piece, left))
            if not data:
                break
            if left is not None:
                left -= len(data)
            yield data


def remove_tree(folder: str | os.PathLike) -> None:
    """Delete a folder of the store with everything in it (the files of one capture, of one mailbox)."""
    folder = Path(folder)
    if not local():
        from .. import store_handover

        store_handover.ask_removal([name_of(folder)])
        return
    with _swap():
        if folder.is_dir():
            if _set_aside(folder):
                return
            for item in folder.iterdir():
                with contextlib.suppress(OSError):
                    os.chmod(item, 0o600)
            shutil.rmtree(folder, ignore_errors=True)


_swap_lock = threading.Lock()


@contextlib.contextmanager
def swapping() -> Iterator[None]:
    """Held while a file takes its place or is deleted, and while the conversion puts the sealed copy
    of a file in the place of the clear one: so the conversion never puts back a file that was
    written again or deleted in between. Between the threads of this process always; between the
    processes of the server through a lock file, where the system has one (``fcntl``)."""
    with _swap_lock:
        handle = None
        try:
            import fcntl
            import tempfile

            handle = io.open(os.path.join(tempfile.gettempdir(), "nik-store.lock"), "a")
            fcntl.flock(handle, fcntl.LOCK_EX)
        except (ImportError, OSError):
            pass
        try:
            yield
        finally:
            if handle is not None:
                handle.close()


def _swap():
    """The lock, only while a conversion may be running: once the store is sealed nothing races."""
    return swapping() if clear_allowed() else contextlib.nullcontext()


class _Writing:
    """A file of the store being written: ``write`` its content; it takes its place when the block ends."""

    def __init__(self, out: BinaryIO, writer: sealed.Writer) -> None:
        self._out, self._writer = out, writer

    def write(self, data: bytes | bytearray | memoryview) -> int:
        return self._writer.write(data)

    @property
    def size(self) -> int:
        return self._writer.size


@contextlib.contextmanager
def writing(path: str | os.PathLike, mode: int = MODE, name: str | None = None) -> Iterator[_Writing]:
    """Write a file of the store, sealed. It is written beside its place and moved there when the
    block ends without an error; when it does not, nothing is left."""
    path = Path(path)
    name = name_of(path) if name is None else name
    part = path.with_name(path.name + PART)
    key = keyring().current
    try:
        with io.open(part, "wb") as out:
            writer = sealed.Writer(out, name, key)
            yield _Writing(out, writer)
            writer.close()
            out.flush()
            os.fsync(out.fileno())
        os.chmod(part, mode)
        with _swap():
            if path.exists():
                # A file that was written read-only (before 6.8) is in the way of the move on some systems.
                with contextlib.suppress(OSError):
                    os.chmod(path, 0o600)
            os.replace(part, path)
    except BaseException:
        with contextlib.suppress(OSError):
            part.unlink()
        raise


def write(path: str | os.PathLike, data: bytes | Iterable[bytes], mode: int = MODE) -> int:
    """Write ``data`` (bytes, or pieces of them) as a file of the store. Returns its size."""
    with writing(path, mode) as out:
        if isinstance(data, (bytes, bytearray, memoryview)):
            out.write(data)
        else:
            for piece in data:
                out.write(piece)
        return out.size


def write_text(path: str | os.PathLike, text: str, encoding: str = "utf-8") -> int:
    return write(path, text.encode(encoding))


def remove(path: str | os.PathLike) -> None:
    """Delete a file of the store. Its key goes with it: it was nowhere else. A process that does
    not hold the store asks the API process to (``store_handover.ask_removal``)."""
    path = Path(path)
    if not local():
        from .. import store_handover

        store_handover.ask_removal([name_of(path)])
        return
    with _swap():
        if path.exists():
            with contextlib.suppress(OSError):
                os.chmod(path, 0o600)
            if _set_aside(path):
                return
            path.unlink()


def _set_aside(path: Path) -> bool:
    """On a server that can be brought back to an earlier moment, a deleted file is kept for as
    long as a recovery could name it again (``app/recovery/kept.py``): moved aside, not removed.
    Says whether it was; everywhere else, and for what is not worth keeping, it was not."""
    from ..recovery import kept

    return kept.keep(path)
