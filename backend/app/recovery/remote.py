"""The directory of the recovery on the second host, over the SFTP account of the backups.

One connection serves a whole pass (``Remote.session``): a segment every few
minutes and a file of the store now and then do not each pay for a new SSH
handshake. Everything goes under ``recovery/`` of the directory the backups
are copied to, so the two never meet.

A file is written as ``<name>.partial`` and renamed when it is whole; then it
is read back from the other host and its size and SHA-256 are compared with
what was sent: only then is it counted. Folders are made readable by the
other users of that host and files too, on purpose: what is written there is
sealed, and the standby that reads it runs as another user than the SFTP
account.

The host key is pinned as for the backups (``offsite.Sftp``): a destination
with no pinned key, or one that presents another, receives nothing.
"""

from __future__ import annotations

import contextlib
import hashlib
import posixpath
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, BinaryIO

from ..backups import container, offsite
from ..backups.offsite import OffsiteError
from . import layout
from .envelope import Hashing

BLOCK = offsite.BLOCK
PARTIAL = container.PARTIAL


def _missing(error: OSError) -> bool:
    return isinstance(error, FileNotFoundError) or getattr(error, "errno", None) == 2


class Session:
    """The other host, for the length of one connection."""

    def __init__(self, sftp, base: str, host: str) -> None:
        self._sftp, self.base, self.host = sftp, base, host
        self._made: set[str] = set()

    def path(self, name: str) -> str:
        return posixpath.join(self.base, name)

    def _folder(self, name: str) -> None:
        folder = posixpath.dirname(self.path(name))
        if folder in self._made:
            return
        current = "/" if folder.startswith("/") else ""
        for piece in [piece for piece in folder.split("/") if piece]:
            current = posixpath.join(current, piece) if current else piece
            if current in self._made:
                continue
            try:
                self._sftp.stat(current)
            except OSError:
                self._sftp.mkdir(current, 0o755)
                with contextlib.suppress(OSError):
                    self._sftp.chmod(current, 0o755)
            self._made.add(current)

    def size(self, name: str) -> int | None:
        try:
            return int(self._sftp.stat(self.path(name)).st_size or 0)
        except OSError as error:
            if _missing(error):
                return None
            raise OffsiteError(f"{self.path(name)} cannot be looked at on {self.host}: {error}") from None

    def _settle(self, name: str, size: int, wanted: str) -> dict[str, Any]:
        """Compare what arrived with what was sent, then give the file its name."""
        final, partial = self.path(name), self.path(name) + PARTIAL
        try:
            if offsite.Sftp._sha256(self._sftp, partial, size) != wanted:
                self._sftp.remove(partial)
                raise OffsiteError(f"What {self.host} holds of {name} is not what was sent: it was removed")
            with contextlib.suppress(OSError):
                self._sftp.chmod(partial, 0o644)
            offsite.Sftp._rename(self._sftp, partial, final)
        except (OSError, EOFError) as error:
            raise OffsiteError(f"{name} could not be written on {self.host}: {error or type(error).__name__}") from None
        return {"remote": final, "bytes": size, "sha256": wanted}

    def put_file(self, source: Path, name: str) -> dict[str, Any]:
        """Send a file of this host; an upload that was cut is resumed from where the partial file ends."""
        size = source.stat().st_size
        digest = hashlib.sha256()
        with open(source, "rb") as handle:
            for piece in iter(lambda: handle.read(BLOCK), b""):
                digest.update(piece)
        try:
            self._folder(name)
            offsite.Sftp._send(self._sftp, source, self.path(name) + PARTIAL, size)
        except (OSError, EOFError) as error:
            raise OffsiteError(f"{name} could not be sent to {self.host}: {error or type(error).__name__}") from None
        return self._settle(name, size, digest.hexdigest())

    def put_stream(self, name: str, write: Callable[[BinaryIO], None]) -> dict[str, Any]:
        """Send what ``write`` writes, as it writes it: nothing is kept on this host meanwhile.
        (A base backup is sealed straight onto the other host.) Not resumed: sent again whole."""
        try:
            self._folder(name)
            with self._sftp.open(self.path(name) + PARTIAL, "wb") as out:
                out.set_pipelined(True)
                counted = Hashing(out)
                write(counted)  # type: ignore[arg-type] - written to, nothing more
        except (OSError, EOFError) as error:
            raise OffsiteError(f"{name} could not be sent to {self.host}: {error or type(error).__name__}") from None
        return self._settle(name, counted.size, counted.digest.hexdigest())

    def put_bytes(self, name: str, data: bytes) -> None:
        """A small file that says something (the heartbeat): written beside its place, then moved."""
        try:
            self._folder(name)
            with self._sftp.open(self.path(name) + PARTIAL, "wb") as out:
                out.write(data)
            with contextlib.suppress(OSError):
                self._sftp.chmod(self.path(name) + PARTIAL, 0o644)
            offsite.Sftp._rename(self._sftp, self.path(name) + PARTIAL, self.path(name))
        except (OSError, EOFError) as error:
            raise OffsiteError(f"{name} could not be written on {self.host}: {error or type(error).__name__}") from None

    def read_bytes(self, name: str, limit: int = 1024 * 1024) -> bytes | None:
        """A small file of the other host, or None when it is not there."""
        try:
            with self._sftp.open(self.path(name), "rb") as back:
                return back.read(limit)
        except OSError as error:
            if _missing(error):
                return None
            raise OffsiteError(f"{name} cannot be read on {self.host}: {error}") from None

    def remove(self, name: str) -> bool:
        removed = False
        for path in (self.path(name), self.path(name) + PARTIAL):
            try:
                self._sftp.remove(path)
                removed = True
            except OSError as error:
                if not _missing(error):
                    raise OffsiteError(f"{path} could not be removed from {self.host}: {error}") from None
        return removed

    def listing(self, folder: str) -> list[tuple[str, int]]:
        """The files of a folder of the other host, as ``(name, size)``; empty when it is not there."""
        try:
            return sorted(
                (entry.filename, int(entry.st_size or 0)) for entry in self._sftp.listdir_attr(self.path(folder))
            )
        except OSError as error:
            if _missing(error):
                return []
            raise OffsiteError(f"{self.path(folder)} cannot be listed on {self.host}: {error}") from None


class Remote:
    """The directory of the recovery on the destination of the backups."""

    def __init__(self, sftp: offsite.Sftp) -> None:
        self._account = sftp
        self.where = f"{sftp.where.rstrip('/')}/{layout.REMOTE}"
        self.base = posixpath.join(sftp.path.rstrip("/") or "/", layout.REMOTE)

    @contextlib.contextmanager
    def session(self) -> Iterator[Session]:
        transport, sftp = self._account._open()
        try:
            yield Session(sftp, self.base, self._account.host)
        except EOFError as error:
            raise OffsiteError(f"The connection to {self._account.host} was cut: {error or 'it closed'}") from None
        except Exception as error:
            # What the SSH library raises when the connection goes while a file is half-way: the
            # same thing to whoever sends, and tried again at the next pass.
            if type(error).__module__.startswith("paramiko"):
                raise OffsiteError(
                    f"The connection to {self._account.host} failed: {error or type(error).__name__}"
                ) from None
            raise
        finally:
            transport.close()


def open_remote(db) -> Remote | None:
    """The directory of the recovery on the destination that is set and ready, or None."""
    destination = offsite.open_destination(db)
    return Remote(destination) if isinstance(destination, offsite.Sftp) else None
