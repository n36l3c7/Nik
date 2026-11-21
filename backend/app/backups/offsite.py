"""The copy off the server.

A backup that sits on the disk of the server it protects is lost with it. So
each backup that passed its restore test is copied to another machine, and
removed from there when the retention removes it here.

**Who sends it.** Not the API process: the backend has no way out of its
networks, on purpose, and this gives it none. The copy is sent by the
automation worker, the one container of the stack that already has a way
out, which reads the backup directory (mounted read-only there) and writes
what happened in the ``offsite`` columns of the row. An installation that
sets no destination runs nothing more than before; one that runs playbooks
inside the API process (``AUTOMATION_WORKER=inline``) sends from there, if
that process can reach the destination.

**Where to.** A ``Destination`` knows four things: ``test``, ``put``,
``remove`` and ``listing``. Today there is one, ``Sftp``; an object store
would be another class with the same four methods, and nothing else here
would change.

**SFTP.** The account signs in with a private key (or a password), and the
server must present the host key that was pinned in the settings: Nik never
trusts a key on first sight, and a destination with no pinned key receives
nothing. The file is written as ``<name>.nikbak.partial`` in the directory
of the destination and renamed when it is whole; an upload that was cut is
resumed from where the partial file ends, three times at most in one pass.
Then the file is read back from the destination and its size and SHA-256
are compared with the local file: only then is the copy counted. The small
``.json`` of the backup goes beside it, so that the other machine can tell
what its files are without their passphrase.

**Snapshots taken before upgrades** are copied too, with their own count
kept there as here. The upgrade does not wait for it: the snapshot is found
in the directory once the server is up, and sent like any backup; a copy
that fails is told to the administrators like any other.

The connection goes straight to the host (SFTP does not go through an HTTP
proxy): the destination must be reachable from the network of the
automation worker.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import socket
import time
import uuid
from pathlib import Path
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core import audit
from ..core.models import Backup, Setting
from . import config, runner
from .container import CHUNK, SUFFIX, BackupError

logger = logging.getLogger("nik.backups")

LEASE = "backup-offsite"
TEST_SETTINGS_ID = 23
CONNECT_TIMEOUT = 20
ATTEMPTS = 3
RETRY_AFTER = 3600
RECONCILE_EVERY = 3600
TEST_ANSWER_WITHIN = 45
BLOCK = 256 * 1024


class OffsiteError(BackupError):
    """The destination could not be reached or did not keep what it was sent."""


class Destination(Protocol):
    where: str

    def test(self) -> dict[str, Any]: ...

    def put(self, source: Path, name: str) -> dict[str, Any]: ...

    def remove(self, name: str) -> None: ...

    def listing(self) -> list[dict[str, Any]]: ...


# --------------------------------------------------------------------------- #
# SFTP                                                                        #
# --------------------------------------------------------------------------- #
def key_line(key) -> str:
    return f"{key.get_name()} {key.get_base64()}"


def fingerprint(key) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _private_key(text: str):
    import paramiko

    last: Exception | None = None
    for kind in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return kind.from_private_key(io.StringIO(text))
        except paramiko.PasswordRequiredException:
            raise OffsiteError(
                "The private key of the destination is protected by a passphrase: give one that is not "
                "(it is kept encrypted here)"
            ) from None
        except (paramiko.SSHException, ValueError, IndexError, TypeError) as error:
            last = error
    raise OffsiteError(f"The private key of the destination cannot be read ({last})")


class Sftp:
    """An SFTP account on another machine. ``connect`` is replaced in tests by one that reaches a local double."""

    def __init__(self, settings: dict[str, Any], secret: str) -> None:
        self.host, self.port = str(settings.get("host") or ""), int(settings.get("port") or 22)
        self.user, self.auth = str(settings.get("user") or ""), str(settings.get("auth") or "key")
        self.path = str(settings.get("path") or ".")
        self.pinned = str(settings.get("hostKey") or "")
        self._secret = secret
        self.where = f"sftp://{self.user}@{self.host}:{self.port}/{self.path.lstrip('/')}"
        self.presented: Any = None

    # ----- the connection ----- #
    def connect(self) -> socket.socket:
        try:
            return socket.create_connection((self.host, self.port), CONNECT_TIMEOUT)
        except OSError as error:
            raise OffsiteError(f"{self.host}:{self.port} cannot be reached: {error}") from None

    def _open(self, *, pin: bool = True):
        import paramiko

        transport = paramiko.Transport(self.connect())
        try:
            transport.start_client(timeout=CONNECT_TIMEOUT)
            self.presented = transport.get_remote_server_key()
            if pin:
                self._hold_to_pin()
            if self.auth == "key":
                transport.auth_publickey(self.user, _private_key(self._secret))
            else:
                transport.auth_password(self.user, self._secret)
            transport.set_keepalive(30)
            return transport, paramiko.SFTPClient.from_transport(transport)
        except paramiko.AuthenticationException:
            transport.close()
            raise OffsiteError(f"{self.host} refused the {self.auth} of the account {self.user}") from None
        except (paramiko.SSHException, OSError, EOFError) as error:
            transport.close()
            raise OffsiteError(f"The SSH connection to {self.host} failed: {error or type(error).__name__}") from None
        except BaseException:
            transport.close()
            raise

    def _hold_to_pin(self) -> None:
        shown = f"{key_line(self.presented)} ({fingerprint(self.presented)})"
        if not self.pinned:
            raise OffsiteError(
                f"No host key is pinned for {self.host}, so nothing is sent to it. It presents: {shown}. "
                "Compare it with the key of the server, then put it in the settings"
            )
        if self.pinned not in (key_line(self.presented), fingerprint(self.presented)):
            raise OffsiteError(
                f"{self.host} presents a host key that is not the one pinned: {shown}. Nothing was sent. "
                "Either the server was reinstalled, and its new key has to be pinned, or this is not the server"
            )

    def _file(self, name: str, suffix: str = SUFFIX) -> str:
        return f"{self.path.rstrip('/')}/{name}{suffix}"

    @staticmethod
    def _make_path(sftp, path: str) -> None:
        pieces = [piece for piece in path.split("/") if piece]
        current = "/" if path.startswith("/") else ""
        for piece in pieces:
            current = f"{current}{piece}" if current.endswith("/") or not current else f"{current}/{piece}"
            try:
                sftp.stat(current)
            except OSError:
                sftp.mkdir(current, 0o700)

    @staticmethod
    def _rename(sftp, old: str, new: str) -> None:
        try:
            sftp.posix_rename(old, new)
        except OSError:
            try:
                sftp.remove(new)
            except OSError:
                pass
            sftp.rename(old, new)

    # ----- what a destination does ----- #
    def test(self) -> dict[str, Any]:
        """Connect, sign in, write a small file in the directory, read it back and remove it."""
        try:
            transport, sftp = self._open()
        except OffsiteError as error:
            shown = {}
            if self.presented is not None:
                shown = {"hostKey": key_line(self.presented), "fingerprint": fingerprint(self.presented)}
            return {"ok": False, "message": str(error), **shown}
        shown = {"hostKey": key_line(self.presented), "fingerprint": fingerprint(self.presented)}
        try:
            self._make_path(sftp, self.path)
            probe = self._file(f"nik-test-{uuid.uuid4().hex[:12]}", ".probe")
            content = uuid.uuid4().bytes
            with sftp.open(probe, "wb") as out:
                out.write(content)
            with sftp.open(probe, "rb") as back:
                same = back.read() == content
            sftp.remove(probe)
            if not same:
                return {"ok": False, "message": f"{self.host} did not give back what was written to it", **shown}
            return {
                "ok": True,
                "message": f"Signed in to {self.host} as {self.user}; a file was written to {self.path}, read back "
                "and removed.",
                **shown,
            }
        except OSError as error:
            return {
                "ok": False,
                "message": f"Signed in to {self.host}, but {self.path} cannot be written to: {error}",
                **shown,
            }
        finally:
            transport.close()

    def put(self, source: Path, name: str) -> dict[str, Any]:
        """Send the backup ``name`` and check what arrived. Returns ``{"remote", "bytes", "sha256", "seconds"}``."""
        import paramiko

        clock = time.monotonic()
        size = source.stat().st_size
        digest = hashlib.sha256()
        with open(source, "rb") as handle:
            for piece in iter(lambda: handle.read(CHUNK), b""):
                digest.update(piece)
        wanted = digest.hexdigest()
        final, partial = self._file(name), self._file(name) + ".partial"
        last: Exception | None = None
        for attempt in range(ATTEMPTS):
            try:
                transport, sftp = self._open()
            except OffsiteError as error:
                last = error
                if "host key" in str(error) or "refused" in str(error):
                    raise  # trying again cannot help
                time.sleep(min(30, 2**attempt))
                continue
            try:
                self._make_path(sftp, self.path)
                self._send(sftp, source, partial, size)
                if self._sha256(sftp, partial, size) != wanted:
                    sftp.remove(partial)
                    raise OffsiteError(f"What {self.host} holds of {name} is not what was sent: it was removed")
                self._rename(sftp, partial, final)
                note = runner.note_of(name, source.parent)
                if note.exists():
                    with sftp.open(self._file(name, ".json"), "wb") as out:
                        out.write(note.read_bytes())
                return {"remote": final, "bytes": size, "sha256": wanted, "seconds": round(time.monotonic() - clock, 1)}
            except OffsiteError:
                raise
            except (OSError, EOFError, paramiko.SSHException) as error:
                # A connection that drops shows as any of the three, by where the code was when it went.
                last = error
                time.sleep(min(30, 2**attempt))
            finally:
                transport.close()
        raise OffsiteError(f"The copy of {name} to {self.host} failed {ATTEMPTS} times: {last}")

    @staticmethod
    def _send(sftp, source: Path, partial: str, size: int) -> None:
        try:
            done = sftp.stat(partial).st_size or 0
        except OSError:
            done = 0
        if done > size:
            sftp.remove(partial)
            done = 0
        with open(source, "rb") as handle, sftp.open(partial, "ab" if done else "wb") as out:
            out.set_pipelined(True)
            handle.seek(done)
            for piece in iter(lambda: handle.read(BLOCK), b""):
                out.write(piece)

    @staticmethod
    def _sha256(sftp, path: str, size: int) -> str:
        if (sftp.stat(path).st_size or 0) != size:
            return ""
        digest = hashlib.sha256()
        with sftp.open(path, "rb") as back:
            back.prefetch(size)
            for piece in iter(lambda: back.read(BLOCK), b""):
                digest.update(piece)
        return digest.hexdigest()

    def remove(self, name: str) -> None:
        transport, sftp = self._open()
        try:
            for path in (self._file(name), self._file(name) + ".partial", self._file(name, ".json")):
                try:
                    sftp.remove(path)
                except FileNotFoundError:
                    continue
                except OSError as error:
                    # paramiko says "no such file" with a plain IOError and errno 2.
                    if getattr(error, "errno", None) == 2:
                        continue
                    raise OffsiteError(f"{path} could not be removed from {self.host}: {error}") from None
        finally:
            transport.close()

    def listing(self) -> list[dict[str, Any]]:
        transport, sftp = self._open()
        try:
            return sorted(
                (
                    {"name": entry.filename[: -len(SUFFIX)], "bytes": entry.st_size or 0}
                    for entry in sftp.listdir_attr(self.path)
                    if entry.filename.endswith(SUFFIX)
                ),
                key=lambda entry: entry["name"],
            )
        except OSError as error:
            raise OffsiteError(f"{self.path} cannot be listed on {self.host}: {error}") from None
        finally:
            transport.close()


def open_destination(db: OrmSession) -> Destination | None:
    """The destination that is set and ready, or None."""
    settings = config.read(db).get("destination") or {}
    if settings.get("kind") != "sftp" or not settings.get("secret"):
        return None
    try:
        return Sftp(settings, config.destination_secret(db, settings))
    except config.ConfigError as error:
        raise OffsiteError(str(error)) from None


# --------------------------------------------------------------------------- #
# The test asked for from the screen                                          #
# --------------------------------------------------------------------------- #
def ask_test(db: OrmSession, now: float | None = None) -> str:
    """Leave a request for a test of the destination (the caller commits). Returns its id."""
    request = uuid.uuid4().hex
    doc = {"request": request, "at": time.time() if now is None else now}
    row = db.get(Setting, TEST_SETTINGS_ID)
    if row is None:
        db.add(Setting(id=TEST_SETTINGS_ID, doc=doc))
    else:
        row.doc = doc
        flag_modified(row, "doc")
    return request


def test_answer(db: OrmSession, request: str) -> dict[str, Any] | None:
    row = db.get(Setting, TEST_SETTINGS_ID)
    doc = (row.doc if row else None) or {}
    answer = doc.get("answer")
    return answer if doc.get("request") == request and isinstance(answer, dict) else None


def _answer_test(now: float) -> bool:
    from ..core.db import SessionLocal

    with SessionLocal() as db:
        row = db.get(Setting, TEST_SETTINGS_ID)
        doc = dict((row.doc if row else None) or {})
        if not doc.get("request") or doc.get("answer") or now - float(doc.get("at") or 0) > TEST_ANSWER_WITHIN:
            return False
        try:
            destination = open_destination(db)
        except OffsiteError as error:
            destination, answer = None, {"ok": False, "message": str(error)}
        else:
            answer = {"ok": False, "message": "No destination with its key or password is set"}
    if destination is not None:
        try:
            answer = destination.test()
        except Exception as error:  # noqa: BLE001 - the person who asked gets an answer whatever happened
            logger.exception("The test of the destination failed")
            answer = {"ok": False, "message": f"{type(error).__name__}: {error}"[:500]}
    with SessionLocal() as db:
        row = db.get(Setting, TEST_SETTINGS_ID)
        if row is not None and (row.doc or {}).get("request") == doc["request"]:
            row.doc = {**row.doc, "answer": answer}
            flag_modified(row, "doc")
            db.commit()
    return True


# --------------------------------------------------------------------------- #
# One pass                                                                    #
# --------------------------------------------------------------------------- #
def _note(db: OrmSession, name: str, state: str, **facts: Any) -> None:
    row = db.get(Backup, name)
    if row is None:
        return
    row.offsite_state = state
    row.offsite = {**(row.offsite or {}), **facts}
    flag_modified(row, "offsite")


def ship(now: float | None = None, holder: str = runner.HOLDER) -> list[str]:
    """One pass of the process that has a way out: answer a test that was asked for, remove the
    copies of the backups that were deleted, send the backups that wait. Returns what it did."""
    from ..core.db import SessionLocal

    clock = time.time() if now is None else now
    did: list[str] = []
    # A test that was asked for is answered at once, lease or not: a person waits for it, and a
    # container that was just restarted would otherwise stand behind the lease of the one it replaced.
    if _answer_test(clock):
        did.append("test")
    with SessionLocal() as db:
        if not runner.acquire(db, holder, now, LEASE):
            return did
    with SessionLocal() as db:
        try:
            destination = open_destination(db)
            trouble = ""
        except OffsiteError as error:
            destination, trouble = None, str(error)
        ready = config.ready(config.read(db).get("destination") or {})
        going = list(db.scalars(select(Backup.id).where(Backup.offsite_state == "delete")))
        waiting = [
            row.id
            for row in db.scalars(
                select(Backup)
                .where(Backup.state == "done", Backup.local.is_(True), Backup.verify_state == "passed")
                .where(Backup.offsite_state.in_(("pending", "failed")))
                .order_by(Backup.created_at)
            )
            if row.offsite_state == "pending" or clock - float((row.offsite or {}).get("triedAt") or 0) >= RETRY_AFTER
        ]
    if not ready and not going:
        return did
    with runner.Renewing(holder, LEASE):
        if ready and destination is not None:
            did += _reconcile(destination, clock)
        did += _work(destination, trouble, going, waiting if ready else [], clock)
    return did


_reconciled = 0.0


def _reconcile(destination, clock: float) -> list[str]:
    """Once an hour, hold the rows that say "copied" to what the destination lists.

    A copy that is not there any more (removed on the other machine, or a
    database put back from before it was removed) is sent again while its
    file is here, and forgotten when it is not: the list never shows a
    backup that exists nowhere.
    """
    global _reconciled
    from ..core.db import SessionLocal

    if abs(clock - _reconciled) < RECONCILE_EVERY:
        return []
    with SessionLocal() as db:
        if not db.scalars(select(Backup.id).where(Backup.offsite_state == "copied").limit(1)).first():
            return []
    try:
        there = {entry["name"] for entry in destination.listing()}
    except OffsiteError:
        return []  # the next copy says what is wrong with the destination
    _reconciled = clock
    did = []
    with SessionLocal() as db:
        for row in db.scalars(select(Backup).where(Backup.offsite_state == "copied")):
            if row.id in there:
                continue
            if row.local and row.state == "done":
                row.offsite_state = "pending"
                did.append(f"again:{row.id}")
            else:
                db.delete(row)
                did.append(f"forgotten:{row.id}")
        if did:
            audit.record(
                db,
                runner.SYSTEM,
                "backup.offsite",
                "The destination no longer holds: " + ", ".join(entry.split(":", 1)[1] for entry in did),
                target="backups",
            )
        db.commit()
    return did


def _work(destination, trouble: str, going: list[str], waiting: list[str], clock: float) -> list[str]:
    from ..core.db import SessionLocal

    did: list[str] = []
    for name in going:
        try:
            if destination is None:
                raise OffsiteError(trouble or "No destination is set any more: the copy stays where it is")
            destination.remove(name)
        except OffsiteError as error:
            logger.warning("The copy of %s was not removed: %s", name, error)
            with SessionLocal() as db:
                row = db.get(Backup, name)
                # With no destination left there is nothing to try again: the row goes, the file is the operator's.
                if row is not None and destination is None:
                    db.delete(row)
                    db.commit()
            continue
        with SessionLocal() as db:
            row = db.get(Backup, name)
            if row is not None:
                db.delete(row)
            audit.record(db, runner.SYSTEM, "backup.offsite", f"Removed the copy of {name} off the server", target=name)
            db.commit()
        did.append(f"removed:{name}")
    for name in waiting:
        try:
            if destination is None:
                raise OffsiteError(trouble or "The destination is not complete")
            sent = destination.put(runner.file_of(name), name)
        except (OffsiteError, OSError) as error:
            with SessionLocal() as db:
                tries = int(((db.get(Backup, name) or Backup()).offsite or {}).get("tries") or 0) + 1
                _note(db, name, "failed", error=str(error)[:900], triedAt=clock, tries=tries)
                audit.record(
                    db,
                    runner.SYSTEM,
                    "backup.offsite",
                    f"The copy of {name} off the server failed: {error}"[:900],
                    target=name,
                )
                db.commit()
            logger.warning("The copy of %s off the server failed: %s", name, error)
            did.append(f"failed:{name}")
            continue
        with SessionLocal() as db:
            _note(db, name, "copied", error="", at=runner.iso(clock), where=destination.where, **sent)
            audit.record(
                db,
                runner.SYSTEM,
                "backup.offsite",
                f"Copied {name} to {destination.where} ({sent['bytes']} bytes, checked after the upload)",
                target=name,
            )
            db.commit()
        did.append(f"copied:{name}")
    return did
