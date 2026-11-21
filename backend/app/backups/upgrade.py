"""Migrating the database so that one can come back: what the entrypoint runs before the server.

``python -m app.backups.upgrade`` takes the place of a bare ``alembic upgrade
head``. When the database is already at the revision of this version it does
nothing. When there are migrations to run:

1. **One at a time.** It takes a lock in the database that a second instance
   waits behind, and that a backup stops at.
2. **Checks.** The revision the database is at must be one this version
   knows (a database migrated by a later Nik is refused, untouched); the
   server must be a PostgreSQL this version runs on; the backup directory
   must have room for the snapshot.
3. **A snapshot** of the database goes into the backup directory, in the
   format of every backup, marked *before the upgrade from X to Y*. It is
   encrypted with the backup passphrase when one is set, and with a key
   derived from ``SECRET_KEY`` when none is (a new upgrade from 6.6, where
   nobody could have set one): never in clear. The store of files is not in
   it: migrations do not touch files.
4. **A rehearsal.** The snapshot is read back, restored into a scratch
   database, and the migrations are run *there*. If they fail, the database
   Nik runs on was never touched: the snapshot of this attempt is removed
   (there is nothing to come back from) and the server does not start.
   ``NIK_UPGRADE_REHEARSAL=false`` skips this step, never the snapshot.
5. **The migrations**, on the database itself.

When step 4 or 5 fails the container does not exit, which would only make it
restart and try again for ever: it says what happened in its log and answers
every request with that sentence (``serve_stopped``), so the web container
shows a page instead of a blank error, until an operator acts
(``deploy/rollback.sh``).

A database with no table (a new installation) is migrated at once: there is
nothing to snapshot.
"""

from __future__ import annotations

import json
import logging
import platform
import sys
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from ..core.config import settings
from . import database, policy, runner
from .container import BackupError, Reader

logger = logging.getLogger("nik.upgrade")

SETTINGS_ID = 22  # which version of Nik last started on this database
LOCK_WAIT = 30 * 60
MIN_POSTGRES = 14
DATABASE_WAIT_SAYS = 30  # seconds between two lines that say the database is still awaited
# The revision a release ended at, for a database whose row of the version cannot be read: one
# from before 6.7, which never wrote it, or one whose row was lost. From 6.7 on the row says it
# (``recorded_version``), and this is only what is said without it: the last release that ended
# at that revision, which is the code to come back to.
RELEASES = {"0047_playbook_files": "6.6.1", "0049_two_factor": "6.7.1", "0051_audit_chain": "6.8.0"}
PORT = 8000


class Stopped(Exception):
    """The upgrade did not happen. ``stage``: checks | rehearsal | migration | unexpected."""

    def __init__(self, stage: str, message: str, output: str = "", snapshot: str = "") -> None:
        super().__init__(message)
        self.stage, self.message, self.output, self.snapshot = stage, message, output, snapshot


@dataclass
class Outcome:
    migrated: bool = False
    before: str | None = None
    after: str | None = None
    snapshot: str = ""
    rehearsed: bool = False
    seconds: dict[str, float] = field(default_factory=dict)


# --------------------------------------------------------------------------- #
# What version ran here last                                                  #
# --------------------------------------------------------------------------- #
def _session():
    from ..core.db import SessionLocal

    return SessionLocal()


def recorded_version() -> str:
    """The version of Nik that last started on this database, or "" when it never wrote one."""
    from ..core.models import Setting

    try:
        with _session() as db:
            row = db.get(Setting, SETTINGS_ID)
            return str(((row.doc if row else None) or {}).get("version") or "")
    except Exception:  # noqa: BLE001 - a database from before the settings table, or with none yet
        return ""


def record_version(revision: str | None) -> None:
    """Write down which version of Nik runs on this database now: the next upgrade names it."""
    from sqlalchemy.orm.attributes import flag_modified

    from ..core.models import Setting

    doc = {"version": runner.nik_version(), "revision": revision or "", "since": runner.iso(time.time())}
    try:
        with _session() as db:
            row = db.get(Setting, SETTINGS_ID)
            if row is None:
                db.add(Setting(id=SETTINGS_ID, doc=doc))
            elif (row.doc or {}).get("version") != doc["version"] or (row.doc or {}).get("revision") != doc["revision"]:
                row.doc = doc
                flag_modified(row, "doc")
            db.commit()
    except Exception:  # noqa: BLE001 - a note for later, never a reason not to start
        logger.warning("The version of Nik could not be written down: the next snapshot will name the revision")


def _version_before(revision: str | None) -> str:
    return recorded_version() or RELEASES.get(revision or "", "")


# --------------------------------------------------------------------------- #
# The lock                                                                    #
# --------------------------------------------------------------------------- #
class _Lock:
    """Held from the first check to the last migration; a second instance waits here."""

    def __init__(self, url) -> None:
        self._url, self._conn = url, None

    def __enter__(self) -> _Lock:
        if not database.is_postgres(self._url):
            return self
        self._conn = database._pg(self._url, autocommit=True)
        waited = 0
        while True:
            taken = self._conn.execute("SELECT pg_try_advisory_lock(%s)", (database.MIGRATION_LOCK,)).fetchone()[0]
            if taken:
                return self
            if waited == 0:
                logger.info("Another instance holds the database (a migration or a backup): waiting for it")
            if waited >= LOCK_WAIT:
                self._conn.close()
                raise Stopped(
                    "checks",
                    f"Something has held the database for {LOCK_WAIT // 60} minutes (another instance migrating "
                    "it, or a backup): nothing was changed. Look at what else runs on this database",
                )
            time.sleep(5)
            waited += 5

    def __exit__(self, *_exc) -> None:
        if self._conn is not None:
            self._conn.close()


# --------------------------------------------------------------------------- #
# The steps                                                                   #
# --------------------------------------------------------------------------- #
def _snapshot(about: dict[str, Any], head: str, now: float | None) -> dict[str, Any]:
    folder = runner.directory()
    try:
        folder.mkdir(parents=True, exist_ok=True)
        runner.clear_partials(folder)
        runner.room(folder, about["bytes"])
    except BackupError as error:
        raise Stopped("checks", f"{error}. The database was not changed") from None
    before = _version_before(about["revision"])
    version = runner.nik_version()
    label = f"Before the upgrade from {before or about['revision'] or 'an unknown version'} to {version}"
    try:
        with _session() as db:
            key = runner.snapshot_key(db)
    except Exception:  # noqa: BLE001 - no settings to read a passphrase from: SECRET_KEY it is
        key = runner.snapshot_key(None)
    facts = {
        "fromVersion": before,
        "fromRevision": about["revision"] or "",
        "toVersion": version,
        "toRevision": head,
        # The code that goes with the snapshot: releases are tagged with their version.
        "tag": f"v{before}" if before else "",
        "database": f"{about['engine']} {about['serverVersion']}",
        "python": platform.python_version(),
    }
    clock = time.time() if now is None else now
    name = runner.new_name("upgrade", clock, folder)
    try:
        return runner.write_file(name, key, kind="upgrade", label=label, migrating=True, upgrade=facts, now=now)
    except (BackupError, OSError) as error:
        raise Stopped(
            "checks", f"The snapshot before the upgrade could not be taken: {error}. The database was not changed"
        ) from None


def _forget(name: str) -> None:
    for path in (runner.file_of(name), runner.note_of(name)):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            logger.warning("%s could not be removed", path.name)


def _prune(keep_name: str) -> None:
    """Keep the latest few snapshots. By the files: the table of the backups may not exist yet."""
    try:
        with _session() as db:
            from . import config

            keep = int(config.read(db)["retention"]["upgrades"])
    except Exception:  # noqa: BLE001 - before the settings can be read: the default
        keep = 3
    folder = runner.directory()
    found = []
    for path in folder.glob("nik-upgrade-*.json"):
        note = runner.read_note(path.stem, folder)
        if note is not None:
            found.append(policy.Taken(note["name"], runner.stamp(note.get("createdAt")), "done", kind="upgrade"))
    for name in policy.upgrade_retention(found, keep):
        if name != keep_name:
            _forget(name)
            logger.info("Removed the older snapshot %s", name)


def _rehearse(note: dict[str, Any], config: Path | None) -> list[str] | None:
    """Restore the snapshot into a scratch database and run the migrations there.

    Returns what was checked of the restored snapshot, or None when no
    scratch database can be made here (the role of Nik may not create one):
    the rehearsal is then skipped, loudly, and the snapshot remains the way
    back.
    """
    from . import config as backup_settings

    name = note["name"]
    try:
        database.sweep("rehearsal")
        scratch = database.Scratch("rehearsal", separate_role=False).create()
    except BackupError as error:
        logger.warning("The migrations are NOT rehearsed: %s", error)
        return None
    try:
        try:
            with _session() as db:
                secrets = backup_settings.secrets(db)
        except Exception:  # noqa: BLE001 - before the settings can be read: SECRET_KEY alone
            secrets = backup_settings.secrets(None)
        loader = database.Loader(scratch.url)
        try:
            with open(runner.file_of(name), "rb") as source:
                reader = Reader(source, secrets)
                for part in reader.parts():
                    loader.take(part)
            checks = loader.finish(reader.manifest)
        except BackupError as error:
            raise Stopped(
                "rehearsal",
                f"The snapshot taken before the upgrade does not restore ({error}), so the upgrade was not "
                "started. The database was not changed",
            ) from None
        finally:
            loader.close()
        try:
            database.migrate(scratch.url, "head", config)
        except database.MigrationFailed as error:
            raise Stopped(
                "rehearsal",
                f"The migrations of Nik {runner.nik_version()} fail on a copy of this database: {error}. "
                "The database itself was not touched: the data is as it was before this start",
                error.output,
            ) from None
        return [*checks, "the migrations of the new version ran on the restored copy"]
    finally:
        try:
            scratch.drop()
        except Exception:  # noqa: BLE001 - what failed inside matters more; the next start sweeps it
            logger.exception("The scratch database %s could not be dropped", scratch.name)


def wait_for_database(url, pause: float = 2.0, sleep=time.sleep) -> int:
    """Wait until the database answers, however long that takes; gives the attempts it took.

    After the host or the container engine restarts, every container starts at once and PostgreSQL
    replays its log for a while ("the database system is starting up"); the order compose keeps at
    ``up`` is not kept then. A database that does not answer yet is not a failed upgrade: nothing was
    read and nothing changed, so the server waits, and says so, instead of stopping for good."""
    attempts, said = 0, 0.0
    while True:
        attempts += 1
        try:
            database.about(url)
            if attempts > 1:
                logger.info("The database answers")
            return attempts
        except Exception as error:  # noqa: BLE001 - whatever the driver raises while the server is not there
            if not database.is_postgres(url):
                raise
            clock = time.monotonic()
            if attempts == 1 or clock - said >= DATABASE_WAIT_SAYS:
                said = clock
                reason = str(error).strip().splitlines()[-1] if str(error).strip() else type(error).__name__
                logger.info("The database does not answer yet (%s): waiting for it", reason)
            sleep(pause)


def run(config: Path | None = None, now: float | None = None) -> Outcome:
    """Bring the database to the revision of this version. Raises ``Stopped`` when it could not,
    with the database either untouched (``checks``, ``rehearsal``) or to be put back (``migration``)."""
    url = database.live_url()
    outcome = Outcome()
    wait_for_database(url)
    with _Lock(url):
        about = database.about(url)
        head = database.head_revision(config)
        outcome.before, outcome.after = about["revision"], head
        if about["revision"] == head:
            record_version(head)
            return outcome
        if about["empty"]:
            clock = time.monotonic()
            _migrate_live(url, config, snapshot="")
            outcome.migrated = True
            outcome.seconds["migration"] = round(time.monotonic() - clock, 1)
            record_version(head)
            return outcome
        if about["revision"] and not database.known_revision(about["revision"], config):
            raise Stopped(
                "checks",
                f"The database is at the revision {about['revision']}, which Nik {runner.nik_version()} does not "
                "know: a later version of Nik migrated it. Nothing was changed. Start that version again, or put "
                "back the snapshot it took before upgrading (deploy/rollback.sh)",
            )
        if about["engine"] == "postgresql" and about["major"] < MIN_POSTGRES:
            raise Stopped(
                "checks",
                f"The database server is PostgreSQL {about['serverVersion']}; Nik {runner.nik_version()} needs "
                f"{MIN_POSTGRES} or later. Nothing was changed",
            )
        clock = time.monotonic()
        note = _snapshot(about, head, now)
        outcome.snapshot = note["name"]
        outcome.seconds["snapshot"] = round(time.monotonic() - clock, 1)
        logger.info("Took the snapshot %s (%s bytes): %s", note["name"], note["size"], note["label"])
        if settings.UPGRADE_REHEARSAL:
            clock = time.monotonic()
            try:
                checks = _rehearse(note, config)
            except Stopped as stopped:
                # Nothing was changed, so there is nothing to come back from: an operator who starts
                # the container again and again must not push the older snapshots out with this one.
                _forget(note["name"])
                stopped.snapshot = ""
                raise
            outcome.seconds["rehearsal"] = round(time.monotonic() - clock, 1)
            outcome.rehearsed = checks is not None
            if outcome.rehearsed:
                # The rehearsal restored the snapshot: that is its restore test, and the note says so.
                note = {
                    **note,
                    "verify": {
                        "passed": True,
                        "checks": checks,
                        "seconds": outcome.seconds["rehearsal"],
                        "at": runner.iso(time.time() if now is None else now),
                    },
                }
                logger.info("The migrations ran on a copy of the database: now on the database itself")
        else:
            logger.warning("NIK_UPGRADE_REHEARSAL is off: the migrations run on the database without a rehearsal")
        clock = time.monotonic()
        _migrate_live(url, config, note["name"])
        outcome.migrated = True
        outcome.seconds["migration"] = round(time.monotonic() - clock, 1)
        try:
            runner.write_note({**note, "upgrade": {**note["upgrade"], "rehearsed": outcome.rehearsed, "done": True}})
            _prune(note["name"])
        except OSError:
            logger.warning("The note of the snapshot %s could not be updated", note["name"])
        record_version(head)
    return outcome


def _migrate_live(url, config: Path | None, snapshot: str) -> None:
    try:
        database.migrate(url, "head", config)
    except database.MigrationFailed as error:
        try:
            at = database.about(url)["revision"]
        except Exception:  # noqa: BLE001 - the server may be what failed
            at = "unknown"
        back = (
            f" The snapshot {snapshot} holds it as it was before: deploy/rollback.sh puts it back."
            if snapshot
            else " It was a new, empty database: nothing was lost."
        )
        raise Stopped(
            "migration",
            f"The migrations of Nik {runner.nik_version()} failed on the database: {error}. "
            f"The database is now at the revision {at or 'none'}.{back}",
            error.output,
            snapshot,
        ) from None


# --------------------------------------------------------------------------- #
# When it did not happen                                                      #
# --------------------------------------------------------------------------- #
PUBLIC = {
    "checks": "The upgrade of Nik was not started. The data is as it was.",
    "rehearsal": "The upgrade of Nik was stopped before it changed anything: its migrations fail on a copy of "
    "the database. The data is as it was.",
    "migration": "The upgrade of Nik failed while it changed the database. A snapshot taken just before holds "
    "the data as it was.",
    "unexpected": "The upgrade of Nik stopped in a way it did not expect.",
}


def stopped_body(stopped: Stopped) -> dict[str, Any]:
    """What an anonymous request is told: that the upgrade stopped, and whose job it is. The reason
    itself may quote the database, so it stays in the log of the container."""
    return {
        "detail": PUBLIC[stopped.stage] + " The administrator of the server finds the reason in the log of the "
        "api container, and the way back in the deployment guide (An upgrade went wrong).",
        "upgrade": {"stopped": True, "stage": stopped.stage, "version": runner.nik_version()},
    }


def serve_stopped(stopped: Stopped, port: int = PORT) -> ThreadingHTTPServer:
    """Answer every request with what happened, in place of the server that did not start."""
    body = json.dumps(stopped_body(stopped)).encode("utf-8")

    class Handler(BaseHTTPRequestHandler):
        def _answer(self) -> None:
            # The health check passes: the container is doing all it can, and the web container
            # must come up to show the sentence. Everything else says the service is not there.
            healthy = self.path.split("?")[0] == "/api/health"
            payload = b'{"status":"upgrade-stopped"}' if healthy else body
            self.send_response(200 if healthy else 503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(payload)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = _answer  # noqa: N815

        def log_message(self, *_args) -> None:
            return

    return ThreadingHTTPServer(("0.0.0.0", port), Handler)  # noqa: S104 - inside the container, as the server binds


def explain(stopped: Stopped) -> str:
    lines = ["", "=" * 78, "NIK DID NOT START: THE UPGRADE WAS STOPPED", "", stopped.message, ""]
    if stopped.output:
        lines += ["What the migrations printed last:", "", stopped.output, ""]
    if stopped.stage == "migration":
        lines += [
            "To come back: run deploy/rollback.sh on the host. It lists the snapshots, puts the one you choose",
            "back, and tells which version of the code goes with it.",
        ]
    elif stopped.stage == "unexpected":
        lines += [
            "Whether the database was changed is said by the lines above this box: a snapshot is named there",
            "once it was taken, and the migrations once they started. If they had started, deploy/rollback.sh",
            "puts the snapshot back; if not, check out the version that worked and start it. Report the failure.",
        ]
    else:
        lines += [
            "Nothing has to be put back. To run the version that worked: check out its tag and start the stack",
            "again (git checkout v<version> && <compose> up -d --build). Report the failure with the lines above.",
        ]
    lines += [
        "",
        "Until then this container answers every request with a sentence that says the upgrade was stopped.",
        "=" * 78,
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    # What Nik says of the upgrade, and only warnings from the libraries under it.
    logging.basicConfig(level=logging.WARNING, format="upgrade: %(message)s", stream=sys.stderr)
    for name in ("nik.upgrade", "nik.backups"):
        logging.getLogger(name).setLevel(logging.INFO)
    try:
        outcome = run()
    except Stopped as stopped:
        sys.stderr.write(explain(stopped))
        sys.stderr.flush()
        serve_stopped(stopped).serve_forever()
        return
    except Exception as error:  # noqa: BLE001 - never a restart loop: each turn of one would take a snapshot more
        logger.exception("The upgrade failed in a way Nik did not expect")
        stopped = Stopped(
            "unexpected", f"The upgrade stopped on an error it did not expect: {type(error).__name__}: {error}"
        )
        sys.stderr.write(explain(stopped))
        sys.stderr.flush()
        serve_stopped(stopped).serve_forever()
        return
    if outcome.migrated:
        logger.info(
            "The database is at the revision %s (was: %s). Seconds: %s",
            outcome.after,
            outcome.before or "empty",
            ", ".join(f"{step} {seconds}" for step, seconds in outcome.seconds.items()),
        )
    else:
        logger.info("The database is at the revision %s: nothing to migrate", outcome.after)


if __name__ == "__main__":
    main()
