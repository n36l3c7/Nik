"""Putting a backup back, from the command line: what ``deploy/restore.sh`` and ``deploy/rollback.sh`` run.

Restoring is never a button on a running server. It is done with the stack
stopped (the database container alone is up), by an operator who has the
file and its passphrase:

    python -m app.backups.restore inspect FILE     read the whole file, say what it holds
    python -m app.backups.restore restore FILE     put it back
    python -m app.backups.restore list [DIRECTORY] the backups of a directory, from their notes
    python -m app.backups.restore secret-key FILE  print the SECRET_KEY a backup holds, if it holds one

``restore`` goes through the file twice. The first time it changes nothing:
every chunk is decrypted and every checksum compared, and what the file says
of itself is checked against this server (the version of Nik, the engine of
the database, whether the database and the store are empty). Only when all
of that holds does the second pass write. The database arrives in one
transaction, so a restore that fails half-way leaves it as it was.

**Versions.** A backup made by this version or an earlier one is restored as
it was; when it is older, the server migrates it at its next start, with a
snapshot and a rehearsal first, like any upgrade. A backup made by a later
version is refused: this code does not know what it holds.

The passphrase is read from ``NIK_BACKUP_PASSPHRASE`` or from the file named
by ``NIK_BACKUP_PASSPHRASE_FILE`` (``deploy/restore.sh`` asks for it and
passes it that way: never on a command line, which other users of the host
can read).
"""

from __future__ import annotations

import argparse
import os
import shutil
import sys
import time
from pathlib import Path
from typing import Any

from ..core.config import settings
from . import database, runner, store
from .container import PASSPHRASE, SUFFIX, BackupError, Reader, Secrets, peek, walk


def _say(text: str = "") -> None:
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def _secrets(header: dict[str, Any]) -> Secrets:
    phrase = os.environ.get("NIK_BACKUP_PASSPHRASE", "")
    path = os.environ.get("NIK_BACKUP_PASSPHRASE_FILE", "")
    if not phrase and path:
        try:
            phrase = Path(path).read_text(encoding="utf-8").strip("\r\n")
        except OSError as error:
            raise BackupError(f"The passphrase file {path} cannot be read: {error}") from None
    if header["key"].get("from") == PASSPHRASE and not phrase:
        raise BackupError(
            "This backup is encrypted with the backup passphrase: give it in NIK_BACKUP_PASSPHRASE or in the file "
            "named by NIK_BACKUP_PASSPHRASE_FILE. Without it the backup cannot be read by anyone"
        )
    return Secrets(
        passphrases=(phrase,) if phrase else (),
        secret_keys=(settings.SECRET_KEY, *settings.SECRET_KEY_PREVIOUS),
    )


def _size(count: int | None) -> str:
    count = int(count or 0)
    for unit in ("bytes", "KB", "MB", "GB"):
        if count < 1024 or unit == "GB":
            return f"{count} {unit}" if unit == "bytes" else f"{count:.1f} {unit}"
        count /= 1024
    return ""


def describe(manifest: dict[str, Any]) -> list[str]:
    base = manifest.get("database") or {}
    held = manifest.get("store")
    lines = [
        f"  name       {manifest.get('name')}" + (f"  ({manifest.get('label')})" if manifest.get("label") else ""),
        f"  taken      {manifest.get('createdAt')} by Nik {manifest.get('nik')}",
        f"  database   {base.get('engine')} {base.get('serverVersion')}, revision {base.get('revision') or 'none'}, "
        f"{sum((base.get('rows') or {}).values())} rows in {len(base.get('rows') or {})} tables",
        f"  store      {held['files']} files, {_size(held['bytes'])}"
        if held
        else "  store      not in this backup (a snapshot taken before an upgrade holds the database alone)",
        "  SECRET_KEY " + ("included" if manifest.get("includesSecretKey") else "not included: it is in your .env"),
    ]
    return lines


def check_version(manifest: dict[str, Any]) -> str:
    """Refuse a backup this version cannot hold; otherwise the sentence that says what happens next."""
    ours, theirs = runner.nik_version(), str(manifest.get("nik") or "")
    revision = (manifest.get("database") or {}).get("revision")
    if revision and not database.known_revision(revision):
        raise BackupError(
            f"The backup was made by Nik {theirs or 'of a later version'} (revision {revision} of the database), "
            f"and this is Nik {ours}, which does not know that revision. Nothing was changed. Check out the "
            f"version that made it (git checkout v{theirs}), or a later one, and run the restore again"
        )
    if theirs and runner.version_tuple(theirs) > runner.version_tuple(ours):
        raise BackupError(
            f"The backup was made by Nik {theirs} and this is Nik {ours}: a backup is not restored into an "
            f"earlier version. Nothing was changed. Check out v{theirs}, or a later version, and run the restore again"
        )
    if revision != database.head_revision():
        return (
            f"The backup is from Nik {theirs or 'of an earlier version'}: the server migrates it to {ours} at its "
            "next start, after a snapshot and a rehearsal, as at any upgrade."
        )
    return f"The backup is from this version of Nik ({ours}): nothing to migrate."


def _empty_store(root: Path) -> None:
    for entry in root.iterdir():
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        else:
            entry.unlink()


def inspect(path: Path) -> dict[str, Any]:
    with open(path, "rb") as source:
        manifest = walk(source, _secrets(peek(path)))
    return manifest


def restore(path: Path, *, replace: bool = False, database_only: bool = False) -> int:
    url = database.live_url()
    header = peek(path)
    secrets = _secrets(header)
    _say(f"Reading {path.name} ({_size(path.stat().st_size)}): nothing is changed yet.")
    clock = time.monotonic()
    with open(path, "rb") as source:
        manifest = walk(source, secrets)
    _say(
        f"The file is whole: {len(manifest['parts'])} parts, every checksum as written "
        f"({time.monotonic() - clock:.0f} s)."
    )
    for line in describe(manifest):
        _say(line)
    next_start = check_version(manifest)
    wanted = "postgresql" if database.is_postgres(url) else "sqlite"
    if (manifest.get("database") or {}).get("engine") != wanted:
        raise BackupError(
            f"The backup holds a {(manifest.get('database') or {}).get('engine')} database and this server runs on "
            f"{wanted}. Nothing was changed"
        )
    with_store = manifest.get("store") is not None and not database_only
    if (manifest.get("upgrade") or {}).get("touchesStore") and manifest.get("store") is None:
        # No migration touches the files today. One that ever does must say so (CONTRIBUTING.md),
        # and the snapshot taken before it must then hold what it touches.
        raise BackupError(
            "The upgrade this snapshot was taken before changed files of the store, and the snapshot does not "
            "hold them: the database alone cannot be put back. Nothing was changed. Restore the last full backup"
        )
    root = Path(settings.SAMPLE_STORE)
    if not replace:
        if not database.about(url)["empty"]:
            raise BackupError(
                "The database is not empty. Nothing was changed. A restore replaces everything it holds: "
                "run it again with --replace if that is what you want"
            )
        if with_store and not store.is_empty(root):
            raise BackupError(
                f"The store of files ({root}) is not empty. Nothing was changed. A restore replaces everything it "
                "holds: run it again with --replace if that is what you want"
            )
    _say()
    _say("Restoring the database" + (" and the store of files." if with_store else "."))
    clock = time.monotonic()
    if with_store:
        root.mkdir(parents=True, exist_ok=True)
        if replace:
            _empty_store(root)
    loader = database.Loader(url, replace=replace)
    unpacker = store.Unpacker(root) if with_store else None
    try:
        with open(path, "rb") as source:
            reader = Reader(source, secrets)
            for part in reader.parts():
                if not loader.take(part) and unpacker is not None:
                    unpacker.take(part)
        if unpacker is not None:
            # The files first: the database is only committed once everything else is in place.
            checks = unpacker.finish(reader.manifest)
            checks = loader.finish(reader.manifest) + checks
        else:
            checks = loader.finish(reader.manifest)
    finally:
        loader.close()
    ended = database.after_restore(url)
    _say(f"Done in {time.monotonic() - clock:.0f} s. Checked:")
    for check in checks:
        _say(f"  - {check}")
    _say()
    _say(next_start)
    if manifest.get("includesSecretKey"):
        _say(
            "The backup holds the SECRET_KEY it was made under. If the SECRET_KEY of this server is another, the "
            "stored secrets (keys of instances, credentials) cannot be read: deploy/restore.sh --secret-key puts "
            "the one of the backup into .env."
        )
    else:
        _say(
            "The stored secrets (keys of instances, credentials) are readable only with the SECRET_KEY the backup "
            "was made under: it must be the one in .env. If it is lost, they have to be entered again."
        )
    _say(
        f"Nobody is signed in on the restored server: the {ended.get('sessions', 0)} session(s) that were open when "
        "the backup was taken are ended. Accounts, second factors, recovery codes and the sign-in policy are as "
        "they were."
    )
    _say("Now start the stack, sign in, and look at: the list of incidents, a file of the store (open a sample),")
    _say("Settings → Backup (the backups this server knows), Settings → System → Workers.")
    return 0


def listing(folder: Path) -> list[dict[str, Any]]:
    found = []
    if folder.is_dir():
        for path in sorted(folder.glob(f"*{SUFFIX}"), reverse=True):
            name = path.name[: -len(SUFFIX)]
            if not runner.NAME.match(name):
                continue
            note = runner.read_note(name, folder) or {}
            try:
                header = peek(path)
            except (BackupError, OSError):
                continue
            found.append(
                {
                    "name": name,
                    "kind": note.get("kind") or header.get("kind") or "",
                    "createdAt": note.get("createdAt") or header.get("createdAt") or "",
                    "size": path.stat().st_size,
                    "nik": note.get("nik") or header.get("nik") or "",
                    "label": note.get("label") or "",
                    "tag": (note.get("upgrade") or {}).get("tag") or "",
                    "fromVersion": (note.get("upgrade") or {}).get("fromVersion") or "",
                    "fromRevision": (note.get("upgrade") or {}).get("fromRevision") or "",
                    "verified": bool((note.get("verify") or {}).get("passed")),
                    "keyFrom": header["key"].get("from") or "",
                }
            )
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.backups.restore", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("inspect", "restore", "secret-key"):
        command = commands.add_parser(name)
        command.add_argument("file")
        if name == "restore":
            command.add_argument(
                "--replace", action="store_true", help="replace a database and a store that are not empty"
            )
            command.add_argument("--database-only", action="store_true", help="leave the store of files as it is")
    command = commands.add_parser("list")
    command.add_argument("directory", nargs="?", default=settings.BACKUP_DIR)
    command.add_argument("--kind", default="", help="full or upgrade")
    args = parser.parse_args(argv)
    try:
        if args.command == "list":
            for entry in listing(Path(args.directory)):
                if args.kind and entry["kind"] != args.kind:
                    continue
                # Tabs: read by the shell scripts.
                print(
                    "\t".join(
                        str(entry[key] or "-")
                        for key in (
                            "name",
                            "kind",
                            "createdAt",
                            "size",
                            "nik",
                            "tag",
                            "fromRevision",
                            "keyFrom",
                            "label",
                        )
                    )
                )
            return 0
        path = Path(args.file)
        if not path.is_file():
            # A name alone is a backup of the backup directory.
            inside = Path(settings.BACKUP_DIR) / (args.file if args.file.endswith(SUFFIX) else args.file + SUFFIX)
            if not inside.is_file():
                raise BackupError(f"There is no backup at {args.file}")
            path = inside
        if args.command == "inspect":
            manifest = inspect(path)
            _say(f"{path.name} is whole: {len(manifest['parts'])} parts, every checksum as written.")
            for line in describe(manifest):
                _say(line)
            _say(check_version(manifest))
            return 0
        if args.command == "secret-key":
            found: list[str] = []

            def each(part) -> None:
                if part.name == "secret-key":
                    found.append(part.read().decode("utf-8"))

            with open(path, "rb") as source:
                walk(source, _secrets(peek(path)), each)
            if not found:
                raise BackupError("This backup does not hold a SECRET_KEY: it was not asked to")
            # With its name in front: the shell script that reads it tells it from anything else printed.
            print(f"SECRET_KEY={found[0]}")
            return 0
        return restore(path, replace=args.replace, database_only=args.database_only)
    except BackupError as error:
        _say(f"restore: {error}")
        return 1
    except OSError as error:
        _say(f"restore: {error}")
        return 1
    except Exception as error:  # noqa: BLE001 - the database said no: its words, not a traceback
        _say(f"restore: {type(error).__name__}: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
