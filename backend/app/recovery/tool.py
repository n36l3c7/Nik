"""The command line of the recovery, run in a container of the stack by the scripts of ``deploy/``.

``deploy/restore.sh --to`` and ``deploy/standby.sh`` do what only the host can
do (stop and start containers, put a base backup in the place of the data
directory with ``deploy/db/pitr.sh``); everything that reads the archive, an
envelope or the database is here::

    plan --to <moment|latest> [--from DIR]   which base backup, whether the log reaches the moment
    fetch --label L --from DIR               open a base backup and its log that came from another host
    after --to <moment|latest> --label L     once the database is back: note it, check it, the store
                                             (--replaced: on another host, in the place of the old server)
    status [--json]                          the role of this server and where things stand
    drain [--promoting]                      a standby takes in everything that arrived (before a promotion)
    promoted --name N                        a standby that was promoted becomes the server
    promoting                                whether a promotion was started here and not finished
    pack-secrets / unpack-secrets            the keys a second host needs, sealed under a passphrase

What a person reads goes to the error output; the lines a script reads go to
the standard output as ``key=value``.
"""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..backups.container import PASSPHRASE, SUFFIX, BackupError, Key, Reader, Secrets, Writer, peek
from ..core.clock import now_iso
from ..core.config import settings
from . import archive, envelope, layout

CARRIED = (
    "DB_PASSWORD",
    "SECRET_KEY",
    "SECRET_KEY_PREVIOUS",
    "STORE_KEY",
    "STORE_KEY_PREVIOUS",
    "AUDIT_KEY",
    "AUDIT_KEY_PREVIOUS",
)
TRANSFER_MIN = 12


def _say(text: str = "") -> None:
    sys.stderr.write(text + "\n")
    sys.stderr.flush()


def _text(at: float) -> str:
    return datetime.fromtimestamp(float(at), timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def parse_moment(text: str) -> float | None:
    """A moment as an operator writes it; None for ``latest``. Without an offset it is read as UTC."""
    text = text.strip()
    if text.lower() == "latest":
        return None
    try:
        moment = datetime.fromisoformat(text.replace(" UTC", "+00:00").replace("Z", "+00:00"))
    except ValueError:
        raise BackupError(
            f"{text!r} is not a moment: write it like 2026-11-21 14:03:00+00 (without an offset it is read as UTC), "
            "or latest"
        ) from None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.timestamp()


def _passphrase() -> Secrets:
    phrase = os.environ.get("NIK_BACKUP_PASSPHRASE", "")
    path = os.environ.get("NIK_BACKUP_PASSPHRASE_FILE", "")
    if not phrase and path:
        phrase = Path(path).read_text(encoding="utf-8").strip("\r\n")
    return Secrets(passphrases=(phrase,) if phrase else (), secret_keys=())


# --------------------------------------------------------------------------- #
# What there is to recover from                                               #
# --------------------------------------------------------------------------- #
def local_source() -> dict[str, Any]:
    """The archive of this server: its base backups and the segments it holds."""
    bases = []
    folder = layout.folder("base")
    for path in sorted(folder.iterdir()) if folder.is_dir() else []:
        if not (path.is_dir() and layout.LABEL.match(path.name)):
            continue
        try:
            facts = archive.read_manifest(path.name)
            finished = (path / "backup_manifest").stat().st_mtime
        except (OSError, ValueError, KeyError):
            continue
        bases.append({"label": path.name, "finished": finished, "place": "base", **facts})
    segments = {name: path.stat().st_mtime for name, path in layout.local_segments().items()}
    newest = max((layout.parse(name)[0] for name in segments), default=1)
    return {"bases": bases, "segments": segments, "history": layout.read_history(newest), "sealed": False}


def sealed_source(folder: Path) -> dict[str, Any]:
    """The copies of another host: ``base/*.nikbak`` and ``wal/*.nikwal`` under ``folder`` (the
    directory the copies are sent to, or its ``recovery`` folder)."""
    if (folder / layout.REMOTE).is_dir():
        folder = folder / layout.REMOTE
    bases = []
    for path in sorted((folder / "base").glob(f"*{SUFFIX}")) if (folder / "base").is_dir() else []:
        try:
            header = peek(path)
        except (BackupError, OSError):
            continue
        if header.get("kind") != "base" or not layout.LABEL.match(str(header.get("name") or "")):
            continue
        bases.append(
            {
                "label": header["name"],
                "finished": float(header.get("finishedAt") or archive.label_time(header["name"])),
                "place": "restore",
                "file": path,
                "timeline": int(header.get("timeline") or 1),
                "endTimeline": int(header.get("endTimeline") or header.get("timeline") or 1),
                "endLsn": int(header.get("endLsn") or 0),
                "startWal": str(header.get("startWal") or ""),
                "endWal": str(header.get("endWal") or ""),
            }
        )
    segments = {}
    for path in (folder / "wal").iterdir() if (folder / "wal").is_dir() else []:
        stem = path.name[: -len(layout.WAL_SUFFIX)] if path.name.endswith(layout.WAL_SUFFIX) else ""
        if layout.is_segment(stem):
            segments[stem] = path.stat().st_mtime
    return {"bases": bases, "segments": segments, "history": None, "sealed": True, "folder": folder}


def choose(source: dict[str, Any], moment: float | None) -> dict[str, Any]:
    """The base backup a recovery to ``moment`` starts from, and whether the log reaches it.
    Raises ``BackupError`` with a sentence when it cannot be done."""
    segments: dict[str, float] = source["segments"]
    newest_timeline = max((layout.parse(name)[0] for name in segments), default=0)
    bases = sorted(source["bases"], key=lambda base: base["finished"])
    usable = [
        base
        for base in bases
        if not newest_timeline
        or layout.on_history(
            base["endTimeline"], base["endLsn"], max(newest_timeline, base["endTimeline"]), source["history"]
        )
    ]
    if not usable:
        raise BackupError("The archive holds no base backup: there is nothing to recover from")
    if moment is None:
        base = usable[-1]
    else:
        before = [entry for entry in usable if entry["finished"] <= moment]
        if not before:
            raise BackupError(
                f"The oldest moment the archive can go back to is {_text(usable[0]['finished'])}: "
                f"the first base backup was finished then, and {_text(moment)} is before it"
            )
        base = before[-1]
    # The log from the end of the base backup on (what was written while it was taken is inside it).
    after = sorted(name for name in segments if name > base["endWal"])
    missing = layout.gap(after)
    if after and after[0][:8] == base["endWal"][:8] and after[0] != layout.next_name(base["endWal"]):
        missing = layout.next_name(base["endWal"])
    newest = max((segments[name] for name in after), default=base["finished"])
    if missing is not None:
        through = max((segments[name] for name in after if name < missing), default=base["finished"])
        if moment is None or moment > through:
            raise BackupError(
                f"The segment {missing} of the log is missing from the archive: it can be replayed up to "
                f"{_text(through)} and no further. Ask for a moment before that"
            )
    if moment is not None and moment > newest:
        raise BackupError(
            f"The archive ends at {_text(newest)}: {_text(moment)} is after it. Use --to latest to replay all it holds"
        )
    return {"base": base, "segments": len(after), "newest": newest, "moment": moment}


def plan(args) -> int:
    moment = parse_moment(args.to)
    source = sealed_source(Path(args.source)) if args.source else local_source()
    found = choose(source, moment)
    base = found["base"]
    _say(f"Base backup: {base['label']}, finished {_text(base['finished'])}.")
    _say(f"Log: {found['segments']} segment(s) after it, the last closed {_text(found['newest'])}.")
    if moment is None:
        _say(
            "Everything the archive holds is replayed: the database comes back as it was at about "
            f"{_text(found['newest'])}."
        )
        _say("What was written after that moment is not in the archive: it is lost.")
    else:
        _say(f"The log is replayed to {_text(moment)}: what was written after that moment is left out.")
    print(f"label={base['label']}")
    print(f"place={base['place']}")
    print(f"target={archive.stamp_text(moment) if moment is not None else ''}")
    print(f"moment={moment if moment is not None else found['newest']}")
    print(f"newest={found['newest']}")
    print(f"sealed={int(source['sealed'])}")
    return 0


def fetch(args) -> int:
    """Open a base backup and the log after it that came from another host into the archive volume."""
    source = sealed_source(Path(args.source))
    base = next((entry for entry in source["bases"] if entry["label"] == args.label), None)
    if base is None:
        raise BackupError(f"{args.source} holds no base backup named {args.label}")
    opens = envelope.Opener(_passphrase())
    target = layout.folder("restore") / base["label"]
    target.mkdir(parents=True, exist_ok=True)
    target.chmod(0o755)
    with open(base["file"], "rb") as handle:
        envelope.unseal(handle, opens, target, expect="base")
    _say(f"Opened the base backup {base['label']} (every part compared with its checksum).")
    incoming = layout.folder("incoming")
    count = 0
    for path in sorted((source["folder"] / "wal").iterdir()) if (source["folder"] / "wal").is_dir() else []:
        stem = path.name[: -len(layout.WAL_SUFFIX)] if path.name.endswith(layout.WAL_SUFFIX) else ""
        wanted = layout.HISTORY.match(stem) or (layout.is_segment(stem) and stem >= base["startWal"])
        if not wanted or (incoming / (stem + layout.GZ)).exists():
            continue
        with open(path, "rb") as handle:
            envelope.unseal(handle, opens, incoming, expect="wal")
        count += 1
    _say(f"Opened {count} file(s) of the log.")
    # The files of the store that were copied with them: taken as they are (sealed under the store
    # key of the server that sent them, which this host must hold), and left where they were.
    from . import standby

    taken = left = 0
    while True:
        did = standby.take_store(source["folder"], limit=5000, remove=False)
        taken += did["taken"]
        left = did["left"]
        if not did["taken"] or not left:
            break
    if taken or left:
        _say(f"Took {taken} file(s) of the store." + (f" {left} could not be taken." if left else ""))
    print(f"opened={count}")
    print(f"store={taken}")
    return 0


# --------------------------------------------------------------------------- #
# Once the database is back                                                   #
# --------------------------------------------------------------------------- #
def _note_recovery(db, label: str, moment: float | None, newest: float, paused: bool = False) -> None:
    """The entry a recovery leaves in the audit log: written with plain SQL, linked by the server
    after the entries that came back (``auditlog/restored.py`` says why it is written this way)."""
    import sqlalchemy as sa

    from ..auditlog.restored import ACTOR
    from ..auditlog.verifier import RESTORE

    log = sa.table("audit_log", *(sa.column(name) for name in ("id", "at", "actor", "action", "target", "details")))
    to = f"to {_text(moment)}" if moment is not None else f"to the end of its archive (about {_text(newest)})"
    db.execute(
        sa.insert(log).values(
            id=str(uuid.uuid4()),
            at=now_iso(),
            actor=ACTOR,
            action=RESTORE,
            target=label,
            details=(
                f"The database was brought back {to} from the base backup {label} and the archive of its log: "
                "the audit log goes on from the head it had at that moment. What was written between that moment "
                "and this recovery is not in this log"
                + (
                    ". The general switch of the automation was turned off by the recovery: this server no longer "
                    "knows what its playbooks did in other systems after that moment"
                    if paused
                    else ""
                )
            ),
        )
    )


def _after_work(moment: float | None, paused: bool) -> list[str]:
    """What the operator is told of the work that was in progress at the moment the database came
    back to, and of what the server does about the other systems."""
    lines = ["The work that was in progress at that moment:"]
    lines += [
        "  analyses, scans, captures and mailboxes that were running start again by themselves;",
        "  a step of a playbook that was running is done again, or, when it was calling another system in a way",
        "  that may not be repeated, waits as interrupted for a person to say what happened (Automations, Runs);",
        "  a schedule whose time passed since runs once, however many times it was missed; a fetch goes on from",
        "  where it was then, so what was fetched since comes in again.",
    ]
    if moment is None:
        return lines
    lines += [
        "This server no longer knows what it did in the other systems after that moment: a call a playbook made",
        "since (a host isolated, a ticket opened, a mail sent) is not in its database, and a playbook started",
        "again by the same alert makes it again.",
    ]
    if paused:
        lines += [
            "So the general switch of the automation was turned OFF: no playbook runs, no schedule fires and nothing",
            "is fetched until an administrator turns it on (Automations, the switch at the top). Look first at",
            "what the other systems hold since that moment.",
        ]
    else:
        lines += ["The general switch of the automation was off at that moment and stays off."]
    return lines


def after(args) -> int:
    from sqlalchemy import delete, select

    from .. import work
    from ..auditlog import chain
    from ..automation import state as automation_state
    from ..backups import database
    from ..core.db import SessionLocal
    from ..core.models import AuditEntry, Lease, Setting
    from . import config, files, role

    problem = None
    moment = parse_moment(args.to)
    newest = float(args.newest or 0) or time.time()
    reached = moment if moment is not None else newest
    about = database.about()
    head = database.head_revision()
    _say("")
    _say(
        f"The database is back: revision {about['revision']}"
        + (
            "."
            if about["revision"] == head
            else f" (this version of Nik expects {head}: it migrates it when it starts)."
        )
    )
    with SessionLocal() as db:
        if role.in_recovery(db):
            raise BackupError("The database is still replaying its log: it is not open yet")
        last = db.execute(
            select(AuditEntry.seq, AuditEntry.at)
            .where(AuditEntry.seq.is_not(None))
            .order_by(AuditEntry.seq.desc())
            .limit(1)
        ).first()
        # Whoever held a lease is gone: the loops of the server that starts take them at once. So
        # is whoever held a piece of work: the sweeper takes each back at its first pass (work.py).
        # The steps of playbooks that were running are taken back by the worker that starts, which
        # is not the one that claimed them (automation/worker.py).
        db.execute(delete(Lease))
        if about["revision"] == head:
            work.orphan_all(db)
        # Brought back to a moment somebody named, the database is older than what the other
        # systems hold: what Nik did there after that moment, it no longer knows. Nothing acts on
        # that by itself. The general switch of the automation goes off, and an administrator
        # turns it on again after a look (``_after_work`` says what happens then). Brought back
        # to the end of its archive, the server lost seconds: it goes on.
        switch = db.get(Setting, automation_state.SETTINGS_ID)
        was_on = bool(((switch.doc if switch else None) or {}).get("enabled", True))
        paused = moment is not None and was_on
        if paused:
            automation_state.write(db, enabled=False)
        _note_recovery(db, args.label, moment, newest, paused)
        if args.replaced:
            # Recovered from the copies of another host: this server takes the place of that one. A
            # generation later, and the file that tells the old server so if it ever comes back.
            marker = role.promote(db, role.name(db), hold=False)
            print(f"marker={json.dumps(marker, sort_keys=True)}")
        db.commit()
    if about["revision"] == head:
        chain.link_strays()
        with SessionLocal() as db:
            found = chain.verify(db, full=True)
            db.commit()
            problem = found.get("problem")
            if problem:
                _say(f"THE AUDIT LOG DOES NOT VERIFY: {problem.get('text')}")
            elif last is not None:
                _say(
                    "The audit log verifies from its first entry to the last one of that moment: "
                    f"entry {last[0]}, made {last[1]}."
                )
            else:
                _say("The audit log is empty at that moment.")
    with SessionLocal() as db:
        outcome = files.reconcile(db, reached)
        # Files that had been deleted before that moment and came with the copies: kept as
        # deletions are, not left in the store as files nothing names.
        files.set_aside_gone(db)
        # The copies and the proof are of another time: the loops look again.
        state = config.held(db, config.ARCHIVE_SETTINGS_ID)
        for key in ("test", "tested", "archiver", "prune", "oldest", "noRoom", "disk") + (
            ("proven",) if args.replaced else ()
        ):
            state.pop(key, None)
        config.keep(db, config.ARCHIVE_SETTINGS_ID, state)
        db.commit()
    _say(f"The store: {outcome['named']} files and folders the database names.")
    if outcome["putBack"]:
        _say(f"  {len(outcome['putBack'])} had been deleted since and were put back from where deletions are kept.")
    if outcome["missing"]:
        _say(f"  {len(outcome['missing'])} ARE MISSING: the database names them and the store does not hold them:")
        for name in outcome["missing"][:200]:
            _say(f"    {name}")
        if len(outcome["missing"]) > 200:
            _say(f"    … and {len(outcome['missing']) - 200} more")
    else:
        _say("  None is missing.")
    _say("")
    _say("What was lost:")
    if moment is not None:
        _say(f"  everything written after {_text(moment)}. That is what going back to that moment means.")
    else:
        _say(f"  everything written after about {_text(newest)}, the end of the archive: the last segment the")
        _say(
            f"  database was writing when it stopped (at most {settings.ARCHIVE_TIMEOUT} seconds of work) never "
            "reached it."
        )
    _say("A new base backup is taken as soon as the server is up: the database writes a new timeline from here.")
    _say("")
    for line in _after_work(moment, paused):
        _say(line)
    print(f"missing={len(outcome['missing'])}")
    print("audit=" + ("later" if about["revision"] != head else "bad" if problem else "ok"))
    return 0


# --------------------------------------------------------------------------- #
# The pair                                                                    #
# --------------------------------------------------------------------------- #
def describe(found: dict[str, Any]) -> list[str]:
    """``status.overview`` as lines a person reads on a terminal."""
    from ..health.checks import lasted, size

    lines = [f"Server: {found.get('name')}"]
    if not found.get("available"):
        return [*lines, "This server has no archive of its log: nothing of the recovery runs here."]
    pair = found.get("pair") or {}
    names = {
        "primary": "the server (it serves)",
        "standby": "standby (it follows the first host and serves nothing)",
        "superseded": "replaced (it serves nothing)",
    }
    lines.append(f"Role: {names[found['role']]}, generation {pair.get('generation', 1)}")
    if pair.get("promotedAt"):
        whose = "The server it follows was promoted" if found["role"] == "standby" else "Promoted"
        lines.append(f"{whose} from standby: {pair['promotedAt'][:19].replace('T', ' ')} UTC")
    if found["role"] == "superseded" and pair.get("superseded"):
        lines.append(
            f"Replaced on {_text(pair['superseded'].get('at') or 0)} by {pair['superseded'].get('by') or 'the standby'}"
        )
    if found["role"] == "standby":
        seen = found["standby"]
        if not seen["inbox"]:
            lines.append("No directory of the first host is mounted (NIK_STANDBY_INBOX in .env): nothing arrives.")
        if seen.get("arrived"):
            lines.append(f"Last file received: {seen['arrived']['name']} at {_text(seen['arrived']['at'])}")
        else:
            lines.append("Last file received: none yet")
        behind = seen.get("behindSeconds")
        lines.append(
            "Replay: "
            + ("the last change is " + lasted(behind) + " old" if behind is not None else "no change replayed yet")
            + f"; {seen['waiting']} segment(s) wait to be replayed"
        )
        beat = seen.get("heartbeat") or {}
        if beat.get("at"):
            lines.append(
                f"First host ({beat.get('name') or 'unnamed'}, Nik {beat.get('version') or '?'}): last spoke "
                f"{lasted(time.time() - float(beat['at']))} ago; it said its copies were "
                f"{lasted(float(beat.get('behindSeconds') or 0))} behind (at most "
                f"{size(int(beat.get('behindBytes') or 0))} of log)"
            )
        if (seen.get("intake") or {}).get("error"):
            lines.append(f"Trouble taking in what arrived: {seen['intake']['error']}")
        lines.append("")
        lines.append("If this standby were promoted now:")
        lines += [f"  {line}" for line in found["loss"]["lines"]]
        return lines
    log = found["archive"]
    lines.append(
        "Archive of the log: "
        + (
            "off"
            if not log["on"]
            else "STUCK since " + str(log["failedAt"])
            if log["stuck"]
            else f"on, last segment {log['lastWal']} at {log['lastAt']}"
        )
        + f"; {log['waiting']} segment(s) wait to be archived"
    )
    window = found["window"]
    lines.append(
        f"One can go back to any moment from {window['oldest']} to {window['newest']}"
        if window["oldest"]
        else "No moment can be gone back to yet: there is no base backup"
    )
    proven = found["test"]["proven"]
    lines.append(f"Recovery proven: to {proven['target']} on {proven['at']}" if proven else "Recovery proven: not yet")
    copies = found["copies"]
    if copies["on"]:
        behind = copies["behind"]
        link = copies.get("link") or {}
        lines.append(f"Second host: {copies['where']}")
        if copies.get("hold") == "own":
            lines.append(
                "  nothing is sent: the copies point at this host itself (set the other host in Settings → Backup)"
            )
        elif link.get("ok") is False:
            lines.append(f"  NOT REACHED since {_text(link.get('since') or 0)}: {link.get('error')}")
        elif behind.get("seconds") is not None:
            lines.append(
                f"  behind by {lasted(behind['seconds'])}"
                + (f" (at most {size(behind['bytes'])} of log)" if behind.get("bytes") is not None else "")
                + f"; last segment sent {(copies.get('shipped') or {}).get('wal')}; "
                + f"{copies['store']['files']} files of the store wait"
            )
            lines.append(
                f"  if this host died now, about {lasted(behind['seconds'])} of work would not be on the second host"
            )
        else:
            lines.append("  nothing was sent yet")
    else:
        lines.append("Second host: none (set a backup passphrase and a destination in Settings → Backup)")
    for problem in found.get("problems") or []:
        lines.append(f"PROBLEM: {problem['text']}")
    return lines


def show_status(args) -> int:
    from ..core.db import SessionLocal
    from . import status

    with SessionLocal() as db:
        found = status.overview(db)
    if args.json:
        print(json.dumps(found, sort_keys=True, default=str))
    else:
        for line in describe(found):
            print(line)
    return 0


def drain(args) -> int:
    """Take in everything that arrived, and wait for the replay to reach it (bounded)."""
    from ..core.db import SessionLocal
    from . import role, standby

    deadline = time.monotonic() + float(args.wait)
    last = ""
    while True:
        did = standby.intake()
        last = did.get("lastOpened") or last
        waiting = int((did.get("wal") or {}).get("waiting") or 0)
        with SessionLocal() as db:
            if not role.in_recovery(db):
                _say("This server is not a standby.")
                return 1
            redo = standby.replay(db)
        replayed = layout.segment_of(redo["timeline"], redo["position"]) if redo["position"] else ""
        if not waiting and (not last or replayed >= last or not did.get("inbox")):
            _say(f"Everything that arrived is replayed (up to {replayed or 'nothing'}).")
            if args.promoting and not standby.mark_promoting():
                _say("The mark of the promotion could not be written in the archive volume.")
                return 1
            return 0
        if (did.get("wal") or {}).get("error"):
            _say(f"A file that arrived cannot be taken in: {did['wal']['error']}")
            if args.force and args.promoting and standby.mark_promoting():
                return 0
            return 2
        if time.monotonic() > deadline:
            _say(f"The replay has not reached the last segment that arrived ({last}) after {args.wait} seconds.")
            if args.force and args.promoting and standby.mark_promoting():
                return 0
            return 2
        time.sleep(1)


def promoted(args) -> int:
    """A standby that PostgreSQL has just promoted becomes the server."""
    from sqlalchemy import delete, select

    from .. import work
    from ..core import audit
    from ..core.db import SessionLocal
    from ..core.models import AuditEntry, Lease
    from . import config, files, role, standby

    with SessionLocal() as db:
        if role.in_recovery(db):
            raise BackupError("The database is still a standby: PostgreSQL was not promoted")
        name = args.name or role.name(db)
        marker = role.promote(db, name)
        # The processes of the first host are gone for this database: their leases, and the work
        # they held, which the sweeper of this server takes back at its first pass (work.py).
        db.execute(delete(Lease))
        work.orphan_all(db)
        # The copies went to this host; from now on they go where an administrator says.
        files.send_again(db)
        # What the first host had deleted and still kept for a recovery is kept here the same way.
        files.set_aside_gone(db)
        state = config.held(db, config.SHIP_SETTINGS_ID)
        for key in ("shipped", "histories", "link", "haveRead"):
            state.pop(key, None)
        config.keep(db, config.SHIP_SETTINGS_ID, state)
        # What the first host knew of its own archive (a test that was running there, what its
        # disk held, what it had proven) is not true of this one: the loop starts from nothing.
        config.keep(db, config.ARCHIVE_SETTINGS_ID, {})
        last = db.execute(
            select(AuditEntry.seq, AuditEntry.at)
            .where(AuditEntry.seq.is_not(None))
            .order_by(AuditEntry.seq.desc())
            .limit(1)
        ).first()
        audit.record(
            db,
            "server console",
            "standby.promote",
            f"This standby was promoted and is the server now (generation {marker['generation']}, as {name}). "
            + (
                f"The audit log it holds ends on entry {last[0]}, made {last[1]}: "
                if last
                else "The audit log it holds is empty: "
            )
            + "entries the first host wrote after that are not here",
            target="server",
        )
        db.commit()
    box = standby.inbox()
    written = False
    if box is not None:
        try:
            (box / role.MARKER).write_text(json.dumps(marker), encoding="utf-8")
            os.chmod(box / role.MARKER, 0o644)
            written = True
        except OSError:
            written = False
    if last:
        _say(f"The audit log ends on entry {last[0]}, made {last[1]}. Entries after it that a syslog receiver holds")
        _say("were written on the first host and are not here: the receiver is where they are.")
    # From here the step of the entrypoint lets this server start.
    standby.done_promoting()
    print(f"marker={json.dumps(marker, sort_keys=True)}")
    print(f"marker_written={int(written)}")
    print(f"generation={marker['generation']}")
    return 0


def is_promoting(_args) -> int:
    """Whether a promotion was started here and not finished (for ``deploy/standby.sh promote`` run again)."""
    from . import standby

    return 0 if standby.promoting() else 1


# --------------------------------------------------------------------------- #
# The keys a second host needs                                                #
# --------------------------------------------------------------------------- #
def pack_secrets(_args) -> int:
    """The keys this server has that another host must hold to be its standby, or to take its
    place: sealed under a passphrase typed for this one transfer, as text."""
    from ..core import keys

    phrase = os.environ.get("NIK_TRANSFER_PASSPHRASE", "")
    if len(phrase) < TRANSFER_MIN:
        raise BackupError(f"The passphrase of the transfer needs at least {TRANSFER_MIN} characters")
    held = {name: keys.value(name) for name in CARRIED}
    held = {name: value for name, value in held.items() if value}
    for needed in ("DB_PASSWORD", "SECRET_KEY", "STORE_KEY"):
        if needed not in held:
            raise BackupError(f"This server has no {needed} to give: is this the api container of a running stack?")
    out = io.BytesIO()
    writer = Writer(out, Key.new(PASSPHRASE, phrase), {"kind": "pair-secrets", "createdAt": now_iso()})
    with writer.part("secrets.json") as part:
        part.write(json.dumps(held, sort_keys=True).encode("utf-8"))
    writer.finish({"names": sorted(held)})
    sys.stdout.write(base64.encodebytes(out.getvalue()).decode("ascii"))
    _say(f"Sealed {len(held)} keys ({', '.join(sorted(held))}).")
    return 0


def unpack_secrets(_args) -> int:
    from ..core import keys

    phrase = os.environ.get("NIK_TRANSFER_PASSPHRASE", "")
    try:
        text = Path(_args.file).read_text(encoding="ascii") if _args.file else sys.stdin.read()
        raw = base64.b64decode(text, validate=False)
    except (ValueError, UnicodeError):
        raise BackupError("That is not a file of keys made by deploy/standby.sh secrets export") from None
    reader = Reader(io.BytesIO(raw), Secrets(passphrases=(phrase,)))
    if reader.header.get("kind") != "pair-secrets":
        raise BackupError("That is not a file of keys made by deploy/standby.sh secrets export")
    held: dict[str, str] = {}
    for part in reader.parts():
        if part.name == "secrets.json":
            held = json.loads(part.read())
    # Keys, one a line, for the script that puts them where this stack keeps its own: into a pipe,
    # never onto a screen.
    lines = [f"{name}={held[name]}" for name in CARRIED if held.get(name) and "\n" not in str(held[name])]
    if keys.to_a_terminal("The keys of the other host"):
        return 2
    sys.stdout.write("".join(line + "\n" for line in lines))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m app.recovery.tool", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    command = commands.add_parser("plan")
    command.add_argument("--to", required=True)
    command.add_argument("--from", dest="source", default="")
    command = commands.add_parser("fetch")
    command.add_argument("--label", required=True)
    command.add_argument("--from", dest="source", required=True)
    command = commands.add_parser("after")
    command.add_argument("--to", required=True)
    command.add_argument("--label", required=True)
    command.add_argument("--newest", default="")
    command.add_argument("--replaced", action="store_true", help="recovered on another host: it replaces the old one")
    command = commands.add_parser("status")
    command.add_argument("--json", action="store_true")
    command = commands.add_parser("drain")
    command.add_argument("--wait", default="120")
    command.add_argument("--promoting", action="store_true", help="leave the mark of a promotion that starts")
    command.add_argument("--force", action="store_true", help="go on although not everything could be replayed")
    commands.add_parser("promoting")
    command = commands.add_parser("promoted")
    command.add_argument("--name", default="")
    commands.add_parser("pack-secrets")
    command = commands.add_parser("unpack-secrets")
    command.add_argument("--file", default="", help="the file to open (default: the standard input)")
    args = parser.parse_args(argv)
    run = {
        "plan": plan,
        "fetch": fetch,
        "after": after,
        "status": show_status,
        "drain": drain,
        "promoted": promoted,
        "promoting": is_promoting,
        "pack-secrets": pack_secrets,
        "unpack-secrets": unpack_secrets,
    }[args.command]
    try:
        return run(args)
    except (BackupError, OSError) as error:
        _say(f"recovery: {error}")
        return 1
    except Exception as error:  # noqa: BLE001 - the database said no: its words, not a traceback
        _say(f"recovery: {type(error).__name__}: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
