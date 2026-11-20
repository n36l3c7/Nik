"""The backups Nik takes by itself (administrators only).

What these routes do is set things and ask for work; the work itself (taking
a backup, its restore test, the copy off the server) is done by the loops of
``app/backups/scheduler.py``, so a request never waits for a backup and two
never run at once. Putting a backup back is not here on purpose: it is done
from the command line with the stack stopped (``deploy/restore.sh``).

``/backup/export`` and ``/backup/import`` (``routers/backup.py``) are the
older export of incidents, accounts and settings as one JSON file. They are
kept: that file moves content between two servers. It is not a backup.

**A key or a person.** Reading the state, asking for a backup, for a restore
test and for a test of the destination are open to an administrator's API key
as to a signed-in administrator: a monitoring tool or a script may want them.
Changing the settings or the passphrase, deleting a backup and downloading
one need a signed-in administrator (``admin_session``): whoever holds a key
alone must not be able to point the copies elsewhere, replace the passphrase
the next backups are made under, remove the way back or take the files away.
"""

from __future__ import annotations

import shutil
import time
from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..backups import config, offsite, policy, runner, watch
from ..backups.container import SUFFIX, BackupError
from ..core import audit
from ..core.config import settings as app_settings
from ..core.db import get_db
from ..core.models import Backup
from ..core.security import Principal, admin_principal, admin_session

router = APIRouter(prefix="/backups", tags=["backup"])


def _backup_out(row: Backup, last_good: str | None) -> dict[str, Any]:
    copy = row.offsite or {}
    return {
        "id": row.id,
        "kind": row.kind,
        "state": row.state,
        "createdAt": row.created_at,
        "finishedAt": row.finished_at,
        "size": row.size,
        "nikVersion": row.nik_version,
        "revision": row.revision,
        "label": row.label,
        "error": row.error,
        "requestedBy": row.requested_by,
        "summary": row.summary or {},
        "verifyState": row.verify_state,
        "verifiedAt": row.verified_at,
        "verify": row.verify or {},
        "local": row.local,
        "offsiteState": row.offsite_state,
        "offsite": {key: copy.get(key) for key in ("where", "at", "error", "bytes", "seconds") if copy.get(key)},
        "lastGood": row.id == last_good,
        "file": f"{row.id}{SUFFIX}",
        # What an operator types on the server to put this backup back.
        "restoreCommand": "deploy/rollback.sh " + row.id if row.kind == "upgrade" else f"deploy/restore.sh {row.id}",
    }


def _state(db: OrmSession) -> dict[str, Any]:
    now = time.time()
    doc = config.read(db)
    rows = list(db.scalars(select(Backup).where(Backup.offsite_state != "delete").order_by(Backup.created_at.desc())))
    good = runner.last_good(db)
    folder = runner.directory()
    try:
        disk = shutil.disk_usage(folder)
        room = {"total": disk.total, "free": disk.free}
    except OSError:
        room = None
    ready = bool(doc.get("passphrase")) and config.passphrase(db) is not None
    upcoming = policy.next_slot(doc["schedule"], now) if ready else None
    destination = doc.get("destination") or {}
    return {
        "settings": config.out(db),
        "state": {
            "lastGood": _backup_out(good, good.id) if good else None,
            "nextRun": runner.iso(upcoming) if upcoming else None,
            "running": any(
                row.state in ("queued", "running") or row.verify_state in ("queued", "running") for row in rows
            ),
            "directory": {"path": str(folder), "disk": room},
            # What the backups that are here take, and the size of the last good one.
            "space": runner.space(db),
            "copies": offsite.Sftp(destination, "").where if config.ready(destination) else "",
            "problems": watch.out(db),
            "nikVersion": runner.nik_version(),
            "sends": app_settings.AUTOMATION_WORKER,
        },
        "backups": [_backup_out(row, good.id if good else None) for row in rows],
    }


@router.get("")
def read_backups(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The settings of the backups, where things stand (the last good backup, the next run, what
    is wrong) and every backup Nik knows, the latest first. No secret is returned: of the
    passphrase and of the key of the destination, only whether they are set."""
    return _state(db)


@router.put("/settings")
def write_settings(
    body: dict[str, Any] = Body(...), caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)
) -> dict:
    """Change the schedule (``schedule``), the retention (``retention``), the age of the last good
    backup that is warned about (``warnAfterHours``), whether ``SECRET_KEY`` goes inside the
    backups (``includeKey``) and the destination of the copy off the server (``destination``).
    Only the keys that are sent change."""
    try:
        changed = config.write(db, body)
    except config.ConfigError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    if changed:
        audit.record(
            db, caller.actor, "backup.settings", "Changed the backups: " + ", ".join(changed), target="backups"
        )
    db.commit()
    return _state(db)


@router.put("/passphrase")
def write_passphrase(
    body: dict[str, Any] = Body(...), caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)
) -> dict:
    """Set the backup passphrase (``passphrase``). Every backup taken from now on is encrypted
    under it; the earlier ones keep the passphrase they were made with. It is never returned."""
    was_set = bool(config.read(db).get("passphrase"))
    try:
        config.set_passphrase(db, body.get("passphrase"))
    except config.ConfigError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    audit.record(
        db,
        caller.actor,
        "backup.settings",
        "Changed the backup passphrase" if was_set else "Set the backup passphrase",
        target="backups",
    )
    db.commit()
    return _state(db)


@router.post("/run", status_code=202)
def run_backup(caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Ask for a backup now. It is taken by the server within a few seconds and tested when it
    is written; the answer is its row, to be read again until it is ``done``."""
    if config.passphrase(db) is None:
        raise HTTPException(status_code=409, detail="Set the backup passphrase first: no backup is written in clear.")
    waiting = db.scalars(select(Backup).where(Backup.kind == "full", Backup.state.in_(("queued", "running")))).first()
    if waiting is not None:
        raise HTTPException(status_code=409, detail="A backup is already being taken.")
    row = runner.start_row(db, "full", caller.actor)
    audit.record(db, caller.actor, "backup.request", f"Asked for the backup {row.id}", target=row.id)
    db.commit()
    return _backup_out(row, None)


def _row(db: OrmSession, backup_id: str) -> Backup:
    row = db.get(Backup, backup_id) if runner.NAME.match(backup_id) else None
    if row is None or row.offsite_state == "delete":
        raise HTTPException(status_code=404, detail="There is no such backup.")
    return row


@router.post("/{backup_id}/verify", status_code=202)
def verify_backup(
    backup_id: str, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Ask for the restore test of a backup again: it is restored into a scratch database and
    everything it holds is compared. The answer is its row, to be read again."""
    row = _row(db, backup_id)
    if row.state != "done" or not row.local:
        raise HTTPException(status_code=409, detail="Only a backup whose file is on the server can be tested.")
    if row.verify_state not in ("queued", "running"):
        row.verify_state = "queued"
        audit.record(db, caller.actor, "backup.request", f"Asked for the restore test of {row.id}", target=row.id)
        db.commit()
    return _backup_out(row, None)


@router.delete("/{backup_id}")
def delete_backup(
    backup_id: str,
    confirm: str = Query(default=""),
    last_good: bool = Query(default=False, alias="lastGood"),
    caller: Principal = Depends(admin_session),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Delete a backup: its file, and its copy off the server at the next pass. ``confirm`` must
    be its name; the last good backup also needs ``lastGood=true``."""
    row = _row(db, backup_id)
    if row.state == "running" or row.verify_state == "running":
        raise HTTPException(status_code=409, detail="This backup is being written or tested: wait for it to end.")
    if confirm != row.id:
        raise HTTPException(status_code=422, detail="Type the name of the backup to delete it.")
    good = runner.last_good(db)
    if good is not None and good.id == row.id and not last_good:
        raise HTTPException(
            status_code=409,
            detail="This is the last good backup: deleting it leaves none that is known to restore. Confirm again.",
        )
    try:
        runner.remove(db, row, caller.actor)
    except BackupError as error:
        raise HTTPException(status_code=500, detail=str(error)) from None
    db.commit()
    return {"deleted": backup_id}


@router.get("/{backup_id}/download")
def download_backup(
    backup_id: str, caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)
) -> FileResponse:
    """The file of a backup, as it is on the disk: encrypted. It can be read only with the
    passphrase it was made with (``deploy/restore.sh``, or ``container.py`` alone)."""
    row = _row(db, backup_id)
    path = runner.file_of(row.id)
    if row.state != "done" or not path.is_file():
        raise HTTPException(status_code=404, detail="The file of this backup is not on the server.")
    audit.record(db, caller.actor, "backup.download", f"Downloaded the backup {row.id}", target=row.id)
    db.commit()
    return FileResponse(path, media_type="application/octet-stream", filename=path.name)


@router.post("/destination/test")
def test_destination(caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Try the destination that is saved: connect, sign in, write a small file, read it back,
    remove it. The process that sends the copies does it (the backend has no way out), so the
    answer can take a few seconds; it carries the host key the server presented."""
    destination = config.read(db).get("destination") or {}
    if destination.get("kind") != "sftp" or not destination.get("secret"):
        raise HTTPException(status_code=409, detail="Save a destination with its key or password first.")
    if app_settings.AUTOMATION_WORKER == "off":
        raise HTTPException(
            status_code=409,
            detail="Copies are sent by the automation worker, and AUTOMATION_WORKER is off on this server.",
        )
    request = offsite.ask_test(db)
    audit.record(
        db, caller.actor, "backup.request", "Tested the destination of the copy off the server", target="backups"
    )
    db.commit()
    deadline = time.time() + offsite.TEST_ANSWER_WITHIN
    while time.time() < deadline:
        db.rollback()  # a new look at the row, and no transaction held while waiting
        answer = offsite.test_answer(db, request)
        if answer is not None:
            return answer
        time.sleep(0.5)
    return {
        "ok": False,
        "message": "The automation worker, which sends the copies, did not answer. "
        "Its state is in Settings → System → Workers.",
    }
