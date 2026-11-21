"""Recovery to a moment and the standby, as the screens see them (administrators only).

These routes read where things stand and ask for work; the work is done by
the loops of ``app/recovery`` and by the recovery service. Going back to a
moment, setting up a standby and promoting one are not here on purpose: each
is a command on the host concerned (``deploy/restore.sh --to``,
``deploy/standby.sh``), run by somebody who can see that host.

As for the backups: reading the state and asking for a base backup or a
recovery test are open to an administrator's API key; changing the settings
needs a signed-in administrator.

``/api/internal/store-sealed`` is not for people. The process that sends the
copies to the second host holds neither the store nor its key
(``app/store_handover.py``): it asks here for each file it sends, and is
given the file as it is on the disk, sealed, never one that is in clear.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session as OrmSession

from .. import store_handover
from ..core import audit, store
from ..core.db import get_db
from ..core.security import Principal, admin_principal, admin_session
from ..recovery import agent, archive, config, kept, ship, status

router = APIRouter(prefix="/recovery", tags=["backup"])
internal = APIRouter(prefix="/internal", tags=["backup"], include_in_schema=False)


@router.get("")
def read_recovery(_: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Where the recovery to a moment stands: whether the log is archived, the oldest and the
    newest moment one can go back to, the base backups, the last recovery test, what the archive
    takes, how far behind the second host is, and the role of this server."""
    return status.overview(db)


@router.put("/settings")
def write_settings(
    body: dict[str, Any] = Body(...), caller: Principal = Depends(admin_session), db: OrmSession = Depends(get_db)
) -> dict:
    """Change when the base backups are taken (``base``), how many days one can go back
    (``keepDays``), the delay of the second host that is warned about (``lagMinutes``), how often
    the archive is proven (``testEveryHours``) and the name this server gives itself to the other
    host (``name``). Only the keys that are sent change."""
    try:
        changed = config.write(db, body)
    except config.ConfigError as error:
        raise HTTPException(status_code=422, detail=str(error)) from None
    if changed:
        audit.record(
            db,
            caller.actor,
            "recovery.settings",
            "Changed the recovery to a moment: " + ", ".join(changed),
            target="recovery",
        )
    db.commit()
    return status.overview(db)


@router.post("/base", status_code=202)
def take_base(caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Ask for a base backup now. The recovery service takes it; the list shows it when it is done."""
    try:
        label = archive.ask_base(db, caller.actor)
    except agent.AgentError as error:
        raise HTTPException(status_code=409, detail=str(error)) from None
    audit.record(db, caller.actor, "recovery.base", f"Asked for the base backup {label}", target=label)
    db.commit()
    return status.overview(db)


@router.post("/test", status_code=202)
def run_test(caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Ask for a recovery test now: the latest base backup and the archive are replayed into a
    scratch server, to a moment a minute before the last segment archived."""
    overview = status.overview(db)
    if not overview.get("available"):
        raise HTTPException(status_code=409, detail="This server has no archive of its log")
    if not any(base["state"] == "done" and base["local"] for base in overview.get("bases") or []):
        raise HTTPException(status_code=409, detail="There is no base backup yet to recover from")
    archive.ask_test_now(db)
    audit.record(db, caller.actor, "recovery.test", "Asked for a recovery test", target="recovery")
    db.commit()
    return status.overview(db)


@internal.get("/store-sealed")
def sealed_file(name: str = Query(default="", max_length=600), x_nik_store: str = Header(default="")):
    """A file of the store as it is on the disk (sealed), for the process that copies the store to
    the second host. The request proves it comes from a process of this server; anything else is
    answered as if the route did not exist. A file in clear is not given."""
    if not name or not store_handover.verify(ship.SEALED_KIND, name, x_nik_store):
        raise HTTPException(status_code=404, detail="Not Found")
    pieces = Path(name).parts
    if name.startswith(("/", "\\")) or ".." in pieces or not pieces or pieces[0] == kept.KEPT:
        raise HTTPException(status_code=404, detail="Not Found")
    root = store.root().resolve()
    path = (root / name).resolve()
    if root not in path.parents or not path.is_file() or not store.is_sealed(path):
        raise HTTPException(status_code=404, detail="The file is not in the store, or is not sealed yet")
    return FileResponse(path, media_type="application/octet-stream")
