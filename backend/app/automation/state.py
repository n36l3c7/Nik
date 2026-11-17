"""The automation settings an admin holds, and the worker's heartbeat.

One row of ``settings`` (id 2, next to the analysts' settings in row 1):

    {"enabled": true,            the general switch: off stops all automation at once
     "hosts": ["siem.corp"],     hosts every "listed" playbook may reach besides its own
     "heartbeat": 1794807000.0}  when the worker last said it was alive
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..core.models import Setting

SETTINGS_ID = 2
HEARTBEAT_EVERY = 10
HEARTBEAT_STALE = 60
DEFAULTS: dict[str, Any] = {"enabled": True, "hosts": [], "heartbeat": 0.0}


def read(db: OrmSession) -> dict[str, Any]:
    row = db.get(Setting, SETTINGS_ID)
    return {**DEFAULTS, **((row.doc if row else None) or {})}


def write(db: OrmSession, **changes: Any) -> dict[str, Any]:
    """Change some of the settings (the caller commits)."""
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        row = Setting(id=SETTINGS_ID, doc=dict(DEFAULTS))
        db.add(row)
    row.doc = {**DEFAULTS, **(row.doc or {}), **changes}
    flag_modified(row, "doc")
    return row.doc


def enabled(db: OrmSession) -> bool:
    return bool(read(db)["enabled"])


def beat(db: OrmSession, now: float | None = None) -> None:
    write(db, heartbeat=time.time() if now is None else now)
    db.commit()


def worker_alive(db: OrmSession, now: float | None = None) -> bool:
    return (time.time() if now is None else now) - float(read(db)["heartbeat"] or 0) < HEARTBEAT_STALE
