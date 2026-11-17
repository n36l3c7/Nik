"""The playbooks Nik ships (``seed/playbooks/*.json``).

Each file is a playbook as "Export" writes it, so it can also be imported by
hand. At start each one that was never added before is added once, **off**:

- as version 1 when its graph is valid here, so that turning it on is all it
  takes;
- as a draft when something is missing (a connection to choose, a repository
  to name): the canvas shows what, and it cannot be turned on until then.

They are playbooks like any other from then on: edited, renamed, deleted. One
that was deleted does not come back, and one that was changed is not
overwritten by a release: what was added is remembered in the automation
settings (``shippedPlaybooks``), by the name of its file.

A script node in a file names its script and no version: it takes the version
the script has here.
"""

from __future__ import annotations

import copy
import json
import logging
import time
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import Playbook, PlaybookVersion, Script
from ..core.security import now_iso
from . import catalog, engine, graph, state, triggers

logger = logging.getLogger("nik.automation")

SEED_DIR = Path(__file__).parent / "seed" / "playbooks"
ACTOR = "nik"


def files() -> list[tuple[str, dict[str, Any]]]:
    """(key, playbook) of every shipped file, by name."""
    found = []
    for path in sorted(SEED_DIR.glob("*.json")):
        source = json.loads(path.read_text(encoding="utf-8"))
        found.append((path.stem, source["playbook"]))
    return found


def with_script_versions(db: OrmSession, shape: dict) -> dict:
    """The graph with every script node that names no version given the script's current one."""
    shape = copy.deepcopy(shape)
    for node in shape.get("nodes") or []:
        config = node.get("config") if isinstance(node, dict) else None
        if (
            not isinstance(config, dict)
            or node.get("kind") != "script"
            or isinstance(config.get("script_version"), int)
        ):
            continue
        script = db.scalars(select(Script).where(Script.name == str(config.get("script") or ""))).first()
        if script is not None and script.current_version:
            config["script_version"] = script.current_version
    return shape


def add(db: OrmSession, source: dict[str, Any], now: float) -> Playbook:
    """Add one shipped playbook, off (the caller commits)."""
    shape = with_script_versions(db, source["graph"])
    stamp = now_iso()
    row = Playbook(
        id=engine.new_id(),
        name=str(source["name"])[:120],
        description=str(source.get("description") or "")[:2000],
        enabled=False,
        draft=shape,
        max_runs_per_hour=int(source.get("maxRunsPerHour") or 60),
        one_per_object=bool(source.get("onePerObject", True)),
        max_seconds=int(source.get("maxSeconds") or 86400),
        approval_default=bool(source.get("approvalDefault", True)),
        builtin=True,
        created_at=stamp,
        created_by=ACTOR,
        updated_at=stamp,
        updated_by=ACTOR,
    )
    db.add(row)
    db.flush()
    if not graph.validate(shape, catalog.Library(db), row.name):
        db.add(
            PlaybookVersion(
                playbook_id=row.id, version=1, graph=shape, note="As shipped", created_at=stamp, created_by=ACTOR
            )
        )
        row.current_version, row.draft = 1, None
        db.flush()
        triggers.sync_schedule(db, row, now)  # off: it has no schedule yet
    return row


def seed(db: OrmSession) -> int:
    """Add the shipped playbooks that were never added here; returns how many (the caller commits)."""
    known = list(state.read(db).get("shippedPlaybooks") or [])
    added = 0
    for key, source in files():
        if key in known:
            continue
        known.append(key)
        name = str(source["name"])
        taken = db.scalars(select(Playbook).where(func.lower(Playbook.name) == name.lower())).first()
        if taken is not None:
            # Someone made a playbook with this name: it is theirs, and the shipped one is not forced beside it.
            continue
        add(db, source, time.time())
        added += 1
    if known != list(state.read(db).get("shippedPlaybooks") or []):
        state.write(db, shippedPlaybooks=known)
    return added
