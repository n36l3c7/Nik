"""capa rules added by admins: validation through the capa worker, files in the store.

The capa worker sees the sample store read-only, so each rule is written to
``<SAMPLE_STORE>/_capa_rules/<id>.yml`` and passed to it as a relative path.
Rules are parsed and checked by the worker (it has capa and the bundled
rules); the backend only keeps rules consistent with each other: a rule that
another enabled rule uses (``match: <name>``) cannot be disabled or deleted.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from .analyzer import post_worker
from .config import settings
from .models import CapaRule
from .samples import store_dir

FOLDER = "_capa_rules"
MAX_SOURCE_CHARS = 64 * 1024
VALIDATE_TIMEOUT = 120
_ID_RE = re.compile(r"^[0-9a-f]{32}$")


def relative_path(row: CapaRule) -> str:
    return f"{FOLDER}/{row.id}.yml"


def _absolute(rule_id: str) -> Path:
    if not _ID_RE.match(rule_id):
        raise ValueError("Invalid rule identifier.")
    folder = store_dir() / FOLDER
    folder.mkdir(exist_ok=True)
    return folder / f"{rule_id}.yml"


def write_file(row: CapaRule) -> None:
    """Store the rule's source read-only for everyone (the worker runs as another user)."""
    path = _absolute(row.id)
    if path.exists():
        os.chmod(path, 0o640)
    tmp = path.with_suffix(".part")
    tmp.write_text(row.source, encoding="utf-8")
    os.chmod(tmp, 0o444)
    tmp.replace(path)


def delete_file(row: CapaRule) -> None:
    path = _absolute(row.id)
    if path.exists():
        os.chmod(path, 0o640)
        path.unlink()


def enabled_rules(db: OrmSession) -> list[CapaRule]:
    return list(db.scalars(select(CapaRule).where(CapaRule.enabled.is_(True)).order_by(CapaRule.created_at)).all())


def enabled_paths(db: OrmSession) -> list[str]:
    """Relative paths of the enabled rules, for the worker."""
    return [relative_path(row) for row in enabled_rules(db)]


def validate(db: OrmSession, source: str, exclude_id: str | None = None) -> dict[str, Any]:
    """The worker's verdict on ``source`` next to the bundled rules and the other enabled admin rules."""
    others = [row.source for row in enabled_rules(db) if row.id != exclude_id]
    payload = {"source": source, "others": others}
    return post_worker(settings.CAPA_URL, settings.CAPA_TOKEN, "/validate", payload, VALIDATE_TIMEOUT)


def dependents(db: OrmSession, row: CapaRule) -> list[str]:
    """Names of the other enabled rules whose features ``match:`` this one."""
    used = re.compile(r"match:\s*[\"']?" + re.escape(row.name) + r"[\"']?\s*$", re.MULTILINE)
    return [other.name for other in enabled_rules(db) if other.id != row.id and used.search(other.source)]


def custom_names(db: OrmSession) -> set[str]:
    """Names of all admin rules, to tell their matches from the bundled ones."""
    return set(db.scalars(select(CapaRule.name)).all())
