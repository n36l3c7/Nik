"""Shared (global) settings routes.

A single row (id=1) holds ``{ keywords, businessHours, iocAllowlist, report }``
(``report``: the organisation name and logo printed on incident reports). When it has never
been written, the factory defaults from ``defaults.py`` are returned.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..db import get_db
from ..defaults import default_settings_doc
from ..iocs import DEFAULT_ALLOWLIST
from ..models import Setting, User
from ..schemas import SettingsIn, SettingsOut
from ..security import Principal, current_user, principal

router = APIRouter(prefix="/settings", tags=["settings"])

# Fixed primary key for the single shared settings row.
SETTINGS_ID = 1


def read_settings(db: OrmSession) -> dict:
    """The shared settings, with any missing key filled from the defaults."""
    row = db.get(Setting, SETTINGS_ID)
    doc = (row.doc if row is not None else None) or {}
    defaults = default_settings_doc()
    return {key: doc.get(key, value) for key, value in defaults.items()}


def _out(doc: dict) -> dict:
    return {**doc, "iocAllowlistDefault": list(DEFAULT_ALLOWLIST)}


@router.get("", response_model=SettingsOut)
def get_settings(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Return the shared settings, falling back to factory defaults."""
    return _out(read_settings(db))


@router.put("", response_model=SettingsOut)
def put_settings(
    body: SettingsIn,
    _user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Store the shared settings and return them."""
    current = read_settings(db)
    doc = {
        "keywords": body.keywords,
        "businessHours": body.businessHours,
        "iocAllowlist": (
            [str(entry).strip() for entry in body.iocAllowlist if str(entry).strip()]
            if body.iocAllowlist is not None
            else current["iocAllowlist"]
        ),
        "report": body.report.model_dump() if body.report is not None else current["report"],
    }
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        row = Setting(id=SETTINGS_ID, doc=doc)
        db.add(row)
    else:
        row.doc = doc
        flag_modified(row, "doc")
    db.commit()
    return _out(doc)
