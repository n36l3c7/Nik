"""Shared (global) settings routes.

A single row (id=1) holds ``{ keywords, businessHours }``. When it has never
been written, the factory defaults from ``defaults.py`` are returned.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from ..db import get_db
from ..defaults import default_settings_doc
from ..models import Setting, User
from ..schemas import SettingsIn, SettingsOut
from ..security import Principal, current_user, principal

router = APIRouter(prefix="/settings", tags=["settings"])

# Fixed primary key for the single shared settings row.
SETTINGS_ID = 1


@router.get("", response_model=SettingsOut)
def get_settings(
    _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Return the shared settings, falling back to factory defaults."""
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        return default_settings_doc()
    doc = row.doc or {}
    # Be defensive: fill any missing top-level key from defaults.
    defaults = default_settings_doc()
    return {
        "keywords": doc.get("keywords", defaults["keywords"]),
        "businessHours": doc.get("businessHours", defaults["businessHours"]),
    }


@router.put("", response_model=SettingsOut)
def put_settings(
    body: SettingsIn,
    _user: User = Depends(current_user),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Store the shared settings and return them."""
    doc = {"keywords": body.keywords, "businessHours": body.businessHours}
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        row = Setting(id=SETTINGS_ID, doc=doc)
        db.add(row)
    else:
        row.doc = doc
        flag_modified(row, "doc")
    db.commit()
    return doc
