"""Shared (global) settings routes.

A single row (id=1) holds ``{ keywords, businessHours, iocAllowlist, report, mail, enrichment }``
(``report``: the organisation name and logo printed on incident reports;
``mail``: own domains and trusted mail servers for Mail Analysis;
``enrichment``: automatic threat-intelligence lookups, never the API keys). When it has never
been written, the factory defaults from ``defaults.py`` are returned.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .. import lists
from ..core import audit
from ..core.db import get_db
from ..core.models import Setting
from ..core.schemas import SettingsIn, SettingsOut
from ..core.security import Principal, principal, writer_principal
from ..defaults import default_settings_doc
from ..enrichment.service import config as enrichment_config
from ..iocs import DEFAULT_ALLOWLIST

router = APIRouter(prefix="/settings", tags=["settings"])

# Fixed primary key for the single shared settings row.
SETTINGS_ID = 1
# What decides where data goes and what a report says: admins only.
ADMIN_KEYS = ("report", "mail", "enrichment")


def read_settings(db: OrmSession) -> dict:
    """The shared settings, with any missing key filled from the defaults."""
    row = db.get(Setting, SETTINGS_ID)
    doc = (row.doc if row is not None else None) or {}
    defaults = default_settings_doc()
    merged = {key: doc.get(key, value) for key, value in defaults.items()}
    # What became lists is read from them, in the shape it always had.
    for key in ("keywords", "businessHours", "iocAllowlist"):
        merged[key] = lists.settings_value(db, key, defaults[key])
    held = merged["mail"] if isinstance(merged["mail"], dict) else {}
    merged["mail"] = {
        **defaults["mail"],
        **held,
        **{key: lists.settings_value(db, f"mail.{key}", []) for key in ("orgDomains", "trustedAuthServers")},
    }
    merged["enrichment"] = enrichment_config(merged)
    return merged


def _out(doc: dict) -> dict:
    return {**doc, "iocAllowlistDefault": list(DEFAULT_ALLOWLIST)}


@router.get("", response_model=SettingsOut)
def get_settings(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Return the shared settings, falling back to factory defaults."""
    return _out(read_settings(db))


@router.put("", response_model=SettingsOut)
def put_settings(
    body: SettingsIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Store the shared settings and return them (a session, or a key with the write scope).

    Detection keywords, business hours and the indicator allowlist are the
    analysts' working tools. The report header, the mail settings and the
    threat-intelligence settings (which decide what leaves the server) are
    changed by admins only: sent by anyone else they are left as they are.
    """
    current = read_settings(db)
    is_admin = caller.has("admin")
    if not is_admin:
        body = body.model_copy(update={key: None for key in ADMIN_KEYS})
    # A key that was not sent keeps what is stored: a page sends only what it changed.
    sent = body.model_fields_set
    doc = {
        "keywords": body.keywords if "keywords" in sent else current["keywords"],
        "businessHours": body.businessHours if "businessHours" in sent else current["businessHours"],
        "iocAllowlist": (
            [str(entry).strip() for entry in body.iocAllowlist if str(entry).strip()]
            if body.iocAllowlist is not None
            else current["iocAllowlist"]
        ),
        "report": body.report.model_dump() if body.report is not None else current["report"],
        "mail": (
            {
                key: sorted({d.strip().lower().strip(".") for d in getattr(body.mail, key) if d.strip(" .")})
                for key in ("orgDomains", "trustedAuthServers")
            }
            if body.mail is not None
            else current["mail"]
        ),
        # What the data guard lets the look-ups send is not saved here: opening a class has a route
        # of its own, behind a double check (PUT /api/enrichment/guard), and saving the rest keeps it.
        "enrichment": (
            {**body.enrichment.model_dump(), "guardOpen": current["enrichment"]["guardOpen"]}
            if body.enrichment is not None
            else current["enrichment"]
        ),
    }
    changed = sorted(key for key, value in doc.items() if value != current.get(key))
    # What is a list is written to its list; the document keeps which list that is.
    stored = dict(doc)
    pointers = lists.pointers_of(db)
    for key in ("keywords", "businessHours", "iocAllowlist"):
        if key in changed or lists.find(db, pointers[key]) is None:
            lists.apply_setting(db, key, doc[key], caller.actor)
        stored[key] = {"list": pointers[key]}
    stored["mail"] = dict(doc["mail"])
    for key in ("orgDomains", "trustedAuthServers"):
        if "mail" in changed or lists.find(db, pointers[f"mail.{key}"]) is None:
            lists.apply_setting(db, f"mail.{key}", doc["mail"].get(key) or [], caller.actor)
        stored["mail"][key] = {"list": pointers[f"mail.{key}"]}
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        row = Setting(id=SETTINGS_ID, doc=stored)
        db.add(row)
    else:
        row.doc = stored
        flag_modified(row, "doc")
    if changed:
        audit.record(db, caller.actor, "settings.update", f"Changed the settings: {', '.join(changed)}")
    db.commit()
    return _out(read_settings(db))
