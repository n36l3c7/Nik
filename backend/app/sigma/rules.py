"""The rules Nik keeps (``sigma_rules``): saving, listing, switching, deleting, going back to a pack's text.

One row is one YAML document. The worker reads it (``checking.py``): what this module stores of a
rule (its title, level, log source, whether Nik can run it) is what the worker said, never read here.
The one exception is ``quick``, a plain YAML read for a rule the worker could not be asked about (it
was not there): such a row is stored as **not checked**, ``engine`` empty and ``supported`` false, so it
is listed but never run, and ``recheck.py`` checks it when the worker answers.

**Whose a rule is.** ``pack`` is empty for a rule written here, ``nik`` for the ones Nik ships, or the
id of the pack that brought it. ``updated_by`` says who last wrote the text: ``nik`` (or ``pack:<id>``)
for the text the pack gave, a person otherwise. A pack rule a person changed keeps their text when the
pack is updated, and ``original`` holds what the pack says, so Reset has it to put back. Pack rules
are switched off, never deleted.

**Switching on.** A rule is run when it is ``enabled`` and ``supported``. One that arrives from a pack
is enabled when it is supported, its status is stable or test, and its level is medium or more; one
written here, or shipped by Nik, when it is supported.
"""

from __future__ import annotations

import re
from typing import Any

import yaml
from sqlalchemy import case, func, or_, select, update
from sqlalchemy.orm import Session as OrmSession

from ..core.models import Pack, Setting, SigmaRule
from ..core.security import now_iso
from .checking import LEVEL_NAMES, level_of

SETTINGS_ID = 110
NIK = "nik"
ID_MAX = 64
CHUNK = 500
NOT_CHECKED = "Not checked yet: the forensics worker was not reached"
ORDERS = ("title", "-level", "level", "-updated")
PACK_STATUS = ("stable", "test")
PACK_LEVEL = 3
FILTERS = (
    "q",
    "pack",
    "level",
    "status",
    "enabled",
    "supported",
    "product",
    "category",
    "service",
    "kind",
)


class SigmaError(Exception):
    """A request the rules cannot take: a sentence, the status, and the errors of a text when it has some."""

    def __init__(
        self,
        message: str,
        status: int = 400,
        errors: list[dict[str, Any]] | None = None,
    ):
        super().__init__(message)
        self.message = message
        self.status = status
        self.errors = errors


# --------------------------------------------------------------------------- #
# The generation: what tells the processes that the set of rules changed        #
# --------------------------------------------------------------------------- #
def generation(db: OrmSession) -> int:
    held = db.scalar(select(Setting.doc).where(Setting.id == SETTINGS_ID))
    value = held.get("gen") if isinstance(held, dict) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def bump(db: OrmSession) -> None:
    """The set the worker is given may have changed (the caller commits)."""
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc={"gen": 1}))
        db.flush()  # a second write in this transaction finds the row
    else:
        held = dict(row.doc or {})
        held["gen"] = (held["gen"] if isinstance(held.get("gen"), int) else 0) + 1
        row.doc = held


def setting(db: OrmSession, key: str, default: Any = None) -> Any:
    held = db.scalar(select(Setting.doc).where(Setting.id == SETTINGS_ID))
    return held.get(key, default) if isinstance(held, dict) else default


def keep_setting(db: OrmSession, key: str, value: Any) -> None:
    row = db.get(Setting, SETTINGS_ID)
    if row is None:
        db.add(Setting(id=SETTINGS_ID, doc={key: value}))
        db.flush()
    else:
        row.doc = {**(row.doc or {}), key: value}


# --------------------------------------------------------------------------- #
# What a row is                                                                #
# --------------------------------------------------------------------------- #
def marker(pack: str) -> str:
    """What ``updated_by`` holds for the text a pack gave."""
    return NIK if pack == NIK else f"pack:{pack}"


def edited(row: SigmaRule) -> bool:
    """Whether a person changed the text of a rule of a pack."""
    return bool(row.pack) and row.updated_by != marker(row.pack)


def quick(text: str) -> dict[str, Any] | None:
    """What a plain read of the YAML says of one rule, for a rule the worker could not be asked about:
    ``None`` when it is not a mapping with an ``id``. This judges nothing."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict) or not str(doc.get("id") or "").strip():
        return None
    where = doc.get("logsource") if isinstance(doc.get("logsource"), dict) else {}
    tags = doc.get("tags") if isinstance(doc.get("tags"), list) else []
    return {
        "id": str(doc["id"]).strip(),
        "name": str(doc.get("name") or ""),
        "title": str(doc.get("title") or ""),
        "author": str(doc.get("author") or ""),
        "level": doc.get("level") or "medium",
        "status": str(doc.get("status") or ""),
        "kind": "correlation" if isinstance(doc.get("correlation"), dict) else "rule",
        "product": str(where.get("product") or ""),
        "category": str(where.get("category") or ""),
        "service": str(where.get("service") or ""),
        "tags": [str(tag) for tag in tags],
        "supported": False,
        "reason": NOT_CHECKED,
        "source": text,
    }


def columns(info: dict[str, Any], engine: str) -> dict[str, Any]:
    """The values of a row, out of what the worker said of a rule (or ``quick`` of one it was not asked
    about, with an empty ``engine``)."""
    return {
        "name": str(info.get("name") or "")[:200],
        "title": str(info.get("title") or info.get("id") or "")[:300],
        "author": str(info.get("author") or "")[:300],
        "kind": "correlation" if info.get("kind") == "correlation" else "rule",
        "level": level_of(info.get("level")),
        "status": str(info.get("status") or "")[:14],
        "product": str(info.get("product") or "")[:40],
        "category": str(info.get("category") or "")[:60],
        "service": str(info.get("service") or "")[:60],
        "tags": [str(tag)[:100] for tag in (info.get("tags") or [])][:100],
        "source": str(info["source"]),
        "supported": bool(info.get("supported", True)) and bool(engine),
        "reason": str(info.get("reason") or "")[:400] if engine else NOT_CHECKED,
        "engine": engine,
    }


def out(row: SigmaRule, *, whole: bool = False) -> dict[str, Any]:
    shown = {
        "id": row.id,
        "name": row.name,
        "title": row.title,
        "author": row.author,
        "kind": row.kind,
        "level": row.level,
        "levelName": LEVEL_NAMES.get(row.level, ""),
        "status": row.status,
        "product": row.product,
        "category": row.category,
        "service": row.service,
        "tags": list(row.tags or []),
        "enabled": bool(row.enabled),
        "supported": bool(row.supported),
        "reason": row.reason,
        "checked": bool(row.engine),
        "pack": row.pack,
        "edited": edited(row),
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }
    if whole:
        shown["source"] = row.source
        shown["original"] = row.original
        shown["engine"] = row.engine
    return shown


# --------------------------------------------------------------------------- #
# Listing                                                                      #
# --------------------------------------------------------------------------- #
def _like(text: str) -> str:
    return "%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"


def filtered(f: dict[str, Any]) -> list[Any]:
    """The conditions of a filter, by the names the API gives: ``q``, ``pack`` (``-`` for the rules
    written here), ``level`` (the lowest), ``status``, ``enabled``, ``supported``, ``product``,
    ``category``, ``service``, ``kind``."""
    row = SigmaRule
    where: list[Any] = []
    if f.get("q"):
        like = _like(str(f["q"]).lower())
        where.append(
            or_(*(func.lower(column).like(like, escape="\\") for column in (row.title, row.id, row.name, row.author)))
        )
    if f.get("pack") not in (None, ""):
        where.append(row.pack == ("" if f["pack"] == "-" else f["pack"]))
    if f.get("level") is not None:
        where.append(row.level >= f["level"])
    for name, column in (
        ("status", row.status),
        ("product", row.product),
        ("category", row.category),
        ("service", row.service),
        ("kind", row.kind),
    ):
        if f.get(name) not in (None, ""):
            where.append(column == f[name])
    for name, column in (("enabled", row.enabled), ("supported", row.supported)):
        if f.get(name) is not None:
            where.append(column.is_(bool(f[name])))
    return where


def _order(order: str) -> list[Any]:
    row = SigmaRule
    if order == "-level":
        return [row.level.desc(), func.lower(row.title), row.id]
    if order == "level":
        return [row.level, func.lower(row.title), row.id]
    if order == "-updated":
        return [row.updated_at.desc(), row.id]
    return [func.lower(row.title), row.id]


def listing(db: OrmSession, f: dict[str, Any], limit: int, offset: int, order: str) -> dict[str, Any]:
    """One page of rules without their text: ``{"rules", "total", "limit", "offset"}``."""
    if order not in ORDERS:
        raise SigmaError("order is one of " + ", ".join(ORDERS))
    where = filtered(f)
    total = db.scalar(select(func.count()).select_from(SigmaRule).where(*where)) or 0
    found = db.scalars(select(SigmaRule).where(*where).order_by(*_order(order)).limit(limit).offset(offset))
    return {
        "rules": [out(row) for row in found],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def get(db: OrmSession, rule_id: str) -> SigmaRule:
    row = db.get(SigmaRule, rule_id)
    if row is None:
        raise SigmaError("Rule not found", 404)
    return row


def summary(db: OrmSession) -> dict[str, Any]:
    """What the screen of rules shows above the list: counts, and the packs the rules come from."""
    row = SigmaRule
    count = func.count()
    on = func.sum(case((row.enabled.is_(True), 1), else_=0))
    packs = db.execute(select(row.pack, count, on).group_by(row.pack)).all()
    names = {pack.id: pack.name for pack in db.scalars(select(Pack))}
    levels = dict(db.execute(select(row.level, count).group_by(row.level)).all())
    products = db.execute(select(row.product, count).group_by(row.product)).all()
    return {
        "total": sum(n for _pack, n, _on in packs),
        "enabled": int(sum(held or 0 for _pack, _n, held in packs)),
        "supported": db.scalar(select(count).where(row.supported.is_(True))) or 0,
        "unchecked": db.scalar(select(count).where(row.engine == "")) or 0,
        "engine": setting(db, "engine", ""),
        "byLevel": {str(number): int(levels.get(number, 0)) for number in range(1, 6)},
        "products": {product: n for product, n in products},
        "packs": [
            {
                "id": pack,
                "name": names.get(pack) or (pack or "Written here"),
                "total": n,
                "enabled": int(held or 0),
            }
            for pack, n, held in sorted(packs, key=lambda item: (item[0] != NIK, item[0] == "", item[0]))
        ],
    }


# --------------------------------------------------------------------------- #
# Writing                                                                      #
# --------------------------------------------------------------------------- #
def check_id(rule_id: str) -> None:
    if not rule_id or len(rule_id) > ID_MAX or not re.fullmatch(r"[A-Za-z0-9._:-]+", rule_id):
        raise SigmaError(f"The id of a rule is 1 to {ID_MAX} letters, digits and . _ : - (a UUID, as a rule has it)")


def default_enabled(info: dict[str, Any], engine: str, pack: str) -> bool:
    """Whether a rule is switched on when it arrives (see the module's text)."""
    known = bool(info.get("supported", True)) or not engine
    if pack and pack != NIK:
        return known and str(info.get("status") or "") in PACK_STATUS and level_of(info.get("level")) >= PACK_LEVEL
    return known


def add(
    db: OrmSession,
    info: dict[str, Any],
    engine: str,
    actor: str,
    *,
    pack: str = "",
    enabled: bool | None = None,
) -> SigmaRule:
    """Store a rule that is not here (the caller commits)."""
    check_id(str(info.get("id") or ""))
    cols = columns(info, engine)
    known = cols["supported"] or not engine
    wanted = default_enabled(info, engine, pack) if enabled is None else bool(enabled) and known
    now = now_iso()
    row = SigmaRule(
        id=str(info["id"]),
        pack=pack,
        enabled=wanted,
        created_at=now,
        created_by=actor[:200],
        updated_at=now,
        updated_by=(marker(pack) if pack else actor)[:200],
        **cols,
    )
    db.add(row)
    bump(db)
    return row


def replace(
    db: OrmSession,
    row: SigmaRule,
    info: dict[str, Any],
    engine: str,
    actor: str,
    enabled: bool | None = None,
) -> None:
    """Put another text in a rule, written by ``actor`` (the caller commits). A rule of a pack keeps what
    the pack said, to go back to; written back as the pack says it, it is the pack's again."""
    cols = columns(info, engine)
    who = actor[:200]
    if row.pack:
        pack_text = row.original if edited(row) else row.source
        if pack_text is not None and cols["source"].strip() == pack_text.strip():
            row.original, who = None, marker(row.pack)
        else:
            row.original = pack_text
    for key, value in cols.items():
        setattr(row, key, value)
    row.updated_at, row.updated_by = now_iso(), who
    if enabled is not None:
        row.enabled = bool(enabled) and (row.supported or not engine)
    elif engine and not row.supported:
        row.enabled = False
    bump(db)


def set_enabled(row: SigmaRule, enabled: bool) -> None:
    if enabled and not row.supported:
        raise SigmaError(f"Nik cannot run this rule: {row.reason or 'it is not supported'}", 409)
    row.enabled = enabled


def switch(db: OrmSession, enabled: bool, ids: list[str] | None, f: dict[str, Any] | None) -> dict[str, int]:
    """Switch many rules on or off, by their ids or by a filter: ``{"matched", "changed"}``. Switching
    on leaves out the rules Nik cannot run. Nothing else of a rule changes, so a rule of a pack stays
    the pack's."""
    row = SigmaRule
    matched = changed = 0
    if ids is not None:
        groups = [[row.id.in_(ids[i : i + CHUNK])] for i in range(0, len(ids), CHUNK)]
    else:
        groups = [filtered(f or {})]
    for where in groups:
        if enabled:
            where = [*where, row.supported.is_(True)]
        matched += db.scalar(select(func.count()).select_from(row).where(*where)) or 0
        result = db.execute(update(row).where(*where, row.enabled.is_(not enabled)).values(enabled=enabled))
        changed += result.rowcount or 0
    if changed:
        bump(db)
    return {"matched": matched, "changed": changed}


def remove(db: OrmSession, row: SigmaRule) -> None:
    if row.pack:
        raise SigmaError(
            "A rule of a pack is switched off, not deleted: it would come back with the pack",
            409,
        )
    db.delete(row)
    bump(db)


def describe(f: dict[str, Any]) -> str:
    """A filter in words, for the audit log."""
    parts = [f"{key}={f[key]}" for key in FILTERS if f.get(key) not in (None, "")]
    return ", ".join(parts) or "every rule"
