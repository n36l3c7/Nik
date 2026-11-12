"""The IoC library: every indicator, lists, bulk add, bulk check, export, feed.

See ``app/ioc_library.py`` for what the library is. Anyone signed in (or a
key with the write scope) adds indicators, makes lists and starts checks;
removing somebody else's list takes an admin.
"""

from __future__ import annotations

import base64
import re
import uuid
from typing import Any, Literal

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, Request, status
from fastapi.responses import Response
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import delete, func, select, update
from sqlalchemy.orm import Session as OrmSession

from .. import ioc_library as lib
from ..core.db import get_db
from ..core.models import ApiKey, AuditEntry, Incident, IocAlert, IocCheck, IocEntry, IocList, IocListItem, IocRecord
from ..core.security import (
    Principal,
    _key_expired,
    hash_api_key,
    normalize_scopes,
    now_iso,
    principal,
    writer_principal,
)
from ..enrichment import service
from ..iocs import TYPES, normalize
from .settings import read_settings

router = APIRouter(prefix="/iocs", tags=["ioc library"])

Type = Literal["ip", "domain", "url", "email", "md5", "sha1", "sha256"]
Tlp = Literal["clear", "green", "amber", "red"]
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _audit(db: OrmSession, caller: Principal, action: str, details: str, target: str | None = None) -> None:
    db.add(
        AuditEntry(
            id=str(uuid.uuid4()), at=now_iso(), actor=caller.actor, action=action, target=target, details=details
        )
    )


# --------------------------------------------------------------------------- #
# Bodies                                                                      #
# --------------------------------------------------------------------------- #
class ItemIn(BaseModel):
    type: Type | None = None
    value: str = Field(min_length=1, max_length=1024)
    tags: list[str] = Field(default_factory=list, max_length=lib.TAGS_MAX)
    note: str = Field(default="", max_length=lib.NOTE_MAX)
    tlp: Tlp | None = None
    expires: str | None = None


class ListRef(BaseModel):
    """An existing list (``id``) or one to make (``name``)."""

    id: str | None = None
    name: str | None = Field(default=None, max_length=120)
    description: str = Field(default="", max_length=500)
    tlp: Tlp | None = None
    watch: bool = False


class AddIn(BaseModel):
    items: list[ItemIn] = Field(default_factory=list, max_length=lib.MAX_BATCH)
    text: str | None = Field(default=None, max_length=lib.MAX_TEXT)
    tags: list[str] = Field(default_factory=list, max_length=lib.TAGS_MAX)
    note: str = Field(default="", max_length=lib.NOTE_MAX)
    tlp: Tlp | None = None
    expires: str | None = None
    model_config = ConfigDict(populate_by_name=True)
    into: ListRef | None = Field(default=None, alias="list")
    check: bool = False
    origin: Literal["manual", "import"] = "manual"


class ParseIn(BaseModel):
    text: str = Field(max_length=lib.MAX_TEXT)


class PairIn(BaseModel):
    type: Type
    value: str = Field(min_length=1, max_length=1024)


class Filters(BaseModel):
    q: str = ""
    type: Type | None = None
    verdict: Literal["malicious", "suspicious", "harmless", "unknown", "none", "flagged"] | None = None
    origin: Literal["incident", "manual", "import", "artifact", "added"] | None = None
    analysis: Literal["done", "none"] | None = None
    model_config = ConfigDict(populate_by_name=True)
    list_id: str | None = Field(default=None, alias="list")
    expired: bool | None = None


class Scope(BaseModel):
    """Which indicators an action is about: the ones named, a list, an
    incident, or everything a filter keeps."""

    items: list[PairIn] | None = Field(default=None, max_length=lib.MAX_BATCH)
    model_config = ConfigDict(populate_by_name=True)
    list_id: str | None = Field(default=None, alias="list")
    incident: str | None = None
    filters: Filters | None = None


class EditIn(PairIn):
    tags: list[str] | None = Field(default=None, max_length=lib.TAGS_MAX)
    note: str | None = Field(default=None, max_length=lib.NOTE_MAX)
    tlp: Tlp | None = None
    expires: str | None = None
    clearExpires: bool = False


class ListIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    tlp: Tlp = "amber"
    watch: bool = False
    scope: Scope | None = None


class ListPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = Field(default=None, max_length=500)
    tlp: Tlp | None = None
    watch: bool | None = None


class ExportIn(BaseModel):
    scope: Scope
    format: Literal["csv", "json", "stix", "misp", "txt"] = "csv"
    fields: list[str] = Field(default_factory=list, max_length=len(lib.FIELDS))
    defang: bool = False
    flaggedOnly: bool = False
    allowlisted: bool = False
    expired: bool = False
    preview: bool = False


class CheckIn(BaseModel):
    scope: Scope
    force: bool = False
    dryRun: bool = False


# --------------------------------------------------------------------------- #
# Helpers                                                                     #
# --------------------------------------------------------------------------- #
def _list_or_404(db: OrmSession, list_id: str) -> IocList:
    row = db.get(IocList, list_id)
    if row is None:
        raise HTTPException(status_code=404, detail="List not found")
    return row


def _pairs(items: list[PairIn]) -> list[lib.Pair]:
    pairs = []
    for item in items:
        value = normalize(item.type, item.value)
        if value is None:
            raise HTTPException(status_code=422, detail=f"Not a valid {item.type}: {item.value[:80]}")
        pairs.append((item.type, value))
    return list(dict.fromkeys(pairs))


def _resolve(db: OrmSession, scope: Scope, shared: dict) -> tuple[list[dict[str, Any]], str]:
    """The library rows a scope names, and a label for them."""
    if scope.items is not None:
        pairs = _pairs(scope.items)
        rows = lib.library(db, shared, only=set(pairs))
        order = {pair: index for index, pair in enumerate(pairs)}
        rows.sort(key=lambda r: order.get((r["type"], r["value"]), 0))
        return rows, f"{len(rows)} selected"
    if scope.list_id:
        target = _list_or_404(db, scope.list_id)
        pairs = set(
            db.execute(select(IocListItem.type, IocListItem.value).where(IocListItem.list_id == target.id)).tuples()
        )
        return lib.select_rows(lib.library(db, shared, only=pairs), {}), target.name
    if scope.incident:
        incident = db.get(Incident, scope.incident)
        if incident is None:
            raise HTTPException(status_code=404, detail="Incident not found")
        pairs = set(
            db.execute(select(IocEntry.type, IocEntry.value).where(IocEntry.incident_id == incident.id)).tuples()
        )
        return lib.select_rows(lib.library(db, shared, only=pairs), {}), str((incident.doc or {}).get("name") or "")
    filters = (scope.filters or Filters()).model_dump(by_alias=True)
    return lib.select_rows(lib.library(db, shared), filters), "indicators"


def _list_out(row: IocList, count: int = 0, flagged: int = 0) -> dict[str, Any]:
    return {
        "id": row.id,
        "name": row.name,
        "description": row.description,
        "tlp": row.tlp,
        "watch": row.watch,
        "count": count,
        "flagged": flagged,
        "createdAt": row.created_at,
        "createdBy": row.created_by,
        "updatedAt": row.updated_at,
    }


def _dates(*values: str | None) -> list[str | None]:
    try:
        return [lib.clean_date(value) for value in values]
    except ValueError:
        raise HTTPException(status_code=422, detail="The date must be YYYY-MM-DD.") from None


# --------------------------------------------------------------------------- #
# The library                                                                 #
# --------------------------------------------------------------------------- #
@router.get("")
def list_library(
    q: str = Query("", max_length=200),
    type: Type | None = Query(None),
    verdict: Literal["malicious", "suspicious", "harmless", "unknown", "none", "flagged"] | None = Query(None),
    origin: Literal["incident", "manual", "import", "artifact", "added"] | None = Query(None),
    analysis: Literal["done", "none"] | None = Query(None, description="Analysed by Nik, or still to analyse"),
    list_id: str | None = Query(None, alias="list"),
    expired: bool | None = Query(None),
    sort: str = Query("", max_length=20),
    dir: Literal["asc", "desc"] = Query("asc"),
    offset: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    _caller: Principal = Depends(principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Every indicator Nik knows: seen in an incident, added by hand, imported
    or kept in a list. ``counts`` are for the whole library, ``total`` for
    the filter."""
    rows = lib.library(db, read_settings(db))
    filters = {
        "q": q,
        "type": type,
        "verdict": verdict,
        "origin": origin,
        "list": list_id,
        "expired": expired,
        "analysis": analysis,
    }
    kept = lib.select_rows(rows, filters, sort, dir == "desc")
    return {
        "iocs": kept[offset : offset + limit],
        "total": len(kept),
        "counts": lib.counts(rows),
        "alerts": db.scalar(select(func.count()).select_from(IocAlert).where(IocAlert.seen.is_(False))) or 0,
    }


@router.post("/parse")
def parse_text(body: ParseIn, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Read a paste or a file without saving anything: the indicators found,
    which are new, which the library already has and which are never sent to
    the sources."""
    parsed = lib.parse(body.text)
    pairs = [(item["type"], item["value"]) for item in parsed["items"]]
    known = lib.known_pairs(db, pairs)
    shared = read_settings(db)
    allowlist = lib.Allowlist(shared.get("iocAllowlist") or [])
    types: dict[str, int] = {}
    never = 0
    for item in parsed["items"]:
        pair = (item["type"], item["value"])
        item["known"] = pair in known
        item["neverSent"] = bool(lib.never_sent(pair[0], pair[1], allowlist, item.get("tlp") == "red"))
        never += item["neverSent"]
        types[pair[0]] = types.get(pair[0], 0) + 1
    return {
        **parsed,
        "summary": {
            "new": len(pairs) - len(known),
            "known": len(known),
            "repeated": parsed["repeated"],
            "neverSent": never,
            "unrecognised": len(parsed["unrecognised"]),
            "types": types,
        },
    }


@router.post("", status_code=status.HTTP_201_CREATED)
def add_indicators(
    body: AddIn,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Add one indicator or many. Each is saved on its own; ``list`` also puts
    them in a list (an indicator the library already has is put in the list
    too, and stays in the ones it was in). ``check`` starts a bulk check."""
    items: list[dict[str, Any]] = []
    for item in body.items:
        found = (item.type, item.value) if item.type else lib.detect(item.value)
        clean = normalize(found[0], lib.refang(found[1])) if found else None
        if not found or clean is None:
            raise HTTPException(status_code=422, detail=f"Not an indicator: {item.value[:80]}")
        (expires,) = _dates(item.expires)
        items.append(
            {
                "type": found[0],
                "value": clean,
                "tags": item.tags,
                "note": item.note,
                "tlp": item.tlp,
                "expires": expires,
            }
        )
    lists: list[str] = []
    if body.text:
        parsed = lib.parse(body.text)
        items += parsed["items"]
        lists = sorted({name for item in parsed["items"] for name in item.get("lists") or []})
    if not items:
        raise HTTPException(status_code=422, detail="No indicator found.")
    (expires,) = _dates(body.expires)
    now = now_iso()
    result = lib.save_items(
        db, items, caller.actor, now, origin=body.origin, tags=body.tags, note=body.note, tlp=body.tlp, expires=expires
    )
    pairs = list(dict.fromkeys((item["type"], item["value"]) for item in items))
    target = None
    if body.into and (body.into.id or (body.into.name or "").strip()):
        target = (
            _list_or_404(db, body.into.id)
            if body.into.id
            else lib.list_named(
                db,
                body.into.name or "",
                caller.actor,
                now,
                description=body.into.description,
                tlp=body.into.tlp or body.tlp,
                watch=body.into.watch,
            )
        )
        result["listed"] = lib.add_to_list(db, target, pairs, caller.actor, now)
    # A Nik export names the lists each indicator was in: they come back.
    for name in lists:
        named = lib.list_named(db, name, caller.actor, now)
        lib.add_to_list(
            db, named, [(i["type"], i["value"]) for i in items if name in (i.get("lists") or [])], caller.actor, now
        )
    check = None
    if body.check:
        db.flush()
        plan = service.plan_check(db, pairs, read_settings(db))
        check = service.start_check(db, plan, target.name if target else f"{len(pairs)} added", caller.actor)
    _audit(
        db,
        caller,
        "ioc.add",
        f"Added {result['added']} indicator(s), {result['existing']} already known"
        + (f', list "{target.name}"' if target else ""),
        target=target.name if target else (pairs[0][1] if len(pairs) == 1 else None),
    )
    db.commit()
    return {
        **result,
        "list": _list_out(target) if target else None,
        "check": service.check_progress(db, check) if check else None,
    }


@router.patch("/item")
def edit_indicator(
    body: EditIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Tags, note, TLP and expiry of an indicator. One seen only in incidents
    gets a record to hold them."""
    value = normalize(body.type, body.value)
    if value is None:
        raise HTTPException(status_code=422, detail=f"Not a valid {body.type}.")
    if not lib.known_pairs(db, [(body.type, value)]):
        raise HTTPException(status_code=404, detail="Indicator not in the library")
    now = now_iso()
    record = db.get(IocRecord, (body.type, value))
    if record is None:
        record = IocRecord(type=body.type, value=value, origin="manual", tags=[], created_at=now, updated_at=now)
        record.created_by = caller.actor
        db.add(record)
    if body.tags is not None:
        record.tags = lib.clean_tags(body.tags)
    if body.note is not None:
        record.note = body.note
    if body.tlp is not None:
        record.tlp = body.tlp
    if body.clearExpires:
        record.expires_at = None
    elif body.expires is not None:
        (record.expires_at,) = _dates(body.expires)
    record.updated_at = now
    db.commit()
    return lib.library(db, read_settings(db), only={(body.type, value)})[0]


@router.post("/remove")
def remove_indicators(
    scope: Scope, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Take indicators out of the library: their record and their place in
    every list. One an incident still holds stays, as part of that incident."""
    rows, _ = _resolve(db, scope, read_settings(db))
    removed = kept = 0
    for row in rows:
        db.execute(delete(IocRecord).where(IocRecord.type == row["type"], IocRecord.value == row["value"]))
        db.execute(delete(IocListItem).where(IocListItem.type == row["type"], IocListItem.value == row["value"]))
        if row["incidents"] or row.get("artifacts"):
            kept += 1
        else:
            removed += 1
    _audit(
        db,
        caller,
        "ioc.remove",
        f"Removed {removed} indicator(s); {kept} stay because an incident or an artifact holds them",
    )
    db.commit()
    return {"removed": removed, "kept": kept}


# --------------------------------------------------------------------------- #
# Lists                                                                       #
# --------------------------------------------------------------------------- #
@router.get("/lists")
def lists(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    sizes = dict(db.execute(select(IocListItem.list_id, func.count()).group_by(IocListItem.list_id)).all())
    rows = db.scalars(select(IocList).order_by(func.lower(IocList.name))).all()
    return {"lists": [_list_out(row, sizes.get(row.id, 0)) for row in rows]}


@router.post("/lists", status_code=status.HTTP_201_CREATED)
def create_list(body: ListIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Make a list, optionally from a scope (a selection, an incident's
    indicators, a filter)."""
    name = body.name.strip()
    if not name:
        raise HTTPException(status_code=422, detail="The list needs a name.")
    if db.scalar(select(IocList.id).where(func.lower(IocList.name) == name.lower())):
        raise HTTPException(status_code=409, detail="A list with this name exists already.")
    now = now_iso()
    target = lib.list_named(db, name, caller.actor, now, description=body.description, tlp=body.tlp, watch=body.watch)
    count = 0
    if body.scope is not None:
        rows, _ = _resolve(db, body.scope, read_settings(db))
        count = lib.add_to_list(db, target, [(r["type"], r["value"]) for r in rows], caller.actor, now)
    _audit(db, caller, "ioc.list.create", f"List with {count} indicator(s)", target=name)
    db.commit()
    return _list_out(target, count)


@router.get("/lists/{list_id}")
def get_list(list_id: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    target = _list_or_404(db, list_id)
    rows, _ = _resolve(db, Scope(list_id=list_id), read_settings(db))
    return {**_list_out(target, len(rows)), "counts": lib.counts(rows)}


@router.patch("/lists/{list_id}")
def edit_list(
    list_id: str, body: ListPatch, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    target = _list_or_404(db, list_id)
    if body.name is not None and body.name.strip().lower() != target.name.lower():
        if db.scalar(select(IocList.id).where(func.lower(IocList.name) == body.name.strip().lower())):
            raise HTTPException(status_code=409, detail="A list with this name exists already.")
    for field in ("name", "description", "tlp", "watch"):
        value = getattr(body, field)
        if value is not None:
            setattr(target, field, value.strip() if isinstance(value, str) else value)
    target.updated_at = now_iso()
    _audit(db, caller, "ioc.list.update", "List changed", target=target.name)
    db.commit()
    size = db.scalar(select(func.count()).select_from(IocListItem).where(IocListItem.list_id == list_id)) or 0
    return _list_out(target, size)


@router.delete("/lists/{list_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_list(
    list_id: str, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Remove the list; its indicators stay in the library. Its author or an admin."""
    target = _list_or_404(db, list_id)
    if caller.role != "admin" and target.created_by != caller.actor:
        raise HTTPException(status_code=403, detail="Only the list's author or an admin can remove it.")
    db.execute(delete(IocListItem).where(IocListItem.list_id == list_id))
    db.execute(delete(IocAlert).where(IocAlert.list_id == list_id))
    _audit(db, caller, "ioc.list.delete", "List removed", target=target.name)
    db.delete(target)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/lists/{list_id}/items")
def add_list_items(
    list_id: str, scope: Scope, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    target = _list_or_404(db, list_id)
    rows, _ = _resolve(db, scope, read_settings(db))
    if scope.items is not None:
        # Indicators named one by one may be new to the library.
        pairs = _pairs(scope.items)
    else:
        pairs = [(r["type"], r["value"]) for r in rows]
    added = lib.add_to_list(db, target, pairs, caller.actor, now_iso())
    db.commit()
    return {"added": added}


@router.post("/lists/{list_id}/items/remove")
def remove_list_items(
    list_id: str, scope: Scope, _caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Take indicators out of the list; they stay in the library."""
    target = _list_or_404(db, list_id)
    removed = 0
    for kind, value in _pairs(scope.items or []):
        removed += db.execute(
            delete(IocListItem).where(
                IocListItem.list_id == target.id, IocListItem.type == kind, IocListItem.value == value
            )
        ).rowcount
    target.updated_at = now_iso()
    db.commit()
    return {"removed": removed}


def _feed_caller(request: Request, db: OrmSession = Depends(get_db)) -> Principal:
    """A feed is read by machines: besides the session and ``X-API-Key``, the
    key is taken as the password of HTTP Basic, which is all some firewalls
    can send."""
    header = request.headers.get("Authorization") or ""
    if header.lower().startswith("basic ") and not request.headers.get("X-API-Key"):
        try:
            secret = base64.b64decode(header[6:]).decode("utf-8").split(":", 1)[1]
        except (ValueError, IndexError, UnicodeDecodeError):
            secret = ""
        row = db.scalar(select(ApiKey).where(ApiKey.key_hash == hash_api_key(secret), ApiKey.revoked_at.is_(None)))
        if secret and row is not None and not _key_expired(row):
            row.last_used_at = now_iso()
            db.commit()
            role = row.role if row.role in {"admin", "analyst"} else "analyst"
            return Principal(
                kind="apikey",
                actor=f"api:{row.label}",
                role=role,
                scopes=normalize_scopes((row.scopes or "").split(","), role),
            )
        raise HTTPException(status_code=401, detail="Not authenticated", headers={"WWW-Authenticate": "Basic"})
    return principal(db, request.cookies.get("nik_session"), request.headers.get("X-API-Key"))


@router.get("/lists/{list_id}/feed")
def feed(
    list_id: str,
    format: Literal["txt", "csv", "json", "stix", "misp"] = Query("txt"),
    types: str | None = Query(None, description="Comma-separated types to keep, e.g. ip,domain"),
    flagged: bool = Query(False, description="Only malicious and suspicious"),
    _caller: Principal = Depends(_feed_caller),
    db: OrmSession = Depends(get_db),
) -> Response:
    """The list as it is now, for a firewall, a SIEM or a SOAR to poll.
    Allowlisted and expired indicators are left out. A TLP:RED list has no feed."""
    target = _list_or_404(db, list_id)
    if target.tlp == "red":
        raise HTTPException(status_code=403, detail="A TLP:RED list is not published as a feed.")
    rows, _ = _resolve(db, Scope(list_id=list_id), read_settings(db))
    wanted = {t.strip() for t in (types or "").split(",") if t.strip() in TYPES} or set(TYPES)
    rows = [
        row
        for row in rows
        if row["type"] in wanted
        and not row["allowlisted"]
        and not row["expired"]
        and row["tlp"] != "red"
        and (not flagged or row["verdict"] in ("malicious", "suspicious"))
    ]
    body, media, _ext = lib.export(db, rows, format, lib.DEFAULT_FIELDS, title=target.name, now=now_iso())
    return Response(content=body, media_type=media, headers={"Cache-Control": "no-store"})


# --------------------------------------------------------------------------- #
# Export                                                                      #
# --------------------------------------------------------------------------- #
@router.post("/export")
def export_indicators(
    body: ExportIn, caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Download a list, a selection or a filter in the chosen format with the
    chosen fields. Allowlisted and expired indicators are left out unless asked for."""
    rows, label = _resolve(db, body.scope, read_settings(db))
    rows = [
        row
        for row in rows
        if (body.allowlisted or not row["allowlisted"])
        and (body.expired or not row["expired"])
        and (not body.flaggedOnly or row["verdict"] in ("malicious", "suspicious"))
    ]
    now = now_iso()
    if body.preview:
        # The first rows, to show what the choice gives: not a download, not audited.
        content, media, _ = lib.export(
            db, rows[:5], body.format, body.fields, title=label, now=now, defanged=body.defang
        )
        return Response(content=content, media_type=media, headers={"X-Nik-Count": str(len(rows))})
    content, media, ext = lib.export(db, rows, body.format, body.fields, title=label, now=now, defanged=body.defang)
    base = _SAFE_NAME.sub("-", label.lower()).strip("-") or "indicators"
    _audit(db, caller, "ioc.export", f"Exported {len(rows)} indicators as {body.format.upper()}", target=label)
    db.commit()
    return Response(
        content=content,
        media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{base}.{ext}"', "X-Nik-Count": str(len(rows))},
    )


# --------------------------------------------------------------------------- #
# Bulk check                                                                  #
# --------------------------------------------------------------------------- #
def _plan_out(plan: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in plan.items() if key not in ("pending", "items")}


@router.post("/check")
def bulk_check(body: CheckIn, caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Ask the sources about many indicators. ``dryRun`` only says what it
    would cost against each source's quota; otherwise the check is queued and
    worked through in the background (poll ``/iocs/checks/{id}``)."""
    shared = read_settings(db)
    rows, label = _resolve(db, body.scope, shared)
    if len(rows) > service.MAX_CHECK_ITEMS:
        raise HTTPException(status_code=422, detail=f"At most {service.MAX_CHECK_ITEMS} indicators in one check.")
    plan = service.plan_check(db, [(r["type"], r["value"]) for r in rows], shared, force=body.force)
    if body.dryRun:
        return {"plan": _plan_out(plan), "label": label, "check": None}
    check = service.start_check(db, plan, label, caller.actor)
    _audit(db, caller, "ioc.check", f"Bulk check of {plan['toAsk']} indicator(s)", target=label)
    db.commit()
    return {"plan": _plan_out(plan), "label": label, "check": service.check_progress(db, check)}


@router.get("/checks")
def checks(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """The bulk checks still going, and the last few that ended."""
    rows = db.scalars(select(IocCheck).order_by(IocCheck.created_at.desc()).limit(20)).all()
    return {"checks": [service.check_progress(db, row) for row in rows]}


@router.get("/checks/{check_id}")
def get_check(check_id: str, _caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    row = db.get(IocCheck, check_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Check not found")
    return service.check_progress(db, row)


@router.post("/checks/{check_id}/stop")
def stop_check(check_id: str, _caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)) -> dict:
    row = db.get(IocCheck, check_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Check not found")
    if row.status in ("running", "waiting"):
        row.status, row.message, row.updated_at = "stopped", "Stopped.", now_iso()
        db.commit()
    return service.check_progress(db, row)


# --------------------------------------------------------------------------- #
# Analyse many addresses                                                      #
# --------------------------------------------------------------------------- #
ANALYSE_MAX = 20


class AnalyseIn(BaseModel):
    scope: Scope
    dryRun: bool = False


@router.post("/analyse")
def analyse_addresses(
    body: AnalyseIn,
    background_tasks: BackgroundTasks,
    caller: Principal = Depends(writer_principal),
    db: OrmSession = Depends(get_db),
) -> dict:
    """Have the isolated browser visit the URLs and domains of a scope that
    Nik has not analysed yet, one after the other (20 at most; a domain is
    visited as ``https://<domain>/``). A visit is seen by the site, so this is
    only done when asked: ``dryRun`` says what would be visited and what is
    left out, and why."""
    from .. import urlscan
    from . import urls as url_routes

    rows, label = _resolve(db, body.scope, read_settings(db))
    visit: list[tuple[dict[str, Any], str]] = []
    skipped: list[dict[str, str]] = []
    for row in rows:
        if row["type"] not in ("url", "domain"):
            skipped.append({"value": row["value"], "reason": "not an address"})
        elif row.get("analysis"):
            skipped.append({"value": row["value"], "reason": "analysed already"})
        elif row["allowlisted"]:
            skipped.append({"value": row["value"], "reason": "on the allowlist"})
        elif row["tlp"] == "red":
            skipped.append({"value": row["value"], "reason": "classified TLP:RED"})
        else:
            try:
                visit.append((row, urlscan.normalise(row["value"])))
            except urlscan.UrlError:
                # Said in fixed words: the text of an exception is not sent to the client.
                skipped.append(
                    {"value": row["value"], "reason": "cannot be visited (not http or https, or an internal host)"}
                )
    if len(visit) > ANALYSE_MAX:
        raise HTTPException(
            status_code=422,
            detail=f"{len(visit)} addresses would be visited: at most {ANALYSE_MAX} at a time. Select fewer.",
        )
    if body.dryRun:
        return {"visit": [url for _, url in visit], "skipped": skipped, "max": ANALYSE_MAX, "started": []}
    started = []
    for _row, url in visit:
        scan = urlscan.register(db, url, caller.actor)
        url_routes._queue(db, scan, caller.actor, background_tasks)
        started.append({"url": url, "artifactId": f"url-{scan.id}"})
    _audit(db, caller, "ioc.analyse", f"Started the analysis of {len(started)} address(es)", target=label)
    db.commit()
    return {"visit": [url for _, url in visit], "skipped": skipped, "max": ANALYSE_MAX, "started": started}


# --------------------------------------------------------------------------- #
# Alerts                                                                      #
# --------------------------------------------------------------------------- #
@router.get("/alerts")
def alerts(_caller: Principal = Depends(principal), db: OrmSession = Depends(get_db)) -> dict:
    """Incidents that came to hold an indicator of a watched list, newest first."""
    rows = db.execute(
        select(IocAlert, IocList.name, Incident.name)
        .join(IocList, IocList.id == IocAlert.list_id)
        .join(Incident, Incident.id == IocAlert.incident_id)
        .order_by(IocAlert.at.desc())
        .limit(200)
    ).all()
    return {
        "alerts": [
            {
                "id": alert.id,
                "at": alert.at,
                "type": alert.type,
                "value": alert.value,
                "seen": alert.seen,
                "list": {"id": alert.list_id, "name": list_name},
                "incident": {"id": alert.incident_id, "name": incident_name},
            }
            for alert, list_name, incident_name in rows
        ]
    }


@router.post("/alerts/seen")
def alerts_seen(_caller: Principal = Depends(writer_principal), db: OrmSession = Depends(get_db)) -> dict:
    changed = db.execute(update(IocAlert).where(IocAlert.seen.is_(False)).values(seen=True)).rowcount
    db.commit()
    return {"seen": changed}
