"""Content packs over the API (``content.manage``).

- ``GET /packs``: the packs that are installed, each with the items that came from it.
- ``POST /packs/inspect`` (a ``.nikpack`` file): what applying it would do, item by item,
  and a ``token`` that stands for the file for an hour.
- ``POST /packs/import {token, choices}``: apply it, all or nothing.
- ``GET /packs/items``: what there is to put in a pack; ``POST /packs/dependencies`` says what a
  choice of items brings with it; ``POST /packs/export`` makes the file.
"""

from __future__ import annotations

import re
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import packs
from ..core import audit
from ..core.db import get_db
from ..core.models import Pack
from ..core.permissions import CONTENT_MANAGE
from ..core.security import Principal, require

router = APIRouter(prefix="/packs", tags=["content packs"])
manage_principal = require(CONTENT_MANAGE)


class ItemIn(BaseModel):
    kind: str = Field(max_length=40)
    name: str = Field(min_length=1, max_length=200)


class ChosenIn(BaseModel):
    items: list[ItemIn] = Field(default_factory=list, max_length=500)


class ExportIn(ChosenIn):
    id: str = Field(max_length=49)
    name: str = Field(max_length=120)
    version: str = Field(default="1.0.0", max_length=20)
    description: str = Field(default="", max_length=2000)
    author: str = Field(default="", max_length=200)
    requires: list[dict[str, Any]] = Field(default_factory=list, max_length=50)
    # Lists go with what they hold only when asked: their items are often the data of one company.
    listItems: bool = False


class ImportIn(BaseModel):
    token: str = Field(min_length=10, max_length=100)
    # "kind/name" → "skip", for the items to leave out. Everything else the plan can do is done.
    choices: dict[str, str] = Field(default_factory=dict)


def _refuse(error: packs.PackError) -> HTTPException:
    return HTTPException(status_code=error.status, detail=error.message)


def _chosen(body: ChosenIn) -> list[tuple[str, str]]:
    for item in body.items:
        if item.kind not in packs.KINDS:
            raise HTTPException(status_code=400, detail=f"Nik has no items of kind {item.kind}")
    return [(item.kind, item.name) for item in body.items]


@router.get("")
def list_packs(_caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The packs that are installed (Nik's own first), each with its items and whether each is still here."""
    return {"packs": [packs.out(db, row) for row in packs.installed(db)]}


@router.get("/items")
def list_items(_caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)) -> dict:
    """What there is to put in a pack, by kind: ``{kinds: [{kind, label, items: [{name, label, builtin}]}]}``."""
    return {
        "kinds": [{"kind": kind, "label": packs.LABELS[kind], "items": packs.names(db, kind)} for kind in packs.KINDS]
    }


@router.post("/dependencies")
def dependencies(
    body: ChosenIn, _caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """The items chosen and what they cannot do without: the scripts and connectors of a playbook, the
    fields of a type… ``asked`` is false for what was added."""
    found = packs.closure(db, _chosen(body))
    return {
        "items": [
            {"kind": kind, "name": name, "label": packs.LABELS[kind], "asked": asked} for kind, name, asked in found
        ]
    }


@router.post("/export")
def export_pack(
    body: ExportIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """A ``.nikpack`` file of the items chosen and of what they need. Never a connection or a secret."""
    try:
        manifest = packs.clean_manifest(body.model_dump(exclude={"items", "listItems"}))
        data = packs.export(db, manifest, _chosen(body), list_items=body.listItems)
    except packs.PackError as error:
        raise _refuse(error) from None
    audit.record(
        db, caller.actor, "pack.export", f'Exported the pack "{manifest["name"]}" {manifest["version"]}',
        target=manifest["id"],
    )  # fmt: skip
    db.commit()
    name = re.sub(r"[^a-z0-9.-]+", "-", f"{manifest['id']}-{manifest['version']}")
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{name}.nikpack"'},
    )


@router.post("/inspect")
async def inspect_pack(
    file: UploadFile = File(...), caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Read a pack and say what applying it would do: ``{token, pack, installed, problems, items: [{kind,
    name, action: add | update | same | conflict, diff?, why?, note?, from?}], counts}``. Nothing is changed."""
    data = await file.read(packs.MAX_BYTES + 1)
    try:
        pack = packs.read(data)
        found = packs.plan(db, pack)
    except packs.PackError as error:
        raise _refuse(error) from None
    token = packs.keep_upload(db, data, file.filename or "pack.nikpack", caller.actor)
    db.commit()
    return {"token": token, **found}


@router.post("/import")
def import_pack(
    body: ImportIn, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Apply an inspected pack, in one transaction: ``{pack, added, updated, same, skipped}``. An item
    that conflicts must be skipped (``choices``) or settled first: otherwise nothing is applied (409)."""
    try:
        upload = packs.take_upload(db, body.token, caller.actor)
        pack = packs.read(upload.data)
        done = packs.apply(db, pack, body.choices, caller.actor)
    except packs.PackError as error:
        db.rollback()
        raise _refuse(error) from None
    db.delete(upload)
    manifest = done["pack"]
    audit.record(
        db, caller.actor, "pack.import",
        f'Installed the pack "{manifest["name"]}" {manifest["version"]}: {done["added"]} added, '
        f'{done["updated"]} updated, {done["skipped"]} skipped',
        target=manifest["id"],
    )  # fmt: skip
    db.commit()
    return {**done, "installed": packs.out(db, db.get(Pack, manifest["id"]))}


@router.get("/{pack_id}/download")
def download_pack(
    pack_id: str, _caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """An installed pack as a file again, from what its items are now (lists without their items)."""
    row = db.get(Pack, pack_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Pack not found")
    shown = packs.out(db, row)
    chosen = [(item["kind"], item["name"]) for item in shown["items"] if item["there"]]
    try:
        items = [packs.Item(kind, name, packs.current(db, kind, name, with_items=False)) for kind, name in chosen]
        if not items:
            raise packs.PackError("Nothing of this pack is here any more", 409)
        data = packs.write(row.manifest or {"id": row.id, "name": row.name, "version": row.version}, items)
    except packs.PackError as error:
        raise _refuse(error) from None
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{row.id}-{row.version}.nikpack"'},
    )


@router.delete("/{pack_id}", status_code=status.HTTP_204_NO_CONTENT)
def forget_pack(
    pack_id: str, caller: Principal = Depends(manage_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """Take a pack off the list. What it brought stays, and is nobody's pack's any more."""
    row = db.get(Pack, pack_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Pack not found")
    try:
        packs.forget(db, row)
    except packs.PackError as error:
        raise _refuse(error) from None
    audit.record(db, caller.actor, "pack.forget", f'Took the pack "{row.name}" off the list', target=pack_id)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)
