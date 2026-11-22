"""Content packs over the API (``content.manage``).

- ``GET /packs``: the packs that are installed, each with the items that came from it.
- ``POST /packs/inspect`` (a ``.nikpack`` file): what applying it would do, item by item,
  and a ``token`` that stands for the file for an hour.
- ``POST /packs/import {token, choices}``: apply it, all or nothing.
- ``GET /packs/items``: what there is to put in a pack; ``POST /packs/dependencies`` says what a
  choice of items brings with it; ``POST /packs/export`` makes the file.
- ``GET /packs/catalogue``: the packs there are to install, as last read; ``POST
  /packs/catalogue/refresh`` reads them again; ``POST /packs/catalogue/{id}/inspect`` takes one from
  the catalogue and answers like ``/packs/inspect``; ``PUT /packs/catalogue/address`` (admin) sets
  where the catalogue is.
- ``GET /packs/{id}/uninstall``: what uninstalling would remove and what it would keep, and what is in
  use and holds the pack; ``DELETE /packs/{id}?remove=true`` does it, unless the pack is held (409 with
  what holds it). Without ``remove`` the pack is only taken off the list.
- ``POST /packs/bulk/plan {action, packs}`` and ``POST /packs/bulk/apply``: several packs at once
  (``app/pack_bulk.py``): what would happen to each, then each done on its own.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session as OrmSession

from .. import pack_bulk as bulk
from .. import pack_catalogue as catalogue
from .. import packs
from ..core import audit
from ..core.db import get_db
from ..core.models import Pack
from ..core.permissions import CONTENT_MANAGE
from ..core.security import Principal, admin_principal, require

router = APIRouter(prefix="/packs", tags=["content packs"])
CATALOGUE_MARK = bulk.CATALOGUE_MARK
content_principal = require(CONTENT_MANAGE)


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


class AddressIn(BaseModel):
    # Both empty: the catalogue of the repository of Nik, and its key.
    address: str = Field(default="", max_length=500)
    key: str = Field(default="", max_length=100)


class BulkPackIn(BaseModel):
    id: str = Field(min_length=2, max_length=49)
    # What the plan answered for a pack to install: the file that was looked at.
    token: str = Field(default="", max_length=100)


class BulkIn(BaseModel):
    action: str = Field(max_length=20)
    packs: list[BulkPackIn] = Field(min_length=1, max_length=bulk.MAX_PACKS)


def _refuse(error: packs.PackError | catalogue.CatalogueError) -> HTTPException:
    if isinstance(error, packs.PackHeld):
        # Said as a sentence and as the list: the page shows each thing with what to do first.
        return HTTPException(status_code=error.status, detail={"message": error.message, "held": error.held})
    return HTTPException(status_code=error.status, detail=error.message)


def _chosen(body: ChosenIn) -> list[tuple[str, str]]:
    for item in body.items:
        if item.kind not in packs.KINDS:
            raise HTTPException(status_code=400, detail=f"Nik has no items of kind {item.kind}")
    return [(item.kind, item.name) for item in body.items]


@router.get("")
def list_packs(_caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The packs that are installed (Nik's own first), each with its items and whether each is still here."""
    return {"packs": [packs.out(db, row) for row in packs.installed(db)]}


@router.get("/items")
def list_items(_caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)) -> dict:
    """What there is to put in a pack, by kind: ``{kinds: [{kind, label, items: [{name, label, builtin}]}]}``."""
    return {
        "kinds": [{"kind": kind, "label": packs.LABELS[kind], "items": packs.names(db, kind)} for kind in packs.KINDS]
    }


@router.post("/dependencies")
def dependencies(
    body: ChosenIn, _caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
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
    body: ExportIn, caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
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


@router.get("/catalogue")
def read_catalogue(_caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)) -> dict:
    """The catalogue as it was last read: ``{address, custom, fetchedAt, error, read, packs: [{id, name,
    vendor, category, tags, version, description, contents, connectors, logo, installed, update,
    needsNik}]}``. Nothing
    goes out: ``refresh`` does."""
    return catalogue.shown(db)


@router.post("/catalogue/refresh")
def refresh_catalogue(_caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Read the catalogue again from its address. ``502`` with why when it cannot be read or its
    signature is not the one of the key Nik holds: what was read before stays."""
    try:
        return catalogue.refresh(db)
    except catalogue.CatalogueError as error:
        raise _refuse(error) from None


@router.put("/catalogue/address")
def set_catalogue(
    body: AddressIn, caller: Principal = Depends(admin_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Set where the catalogue is read from, and the public key it is signed with (admin). Both empty:
    the one of Nik. What was read before is forgotten."""
    try:
        place = catalogue.set_where(db, body.address, body.key)
    except catalogue.CatalogueError as error:
        raise _refuse(error) from None
    audit.record(
        db, caller.actor, "pack.catalogue",
        f"Set the catalogue of packs to {place['address']}" + (" with a key of its own" if place["ownKey"] else ""),
        target="catalogue",
    )  # fmt: skip
    db.commit()
    return catalogue.shown(db)


@router.get("/catalogue/{pack_id}/logo")
def catalogue_logo(
    pack_id: str, _caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
) -> Response:
    """The logo the catalogue gives for a pack (it came inside the signed index)."""
    try:
        logo = catalogue.entry_of(db, pack_id).get("logo")
    except catalogue.CatalogueError as error:
        raise _refuse(error) from None
    if not logo:
        raise HTTPException(status_code=404, detail="This pack has no logo")
    return Response(
        content=base64.b64decode(logo["data"]),
        media_type=logo["type"],
        headers={"Cache-Control": "private, max-age=300", "Content-Security-Policy": "default-src 'none'; sandbox"},
    )


@router.post("/catalogue/{pack_id}/inspect")
def inspect_from_catalogue(
    pack_id: str, caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Take a pack from the catalogue (its size and SHA-256 are checked against the signed index) and say
    what applying it would do, like ``/packs/inspect``. Nothing is changed."""
    try:
        data = catalogue.download(db, pack_id)
        pack = packs.read(data)
        if pack.manifest["id"] != pack_id:
            raise packs.PackError("The file of this pack is the file of another pack", 502)
        found = packs.plan(db, pack)
    except (packs.PackError, catalogue.CatalogueError) as error:
        raise _refuse(error) from None
    token = packs.keep_upload(db, data, f"{CATALOGUE_MARK}{pack_id}.nikpack", caller.actor)
    db.commit()
    return {"token": token, **found}


@router.post("/inspect")
async def inspect_pack(
    file: UploadFile = File(...), caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
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
    body: ImportIn, caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """Apply an inspected pack, in one transaction: ``{pack, added, updated, same, skipped}``. An item
    that conflicts must be skipped (``choices``) or settled first: otherwise nothing is applied (409)."""
    try:
        upload = packs.take_upload(db, body.token, caller.actor)
        pack = packs.read(upload.data)
        source = "catalogue" if upload.file_name.startswith(CATALOGUE_MARK) else "file"
        done = packs.apply(db, pack, body.choices, caller.actor, source=source)
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
    pack_id: str, _caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
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
        data = packs.write(
            row.manifest or {"id": row.id, "name": row.name, "version": row.version}, items, logo=row.logo
        )
    except packs.PackError as error:
        raise _refuse(error) from None
    return Response(
        content=data,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{row.id}-{row.version}.nikpack"'},
    )


@router.get("/{pack_id}/logo")
def pack_logo(
    pack_id: str, _caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
) -> Response:
    row = db.get(Pack, pack_id)
    if row is None or not row.logo:
        raise HTTPException(status_code=404, detail="This pack has no logo")
    return Response(
        content=row.logo,
        media_type=row.logo_type,
        headers={"Cache-Control": "private, max-age=300", "Content-Security-Policy": "default-src 'none'; sandbox"},
    )


@router.post("/bulk/plan")
def bulk_plan(body: BulkIn, caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)) -> dict:
    """What installing, updating or uninstalling several packs would do (``action``; ``packs: [{id}]``),
    in the order they would be done: ``{action, packs: [{id, name, version, installed, ok, why, counts,
    items, token? | held?}]}``. ``ok`` is false, with ``why``, for one that would be left out. To install
    or update, each pack is taken from the catalogue and kept: its ``token`` is given back to apply it.
    Nothing else is changed."""
    ids = [entry.id for entry in body.packs]
    if body.action == "uninstall":
        return {"action": body.action, "packs": bulk.plan_uninstall(db, ids)}
    if body.action not in bulk.ACTIONS:
        raise HTTPException(status_code=400, detail="The action is install, update or uninstall")
    found = bulk.plan_install(db, body.action, ids, caller.actor)
    db.commit()
    return {"action": body.action, "packs": found}


@router.post("/bulk/apply")
def bulk_apply(body: BulkIn, caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)) -> dict:
    """Do it: the packs one after the other, each in its own transaction, a pack after the ones it
    requires (before them, to uninstall). ``{action, packs: [{id, name, ok, why, …}]}``: one that failed
    says why (``held`` lists what uses a pack that was not uninstalled), and undoes none of the others."""
    if body.action == "uninstall":
        return {
            "action": body.action,
            "packs": bulk.apply_uninstall(db, [entry.id for entry in body.packs], caller.actor),
        }
    if body.action not in bulk.ACTIONS:
        raise HTTPException(status_code=400, detail="The action is install, update or uninstall")
    chosen = [{"id": entry.id, "token": entry.token} for entry in body.packs]
    return {"action": body.action, "packs": bulk.apply_install(db, body.action, chosen, caller.actor)}


@router.get("/{pack_id}/uninstall")
def uninstall_plan(
    pack_id: str, _caller: Principal = Depends(content_principal), db: OrmSession = Depends(get_db)
) -> dict:
    """What uninstalling the pack would do: ``{items: [{kind, name, label, action: remove | keep | gone,
    why}], held: [{kind, name, label, what, todo}]}``. ``held`` is what is in use, each with what to do
    first: while it is not empty the pack is not uninstalled."""
    row = db.get(Pack, pack_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Pack not found")
    try:
        return packs.uninstall_plan(db, row)
    except packs.PackError as error:
        raise _refuse(error) from None


@router.delete("/{pack_id}", response_model=None)
def remove_pack(
    pack_id: str,
    remove: bool = False,
    caller: Principal = Depends(content_principal),
    db: OrmSession = Depends(get_db),
) -> Response | dict:
    """Without ``remove``: take the pack off the list (``204``); what it brought stays, and is no pack's
    any more. With ``remove``: uninstall it. What it gave is deleted, except what was changed here, which
    stays and is no pack's any more. Answers ``{removed, kept}``. A pack of which something is in use (an
    instance of its connector, a playbook that is on…) is not uninstalled: ``409`` with ``detail:
    {message, held}``."""
    row = db.get(Pack, pack_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Pack not found")
    name = row.name
    try:
        if not remove:
            packs.forget(db, row)
            audit.record(db, caller.actor, "pack.forget", f'Took the pack "{name}" off the list', target=pack_id)
            db.commit()
            return Response(status_code=status.HTTP_204_NO_CONTENT)
        done = packs.uninstall(db, row)
    except packs.PackError as error:
        db.rollback()
        raise _refuse(error) from None
    audit.record(
        db, caller.actor, "pack.uninstall",
        f'Uninstalled the pack "{name}": {len(done["removed"])} removed, {len(done["kept"])} kept',
        target=pack_id,
    )  # fmt: skip
    db.commit()
    return done
