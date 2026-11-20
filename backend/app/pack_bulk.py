"""Several content packs at once: installed, updated or uninstalled in one go.

Doing it to several is doing it to each, in an order: a pack is installed
after the packs it requires and uninstalled before them. It is two steps, as
for one pack. ``plan`` says what would happen to each and leaves out, with
why, the ones it cannot do: a pack with an item in conflict (that one is
installed on its own, where each item can be left out), one whose requirements
are missing, one that is in use. ``apply`` then does them one after the other,
**each in its own transaction**: a pack that fails does not undo the ones
before it, and stops only the ones that require it. Every pack is judged again
when its turn comes, against what is there by then.

A pack taken from the catalogue for the plan is kept, like an inspected file
(``packs.keep_upload``), and its ``token`` is what is applied: what was shown
is what is installed, and the catalogue is not asked twice.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as OrmSession

from . import pack_catalogue as catalogue
from . import packs
from .core import audit
from .core.models import Pack

MAX_PACKS = 100
ACTIONS = ("install", "update", "uninstall")
UNINSTALLED = ("remove", "keep", "gone")  # what happens to an item of a pack that is uninstalled
CATALOGUE_MARK = "catalogue:"  # how the file of an inspection says it came from the catalogue
ALONE = "install it on its own to leave them out"


def _line(pack_id: str, row: Pack | None, manifest: dict[str, Any] | None = None) -> dict[str, Any]:
    """One pack of a plan or of a result, before what is found of it."""
    shown = manifest or {}
    return {
        "id": pack_id,
        "name": shown.get("name") or (row.name if row is not None else pack_id),
        "version": shown.get("version") or (row.version if row is not None else ""),
        "installed": row.version if row is not None else None,
        "ok": False,
        "why": "",
    }


def _not_for(action: str, row: Pack | None, manifest: dict[str, Any]) -> str:
    """Why a pack is not one to install, or to update; "" when it is."""
    if action == "install" and row is not None:
        return f"Version {row.version} is installed already"
    if action == "update":
        if row is None:
            return "It is not installed"
        if (packs.version_of(manifest["version"]) or (0, 0, 0)) <= (packs.version_of(row.version) or (0, 0, 0)):
            return f"Version {row.version} is installed: this one is not newer"
    return ""


def _conflicts(found: dict[str, Any]) -> str:
    count = found["counts"]["conflict"]
    return f"{count} of its items {'is' if count == 1 else 'are'} in conflict: {ALONE}" if count else ""


def _unique(ids: list[str]) -> list[str]:
    return list(dict.fromkeys(ids))


# --------------------------------------------------------------------------- #
# Installing and updating                                                     #
# --------------------------------------------------------------------------- #
def plan_install(db: OrmSession, action: str, ids: list[str], actor: str) -> list[dict[str, Any]]:
    """What installing (or updating) each pack from the catalogue would do, in the order they would be
    applied. The caller commits: the files taken are kept for ``apply_install``."""
    lines: dict[str, dict[str, Any]] = {}
    files: dict[str, packs.PackFile] = {}
    for pack_id in _unique(ids):
        line = lines[pack_id] = _line(pack_id, db.get(Pack, pack_id))
        try:
            data = catalogue.download(db, pack_id)
            pack = packs.read(data)
            if pack.manifest["id"] != pack_id:
                raise packs.PackError("The file of this pack is the file of another pack", 502)
        except (packs.PackError, catalogue.CatalogueError) as error:
            line["why"] = error.message
            continue
        line.update(name=pack.manifest["name"], version=pack.manifest["version"])
        line["token"] = packs.keep_upload(db, data, f"{CATALOGUE_MARK}{pack_id}.nikpack", actor)
        files[pack_id] = pack
    needs = {pack_id: [need["pack"] for need in pack.manifest["requires"]] for pack_id, pack in files.items()}
    order = packs.in_order(needs, {pack_id: line["name"] for pack_id, line in lines.items()})
    coming = packs.Coming()
    for pack_id in order:
        line, pack = lines[pack_id], files[pack_id]
        found = packs.plan(db, pack, coming)
        line.update(
            counts=found["counts"],
            items=[
                {key: entry[key] for key in ("kind", "name", "label", "action", "why") if key in entry}
                for entry in found["items"]
            ],
        )
        line["why"] = (
            _not_for(action, db.get(Pack, pack_id), pack.manifest)
            or (found["problems"][0] if found["problems"] else "")
            or _conflicts(found)
        )
        line["ok"] = not line["why"]
        if line["ok"]:
            coming.add(pack)
    return [lines[pack_id] for pack_id in order] + [line for pack_id, line in lines.items() if pack_id not in files]


def apply_install(db: OrmSession, action: str, chosen: list[dict[str, str]], actor: str) -> list[dict[str, Any]]:
    """Install the packs a plan kept (``[{id, token}]``), one after the other, each committed on its own.
    Answers, for each: ``{id, name, version, ok, why, added, updated, same}``."""
    lines: dict[str, dict[str, Any]] = {}
    files: dict[str, tuple[packs.PackFile, Any]] = {}
    for entry in chosen:
        pack_id = entry["id"]
        if pack_id in lines:
            continue
        line = lines[pack_id] = _line(pack_id, db.get(Pack, pack_id))
        try:
            upload = packs.take_upload(db, entry.get("token") or "", actor)
            pack = packs.read(upload.data)
            if pack.manifest["id"] != pack_id or not upload.file_name.startswith(CATALOGUE_MARK):
                raise packs.PackError("This is not the pack that was looked at: choose the packs again", 409)
        except packs.PackError as error:
            line["why"] = error.message
            continue
        line.update(name=pack.manifest["name"], version=pack.manifest["version"])
        files[pack_id] = (pack, upload)
    needs = {pack_id: [need["pack"] for need in pack.manifest["requires"]] for pack_id, (pack, _) in files.items()}
    order = packs.in_order(needs, {pack_id: line["name"] for pack_id, line in lines.items()})
    for pack_id in order:
        line, (pack, upload) = lines[pack_id], files[pack_id]
        try:
            # Judged again now: the packs before it are in, or are not.
            found = packs.plan(db, pack)
            why = _not_for(action, db.get(Pack, pack_id), pack.manifest) or _conflicts(found)
            if why:
                raise packs.PackError(why, 409)
            done = packs.apply(db, pack, {}, actor, source="catalogue")
            db.delete(upload)
            audit.record(
                db, actor, "pack.import",
                f'Installed the pack "{line["name"]}" {line["version"]}: {done["added"]} added, '
                f'{done["updated"]} updated, {done["skipped"]} skipped',
                target=pack_id,
            )  # fmt: skip
            db.commit()
        except packs.PackError as error:
            db.rollback()
            line["why"] = error.message
            continue
        line.update(ok=True, added=done["added"], updated=done["updated"], same=done["same"])
    return [lines[pack_id] for pack_id in order] + [line for pack_id, line in lines.items() if pack_id not in files]


# --------------------------------------------------------------------------- #
# Uninstalling                                                                #
# --------------------------------------------------------------------------- #
def _installed(db: OrmSession, ids: list[str]) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """The lines of the packs asked for, and the ids of the ones that are installed, in the order to
    uninstall them: a pack before the packs it requires."""
    lines: dict[str, dict[str, Any]] = {}
    needs: dict[str, list[str]] = {}
    for pack_id in _unique(ids):
        row = db.get(Pack, pack_id)
        lines[pack_id] = _line(pack_id, row)
        if row is None:
            lines[pack_id]["why"] = "It is not installed"
        else:
            needs[pack_id] = [str(need.get("pack")) for need in (row.manifest or {}).get("requires") or []]
    order = packs.in_order(needs, {pack_id: line["name"] for pack_id, line in lines.items()}, reverse=True)
    return lines, order


def plan_uninstall(db: OrmSession, ids: list[str]) -> list[dict[str, Any]]:
    """What uninstalling each pack would do, in the order they would go. Nothing is written."""
    lines, order = _installed(db, ids)
    leaving = packs.Leaving()
    for pack_id in order:
        line = lines[pack_id]
        try:
            found = packs.uninstall_plan(db, db.get(Pack, pack_id), leaving)
        except packs.PackError as error:
            line["why"] = error.message
            continue
        counts = {action: sum(1 for entry in found["items"] if entry["action"] == action) for action in UNINSTALLED}
        line.update(items=found["items"], held=found["held"], counts=counts)
        if found["held"]:
            line["why"] = "It is in use"
        else:
            line["ok"] = True
            leaving.add(pack_id, found["items"])
    return [lines[pack_id] for pack_id in order] + [line for pack_id, line in lines.items() if pack_id not in order]


def apply_uninstall(db: OrmSession, ids: list[str], actor: str) -> list[dict[str, Any]]:
    """Uninstall the packs, one after the other, each committed on its own. Answers, for each:
    ``{id, name, ok, why, held?, removed, kept}`` (the last two as numbers)."""
    lines, order = _installed(db, ids)
    for pack_id in order:
        line = lines[pack_id]
        try:
            done = packs.uninstall(db, db.get(Pack, pack_id))
            audit.record(
                db, actor, "pack.uninstall",
                f'Uninstalled the pack "{line["name"]}": {len(done["removed"])} removed, {len(done["kept"])} kept',
                target=pack_id,
            )  # fmt: skip
            db.commit()
        except packs.PackHeld as error:
            db.rollback()
            line.update(why="It is in use", held=error.held)
            continue
        except packs.PackError as error:
            db.rollback()
            line["why"] = error.message
            continue
        line.update(ok=True, removed=len(done["removed"]), kept=len(done["kept"]))
    return [lines[pack_id] for pack_id in order] + [line for pack_id, line in lines.items() if pack_id not in order]
