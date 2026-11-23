"""Content packs: what Nik is taught, carried from one Nik to another as one file.

A pack is a ``.nikpack`` file: a zip with ``pack.yml`` (its id, name, version)
and a folder for each kind of item, one file an item::

    connectors/<id>.yml          the connector file, as it is
    scripts/<Name>.yml           name, description, code, arguments, outputs, test
    playbooks/<slug>.json        the graph of its current version and its limits
    fields/<name>.json           a custom field of incidents
    incident_types/<slug>.json   a type: its fields, layout, SLA, close reasons
    mappers/<connector>.json     incoming and outgoing rules, for every type and by type
    lists/<name>.json            a list, with its items when the pack carries them
    dashboards/<slug>.json       a dashboard
    preprocess_rules/<slug>.json a pre-processing rule

Never a connection, a credential, or what a playbook may reach and send:
those belong to the Nik they were set in.

An item is the same item in every Nik by its **name** (a connector by its
id): never by a database id. What an item refers to is named too (a type
names its fields and its playbook) and found again where the pack is
imported.

Importing is two steps. ``inspect`` reads the file and says, for each item,
what applying it would do: ``add``, ``update`` (with the difference),
``same``, or ``conflict`` (with why). ``apply`` does what was chosen, in one
transaction: all of it, or nothing. A playbook or a script that exists gets a
new version; its history is never rewritten.
"""

from __future__ import annotations

import copy
import difflib
import hashlib
import io
import json
import logging
import re
import secrets
import time
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import yaml
from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as OrmSession

from . import dashboards as boards
from . import fields as registry
from . import incident_types as types
from . import lists as named_lists
from . import mapping, preprocess
from .automation import catalog, connector_actions, connector_logo, graph, scripts
from .automation import engine as automation_engine
from .automation.connectors import ConnectorError
from .automation.connectors import load as load_connector
from .core import audit
from .core.models import (
    Connection,
    Connector,
    Dashboard,
    Field,
    Incident,
    IncidentType,
    NamedList,
    Pack,
    PackItem,
    PackUpload,
    Playbook,
    PlaybookVersion,
    PreprocessRule,
    Run,
    Script,
)
from .core.security import now_iso

logger = logging.getLogger("nik.packs")

MAX_BYTES = 20 * 1024 * 1024  # the file
MAX_UNPACKED = 100 * 1024 * 1024  # what it holds, unpacked
MAX_ENTRIES = 2000
MAX_ITEM = 5 * 1024 * 1024  # one item
UPLOAD_SECONDS = 3600  # how long an inspected file waits to be applied
DIFF_MAX = 8000

ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,48}$")
VERSION_RE = re.compile(r"^(\d{1,5})\.(\d{1,5})\.(\d{1,5})$")
# A tag says what the product is or what it is used on ("ticketing", "threat-intelligence", "url").
TAG_RE = re.compile(r"^[a-z][a-z0-9-]{1,29}$")
TAGS_MAX = 8
# The kinds, in the order they are applied: what others name comes first.
KINDS = (
    "fields",
    "lists",
    "scripts",
    "connectors",
    "playbooks",
    "incident_types",
    "mappers",
    "preprocess_rules",
    "dashboards",
)
LABELS = {
    "fields": "Field",
    "lists": "List",
    "scripts": "Script",
    "connectors": "Connector",
    "playbooks": "Playbook",
    "incident_types": "Incident type",
    "mappers": "Mapper",
    "preprocess_rules": "Pre-processing rule",
    "dashboards": "Dashboard",
}
YAML_KINDS = frozenset({"connectors", "scripts"})
NIK_VERSION = (6, 11, 0)
BUILTIN_ID = "nik"  # the one pack that is part of Nik
LOGO_NAMES = ("logo.svg", "logo.png")
CRLF, LF = bytes((13, 10)), bytes((10,))


class PackError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class Item:
    kind: str
    name: str
    data: Any  # the text of a connector; the parsed file of anything else
    # What a connector comes with beside its file: {"logo": bytes, "readme": str}.
    extras: dict[str, Any] = field(default_factory=dict)


@dataclass
class PackFile:
    manifest: dict[str, Any]
    items: list[Item] = field(default_factory=list)
    logo: bytes | None = None  # logo.svg or logo.png beside pack.yml: what the catalogue shows

    def has(self, kind: str, name: str) -> bool:
        return any(item.kind == kind and item.name.lower() == name.lower() for item in self.items)


# --------------------------------------------------------------------------- #
# The file                                                                    #
# --------------------------------------------------------------------------- #
def slug(text: str) -> str:
    found = re.sub(r"[^a-z0-9]+", "-", str(text).lower()).strip("-")
    return found[:60] or "item"


def version_of(text: Any) -> tuple[int, int, int] | None:
    found = VERSION_RE.match(str(text or "").strip())
    return (int(found.group(1)), int(found.group(2)), int(found.group(3))) if found else None


def clean_manifest(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PackError("pack.yml does not say what the pack is")
    pack_id = str(raw.get("id") or "").strip()
    if not ID_RE.match(pack_id):
        raise PackError("The id of a pack is a lower-case letter, then lower-case letters, digits or - (2 to 49)")
    name = str(raw.get("name") or "").strip()[:120]
    if not name:
        raise PackError("A pack needs a name")
    if version_of(raw.get("version")) is None:
        raise PackError("The version of a pack is three numbers: 1.0.0")
    requires = []
    for need in raw.get("requires") or []:
        if not isinstance(need, dict) or not ID_RE.match(str(need.get("pack") or "")):
            raise PackError('"requires" lists packs by their id: {pack: other-pack, version: 1.0.0}')
        if need.get("version") is not None and version_of(need.get("version")) is None:
            raise PackError(f'The version "{need.get("version")}" a pack requires is three numbers')
        requires.append({"pack": str(need["pack"]), "version": str(need.get("version") or "0.0.0")})
    tags = raw.get("tags") or []
    if not isinstance(tags, list) or not all(isinstance(tag, str) and TAG_RE.match(tag) for tag in tags):
        raise PackError('"tags" is a list of lower-case words (a letter, then letters, digits or -): [ticketing, itsm]')
    tags = list(dict.fromkeys(tags))
    if len(tags) > TAGS_MAX:
        raise PackError(f"A pack has {TAGS_MAX} tags at most")
    nik = str(raw.get("nik") or "").strip()
    if nik and not re.fullmatch(r">=\s*\d{1,3}\.\d{1,3}(\.\d{1,3})?", nik):
        raise PackError('"nik" says the oldest Nik the pack is for: ">=4.6"')
    return {
        "id": pack_id,
        "name": name,
        "vendor": str(raw.get("vendor") or "").strip()[:80],
        "category": str(raw.get("category") or "").strip()[:60],
        "version": str(raw["version"]).strip(),
        "description": str(raw.get("description") or "")[:2000],
        "author": str(raw.get("author") or "")[:200],
        "tags": tags,
        "requires": requires[:50],
        "nik": nik.replace(" ", ""),
    }


def _entry_path(info: zipfile.ZipInfo) -> PurePosixPath | None:
    """The path of an entry inside the pack, or None for one that is only a folder.
    Raises for a path that would leave the pack, and for a link."""
    name = info.filename
    if "\\" in name or name.startswith("/") or "\x00" in name or re.match(r"^[A-Za-z]:", name):
        raise PackError(f'The pack holds a path that is not allowed: "{name[:80]}"')
    if (info.external_attr >> 16) & 0o170000 == 0o120000:
        raise PackError(f'The pack holds a link, which is not allowed: "{name[:80]}"')
    path = PurePosixPath(name)
    if any(part in ("..", "") for part in path.parts) or path.is_absolute():
        raise PackError(f'The pack holds a path that is not allowed: "{name[:80]}"')
    return None if info.is_dir() else path


def _parse(kind: str, path: PurePosixPath, raw: bytes) -> Any:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise PackError(f"{path} is not text") from None
    if kind == "connectors":
        return text
    try:
        data = yaml.safe_load(text) if kind in YAML_KINDS else json.loads(text)
    except (yaml.YAMLError, ValueError):
        raise PackError(f"{path} cannot be read") from None
    if not isinstance(data, dict):
        raise PackError(f"{path} is not an item of a pack")
    return data


def read(data: bytes) -> PackFile:
    """A pack from the bytes of its file, checked as a file: nothing of it is applied here."""
    if len(data) > MAX_BYTES:
        raise PackError(f"A pack is {MAX_BYTES // (1024 * 1024)} MB at most", 413)
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, ValueError):
        raise PackError("This is not a content pack (a .nikpack file)") from None
    with archive:
        infos = archive.infolist()
        if len(infos) > MAX_ENTRIES:
            raise PackError(f"A pack holds {MAX_ENTRIES} files at most")
        if sum(info.file_size for info in infos) > MAX_UNPACKED:
            raise PackError("The pack is too large once unpacked")
        manifest = None
        logo = None
        items: list[Item] = []
        seen: set[tuple[str, str]] = set()
        # A connector kept as a folder: connectors/<id>/connector.yml, with a logo and a README beside it.
        beside: dict[str, dict[str, Any]] = {}
        for info in infos:
            path = _entry_path(info)
            if path is None:
                continue
            if info.file_size > MAX_ITEM:
                raise PackError(f"{path} is too large")
            if len(path.parts) == 3 and path.parts[0] == "connectors":
                folder, name = path.parts[1], path.parts[2]
                if name in ("connector.yml", "connector.yaml"):
                    text = _parse("connectors", path, archive.read(info))
                    found = _name_of("connectors", text, folder)
                    if ("connectors", found.lower()) in seen:
                        raise PackError(f'The pack holds the connector "{found}" twice')
                    seen.add(("connectors", found.lower()))
                    items.append(Item("connectors", found, text, beside.setdefault(folder, {})))
                elif connector_logo.by_name(name):
                    beside.setdefault(folder, {})["logo"] = archive.read(info)
                elif name.lower() == "readme.md":
                    beside.setdefault(folder, {})["readme"] = _parse("connectors", path, archive.read(info))
                else:
                    raise PackError(f'The pack holds something Nik does not know: "{path}"')
                continue
            if len(path.parts) == 1:
                if path.name in ("pack.yml", "pack.yaml"):
                    try:
                        manifest = clean_manifest(yaml.safe_load(archive.read(info).decode("utf-8")))
                    except (yaml.YAMLError, UnicodeDecodeError):
                        raise PackError("pack.yml cannot be read") from None
                elif path.name in LOGO_NAMES:
                    logo = archive.read(info)
                continue  # a README beside it is nobody's business
            kind = path.parts[0]
            if kind not in KINDS or len(path.parts) != 2:
                if kind in ("classifiers", "layouts"):
                    continue  # a classifier belongs to a connection, a layout to its type: neither travels alone
                raise PackError(f'The pack holds something Nik does not know: "{path}"')
            wanted = (".yml", ".yaml") if kind in YAML_KINDS else (".json",)
            if path.suffix not in wanted:
                raise PackError(f"{path} is not a {wanted[0]} file")
            parsed = _parse(kind, path, archive.read(info))
            name = _name_of(kind, parsed, path.stem)
            if (kind, name.lower()) in seen:
                raise PackError(f'The pack holds the {LABELS[kind].lower()} "{name}" twice')
            seen.add((kind, name.lower()))
            items.append(Item(kind, name, parsed))
    if manifest is None:
        raise PackError("This is not a content pack: it has no pack.yml")
    if logo is not None:
        try:
            connector_logo.clean(logo)
        except connector_logo.LogoError as error:
            raise PackError(f"The logo of the pack: {error.message}") from None
    for item in items:
        if item.extras.get("logo"):
            try:
                connector_logo.clean(item.extras["logo"])
            except connector_logo.LogoError as error:
                raise PackError(f'The logo of the connector "{item.name}": {error.message}') from None
    items.sort(key=lambda item: (KINDS.index(item.kind), item.name.lower()))
    return PackFile(manifest, items, logo)


def _name_of(kind: str, data: Any, stem: str) -> str:
    """What an item is called: its identity across every Nik."""
    if kind == "connectors":
        try:
            return load_connector(data).id
        except ConnectorError as error:
            first = error.problems[0].message if error.problems else "it cannot be read"
            raise PackError(f"connectors/{stem}: {first}") from None
    if kind == "mappers":
        return str(data.get("connector") or stem)
    if kind == "playbooks" and isinstance(data.get("playbook"), dict):
        data = data["playbook"]
    name = str(data.get("name") or "").strip()
    if not name:
        raise PackError(f"{kind}/{stem} has no name")
    return name[:120]


def folder_bytes(folder: Path) -> bytes:
    """A pack kept as a folder (``packs/<id>/`` of the repository, a folder of ``NIK_PACKS_DIR``) as the
    bytes of its file: the same folder always gives the same bytes. Nothing is checked here: ``read`` does."""
    held = io.BytesIO()
    with zipfile.ZipFile(held, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((item for item in folder.rglob("*") if item.is_file()), key=lambda item: item.as_posix()):
            relative = path.relative_to(folder).as_posix()
            if any(part.startswith(".") for part in relative.split("/")):
                continue
            info = zipfile.ZipInfo(relative, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            # Text is written with the line ends of a repository, whatever the machine that built it.
            data = path.read_bytes()
            archive.writestr(info, data if path.suffix == ".png" else data.replace(CRLF, LF))
    return held.getvalue()


class _Readable(yaml.SafeDumper):
    """YAML as a person writes it: a text of several lines (the code of a script) as a block."""


def _block(dumper: yaml.SafeDumper, value: str):
    lines = value.splitlines()
    plain = "\n" in value and all(line == line.rstrip() and "\t" not in line for line in lines)
    return dumper.represent_scalar("tag:yaml.org,2002:str", value, style="|" if plain else None)


_Readable.add_representer(str, _block)


def _text(kind: str, data: Any) -> str:
    """An item as the text of its file: what is written to a pack, and what two versions are compared by."""
    if kind == "connectors":
        return str(data)
    if kind in YAML_KINDS:
        return yaml.dump(data, Dumper=_Readable, sort_keys=False, allow_unicode=True, width=100)
    return json.dumps(data, indent=2, ensure_ascii=False, sort_keys=kind != "playbooks") + "\n"


def write(manifest: dict[str, Any], items: list[Item], logo: bytes | None = None) -> bytes:
    """The bytes of a pack. The same pack always gives the same bytes: entries are in order and undated."""
    held = io.BytesIO()
    shown = {key: value for key, value in clean_manifest(manifest).items() if value not in ("", [], None)}
    with zipfile.ZipFile(held, "w", zipfile.ZIP_DEFLATED) as archive:

        def put(path: str, text: str | bytes) -> None:
            info = zipfile.ZipInfo(path, date_time=(2026, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            archive.writestr(info, text if isinstance(text, bytes) else text.encode("utf-8"))

        put("pack.yml", yaml.safe_dump(shown, sort_keys=False, allow_unicode=True))
        if logo:
            cleaned, logo_kind = connector_logo.clean(logo)
            put(f"logo.{connector_logo.EXTENSIONS[logo_kind]}", cleaned)
        used: set[str] = set()
        for item in sorted(items, key=lambda entry: (KINDS.index(entry.kind), entry.name.lower())):
            stem = (
                item.name if item.kind in ("connectors", "scripts", "fields", "lists", "mappers") else slug(item.name)
            )
            base, counter = stem, 2
            while f"{item.kind}/{stem}".lower() in used:
                stem, counter = f"{base}-{counter}", counter + 1
            used.add(f"{item.kind}/{stem}".lower())
            logo, readme = item.extras.get("logo"), item.extras.get("readme")
            if item.kind == "connectors" and (logo or readme):
                # With what it comes with, a connector is a folder.
                put(f"connectors/{stem}/connector.yml", _text(item.kind, item.data))
                if logo:
                    cleaned, kind = connector_logo.clean(logo)
                    put(f"connectors/{stem}/logo.{connector_logo.EXTENSIONS[kind]}", cleaned)
                if readme:
                    put(f"connectors/{stem}/README.md", str(readme))
                continue
            put(f"{item.kind}/{stem}.{'yml' if item.kind in YAML_KINDS else 'json'}", _text(item.kind, item.data))
    return held.getvalue()


# --------------------------------------------------------------------------- #
# Each kind: what is here, as a pack writes it                                #
# --------------------------------------------------------------------------- #
def _without_versions(shape: Any) -> Any:
    """A graph without the version numbers of its script nodes: a pack names a script, not a version of it."""
    shape = copy.deepcopy(shape) if isinstance(shape, dict) else {}
    for node in shape.get("nodes") or []:
        config = node.get("config") if isinstance(node, dict) else None
        if isinstance(config, dict) and node.get("kind") == "script":
            config.pop("script_version", None)
    return shape


def _playbook(db: OrmSession, name: str) -> Playbook | None:
    return db.scalars(select(Playbook).where(func.lower(Playbook.name) == name.lower())).first()


def _script(db: OrmSession, name: str) -> Script | None:
    return db.scalars(select(Script).where(func.lower(Script.name) == name.lower())).first()


def _type(db: OrmSession, name: str) -> IncidentType | None:
    types.every(db)
    return db.scalars(select(IncidentType).where(func.lower(IncidentType.name) == name.lower())).first()


def _dashboard(db: OrmSession, name: str) -> Dashboard | None:
    """The dashboard a pack means by a name: one that is shared (a pack's are), not somebody's own."""
    rows = db.scalars(select(Dashboard).where(func.lower(Dashboard.name) == name.lower())).all()
    return next((row for row in rows if row.builtin or boards.is_shared(row)), None)


def _rule(db: OrmSession, name: str) -> PreprocessRule | None:
    return db.scalars(select(PreprocessRule).where(func.lower(PreprocessRule.name) == name.lower())).first()


def _playbook_body(data: Any) -> dict[str, Any]:
    return data["playbook"] if isinstance(data.get("playbook"), dict) else data


def _layout_now(layout: Any) -> Any:
    """A stored layout without the widgets of a kind that is no more (the playbook buttons of 5.3, which 6.2
    replaced with script buttons): a type saved before then still holds them, and a pack made from it would
    carry what no Nik can read."""
    if not isinstance(layout, dict):
        return layout

    def kept(grid: Any) -> Any:
        if not isinstance(grid, list):
            return grid
        return [widget for widget in grid if not isinstance(widget, dict) or widget.get("kind") in types.GRID_KINDS]

    shown = dict(layout)
    if "grid" in shown:
        shown["grid"] = kept(shown["grid"])
    if isinstance(shown.get("pages"), list):
        shown["pages"] = [
            {**page, "grid": kept(page.get("grid"))} if isinstance(page, dict) else page for page in shown["pages"]
        ]
    return shown


def current(db: OrmSession, kind: str, name: str, *, with_items: bool = True) -> Any:
    """The item as it is in this Nik, in the shape a pack writes it; None when there is none."""
    if kind == "connectors":
        row = db.get(Connector, name)
        return row.source if row is not None else None
    if kind == "scripts":
        row = _script(db, name)
        if row is None:
            return None
        latest = scripts.current(db, row)
        source = (
            {"code": latest.code, "arguments": latest.arguments, "outputs": latest.outputs, "test": latest.test}
            if latest is not None
            else (row.draft or {})
        )
        return {
            "name": row.name,
            "description": row.description,
            "code": source.get("code", ""),
            "arguments": source.get("arguments", []),
            "outputs": source.get("outputs", []),
            "test": source.get("test", {}),
        }
    if kind == "playbooks":
        row = _playbook(db, name)
        if row is None:
            return None
        version = db.get(PlaybookVersion, (row.id, row.current_version)) if row.current_version else None
        return {
            "app": "Nik",
            "type": "playbook",
            "version": 1,
            "playbook": {
                "name": row.name,
                "description": row.description,
                "graph": _without_versions(version.graph if version else row.draft),
                "maxRunsPerHour": row.max_runs_per_hour,
                "onePerObject": bool(row.one_per_object),
                "maxSeconds": row.max_seconds,
                "approvalDefault": bool(row.approval_default),
            },
        }
    if kind == "fields":
        row = db.scalars(select(Field).where(Field.name == name)).first()
        if row is None or row.system:
            return None
        return {
            "name": row.name,
            "label": row.label,
            "description": row.description,
            "type": row.type,
            "options": row.options or {},
            "appliesTo": row.applies_to,
            "allTypes": bool(row.all_types),
        }
    if kind == "incident_types":
        row = _type(db, name)
        if row is None:
            return None
        shown = types.out(db, row)
        playbook = db.get(Playbook, row.default_playbook_id) if row.default_playbook_id else None
        return {
            "name": row.name,
            "description": row.description,
            "colour": row.colour,
            "icon": row.icon,
            "fields": shown["fields"],
            "layout": _layout_now(row.layout),
            "sla": shown["sla"],
            "closeReasons": shown["closeReasons"],
            "defaultPlaybook": playbook.name if playbook is not None else None,
            "autoRun": bool(row.auto_run) and playbook is not None,
            "visibleToRoles": row.visible_to_roles,
        }
    if kind == "mappers":
        rows = mapping.mappers_of(db, name)
        if not rows:
            return None
        names = {row.id: row.name for row in types.every(db)}
        shown: dict[str, Any] = {"connector": name, "incoming": [], "outgoing": [], "types": {}}
        for row in rows:
            if row.incident_type == mapping.ANY_TYPE:
                shown[row.direction] = row.rules or []
            elif row.incident_type in names:
                shown["types"].setdefault(names[row.incident_type], {})[row.direction] = row.rules or []
        return shown
    if kind == "lists":
        row = named_lists.find(db, name)
        if row is None:
            return None
        shown = named_lists.out(db, row, with_items=with_items)
        data = {
            "name": row.name,
            "label": shown["label"],
            "description": row.description,
            "kind": row.kind,
            "itemType": row.item_type,
            "writableByAutomation": bool(row.writable_by_automation),
        }
        if with_items:
            if row.kind == "json":
                data["document"] = shown["document"]
            else:
                data["entries"] = [
                    {key: entry[key] for key in ("key", "value", "note") if entry.get(key) not in (None, "")}
                    for entry in shown["entries"]
                ]
        return data
    if kind == "dashboards":
        row = _dashboard(db, name)
        return boards.exported(row) if row is not None else None
    if kind == "preprocess_rules":
        row = _rule(db, name)
        if row is None:
            return None
        shown = preprocess.out(row)
        return {key: shown[key] for key in ("name", "enabled", "when", "action", "params")}
    raise PackError(f"Nik has no items of kind {kind}")


def names(db: OrmSession, kind: str) -> list[dict[str, Any]]:
    """What there is of a kind to put in a pack: ``[{name, label, builtin}]``."""

    def rows(found, name=lambda row: row.name, label=lambda row: row.name, builtin=lambda row: bool(row.builtin)):
        return [{"name": name(row), "label": label(row), "builtin": builtin(row)} for row in found]

    if kind == "connectors":
        return rows(db.scalars(select(Connector).order_by(Connector.name)), name=lambda row: row.id)
    if kind == "scripts":
        return rows(db.scalars(select(Script).order_by(Script.name)))
    if kind == "playbooks":
        return rows(db.scalars(select(Playbook).order_by(Playbook.name)))
    if kind == "fields":
        found = db.scalars(select(Field).where(Field.system.is_(False)).order_by(Field.name))
        return rows(found, label=lambda row: row.label or row.name, builtin=lambda row: False)
    if kind == "incident_types":
        return rows(sorted(types.every(db), key=lambda row: row.name.lower()))
    if kind == "mappers":
        ids = sorted({row.connector_id for row in mapping.mappers_of(db)})
        known = {row.id: row for row in db.scalars(select(Connector)).all()}
        return [{"name": name, "label": known[name].name if name in known else name, "builtin": False} for name in ids]
    if kind == "lists":
        found = db.scalars(select(NamedList).order_by(NamedList.name))
        return rows(found, label=lambda row: row.label or row.name)
    if kind == "dashboards":
        found = [
            row for row in db.scalars(select(Dashboard).order_by(Dashboard.name)) if _dashboard(db, row.name) is row
        ]
        return rows(found)
    if kind == "preprocess_rules":
        return rows(preprocess.every(db), builtin=lambda row: False)
    raise PackError(f"Nik has no items of kind {kind}")


def needs(db: OrmSession, kind: str, name: str, data: Any = None) -> list[tuple[str, str]]:
    """What an item cannot do without: the scripts and connectors of a playbook, the fields of a type…"""
    data = current(db, kind, name, with_items=False) if data is None else data
    found: list[tuple[str, str]] = []
    if data is None:
        return found
    custom = {row.name for row in db.scalars(select(Field).where(Field.system.is_(False))).all()}
    if kind == "playbooks":
        connectors = {row.id for row in db.scalars(select(Connector)).all()}
        for node in (_playbook_body(data).get("graph") or {}).get("nodes") or []:
            config = node.get("config") if isinstance(node, dict) else None
            if not isinstance(config, dict):
                continue
            if node.get("kind") == "script" and config.get("script"):
                found.append(("scripts", str(config["script"])))
            head = str(config.get("action") or "").split(".")[0]
            if node.get("kind") == "action" and head in connectors:
                found.append(("connectors", head))
            if node.get("kind") == "playbook" and config.get("playbook"):
                other = db.get(Playbook, str(config["playbook"])) or _playbook(db, str(config["playbook"]))
                if other is not None:
                    found.append(("playbooks", other.name))
            if str(config.get("action") or "").startswith("list.") and isinstance(config.get("args"), dict):
                listed = str(config["args"].get("list") or "")
                if listed and "{{" not in listed and named_lists.find(db, listed) is not None:
                    found.append(("lists", listed))
    elif kind == "incident_types":
        found += [("fields", item["name"]) for item in data.get("fields") or [] if item.get("name") in custom]
        if data.get("defaultPlaybook"):
            found.append(("playbooks", str(data["defaultPlaybook"])))
    elif kind == "mappers":
        found.append(("connectors", str(data.get("connector") or name)))
        groups = [data, *(data.get("types") or {}).values()]
        for rules in (group.get("incoming") or [] for group in groups if isinstance(group, dict)):
            found += [("fields", rule["to"]) for rule in rules if isinstance(rule, dict) and rule.get("to") in custom]
        found += [("incident_types", str(type_name)) for type_name in data.get("types") or {}]
    elif kind == "preprocess_rules":
        script = str((data.get("params") or {}).get("script") or "")
        if script:
            found.append(("scripts", script))
    return list(dict.fromkeys(found))


def closure(db: OrmSession, chosen: list[tuple[str, str]]) -> list[tuple[str, str, bool]]:
    """The items chosen and everything they cannot do without: ``(kind, name, asked for)``."""
    asked = list(dict.fromkeys(chosen))
    seen: dict[tuple[str, str], bool] = {item: True for item in asked}
    waiting = list(asked)
    while waiting:
        kind, name = waiting.pop()
        for need in needs(db, kind, name):
            if need not in seen and current(db, need[0], need[1], with_items=False) is not None:
                seen[need] = False
                waiting.append(need)
    return sorted(
        ((kind, name, wanted) for (kind, name), wanted in seen.items()), key=lambda i: (KINDS.index(i[0]), i[1])
    )


def export(
    db: OrmSession, manifest: dict[str, Any], chosen: list[tuple[str, str]], *, list_items: bool = False
) -> bytes:
    """A pack of the items chosen and of what they need. Lists go without their items unless asked."""
    items = []
    for kind, name, _asked in closure(db, chosen):
        data = current(db, kind, name, with_items=list_items)
        if data is None:
            raise PackError(f'There is no {LABELS.get(kind, kind).lower()} "{name}" to put in a pack', 404)
        extras: dict[str, Any] = {}
        if kind == "connectors":
            row = db.get(Connector, name)
            if row is not None and row.logo:
                extras["logo"] = bytes(row.logo)
            if row is not None and row.readme:
                extras["readme"] = row.readme
        items.append(Item(kind, _name_of(kind, data, name), data, extras))
    if not items:
        raise PackError("A pack holds one item at least")
    return write(manifest, items)


# --------------------------------------------------------------------------- #
# The plan: what applying a pack would do                                     #
# --------------------------------------------------------------------------- #
def _comparable(kind: str, data: Any) -> Any:
    """An item without what does not make it another item: the envelope of a playbook, the items of a list
    a pack does not carry."""
    if kind == "connectors":
        return str(data).strip()
    data = copy.deepcopy(data)
    if kind == "playbooks":
        body = _playbook_body(data)
        return {
            "name": body.get("name"),
            "description": body.get("description") or "",
            "graph": _without_versions(body.get("graph")),
            "maxRunsPerHour": body.get("maxRunsPerHour") or 60,
            "onePerObject": bool(body.get("onePerObject", True)),
            "maxSeconds": body.get("maxSeconds") or 86400,
            "approvalDefault": bool(body.get("approvalDefault", True)),
        }
    if kind == "scripts":
        cleaned = scripts.clean(data)
        return {"description": str(data.get("description") or ""), **cleaned}
    if kind == "dashboards":
        try:
            widgets = boards.clean_widgets(data.get("widgets") or [])
        except boards.DashboardError:
            widgets = data.get("widgets")
        return {
            "name": data.get("name"),
            "description": data.get("description") or "",
            "timeRange": data.get("timeRange") or "30d",
            "refreshSeconds": data.get("refreshSeconds") or 0,
            "filter": data.get("filter") or "",
            "filterEntity": data.get("filterEntity") or "incidents",
            "widgets": widgets,
        }
    if kind == "mappers":
        return {
            "incoming": data.get("incoming") or [],
            "outgoing": data.get("outgoing") or [],
            "types": {key: value for key, value in (data.get("types") or {}).items() if value},
        }
    # What a file may leave out is what it would be given: two items that differ only by that are the same.
    if kind == "fields":
        return {
            "name": data.get("name"),
            "label": data.get("label") or data.get("name"),
            "description": data.get("description") or "",
            "type": data.get("type") or "text",
            "options": data.get("options") or {},
            "appliesTo": data.get("appliesTo") or "incident",
            "allTypes": bool(data.get("allTypes")),
        }
    if kind == "lists":
        shown = {
            "name": data.get("name"),
            "label": data.get("label") or data.get("name"),
            "description": data.get("description") or "",
            "kind": data.get("kind") or "values",
            "itemType": data.get("itemType") or "text",
            "writableByAutomation": bool(data.get("writableByAutomation")),
        }
        if "document" in data:
            shown["document"] = data["document"]
        if "entries" in data:
            entries = data["entries"] if isinstance(data["entries"], list) else []
            shown["entries"] = [
                {key: value for key, value in (entry if isinstance(entry, dict) else {"key": entry}).items()
                 if key in ("key", "value", "note") and value not in (None, "")}
                for entry in entries
            ]  # fmt: skip
        return shown
    if kind == "incident_types":
        return {
            "name": data.get("name"),
            "description": data.get("description") or "",
            "colour": data.get("colour") or "slate",
            "icon": data.get("icon") or "",
            "fields": [
                {
                    "name": entry.get("name"),
                    "required": bool(entry.get("required")),
                    "requiredOnClose": bool(entry.get("requiredOnClose")),
                }
                for entry in data.get("fields") or []
                if isinstance(entry, dict)
            ],  # fmt: skip
            "layout": data.get("layout") or None,
            "sla": data.get("sla") or [],
            "closeReasons": data.get("closeReasons") or list(types.CLOSE_REASONS),
            "defaultPlaybook": data.get("defaultPlaybook") or None,
            "autoRun": bool(data.get("autoRun")),
            "visibleToRoles": data.get("visibleToRoles") or None,
        }
    if kind == "preprocess_rules":
        return {
            "name": data.get("name"),
            "enabled": bool(data.get("enabled", True)),
            "when": data.get("when") or {},
            "action": data.get("action"),
            "params": data.get("params") or {},
        }
    return data


def _diff(kind: str, before: Any, after: Any) -> str:
    old, new = _text(kind, before).splitlines(), _text(kind, after).splitlines()
    text = "\n".join(difflib.unified_diff(old, new, "here", "in the pack", lineterm="", n=2))
    return text if len(text) <= DIFF_MAX else text[:DIFF_MAX] + "\n… (cut)"


def _conflict(db: OrmSession, pack: PackFile, item: Item, here: Any, coming: Coming | None = None) -> str | None:
    """Why an item cannot be applied at all, or None."""
    kind, data = item.kind, item.data

    def there(need_kind: str, need_name: str) -> bool:
        if pack.has(need_kind, need_name) or (coming is not None and coming.has(need_kind, need_name)):
            return True
        return current(db, need_kind, need_name, with_items=False) is not None

    if kind == "fields":
        if item.name in registry.SYSTEM_FIELDS:
            return "Nik has a field of its own with this name"
        if here is not None and here["type"] != data.get("type"):
            return f"There is a field with this name of another type ({here['type']}): a field keeps its type"
        if here is not None and here["appliesTo"] != (data.get("appliesTo") or "incident"):
            return "There is a field with this name of something else than what the pack says"
    if kind == "connectors":
        row = db.get(Connector, item.name)
        wanted = load_connector(data)
        if row is not None and row.version > wanted.version:
            return f"Version {row.version} is installed, the pack holds version {wanted.version}: versions only go up"
    if kind == "lists":
        if named_lists.watch_list(db, item.name) is not None:
            return "A list of the Indicators page has this name"
        if here is not None and here["kind"] != (data.get("kind") or "values"):
            return f"There is a list with this name of another kind ({here['kind']})"
        row = named_lists.find(db, item.name)
        if row is not None and row.builtin and ("entries" in data or "document" in data):
            return "This is a list of Nik's own settings: its items are not replaced by a pack"
    if kind == "mappers":
        connector = str(data.get("connector") or item.name)
        if not there("connectors", connector):
            return f'It is for the connector "{connector}", which is neither here nor in the pack'
        for type_name in data.get("types") or {}:
            if not there("incident_types", str(type_name)):
                return f'It names the incident type "{type_name}", which is neither here nor in the pack'
    if kind == "incident_types":
        known = set(registry.registry(db))
        for entry in data.get("fields") or []:
            name = str((entry or {}).get("name") or "")
            if name not in known and not there("fields", name):
                return f'It has the field "{name}", which is neither here nor in the pack'
        if data.get("defaultPlaybook") and not there("playbooks", str(data["defaultPlaybook"])):
            return f'Its playbook "{data["defaultPlaybook"]}" is neither here nor in the pack'
    if kind == "preprocess_rules":
        script = str((data.get("params") or {}).get("script") or "")
        if script and not there("scripts", script):
            return f'It runs the script "{script}", which is neither here nor in the pack'
    if kind == "dashboards" and here is not None:
        row = _dashboard(db, item.name)
        if row is not None and row.builtin:
            return "This is a dashboard Nik ships: it is not replaced by a pack"
    return None


def _shape_problem(item: Item) -> str | None:
    """What is wrong with an item on its own, whatever is here."""
    try:
        if item.kind == "scripts":
            if not scripts.NAME_RE.match(item.name):
                return "The name of a script is a capital letter, then letters and digits"
            scripts.clean(item.data)
        elif item.kind == "playbooks":
            if not isinstance(_playbook_body(item.data).get("graph"), dict):
                return "It has no graph"
        elif item.kind == "dashboards":
            boards.clean_widgets(item.data.get("widgets") or [])
        elif item.kind == "fields":
            if not registry.NAME_RE.match(item.name) or str(item.data.get("type")) not in registry.TYPES:
                return "It is not a field: its name or its type is not one Nik knows"
            registry.clean_options(str(item.data["type"]), item.data.get("options"))
    except (scripts.ScriptError, boards.DashboardError, registry.FieldError) as error:
        return getattr(error, "message", str(error))
    return None


@dataclass
class Coming:
    """What the packs installed just before this one, in the same go, will have brought: a pack of several
    installed together is judged against them too, since it is applied after them."""

    packs: dict[str, str] = field(default_factory=dict)  # id → version
    items: set[tuple[str, str]] = field(default_factory=set)  # (kind, name in lower case)

    def has(self, kind: str, name: str) -> bool:
        return (kind, name.lower()) in self.items

    def add(self, pack: PackFile) -> None:
        self.packs[pack.manifest["id"]] = pack.manifest["version"]
        self.items.update((item.kind, item.name.lower()) for item in pack.items)


def requirement_problems(db: OrmSession, manifest: dict[str, Any], coming: Coming | None = None) -> list[str]:
    found = []
    wanted = re.findall(r"\d+", manifest.get("nik") or "")
    if wanted and tuple(int(part) for part in (wanted + ["0"])[:3]) > NIK_VERSION:
        found.append(f"The pack is for Nik {manifest['nik'][2:]} or later")
    for need in manifest.get("requires") or []:
        row = db.get(Pack, need["pack"])
        # One that comes in the same go replaces the one that is here.
        has = (coming.packs.get(need["pack"]) if coming is not None else None) or (row.version if row else None)
        if has is None:
            found.append(f'It requires the pack "{need["pack"]}", which is not installed')
        elif (version_of(has) or (0, 0, 0)) < (version_of(need["version"]) or (0, 0, 0)):
            found.append(f'It requires version {need["version"]} of the pack "{need["pack"]}": {has} is installed')
    return found


def plan(db: OrmSession, pack: PackFile, coming: Coming | None = None) -> dict[str, Any]:
    """What applying the pack would do, item by item. Nothing is written. ``coming`` is what the packs
    installed before it in the same go bring: what it requires of them is not missing."""
    origin = {(row.kind, row.name.lower()): row.pack_id for row in db.scalars(select(PackItem)).all()}
    items = []
    for item in pack.items:
        entry: dict[str, Any] = {"kind": item.kind, "name": item.name, "label": LABELS[item.kind]}
        here = current(db, item.kind, item.name, with_items=True)
        wrong = _shape_problem(item)
        theirs = ours = None
        if wrong is None and here is not None:
            theirs, ours = _comparable(item.kind, item.data), _comparable(item.kind, here)
            if item.kind == "lists" and "entries" not in item.data and "document" not in item.data:
                ours = {key: value for key, value in ours.items() if key not in ("entries", "document")}
        if wrong is None and here is not None and theirs == ours:
            entry["action"] = "same"  # as the pack has it: nothing to do, whatever else is true of it
        else:
            wrong = wrong or _conflict(db, pack, item, here, coming)
            if wrong is not None:
                entry.update(action="conflict", why=wrong)
            elif here is None:
                entry["action"] = "add"
            else:
                entry.update(action="update", diff=_diff(item.kind, ours, theirs))
                if item.kind in ("playbooks", "scripts"):
                    entry["note"] = "A new version is made: the ones there are stay."
        owner = origin.get((item.kind, item.name.lower()))
        if owner and owner != pack.manifest["id"]:
            entry["from"] = owner
        items.append(entry)
    installed = db.get(Pack, pack.manifest["id"])
    return {
        "pack": pack.manifest,
        "installed": installed.version if installed is not None else None,
        "problems": requirement_problems(db, pack.manifest, coming),
        "items": items,
        "counts": {
            action: sum(1 for entry in items if entry["action"] == action)
            for action in ("add", "update", "same", "conflict")
        },
    }


# --------------------------------------------------------------------------- #
# Applying                                                                    #
# --------------------------------------------------------------------------- #
def _apply_item(db: OrmSession, pack: PackFile, item: Item, actor: str) -> None:
    kind, name, data = item.kind, item.name, item.data
    if kind == "connectors":
        connector_actions.install(db, data, actor, extras=item.extras or None)
    elif kind == "scripts":
        cleaned = scripts.clean(data)
        row = _script(db, name)
        if row is None:
            stamp = now_iso()
            row = Script(
                id=automation_engine.new_id(), name=name, description="", created_at=stamp, created_by=actor,
                updated_at=stamp, updated_by=actor,
            )  # fmt: skip
            db.add(row)
            db.flush()
        row.description = str(data.get("description") or "")[:2000]
        # Its test was not run here: the sandbox says so when the script is opened.
        scripts.add_version(db, row, cleaned, {"passed": None, "pack": pack.manifest["id"], "at": now_iso()}, actor)
    elif kind == "playbooks":
        _apply_playbook(db, _playbook_body(data), actor)
    elif kind == "fields":
        row = db.scalars(select(Field).where(Field.name == name)).first()
        if row is None:
            registry.create(db, data, actor)
        else:
            row.label = str(data.get("label") or name).strip()[:80]
            row.description = str(data.get("description") or "")[:1000]
            row.options = registry.clean_options(row.type, data.get("options"))
            row.all_types = bool(data.get("allTypes"))
    elif kind == "incident_types":
        _apply_type(db, data, actor)
    elif kind == "mappers":
        connector = str(data.get("connector") or name)
        groups = {mapping.ANY_TYPE: data}
        for type_name, rules in (data.get("types") or {}).items():
            row = _type(db, str(type_name))
            if row is not None and isinstance(rules, dict):
                groups[row.id] = rules
        for type_id, rules in groups.items():
            for direction in mapping.DIRECTIONS:
                if rules.get(direction):
                    body = {"connectorId": connector, "direction": direction, "incidentType": type_id}
                    mapping.save_mapper(db, {**body, "rules": rules[direction]}, actor)
        if isinstance(data.get("classifier"), dict):
            # What a new instance of the connector starts with: kept, and given when one is made.
            mapping.keep_default_classifier(db, connector, data["classifier"])
    elif kind == "lists":
        row = named_lists.find(db, name)
        if row is None:
            row = named_lists.create(db, data, actor)
            db.flush()
        else:
            named_lists.update(db, row, {k: data[k] for k in ("label", "description", "itemType") if k in data}, actor)
        if "document" in data and row.kind == "json":
            named_lists.set_items(db, row, data["document"], actor)
        elif "entries" in data and row.kind != "json":
            named_lists.set_items(db, row, data["entries"], actor)
    elif kind == "dashboards":
        body = {key: data.get(key) for key in ("description", "timeRange", "refreshSeconds", "filter", "filterEntity")}
        body = {key: value for key, value in body.items() if value is not None}
        body.update(name=name, widgets=data.get("widgets") or [])
        row = _dashboard(db, name)
        if row is None:
            row = boards.create(db, body, actor)
            row.shared_with = {"everyone": True, "roles": [], "users": []}  # a pack's dashboard is everyone's
        else:
            boards._apply(row, body, actor)
    elif kind == "preprocess_rules":
        preprocess.save(db, data, actor, _rule(db, name))
    db.flush()


def _apply_playbook(db: OrmSession, source: dict[str, Any], actor: str) -> None:
    """A playbook from a pack: off, reaching only listed hosts, sending no class of data; a new
    version of one that exists. A graph with problems here stays a draft."""
    from .automation import shipped

    name = str(source.get("name") or "").strip()[:120]
    shape = shipped.with_script_versions(db, source["graph"])
    stamp = now_iso()

    def number(key: str, default: int, low: int, high: int) -> int:
        value = source.get(key)
        return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else default

    row = _playbook(db, name)
    if row is None:
        row = Playbook(id=automation_engine.new_id(), name=name, enabled=False, created_at=stamp, created_by=actor)
        db.add(row)
    row.description = str(source.get("description") or "")[:2000]
    row.max_runs_per_hour = number("maxRunsPerHour", 60, 1, 10_000)
    row.one_per_object = bool(source.get("onePerObject", True))
    row.max_seconds = number("maxSeconds", 86400, 60, 7 * 86400)
    row.approval_default = bool(source.get("approvalDefault", True))
    row.updated_at, row.updated_by = stamp, actor
    db.flush()
    if graph.validate(shape, catalog.Library(db), row.name):
        row.draft = shape  # something it needs is missing here: it waits as a draft, the version in use stays
        return
    latest = db.scalar(select(func.max(PlaybookVersion.version)).where(PlaybookVersion.playbook_id == row.id)) or 0
    db.add(
        PlaybookVersion(
            playbook_id=row.id,
            version=latest + 1,
            graph=shape,
            note="From a content pack",
            created_at=stamp,
            created_by=actor,
        )  # fmt: skip
    )
    row.current_version, row.draft = latest + 1, None


def _apply_type(db: OrmSession, data: dict[str, Any], actor: str) -> None:
    row = _type(db, str(data["name"]))
    body = {
        key: data[key]
        for key in ("name", "description", "colour", "icon", "fields", "sla", "closeReasons", "visibleToRoles")
        if key in data
    }
    if data.get("layout") is not None:
        body["layout"] = data["layout"]
    playbook = _playbook(db, str(data["defaultPlaybook"])) if data.get("defaultPlaybook") else None
    body["defaultPlaybookId"] = playbook.id if playbook is not None else None
    body["autoRun"] = bool(data.get("autoRun")) and playbook is not None
    try:
        cleaned = types.clean(db, body, row)
    except types.TypeError_ as error:
        raise PackError(f'The incident type "{data["name"]}": {error.message}') from None
    stamp = now_iso()
    if row is None:
        row = IncidentType(id=types.new_id(db, cleaned["name"]), created_at=stamp, updated_at=stamp, fields=[], sla=[])
        row.close_reasons = list(types.CLOSE_REASONS)
        db.add(row)
    for key, value in cleaned.items():
        setattr(row, key, value)
    row.updated_at, row.updated_by = stamp, actor


def apply(
    db: OrmSession, pack: PackFile, choices: dict[str, str] | None, actor: str, *, source: str = "file"
) -> dict[str, Any]:
    """Do what the plan says, except the items the caller chose to skip (``{"kind/name": "skip"}``).
    The caller commits: anything that fails raises, and nothing of the pack stays."""
    choices = choices or {}
    found = plan(db, pack)
    if found["problems"]:
        raise PackError(found["problems"][0], 409)
    actions = {(entry["kind"], entry["name"]): entry for entry in found["items"]}
    done: dict[str, Any] = {"added": 0, "updated": 0, "same": 0, "skipped": 0, "mirroring": []}
    applied: list[Item] = []
    for item in pack.items:
        entry = actions[(item.kind, item.name)]
        skipped = choices.get(f"{item.kind}/{item.name}") == "skip"
        if entry["action"] == "conflict":
            if not skipped:
                raise PackError(f'{entry["label"]} "{item.name}": {entry["why"]}. Skip it, or settle it first.', 409)
            done["skipped"] += 1
            continue
        if skipped:
            done["skipped"] += 1
            continue
        if entry["action"] == "same":
            done["same"] += 1
            if item.kind == "connectors" and item.extras:
                _give_extras(db, item)
            applied.append(item)
            continue
        # What its mapper says of mirroring for every item, before the pack replaces it.
        named = _direction_named(db, item) if item.kind == "mappers" and entry["action"] == "update" else None
        try:
            _apply_item(db, pack, item, actor)
        except PackError:
            raise
        except ConnectorError as error:
            first = error.problems[0].message if error.problems else "it cannot be read"
            raise PackError(f'Connector "{item.name}": {first}') from None
        except (
            scripts.ScriptError, registry.FieldError, named_lists.ListError, mapping.MappingError, preprocess.RuleError,
            boards.DashboardError,
        ) as error:  # fmt: skip
            raise PackError(f'{entry["label"]} "{item.name}": {getattr(error, "message", str(error))}') from None
        done["added" if entry["action"] == "add" else "updated"] += 1
        applied.append(item)
        if named:
            kept = _keep_direction(db, pack, item, named, actor)
            if kept:
                done["mirroring"].append(kept)
    remember(db, pack.manifest, [(item.kind, item.name) for item in applied], actor, logo=pack.logo, source=source)
    return {"pack": pack.manifest, **done}


def _direction_of(rules: Any) -> str | None:
    """The direction an incoming mapper gives the mirror of every incident it makes, when it names one
    outright (``mirror_direction`` from "in"); None when it names none, or works it out of the item."""
    for rule in rules if isinstance(rules, list) else []:
        if isinstance(rule, dict) and rule.get("to") == "mirror_direction":
            said = str(rule.get("from") or "").strip()
            return said if said in ("in", "out", "both") else None
    return None


def _direction_named(db: OrmSession, item: Item) -> str | None:
    """The direction the mapper that is here names for every type, for the connector a pack's mapper is for."""
    connector = str(item.data.get("connector") or item.name)
    for row in mapping.mappers_of(db, connector):
        if row.direction == "incoming" and row.incident_type == mapping.ANY_TYPE:
            return _direction_of(row.rules)
    return None


def _keep_direction(db: OrmSession, pack: PackFile, item: Item, named: str, actor: str) -> dict[str, Any] | None:
    """A pack just replaced a mapper that named the direction of mirroring by one that leaves it to
    the instance: the instances of that connector that say None are told the direction the mapper
    named, so that what they fetch goes on being mirrored as it was with nobody touching anything.
    An instance someone gave a direction is left as it is. None when nothing was to be done: a mapper
    of the connector still names a direction (one of a type, which the pack does not carry)."""
    from . import mirror

    connector_id = str(item.data.get("connector") or item.name)
    if any(row.direction == "incoming" and _direction_of(row.rules) for row in mapping.mappers_of(db, connector_id)):
        return None
    row = db.get(Connector, connector_id)
    connector = connector_actions.parsed(row) if row is not None else None
    if connector is None or connector.mirror is None:
        return None
    told = []
    for connection in db.scalars(
        select(Connection).where(Connection.connector_id == connector_id).order_by(Connection.name)
    ):
        if mirror.choice_of(connection)[0] != mirror.NONE:
            continue
        try:
            mirror.set_choice(connection, connector, {"mirror": named})
        except mirror.MirrorError:
            continue  # a direction this connector cannot do any more: nothing is chosen for it
        told.append(connection.name)
    if not told:
        return None
    db.flush()
    label = mirror.LABELS[named]
    audit.record(
        db,
        actor,
        "mirror.kept",
        f'The pack "{pack.manifest["name"]}" {pack.manifest["version"]} leaves the direction of mirroring to the '
        f"instances, where its mapper said {label} until now. Mirroring was set to {label} in the instances that "
        f"said None, so that they mirror as before: {', '.join(told)}",
        target=connector_id,
    )
    return {"connector": connector_id, "direction": named, "instances": told}


def digest(db: OrmSession, kind: str, name: str) -> str:
    """What an item is now, as a fingerprint: the same after someone changes it back, another after any
    change that makes it another item. Empty for one that is not here or cannot be read."""
    try:
        here = current(db, kind, name, with_items=True)
        if here is None:
            return ""
        shown = json.dumps(_comparable(kind, here), sort_keys=True, default=str, ensure_ascii=False)
    except Exception:  # noqa: BLE001 - an item that cannot be read has no fingerprint, and is never removed for it
        return ""
    return hashlib.sha256(shown.encode("utf-8")).hexdigest()


def _give_extras(db: OrmSession, item: Item) -> None:
    """A connector that is here exactly as the pack has it may still lack what the pack brings beside its
    file: the logo and the README are given where the connector has none (one set here is left)."""
    row = db.get(Connector, item.name)
    if row is None:
        return
    if item.extras.get("logo") and not row.logo:
        row.logo, row.logo_type = connector_logo.clean(item.extras["logo"])
    if item.extras.get("readme") and not row.readme:
        row.readme = str(item.extras["readme"])[: connector_actions.README_MAX]


def remember(
    db: OrmSession,
    manifest: dict[str, Any],
    items: list[tuple[str, str]],
    actor: str,
    *,
    builtin: bool = False,
    logo: bytes | None = None,
    source: str = "file",
) -> Pack:
    """Write down that a pack is installed, and which items came from it (an item is of the last pack that
    gave it), each with what it was when the pack gave it: that is how a later change is told."""
    row = db.get(Pack, manifest["id"])
    if row is None:
        row = Pack(id=manifest["id"], installed_at=now_iso(), installed_by=actor[:200])
        db.add(row)
    row.name, row.version = manifest["name"], manifest["version"]
    row.description, row.author = manifest.get("description") or "", manifest.get("author") or ""
    row.manifest, row.builtin, row.source = manifest, builtin, source[:20]
    if logo:
        row.logo, row.logo_type = connector_logo.clean(logo)
    row.updated_at, row.updated_by = now_iso(), actor[:200]
    db.flush()
    wanted = {(kind, name) for kind, name in items}
    db.execute(delete(PackItem).where(PackItem.pack_id == row.id))
    for kind, name in sorted(wanted):
        db.execute(delete(PackItem).where(PackItem.kind == kind, func.lower(PackItem.name) == name.lower()))
        db.add(PackItem(kind=kind, name=name, pack_id=row.id, digest=digest(db, kind, name)))
    db.flush()
    return row


def _order(kind: str) -> int:
    return KINDS.index(kind) if kind in KINDS else len(KINDS)


def out(db: OrmSession, row: Pack) -> dict[str, Any]:
    items = db.scalars(select(PackItem).where(PackItem.pack_id == row.id)).all()
    shown = [
        {"kind": item.kind, "name": item.name, "label": LABELS.get(item.kind, item.kind),
         "there": current(db, item.kind, item.name, with_items=False) is not None,
         "changed": bool(item.digest) and item.digest != digest(db, item.kind, item.name)}
        for item in sorted(items, key=lambda entry: (_order(entry.kind), entry.name))
    ]  # fmt: skip
    return {
        "id": row.id,
        "name": row.name,
        "version": row.version,
        "description": row.description,
        "author": row.author,
        "vendor": (row.manifest or {}).get("vendor") or "",
        "category": (row.manifest or {}).get("category") or "",
        "tags": (row.manifest or {}).get("tags") or [],
        "source": row.source or "file",
        "hasLogo": bool(row.logo),
        "builtin": bool(row.builtin),
        "requires": (row.manifest or {}).get("requires") or [],
        "installedAt": row.installed_at,
        "installedBy": row.installed_by,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
        "items": shown,
    }


def installed(db: OrmSession) -> list[Pack]:
    return sorted(db.scalars(select(Pack)).all(), key=lambda row: (not row.builtin, row.name.lower()))


def _requiring(db: OrmSession, row: Pack) -> list[str]:
    return [
        other.name
        for other in db.scalars(select(Pack)).all()
        if other.id != row.id
        and any(need.get("pack") == row.id for need in (other.manifest or {}).get("requires") or [])
    ]


def forget(db: OrmSession, row: Pack) -> None:
    """Take a pack off the list of what is installed. Its items stay: they are Nik's now."""
    if row.builtin:
        raise PackError("A pack Nik ships is part of Nik", 409)
    needed = _requiring(db, row)
    if needed:
        raise PackError(f'The pack "{needed[0]}" requires it', 409)
    db.execute(delete(PackItem).where(PackItem.pack_id == row.id))
    db.delete(row)


# --------------------------------------------------------------------------- #
# Uninstalling: what the pack gave goes, unless something of it is in use      #
# --------------------------------------------------------------------------- #
def _node_users(db: OrmSession, wanted) -> list[str]:
    """The names of the playbooks whose current version or draft has a node ``wanted`` says yes to."""
    found = []
    for playbook in db.scalars(select(Playbook).order_by(Playbook.name)):
        version = db.get(PlaybookVersion, (playbook.id, playbook.current_version)) if playbook.current_version else None
        for shape in (version.graph if version else None, playbook.draft):
            if shape and any(wanted(node) for node in graph.nodes_of(shape).values()):
                found.append(playbook.name)
                break
    return found


@dataclass
class _Use:
    """One thing that uses an item of a pack: what it is (``what``, a sentence) and what to do about it
    first (``todo``). ``by`` names it when it is itself something a pack gives (a playbook, a type): one
    that leaves with the pack does not hold. ``stays`` is for what only makes the item stay behind (it is
    Nik's own, its connector stays) and stops nothing."""

    what: str
    todo: str = ""
    by: tuple[str, str] | None = None
    stays: bool = False


def _uses(db: OrmSession, kind: str, name: str) -> list[_Use]:
    """Everything that uses an item, whoever gave it."""

    def config(node: dict) -> dict:
        return node.get("config") or {}

    def playbooks(wanted, what: str, todo: str) -> list[_Use]:
        return [_Use(what.format(found), todo, by=("playbooks", found)) for found in _node_users(db, wanted)]

    found: list[_Use] = []
    if kind == "connectors":
        for held in db.scalars(select(Connection).where(Connection.connector_id == name).order_by(Connection.name)):
            found.append(
                _Use(
                    f'The instance "{held.name}" of its connector "{name}" is turned {"on" if held.enabled else "off"}',
                    "Delete the instance first: it holds credentials that are yours.",
                )
            )
        found += playbooks(
            lambda node: node.get("kind") == "action" and str(config(node).get("action") or "").startswith(name + "."),
            f'The playbook "{{}}" uses its connector "{name}"',
            "Take the connector out of the playbook, or delete the playbook.",
        )
    elif kind == "mappers":
        if db.get(Connector, name) is not None:
            found.append(_Use("Its connector stays", by=("connectors", name), stays=True))
    elif kind == "scripts":
        row = _script(db, name)
        if row is not None and row.builtin:
            found.append(_Use("It is a script of Nik", stays=True))
        found += playbooks(
            lambda node: node.get("kind") == "script" and config(node).get("script") == name,
            f'The playbook "{{}}" runs its script "{name}"',
            "Take the script out of the playbook, or delete the playbook.",
        )
        for rule in preprocess.every(db):
            if str((rule.params or {}).get("script") or "") == name:
                found.append(
                    _Use(
                        f'The pre-processing rule "{rule.name}" runs its script "{name}"',
                        "Delete the rule, or give it another script.",
                        by=("preprocess_rules", rule.name),
                    )
                )
    elif kind == "playbooks":
        row = _playbook(db, name)
        if row is None:
            return found
        if row.enabled:
            found.append(_Use(f'Its playbook "{row.name}" is turned on', "Turn the playbook off first."))
        active = db.scalar(
            select(func.count())
            .select_from(Run)
            .where(Run.playbook_id == row.id, Run.status.notin_(automation_engine.FINISHED))
        )
        if active:
            found.append(
                _Use(f'A run of its playbook "{row.name}" is in progress', "Wait for the run to end, or stop it.")
            )
        for held in db.scalars(select(IncidentType).where(IncidentType.default_playbook_id == row.id)):
            found.append(
                _Use(
                    f'Its playbook "{row.name}" is the playbook of the type "{held.name}"',
                    "Give the type another playbook, or none.",
                    by=("incident_types", held.name),
                )
            )
        found += [
            use
            for use in playbooks(
                lambda node: node.get("kind") == "playbook" and config(node).get("playbook") in (row.name, row.id),
                f'The playbook "{{}}" runs its playbook "{row.name}"',
                "Take it out of that playbook, or delete that playbook.",
            )
            if use.by is not None and use.by[1].lower() != row.name.lower()
        ]
    elif kind == "incident_types":
        row = _type(db, name)
        if row is None:
            return found
        if row.id == types.UNCLASSIFIED or row.builtin:
            found.append(_Use("It is a type of Nik", stays=True))
        count = db.scalar(select(func.count()).select_from(Incident).where(Incident.type_id == row.id)) or 0
        if count:
            found.append(
                _Use(
                    f'{count} incident{"s are" if count != 1 else " is"} of its type "{row.name}"',
                    "Give them another type, or delete them.",
                )
            )
    elif kind == "fields":
        row = db.scalars(select(Field).where(Field.name == name)).first()
        if row is None:
            return found
        if row.system:
            found.append(_Use("It is a field of Nik", stays=True))
        used = registry.used_by(db, row)
        for type_name in used["types"]:
            found.append(
                _Use(
                    f'The type "{type_name}" lists its field "{name}"',
                    "Take the field off the type.",
                    by=("incident_types", type_name),
                )
            )
        if used["incidents"]:
            count = used["incidents"]
            found.append(
                _Use(
                    f'{count} incident{"s hold" if count != 1 else " holds"} a value of its field "{name}"',
                    "Empty the field on them, or delete them.",
                )
            )
    elif kind == "lists":
        row = named_lists.find(db, name)
        if row is None:
            return found
        if row.builtin:
            found.append(_Use("It is a list of Nik", stays=True))
        for where in named_lists.used_by(db, row.name):
            if where.startswith("Playbook "):
                playbook = where[len("Playbook ") :]
                found.append(
                    _Use(
                        f'The playbook "{playbook}" reads its list "{name}"',
                        "Take the list out of the playbook, or delete the playbook.",
                        by=("playbooks", playbook),
                    )
                )
            else:
                found.append(
                    _Use(f'Its list "{name}" is read by a setting: {where}', "Point the setting to another list.")
                )
    elif kind == "dashboards":
        row = _dashboard(db, name)
        if row is not None and row.builtin:
            found.append(_Use("It is a dashboard of Nik", stays=True))
    return found


@dataclass
class Leaving:
    """What the packs uninstalled just before this one, in the same go, take with them: none of it holds a
    pack that is uninstalled after them."""

    packs: set[str] = field(default_factory=set)
    items: set[tuple[str, str]] = field(default_factory=set)  # (kind, name in lower case)

    def add(self, pack_id: str, items: list[dict[str, Any]]) -> None:
        self.packs.add(pack_id)
        self.items.update((entry["kind"], entry["name"].lower()) for entry in items if entry["action"] == "remove")


def uninstall_plan(db: OrmSession, row: Pack, leaving: Leaving | None = None) -> dict[str, Any]:
    """What uninstalling the pack would do: ``{items, held}``.

    ``items`` is each thing it gave with what happens to it: ``remove``; ``keep``, with why (it was changed
    here and is yours now, or something of the pack that stays needs it); or ``gone``, for what is not here
    any more.

    ``held`` is what is **in use**: each thing outside the pack that uses something of it (an instance of
    its connector, a playbook of yours that runs its script, incidents of its type, another pack that
    requires it…) or shows it is at work (a playbook of it that is turned on), with what to do first. While
    there is one the pack is not uninstalled: nothing that is used is pulled from under what uses it.
    ``leaving`` is what goes just before, when several packs are uninstalled together."""
    if row.builtin:
        raise PackError("A pack Nik ships is part of Nik", 409)
    leaving = leaving or Leaving()
    held: list[dict[str, Any]] = []
    for other in sorted(db.scalars(select(Pack)).all(), key=lambda found: found.name.lower()):
        requires = any(need.get("pack") == row.id for need in (other.manifest or {}).get("requires") or [])
        if other.id != row.id and requires and other.id not in leaving.packs:
            held.append(
                {
                    "kind": "packs",
                    "name": other.name,
                    "label": "Pack",
                    "what": f'The pack "{other.name}" requires it',
                    "todo": "Uninstall that pack first.",
                }
            )
    entries: dict[tuple[str, str], dict[str, Any]] = {}
    for item in db.scalars(select(PackItem).where(PackItem.pack_id == row.id)).all():
        entry = {"kind": item.kind, "name": item.name, "label": LABELS.get(item.kind, item.kind), "why": ""}
        now = digest(db, item.kind, item.name)
        if current(db, item.kind, item.name, with_items=False) is None:
            entry.update(action="gone", why="It is not here any more")
        elif item.digest and now != item.digest:
            entry.update(action="keep", why="It was changed here")
        else:
            entry["action"] = "remove"
        entries[(item.kind, item.name.lower())] = entry
    ordered = sorted(entries.values(), key=lambda entry: (_order(entry["kind"]), entry["name"].lower()))
    uses = {
        (entry["kind"], entry["name"].lower()): _uses(db, entry["kind"], entry["name"])
        for entry in ordered
        if entry["action"] != "gone"
    }

    def user(use: _Use) -> dict[str, Any] | None:
        return entries.get((use.by[0], use.by[1].lower())) if use.by is not None else None

    def leaves(use: _Use) -> bool:
        """Whether what uses the item goes too: with this pack, or with one uninstalled just before."""
        if use.by is None:
            return False
        found = user(use)
        return (found is not None and found["action"] == "remove") or (use.by[0], use.by[1].lower()) in leaving.items

    # What stays of the pack keeps what it needs of the pack: found again until nothing more stays.
    settled = False
    while not settled:
        settled = True
        for entry in ordered:
            if entry["action"] != "remove":
                continue
            for use in uses[(entry["kind"], entry["name"].lower())]:
                if leaves(use) or not (use.stays or user(use) is not None):
                    continue
                needed_by = f'The {LABELS.get(use.by[0], use.by[0]).lower()} "{use.by[1]}", which stays, needs it'
                entry.update(action="keep", why=use.what if use.stays else needed_by)
                settled = False
                break
    for entry in ordered:
        for use in uses.get((entry["kind"], entry["name"].lower()), []):
            if use.stays or leaves(use) or user(use) is not None:
                continue
            held.append(
                {"kind": entry["kind"], "name": entry["name"], "label": entry["label"], "what": use.what,
                 "todo": use.todo}
            )  # fmt: skip
    return {"items": ordered, "held": held}


class PackHeld(PackError):
    """A pack that is not uninstalled because something of it is in use: ``held`` says what."""

    def __init__(self, name: str, held: list[dict[str, Any]]):
        more = f", and {len(held) - 1} more" if len(held) > 1 else ""
        super().__init__(f'"{name}" is in use and was not uninstalled. {held[0]["what"]}{more}.', 409)
        self.held = held


def uninstall(db: OrmSession, row: Pack) -> dict[str, Any]:
    """Uninstall a pack (the caller commits): what the plan removes is deleted, what it keeps stays and is
    no pack's any more. A pack that is held is not touched: ``PackHeld`` says by what. Returns
    ``{removed, kept}``, as lists of entries."""
    found = uninstall_plan(db, row)
    if found["held"]:
        raise PackHeld(row.name, found["held"])
    removed = []
    # What uses goes before what is used.
    for entry in sorted(found["items"], key=lambda entry: -_order(entry["kind"])):
        if entry["action"] != "remove":
            continue
        kind, name = entry["kind"], entry["name"]
        if kind == "connectors":
            db.delete(db.get(Connector, name))
            mapping.forget_default_classifier(db, name)
        elif kind == "mappers":
            for mapper in mapping.mappers_of(db, name):
                db.delete(mapper)
        elif kind == "scripts":
            db.delete(_script(db, name))
        elif kind == "playbooks":
            db.delete(_playbook(db, name))
        elif kind == "incident_types":
            db.delete(_type(db, name))
        elif kind == "fields":
            db.delete(db.scalars(select(Field).where(Field.name == name)).first())
        elif kind == "lists":
            named_lists.remove(db, named_lists.find(db, name))
        elif kind == "dashboards":
            db.delete(_dashboard(db, name))
        elif kind == "preprocess_rules":
            db.delete(_rule(db, name))
        db.flush()
        removed.append(entry)
    db.execute(delete(PackItem).where(PackItem.pack_id == row.id))
    db.delete(row)
    db.flush()
    return {"removed": removed, "kept": [entry for entry in found["items"] if entry["action"] == "keep"]}


def in_order(needs: dict[str, list[str]], names: dict[str, str] | None = None, *, reverse: bool = False) -> list[str]:
    """The packs of ``needs`` (id → the ids it requires) in the order to install them: each after the ones
    it requires, and by name where nothing decides. ``reverse`` is the order to uninstall them: each before
    the ones it requires. Packs that require each other in a circle come last, by name."""
    names = names or {}

    def by_name(pack_id: str) -> tuple[str, str]:
        return (names.get(pack_id, pack_id).lower(), pack_id)

    waiting, done = sorted(needs, key=by_name), []
    while waiting:
        ready = [
            pack_id for pack_id in waiting if not any(need in waiting and need != pack_id for need in needs[pack_id])
        ]
        if not ready:
            done += waiting
            break
        done.append(ready[0])
        waiting.remove(ready[0])
    return done[::-1] if reverse else done


# --------------------------------------------------------------------------- #
# A file between its inspection and its application                           #
# --------------------------------------------------------------------------- #
def keep_upload(db: OrmSession, data: bytes, file_name: str, actor: str, now: float | None = None) -> str:
    now = time.time() if now is None else now
    db.execute(delete(PackUpload).where(PackUpload.created_epoch < now - UPLOAD_SECONDS))
    token = secrets.token_urlsafe(24)
    db.add(
        PackUpload(
            token=token,
            data=data,
            file_name=file_name[:200],
            created_epoch=now,
            created_by=actor[:200],
            id=uuid.uuid4().hex,
        )  # fmt: skip
    )
    return token


def take_upload(db: OrmSession, token: str, actor: str, now: float | None = None) -> PackUpload:
    """The file an inspection kept, for who inspected it, while it is still fresh."""
    now = time.time() if now is None else now
    row = db.scalars(select(PackUpload).where(PackUpload.token == str(token))).first()
    if row is None or row.created_by != actor[:200] or row.created_epoch < now - UPLOAD_SECONDS:
        raise PackError("This pack was inspected too long ago, or by someone else: choose the file again", 410)
    return row


# --------------------------------------------------------------------------- #
# What Nik ships, as one pack                                                 #
# --------------------------------------------------------------------------- #
def builtin_manifest() -> tuple[dict[str, Any], list[tuple[str, str]]]:
    """The pack Nik is made of, with the items it ships, by name. They are installed by Nik itself at
    startup (each kind by its own seeding); here they are only written down, so that what ships is listed,
    downloaded and compared like anything that came in a file. What is about one product of a vendor is not
    here: it is a pack of its own, taken from the catalogue."""
    from .automation import shipped as shipped_playbooks

    manifest = {
        "id": BUILTIN_ID,
        "name": "Nik built-in",
        "vendor": "Nik",
        "category": "",
        "version": ".".join(str(part) for part in NIK_VERSION),
        "description": "What Nik ships: its types of incident and lists, its scripts, playbooks and dashboards, "
        "and the Mail connector.",
        "author": "Nik",
        "tags": [],
        "requires": [],
        "nik": "",
    }
    items = [
        *(("incident_types", str(item["name"])) for item in types.SHIPPED),
        *(("lists", name) for name in named_lists.BUILTIN),
        *(("scripts", str(item["name"])) for item in scripts.shipped()),
        *(("playbooks", str(source["name"])) for _key, source in shipped_playbooks.files()),
        *(("connectors", connector.id) for _text, connector in connector_actions.shipped()),
        *(("mappers", name) for name in mapping.shipped()),
        *(("dashboards", str(data["name"])) for data in boards.shipped()),
    ]
    return manifest, items


def register_builtin(db: OrmSession) -> int:
    """Write down the pack Nik ships and what is of it (the caller commits). An item that a pack someone
    installed gave last stays of that pack. Returns how many packs or items changed."""
    changed = 0
    owners = {(row.kind, row.name.lower()): row for row in db.scalars(select(PackItem)).all()}
    manifest, items = builtin_manifest()
    row = db.get(Pack, manifest["id"])
    if row is None or row.version != manifest["version"] or not row.builtin or row.name != manifest["name"]:
        if row is None:
            row = Pack(id=manifest["id"], installed_at=now_iso(), installed_by="nik")
            db.add(row)
        row.name, row.version, row.description = manifest["name"], manifest["version"], manifest["description"]
        row.author, row.manifest, row.builtin, row.source = "Nik", manifest, True, "nik"
        row.updated_at, row.updated_by = now_iso(), "nik"
        db.flush()
        changed += 1
    wanted = {(kind, name.lower()) for kind, name in items}
    for kind, name in items:
        if (kind, name.lower()) not in owners:
            held = PackItem(kind=kind, name=name, pack_id=row.id, digest="")
            db.add(held)
            owners[(kind, name.lower())] = held
            changed += 1
    for key, held in list(owners.items()):
        if held.pack_id == row.id and key not in wanted:  # a release no longer ships it
            db.delete(held)
            del owners[key]
            changed += 1
    return changed


# --------------------------------------------------------------------------- #
# A folder of packs, installed at start                                       #
# --------------------------------------------------------------------------- #
def install_folder(db: OrmSession, folder: Path, actor: str = "nik") -> int:
    """Install the packs of a folder (``NIK_PACKS_DIR``): each a folder with a ``pack.yml`` or a
    ``.nikpack`` file. One that is installed at the same version or a later one is left; an item that
    conflicts is skipped. Each pack is committed on its own, so that one that cannot be installed does not
    hold the others back. Returns how many were installed. This is for a Nik that cannot reach the
    catalogue: nothing here is checked against a signature, the folder is the administrator's."""
    if not folder.is_dir():
        return 0
    waiting = [
        path
        for path in sorted(folder.iterdir())
        if (path.is_dir() and (path / "pack.yml").is_file()) or (path.is_file() and path.suffix == ".nikpack")
    ]
    installed = 0
    for _attempt in range(3):  # a pack may require another of the same folder
        again = []
        for path in waiting:
            try:
                pack = read(folder_bytes(path) if path.is_dir() else path.read_bytes())
                row = db.get(Pack, pack.manifest["id"])
                if row is not None and (version_of(row.version) or (0, 0, 0)) >= version_of(pack.manifest["version"]):
                    continue
                found = plan(db, pack)
                if found["problems"]:
                    again.append(path)
                    continue
                skipped = {
                    f"{entry['kind']}/{entry['name']}": "skip"
                    for entry in found["items"]
                    if entry["action"] == "conflict"
                }
                apply(db, pack, skipped, actor, source="folder")
                db.commit()
                installed += 1
            except PackError as error:
                db.rollback()
                logger.warning("The pack %s of %s was not installed: %s", path.name, folder, error.message)
            except IntegrityError:
                db.rollback()  # another process of the server installed it at the same moment
        if not again or len(again) == len(waiting):
            for path in again:
                logger.warning("The pack %s of %s was not installed: what it requires is not here", path.name, folder)
            break
        waiting = again
    return installed
