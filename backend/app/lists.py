"""Lists: what a feature or a playbook reads by a name.

A list is of one kind:

- ``values``: items, each a text (a domain, a network, an address…);
- ``key_value``: items with a key and a value of any JSON shape (``columns``
  says which keys the value has, when it has a fixed shape);
- ``json``: one document;
- ``indicators``: a watch list of the Indicators page, read here like the others
  and changed where indicators are.

Everything Nik kept as a fixed list in its settings is a list Nik ships
(``BUILTIN``), filled once from what the settings held (``seed``). A setting
that was moved holds ``{"list": "<name>"}``: which list a feature reads can
be changed, and the default is the one that was moved. The settings API goes
on giving and taking the old arrays (``settings_value``, ``apply_setting``).

Reads go through a short cache, dropped whenever this process writes a list;
another process sees a change a few seconds later at most.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
import time
import uuid
from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from .core.models import IocList, IocListItem, NamedList, NamedListItem, Playbook, PlaybookVersion, Setting
from .core.security import now_iso

KINDS = ("values", "key_value", "json")
ITEM_TYPES = ("text", "domain", "host", "cidr", "ip", "email", "user", "url", "indicator", "keyword")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{1,48}$")
ITEMS_MAX = 50_000
KEY_MAX = 500
VALUE_MAX = 20_000  # characters of a value as JSON
DOCUMENT_KEY = "value"  # the one item of a list of kind json
CACHE_SECONDS = 3.0
SETTINGS_ID = 1
AUTOMATION_SETTINGS_ID = 2

KEYWORD_COLUMNS = [
    {"name": "label", "label": "Label", "type": "text"},
    {"name": "pattern", "label": "Pattern", "type": "text"},
    {"name": "severity", "label": "Severity", "type": "choice", "choices": ["low", "medium", "high", "critical"]},
    {"name": "description", "label": "Description", "type": "text"},
]

# name → what Nik ships, and the setting it was moved from (``setting``: the key of the
# settings document, dotted for a key inside another; ``state`` for the automation's own row).
BUILTIN: dict[str, dict[str, Any]] = {
    "ioc_allowlist": {
        "label": "IoC allowlist",
        "description": "Addresses, networks and domains that are never an indicator: yours, and well-known ones.",
        "kind": "values",
        "item_type": "indicator",
        "setting": "iocAllowlist",
        "used": "Settings → Indicators → Allowlist",
    },
    "internal_domains": {
        "label": "Your organisation's domains",
        "description": "The domains that are yours: look-alike senders are flagged, and the data guard knows them.",
        "kind": "values",
        "item_type": "domain",
        "setting": "mail.orgDomains",
        "used": "Settings → Analysis → Mail analysis",
    },
    "mail_trusted_auth_servers": {
        "label": "Trusted mail servers",
        "description": "The mail servers whose Authentication-Results header is believed.",
        "kind": "values",
        "item_type": "host",
        "setting": "mail.trustedAuthServers",
        "used": "Settings → Analysis → Mail analysis",
    },
    "suspicious_keywords": {
        "label": "Suspicious keywords",
        "description": "The keywords of the detection rules: each with its pattern and its severity.",
        "kind": "key_value",
        "item_type": "keyword",
        "columns": KEYWORD_COLUMNS,
        "setting": "keywords",
        "used": "Settings → Analysis → Detection rules",
    },
    "business_hours": {
        "label": "Business hours",
        "description": "The hours your organisation works, in UTC: activity outside them is highlighted, "
        "and SLA timers can count only inside them.",
        "kind": "json",
        "item_type": "text",
        "setting": "businessHours",
        "used": "Settings → Analysis → Business hours; SLA timers",
    },
    "automation_hosts": {
        "label": "Hosts every playbook may reach",
        "description": "The hosts a playbook that reaches listed hosts only may reach besides its own.",
        "kind": "values",
        "item_type": "host",
        "setting": "state.hosts",
        "used": "Settings → Automation → Network and data",
    },
}
# setting → the list Nik ships for it.
BY_SETTING = {spec["setting"]: name for name, spec in BUILTIN.items()}


class ListError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# The cache                                                                   #
# --------------------------------------------------------------------------- #
_cache: dict[str, tuple[float, Any]] = {}


def clear_cache() -> None:
    _cache.clear()


def _cached(key: str, make) -> Any:
    held = _cache.get(key)
    now = time.monotonic()
    if held is not None and now - held[0] < CACHE_SECONDS:
        return held[1]
    value = make()
    _cache[key] = (now, value)
    return value


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def slug(text: str) -> str:
    out = re.sub(r"[^a-z0-9]+", "_", str(text).strip().lower()).strip("_")
    return (out if out[:1].isalpha() else f"list_{out}")[:49] or "list"


def find(db: OrmSession, name: str) -> NamedList | None:
    return db.scalars(select(NamedList).where(NamedList.name == str(name))).one_or_none()


def watch_list(db: OrmSession, name: str) -> IocList | None:
    """A list of the Indicators page by the name it has here (its own name, as a slug)."""
    for row in db.scalars(select(IocList).order_by(IocList.created_at)):
        if slug(row.name) == name:
            return row
    return None


def _rows(db: OrmSession, row: NamedList, now: float | None = None) -> list[NamedListItem]:
    now = time.time() if now is None else now
    found = db.scalars(
        select(NamedListItem)
        .where(NamedListItem.list_id == row.id)
        .order_by(NamedListItem.position, NamedListItem.added_at, NamedListItem.key)
    ).all()
    return [item for item in found if item.expires_at is None or item.expires_at > now]


def items(db: OrmSession, name: str) -> list[dict[str, Any]]:
    """The items of a list, in order: ``[{key, value, note, …}]``. [] for a list that does not exist."""

    def read() -> list[dict[str, Any]]:
        row = find(db, name)
        if row is not None:
            return [_item(item) for item in _rows(db, row)]
        watched = watch_list(db, name)
        if watched is None:
            return []
        members = db.scalars(
            select(IocListItem).where(IocListItem.list_id == watched.id).order_by(IocListItem.added_at)
        )
        return [
            {
                "key": member.value,
                "value": {"type": member.type},
                "note": "",
                "addedAt": member.added_at,
                "addedBy": member.added_by,
                "expiresAt": None,
            }
            for member in members
        ]

    return _cached(name, read)


def _item(item: NamedListItem) -> dict[str, Any]:
    return {
        "key": item.key,
        "value": item.value,
        "note": item.note,
        "addedAt": item.added_at,
        "addedBy": item.added_by,
        "expiresAt": item.expires_at,
    }


def values(db: OrmSession, name: str) -> list[str]:
    """The keys of a list: what a list of values holds."""
    return [item["key"] for item in items(db, name)]


def mapping(db: OrmSession, name: str) -> dict[str, Any]:
    return {item["key"]: item["value"] for item in items(db, name)}


def document(db: OrmSession, name: str, default: Any = None) -> Any:
    """The document of a list of kind json."""
    found = items(db, name)
    return found[0]["value"] if found else default


def get(db: OrmSession, name: str) -> Any:
    """A list as a playbook reads it: a list of values, a mapping, or a document."""
    row = find(db, name)
    if row is None:
        if watch_list(db, name) is None:
            raise ListError(f'There is no list called "{name}"', 404)
        return values(db, name)
    if row.kind == "json":
        return document(db, name)
    return mapping(db, name) if row.kind == "key_value" else values(db, name)


def contains(db: OrmSession, name: str, value: Any) -> bool:
    """Whether a value is in a list. A list of networks holds the addresses inside them;
    names and addresses are compared without regard to case."""
    wanted = str(value if value is not None else "").strip()
    if not wanted:
        return False
    row = find(db, name)
    keys = values(db, name)
    if row is not None and row.kind == "json":
        held = document(db, name)
        return wanted in held if isinstance(held, (list, dict, str)) else False
    if wanted in keys:
        return True
    lowered = wanted.lower()
    if any(key.lower() == lowered for key in keys):
        return True
    try:
        address = ipaddress.ip_address(wanted)
    except ValueError:
        return False
    for key in keys:
        if "/" in key:
            try:
                if address in ipaddress.ip_network(key, strict=False):
                    return True
            except ValueError:
                continue
    return False


# --------------------------------------------------------------------------- #
# Showing                                                                     #
# --------------------------------------------------------------------------- #
def out(db: OrmSession, row: NamedList, *, with_items: bool = False) -> dict[str, Any]:
    count = db.scalar(select(func.count()).select_from(NamedListItem).where(NamedListItem.list_id == row.id)) or 0
    shown = {
        "name": row.name,
        "label": row.label or row.name,
        "description": row.description,
        "kind": row.kind,
        "itemType": row.item_type,
        "columns": row.columns or [],
        "builtin": bool(row.builtin),
        "writableByAutomation": bool(row.writable_by_automation),
        "readOnly": False,
        "items": count if row.kind != "json" else None,
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
        "usedBy": used_by(db, row.name),
    }
    if with_items:
        found = [_item(item) for item in _rows(db, row)]
        shown["entries"] = found if row.kind != "json" else []
        shown["document"] = found[0]["value"] if row.kind == "json" and found else None
    return shown


def _watch_out(db: OrmSession, row: IocList, *, with_items: bool = False) -> dict[str, Any]:
    name = slug(row.name)
    count = db.scalar(select(func.count()).select_from(IocListItem).where(IocListItem.list_id == row.id)) or 0
    shown = {
        "name": name,
        "label": row.name,
        "description": row.description or "A list of the Indicators page: it is changed where indicators are.",
        "kind": "indicators",
        "itemType": "indicator",
        "columns": [],
        "builtin": False,
        "writableByAutomation": False,
        "readOnly": True,
        "items": count,
        "updatedAt": row.updated_at,
        "updatedBy": row.created_by,
        "usedBy": used_by(db, name),
    }
    if with_items:
        shown["entries"] = items(db, name)
        shown["document"] = None
    return shown


def every(db: OrmSession) -> list[dict[str, Any]]:
    """Every list by name: Nik's and yours, then the watch lists of the Indicators page."""
    rows = db.scalars(select(NamedList).order_by(NamedList.builtin.desc(), NamedList.name)).all()
    taken = {row.name for row in rows}
    shown = [out(db, row) for row in rows]
    for watched in db.scalars(select(IocList).order_by(IocList.name)):
        if slug(watched.name) not in taken:
            taken.add(slug(watched.name))
            shown.append(_watch_out(db, watched))
    return shown


def one(db: OrmSession, name: str) -> dict[str, Any]:
    row = find(db, name)
    if row is not None:
        return out(db, row, with_items=True)
    watched = watch_list(db, name)
    if watched is None:
        raise ListError(f'There is no list called "{name}"', 404)
    return _watch_out(db, watched, with_items=True)


def used_by(db: OrmSession, name: str) -> list[str]:
    """Where a list is read: the settings that point to it, and the playbooks that name it."""
    found = []
    pointers = pointers_of(db)
    for setting, spec_name in BY_SETTING.items():
        if pointers.get(setting, spec_name) == name:
            found.append(BUILTIN[spec_name]["used"])
    quoted = (f'"{name}"', f"'{name}'")
    for playbook in db.scalars(select(Playbook).where(Playbook.current_version.isnot(None))):
        version = db.get(PlaybookVersion, (playbook.id, playbook.current_version))
        text = json.dumps(version.graph, ensure_ascii=False) if version is not None else ""
        if "list." in text or "in_list" in text:
            if any(mark in text for mark in quoted) or f'\\"{name}\\"' in text:
                found.append(f"Playbook {playbook.name}")
    return found


# --------------------------------------------------------------------------- #
# Writing                                                                     #
# --------------------------------------------------------------------------- #
def _touch(row: NamedList, actor: str) -> None:
    row.updated_at, row.updated_by = now_iso(), actor[:200]
    _cache.pop(row.name, None)


def _key(raw: Any, item_type: str = "text", check: bool = True) -> str:
    """An item as it is kept: a domain in lower case, a host as the network rules write it."""
    key = str(raw if raw is not None else "").strip()
    if not key or len(key) > KEY_MAX:
        raise ListError(f"An item is a text of 1 to {KEY_MAX} characters")
    if not check:
        return key
    if item_type == "domain":
        key = key.lower().strip(".")
        if not key or " " in key:
            raise ListError("A domain is a name such as corp.example")
    elif item_type == "host":
        from .automation import egress

        cleaned = egress.clean_host(key)
        if cleaned is None:
            raise ListError("A host is a name or an address, with a port if needed")
        key = cleaned
    return key


def _value(raw: Any) -> Any:
    try:
        text = json.dumps(raw, ensure_ascii=False)
    except (TypeError, ValueError):
        raise ListError("A value is JSON") from None
    if len(text) > VALUE_MAX:
        raise ListError(f"A value is at most {VALUE_MAX} characters as JSON")
    return raw


def create(db: OrmSession, body: dict[str, Any], actor: str) -> NamedList:
    name = str(body.get("name") or "").strip()
    if not NAME_RE.match(name):
        raise ListError("A list needs a name: a lower-case letter, then letters, digits or _ (2 to 49)")
    if find(db, name) is not None or watch_list(db, name) is not None:
        raise ListError("There is a list with this name already", 409)
    kind = str(body.get("kind") or "values")
    if kind not in KINDS:
        raise ListError("A list is of kind: " + ", ".join(KINDS))
    row = NamedList(id=uuid.uuid4().hex, name=name, kind=kind, updated_at=now_iso(), updated_by=actor)
    db.add(row)
    update(db, row, body, actor)
    return row


def update(db: OrmSession, row: NamedList, body: dict[str, Any], actor: str) -> NamedList:
    """Change what a list is called and how it is used (not its name or its kind)."""
    if "label" in body:
        row.label = str(body.get("label") or "").strip()[:120]
    if "description" in body:
        row.description = str(body.get("description") or "")[:2000]
    if "itemType" in body:
        item_type = str(body.get("itemType") or "text")
        if item_type not in ITEM_TYPES:
            raise ListError("The items of a list are: " + ", ".join(ITEM_TYPES))
        row.item_type = item_type
    if "writableByAutomation" in body:
        row.writable_by_automation = bool(body.get("writableByAutomation"))
    _touch(row, actor)
    return row


def remove(db: OrmSession, row: NamedList) -> None:
    if row.builtin:
        raise ListError("A list Nik ships cannot be deleted: empty it instead", 409)
    used = used_by(db, row.name)
    if used:
        raise ListError("This list is used by: " + "; ".join(used), 409)
    db.execute(delete(NamedListItem).where(NamedListItem.list_id == row.id))
    db.delete(row)
    _cache.pop(row.name, None)


def add_item(
    db: OrmSession,
    row: NamedList,
    key: Any,
    value: Any = None,
    actor: str = "",
    *,
    note: str = "",
    expires_at: float | None = None,
) -> bool:
    """Add an item, or change the value of the one with that key. Says whether it is new."""
    if row.kind == "json":
        raise ListError("This list is one document: set it whole")
    key = _key(key, row.item_type)
    held = db.get(NamedListItem, (row.id, key))
    if held is None:
        count = db.scalar(select(func.count()).select_from(NamedListItem).where(NamedListItem.list_id == row.id)) or 0
        if count >= ITEMS_MAX:
            raise ListError(f"A list holds {ITEMS_MAX} items at most")
        last = db.scalar(select(func.max(NamedListItem.position)).where(NamedListItem.list_id == row.id))
        db.add(
            NamedListItem(
                list_id=row.id,
                key=key,
                value=_value(value) if row.kind == "key_value" else None,
                note=str(note or "")[:500],
                position=(last or 0) + 1,
                added_at=now_iso(),
                added_by=actor[:200],
                expires_at=expires_at,
            )
        )
    else:
        if row.kind == "key_value":
            held.value = _value(value)
            flag_modified(held, "value")
        if note:
            held.note = str(note)[:500]
        held.expires_at = expires_at
    _touch(row, actor)
    return held is None


def remove_item(db: OrmSession, row: NamedList, key: Any, actor: str) -> bool:
    held = db.get(NamedListItem, (row.id, str(key if key is not None else "").strip()))
    if held is None:
        return False
    db.delete(held)
    _touch(row, actor)
    return True


def set_items(db: OrmSession, row: NamedList, entries: Any, actor: str, *, check: bool = True) -> int:
    """Replace everything a list holds. ``entries``: values, or ``{key, value, note, expiresAt}``,
    or for a list of kind json the document itself. Returns how many items it holds after."""
    stamp = now_iso()
    if row.kind == "json":
        db.execute(delete(NamedListItem).where(NamedListItem.list_id == row.id))
        db.add(
            NamedListItem(
                list_id=row.id, key=DOCUMENT_KEY, value=_value(entries), position=1, added_at=stamp, added_by=actor
            )
        )
        _touch(row, actor)
        return 1
    if isinstance(entries, dict) and row.kind == "key_value":
        entries = [{"key": key, "value": value} for key, value in entries.items()]
    if not isinstance(entries, list) or len(entries) > ITEMS_MAX:
        raise ListError(f"The items of a list are a list, {ITEMS_MAX} at most")
    before = {item.key: item for item in db.scalars(select(NamedListItem).where(NamedListItem.list_id == row.id))}
    wanted: dict[str, dict[str, Any]] = {}
    for entry in entries:
        item = entry if isinstance(entry, dict) else {"key": entry}
        key = _key(item.get("key"), row.item_type, check)
        if key not in wanted:
            wanted[key] = item
    for key, held in before.items():
        if key not in wanted:
            db.delete(held)
    for position, (key, item) in enumerate(wanted.items(), start=1):
        value = _value(item.get("value")) if row.kind == "key_value" else None
        held = before.get(key)
        if held is None:
            db.add(
                NamedListItem(
                    list_id=row.id,
                    key=key,
                    value=value,
                    note=str(item.get("note") or "")[:500],
                    position=position,
                    added_at=stamp,
                    added_by=actor[:200],
                    expires_at=item.get("expiresAt"),
                )
            )
        else:
            held.value, held.position = value, position
            flag_modified(held, "value")
            if "note" in item:
                held.note = str(item.get("note") or "")[:500]
            if "expiresAt" in item:
                held.expires_at = item.get("expiresAt")
    _touch(row, actor)
    return len(wanted)


def prune(db: OrmSession, now: float) -> int:
    """Remove the items whose time is over (the worker; the caller commits)."""
    old = db.scalars(select(NamedListItem).where(NamedListItem.expires_at.isnot(None), NamedListItem.expires_at <= now))
    count = 0
    for item in old.all():
        db.delete(item)
        count += 1
    if count:
        clear_cache()
    return count


# --------------------------------------------------------------------------- #
# Files                                                                       #
# --------------------------------------------------------------------------- #
def export(db: OrmSession, name: str, fmt: str) -> tuple[str, str]:
    """A list as a file: (text, media type). JSON holds everything; CSV, the items as rows."""
    shown = one(db, name)
    if fmt == "json" or shown["kind"] == "json":
        body = {
            "name": shown["name"],
            "label": shown["label"],
            "description": shown["description"],
            "kind": shown["kind"],
            "itemType": shown["itemType"],
            "entries": [
                {"key": item["key"], "value": item["value"], "note": item["note"]} for item in shown["entries"]
            ],
            "document": shown["document"],
        }
        return json.dumps(body, ensure_ascii=False, indent=2), "application/json"
    from .ioc_library import _csv_safe as csv_cell

    columns = [column["name"] for column in shown["columns"]]
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["key", *(columns or (["value"] if shown["kind"] == "key_value" else [])), "note"])
    for item in shown["entries"]:
        value = item["value"]
        if columns:
            cells = [(value or {}).get(column, "") if isinstance(value, dict) else "" for column in columns]
        elif shown["kind"] == "key_value":
            cells = [value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)]
        else:
            cells = []
        writer.writerow([csv_cell(cell) for cell in (item["key"], *cells, item["note"])])
    return buffer.getvalue(), "text/csv"


def parse_file(row: NamedList, text: str, fmt: str) -> Any:
    """What a file holds, as ``set_items`` takes it. CSV: a header row with ``key`` (or one column of values)."""
    if fmt == "json":
        try:
            body = json.loads(text)
        except ValueError:
            raise ListError("The file is not valid JSON") from None
        if row.kind == "json":
            return body.get("document") if isinstance(body, dict) and "document" in body else body
        if isinstance(body, dict) and isinstance(body.get("entries"), list):
            return body["entries"]
        if isinstance(body, (list, dict)):
            return body
        raise ListError("A JSON file holds a list of items, or what an export of a list holds")
    if row.kind == "json":
        raise ListError("A list that is one document is imported from JSON")
    rows = [line for line in csv.reader(io.StringIO(text)) if any(cell.strip() for cell in line)]
    if not rows:
        return []
    header = [cell.strip().lower() for cell in rows[0]]
    if "key" not in header:
        # No header: one value on each line.
        return [{"key": line[0].strip()} for line in rows if line[0].strip()]
    columns = [column["name"] for column in row.columns or []]
    entries = []
    for line in rows[1:]:
        cells = dict(zip(header, (cell.strip() for cell in line), strict=False))
        if not cells.get("key"):
            continue
        entry: dict[str, Any] = {"key": cells["key"], "note": cells.get("note", "")}
        if row.kind == "key_value":
            if columns:
                entry["value"] = {column: cells.get(column.lower(), "") for column in columns}
            else:
                raw = cells.get("value", "")
                try:
                    entry["value"] = json.loads(raw)
                except ValueError:
                    entry["value"] = raw
        entries.append(entry)
    return entries


# --------------------------------------------------------------------------- #
# The settings that became lists                                              #
# --------------------------------------------------------------------------- #
def _settings_doc(db: OrmSession, setting: str) -> tuple[Setting | None, dict, str]:
    """The row, the dictionary inside its document and the key a setting lives at."""
    if setting.startswith("state."):
        row = db.get(Setting, AUTOMATION_SETTINGS_ID)
        return row, (row.doc if row is not None else None) or {}, setting[6:]
    row = db.get(Setting, SETTINGS_ID)
    doc = (row.doc if row is not None else None) or {}
    if "." in setting:
        outer, key = setting.split(".", 1)
        inner = doc.get(outer)
        return row, inner if isinstance(inner, dict) else {}, key
    return row, doc, setting


def pointers_of(db: OrmSession) -> dict[str, str]:
    """setting → the list it reads (the one Nik ships, unless another was chosen)."""

    def read() -> dict[str, str]:
        found = {}
        for setting, name in BY_SETTING.items():
            _row, holder, key = _settings_doc(db, setting)
            held = holder.get(key)
            found[setting] = str(held["list"]) if isinstance(held, dict) and held.get("list") else name
        return found

    return _cached("\0pointers", read)


def _as_setting(db: OrmSession, setting: str, name: str) -> Any:
    """What a list holds, in the shape the setting always had."""
    if setting == "keywords":
        return [
            {"id": item["key"], **(item["value"] if isinstance(item["value"], dict) else {})}
            for item in items(db, name)
        ]
    if setting == "businessHours":
        return document(db, name)
    return values(db, name)


def settings_value(db: OrmSession, setting: str, default: Any) -> Any:
    """A setting that became a list, as its readers know it. ``default`` until the lists are there."""
    name = pointers_of(db)[setting]
    if find(db, name) is None:
        _row, holder, key = _settings_doc(db, setting)
        held = holder.get(key)
        return default if held is None or (isinstance(held, dict) and "list" in held) else held
    found = _as_setting(db, setting, name)
    return default if found is None else found


def _entries_of(setting: str, value: Any) -> Any:
    """A setting's value as the items of its list."""
    if setting == "keywords":
        entries = []
        for item in value or []:
            if isinstance(item, dict) and str(item.get("id") or "").strip():
                entries.append(
                    {"key": str(item["id"]).strip(), "value": {key: item[key] for key in item if key != "id"}}
                )
        return entries
    if setting == "businessHours":
        return value if isinstance(value, dict) else {}
    return [str(entry).strip() for entry in value or [] if str(entry).strip()]


def apply_setting(db: OrmSession, setting: str, value: Any, actor: str) -> None:
    """Write a setting the old way: its list takes what was sent (the caller commits)."""
    name = pointers_of(db)[setting]
    row = find(db, name) or _make_builtin(db, BY_SETTING[setting] if name not in BUILTIN else name, actor)
    # The settings API cleaned what it was sent, as it always did.
    set_items(db, row, _entries_of(setting, value), actor, check=False)


def point(db: OrmSession, setting: str, name: str) -> None:
    """Choose which list a feature reads (the caller commits)."""
    if setting not in BY_SETTING:
        raise ListError("This setting does not read a list")
    row = find(db, name)
    wanted = BUILTIN[BY_SETTING[setting]]["kind"]
    if row is None or row.kind != wanted:
        raise ListError(f"Choose a list of kind {wanted} that exists")
    target, holder, key = _settings_doc(db, setting)
    if target is None:
        target = Setting(id=AUTOMATION_SETTINGS_ID if setting.startswith("state.") else SETTINGS_ID, doc={})
        db.add(target)
    doc = dict(target.doc or {})
    if "." in setting and not setting.startswith("state."):
        outer = setting.split(".", 1)[0]
        doc[outer] = {**(doc.get(outer) if isinstance(doc.get(outer), dict) else {}), key: {"list": name}}
    else:
        doc[key] = {"list": name}
    target.doc = doc
    flag_modified(target, "doc")
    clear_cache()


def _make_builtin(db: OrmSession, name: str, actor: str = "nik") -> NamedList:
    spec = BUILTIN[name]
    row = NamedList(
        id=uuid.uuid4().hex,
        name=name,
        label=spec["label"],
        description=spec["description"],
        kind=spec["kind"],
        item_type=spec["item_type"],
        columns=spec.get("columns") or [],
        builtin=True,
        updated_at=now_iso(),
        updated_by=actor,
    )
    db.add(row)
    db.flush()
    return row


def _factory(setting: str) -> Any:
    from .automation.state import DEFAULTS as STATE_DEFAULTS
    from .defaults import default_settings_doc

    if setting.startswith("state."):
        return STATE_DEFAULTS.get(setting[6:])
    doc = default_settings_doc()
    if "." in setting:
        outer, key = setting.split(".", 1)
        return (doc.get(outer) or {}).get(key)
    return doc.get(setting)


def seed(db: OrmSession) -> int:
    """Add the lists Nik ships that are missing, each filled from what its setting held
    (or from the factory value), and leave ``{"list": name}`` where the value was. A list that
    exists is left as it is. The caller commits; returns how many were added."""
    added = 0
    for name, spec in BUILTIN.items():
        if find(db, name) is not None:
            continue
        setting = spec["setting"]
        target, holder, key = _settings_doc(db, setting)
        held = holder.get(key)
        moved = held is not None and not (isinstance(held, dict) and "list" in held)
        row = _make_builtin(db, name)
        # Moved as it was: what a setting held is not judged again.
        set_items(db, row, _entries_of(setting, held if moved else _factory(setting)), "nik", check=False)
        if moved and target is not None:
            doc = dict(target.doc or {})
            if "." in setting and not setting.startswith("state."):
                outer = setting.split(".", 1)[0]
                doc[outer] = {**(doc.get(outer) or {}), key: {"list": name}}
            else:
                doc[key] = {"list": name}
            target.doc = doc
            flag_modified(target, "doc")
        added += 1
    if added:
        clear_cache()
    return added


def unseed(db: OrmSession) -> None:
    """Put back in the settings what their lists hold (a downgrade)."""
    pointers = pointers_of(db)
    for setting in BY_SETTING:
        target, holder, key = _settings_doc(db, setting)
        held = holder.get(key)
        if target is None or not (isinstance(held, dict) and "list" in held):
            continue
        value = _as_setting(db, setting, pointers[setting])
        doc = dict(target.doc or {})
        if "." in setting and not setting.startswith("state."):
            outer = setting.split(".", 1)[0]
            doc[outer] = {**(doc.get(outer) or {}), key: value}
        else:
            doc[key] = value
        target.doc = doc
        flag_modified(target, "doc")
    clear_cache()
