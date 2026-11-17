"""The context of an incident: what is known of it, as data playbooks read and write.

One JSON document per incident (``incident_context``):

    File, Mail, URL, IP, Domain, Host, Account, Ticket, Alert, Process, Rule
        Nik's **common schema**: lists of objects with fixed, PascalCase keys,
        whatever product a value came from. ``{{ context.Ticket[0].Number }}``.
    ext.<connector>.<name>
        What a connector knows that has no place in the common schema.

The fields of the incident are not stored here: ``{{ incident.severity }}``
reads them from the registry, and a write to ``incident.<field>`` goes through
``fields.update``.

Nothing writes the document freely. A command or a script declares where an
output goes with a **context path**, and only three forms exist:

    Ticket                              append the object (each one of a list)
    Ticket(val.ID == obj.ID)            upsert by that key: merge over the item
                                        that has it, append when none has
    Ticket.Status                       set a key on the one item there is

An entity named alone upserts by its default key (``File.SHA256``,
``Ticket.ID`` …) when the object has it. The key expression is exactly
``val.<Key> == obj.<Key>``, joined by ``&&``; nothing else is parsed.

**Provenance** (``incident_context_meta``): for every item of an entity and
every ``ext`` key, who set it last (``nik``, ``connector:<id>``,
``user:<name>``, ``run:<id>``) and when. It decides whether what a connector
fetches later may overwrite a value: see ``may_overwrite``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy import delete, select, update
from sqlalchemy.orm import Session as OrmSession

from .core.models import Incident, IncidentContext, IncidentContextMeta
from .core.security import now_iso

MAX_BYTES = 4_000_000
ITEMS_MAX = 2000  # of one entity
RETRIES = 3

# The common schema: entity → (its keys, the keys an item is told apart by).
SCHEMA: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "File": (("Name", "Size", "Type", "MD5", "SHA1", "SHA256", "Path", "Verdict", "Score"), ("SHA256",)),
    "IP": (("Address", "ASN", "Geo", "Verdict", "Score"), ("Address",)),
    "Domain": (("Name", "Registrar", "Created", "Verdict", "Score"), ("Name",)),
    "URL": (("Data", "Host", "Verdict", "Score"), ("Data",)),
    "Mail": (
        ("MessageID", "Subject", "From", "To", "Date", "Verdict", "Score", "Recipients"),
        ("MessageID",),
    ),
    "Host": (("Name", "IP", "OS", "Domain", "AgentID", "Isolated"), ("Name",)),
    "Account": (("Username", "Email", "DisplayName", "Disabled"), ("Username",)),
    "Ticket": (("ID", "Number", "System", "URL", "Status"), ("ID",)),
    "Alert": (("ID", "Name", "Severity", "Source", "URL", "Time"), ("ID",)),
    "Process": (("Name", "PID", "CommandLine", "Host", "SHA256"), ("PID", "Host")),
    "Rule": (("Name", "ID"), ("Name",)),
}
ENTITIES = tuple(SCHEMA)

# The classes of data of what the common schema holds, for the data guard (automation/guard.py).
CLASSES: dict[str, list[str]] = {
    "File.Name": ["attachment_name"],
    "File.Path": ["private_value"],
    "File.MD5": ["hash"],
    "File.SHA1": ["hash"],
    "File.SHA256": ["hash"],
    "File.Verdict": ["verdict"],
    "File.Score": ["verdict"],
    "Mail.Subject": ["subject"],
    "Mail.From": ["email_address"],
    "Mail.To": ["email_address"],
    "Mail.Recipients": ["email_address"],
    "Mail.Verdict": ["verdict"],
    "Mail.Score": ["verdict"],
    "Host.Name": ["private_value"],
    "Host.IP": ["private_value"],
    "Host.Domain": ["private_value"],
    "Account.Username": ["private_value"],
    "Account.Email": ["email_address"],
    "Account.DisplayName": ["private_value"],
    "Process.CommandLine": ["private_value"],
    "Process.Host": ["private_value"],
    "Process.SHA256": ["hash"],
    "IP.Verdict": ["verdict"],
    "IP.Score": ["verdict"],
    "Domain.Verdict": ["verdict"],
    "Domain.Score": ["verdict"],
    "URL.Verdict": ["verdict"],
    "URL.Score": ["verdict"],
}

_NAME = r"[A-Za-z][A-Za-z0-9_]*"
_KEY_PAIR = re.compile(rf"^\s*val\.({_NAME})\s*==\s*obj\.({_NAME})\s*$")
_PATH = re.compile(rf"^({_NAME})(?:\((.*)\))?((?:\.{_NAME})*)$")
_EXT = re.compile(r"^ext\.([a-z][a-z0-9-]{1,40})\.([A-Za-z][A-Za-z0-9_]{0,60})$")
_FIELD = re.compile(r"^incident\.([a-z][a-z0-9_]{1,40})$")


class ContextError(ValueError):
    """What is wrong with a context path or with what was written, as a sentence."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass(frozen=True)
class Path:
    """A context path, read: where a value goes."""

    kind: str  # entity | ext | field
    entity: str = ""
    keys: tuple[str, ...] = ()  # entity: the keys an item is found by (empty: the default ones)
    sub: tuple[str, ...] = ()  # entity: the key to set on the one item
    connector: str = ""  # ext
    name: str = ""  # ext, field


def parse(text: str) -> Path:
    """Read a context path. Raises ``ContextError`` with what is wrong."""
    text = str(text or "").strip()
    found = _FIELD.match(text)
    if found:
        return Path(kind="field", name=found.group(1))
    found = _EXT.match(text)
    if found:
        return Path(kind="ext", connector=found.group(1), name=found.group(2))
    found = _PATH.match(text)
    if not found or found.group(1) not in SCHEMA:
        raise ContextError(
            f'"{text}" is not a context path: an entity ({", ".join(ENTITIES)}), '
            "ext.<connector>.<name> or incident.<field>"
        )
    entity, key_text, sub_text = found.group(1), found.group(2), found.group(3)
    keys: list[str] = []
    if key_text is not None:
        for part in key_text.split("&&"):
            pair = _KEY_PAIR.match(part)
            if not pair or pair.group(1) != pair.group(2):
                raise ContextError(f'The key of "{text}" is written val.<Key> == obj.<Key>, joined by &&')
            keys.append(pair.group(1))
    sub = tuple(part for part in sub_text.split(".") if part)
    if sub and keys:
        raise ContextError(f'"{text}" sets a key on the one item there is: it takes no key expression')
    if len(sub) > 1:
        raise ContextError(f'"{text}" goes too deep: an entity, then one of its keys')
    for name in (*keys, *sub):
        if name not in SCHEMA[entity][0]:
            raise ContextError(f"{entity} has no key called {name}: " + ", ".join(SCHEMA[entity][0]))
    return Path(kind="entity", entity=entity, keys=tuple(keys), sub=sub)


def problem(text: str) -> str | None:
    """Why a context path cannot be used (None when it can)."""
    try:
        parse(text)
    except ContextError as error:
        return error.message
    return None


# --------------------------------------------------------------------------- #
# Reading                                                                     #
# --------------------------------------------------------------------------- #
def read(db: OrmSession, incident_id: str) -> dict[str, Any]:
    row = db.get(IncidentContext, incident_id)
    return dict(row.data or {}) if row is not None else {}


def provenance(db: OrmSession, incident_id: str) -> dict[str, dict[str, str]]:
    """path key → {source, at}."""
    rows = db.scalars(select(IncidentContextMeta).where(IncidentContextMeta.incident_id == incident_id))
    return {row.path_key: {"source": row.source, "at": row.at} for row in rows}


def classes() -> dict[str, list[str]]:
    """The classes of the context, as a scope of expressions takes them."""
    return dict(CLASSES)


def item_key(entity: str, item: dict, keys: tuple[str, ...] = ()) -> str | None:
    """What tells an item of an entity apart ("" joined by +): None when it lacks one of the keys."""
    parts = []
    for key in keys or SCHEMA[entity][1]:
        value = item.get(key)
        if value in (None, ""):
            return None
        parts.append(str(value))
    return "+".join(parts)


def path_key(entity: str, item: dict) -> str | None:
    """The provenance key of an item: ``Ticket:<its key>``."""
    key = item_key(entity, item)
    return f"{entity}:{key}"[:400] if key else None


# --------------------------------------------------------------------------- #
# Writing                                                                     #
# --------------------------------------------------------------------------- #
def _clean_item(entity: str, value: Any) -> dict:
    if not isinstance(value, dict):
        raise ContextError(f"{entity} takes objects with the keys " + ", ".join(SCHEMA[entity][0]))
    unknown = [key for key in value if key not in SCHEMA[entity][0]]
    if unknown:
        raise ContextError(
            f"{entity} has no key called {unknown[0]}: " + ", ".join(SCHEMA[entity][0]) + " (the rest goes under ext)"
        )
    return {key: item for key, item in value.items() if item not in (None, "", [], {})}


def _merge(data: dict, path: Path, value: Any) -> list[str]:
    """Apply one write to the document; returns the provenance keys it touched."""
    if path.kind == "ext":
        branch = data.setdefault("ext", {}).setdefault(path.connector, {})
        if value in (None, "", [], {}):
            branch.pop(path.name, None)
        else:
            branch[path.name] = value
        return [f"ext.{path.connector}.{path.name}"]
    items = data.setdefault(path.entity, [])
    if not isinstance(items, list):
        items = data[path.entity] = []
    if path.sub:
        if len(items) != 1:
            raise ContextError(
                f"{path.entity}.{path.sub[0]} sets a key on the one {path.entity} there is: there are {len(items)}"
            )
        cleaned = _clean_item(path.entity, {**items[0], path.sub[0]: value})
        items[0] = cleaned
        key = path_key(path.entity, cleaned)
        return [key] if key else []
    touched = []
    for raw in value if isinstance(value, list) else [value]:
        new = _clean_item(path.entity, raw)
        if not new:
            continue
        keys = path.keys
        wanted = item_key(path.entity, new, keys)
        if path.keys and wanted is None:
            raise ContextError(f"What goes to {path.entity} lacks its key: " + ", ".join(path.keys))
        index = None
        if wanted is not None:
            index = next(
                (
                    at
                    for at, old in enumerate(items)
                    if isinstance(old, dict) and item_key(path.entity, old, keys) == wanted
                ),
                None,
            )
        if index is None:
            if len(items) >= ITEMS_MAX:
                raise ContextError(f"The context holds {ITEMS_MAX} {path.entity} at most")
            items.append(new)
            merged = new
        else:
            # A shallow merge: the new keys over the old ones, lists replaced.
            merged = items[index] = {**items[index], **new}
        key = path_key(path.entity, merged)
        if key:
            touched.append(key)
    return touched


def apply(db: OrmSession, incident: Incident, writes: list[tuple[str, Any]], source: str, actor: str = "") -> list[str]:
    """Write to the context of an incident (the caller commits). Returns the provenance keys written.

    ``writes`` is a list of ``(context path, value)``. A write to
    ``incident.<field>`` goes to the field registry. The document is replaced
    with a compare-and-swap on its version, tried three times; over 4 MB the
    write is refused with what would make it so.
    """
    from . import fields as registry

    parsed = [(parse(path), value) for path, value in writes]
    field_changes = {path.name: value for path, value in parsed if path.kind == "field"}
    if field_changes:
        try:
            registry.update(db, incident, field_changes, actor or source, source)
        except registry.FieldError as error:
            raise ContextError(error.message) from None
    rest = [(path, value) for path, value in parsed if path.kind != "field"]
    if not rest:
        return [f"field:{name}" for name in field_changes]
    for _attempt in range(RETRIES):
        row = db.get(IncidentContext, incident.id)
        if row is None:
            row = IncidentContext(incident_id=incident.id, data={}, version=0, updated_at=now_iso())
            db.add(row)
            db.flush()
        data = json.loads(json.dumps(row.data or {}))  # a copy to work on
        touched: list[str] = []
        for path, value in rest:
            touched += _merge(data, path, value)
        size = len(json.dumps(data))
        if size > MAX_BYTES:
            raise ContextError("The context of an incident holds 4 MB at most: this write would take it over")
        stamp = now_iso()
        swapped = db.execute(
            update(IncidentContext)
            .where(IncidentContext.incident_id == incident.id, IncidentContext.version == row.version)
            .values(data=data, version=row.version + 1, updated_at=stamp)
        ).rowcount
        if swapped:
            db.expire(row)
            for key in dict.fromkeys(touched):
                meta = db.get(IncidentContextMeta, (incident.id, key))
                if meta is None:
                    db.add(IncidentContextMeta(incident_id=incident.id, path_key=key, source=source, at=stamp))
                else:
                    meta.source, meta.at = source, stamp
            return [*(f"field:{name}" for name in field_changes), *dict.fromkeys(touched)]
        db.expire(row)  # someone wrote in between: read it again
    raise ContextError("The context was being written by something else: try again")


def forget(db: OrmSession, incident_id: str) -> None:
    """Drop the context of an incident that is deleted."""
    db.execute(delete(IncidentContextMeta).where(IncidentContextMeta.incident_id == incident_id))
    db.execute(delete(IncidentContext).where(IncidentContext.incident_id == incident_id))


def may_overwrite(last_source: str | None, source: str, authoritative: bool = False) -> bool:
    """Whether a value a connector brings (a fetch, a mirror) may replace what is there.

    What that connector set itself, or nobody set: yes. What a person or
    Nik's own analysis set last: no, unless the mapper marks the field
    authoritative. What another connector or a run set: yes.
    """
    if last_source is None or last_source == source or authoritative:
        return True
    return not (last_source.startswith("user:") or last_source == "nik")


# --------------------------------------------------------------------------- #
# What Nik's own analysis knows                                               #
# --------------------------------------------------------------------------- #
def analysis_items(samples: dict, mails: dict, urls: dict, names: dict[str, str]) -> list[tuple[str, dict]]:
    """(entity, item) for the files, e-mails and addresses an incident references, from their analysis."""
    from . import artifacts

    found: list[tuple[str, dict]] = []
    for sample in list(samples.values())[:200]:
        verdict = artifacts.file_verdict(sample.analysis or {}, sample.size)
        item = {
            "Name": names.get(sample.sha256) or "",
            "Size": sample.size,
            "Type": sample.type_label or "",
            "MD5": sample.md5,
            "SHA1": sample.sha1,
            "SHA256": sample.sha256,
            "Verdict": verdict,
        }
        found.append(("File", item))
    for mail in list(mails.values())[:200]:
        who = (mail.analysis or {}).get("sender") or {}
        item = {
            # A message with no Message-ID is told apart by its hash.
            "MessageID": str(who.get("messageId") or "").strip("<> ") or mail.sha256,
            "Subject": mail.subject or "",
            "From": mail.sender or "",
            "Date": _iso_ms(mail.sent_at),
            "Verdict": mail.verdict or "",
            "Score": mail.score,
        }
        found.append(("Mail", item))
    for scan in list(urls.values())[:200]:
        if scan.status != "done":
            continue
        found.append(
            ("URL", {"Data": scan.url, "Host": scan.host or "", "Verdict": scan.verdict or "", "Score": scan.score})
        )
    return [(entity, {key: value for key, value in item.items() if value not in (None, "")}) for entity, item in found]


def _iso_ms(ms: Any) -> str:
    from datetime import datetime, timezone

    if not isinstance(ms, (int, float)) or isinstance(ms, bool):
        return ""
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return ""


def sync_analysis(db: OrmSession, incident: Incident, samples: dict, mails: dict, urls: dict, names: dict) -> int:
    """Put what Nik analysed for the incident in its context, as ``nik``. Writes only what is new
    or changed, so saving an incident again costs nothing. Returns how many items were written."""
    current = read(db, incident.id)
    writes: list[tuple[str, Any]] = []
    for entity, item in analysis_items(samples, mails, urls, names):
        key = item_key(entity, item)
        held = next(
            (old for old in current.get(entity) or [] if isinstance(old, dict) and item_key(entity, old) == key), None
        )
        if held is None or any(held.get(name) != value for name, value in item.items()):
            writes.append((entity, item))
    if not writes:
        return 0
    try:
        apply(db, incident, writes, "nik")
    except ContextError:
        return 0  # a context that is full keeps what it has: the analysis itself is not lost
    return len(writes)
