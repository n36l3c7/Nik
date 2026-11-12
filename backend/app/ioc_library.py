"""The IoC library: every indicator Nik knows, lists of them, import and export.

An indicator is in the library when an incident holds it (``ioc_index``),
when an analyst added it (``iocs``) or when it is in a list
(``ioc_list_items``). ``library`` merges the three into one row per
``(type, value)`` with its reputation; the routes filter, sort and page it.

``parse`` reads what an analyst pastes or drops: free text (defanged values
included), CSV with a ``value`` column, a STIX 2.1 bundle, a MISP event or
Nik's own JSON export.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import date, datetime, timezone
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from .core.models import Incident, IocAlert, IocEntry, IocList, IocListItem, IocRecord
from .enrichment import service
from .enrichment.providers import PROVIDERS
from .iocs import TYPES, Allowlist, misp_event, normalize, stix_bundle, text_iocs

TLPS = ("clear", "green", "amber", "red")
TAG_RE = re.compile(r"[a-z0-9][a-z0-9._:-]{0,39}")
TAGS_MAX = 12
NOTE_MAX = 2000
MAX_BATCH = 10_000
MAX_TEXT = 5_000_000

Pair = tuple[str, str]

# What an export can hold; ``DEFAULT_FIELDS`` are ticked when nothing is chosen.
FIELDS = (
    "type",
    "value",
    "verdict",
    "score",
    "tags",
    "first_seen",
    "last_checked",
    "sources_flagging",
    "per_source",
    "incidents",
    "lists",
    "note",
    "tlp",
    "origin",
    "added_by",
    "expires",
)
DEFAULT_FIELDS = ("type", "value", "verdict", "score", "tags", "first_seen")


# --------------------------------------------------------------------------- #
# Reading what is pasted or dropped                                           #
# --------------------------------------------------------------------------- #
_REFANG = (
    (re.compile(r"\bh(?:xx|XX)p(s?)://", re.IGNORECASE), r"http\1://"),
    (re.compile(r"\[(?:\.|dot)\]|\((?:\.|dot)\)|\{\.\}", re.IGNORECASE), "."),
    (re.compile(r"\[(?:@|at)\]|\(at\)", re.IGNORECASE), "@"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
)


def refang(text: str) -> str:
    """``hxxps://evil[.]example`` as it is meant: ``https://evil.example``."""
    for pattern, replacement in _REFANG:
        text = pattern.sub(replacement, text)
    return text


def defang(kind: str, value: str) -> str:
    if kind in ("md5", "sha1", "sha256"):
        return value
    return re.sub(r"^http", "hxxp", value, flags=re.IGNORECASE).replace(".", "[.]").replace("@", "[@]")


_HOSTNAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}", re.IGNORECASE)


def _bare_hosts(line: str) -> list[Pair]:
    """Host names written on their own, whatever their top-level domain: the
    text patterns only know the common ones."""
    found = []
    for token in re.split(r"[\s,;|]+", line):
        token = token.strip("\"'<>()[]")
        if _HOSTNAME.fullmatch(token):
            clean = normalize("domain", token)
            if clean:
                found.append(("domain", clean))
    return found


def detect(value: str) -> Pair | None:
    """The type of one value, or None."""
    text = refang(str(value or "").strip())
    if not text:
        return None
    found = text_iocs(text)
    for kind, raw in found:
        clean = normalize(kind, raw)
        if clean and clean.lower() == normalize(kind, text.rstrip("/") if kind != "url" else text):
            return kind, clean
    if found:
        kind, raw = found[0]
        clean = normalize(kind, raw)
        if clean:
            return kind, clean
    bare = _bare_hosts(text)
    return bare[0] if bare else None


def clean_tags(tags: Iterable[Any]) -> list[str]:
    kept: list[str] = []
    for tag in tags or []:
        text = str(tag or "").strip().lower().lstrip("#")
        if TAG_RE.fullmatch(text) and text not in kept:
            kept.append(text)
    return kept[:TAGS_MAX]


def clean_date(value: Any) -> str | None:
    """``YYYY-MM-DD`` or None; raises ValueError on anything else."""
    if value in (None, ""):
        return None
    return date.fromisoformat(str(value)[:10]).isoformat()


def _item(kind: str, value: str, **fields: Any) -> dict[str, Any] | None:
    clean = normalize(kind, refang(str(value or "")))
    if kind not in TYPES or clean is None:
        return None
    item: dict[str, Any] = {"type": kind, "value": clean}
    if clean_tags(fields.get("tags") or []):
        item["tags"] = clean_tags(fields["tags"])
    if fields.get("note"):
        item["note"] = str(fields["note"])[:NOTE_MAX]
    if str(fields.get("tlp") or "").lower().replace("tlp:", "") in TLPS:
        item["tlp"] = str(fields["tlp"]).lower().replace("tlp:", "")
    if fields.get("expires"):
        try:
            item["expires"] = clean_date(fields["expires"])
        except ValueError:
            pass
    if fields.get("lists"):
        item["lists"] = [str(name).strip()[:120] for name in fields["lists"] if str(name).strip()][:20]
    return item


_STIX_VALUE = re.compile(r"=\s*'((?:[^'\\]|\\.)*)'")
_STIX_KINDS = (
    ("ipv4-addr:value", "ip"),
    ("ipv6-addr:value", "ip"),
    ("domain-name:value", "domain"),
    ("url:value", "url"),
    ("email-addr:value", "email"),
    ("MD5", "md5"),
    ("SHA-1", "sha1"),
    ("SHA-256", "sha256"),
)
_MISP_KINDS = {
    "ip-dst": "ip",
    "ip-src": "ip",
    "domain": "domain",
    "hostname": "domain",
    "url": "url",
    "link": "url",
    "email-src": "email",
    "email-dst": "email",
    "email": "email",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
}


def _from_json(doc: Any) -> tuple[str, list[dict[str, Any]], list[str]] | None:
    """Indicators of a known JSON document: ``(format, items, list names)``."""
    if isinstance(doc, dict) and doc.get("format") == "nik-iocs" and isinstance(doc.get("iocs"), list):
        items = []
        for row in doc["iocs"]:
            if isinstance(row, dict):
                tags = row.get("tags")
                item = _item(
                    str(row.get("type") or ""),
                    row.get("value"),
                    tags=tags.split(";") if isinstance(tags, str) else tags,
                    note=row.get("note"),
                    tlp=row.get("tlp"),
                    expires=row.get("expires"),
                    lists=row.get("lists").split(";") if isinstance(row.get("lists"), str) else row.get("lists"),
                )
                if item:
                    items.append(item)
        return "nik", items, []
    if isinstance(doc, dict) and doc.get("type") == "bundle" and isinstance(doc.get("objects"), list):
        items = []
        for obj in doc["objects"]:
            if not isinstance(obj, dict) or obj.get("type") != "indicator":
                continue
            pattern = str(obj.get("pattern") or "")
            for marker, kind in _STIX_KINDS:
                if marker in pattern:
                    for raw in _STIX_VALUE.findall(pattern):
                        item = _item(kind, raw.replace("\\'", "'").replace("\\\\", "\\"), tags=obj.get("labels"))
                        if item:
                            items.append(item)
                    break
        return "stix", items, []
    event = doc.get("Event") if isinstance(doc, dict) else None
    if isinstance(event, dict):
        attributes = list(event.get("Attribute") or [])
        for obj in event.get("Object") or []:
            if isinstance(obj, dict):
                attributes += list(obj.get("Attribute") or [])
        items = []
        for attribute in attributes:
            if not isinstance(attribute, dict):
                continue
            kind = _MISP_KINDS.get(str(attribute.get("type") or ""))
            if kind:
                item = _item(kind, str(attribute.get("value") or "").split("|")[0], note=attribute.get("comment"))
                if item:
                    items.append(item)
        info = str(event.get("info") or "").strip()
        return "misp", items, [info[:120]] if info else []
    return None


_CSV_VALUE = ("value", "indicator", "ioc", "observable")


def _from_csv(text: str) -> list[dict[str, Any]] | None:
    """Rows of a CSV whose header names a value column; None when it is not one."""
    first = text.lstrip().split("\n", 1)[0]
    if not any(sep in first for sep in ",;\t"):
        return None
    try:
        dialect = csv.Sniffer().sniff(first, delimiters=",;\t")
    except csv.Error:
        return None
    reader = csv.DictReader(io.StringIO(text.lstrip()), dialect=dialect)
    names = {str(name or "").strip().lower(): name for name in reader.fieldnames or []}
    column = next((names[key] for key in _CSV_VALUE if key in names), None)
    if column is None:
        return None
    items = []
    for row in reader:
        raw = str(row.get(column) or "").strip()
        kind = str(row.get(names.get("type", "")) or "").strip().lower()
        found = (kind, raw) if kind in TYPES else detect(raw)
        if not found:
            continue
        item = _item(
            found[0],
            found[1] if kind not in TYPES else raw,
            tags=re.split(r"[;|]", str(row.get(names.get("tags", "")) or "")),
            note=row.get(names.get("note", "")),
            tlp=row.get(names.get("tlp", "")),
            expires=row.get(names.get("expires", "")),
        )
        if item:
            items.append(item)
        if len(items) >= MAX_BATCH:
            break
    return items


def parse(text: str) -> dict[str, Any]:
    """What a paste or a dropped file holds: ``{format, items, lists, unrecognised, repeated}``.

    Items come out once each, in the order met; ``unrecognised`` lists the
    lines of free text that held no indicator (at most 50)."""
    text = str(text or "")[:MAX_TEXT]
    source, items, lists, unrecognised = "text", [], [], []
    stripped = text.lstrip()
    known = None
    if stripped[:1] in "{[":
        try:
            known = _from_json(json.loads(stripped))
        except ValueError:
            known = None
    if known:
        source, items, lists = known
    else:
        rows = _from_csv(text)
        if rows is not None:
            source, items = "csv", rows
        else:
            for line in text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                found = [(k, normalize(k, v)) for k, v in text_iocs(refang(line))]
                found = [(k, v) for k, v in found if v]
                # The host of a URL is its own indicator in an incident; in a
                # list an analyst wrote, the URL is what was meant.
                urls = [v for k, v in found if k == "url"]
                found = [(k, v) for k, v in found if k == "url" or not any(v in url for url in urls)]
                found = found or _bare_hosts(refang(line))
                if not found and len(unrecognised) < 50:
                    unrecognised.append(line[:200])
                items += [{"type": k, "value": v} for k, v in found]
    seen: dict[Pair, dict[str, Any]] = {}
    repeated = 0
    for item in items:
        pair = (item["type"], item["value"])
        if pair in seen:
            repeated += 1
            continue
        seen[pair] = item
        if len(seen) >= MAX_BATCH:
            break
    return {
        "format": source,
        "items": list(seen.values()),
        "lists": lists,
        "unrecognised": unrecognised,
        "repeated": repeated,
    }


# --------------------------------------------------------------------------- #
# The library                                                                 #
# --------------------------------------------------------------------------- #
def today() -> str:
    return datetime.now(timezone.utc).date().isoformat()


def _iso_ms(ms: int | None) -> str | None:
    if not ms:
        return None
    try:
        return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).isoformat()
    except (ValueError, OverflowError, OSError):
        return None


def never_sent(kind: str, value: str, allowlist: Allowlist, red: bool) -> str | None:
    """Why the indicator is not sent to the sources, without a query per row."""
    if red:
        return "it is classified TLP:RED"
    return service.blocked(None, kind, value, allowlist, red=set())  # type: ignore[arg-type]


def red_pairs(db: OrmSession) -> set[Pair]:
    """Indicators an analyst, a list or an incident classified TLP:RED."""
    pairs = {(t, v) for t, v in db.execute(select(IocRecord.type, IocRecord.value).where(IocRecord.tlp == "red"))}
    pairs |= {
        (t, v)
        for t, v in db.execute(
            select(IocListItem.type, IocListItem.value)
            .join(IocList, IocList.id == IocListItem.list_id)
            .where(IocList.tlp == "red")
        )
    }
    red = service.red_incidents(db)
    if red:
        pairs |= {
            (t, v) for t, v in db.execute(select(IocEntry.type, IocEntry.value).where(IocEntry.incident_id.in_(red)))
        }
    return pairs


def library(db: OrmSession, shared: dict[str, Any], only: set[Pair] | None = None) -> list[dict[str, Any]]:
    """One row per indicator, with where it comes from and its reputation.
    ``only`` limits the rows to those pairs."""
    allowlist = Allowlist(shared.get("iocAllowlist") or [])
    cfg = service.config(shared)
    rows: dict[Pair, dict[str, Any]] = {}

    def row(kind: str, value: str) -> dict[str, Any] | None:
        pair = (kind, value)
        if only is not None and pair not in only:
            return None
        found = rows.get(pair)
        if found is None:
            found = rows[pair] = {
                "type": kind,
                "value": value,
                "origin": "incident",
                "incidents": 0,
                "firstSeen": None,
                "tags": [],
                "note": "",
                "tlp": None,
                "expires": None,
                "expired": False,
                "addedBy": None,
                "addedAt": None,
                "removable": False,
                "lists": [],
            }
        return found

    indexed = db.execute(
        select(IocEntry.type, IocEntry.value, func.count(IocEntry.incident_id), func.min(IocEntry.first_seen)).group_by(
            IocEntry.type, IocEntry.value
        )
    )
    for kind, value, incidents, first in indexed:
        item = row(kind, value)
        if item:
            item["incidents"] = incidents
            item["firstSeen"] = _iso_ms(first)
    now = today()
    for record in db.scalars(select(IocRecord)):
        item = row(record.type, record.value)
        if item:
            item.update(
                origin=record.origin if not item["incidents"] else "incident",
                tags=list(record.tags or []),
                note=record.note,
                tlp=record.tlp,
                expires=record.expires_at,
                expired=bool(record.expires_at and record.expires_at < now),
                addedBy=record.created_by,
                addedAt=record.created_at,
                removable=True,
            )
            item["firstSeen"] = item["firstSeen"] or record.created_at
    names = dict(db.execute(select(IocList.id, IocList.name)).all())
    for list_id, kind, value, added_at in db.execute(
        select(IocListItem.list_id, IocListItem.type, IocListItem.value, IocListItem.added_at)
    ):
        item = row(kind, value)
        if item:
            item["lists"].append({"id": list_id, "name": names.get(list_id, "")})
            item["firstSeen"] = item["firstSeen"] or added_at
            if item["origin"] == "incident" and not item["incidents"]:
                item["origin"] = "manual"

    from . import analysis_links

    # Indicators of the artifacts analysed on their own, with no incident.
    for (kind, value), holders in analysis_links.standalone(db).items():
        known = (kind, value) in rows
        item = row(kind, value)
        if item:
            item["artifacts"] = holders[:5]
            if not known:
                item["origin"] = "artifact"
                item["firstSeen"] = holders[-1]["createdAt"]
    analysed = analysis_links.analyses_for(db, rows.keys()) if rows else {}
    reputation = service.summaries(db, rows.keys()) if rows else {}
    checked: dict[Pair, str] = {}
    if rows:
        from .core.models import Enrichment

        for kind, value, at in db.execute(
            select(Enrichment.type, Enrichment.value, func.max(Enrichment.checked_at)).group_by(
                Enrichment.type, Enrichment.value
            )
        ):
            checked[(kind, value)] = at
    red = red_pairs(db)
    for pair, item in rows.items():
        summary = reputation.get(pair)
        item["reputation"] = summary
        item["verdict"] = summary["verdict"] if summary else None
        item["score"] = summary["score"] if summary else None
        item["checkedAt"] = checked.get(pair)
        item["allowlisted"] = allowlist.matches(*pair)
        item["neverSent"] = never_sent(pair[0], pair[1], allowlist, pair in red)
        # What Nik saw when it analysed the value itself, if it did.
        found = analysed.get(pair) or []
        item["analysis"] = analysis_links.brief(found[0]) if found else None
        item["canAnalyse"] = pair[0] in ("url", "domain") and analysis_links.scan_id_of(pair[1]) is not None
        item.setdefault("artifacts", [])
    del cfg
    return list(rows.values())


VERDICT_RANK = {"malicious": 3, "suspicious": 2, "harmless": 1, "unknown": 0, None: -1}
SORTS = {
    "type": lambda r: (r["type"], r["value"]),
    "value": lambda r: r["value"],
    "verdict": lambda r: (VERDICT_RANK.get(r["verdict"], 0), r["score"] or 0),
    "score": lambda r: (r["score"] is not None, r["score"] or 0),
    "incidents": lambda r: r["incidents"],
    "checked": lambda r: r["checkedAt"] or "",
    "firstSeen": lambda r: r["firstSeen"] or "",
    "origin": lambda r: r["origin"],
}


def matches(row: dict[str, Any], filters: dict[str, Any]) -> bool:
    if filters.get("type") and row["type"] != filters["type"]:
        return False
    verdict = filters.get("verdict")
    if verdict == "none":
        if row["verdict"] is not None:
            return False
    elif verdict == "flagged":
        if row["verdict"] not in ("malicious", "suspicious"):
            return False
    elif verdict and row["verdict"] != verdict:
        return False
    origin = filters.get("origin")
    if origin == "added":
        if row["origin"] not in ("manual", "import"):
            return False
    elif origin and row["origin"] != origin:
        return False
    if filters.get("list") and not any(entry["id"] == filters["list"] for entry in row["lists"]):
        return False
    if filters.get("expired") is not None and row["expired"] != bool(filters["expired"]):
        return False
    analysis = filters.get("analysis")
    if analysis == "done" and not row.get("analysis"):
        return False
    if analysis == "none" and (row.get("analysis") or not row.get("canAnalyse")):
        return False
    text = str(filters.get("q") or "").strip().lower().lstrip("#")
    if text:
        haystack = [row["value"].lower(), row["note"].lower(), *row["tags"], *(e["name"].lower() for e in row["lists"])]
        if not any(text in part for part in haystack):
            return False
    return True


def select_rows(rows: list[dict[str, Any]], filters: dict[str, Any], sort: str = "", descending: bool = False):
    kept = [row for row in rows if matches(row, filters)]
    key = SORTS.get(sort)
    if key:
        kept.sort(key=lambda r: (r["type"], r["value"]))
        kept.sort(key=key, reverse=descending)
    else:
        kept.sort(key=lambda r: (-VERDICT_RANK.get(r["verdict"], 0), -(r["score"] or 0), r["type"], r["value"]))
    return kept


def counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    return {
        "all": len(rows),
        "added": sum(1 for r in rows if r["origin"] in ("manual", "import")),
        "toAnalyse": sum(1 for r in rows if r.get("canAnalyse") and not r.get("analysis")),
        "malicious": sum(1 for r in rows if r["verdict"] == "malicious"),
        "suspicious": sum(1 for r in rows if r["verdict"] == "suspicious"),
        "harmless": sum(1 for r in rows if r["verdict"] == "harmless"),
        "unchecked": sum(1 for r in rows if r["verdict"] is None),
        "expired": sum(1 for r in rows if r["expired"]),
        "inIncidents": sum(1 for r in rows if r["incidents"]),
    }


# --------------------------------------------------------------------------- #
# Writing                                                                     #
# --------------------------------------------------------------------------- #
def known_pairs(db: OrmSession, pairs: Iterable[Pair]) -> set[Pair]:
    """Which of the pairs the library already holds."""
    wanted = set(pairs)
    if not wanted:
        return set()
    found: set[Pair] = set()
    for model in (IocRecord, IocEntry, IocListItem):
        for kind in {k for k, _ in wanted}:
            values = [v for k, v in wanted if k == kind]
            for start in range(0, len(values), 500):
                chunk = values[start : start + 500]
                found |= {
                    (kind, v) for v in db.scalars(select(model.value).where(model.type == kind, model.value.in_(chunk)))
                }
    return found


def save_items(
    db: OrmSession,
    items: list[dict[str, Any]],
    actor: str,
    now: str,
    *,
    origin: str = "manual",
    tags: Iterable[str] = (),
    note: str = "",
    tlp: str | None = None,
    expires: str | None = None,
) -> dict[str, int]:
    """Keep each indicator as its own record. An indicator already in the
    library is kept as it is: only tags are added to what it has."""
    shared_tags = clean_tags(tags)
    pairs = [(item["type"], item["value"]) for item in items]
    existing = known_pairs(db, pairs)
    records = {}
    for kind in {k for k, _ in pairs}:
        values = [v for k, v in pairs if k == kind]
        for start in range(0, len(values), 500):
            chunk = values[start : start + 500]
            for record in db.scalars(select(IocRecord).where(IocRecord.type == kind, IocRecord.value.in_(chunk))):
                records[(record.type, record.value)] = record
    added = 0
    for item in items:
        pair = (item["type"], item["value"])
        merged_tags = clean_tags([*shared_tags, *(item.get("tags") or [])])
        record = records.get(pair)
        if record is None:
            record = records[pair] = IocRecord(
                type=pair[0],
                value=pair[1],
                origin=origin,
                tags=merged_tags,
                note=str(item.get("note") or note or "")[:NOTE_MAX],
                tlp=item.get("tlp") or tlp or "amber",
                expires_at=item.get("expires") or expires,
                created_at=now,
                created_by=actor,
                updated_at=now,
            )
            db.add(record)
            if pair not in existing:
                added += 1
        elif merged_tags:
            combined = clean_tags([*(record.tags or []), *merged_tags])
            if combined != list(record.tags or []):
                record.tags = combined
                record.updated_at = now
    return {"added": added, "existing": len(set(pairs) & existing), "total": len(set(pairs))}


def add_to_list(db: OrmSession, target: IocList, pairs: Iterable[Pair], actor: str, now: str) -> int:
    wanted = list(dict.fromkeys(pairs))
    have = {
        (t, v)
        for t, v in db.execute(select(IocListItem.type, IocListItem.value).where(IocListItem.list_id == target.id))
    }
    fresh = [pair for pair in wanted if pair not in have]
    db.add_all(IocListItem(list_id=target.id, type=t, value=v, added_at=now, added_by=actor) for t, v in fresh)
    if fresh:
        target.updated_at = now
    return len(fresh)


def list_named(db: OrmSession, name: str, actor: str, now: str, **fields: Any) -> IocList:
    """The list with that name, made if there is none."""
    import uuid

    name = name.strip()[:120]
    found = db.scalar(select(IocList).where(func.lower(IocList.name) == name.lower()))
    if found is None:
        found = IocList(
            id=uuid.uuid4().hex,
            name=name,
            description=str(fields.get("description") or "")[:500],
            tlp=fields.get("tlp") if fields.get("tlp") in TLPS else "amber",
            watch=bool(fields.get("watch")),
            created_at=now,
            created_by=actor,
            updated_at=now,
        )
        db.add(found)
        db.flush()
    return found


# --------------------------------------------------------------------------- #
# Alerts: an incident holds an indicator of a watched list                    #
# --------------------------------------------------------------------------- #
def watch_hits(db: OrmSession, incident: Incident, before: set[Pair], after: set[Pair], now: str) -> list[dict]:
    """Record an alert for each indicator the incident newly holds that is in
    a watched list. Returns what to announce."""
    import uuid

    new = after - before
    if not new:
        return []
    watched = db.execute(
        select(IocListItem.list_id, IocList.name, IocListItem.type, IocListItem.value)
        .join(IocList, IocList.id == IocListItem.list_id)
        .where(IocList.watch.is_(True))
    ).all()
    hits = []
    for list_id, name, kind, value in watched:
        if (kind, value) in new:
            db.add(
                IocAlert(id=uuid.uuid4().hex, at=now, list_id=list_id, incident_id=incident.id, type=kind, value=value)
            )
            hits.append(
                {
                    "list": {"id": list_id, "name": name},
                    "incident": {"id": incident.id, "name": (incident.doc or {}).get("name")},
                    "type": kind,
                    "value": value,
                }
            )
    return hits


# --------------------------------------------------------------------------- #
# Export                                                                      #
# --------------------------------------------------------------------------- #
def _cell(row: dict[str, Any], field: str, answers: dict[str, dict[str, str]]) -> Any:
    if field == "type":
        return row["type"]
    if field == "value":
        return row["value"]
    if field == "verdict":
        return row["verdict"] or ""
    if field == "score":
        return "" if row["score"] is None else row["score"]
    if field == "tags":
        return ";".join(row["tags"])
    if field == "first_seen":
        return (row["firstSeen"] or "")[:19]
    if field == "last_checked":
        return (row["checkedAt"] or "")[:19]
    if field == "sources_flagging":
        summary = row["reputation"]
        return f"{summary['flagged']}/{summary['checked']}" if summary else ""
    if field == "incidents":
        return row["incidents"]
    if field == "lists":
        return ";".join(entry["name"] for entry in row["lists"])
    if field == "note":
        return row["note"]
    if field == "tlp":
        return row["tlp"] or ""
    if field == "origin":
        return row["origin"]
    if field == "added_by":
        return row["addedBy"] or ""
    if field == "expires":
        return row["expires"] or ""
    return ""


def per_source(db: OrmSession, rows: list[dict[str, Any]]) -> dict[Pair, dict[str, str]]:
    from .core.models import Enrichment

    wanted = {(r["type"], r["value"]) for r in rows}
    answers: dict[Pair, dict[str, str]] = {}
    for item in db.scalars(select(Enrichment)):
        if (item.type, item.value) in wanted and item.verdict:
            answers.setdefault((item.type, item.value), {})[item.provider] = item.verdict
    return answers


def export(
    db: OrmSession,
    rows: list[dict[str, Any]],
    fmt: str,
    fields: Iterable[str],
    *,
    title: str,
    now: str,
    defanged: bool = False,
) -> tuple[str, str, str]:
    """``(body, media type, extension)`` of the rows in the chosen format."""
    chosen = [f for f in fields if f in FIELDS] or list(DEFAULT_FIELDS)

    def shown(row: dict[str, Any]) -> str:
        return defang(row["type"], row["value"]) if defanged else row["value"]

    if fmt == "txt":
        return "\n".join(shown(row) for row in rows) + ("\n" if rows else ""), "text/plain", "txt"
    if fmt == "stix" or fmt == "misp":
        iocs = [
            {
                "type": row["type"],
                "value": row["value"],
                "sources": [row["origin"]],
                "count": row["incidents"],
                "firstSeen": None,
                "description": (
                    f"Nik: {row['verdict'] or 'not checked'}"
                    + (f", score {row['score']}" if row["score"] is not None else "")
                    + (f". {row['note']}" if row["note"] else "")
                ),
            }
            for row in rows
        ]
        subject = {"id": f"list:{title}", "name": title, "reportType": "indicator", "info": f"Nik indicators: {title}"}
        if fmt == "stix":
            return json.dumps(stix_bundle(subject, iocs, now), indent=2), "application/json", "stix.json"
        return json.dumps(misp_event(subject, iocs, now), indent=2), "application/json", "misp.json"

    providers = [p for p in PROVIDERS] if "per_source" in chosen else []
    answers = per_source(db, rows) if providers else {}
    columns = [f for f in chosen if f != "per_source"]

    def record(row: dict[str, Any]) -> dict[str, Any]:
        out = {f: (shown(row) if f == "value" else _cell(row, f, {})) for f in columns}
        for provider in providers:
            out[provider.id] = answers.get((row["type"], row["value"]), {}).get(provider.id, "")
        return out

    if fmt == "json":
        body = {
            "format": "nik-iocs",
            "version": 1,
            "title": title,
            "exportedAt": now,
            "iocs": [record(r) for r in rows],
        }
        return json.dumps(body, indent=2), "application/json", "json"
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([*columns, *(p.id for p in providers)])
    for row in rows:
        writer.writerow(_csv_safe(v) for v in record(row).values())
    return buffer.getvalue(), "text/csv", "csv"


def _csv_safe(value: Any) -> Any:
    """A cell a spreadsheet will not read as a formula."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value
