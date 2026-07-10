"""Endpoint artifact parser — port of ``artifactParsers.js``.

Produces records shaped by the category's fields:
``{ records: [{ id, time, fields: {...} }], format }``.
"""

from __future__ import annotations

import json
import plistlib
import re
import xml.etree.ElementTree as ET
from urllib.parse import unquote

from .common import (
    as_text,
    base_name,
    gen_id,
    normalize_row,
    open_sqlite,
    parse_csv,
    pick,
    query_rows,
)
from .timeutil import any_to_ms, mac_to_ms


# --------------------------------------------------------------------------- #
# CSV / JSON (script output, or any export)                                   #
# --------------------------------------------------------------------------- #
def _map_delimited(rows, category):
    records = []
    for raw in rows:
        if not isinstance(raw, dict):
            continue
        row = normalize_row(raw)
        fields = {k: as_text(pick(row, aliases)) for k, aliases in category["fields"].items()}
        if not fields.get(category["primaryField"]):
            continue
        records.append({"id": gen_id(), "time": any_to_ms(pick(row, category["timeAliases"])), "fields": fields})
    return records


def parse_csvjson(text, category):
    trimmed = text.lstrip()
    if trimmed.startswith("{") or trimmed.startswith("["):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        rows = None
        if isinstance(parsed, list):
            rows = parsed
        elif isinstance(parsed, dict):
            for key in ("records", "rows", "data"):
                if isinstance(parsed.get(key), list):
                    rows = parsed[key]
                    break
        if rows is not None:
            records = _map_delimited(rows, category)
            if records:
                return {"records": records}, "json"
    rows = parse_csv(text)
    if rows:
        records = _map_delimited(rows, category)
        if records:
            return {"records": records}, "csv"
    raise ValueError(f'Could not map records: a column for "{category["primaryField"]}" is required.')


# --------------------------------------------------------------------------- #
# File-mode parsers                                                           #
# --------------------------------------------------------------------------- #
def parse_xbel(text, category):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        raise ValueError("Not a valid XBEL/XML file.")
    records = []
    for b in root.iter("bookmark"):
        href = b.get("href") or ""
        if not href:
            continue
        try:
            target = unquote(re.sub(r"^file:/*", "/", href, flags=re.I))
        except Exception:
            target = href
        when = b.get("modified") or b.get("visited") or b.get("added")
        records.append(
            {"id": gen_id(), "time": any_to_ms(when), "fields": {"name": base_name(target), "target": target, "kind": "recently-used"}}
        )
    if not records:
        raise ValueError("No bookmarks found in the XBEL file.")
    return {"records": records}, "xbel"


def parse_configlines(text, category, source):
    kind = source.get("recordKind", "config")
    label = source.get("recordName", kind)
    records = []
    for raw in text.split("\n"):
        line = raw.rstrip("\r").strip()
        if not line or line.startswith("#"):
            continue
        records.append({"id": gen_id(), "time": None, "fields": {"name": label, "kind": kind, "command": line, "location": source["name"]}})
    if not records:
        raise ValueError("No entries found (only comments or blank lines).")
    return {"records": records}, "text"


def parse_plist(data, category, source):
    try:
        obj = plistlib.loads(data)
    except Exception:
        raise ValueError("Not a valid plist.")
    if not isinstance(obj, dict):
        raise ValueError("Unexpected plist structure.")
    label = str(obj.get("Label") or base_name(source["name"]))
    args = obj.get("ProgramArguments")
    if isinstance(args, list):
        command = " ".join(str(a) for a in args)
    else:
        command = str(obj.get("Program") or "")
    return {"records": [{"id": gen_id(), "time": None, "fields": {"name": label, "kind": "LaunchAgent", "command": command, "location": source["name"]}}]}, "plist"


def parse_setupapi(text, category):
    records = []
    pending = None
    for raw in text.split("\n"):
        line = raw.rstrip("\r")
        header = re.search(r"\[Device Install[^\]]*-\s*(USBSTOR\\[^\]]+|USB\\VID_[^\]]+)\]", line, re.I)
        if header:
            pending = header.group(1).strip()
            continue
        if pending:
            ts = re.search(r"Section start\s+([\d/]+\s+[\d:.]+)", line)
            serial = pending.split("\\")[-1] if "\\" in pending else ""
            records.append(
                {"id": gen_id(), "time": any_to_ms(ts.group(1).replace("/", "-")) if ts else None,
                 "fields": {"device": pending, "serial": serial, "vendor": "", "connection": "setupapi"}}
            )
            pending = None
    if not records:
        raise ValueError("No USB device-install sections found in the log.")
    return {"records": records}, "setupapi"


def parse_knowledgec(data, category):
    with open_sqlite(data) as conn:
        rows = query_rows(
            conn,
            "SELECT ZVALUESTRING AS app, ZSTARTDATE AS start FROM ZOBJECT "
            "WHERE ZSTREAMNAME='/app/usage' AND ZVALUESTRING IS NOT NULL ORDER BY ZSTARTDATE DESC",
        )
        if not rows:
            raise ValueError("No /app/usage rows found (is this a knowledgeC.db?).")
        records = [
            {"id": gen_id(), "time": mac_to_ms(r.get("start")), "fields": {"name": r.get("app"), "path": r.get("app"), "runCount": "", "source": "KnowledgeC"}}
            for r in rows
        ]
    return {"records": records}, "sqlite"


def parse_artifact(data: bytes, category: dict, source: dict):
    """Parse an uploaded endpoint-artifact file → ({records}, format)."""
    if not data:
        raise ValueError("The file is empty.")
    parser = source.get("parser")
    if parser == "knowledgec":
        return parse_knowledgec(data, category)
    if parser == "plist":
        return parse_plist(data, category, source)

    text = data.decode("utf-8", errors="replace")
    if not text.strip():
        raise ValueError("The file is empty.")
    if parser == "xbel":
        return parse_xbel(text, category)
    if parser == "configlines":
        return parse_configlines(text, category, source)
    if parser == "setupapi":
        return parse_setupapi(text, category)
    # Script-mode sources (and any export): CSV/JSON.
    return parse_csvjson(text, category)
