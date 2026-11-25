"""What the Sigma tests share: rules and records made here, harmless, never evidence."""

from __future__ import annotations

import os
import sys
import uuid

import yaml

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, HERE)

from nik_forensics.sigma.engine import Engine  # noqa: E402

NAMESPACE = uuid.UUID("6f0a7a1e-1d2b-4c3d-9e4f-5a6b7c8d9e0f")
SYSMON = "Microsoft-Windows-Sysmon/Operational"


def rid(name: str) -> str:
    return str(uuid.uuid5(NAMESPACE, name))


def rule(
    name: str,
    detection: dict,
    product: str | None = "windows",
    category: str | None = "process_creation",
    service: str | None = None,
    level: str = "high",
    extra: dict | None = None,
) -> dict:
    """A rule line of the wire contract: the YAML of one document and its log source."""
    logsource = {
        key: value for key, value in (("product", product), ("category", category), ("service", service)) if value
    }
    document = {
        "title": name,
        "id": rid(name),
        "name": name,
        "status": "test",
        "level": level,
        "author": "the tests",
        "logsource": logsource,
        "detection": detection,
        **(extra or {}),
    }
    return {
        "id": rid(name),
        "title": name,
        "level": 4,
        "kind": "rule",
        "product": product or "",
        "category": category or "",
        "service": service or "",
        "source": yaml.safe_dump(document, sort_keys=False),
    }


def correlation(name: str, body: dict) -> dict:
    document = {"title": name, "id": rid(name), "name": name, "correlation": body}
    return {
        "id": rid(name),
        "title": name,
        "level": 4,
        "kind": "correlation",
        "product": "",
        "category": "",
        "service": "",
        "source": yaml.safe_dump(document, sort_keys=False),
    }


def record(
    data: dict | None = None,
    channel: str = SYSMON,
    event_id: int | None = 1,
    kind: str = "eventlog",
    key: str = "k1",
    ts: int | None = 1_700_000_000_000,
    host: str = "WKS-1",
    username: str = "",
    summary: str = "",
    rtype: str = "event",
    source: str = "evtx",
) -> tuple:
    """The arguments of ``Engine.see``."""
    return (kind, key, rtype, ts, host, username, event_id, channel, summary, data or {}, source)


def names(engine: Engine, *args, **kwargs) -> set[str]:
    """The names of the rules a record matches."""
    by_id = {slot.rid: slot.line["title"] for slot in engine.slots}
    return {by_id[found] for found in engine.see(*record(*args, **kwargs))}


def one(detection: dict, data: dict, **kwargs) -> bool:
    """Does a single process-creation rule with this detection match a Sysmon process record with this data?"""
    engine = Engine([rule("r", detection)])
    return bool(names(engine, data, **kwargs))
