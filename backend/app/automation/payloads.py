"""What an event carries to the playbooks it triggers, and the classes of its fields.

One builder per event. Each returns the data (what ``{{ trigger.… }}`` reads)
and, beside it, a map of the classes of data its fields hold, so the data
guard knows what a value is without guessing from its content:

    data    = {"incident": {"id": …, "name": …, "assignee": …}, "changed": […]}
    classes = {"incident.id": ["nik_id"], "incident.name": ["incident_text"], …}

Classes are defined in guard.py. A field that is not in the map has none of
its own and is caught, if at all, by the guard's scan of what leaves.
"""

from __future__ import annotations

from typing import Any

from ..core.models import Incident

# The fields of an incident a trigger can compare and a playbook can read, and their classes.
_INCIDENT = {
    "id": "nik_id",
    "url": "nik_id",
    "status": "verdict",
    "severity": "verdict",
    "name": "incident_text",
    "ticket": "incident_text",
    "host": "private_value",
    "username": "private_value",
    "assignee": "private_value",
    "os": "verdict",
    "created": "nik_id",
    "modified": "nik_id",
}


def incident_data(incident: Incident) -> dict[str, Any]:
    return {
        "id": incident.id,
        "url": f"/incident/{incident.id}",
        "name": incident.name,
        "ticket": incident.ticket_id,
        "host": incident.host,
        "username": incident.username,
        "os": incident.os,
        "status": incident.status or "open",
        "severity": incident.severity or "",
        "assignee": incident.assignee or "",
        "created": incident.created_at,
        "modified": incident.updated_at,
    }


def incident_classes(prefix: str = "incident") -> dict[str, list[str]]:
    return {f"{prefix}.{name}": [held] for name, held in _INCIDENT.items()}


def incident_event(incident: Incident, changed: list[str] | None = None) -> tuple[dict, dict]:
    """``incident.created`` / ``incident.updated``."""
    data = {"incident": incident_data(incident), "changed": sorted(changed or [])}
    return data, incident_classes()


def manual(actor: str, incident: Incident | None) -> tuple[dict, dict]:
    """A run started by hand, on an incident or on nothing."""
    data: dict[str, Any] = {"actor": actor}
    classes: dict[str, list[str]] = {"actor": ["private_value"]}
    if incident is not None:
        data["incident"] = incident_data(incident)
        classes.update(incident_classes())
    return data, classes


def schedule(at: str, cron: str) -> tuple[dict, dict]:
    return {"at": at, "cron": cron}, {}
