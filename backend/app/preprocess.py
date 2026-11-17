"""Pre-processing: what is done with a fetched item before it becomes an incident.

The rules come with the change after this one: until then every new item
becomes an incident.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as OrmSession

from .core.models import Incident


def decide(
    db: OrmSession, connection: Any, connector: Any, item: Any, item_id: str, made: dict[str, Any], now: float
) -> dict[str, Any]:
    """What becomes of an item: ``{"outcome": "create"}`` until there are rules."""
    return {"outcome": "create"}


def close_as_duplicate(db: OrmSession, incident: Incident, decided: dict[str, Any], now: float) -> None:
    """Close an incident just made as a duplicate of another (the caller commits)."""
