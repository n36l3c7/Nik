"""Pre-processing: what is done with a fetched item before it becomes an incident.

Rules are tried in order on what the item *would* become: ``incident`` (its
type and the fields its mapper gave) and ``item`` (as it came). The first
enabled rule whose condition holds decides:

- ``drop``: no incident; the item is remembered so that it does not come back;
- ``link_to_existing``: no incident; the item becomes a line of the War Room
  of an open incident that has the *same* values in the fields the rule names
  (``same: ["host", "name"]``), made in the last ``within_hours`` if it says so;
- ``close_duplicate``: the incident is made, and closed at once as a
  duplicate of such an open incident;
- ``run_script``: a script of the library is given ``{item, incident}`` and
  returns ``{"action": "drop" | "link_to_existing" | "close_duplicate" |
  "create", "same": [...], "note": "..."}``.

A rule that finds no incident to link to or to be a duplicate of decides
nothing: the next rule is tried. With no rule that decides, the item becomes
an incident. The condition is the kind a classifier has (comparisons over
``incident`` and ``item``): the item is not stored yet, so the query language
of the lists, which reads what is stored, does not apply to it.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from . import fields as registry
from . import mapping, war_room
from .automation import expressions as ex
from .core.models import Incident, PreprocessRule, Script, ScriptVersion
from .core.security import now_iso

ACTIONS = ("drop", "link_to_existing", "close_duplicate", "run_script")
RULES_MAX = 100
# The fields "the same incident" can be told by: columns of the incident, read without its document.
SAME = {
    "name": Incident.name,
    "host": Incident.host,
    "username": Incident.username,
    "ticket": Incident.ticket_id,
    "severity": Incident.severity,
    "source_id": Incident.source_id,
    "type": Incident.type_id,
}
WITHIN_MAX = 24 * 90
ROOTS = frozenset({"incident", "item"})


class RuleError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# The store                                                                   #
# --------------------------------------------------------------------------- #
def _when(raw: Any) -> dict:
    """The condition of a rule: empty for "always", else all/any of comparisons over incident and item."""
    if raw in (None, "", {}):
        return {}
    groups = [key for key in ("all", "any") if isinstance(raw, dict) and key in raw]
    if len(groups) != 1 or not isinstance(raw[groups[0]], list) or not raw[groups[0]]:
        raise RuleError('A condition is "all" or "any" of at least one comparison, or nothing for "always"')
    cleaned = []
    for item in raw[groups[0]]:
        if not isinstance(item, dict) or item.get("op") not in mapping.OPERATORS or "left" not in item:
            raise RuleError("A comparison has what to compare and one of: " + ", ".join(mapping.OPERATORS))
        for side in ("left", "right"):
            try:
                mapping._template(item.get(side), ROOTS, "The condition")
            except mapping.MappingError as error:
                raise RuleError(error.message) from None
        if item["op"] == "matches" and not (isinstance(item.get("right"), str) and 0 < len(item["right"]) <= 500):
            raise RuleError("A pattern of 1 to 500 characters is needed")
        cleaned.append({"left": item["left"], "op": item["op"], "right": item.get("right")})
    return {groups[0]: cleaned}


def _params(db: OrmSession, action: str, raw: Any) -> dict[str, Any]:
    params = raw if isinstance(raw, dict) else {}
    if action == "drop":
        return {}
    if action == "run_script":
        name = str(params.get("script") or "").strip()
        script = db.scalars(select(Script).where(Script.name == name)).first()
        if script is None or not script.current_version:
            raise RuleError("Choose a script of the library that has a saved version")
        return {"script": name}
    same = params.get("same")
    if not isinstance(same, list) or not same or any(name not in SAME for name in same):
        raise RuleError("Say which fields are the same in the incident to look for: " + ", ".join(SAME))
    out: dict[str, Any] = {"same": list(dict.fromkeys(same))}
    hours = params.get("within_hours", params.get("withinHours"))
    if hours not in (None, ""):
        if isinstance(hours, bool) or not isinstance(hours, (int, float)) or not 1 <= int(hours) <= WITHIN_MAX:
            raise RuleError("The time to look back is in hours, 1 to 2160")
        out["within_hours"] = int(hours)
    return out


def clean(db: OrmSession, body: dict[str, Any]) -> dict[str, Any]:
    action = str(body.get("action") or "")
    if action not in ACTIONS:
        raise RuleError("A rule does one of: " + ", ".join(ACTIONS))
    name = str(body.get("name") or "").strip()[:120]
    if not name:
        raise RuleError("A rule needs a name")
    return {
        "name": name,
        "enabled": bool(body.get("enabled", True)),
        "when": _when(body.get("when")),
        "action": action,
        "params": _params(db, action, body.get("params")),
    }


def _when_of(row: PreprocessRule) -> dict:
    import json

    try:
        held = json.loads(row.when) if row.when else {}
    except ValueError:
        held = {}
    return held if isinstance(held, dict) else {}


def out(row: PreprocessRule) -> dict[str, Any]:
    return {
        "id": row.id,
        "position": row.position,
        "name": row.name,
        "enabled": bool(row.enabled),
        "when": _when_of(row),
        "action": row.action,
        "params": row.params or {},
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def every(db: OrmSession) -> list[PreprocessRule]:
    return list(db.scalars(select(PreprocessRule).order_by(PreprocessRule.position, PreprocessRule.id)))


def save(db: OrmSession, body: dict[str, Any], actor: str, row: PreprocessRule | None = None) -> PreprocessRule:
    import json

    cleaned = clean(db, body)
    if row is None:
        count = db.scalar(select(func.count()).select_from(PreprocessRule)) or 0
        if count >= RULES_MAX:
            raise RuleError(f"There are {RULES_MAX} rules at most")
        last = db.scalar(select(func.max(PreprocessRule.position))) or 0
        row = PreprocessRule(id=uuid.uuid4().hex, position=last + 1)
        db.add(row)
    row.name, row.enabled, row.action, row.params = (
        cleaned["name"],
        cleaned["enabled"],
        cleaned["action"],
        cleaned["params"],
    )
    row.when = json.dumps(cleaned["when"]) if cleaned["when"] else ""
    row.updated_at, row.updated_by = now_iso(), actor[:200]
    return row


def reorder(db: OrmSession, ids: list[str]) -> None:
    """Put the rules in the order of ``ids`` (those left out follow, as they were)."""
    rows = {row.id: row for row in every(db)}
    wanted = [rule_id for rule_id in dict.fromkeys(ids) if rule_id in rows]
    rest = [rule_id for rule_id in rows if rule_id not in wanted]
    for position, rule_id in enumerate([*wanted, *rest], start=1):
        rows[rule_id].position = position


# --------------------------------------------------------------------------- #
# Deciding                                                                    #
# --------------------------------------------------------------------------- #
def as_incident(made: dict[str, Any]) -> dict[str, Any]:
    """What an item would be as an incident, for a rule to read: its type and the fields its mapper gave."""
    mapped: mapping.Mapped = made["mapped"]
    return {"type": made.get("type") or registry.UNCLASSIFIED, **mapped.fields}


def _holds(when: dict, scope: ex.Scope) -> bool:
    from .automation import engine

    if not when:
        return True
    try:
        return engine.holds(when, scope)
    except (ex.ExpressionError, engine.StepFailed):
        return False  # a rule that cannot be judged on this item does not hold


def find_same(db: OrmSession, would_be: dict[str, Any], params: dict[str, Any], now: float) -> Incident | None:
    """An open incident that has the same values in the fields a rule names: the newest."""
    stmt = select(Incident).where(Incident.status != "closed")
    for name in params.get("same") or []:
        value = would_be.get(name)
        if name == "type":
            value = None if value in (None, "", registry.UNCLASSIFIED) else value
            stmt = stmt.where(Incident.type_id.is_(None) if value is None else Incident.type_id == value)
            continue
        if value in (None, ""):
            return None  # nothing to tell "the same" by
        stmt = stmt.where(func.lower(SAME[name]) == str(value).lower())
    hours = params.get("within_hours")
    if hours:
        since = datetime.fromtimestamp(now - int(hours) * 3600, timezone.utc).isoformat()
        stmt = stmt.where(Incident.created_at >= since)
    return db.scalars(stmt.order_by(Incident.created_at.desc()).limit(1)).first()


def _script_says(db: OrmSession, name: str, item: Any, would_be: dict[str, Any]) -> dict[str, Any]:
    from .automation import scripts

    script = db.scalars(select(Script).where(Script.name == name)).first()
    version = db.get(ScriptVersion, (script.id, script.current_version)) if script is not None else None
    if version is None:
        return {}
    answer = scripts.execute(version.code, {"item": item, "incident": would_be})
    result = answer.get("result") if answer.get("ok") else None
    return result if isinstance(result, dict) else {}


def decide(
    db: OrmSession, connection: Any, connector: Any, item: Any, item_id: str, made: dict[str, Any], now: float
) -> dict[str, Any]:
    """What becomes of an item: ``{"outcome": "create" | "dropped" | "linked", "note", "incident_id",
    "after", "duplicate_of"}``. ``after: "close_duplicate"`` asks for the incident to be made, then closed."""
    would_be = as_incident(made)
    scope = ex.Scope(values={"incident": would_be, "item": item})
    for rule in every(db):
        if not rule.enabled or not _holds(_when_of(rule), scope):
            continue
        action, params = rule.action, dict(rule.params or {})
        if action == "run_script":
            said = _script_says(db, str(params.get("script") or ""), item, would_be)
            action = str(said.get("action") or "")
            if action not in ("drop", "link_to_existing", "close_duplicate"):
                continue  # the script says to go on, or said nothing that can be read
            params = {"same": [name for name in said.get("same") or [] if name in SAME]}
            if action != "drop" and not params["same"]:
                continue
        if action == "drop":
            return {"outcome": "dropped", "note": f'Dropped by the rule "{rule.name}"'}
        found = find_same(db, would_be, params, now)
        if found is None:
            continue
        if action == "link_to_existing":
            war_room.add(
                db,
                found.id,
                "system",
                {
                    "text": f"Another alert of the same came in from {connection.name}: "
                    f"{would_be.get('name') or item_id} (item {item_id})",
                    "item": _shown(item),
                },
                f"connector:{connector.id}",
            )
            return {"outcome": "linked", "incident_id": found.id, "note": f'Linked by the rule "{rule.name}"'}
        return {
            "outcome": "create",
            "after": "close_duplicate",
            "duplicate_of": found.id,
            "note": f'Closed as a duplicate of "{found.name}" by the rule "{rule.name}"',
        }
    return {"outcome": "create"}


def _shown(item: Any) -> Any:
    from . import fetch

    return fetch._cut(item)


def close_as_duplicate(db: OrmSession, incident: Incident, decided: dict[str, Any], now: float) -> None:
    """Close an incident just made as a duplicate of another (the caller commits)."""
    source = "nik"
    other = db.get(Incident, decided.get("duplicate_of") or "")
    notes = f'Duplicate of "{other.name}" ({other.id})' if other is not None else "Duplicate"
    try:
        registry.update(
            db,
            incident,
            {
                "status": "closed",
                "close_reason": "Duplicate",
                "close_notes": notes,
                **({"related_incidents": [other.id]} if other is not None else {}),
            },
            source,
            source,
        )
    except registry.FieldError:
        # Its type wants more before closing: it is closed all the same, as the duplicate it is.
        from .routers.incidents import _sync_columns

        doc = dict(incident.doc or {})
        doc["status"] = "closed"
        incident.doc = doc
        incident.close_reason, incident.close_notes = "Duplicate", notes
        _sync_columns(incident)
    if other is not None:
        war_room.system(db, other.id, f'"{incident.name}" came in and was closed as a duplicate of this incident')


def try_rules(db: OrmSession, item: Any, made: dict[str, Any], now: float) -> dict[str, Any]:
    """Which rule would decide for an item, and what, without doing it."""
    would_be = as_incident(made)
    scope = ex.Scope(values={"incident": would_be, "item": item})
    for rule in every(db):
        if not rule.enabled or not _holds(_when_of(rule), scope):
            continue
        if rule.action == "drop":
            return {"rule": rule.name, "action": "drop", "incident": None}
        if rule.action == "run_script":
            return {"rule": rule.name, "action": "run_script", "incident": None}
        found = find_same(db, would_be, rule.params or {}, now)
        if found is not None:
            return {"rule": rule.name, "action": rule.action, "incident": {"id": found.id, "name": found.name}}
    return {"rule": None, "action": "create", "incident": None}
