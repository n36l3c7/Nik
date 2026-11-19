"""Classifiers and mappers: how what another product calls things becomes Nik's, and back.

They are data in Nik, not part of a connector file, so that whoever manages
connectors changes them without touching YAML.

- A **classifier** belongs to a connection that fetches: rules, each a
  condition on the fetched item and a type of incident; the first that holds
  wins, else the default type.
- An **incoming mapper** belongs to a connector and a type of incident (``*``
  for every type without one of its own): rules ``{to, from, authoritative}``
  where ``to`` is a field of the registry or a context path and ``from`` a
  template over ``item``. It is applied to what a fetch brings and to what
  mirroring reads.
- An **outgoing mapper**: rules ``{to, from}`` where ``to`` is a name of the
  other product and ``from`` a template over ``incident`` and ``context``.
  It is what mirroring sends, and what a "create" command starts from.

``apply_incoming`` never fails on one rule: a value that cannot be read is no
value, one the field refuses is a problem to show, and the rest goes on.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from . import context as incident_context
from . import fields as registry
from .automation import expressions as ex
from .core.models import Classifier, Connection, Connector, Incident, IncidentType, Mapper
from .core.security import now_iso

DIRECTIONS = ("incoming", "outgoing")
ANY_TYPE = "*"
RULES_MAX = 200
CLASSIFIER_RULES_MAX = 50
FROM_MAX = 2000
OPERATORS = ("eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "matches", "exists", "empty")
# Fields a mapper never sets: the type is the classifier's, the rest is Nik's own.
NOT_MAPPED = frozenset({"id", "type", "created", "modified", "closed", "sla_breached"})


class MappingError(ValueError):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


@dataclass
class Mapped:
    """What an incoming mapper made of an item."""

    fields: dict[str, Any] = field(default_factory=dict)
    context: list[tuple[str, Any]] = field(default_factory=list)
    authoritative: set[str] = field(default_factory=set)
    problems: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)  # required fields of the type nothing gave

    def out(self) -> dict[str, Any]:
        return {
            "fields": self.fields,
            "context": [{"path": path, "value": value} for path, value in self.context],
            "authoritative": sorted(self.authoritative),
            "problems": self.problems,
            "missing": self.missing,
        }


# --------------------------------------------------------------------------- #
# Checking what is saved                                                      #
# --------------------------------------------------------------------------- #
def _template(value: Any, allowed: frozenset, what: str) -> None:
    """A template parses and reads only the names it may read there (inside an object or a list too)."""
    if isinstance(value, dict):
        for item in value.values():
            _template(item, allowed, what)
        return
    if isinstance(value, list):
        for item in value:
            _template(item, allowed, what)
        return
    if not isinstance(value, str):
        return
    if len(value) > FROM_MAX:
        raise MappingError(f"{what}: at most {FROM_MAX} characters")
    if "{{" not in value:
        return
    try:
        found = ex.references(value)
    except ex.ExpressionError as error:
        raise MappingError(f"{what}: {error.message}") from None
    for name, _position in found:
        if name not in allowed:
            raise MappingError(f'{what}: "{name}" cannot be read here, only {", ".join(sorted(allowed))}')


def _conditions(raw: Any, what: str) -> dict:
    groups = [key for key in ("all", "any") if isinstance(raw, dict) and key in raw]
    if len(groups) != 1 or not isinstance(raw[groups[0]], list) or not raw[groups[0]]:
        raise MappingError(f'{what}: a condition is "all" or "any" of at least one comparison')
    cleaned = []
    for item in raw[groups[0]]:
        if not isinstance(item, dict) or item.get("op") not in OPERATORS or "left" not in item:
            raise MappingError(f"{what}: a comparison has what to compare and one of: " + ", ".join(OPERATORS))
        _template(item.get("left"), frozenset({"item"}), what)
        _template(item.get("right"), frozenset({"item"}), what)
        if item["op"] == "matches" and not (isinstance(item.get("right"), str) and 0 < len(item["right"]) <= 500):
            raise MappingError(f"{what}: a pattern of 1 to 500 characters is needed")
        cleaned.append({"left": item["left"], "op": item["op"], "right": item.get("right")})
    return {groups[0]: cleaned}


def clean_classifier(db: OrmSession, body: dict[str, Any]) -> tuple[list[dict], str | None]:
    rules = body.get("rules") or []
    if not isinstance(rules, list) or len(rules) > CLASSIFIER_RULES_MAX:
        raise MappingError(f"A classifier has {CLASSIFIER_RULES_MAX} rules at most")
    cleaned = []
    for index, rule in enumerate(rules, start=1):
        if not isinstance(rule, dict):
            raise MappingError(f"Rule {index} is not an object")
        cleaned.append({"when": _conditions(rule.get("when"), f"Rule {index}"), "type": _type(db, rule.get("type"))})
    default = body.get("defaultType")
    return cleaned, _type(db, default) if default else None


def _type(db: OrmSession, raw: Any) -> str:
    from . import incident_types

    incident_types.every(db)  # the shipped ones, when this is the first time they are asked for
    type_id = str(raw or "")
    if db.get(IncidentType, type_id) is None:
        raise MappingError(f'There is no type of incident "{type_id}"')
    return type_id


def target_kind(db: OrmSession, to: str, connector_id: str) -> tuple[str, str]:
    """What an incoming rule writes to: ("field", name) or ("context", path). Raises ``MappingError``."""
    to = str(to or "").strip()
    name = to[len("incident.") :] if to.startswith("incident.") else to
    known = registry.registry(db).get(name)
    if known is not None and known.applies_to == "incident":
        spec = registry.SYSTEM_FIELDS.get(name)
        if (
            name in NOT_MAPPED
            or known.type == "timer"
            or (spec is not None and not spec.writable and name not in _SOURCE)
        ):
            raise MappingError(f'"{name}" is not a field a mapper sets')
        return "field", name
    wrong = incident_context.problem(to)
    if wrong is not None:
        raise MappingError(f'"{to}" is not a field of incidents nor a context path: {wrong}')
    target = incident_context.parse(to)
    if target.kind == "ext" and target.connector != connector_id:
        raise MappingError(f"A mapper of {connector_id} writes under ext.{connector_id}")
    return "context", to


# What says where an incident came from: not writable by hand, set by what fetched it.
_SOURCE = frozenset({"source_id", "source_url", "source_connector", "mirror_id", "mirror_direction"})


def clean_rules(db: OrmSession, connector_id: str, direction: str, rules: Any) -> list[dict[str, Any]]:
    if not isinstance(rules, list) or len(rules) > RULES_MAX:
        raise MappingError(f"A mapper has {RULES_MAX} rules at most")
    cleaned: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, rule in enumerate(rules, start=1):
        what = f"Rule {index}"
        if not isinstance(rule, dict) or not str(rule.get("to") or "").strip():
            raise MappingError(f"{what} needs what it writes to")
        to = str(rule["to"]).strip()[:200]
        if "from" not in rule or rule["from"] in (None, ""):
            raise MappingError(f"{what} needs where its value comes from")
        if direction == "incoming":
            _kind, name = target_kind(db, to, connector_id)
            _template(rule["from"], frozenset({"item"}), what)
            item = {"to": name, "from": rule["from"], "authoritative": bool(rule.get("authoritative"))}
        else:
            _template(rule["from"], frozenset({"incident", "context", "mirror"}), what)
            item = {"to": to, "from": rule["from"]}
        if item["to"] in seen:
            raise MappingError(f'{what}: "{item["to"]}" is written twice')
        seen.add(item["to"])
        cleaned.append(item)
    return cleaned


# --------------------------------------------------------------------------- #
# The store                                                                   #
# --------------------------------------------------------------------------- #
def mapper_out(row: Mapper) -> dict[str, Any]:
    return {
        "id": row.id,
        "connectorId": row.connector_id,
        "direction": row.direction,
        "incidentType": row.incident_type,
        "rules": row.rules or [],
        "builtin": bool(row.builtin),
        "updatedAt": row.updated_at,
        "updatedBy": row.updated_by,
    }


def mappers_of(db: OrmSession, connector_id: str | None = None) -> list[Mapper]:
    stmt = select(Mapper).order_by(Mapper.connector_id, Mapper.direction, Mapper.incident_type)
    if connector_id:
        stmt = stmt.where(Mapper.connector_id == connector_id)
    return list(db.scalars(stmt))


def find_mapper(db: OrmSession, connector_id: str, direction: str, incident_type: str | None) -> Mapper | None:
    """The mapper for a type: its own, else the one for every type."""
    rows = {
        row.incident_type: row
        for row in db.scalars(select(Mapper).where(Mapper.connector_id == connector_id, Mapper.direction == direction))
    }
    return rows.get(incident_type or registry.UNCLASSIFIED) or rows.get(ANY_TYPE)


def save_mapper(db: OrmSession, body: dict[str, Any], actor: str, *, builtin: bool = False) -> Mapper:
    connector_id = str(body.get("connectorId") or "")
    if db.get(Connector, connector_id) is None:
        raise MappingError("This connector does not exist", 404)
    direction = str(body.get("direction") or "")
    if direction not in DIRECTIONS:
        raise MappingError("A mapper is incoming or outgoing")
    incident_type = str(body.get("incidentType") or ANY_TYPE)
    if incident_type != ANY_TYPE:
        _type(db, incident_type)
    rules = clean_rules(db, connector_id, direction, body.get("rules") or [])
    row = db.scalars(
        select(Mapper).where(
            Mapper.connector_id == connector_id, Mapper.direction == direction, Mapper.incident_type == incident_type
        )
    ).one_or_none()
    if row is None:
        row = Mapper(id=uuid.uuid4().hex, connector_id=connector_id, direction=direction, incident_type=incident_type)
        db.add(row)
    row.rules, row.builtin = rules, builtin
    row.updated_at, row.updated_by = now_iso(), actor[:200]
    return row


def classifier_out(db: OrmSession, connection: Connection) -> dict[str, Any]:
    row = db.get(Classifier, connection.id)
    return {
        "instanceId": connection.id,
        "rules": (row.rules if row is not None else None) or [],
        "defaultType": row.default_type if row is not None else None,
        "updatedAt": row.updated_at if row is not None else None,
        "updatedBy": row.updated_by if row is not None else "",
    }


def save_classifier(db: OrmSession, connection: Connection, body: dict[str, Any], actor: str) -> Classifier:
    rules, default = clean_classifier(db, body)
    row = db.get(Classifier, connection.id)
    if row is None:
        row = Classifier(connection_id=connection.id)
        db.add(row)
    row.rules, row.default_type = rules, default
    row.updated_at, row.updated_by = now_iso(), actor[:200]
    return row


# --------------------------------------------------------------------------- #
# Applying                                                                    #
# --------------------------------------------------------------------------- #
def classify(rules: list | None, default: str | None, item: Any) -> str | None:
    """The type of incident an item becomes: that of the first rule that holds, else the default."""
    from .automation import engine

    scope = ex.Scope(values={"item": item})
    for rule in rules or []:
        try:
            if engine.holds(rule.get("when") or {}, scope):
                return rule.get("type")
        except (ex.ExpressionError, engine.StepFailed):
            continue  # a rule that cannot be judged on this item does not hold
    return default


def classify_for(db: OrmSession, connection_id: str, item: Any) -> str | None:
    row = db.get(Classifier, connection_id)
    if row is None:
        return None
    found = classify(row.rules, row.default_type, item)
    return found if found and db.get(IncidentType, found) is not None else None


def _value(template: Any, scope: ex.Scope) -> tuple[Any, str | None]:
    """What a rule reads: (value, None), or (None, why) when it cannot be read."""
    if isinstance(template, str) and "{{" not in template:
        return template, None
    if not isinstance(template, (str, dict, list)):
        return template, None
    try:
        return ex.render(template, scope).data, None
    except ex.ExpressionError as error:
        return None, error.message


def apply_incoming(
    db: OrmSession, rules: list | None, item: Any, connector_id: str, incident_type: str | None = None
) -> Mapped:
    """What an item becomes: fields of the registry, checked as the registry checks them, and
    writes to the context. Nothing is written here."""
    out = Mapped()
    scope = ex.Scope(values={"item": item})
    known = registry.registry(db)
    for rule in rules or []:
        to = str(rule.get("to") or "")
        value, _unread = _value(rule.get("from"), scope)
        if value is None or value == "" or value == []:
            continue  # nothing there on this item: the field keeps what it has
        try:
            kind, name = target_kind(db, to, connector_id)
        except MappingError as error:
            out.problems.append(error.message)
            continue
        if kind == "context":
            out.context.append((name, value))
            continue
        spec = known[name]
        try:
            out.fields[name] = registry.coerce(db, spec.label or name, spec.type, spec.options or {}, value)
        except registry.FieldError as error:
            out.problems.append(error.message)
            continue
        if rule.get("authoritative"):
            out.authoritative.add(name)
    kind_row = db.get(IncidentType, incident_type) if incident_type else None
    for name, item_of_type in registry.type_fields(kind_row).items():
        if item_of_type.get("required") and name in known and out.fields.get(name) in (None, "", []):
            out.missing.append(known[name].label or name)
    return out


def apply_outgoing(db: OrmSession, rules: list | None, incident: Incident, extra: dict | None = None) -> dict[str, Any]:
    """What goes to the other side for an incident: {the product's name: value}. A rule whose
    value cannot be read, or is empty, sends nothing for its name."""
    scope = ex.Scope(
        values={
            "incident": registry.read(db, incident),
            "context": incident_context.read(db, incident.id),
            "mirror": extra or {},
        }
    )
    out: dict[str, Any] = {}
    for rule in rules or []:
        value, _unread = _value(rule.get("from"), scope)
        if value is None or value == "":
            continue
        out[str(rule.get("to"))] = value
    return out


def targets(db: OrmSession, incident_type: str | None) -> dict[str, Any]:
    """Nik's side of the mapper editor: the fields a mapper may set (those the type needs first),
    and the entities of the context."""
    known = registry.registry(db)
    kind = db.get(IncidentType, incident_type) if incident_type and incident_type != ANY_TYPE else None
    of_type = registry.type_fields(kind)
    found = []
    for name, spec in known.items():
        if spec.applies_to != "incident" or name in NOT_MAPPED or spec.type == "timer":
            continue
        system = registry.SYSTEM_FIELDS.get(name)
        if system is not None and not system.writable and name not in _SOURCE:
            continue
        if system is None and not spec.all_types and name not in of_type:
            continue
        found.append(
            {
                "name": name,
                "label": spec.label or name,
                "type": spec.type,
                "required": bool(of_type.get(name, {}).get("required")),
                "system": bool(spec.system),
            }
        )
    found.sort(key=lambda item: (not item["required"], not item["system"], item["label"].lower()))
    return {
        "fields": found,
        "context": [
            {"entity": entity, "keys": list(keys), "path": f"{entity}(val.{told[0]} == obj.{told[0]})"}
            for entity, (keys, told) in incident_context.SCHEMA.items()
        ],
    }


# --------------------------------------------------------------------------- #
# What the shipped connectors come with                                       #
# --------------------------------------------------------------------------- #
def shipped() -> dict[str, dict[str, Any]]:
    """connector id → ``{"incoming": [...], "outgoing": [...], "classifier": {...}}``
    (``automation/seed/mappers/<id>.json``): the mappers a shipped connector starts with."""
    import json
    from pathlib import Path

    found = {}
    for path in sorted((Path(__file__).parent / "automation" / "seed" / "mappers").glob("*.json")):
        found[path.stem] = json.loads(path.read_text(encoding="utf-8"))
    return found


def seed(db: OrmSession) -> int:
    """Add the mappers the shipped connectors come with, for every type of incident, and bring
    up to date those nobody changed (the caller commits). A mapper someone saved is theirs."""
    changed = 0
    for connector_id, spec in shipped().items():
        if db.get(Connector, connector_id) is None:
            continue
        for direction in DIRECTIONS:
            rules = spec.get(direction)
            if not rules:
                continue
            row = db.scalars(
                select(Mapper).where(
                    Mapper.connector_id == connector_id, Mapper.direction == direction, Mapper.incident_type == ANY_TYPE
                )
            ).one_or_none()
            if row is not None and not row.builtin:
                continue
            cleaned = clean_rules(db, connector_id, direction, rules)
            if row is not None and row.rules == cleaned:
                continue
            body = {"connectorId": connector_id, "direction": direction, "incidentType": ANY_TYPE, "rules": rules}
            save_mapper(db, body, "nik", builtin=True)
            changed += 1
    return changed


def state_defaults(db: OrmSession) -> dict[str, Any]:
    """connector id → the classifier its pack gives a new instance."""
    from .automation import state

    return dict(state.read(db).get("classifierDefaults") or {})


def keep_default_classifier(db: OrmSession, connector_id: str, spec: dict[str, Any]) -> None:
    """Keep the classifier a connector's pack gives its new instances (the caller commits)."""
    from .automation import state

    held = dict(state.read(db).get("classifierDefaults") or {})
    if held.get(connector_id) != spec:
        held[connector_id] = spec
        state.write(db, classifierDefaults=held)


def forget_default_classifier(db: OrmSession, connector_id: str) -> None:
    from .automation import state

    held = dict(state.read(db).get("classifierDefaults") or {})
    if held.pop(connector_id, None) is not None:
        state.write(db, classifierDefaults=held)


def default_classifier(db: OrmSession, connection: Connection) -> bool:
    """Give a connection that has no classifier the one its connector came with: the one of its pack, or
    the one Nik ships for its own connectors (the caller commits)."""
    from .automation import state

    kept = (state.read(db).get("classifierDefaults") or {}).get(connection.connector_id)
    spec = kept or (shipped().get(connection.connector_id) or {}).get("classifier") or {}
    if db.get(Classifier, connection.id) is not None or not (spec.get("rules") or spec.get("defaultType")):
        return False
    try:
        save_classifier(db, connection, spec, "nik")
    except MappingError:
        return False  # a type it names was deleted: the connection starts with none
    return True
