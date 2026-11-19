"""What the canvas library lists, and what a graph is validated against.

The library has every node there is, in groups: **Flow** (the kinds of node
that shape a playbook), then one group per family of actions (**Nik**,
**HTTP**, **E-mail**; one per connector from 4.2), then **Scripts**. An entry
says what the node takes and gives, which is what the inspector builds its
form and the "pick a value" tree from.
"""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session as OrmSession

from ..core.models import Connection, Connector, Playbook, PlaybookVersion, Script, ScriptVersion
from . import actions, graph

FLOW = [
    {
        "id": "flow.condition",
        "kind": "condition",
        "name": "Condition",
        "description": "Go one way when the comparisons hold, another when they do not.",
        "outputs": [{"name": "result", "type": "bool", "description": "Whether the condition held"}],
    },
    {
        "id": "flow.for_each",
        "kind": "for_each",
        "name": "For each",
        "description": "Do the same steps for every item of a list (500 at most), five at a time.",
        "outputs": [
            {"name": "count", "type": "number", "description": "How many items there were"},
            {"name": "failed", "type": "number", "description": "How many of them failed"},
            {"name": "results", "type": "list", "description": "What the steps gave for each item, in order"},
        ],
    },
    {
        "id": "flow.wait",
        "kind": "wait",
        "name": "Wait",
        "description": "Wait for a time, or until a condition holds.",
        "outputs": [
            {"name": "waited", "type": "number", "description": "Seconds waited"},
            {"name": "timed_out", "type": "bool", "description": "The condition never held"},
        ],
    },
    {
        "id": "flow.approval",
        "kind": "approval",
        "name": "Approval",
        "description": "Stop and ask a person; go on by their answer.",
        "outputs": [
            {"name": "answer", "type": "text", "description": "approved, refused or expired"},
            {"name": "by", "type": "text", "description": "Who answered"},
            {"name": "at", "type": "text", "description": "When"},
            {"name": "comment", "type": "text", "description": "What they wrote"},
        ],
    },
    {
        "id": "flow.task",
        "kind": "task",
        "name": "Task",
        "description": "Give a person something to do and wait until it is done.",
        "outputs": [
            {"name": "by", "type": "text", "description": "Who did it"},
            {"name": "at", "type": "text", "description": "When"},
            {"name": "comment", "type": "text", "description": "What they wrote"},
            {"name": "fields", "type": "object", "description": "The fields they filled, by name"},
            {"name": "skipped", "type": "text", "description": "Why it was skipped, when it was"},
            {"name": "overdue", "type": "bool", "description": "True after its due time, until it is done"},
            {"name": "task", "type": "text", "description": "The id of the task"},
        ],
    },
    {
        "id": "flow.ask",
        "kind": "ask",
        "name": "Question",
        "description": "Ask a person to choose or to fill a small form; go on by their answer.",
        "outputs": [
            {"name": "choice", "type": "text", "description": "The choice they made"},
            {"name": "values", "type": "object", "description": "What they typed, by name"},
            {"name": "fields", "type": "object", "description": "The fields they filled, by name"},
            {"name": "by", "type": "text", "description": "Who answered"},
            {"name": "at", "type": "text", "description": "When"},
            {"name": "comment", "type": "text", "description": "What they wrote"},
            {"name": "skipped", "type": "text", "description": "Why there is no answer, when nobody gave one"},
            {"name": "task", "type": "text", "description": "The id of the question"},
        ],
    },
    {
        "id": "flow.playbook",
        "kind": "playbook",
        "name": "Run another playbook",
        "description": "Start another playbook and, if you want, wait for what it gives.",
        "outputs": [
            {"name": "run", "type": "text", "description": "The id of the run it started"},
            {"name": "result", "type": "object", "description": "The outputs the other playbook declares"},
        ],
    },
    {
        "id": "flow.end",
        "kind": "end",
        "name": "End",
        "description": "Finish the run here, as done or as failed, with a message.",
        "outputs": [],
    },
]
for _entry in FLOW:
    _entry.setdefault("group", "Flow")
    _entry.setdefault("arguments", [])


# Kept for the graphs that name them, not offered in the library (5.1: mail is a connector).
RETIRED = frozenset({"email.send"})


class Library:
    """The actions, scripts and playbooks a graph can name, read from the database."""

    def __init__(self, db: OrmSession):
        self.db = db

    def action(self, action_id: str) -> dict | None:
        spec = actions.lookup(self.db, action_id)
        return spec.entry() if spec else None

    def script(self, name: str, version: int | None) -> dict | None:
        script = self.db.scalars(select(Script).where(Script.name == name)).first()
        if script is None or not isinstance(version, int):
            return None
        row = self.db.get(ScriptVersion, (script.id, version))
        if row is None:
            return None
        return {"arguments": row.arguments or [], "outputs": row.outputs or []}

    def connections(self, connector_id: str) -> list[tuple[str, str]]:
        """(id, name) of the connections of a connector."""
        rows = self.db.execute(select(Connection.id, Connection.name).where(Connection.connector_id == connector_id))
        return [(row[0], row[1]) for row in rows]

    def fillable_fields(self) -> set[str]:
        """The fields of incidents a task or a question may ask a person to fill."""
        from .. import tasks

        return tasks.fillable(self.db)

    def playbook_graph(self, name: str) -> dict | None:
        playbook = self.db.scalars(select(Playbook).where(Playbook.name == name)).first()
        if playbook is None or not playbook.current_version:
            return None
        row = self.db.get(PlaybookVersion, (playbook.id, playbook.current_version))
        return row.graph if row else None


def script_entries(db: OrmSession) -> list[dict[str, Any]]:
    """The scripts in the library: those with a saved version, at their current one."""
    out = []
    for script in db.scalars(select(Script).where(Script.current_version.isnot(None)).order_by(Script.name)):
        row = db.get(ScriptVersion, (script.id, script.current_version))
        if row is None:
            continue
        out.append(
            {
                "id": f"script.{script.name}",
                "kind": "script",
                "group": "Scripts",
                "name": script.name,
                "description": script.description,
                "script": script.name,
                "version": script.current_version,
                "arguments": row.arguments or [],
                "outputs": row.outputs or [],
            }
        )
    return out


def entries(db: OrmSession) -> list[dict[str, Any]]:
    """Every node of the library. An entry of a connector says which one (``connector``) and
    whether it can be used now (``available``: one of its instances is on); one kept only for the
    playbooks made before is ``retired`` and is not offered for new nodes."""
    from . import connector_actions

    connectors = set(db.scalars(select(Connector.id)))
    enabled = connector_actions.enabled_connectors(db)
    found = []
    for spec in actions.every(db):
        entry = spec.entry()
        head = spec.id.split(".", 1)[0]
        if head in connectors:
            entry["connector"] = head
            entry["available"] = head in enabled
        if spec.id in RETIRED:
            entry["retired"] = True
        found.append(entry)
    return [*FLOW, *found, *script_entries(db)]


def updates(db: OrmSession, shape: dict) -> list[dict[str, Any]]:
    """The nodes of a graph whose script has a newer version than the one they stay on."""
    current = {entry["script"]: entry["version"] for entry in script_entries(db)}
    found = []
    for node in graph.nodes_of(shape).values():
        config = node.get("config") or {}
        if node.get("kind") != "script":
            continue
        latest = current.get(str(config.get("script")))
        if latest and isinstance(config.get("script_version"), int) and latest > config["script_version"]:
            found.append(
                {"node": node["id"], "script": config["script"], "from": config["script_version"], "to": latest}
            )
    return found


def connections(db: OrmSession) -> dict[str, list[dict[str, Any]]]:
    """connector id → its instances (id, name, whether it is on), for the inspector of a connector's node."""
    found: dict[str, list[dict[str, Any]]] = {}
    wanted = select(Connection.id, Connection.name, Connection.connector_id, Connection.enabled)
    for row in db.execute(wanted.order_by(Connection.name)):
        found.setdefault(row[2], []).append({"id": row[0], "name": row[1], "enabled": bool(row[3])})
    return found
