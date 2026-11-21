"""The command line of the War Room: what a line means, and running it.

    !servicenow-get-incident number=INC001 using="ServiceNow prod"
    !ExtractDomains text=${context.Mail[0].Subject}
    !ip 185.220.101.47
    /note Called the user.      /assign @anna      /close
    anything else is a note

    line  := "!" name (ws pair)*  |  "/" name ws rest  |  text
    pair  := key "=" value   |   value            (a value alone is the first argument)
    value := bare | "quoted" | `json`

A ``!`` line names a command of a connector (``<connector id>-<command>``),
an action of Nik (``nik-add-tags``), a script, or a reputation command
(``ip``, ``domain``, ``url``, ``file``, ``email``). A bare value written
``${path}`` or ``{{ … }}`` is an expression on the incident and its context.
Reserved pairs: ``using=<connection>`` picks the connection, ``raw=true``
asks for the result as JSON, ``extend=<key>`` keeps the result out of the
context.

A command is a **run of one node** on the automation engine (kind ``adhoc``):
the same permission as running a playbook, the same egress rules and data
guard with nothing opened (it reaches the host of its connection and the
hosts listed for every playbook), the same audit. A command that changes
something outside is not started until the caller confirms it.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession
from sqlalchemy.orm.attributes import flag_modified

from . import war_room
from .automation import actions, engine
from .core.models import Connection, Incident, Playbook, PlaybookVersion, Run, Script
from .core.security import now_iso

ADHOC_ID = "adhoc"
_WHAT = {
    "ip": "an IP address",
    "domain": "a domain",
    "url": "a URL",
    "file": "a file hash",
    "email": "an e-mail address",
}
ADHOC_NAME = "War Room commands"
REPUTATION = ("ip", "domain", "url", "file", "email")
RESERVED = ("using", "raw", "extend")
SLASH = ("note", "assign", "close", "task")
LINE_MAX = 8000

_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_.-]*")
_KEY = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)=")
_REFERENCE = re.compile(r"^\$\{(.+)\}$", re.S)


class CommandError(ValueError):
    """What is wrong with a line, as a sentence for whoever typed it."""

    def __init__(self, message: str):
        super().__init__(message)
        self.message = message


@dataclass
class Parsed:
    kind: str  # note | command | slash
    name: str = ""
    args: dict[str, Any] = field(default_factory=dict)
    positional: list[Any] = field(default_factory=list)
    text: str = ""  # a note, or what follows a slash command
    using: str = ""
    raw: bool = False
    extend: str = ""


def _value(text: str, at: int) -> tuple[Any, int]:
    """Read one value at ``at``: a quoted text, a JSON between backticks, or a bare word."""
    char = text[at]
    if char in "\"'":
        out, index = [], at + 1
        while index < len(text):
            if text[index] == "\\" and index + 1 < len(text):
                out.append(text[index + 1])
                index += 2
            elif text[index] == char:
                return "".join(out), index + 1
            else:
                out.append(text[index])
                index += 1
        raise CommandError("A quote is not closed")
    if char == "`":
        end = text.find("`", at + 1)
        if end < 0:
            raise CommandError("A ` is not closed")
        try:
            return json.loads(text[at + 1 : end]), end + 1
        except ValueError:
            raise CommandError("What is between ` ` is not valid JSON") from None
    # A bare word; an expression may hold spaces: it ends where its braces do.
    for opener, closer in (("${", "}"), ("{{", "}}")):
        if text.startswith(opener, at):
            end = text.find(closer, at + len(opener))
            if end < 0:
                raise CommandError(f"An expression is not closed: {closer} is missing")
            return text[at : end + len(closer)], end + len(closer)
    end = at
    while end < len(text) and not text[end].isspace():
        end += 1
    return text[at:end], end


def parse(line: str) -> Parsed:
    """Read a line. Raises ``CommandError``."""
    line = str(line or "").strip()
    if not line:
        raise CommandError("Nothing was written")
    if len(line) > LINE_MAX:
        raise CommandError("The line is too long")
    if line[0] == "/":
        found = _NAME.match(line, 1)
        if not found or found.group(0).lower() not in SLASH:
            raise CommandError("A / command is one of: " + ", ".join(f"/{name}" for name in SLASH))
        return Parsed(kind="slash", name=found.group(0).lower(), text=line[found.end() :].strip())
    if line[0] != "!":
        return Parsed(kind="note", text=line)
    found = _NAME.match(line, 1)
    if not found:
        raise CommandError("After ! comes the name of a command")
    parsed = Parsed(kind="command", name=found.group(0))
    at = found.end()
    while at < len(line):
        if line[at].isspace():
            at += 1
            continue
        key = _KEY.match(line, at)
        if key and key.end() < len(line) and not line[key.end()].isspace():
            value, at = _value(line, key.end())
            name = key.group(1)
            if name == "using":
                parsed.using = str(value)
            elif name == "raw":
                parsed.raw = str(value).lower() in ("true", "yes", "1")
            elif name == "extend":
                parsed.extend = str(value)
            elif name in parsed.args:
                raise CommandError(f'"{name}" is given twice')
            else:
                parsed.args[name] = value
        elif key:
            raise CommandError(f'"{key.group(1)}=" has no value')
        else:
            value, at = _value(line, at)
            parsed.positional.append(value)
    return parsed


def _templated(value: Any) -> Any:
    """A value as a node holds it: ``${path}`` becomes ``{{ path }}``."""
    if isinstance(value, str):
        reference = _REFERENCE.match(value.strip())
        return "{{ " + reference.group(1).strip() + " }}" if reference else value
    return value


def _typed(argument: dict, value: Any) -> Any:
    """What was typed, as the argument's type wants it. Expressions are left for the engine."""
    if not isinstance(value, str) or "{{" in value:
        return value
    kind = argument.get("type") or "text"
    if kind == "number":
        try:
            number = float(value)
        except ValueError:
            raise CommandError(f"{argument['name']} is a number") from None
        return int(number) if number.is_integer() else number
    if kind == "bool":
        if value.lower() in ("true", "yes", "1"):
            return True
        if value.lower() in ("false", "no", "0"):
            return False
        raise CommandError(f"{argument['name']} is true or false")
    if kind == "list":
        return [part.strip() for part in value.split(",") if part.strip()]
    if kind == "choice" and argument.get("choices") and value not in argument["choices"]:
        raise CommandError(f"{argument['name']} is one of: " + ", ".join(str(c) for c in argument["choices"]))
    return value


# --------------------------------------------------------------------------- #
# What a name is                                                              #
# --------------------------------------------------------------------------- #
@dataclass
class Target:
    """What a ``!`` line runs: the node, and what the engine needs to know of it."""

    title: str
    node: dict[str, Any]
    changes: bool = False
    connector: str = ""
    # A reputation command: the kind and the value it looks up, when the value was typed as it is.
    lookup: tuple[str, str] | None = None


def _action_of(db: OrmSession, name: str) -> actions.Spec | None:
    """``servicenow-create-incident`` → the action ``servicenow.create-incident`` (an id may hold dashes)."""
    for at, char in enumerate(name):
        if char == "-":
            spec = actions.lookup(db, f"{name[:at]}.{name[at + 1 :]}")
            if spec is not None:
                return spec
    return None


def command_name(action_id: str) -> str:
    """The name a command is typed with: the id of its action with a dash for the dot."""
    return action_id.replace(".", "-", 1)


def confirm_answer(target: Target) -> dict[str, Any]:
    """What is answered (409) for a command that changes something outside Nik, until it is confirmed."""
    return {
        "detail": f"{target.title} changes something outside Nik: confirm to run it",
        "needsConfirm": True,
        "command": target.title,
    }


def resolve(db: OrmSession, parsed: Parsed) -> Target:
    """The node a parsed ``!`` line runs. Raises ``CommandError``."""
    name = parsed.name
    if name.lower() in REPUTATION:
        if len(parsed.positional) != 1 or parsed.args:
            raise CommandError(f"!{name.lower()} takes one value: !{name.lower()} <what to look up>")
        args = {"kind": name.lower(), "value": _templated(parsed.positional[0])}
        node = {"kind": "action", "config": {"action": "nik.reputation", "args": args, "approval": {"ask": False}}}
        typed = str(parsed.positional[0])
        lookup = (name.lower(), typed) if "{{" not in typed and "${" not in typed else None
        return Target(title=f"{name.lower()} {parsed.positional[0]}", node=node, lookup=lookup)
    script = db.scalars(select(Script).where(func.lower(Script.name) == name.lower())).first()
    if script is not None and script.current_version:
        from .automation import scripts as script_store

        version = script_store.current(db, script)
        declared = list(version.arguments or [])
        args = _arguments(declared, parsed)
        node = {"kind": "script", "config": {"script": script.name, "script_version": version.version, "args": args}}
        return Target(title=script.name, node=node)
    spec = _action_of(db, name)
    if spec is None:
        raise CommandError(f'There is no command called "{name}": type ! to see those there are')
    args = _arguments([dict(argument) for argument in spec.arguments], parsed)
    config: dict[str, Any] = {"action": spec.id, "args": args, "approval": {"ask": False}}
    connector = str(spec.extra.get("connector") or "")
    if spec.extra.get("needsConnection"):
        config["connection"] = _connection(db, connector, parsed.using)
    elif parsed.using:
        raise CommandError(f"{name} uses no instance: using= does not apply")
    return Target(
        title=command_name(spec.id),
        node={"kind": "action", "config": config},
        changes=spec.changes(args),
        connector=connector,
    )


def _arguments(declared: list[dict], parsed: Parsed) -> dict[str, Any]:
    known = {argument["name"]: argument for argument in declared}
    given = dict(parsed.args)
    if parsed.positional:
        if len(parsed.positional) > 1 or not declared:
            raise CommandError("A value with no name is the first argument: give the others as name=value")
        first = declared[0]["name"]
        if first in given:
            raise CommandError(f'"{first}" is given twice')
        given[first] = parsed.positional[0]
    out: dict[str, Any] = {}
    for name, value in given.items():
        if name not in known:
            raise CommandError(
                f'"{name}" is not an argument of this command'
                + (": " + ", ".join(known) if known else " (it takes none)")
            )
        out[name] = _typed(known[name], _templated(value))
    missing = [a["name"] for a in declared if a.get("required") and out.get(a["name"]) in (None, "", [])]
    if missing:
        raise CommandError("Needed: " + ", ".join(f"{name}=" for name in missing))
    return out


def _connection(db: OrmSession, connector_id: str, using: str) -> str:
    rows = db.scalars(
        select(Connection)
        .where(Connection.connector_id == connector_id, Connection.enabled.is_(True))
        .order_by(Connection.name)
    ).all()
    if not rows:
        raise CommandError("This command needs an instance of its connector that is on, and there is none")
    if using:
        found = next((row for row in rows if row.name.lower() == using.lower()), None)
        if found is None:
            raise CommandError("There is no such instance: " + ", ".join(row.name for row in rows))
        return found.name
    if len(rows) > 1:
        raise CommandError('Which connection? using="' + '" or using="'.join(row.name for row in rows) + '"')
    return rows[0].name


def catalog(db: OrmSession, prefix: str = "") -> list[dict[str, Any]]:
    """Every command there is, for the completion of the command line."""
    found: list[dict[str, Any]] = [
        {
            "name": kind,
            "description": f"What is known of {_WHAT[kind]}: the sources that are on (the connectors that judge it)",
            "arguments": [{"name": "value", "type": "text", "required": True}],
            "changesOutside": False,
            "needsConnection": False,
            "group": "Reputation",
        }
        for kind in REPUTATION
    ]
    for spec in actions.every(db):
        if spec.id == "nik.reputation" or spec.id.startswith("flow."):
            continue
        found.append(
            {
                "name": command_name(spec.id),
                "description": spec.description,
                "arguments": list(spec.arguments),
                "changesOutside": bool(spec.changes_outside),
                "needsConnection": bool(spec.extra.get("needsConnection")),
                "group": spec.group,
            }
        )
    from .automation import scripts as script_store

    for script in db.scalars(select(Script).where(Script.current_version.isnot(None)).order_by(Script.name)):
        version = script_store.current(db, script)
        found.append(
            {
                "name": script.name,
                "description": script.description,
                "arguments": list(version.arguments or []) if version is not None else [],
                "changesOutside": False,
                "needsConnection": False,
                "group": "Scripts",
            }
        )
    wanted = prefix.strip().lower()
    # The reputation commands first, then the others by name.
    found = found[: len(REPUTATION)] + sorted(found[len(REPUTATION) :], key=lambda item: item["name"].lower())
    return [item for item in found if not wanted or item["name"].lower().startswith(wanted)]


# --------------------------------------------------------------------------- #
# Running                                                                     #
# --------------------------------------------------------------------------- #
def adhoc_playbook(db: OrmSession) -> Playbook:
    """The playbook the commands of the War Room run as: never listed, never turned on, with
    nothing opened. Each command is a version of it with one node."""
    row = db.get(Playbook, ADHOC_ID)
    if row is None:
        stamp = now_iso()
        row = Playbook(
            id=ADHOC_ID,
            name=ADHOC_NAME,
            description="The commands typed in the War Room of an incident. Not a playbook to edit.",
            enabled=False,
            egress_mode="listed",
            egress_hosts=[],
            data_allow=[],
            max_runs_per_hour=10_000,
            one_per_object=False,
            max_seconds=3600,
            approval_default=False,
            builtin=True,
            created_at=stamp,
            created_by="nik",
            updated_at=stamp,
            updated_by="nik",
        )
        db.add(row)
        db.flush()
    return row


def start(
    db: OrmSession,
    incident: Incident | None,
    line: str,
    target: Target,
    parsed: Parsed,
    actor: str,
    *,
    button: str = "",
    payload: dict[str, Any] | None = None,
    classes: dict[str, list[str]] | None = None,
) -> tuple[Any, Run]:
    """Write the command in the War Room of the incident and start its run (the caller commits).
    With no incident it is written in the Playground of who typed it, and its run works on nothing.

    ``button`` is the text of the script button that was pressed, when the command was not typed
    (buttons.py): the entry says so, and ``payload`` (with its ``classes``) is what the node reads
    under ``trigger`` beside the line: the arguments the server rendered for it."""
    playbook = adhoc_playbook(db)
    number = (
        db.scalar(select(func.max(PlaybookVersion.version)).where(PlaybookVersion.playbook_id == playbook.id)) or 0
    ) + 1
    node = {"id": "command", "name": target.title, "position": {"x": 40, "y": 160}, **target.node}
    shape = {
        "nodes": [
            {
                "id": "start",
                "kind": "trigger",
                "name": (
                    f"Pressed: {button}"[:200]
                    if button
                    else "Typed in the War Room"
                    if incident is not None
                    else "Typed in the Playground"
                ),
                "position": {"x": 40, "y": 40},
                "config": {"manual": True},
            },
            node,
        ],
        "edges": [{"from": "start", "to": "command"}],
    }
    db.add(
        PlaybookVersion(
            playbook_id=playbook.id,
            version=number,
            graph=shape,
            note=line[:500],
            created_at=now_iso(),
            created_by=actor,
        )
    )
    db.flush()
    said = {"line": line, "command": target.title, "raw": parsed.raw, "extend": parsed.extend}
    if button:
        said["button"] = button[:200]
    if incident is None:
        from . import playground

        entry = playground.add(db, actor, "command", said)
    else:
        entry = war_room.add(db, incident.id, "command", said, actor)
    now = time.time()
    run = engine.start_run(
        db,
        playbook,
        kind="adhoc",
        payload={**(payload or {}), "actor": actor, "line": line},
        classes={**(classes or {}), "actor": ["private_value"]},
        object_kind="incident" if incident is not None else "",
        object_id=incident.id if incident is not None else "",
        incident_id=incident.id if incident is not None else None,
        started_by=actor,
        version=number,
        now=now,
    )
    run.trigger = {**(run.trigger or {}), "entry_id": entry.id, "no_context": bool(parsed.extend)}
    if incident is None:
        # Whose Playground the results go to (playground.step_done).
        run.trigger["playground"] = actor
    flag_modified(run, "trigger")
    entry.run_id = run.id
    return entry, run
