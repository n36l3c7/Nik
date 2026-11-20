"""Script buttons: a script run on an incident from a button of its page (6.2).

A type of incident puts buttons on its pages (``incident_types.clean_buttons``):
each has a text, two colours, a script, and for every argument of the script a
template, or nothing.

    address   {{ sender_address }}      filled from the incident
    urls      {{ urls_in_mail }}        a field that holds several values
    reason                              left empty: asked when the button is pressed

A template is written in the ``{{ }}`` language of playbooks (expressions.py).
It reads the fields of the incident by their names (``{{ sender_address }}``,
or ``{{ incident.host }}``; ``incident.number``, ``incident.user`` and
``incident.url`` are there too) and its context (``{{ context.Mail[0].From }}``).

**The server renders.** The page sends the templates it was given and what
the person typed; what the script receives is worked out here, from the
incident as it is now. A template that gives nothing (the field is empty) is
asked like an argument that was left empty.

**A field that holds several values runs the script once for each.** One
argument at most may do so: with two, nobody could tell which values go
together, and the press is refused with the way out (``| join(", ")``).

A press is a command of the War Room that nobody typed: each run is written
there as ``!Script name=value``, runs on the automation engine as a run of one
node (``commands.start``), puts its result under its line, and leaves a line
in the audit log. It asks for what a command asks for: ``automation.run``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session as OrmSession

from . import commands
from . import context as incident_context
from . import fields as registry
from .automation import expressions as ex
from .automation import payloads
from .automation import scripts as script_store
from .core import audit
from .core.models import Incident, Run, RunStep, Script, ScriptVersion

# Above this many runs the page asks a second time before it starts them. Nothing is refused here.
WARN_RUNS = 50
STATUS_MAX = 500
# Beside the fields of the registry, under ``incident.``: what people call an incident by.
ALIASES = {"number": "Number", "user": "User", "url": "Address in Nik"}
_BARE = re.compile(r"^[^\s\"'`{}$=]+$")
_EMPTY = (None, "", [], {})


class ButtonError(ValueError):
    """Why a button cannot run, as a sentence for whoever pressed it."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status


# --------------------------------------------------------------------------- #
# The scripts a button can run                                                #
# --------------------------------------------------------------------------- #
def library(db: OrmSession) -> list[dict[str, Any]]:
    """The scripts with a saved version, each with the arguments its current version takes."""
    found = []
    for script in db.scalars(select(Script).where(Script.current_version.isnot(None)).order_by(Script.name)):
        version = script_store.current(db, script)
        if version is None:
            continue
        found.append(
            {
                "name": script.name,
                "description": script.description,
                "version": version.version,
                "arguments": list(version.arguments or []),
            }
        )
    return found


def _script(db: OrmSession, name: str) -> tuple[Script, ScriptVersion]:
    script = db.scalars(select(Script).where(func.lower(Script.name) == str(name or "").lower())).first()
    if script is None:
        raise ButtonError(f'There is no script called "{name}": it was renamed or deleted', 404)
    version = script_store.current(db, script) if script.current_version else None
    if version is None:
        raise ButtonError(f"{script.name} has no saved version: save one in Automations, Scripts, before it can run")
    return script, version


# --------------------------------------------------------------------------- #
# What a template reads                                                       #
# --------------------------------------------------------------------------- #
def scope_of(db: OrmSession, incident: Incident) -> ex.Scope:
    """The names a template of a button reads: every field of incidents by its name (empty ones
    too, so that an empty field is told apart from a name that does not exist), the same under
    ``incident`` with what an incident is called by, and its context."""
    held = registry.read(db, incident)
    known = registry.registry(db)
    values: dict[str, Any] = {
        name: held.get(name) for name, spec in known.items() if spec.applies_to == "incident" or spec.system
    }
    values.update(held)
    classes: dict[str, dict[str, list]] = {name: {"": kinds} for name, kinds in payloads.registry_classes().items()}
    values["incident"] = {
        **values,
        "number": incident.number,
        "user": held.get("username"),
        "url": f"/incident/{incident.id}",
    }
    classes["incident"] = {**payloads.registry_classes(), "user": ["private_value"], "number": ["nik_id"]}
    values["context"] = incident_context.read(db, incident.id)
    classes["context"] = incident_context.classes()
    return ex.Scope(values=values, classes=classes)


def _source(template: str, known: dict) -> dict[str, str] | None:
    """The field a template takes its value from, when it is one expression on one field."""
    try:
        parts = ex.parse(template)
    except ex.ExpressionError:
        return None
    if len(parts) != 1 or not isinstance(parts[0], ex.Expr):
        return None
    expr = parts[0]
    if not expr.root:
        return None  # something computed, not one field
    name = expr.root
    if expr.root == "incident" and expr.steps and isinstance(expr.steps[0], str):
        name = expr.steps[0]
    elif expr.root in ("incident", "context"):
        return {"field": ex.path_text(expr), "label": ex.path_text(expr)}
    if name in known:
        return {"field": name, "label": known[name].label or name}
    if expr.root == "incident" and name in ALIASES:
        return {"field": f"incident.{name}", "label": ALIASES[name]}
    return {"field": ex.path_text(expr), "label": ex.path_text(expr)}


def _shaped(argument: dict, value: Any) -> Any:
    """A value as the argument's type wants it: one value for a list is a list of one."""
    if (argument.get("type") or "any") == "list" and not isinstance(value, (list, tuple)):
        return [value]
    return value


# --------------------------------------------------------------------------- #
# The plan of a press                                                         #
# --------------------------------------------------------------------------- #
@dataclass
class Plan:
    """What a press would run: the script, what each argument holds, and the runs it makes."""

    script: Script
    version: ScriptVersion
    arguments: list[dict[str, Any]]
    # The argument that holds several values (None when none does) with those values, and the
    # arguments of each run.
    each: str | None = None
    items: list[Any] = field(default_factory=list)
    runs: list[dict[str, Any]] = field(default_factory=list)
    classes: dict[str, list[str]] = field(default_factory=dict)
    missing: list[str] = field(default_factory=list)

    def out(self) -> dict[str, Any]:
        return {
            "script": self.script.name,
            "version": self.version.version,
            "description": self.script.description,
            "arguments": self.arguments,
            "each": self.each,
            "runs": len(self.runs),
            "items": list(self.items),
            "missing": self.missing,
            "warnAbove": WARN_RUNS,
        }


def plan(
    db: OrmSession,
    incident: Incident,
    script_name: str,
    templates: dict[str, Any] | None,
    typed: dict[str, Any] | None = None,
) -> Plan:
    """Work out a press: render the templates on the incident, take what was typed for the rest.

    Each argument comes out ``filled`` (with its ``value``, and ``count`` when it holds several)
    or ``ask`` (with ``problem`` when a template was there and gave nothing). ``missing`` lists
    the required ones nobody filled: the press cannot start while it is not empty."""
    script, version = _script(db, script_name)
    known = registry.registry(db)
    scope = scope_of(db, incident)
    templates = templates if isinstance(templates, dict) else {}
    typed = typed if isinstance(typed, dict) else {}
    arguments: list[dict[str, Any]] = []
    fixed: dict[str, Any] = {}
    classes: dict[str, list[str]] = {}
    several: list[tuple[str, list]] = []
    missing: list[str] = []

    for declared in version.arguments or []:
        name = declared["name"]
        template = str(templates.get(name) or "").strip()
        shown: dict[str, Any] = {
            "name": name,
            "type": declared.get("type") or "any",
            "required": bool(declared.get("required")),
            "description": declared.get("description") or "",
            "template": template,
            "state": "ask",
        }
        if template:
            shown["source"] = _source(template, known)
            what = (shown["source"] or {}).get("label") or "The template"
            try:
                rendered = ex.render_text(template, scope)
            except ex.ExpressionError as error:
                rendered = None
                nothing = error.message.startswith("There is nothing at")
                shown["problem"] = f"{what} is empty on this incident" if nothing else error.message
            value = rendered.data if rendered is not None else None
            if isinstance(value, (list, tuple)):
                # Several values: one run for each. One value alone is that value.
                value = [item for item in value if item not in _EMPTY]
                if len(value) > 1:
                    several.append((name, value))
                    shown.update(state="filled", value=value, count=len(value))
                    classes[f"args.{name}"] = sorted(rendered.classes)
                    value = None
                else:
                    value = value[0] if value else None
            if shown["state"] == "filled":
                pass  # several values: the runs are made below
            elif value in _EMPTY:
                shown.setdefault("problem", f"{what} is empty on this incident")
            else:
                fixed[name] = _shaped(declared, value)
                shown.update(state="filled", value=value)
                classes[f"args.{name}"] = sorted(rendered.classes)
        if shown["state"] == "ask":
            given = typed.get(name)
            if given not in _EMPTY:
                try:
                    fixed[name] = commands._typed(declared, given)
                except commands.CommandError as error:
                    raise ButtonError(error.message) from None
                shown["typed"] = given
            elif shown["required"]:
                missing.append(name)
        arguments.append(shown)

    if len(several) > 1:
        names = ", ".join(name for name, _ in several)
        raise ButtonError(
            f"Two arguments hold several values ({names}): a button runs once for each value of one "
            'argument. Make one text of the other in the settings of the button, with | join(", ")'
        )
    declared_by_name = {item["name"]: item for item in version.arguments or []}
    if several:
        name, items = several[0]
        runs = [{**fixed, name: _shaped(declared_by_name[name], item)} for item in items]
    else:
        runs = [dict(fixed)]
    return Plan(
        script=script,
        version=version,
        arguments=arguments,
        each=several[0][0] if several else None,
        items=list(several[0][1]) if several else [],
        runs=runs,
        classes=classes,
        missing=missing,
    )


# --------------------------------------------------------------------------- #
# Running                                                                     #
# --------------------------------------------------------------------------- #
def _written(value: Any) -> str:
    """A value as the command line reads it back: a bare word, a quoted text, or JSON between ` `."""
    if isinstance(value, str):
        if _BARE.match(value):
            return value
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    return "`" + json.dumps(value, ensure_ascii=False) + "`"


def command_line(script: str, args: dict[str, Any]) -> str:
    """The line a run is written with in the War Room: what typing the same command would be."""
    line = " ".join([f"!{script}", *(f"{name}={_written(value)}" for name, value in args.items())])
    return line if len(line) <= commands.LINE_MAX else line[: commands.LINE_MAX - 1] + "…"


def start(
    db: OrmSession, incident: Incident, label: str, planned: Plan, actor: str, only: list[int] | None = None
) -> list[dict[str, Any]]:
    """Start the runs of a press (the caller commits): each a command in the War Room of the
    incident and a line of the audit log. ``only`` keeps the runs at those places: the ones
    that failed, to run again."""
    if planned.missing:
        raise ButtonError("Needed: " + ", ".join(planned.missing))
    label = (label or planned.script.name).strip()[:200]
    wanted = set(only) if only is not None else None
    started = []
    for index, args in enumerate(planned.runs):
        if wanted is not None and index not in wanted:
            continue
        # The node reads the values from what started the run: they are data there, never read
        # again as expressions, whatever a field of the incident holds.
        node = {
            "kind": "script",
            "config": {
                "script": planned.script.name,
                "script_version": planned.version.version,
                "args": {name: "{{ trigger.args." + name + " }}" for name in args},
            },
        }
        entry, run = commands.start(
            db,
            incident,
            command_line(planned.script.name, args),
            commands.Target(title=planned.script.name, node=node),
            commands.Parsed(kind="command", name=planned.script.name),
            actor,
            button=label,
            payload={"args": args, "button": label},
            classes=planned.classes,
        )
        item = planned.items[index] if planned.each else None
        audit.record(
            db,
            actor,
            "button.run",
            f'Pressed "{label}": ran {planned.script.name}'
            + (f" for {ex._text(item)[:200]}" if planned.each else "")
            + (f" ({index + 1} of {len(planned.runs)})" if len(planned.runs) > 1 else ""),
            incident,
            target=planned.script.name,
        )
        started.append({"index": index, "item": item, "runId": run.id, "entryId": entry.id})
    return started


def _seconds(start_at: str | None, end_at: str | None) -> int | None:
    try:
        began = datetime.fromisoformat(str(start_at).replace("Z", "+00:00"))
        ended = datetime.fromisoformat(str(end_at).replace("Z", "+00:00"))
    except ValueError:
        return None
    return max(0, int((ended - began).total_seconds() * 1000))


def status(db: OrmSession, incident: Incident, run_ids: list[str]) -> list[dict[str, Any]]:
    """Where the runs of a press are: each ``running``, ``done`` (with how long it took) or
    ``failed`` (with why). A run that is not a command of this incident is left out."""
    wanted = [str(run_id) for run_id in run_ids][:STATUS_MAX]
    if not wanted:
        return []
    runs = db.scalars(select(Run).where(Run.id.in_(wanted), Run.incident_id == incident.id)).all()
    steps = {
        step.run_id: step
        for step in db.scalars(
            select(RunStep).where(RunStep.run_id.in_([run.id for run in runs]), RunStep.node_id == "command")
        )
    }
    found = {}
    for run in runs:
        if (run.trigger or {}).get("kind") != "adhoc":
            continue
        step = steps.get(run.id)
        state = "done" if run.status == "done" else "running" if run.status in ("running", "waiting") else "failed"
        item: dict[str, Any] = {"runId": run.id, "status": state}
        if state != "running":
            took = _seconds(step.started_at, step.finished_at) if step is not None else None
            item["durationMs"] = took if took is not None else _seconds(run.started_at, run.finished_at)
        if state == "failed":
            item["error"] = (step.error if step is not None else None) or run.error or f"The run ended {run.status}"
        found[run.id] = item
    return [found[run_id] for run_id in wanted if run_id in found]
