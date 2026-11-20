"""The registry of what an ``action`` node can do.

An action has an id (``nik.add-note``, ``http.request``), a description of
its arguments and outputs (what the canvas builds its form from) and a
function. Modules register theirs when imported (``nik_actions``, the HTTP and
e-mail nodes; connector commands in 4.2 are entries of the same registry,
looked up by ``<connector>.<command>``).

    @action("nik.add-note", group="Nik", name="Add a note", arguments=[…], outputs=[…])
    def add_note(call: Call) -> Result: …

An output that is an object or a list says what is inside it with ``shape``, so
the editor can offer ``create_incident.incident.id`` and not only the object:
either the name of a shape the catalog carries once (``"incident"``,
``"fields"``: see ``catalog.shapes``) or a list of ``{name, type, description}``
whose names are paths under the output (``verdict``, ``[0].value``). A shape
is a promise: every path in it is there whenever the action succeeds, in a dry
run too (tests/test_automation_shapes.py holds each action to it; the first
item of a list is there when the list has one).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session as OrmSession

from .expressions import Value


class ActionError(Exception):
    """An action that failed, with a sentence that is safe to show.

    ``retry`` False: trying again cannot help (a refusal, a missing object).
    ``unknown_outcome``: the request left and no answer came back.
    """

    def __init__(self, message: str, *, retry: bool = True, unknown_outcome: bool = False, request: dict | None = None):
        super().__init__(message)
        self.message = message
        self.retry = retry
        self.unknown_outcome = unknown_outcome
        self.request = request


@dataclass
class Call:
    """What an action is given."""

    db: OrmSession
    args: dict[str, Any]  # rendered arguments
    classes: frozenset  # the classes of data the arguments hold together
    arg_classes: dict[str, list]  # per argument: {"text": ["email_address"]}
    dry_run: bool
    run: Any  # the Run (read it, do not change it)
    playbook: Any  # the Playbook (its egress and data settings)
    step_id: str = ""
    approved_by: str | None = None
    now: float = 0.0
    held: str = "fail"  # what the node does with data the guard holds back: fail | drop
    connection: str = ""  # the connection a connector command uses (its id or its name)
    state: dict | None = None  # what the action left when it asked to be called again


@dataclass
class Result:
    """What an action gives back."""

    output: Any = None
    classes: dict[str, list] = field(default_factory=dict)  # of the output: {path: [class]}
    request: dict | None = None  # what was sent, or would have been (dry run): method, host, path, held…
    log: str | None = None
    # "Call me again at this time": the step waits without holding a worker (a command that polls).
    again_at: float | None = None
    state: dict | None = None  # given back in ``Call.state`` at that time
    # What goes to the context of the incident the run works on: (context path, value). The engine
    # writes it (never in a dry run), with ``context_source`` as who set it (the run when left out).
    context: list[tuple[str, Any]] = field(default_factory=list)
    context_source: str = ""


@dataclass(frozen=True)
class Spec:
    id: str
    group: str
    name: str
    description: str
    arguments: tuple
    outputs: tuple
    changes_outside: bool
    idempotent: bool
    timeout: int
    run: Callable[[Call], Result]
    outside: Callable[[dict], bool] | None = None  # when it depends on the arguments (a GET changes nothing)
    extra: dict = field(default_factory=dict)  # more for the catalog: the connector a command belongs to

    def changes(self, args: dict) -> bool:
        """Whether this call changes something outside Nik."""
        return bool(self.outside(args)) if self.outside is not None else self.changes_outside

    def entry(self) -> dict:
        """The action as the catalog lists it."""
        return {
            "id": self.id,
            "kind": "action",
            "group": self.group,
            "name": self.name,
            "description": self.description,
            "arguments": list(self.arguments),
            "outputs": list(self.outputs),
            "changesOutside": self.changes_outside,
            **self.extra,
        }


_REGISTRY: dict[str, Spec] = {}


def action(
    action_id: str,
    *,
    group: str,
    name: str,
    description: str = "",
    arguments: list[dict] | None = None,
    outputs: list[dict] | None = None,
    changes_outside: bool = False,
    outside: Callable[[dict], bool] | None = None,
    idempotent: bool = True,
    timeout: int = 60,
):
    def register(fn: Callable[[Call], Result]):
        _REGISTRY[action_id] = Spec(
            id=action_id,
            group=group,
            name=name,
            description=description,
            arguments=tuple(arguments or ()),
            outputs=tuple(outputs or ()),
            changes_outside=changes_outside or outside is not None,
            idempotent=idempotent,
            timeout=timeout,
            run=fn,
            outside=outside,
        )
        return fn

    return register


def get(action_id: str) -> Spec | None:
    return _REGISTRY.get(action_id)


# Actions that are not written in code: the commands of the connectors that are installed.
# A provider answers ``find(db, action_id)`` and ``every(db)``.
_PROVIDERS: list[Any] = []


def provide(provider: Any) -> None:
    if provider not in _PROVIDERS:
        _PROVIDERS.append(provider)


def lookup(db: OrmSession, action_id: str) -> Spec | None:
    """An action by its id: one written in code, or a command of an installed connector."""
    found = _REGISTRY.get(action_id)
    if found is not None:
        return found
    for provider in _PROVIDERS:
        found = provider.find(db, action_id)
        if found is not None:
            return found
    return None


def every(db: OrmSession) -> list[Spec]:
    """Every action there is: those written in code, then those of the connectors."""
    found = list(all_specs())
    for provider in _PROVIDERS:
        found += provider.every(db)
    return found


def all_specs() -> list[Spec]:
    return sorted(_REGISTRY.values(), key=lambda spec: (spec.group, spec.name))


def unregister(action_id: str) -> None:
    """For tests that register an action of their own."""
    _REGISTRY.pop(action_id, None)


def argument_values(spec: Spec, rendered: Value) -> dict[str, Any]:
    """The rendered arguments with the defaults of those left out."""
    given = rendered.data if isinstance(rendered.data, dict) else {}
    out = {}
    for arg in spec.arguments:
        value = given.get(arg["name"])
        if value is None or value == "":
            value = arg.get("default")
        out[arg["name"]] = value
    return out
