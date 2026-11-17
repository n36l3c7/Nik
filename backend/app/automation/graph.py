"""The graph of a playbook: its shape, and what makes it valid.

    {"nodes": [{"id", "kind", "name", "position": {"x", "y"}, "config": {…}}],
     "edges": [{"from", "port"?, "to"}],
     "inputs": [{"name", "type", "required", "default"}],   # of a playbook run by another, or by hand
     "outputs": [{"name", "from"}]}

A version is saved only when ``validate`` finds nothing; a draft may be
anything. The rules keep a run predictable:

- one trigger; ids unique; edges between existing nodes and ports;
- no cycle. A "for each" is not a loop in the graph: its body hangs off its
  ``each`` port and ends there, and the flow goes on from ``done``;
- an expression reads only what is certain to have run before it: the
  trigger, a node every path to it passes through, and inside a "for each"
  body the ``item`` and ``index`` of that loop;
- what a node needs is there: required arguments, an action or a script
  version that exists, numbers within their limits.

Where two branches meet, the node after them waits for every branch that can
still reach it (engine.py); a branch not taken is dead and does not hold it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Protocol

from . import expressions

MAX_NODES = 200
MAX_EDGES = 600
ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,31}$")
INPUT_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")

KINDS = ("trigger", "condition", "for_each", "wait", "approval", "action", "script", "playbook", "end")

# The ports a node leaves by. ``error`` is drawn only when a failure is handled.
PORTS = {
    "trigger": ("out",),
    "condition": ("yes", "no"),
    "for_each": ("each", "done", "error"),
    "wait": ("out",),
    "approval": ("approved", "refused"),
    "action": ("out", "error"),
    "script": ("out", "error"),
    "playbook": ("out", "error"),
    "end": (),
}
DEFAULT_PORT = {kind: (ports[0] if ports else "") for kind, ports in PORTS.items()}
DEFAULT_PORT["for_each"] = "done"

OPERATORS = ("eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "matches", "exists", "empty")
ARGUMENT_TYPES = ("text", "number", "bool", "list", "object", "any", "choice", "file")

# The events a trigger can wait for in this release (the others come with their features).
EVENTS = ("incident.created", "incident.updated")

# Names an expression may read besides the nodes before it.
ALWAYS = ("trigger", "run", "inputs")
IN_LOOP = ("item", "index")

WAIT_MIN, WAIT_MAX = 60, 2_592_000
EACH_MAX = 500
RETRY_MAX = 100
CALL_DEPTH = 5


@dataclass(frozen=True)
class Problem:
    """What is wrong with a graph, and where: a node (or none) and a field of it."""

    message: str
    node: str | None = None
    field: str | None = None

    def as_dict(self) -> dict:
        return {"message": self.message, "node": self.node, "field": self.field}


class Library(Protocol):
    """What a graph is validated against: the actions and scripts that exist."""

    def action(self, action_id: str) -> dict | None: ...

    def script(self, name: str, version: int | None) -> dict | None: ...

    def playbook_graph(self, name: str) -> dict | None: ...


# --------------------------------------------------------------------------- #
# Shape                                                                       #
# --------------------------------------------------------------------------- #
def nodes_of(graph: dict) -> dict[str, dict]:
    return {node["id"]: node for node in graph.get("nodes") or [] if isinstance(node, dict) and "id" in node}


def port_of(edge: dict, kinds: dict[str, str]) -> str:
    """The port an edge leaves by (the node's first one when it names none)."""
    return edge.get("port") or DEFAULT_PORT.get(kinds.get(edge.get("from"), ""), "out")


def edges_from(graph: dict) -> dict[str, list[tuple[str, str]]]:
    """node id → [(port, target)]."""
    kinds = {node_id: node.get("kind", "") for node_id, node in nodes_of(graph).items()}
    out: dict[str, list[tuple[str, str]]] = {node_id: [] for node_id in kinds}
    for edge in graph.get("edges") or []:
        if isinstance(edge, dict) and edge.get("from") in out:
            out[edge["from"]].append((port_of(edge, kinds), edge.get("to")))
    return out


def edges_to(graph: dict) -> dict[str, list[tuple[str, str]]]:
    """node id → [(source, port)]."""
    out: dict[str, list[tuple[str, str]]] = {node_id: [] for node_id in nodes_of(graph)}
    for source, targets in edges_from(graph).items():
        for port, target in targets:
            if target in out:
                out[target].append((source, port))
    return out


def trigger_of(graph: dict) -> dict | None:
    found = [node for node in nodes_of(graph).values() if node.get("kind") == "trigger"]
    return found[0] if len(found) == 1 else None


def topological(graph: dict) -> list[str] | None:
    """The nodes in an order where each comes after what leads to it; None when there is a cycle."""
    outgoing = edges_from(graph)
    incoming = {node_id: len(sources) for node_id, sources in edges_to(graph).items()}
    ready = sorted(node_id for node_id, count in incoming.items() if count == 0)
    order: list[str] = []
    while ready:
        node_id = ready.pop(0)
        order.append(node_id)
        for _port, target in outgoing.get(node_id, []):
            if target in incoming:
                incoming[target] -= 1
                if incoming[target] == 0:
                    ready.append(target)
    return order if len(order) == len(incoming) else None


def reachable(graph: dict, start: str, port: str | None = None) -> set[str]:
    """Everything a node leads to (from one of its ports only, when named)."""
    outgoing = edges_from(graph)
    todo = [target for found, target in outgoing.get(start, []) if port is None or found == port]
    seen: set[str] = set()
    while todo:
        node_id = todo.pop()
        if node_id in seen or node_id not in outgoing:
            continue
        seen.add(node_id)
        todo += [target for _port, target in outgoing[node_id]]
    return seen


def loop_bodies(graph: dict) -> dict[str, set[str]]:
    """for_each node id → the nodes of its body (what its ``each`` port leads to)."""
    return {
        node_id: reachable(graph, node_id, "each")
        for node_id, node in nodes_of(graph).items()
        if node.get("kind") == "for_each"
    }


def dominators(graph: dict, order: list[str]) -> dict[str, set[str]]:
    """node id → the nodes every path from the trigger to it passes through (itself left out)."""
    incoming = edges_to(graph)
    everything = set(order)
    dom: dict[str, set[str]] = {}
    for node_id in order:  # a topological order: one pass is enough
        sources = [source for source, _port in incoming[node_id] if source in dom]
        if not sources:
            dom[node_id] = {node_id}
            continue
        shared = set(everything)
        for source in sources:
            shared &= dom[source]
        dom[node_id] = shared | {node_id}
    return {node_id: found - {node_id} for node_id, found in dom.items()}


# --------------------------------------------------------------------------- #
# Validation                                                                  #
# --------------------------------------------------------------------------- #
def _check_arguments(node: dict, declared: list[dict], problems: list[Problem]) -> None:
    args = (node.get("config") or {}).get("args") or {}
    if not isinstance(args, dict):
        problems.append(Problem("The arguments are not an object", node["id"], "args"))
        return
    known = {arg["name"] for arg in declared}
    for arg in declared:
        value = args.get(arg["name"])
        if arg.get("required") and (value is None or value == "") and arg.get("default") in (None, ""):
            problems.append(Problem(f'"{arg["name"]}" is required', node["id"], f"args.{arg['name']}"))
        if arg.get("type") == "choice" and isinstance(value, str) and "{{" not in value and value != "":
            if value not in (arg.get("choices") or []):
                problems.append(
                    Problem(
                        f'"{arg["name"]}" is one of: {", ".join(arg.get("choices") or [])}',
                        node["id"],
                        f"args.{arg['name']}",
                    )
                )
    for name in args:
        if name not in known:
            problems.append(Problem(f'There is no argument "{name}" here', node["id"], f"args.{name}"))


def _check_on_error(node: dict, problems: list[Problem]) -> None:
    on_error = (node.get("config") or {}).get("on_error")
    if on_error is None:
        return
    if not isinstance(on_error, dict) or on_error.get("mode", "stop") not in ("stop", "retry"):
        problems.append(Problem('"If it fails" is stop at once or try again', node["id"], "on_error"))
        return
    if on_error.get("mode") == "retry":
        times = on_error.get("times")
        if not isinstance(times, int) or isinstance(times, bool) or not 1 <= times <= RETRY_MAX:
            problems.append(Problem(f"Try again 1 to {RETRY_MAX} times", node["id"], "on_error.times"))


def _check_wait(value: Any, node_id: str, field: str, problems: list[Problem], *, optional: bool) -> None:
    if value is None and optional:
        return
    if not isinstance(value, int) or isinstance(value, bool) or not WAIT_MIN <= value <= WAIT_MAX:
        problems.append(Problem("A wait is between 1 minute and 30 days", node_id, field))


def _check_conditions(config: dict, node_id: str, field: str, problems: list[Problem]) -> None:
    groups = [key for key in ("all", "any") if key in config]
    if len(groups) != 1 or not isinstance(config[groups[0]], list) or not config[groups[0]]:
        problems.append(Problem('A condition is "all" or "any" of at least one comparison', node_id, field))
        return
    for index, item in enumerate(config[groups[0]]):
        where = f"{field}.{groups[0]}.{index}"
        if not isinstance(item, dict) or item.get("op") not in OPERATORS:
            problems.append(Problem("A comparison needs one of the operators: " + ", ".join(OPERATORS), node_id, where))
            continue
        if "left" not in item:
            problems.append(Problem("A comparison needs what to compare", node_id, where))
        if item["op"] == "matches":
            pattern = item.get("right")
            if not isinstance(pattern, str) or not pattern or len(pattern) > 500:
                problems.append(Problem("A pattern of 1 to 500 characters is needed", node_id, where))


def _check_node(node: dict, library: Library, problems: list[Problem]) -> None:
    node_id, kind = node["id"], node["kind"]
    config = node.get("config") or {}
    if not isinstance(config, dict):
        problems.append(Problem("The settings of the node are not an object", node_id, "config"))
        return
    if kind == "trigger":
        ways = [key for key in ("event", "cron", "manual") if config.get(key)]
        if not ways:
            problems.append(Problem("A trigger needs an event, a schedule or to be run by hand", node_id, "event"))
        if config.get("event") and config["event"] not in EVENTS:
            problems.append(Problem("Unknown event: " + ", ".join(EVENTS), node_id, "event"))
        if config.get("cron"):
            from .schedules import cron_problem

            wrong = cron_problem(config["cron"], config.get("timezone") or "UTC")
            if wrong:
                problems.append(Problem(wrong, node_id, "cron"))
        if config.get("conditions"):
            _check_conditions(config["conditions"], node_id, "conditions", problems)
    elif kind == "condition":
        _check_conditions(config, node_id, "config", problems)
    elif kind == "for_each":
        if not isinstance(config.get("items"), str) or not config["items"].strip():
            problems.append(Problem("What to go through is needed: an expression that gives a list", node_id, "items"))
        ceiling = config.get("max", EACH_MAX)
        if not isinstance(ceiling, int) or isinstance(ceiling, bool) or not 1 <= ceiling <= EACH_MAX:
            problems.append(Problem(f"At most 1 to {EACH_MAX} items", node_id, "max"))
    elif kind == "wait":
        if config.get("until"):
            _check_conditions(config["until"], node_id, "until", problems)
            _check_wait(config.get("timeout", 86400), node_id, "timeout", problems, optional=False)
        else:
            _check_wait(config.get("seconds"), node_id, "seconds", problems, optional=False)
    elif kind == "approval":
        if not str(config.get("question") or "").strip():
            problems.append(Problem("The question to ask is needed", node_id, "question"))
        _check_wait(config.get("wait_seconds"), node_id, "wait_seconds", problems, optional=True)
        if config.get("on_expire", "skip") not in ("skip", "stop", "refuse"):
            problems.append(Problem("When the wait ends: skip, stop or refuse", node_id, "on_expire"))
    elif kind == "action":
        entry = library.action(str(config.get("action") or ""))
        if entry is None:
            problems.append(Problem("This action does not exist", node_id, "action"))
        else:
            _check_arguments(node, entry["arguments"], problems)
            if entry.get("needsConnection"):
                # A command of a connector is sent through a connection: the one named, or the only one.
                known = getattr(library, "connections", lambda _connector: [])(entry.get("connector"))
                wanted = str(config.get("connection") or "")
                if wanted and not any(wanted in pair for pair in known):
                    problems.append(Problem("This connection does not exist", node_id, "connection"))
                elif not wanted and len(known) != 1:
                    problems.append(Problem("Choose the connection to send through", node_id, "connection"))
        _check_on_error(node, problems)
        approval = config.get("approval")
        if approval is not None:
            if not isinstance(approval, dict):
                problems.append(Problem("The approval settings are not an object", node_id, "approval"))
            else:
                _check_wait(approval.get("wait_seconds"), node_id, "approval.wait_seconds", problems, optional=True)
    elif kind == "script":
        entry = library.script(str(config.get("script") or ""), config.get("script_version"))
        if entry is None:
            problems.append(Problem("This script, or this version of it, does not exist", node_id, "script"))
        else:
            _check_arguments(node, entry["arguments"], problems)
        _check_on_error(node, problems)
    elif kind == "playbook":
        if not str(config.get("playbook") or "").strip():
            problems.append(Problem("The playbook to run is needed", node_id, "playbook"))
        elif library.playbook_graph(str(config["playbook"])) is None:
            problems.append(Problem("This playbook does not exist, or has no saved version", node_id, "playbook"))
        _check_on_error(node, problems)
    elif kind == "end":
        if config.get("status", "done") not in ("done", "failed"):
            problems.append(Problem("An end is done or failed", node_id, "status"))


def _calls(graph: dict) -> list[str]:
    return [
        str((node.get("config") or {}).get("playbook") or "")
        for node in nodes_of(graph).values()
        if node.get("kind") == "playbook"
    ]


def _call_cycle(name: str | None, graph: dict, library: Library) -> bool:
    """True when the playbook ends up running itself, or calls deeper than allowed."""

    def visit(current: dict, trail: tuple[str, ...]) -> bool:
        for called in _calls(current):
            if not called:
                continue
            if called in trail or len(trail) >= CALL_DEPTH:
                return True
            inner = library.playbook_graph(called)
            if inner is not None and visit(inner, (*trail, called)):
                return True
        return False

    return visit(graph, (name,) if name else ())


def validate(graph: Any, library: Library, name: str | None = None) -> list[Problem]:
    """Everything that keeps the graph from being saved as a version ([] when it is valid)."""
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list):
        return [Problem("A playbook is a list of nodes and a list of edges")]
    raw_nodes = graph["nodes"]
    raw_edges = graph.get("edges") or []
    if not isinstance(raw_edges, list):
        return [Problem("The edges are not a list")]
    if len(raw_nodes) > MAX_NODES:
        return [Problem(f"A playbook has at most {MAX_NODES} nodes")]
    if len(raw_edges) > MAX_EDGES:
        return [Problem(f"A playbook has at most {MAX_EDGES} edges")]

    problems: list[Problem] = []
    seen: set[str] = set()
    for node in raw_nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not ID_RE.match(node["id"]):
            return [Problem("A node needs an id: a lower-case letter, then letters, digits or _ (32 at most)")]
        if node["id"] in seen:
            return [Problem("Two nodes have the same id", node["id"])]
        seen.add(node["id"])
        if node.get("kind") not in KINDS:
            return [Problem("Unknown kind of node", node["id"], "kind")]
        if node["id"] in ALWAYS + IN_LOOP + ("context", "incident", "args", "config", "response", "steps", "secret"):
            problems.append(
                Problem(f'"{node["id"]}" is a name of the expressions: give the node another id', node["id"])
            )
        if len(str(node.get("name") or "")) > 80:
            problems.append(Problem("A node's name has at most 80 characters", node["id"], "name"))

    nodes = nodes_of(graph)
    triggers = [node_id for node_id, node in nodes.items() if node["kind"] == "trigger"]
    if len(triggers) != 1:
        return [*problems, Problem("A playbook has exactly one trigger")]
    trigger = triggers[0]

    pairs: set[tuple[str, str, str]] = set()
    for edge in raw_edges:
        if not isinstance(edge, dict) or edge.get("from") not in nodes or edge.get("to") not in nodes:
            return [*problems, Problem("An edge joins two nodes of the playbook")]
        source = nodes[edge["from"]]
        port = edge.get("port") or DEFAULT_PORT[source["kind"]]
        if port not in PORTS[source["kind"]]:
            return [*problems, Problem(f'A {source["kind"].replace("_", " ")} node has no "{port}" port', source["id"])]
        if edge["to"] == trigger:
            problems.append(Problem("Nothing leads to the trigger", trigger))
        if (edge["from"], port, edge["to"]) in pairs:
            problems.append(Problem("The same edge is drawn twice", source["id"]))
        pairs.add((edge["from"], port, edge["to"]))

    order = topological(graph)
    if order is None:
        return [*problems, Problem('The playbook goes round in a circle: use a "for each" to repeat')]

    after_trigger = reachable(graph, trigger) | {trigger}
    for node_id in nodes:
        if node_id not in after_trigger:
            problems.append(Problem("Nothing leads to this node", node_id))

    # "For each": a body belongs to one loop, is not entered from outside, and holds no other loop.
    bodies = loop_bodies(graph)
    incoming = edges_to(graph)
    for loop, body in bodies.items():
        if not body:
            problems.append(Problem('A "for each" needs something to do for each item', loop, "each"))
        outside = reachable(graph, loop, "done") | reachable(graph, loop, "error")
        for node_id in sorted(body):
            if node_id in outside:
                problems.append(Problem('A step of a "for each" body cannot also come after the loop', node_id))
            if nodes[node_id]["kind"] == "for_each":
                problems.append(Problem('A "for each" inside another is not supported: run another playbook', node_id))
            if nodes[node_id]["kind"] == "approval":
                problems.append(
                    Problem('An approval inside a "for each" would ask once per item: ask before the loop', node_id)
                )
            for source, _port in incoming[node_id]:
                if source != loop and source not in body:
                    problems.append(Problem('A "for each" body is entered only through its loop', node_id))

    for node in nodes.values():
        try:
            _check_node(node, library, problems)
        except expressions.ExpressionError as error:
            problems.append(Problem(error.message, node["id"]))

    # Expressions read what is certain to have run before.
    in_body = {node_id: loop for loop, body in bodies.items() for node_id in body}
    dom = dominators(graph, order)
    for node_id, node in nodes.items():
        allowed = set(ALWAYS) | dom.get(node_id, set())
        if node_id in in_body:
            allowed |= set(IN_LOOP)
        # A wait that asks an action again and again reads its last answer as "poll".
        if node["kind"] == "wait" and (node.get("config") or {}).get("poll"):
            allowed.add("poll")
        # A result inside a loop is one per item: outside it, read the loop's results.
        allowed -= {other for other, loop in in_body.items() if loop != in_body.get(node_id)}
        try:
            found = expressions.references(node.get("config") or {})
        except expressions.ExpressionError as error:
            problems.append(Problem(error.message, node_id))
            continue
        for name, _position in found:
            if name in allowed or name == trigger:
                continue
            if name in nodes:
                reason = "is not certain to have run before this node"
                if name in in_body and in_body[name] != in_body.get(node_id):
                    reason = f'runs once per item: read the results of "{in_body[name]}" instead'
                problems.append(Problem(f'"{name}" {reason}', node_id))
            elif name in IN_LOOP:
                problems.append(Problem(f'"{name}" can be read only inside a "for each"', node_id))
            else:
                problems.append(Problem(f'"{name}" is not a node of this playbook', node_id))

    for index, item in enumerate(graph.get("inputs") or []):
        if not isinstance(item, dict) or not INPUT_RE.match(str(item.get("name") or "")):
            problems.append(Problem("An input needs a name: lower-case letters, digits, _", None, f"inputs.{index}"))
        elif item.get("type", "text") not in ARGUMENT_TYPES:
            problems.append(Problem("Unknown type of input", None, f"inputs.{index}"))

    if _call_cycle(name, graph, library):
        problems.append(Problem(f"Playbooks call each other in a circle, or more than {CALL_DEPTH} deep"))
    return problems
