"""Playbooks as data: the expression language, and what makes a graph valid."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.automation import expressions as ex
from app.automation import graph as g
from app.automation.schedules import cron_problem, next_after

DATA = json.loads((Path(__file__).parent / "data" / "expressions.json").read_text(encoding="utf-8"))
SCOPE = ex.Scope(values=DATA["scope"])


# --------------------------------------------------------------------------- #
# Expressions                                                                 #
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vector", DATA["vectors"], ids=lambda v: v["template"][:50] or "(empty)")
def test_expressions_give_what_the_shared_vectors_say(vector):
    """The same file is read by the frontend's parser (domain/automation/expressions.test.js)."""
    if "error" in vector:
        with pytest.raises(ex.ExpressionError) as caught:
            ex.render_text(vector["template"], SCOPE)
        assert caught.value.position == vector["error"]["position"]
        assert caught.value.message == vector["message"]
    else:
        assert ex.render_text(vector["template"], SCOPE).data == vector["result"]


def test_an_expression_is_a_path_and_filters_and_nothing_else():
    assert len(DATA["vectors"]) > 70 and sum("error" in v for v in DATA["vectors"]) >= 18
    # One expression alone keeps its type; mixed with text it is text.
    assert ex.render_text("{{ trigger.mail.score }}", SCOPE).data == 82
    assert ex.render_text(" {{ trigger.mail.score }}", SCOPE).data == " 82"
    # A structure is rendered through, leaving what is not text as it is.
    config = {
        "to": ["{{ trigger.mail.sender }}", 7],
        "n": "{{ search.count }}",
        "keep": None,
        "deep": {"x": "a{{ index }}"},
    }
    assert ex.render(config, SCOPE).data == {
        "to": ["Eve <eve@evil.example>", 7],
        "n": 3,
        "keep": None,
        "deep": {"x": "a2"},
    }
    assert sorted(ex.references(config)) == [("index", 1), ("search", 0), ("trigger", 0)]
    assert ex.references("no braces") == [] and ex.references(12) == []
    # Limits.
    with pytest.raises(ex.ExpressionError):
        ex.parse("x" * (ex.MAX_TEMPLATE + 1))
    with pytest.raises(ex.ExpressionError):
        ex.parse("{{ a }}" * (ex.MAX_EXPRESSIONS + 1))
    deep: dict = {}
    for _ in range(ex.MAX_DEPTH + 3):
        deep = {"d": deep}
    with pytest.raises(ex.ExpressionError):
        ex.render(deep, SCOPE)
    # Nothing in the module evaluates text as code.
    source = Path(ex.__file__).read_text(encoding="utf-8")
    assert "eval(" not in source and "exec(" not in source and "__import__" not in source


def test_classes_of_data_travel_with_values():
    scope = ex.Scope(
        values={
            "trigger": {
                "mail": {
                    "subject": "Hi",
                    "sender": "eve@evil.example",
                    "sha256": "ab",
                    "attachments": [{"name": "a.pdf", "sha256": "cd"}],
                }
            },
            "lookup": {"verdict": "malicious"},
        },
        classes={
            "trigger": {
                "mail.subject": ["subject"],
                "mail.sender": ["email_address"],
                "mail.sha256": ["hash"],
                "mail.attachments.name": ["attachment_name"],
                "mail.attachments.sha256": ["hash"],
            },
            "lookup": {"": ["verdict"]},
        },
    )

    def classes(template):
        return sorted(ex.render(template, scope).classes)

    assert classes("{{ trigger.mail.sender }}") == ["email_address"]
    assert classes("{{ trigger.mail.sha256 }}") == ["hash"]
    assert classes("plain") == []
    # A list has the classes of its items, whichever index is read.
    assert classes("{{ trigger.mail.attachments[0].name }}") == ["attachment_name"]
    assert classes("{{ trigger.mail.attachments[*].sha256 }}") == ["hash"]
    # Reading a whole object carries everything under it.
    assert classes("{{ trigger.mail.attachments }}") == ["attachment_name", "hash"]
    assert classes("{{ trigger.mail }}") == ["attachment_name", "email_address", "hash", "subject"]
    # A class on the whole of a name covers every field of it.
    assert classes("{{ lookup.verdict }}") == ["verdict"]
    # A filter cannot launder: the result has the classes of what went in.
    assert classes("{{ trigger.mail.sender | upper | replace('@', ' at ') }}") == ["email_address"]
    assert classes("{{ trigger.mail.sender | length }}") == ["email_address"]
    # A rendered text, and a structure, carry the classes of everything put into them.
    assert classes("From {{ trigger.mail.sender }}: {{ trigger.mail.subject }}") == ["email_address", "subject"]
    assert classes({"a": "{{ trigger.mail.sha256 }}", "b": ["{{ trigger.mail.subject }}"]}) == ["hash", "subject"]
    assert ex.render_classes(
        {"to": "{{ trigger.mail.sender }}", "n": 1, "x": {"h": "{{ trigger.mail.sha256 }}"}}, scope
    ) == {
        "to": ["email_address"],
        "x.h": ["hash"],
    }


def test_the_operators_of_a_condition():
    c = ex.compare
    assert c("Phishing", "eq", "phishing") and c(5, "eq", 5) and c("5", "eq", 5) and not c([1], "eq", "[1]")
    assert c("a", "ne", "b") and not c("a", "ne", "A")
    assert c(70, "gte", 70) and c("82", "gt", 70) and c(1, "lt", 2) and c(2, "lte", 2) and not c(1, "gt", 2)
    assert c("b", "gt", "a")  # text when they are not numbers
    assert c("Invoice 2026", "contains", "invoice") and c(["a", "B"], "contains", "b") and not c(["a"], "contains", "c")
    assert c("rome", "in", ["Rome", "Milan"]) and not c("x", "in", ["a"]) and c("a", "in", "a")
    assert c("", "exists", None) and not c(None, "exists", None) and not c(ex.MISSING, "exists", None)
    for empty in (None, "", [], {}, ex.MISSING):
        assert c(empty, "empty", None)
    assert not c(0, "empty", None) and not c("x", "empty", None)
    assert c(ex.MISSING, "eq", None)
    with pytest.raises(ValueError):
        c(1, "nope", 2)
    assert ex.lookup({"a": [{"b": 1}]}, "a.0.b") == 1 and ex.lookup({"a": 1}, "a.b") is ex.MISSING


# --------------------------------------------------------------------------- #
# Graphs                                                                      #
# --------------------------------------------------------------------------- #
class Lib:
    """A library with one action, one script and two playbooks."""

    def __init__(self, playbooks=None):
        self.playbooks = playbooks or {}

    def action(self, action_id):
        if action_id != "nik.add-note":
            return None
        return {
            "arguments": [
                {"name": "text", "type": "text", "required": True},
                {"name": "kind", "type": "choice", "choices": ["note", "evidence"], "default": "note"},
            ]
        }

    def script(self, name, version):
        return (
            {"arguments": [{"name": "items", "type": "list", "required": True}]}
            if (name, version) == ("Group", 2)
            else None
        )

    def playbook_graph(self, name):
        return self.playbooks.get(name)


def node(node_id, kind, **config):
    return {"id": node_id, "kind": kind, "name": node_id, "config": config}


def edge(source, target, port=None):
    return {"from": source, "to": target, **({"port": port} if port else {})}


TRIGGER = node("start", "trigger", event="incident.created", manual=True)
NOTE = {"action": "nik.add-note", "args": {"text": "hello"}}


def make(nodes, edges, **extra):
    return {"nodes": [TRIGGER, *nodes], "edges": edges, **extra}


def problems(graph, lib=None, name=None):
    return [p.message for p in g.validate(graph, lib or Lib(), name)]


def test_a_valid_graph_has_no_problem():
    graph = make(
        [
            node("check", "condition", all=[{"left": "{{ trigger.incident.severity }}", "op": "eq", "right": "high"}]),
            node("ask", "approval", question="Add a note?", wait_seconds=None, on_expire="skip"),
            node(
                "note",
                "action",
                action="nik.add-note",
                args={"text": "by {{ ask.by }} on {{ run.id }}"},
                on_error={"mode": "retry", "times": 3},
            ),
            node("loop", "for_each", items="{{ trigger.incident.hosts }}", max=50),
            node("each", "script", script="Group", script_version=2, args={"items": "{{ item }}"}),
            node("pause", "wait", seconds=60),
            node("stop", "end", status="done"),
            node("failed", "end", status="failed", message="no"),
        ],
        [
            edge("start", "check"),
            edge("check", "ask", "yes"),
            edge("check", "stop", "no"),
            edge("ask", "note", "approved"),
            edge("ask", "stop", "refused"),
            edge("note", "loop"),
            edge("note", "failed", "error"),
            edge("loop", "each", "each"),
            edge("loop", "pause", "done"),
            edge("pause", "stop"),
        ],
        inputs=[{"name": "reason", "type": "text"}],
    )
    assert problems(graph) == []
    assert g.topological(graph)[0] == "start"
    assert g.loop_bodies(graph) == {"loop": {"each"}}
    assert g.reachable(graph, "check", "no") == {"stop"}
    dom = g.dominators(graph, g.topological(graph))
    assert dom["note"] == {"start", "check", "ask"} and dom["stop"] == {"start", "check"}
    assert g.edges_to(graph)["stop"] == [("check", "no"), ("ask", "refused"), ("pause", "out")]


def test_the_shape_of_a_graph_is_checked_first():
    assert problems([]) == ["A playbook is a list of nodes and a list of edges"]
    assert problems({"nodes": [], "edges": []}) == ["A playbook has exactly one trigger"]
    assert problems(make([node("t2", "trigger", manual=True)], [])) == ["A playbook has exactly one trigger"]
    assert problems(make([node("Bad Id", "end")], []))[0].startswith("A node needs an id")
    assert problems(make([node("a", "end"), node("a", "end")], [])) == ["Two nodes have the same id"]
    assert problems(make([node("a", "teleport")], [])) == ["Unknown kind of node"]
    assert problems(make([node("a", "end")], [edge("start", "nowhere")])) == ["An edge joins two nodes of the playbook"]
    assert problems(make([node("a", "end")], [edge("start", "a", "yes")])) == ['A trigger node has no "yes" port']
    assert problems({"nodes": [TRIGGER] * 201, "edges": []}) == ["A playbook has at most 200 nodes"]
    loop = make(
        [node("a", "action", **NOTE), node("b", "action", **NOTE)], [edge("start", "a"), edge("a", "b"), edge("b", "a")]
    )
    assert problems(loop) == ['The playbook goes round in a circle: use a "for each" to repeat']
    assert "Nothing leads to this node" in problems(make([node("a", "end")], []))
    back = make([node("a", "action", **NOTE)], [edge("start", "a"), edge("a", "start")])
    assert problems(back)[0] == "Nothing leads to the trigger"
    twice = make([node("a", "end")], [edge("start", "a"), edge("start", "a")])
    assert problems(twice) == ["The same edge is drawn twice"]
    assert problems(make([node("item", "end")], [edge("start", "item")])) == [
        '"item" is a name of the expressions: give the node another id'
    ]


def test_each_kind_of_node_is_checked():
    def one(kind, **config):
        return problems(make([node("n", kind, **config)], [edge("start", "n")]))

    assert one("action", action="nope") == ["This action does not exist"]
    assert one("action", action="nik.add-note") == ['"text" is required']
    assert one("action", action="nik.add-note", args={"text": "x", "extra": 1}) == ['There is no argument "extra" here']
    assert one("action", action="nik.add-note", args={"text": "x", "kind": "poem"}) == [
        '"kind" is one of: note, evidence'
    ]
    assert one("action", action="nik.add-note", args={"text": "x", "kind": "{{ trigger.kind }}"}) == []
    assert one("action", **NOTE, on_error={"mode": "retry", "times": 101}) == ["Try again 1 to 100 times"]
    assert one("action", **NOTE, on_error={"mode": "retry", "times": True}) == ["Try again 1 to 100 times"]
    assert one("action", **NOTE, on_error={"mode": "explode"}) == ['"If it fails" is stop at once or try again']
    assert one("action", **NOTE, approval={"ask": True, "wait_seconds": 5}) == [
        "A wait is between 1 minute and 30 days"
    ]
    assert one("script", script="Group", script_version=1) == ["This script, or this version of it, does not exist"]
    assert one("script", script="Group", script_version=2) == ['"items" is required']
    assert one("condition") == ['A condition is "all" or "any" of at least one comparison']
    assert one("condition", all=[{"left": "a", "op": "like", "right": "b"}])[0].startswith("A comparison needs one of")
    assert one("condition", any=[{"left": "a", "op": "matches", "right": "x" * 501}]) == [
        "A pattern of 1 to 500 characters is needed"
    ]
    assert one("wait", seconds=59) == ["A wait is between 1 minute and 30 days"]
    assert one("wait", seconds=2_592_001) == ["A wait is between 1 minute and 30 days"]
    assert one("wait", until={"all": [{"left": "{{ trigger.x }}", "op": "exists"}]}) == []
    assert one("approval") == ["The question to ask is needed"]
    assert one("approval", question="ok?", on_expire="explode") == ["When the wait ends: skip, stop or refuse"]
    assert one("end", status="maybe") == ["An end is done or failed"]
    assert one("playbook", playbook="Other") == ["This playbook does not exist, or has no saved version"]
    assert one("playbook") == ["The playbook to run is needed"]

    def trigger(**config):
        return problems({"nodes": [node("start", "trigger", **config)], "edges": []})

    assert trigger() == ["A trigger needs an event, a schedule or to be run by hand"]
    assert trigger(event="mail.analysed")[0].startswith("Unknown event")
    assert trigger(cron="30 6 * * 1", timezone="Europe/Rome") == []
    assert trigger(cron="* * * * *") == ["A schedule fires every five minutes at most"]
    assert trigger(cron="nope") == ["A schedule is five fields: minute, hour, day of the month, month, day of the week"]
    assert trigger(cron="0 6 * * *", timezone="Mars/Olympus") == [
        "Unknown time zone: use a name such as Europe/Rome or UTC"
    ]
    assert trigger(event="incident.updated", conditions={"all": []}) == [
        'A condition is "all" or "any" of at least one comparison'
    ]


def test_an_expression_reads_only_what_is_certain_to_have_run():
    cond = node("check", "condition", all=[{"left": "{{ trigger.x }}", "op": "exists"}])
    a = node("a", "action", **NOTE)
    b = node("b", "action", **NOTE)

    def after(text, edges):
        last = node("last", "action", action="nik.add-note", args={"text": text})
        return problems(make([cond, a, b, last], edges))

    branches = [
        edge("start", "check"),
        edge("check", "a", "yes"),
        edge("check", "b", "no"),
        edge("a", "last"),
        edge("b", "last"),
    ]
    # a runs on one branch only: the node where the branches meet cannot count on it.
    assert after("{{ a.id }}", branches) == ['"a" is not certain to have run before this node']
    assert after("{{ check.result }} {{ trigger.x }} {{ run.id }} {{ inputs.reason | default('') }}", branches) == []
    chain = [edge("start", "check"), edge("check", "a", "yes"), edge("a", "b"), edge("b", "last")]
    assert after("{{ a.id }} {{ b.id }}", chain) == []
    assert after("{{ ghost.x }}", chain) == ['"ghost" is not a node of this playbook']
    assert after("{{ item }}", chain) == ['"item" can be read only inside a "for each"']
    assert after("{{ last.x }}", chain) == ['"last" is not certain to have run before this node']
    assert after("{{ a.x ", chain) == ["The expression is not closed: add }}"]


def test_a_for_each_body_belongs_to_its_loop():
    loop = node("loop", "for_each", items="{{ trigger.list }}")
    inner = node("inner", "action", action="nik.add-note", args={"text": "{{ item.name }} {{ index }}"})
    after = node("after", "action", action="nik.add-note", args={"text": "{{ loop.count }}"})
    good = make(
        [loop, inner, after], [edge("start", "loop"), edge("loop", "inner", "each"), edge("loop", "after", "done")]
    )
    assert problems(good) == []

    assert problems(make([loop, after], [edge("start", "loop"), edge("loop", "after", "done")])) == [
        'A "for each" needs something to do for each item'
    ]
    reads = node("after", "action", action="nik.add-note", args={"text": "{{ inner.id }}"})
    assert problems(make([loop, inner, reads], good["edges"])) == [
        '"inner" runs once per item: read the results of "loop" instead'
    ]
    both = [*good["edges"], edge("inner", "after")]
    assert 'A step of a "for each" body cannot also come after the loop' in problems(make([loop, inner, after], both))
    nested = node("inner", "for_each", items="{{ item.list }}")
    deepest = node("deepest", "action", **NOTE)
    assert 'A "for each" inside another is not supported: run another playbook' in problems(
        make(
            [loop, nested, deepest],
            [edge("start", "loop"), edge("loop", "inner", "each"), edge("inner", "deepest", "each")],
        )
    )
    asks = node("inner", "approval", question="ok?")
    assert problems(make([loop, asks], [edge("start", "loop"), edge("loop", "inner", "each")])) == [
        'An approval inside a "for each" would ask once per item: ask before the loop'
    ]
    side = node("side", "action", **NOTE)
    entered = [edge("start", "loop"), edge("start", "side"), edge("loop", "inner", "each"), edge("side", "inner")]
    assert 'A "for each" body is entered only through its loop' in problems(make([loop, inner, side], entered))


def test_playbooks_do_not_call_each_other_in_a_circle():
    def calls(other):
        return make([node("call", "playbook", playbook=other)], [edge("start", "call")])

    lib = Lib({"A": calls("B"), "B": calls("A"), "Leaf": make([], [])})
    assert problems(calls("Leaf"), lib, "Me") == []
    assert problems(calls("Me"), Lib({"Me": make([], [])}), "Me") == [
        "Playbooks call each other in a circle, or more than 5 deep"
    ]
    assert problems(calls("A"), lib, "Me") == ["Playbooks call each other in a circle, or more than 5 deep"]
    chain = {f"P{i}": calls(f"P{i + 1}") for i in range(6)} | {"P6": make([], [])}
    assert problems(calls("P0"), Lib(chain), "Me") == ["Playbooks call each other in a circle, or more than 5 deep"]
    assert problems(calls("P3"), Lib(chain), "Me") == []


def test_schedules():
    assert cron_problem("30 6 * * 1", "Europe/Rome") is None
    assert cron_problem("*/5 * * * *", "UTC") is None
    assert cron_problem("*/4 * * * *", "UTC") == "A schedule fires every five minutes at most"
    assert cron_problem("", "UTC") and cron_problem(None, "UTC") and cron_problem("0 6 * * * *", "UTC")
    # Monday 06:30 in Rome is 05:30 UTC in winter: 2026-11-16 was a Monday.
    monday = 1794807000.0  # 2026-11-16T05:30:00Z
    assert next_after("30 6 * * 1", "Europe/Rome", monday - 60) == monday
    assert next_after("30 6 * * 1", "Europe/Rome", monday) == monday + 7 * 86400
    assert next_after("30 6 * * 1", "UTC", monday) == monday + 3600
