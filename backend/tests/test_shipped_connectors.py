"""The connectors Nik ships, each command against an exchange recorded from the vendor's documentation.

No test instance exists for these products: a fixture
(``tests/data/connectors/<id>/<command>.json``) says, for the arguments it
gives, which requests the command must send (method, path, body) and what it
must give back for the answers the documentation shows. Every command of
every shipped connector has one, and none of them is "verified" until the
maintainer runs "Test the connection" against a real system.

    {"args": {...},
     "exchanges": [{"request": {"method", "path", "query"?, "json"?, "form"?, "headers"?, "body_has"?,
                                "host"? (another host the connector lists), "without_headers"?},
                    "response": {"status", "json"? | "text"?, "headers"?}}],
     "outputs": {...}}

``connection.json`` beside them holds the configuration and the (invented)
credentials the fixtures are run with.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import pytest

from app.automation import connector_actions as ca
from app.automation import connector_runtime as rt
from app.automation import egress
from tests import vendor

DATA = Path(__file__).parent / "data" / "connectors"
# The connectors that speak HTTP: each command has a recorded exchange. The native ones (mail) are
# run by Nik's own code and have tests of their own (test_mail_connector.py).
SHIPPED = [(text, connector) for text, connector in vendor.connectors() if connector.native is None]
CASES = [(connector, command.name) for _text, connector in SHIPPED for command in connector.commands]


def _connection(connector_id: str) -> dict:
    return json.loads((DATA / connector_id / "connection.json").read_text(encoding="utf-8"))


class Recorded:
    """The egress client of a fixture: checks each request against what is recorded, answers what is recorded."""

    def __init__(self, exchanges: list[dict], host: str):
        self.exchanges = list(exchanges)
        self.host = host
        self.count = 0

    def __call__(self, policy, method, url, **sent):
        assert self.exchanges, f"request {self.count + 1} was not expected: {method} {url}"
        exchange = self.exchanges.pop(0)
        self.count += 1
        wanted, answer = exchange["request"], exchange["response"]
        where = f"request {self.count} ({wanted['method']} {wanted['path']})"
        parts = urlsplit(url)
        # A request to another host the connector lists says so: "host" in the fixture.
        assert parts.hostname == wanted.get("host", self.host), f"{where}: sent to {parts.hostname}"
        assert (method, parts.path) == (wanted["method"], wanted["path"]), where
        query = {
            **dict(parse_qsl(parts.query)),
            **{key: str(value) for key, value in (sent.get("query") or {}).items()},
        }
        assert query == {key: str(value) for key, value in wanted.get("query", {}).items()}, f"{where}: query"
        for kind in ("json", "form"):
            if kind in wanted:
                assert sent.get(kind) == wanted[kind], f"{where}: {kind}"
            else:
                assert sent.get(kind) is None, f"{where}: an unexpected {kind} body"
        headers = sent.get("headers") or {}
        for key, value in wanted.get("headers", {}).items():
            assert headers.get(key) == value, f"{where}: header {key}"
        for key in wanted.get("without_headers", []):
            assert key not in headers, f"{where}: the header {key} must not be sent there"
        body = sent.get("body")
        text = body.decode() if isinstance(body, bytes) else (body or "")
        for piece in wanted.get("body_has", []):
            assert piece in text, f"{where}: the body lacks {piece!r}"
        content = answer["text"] if "text" in answer else json.dumps(answer.get("json", {}))
        head = {"content-type": "text/plain" if "text" in answer else "application/json", **answer.get("headers", {})}
        record = {"method": method, "host": parts.hostname, "path": parts.path, "status": answer["status"]}
        return egress.Response(status=answer["status"], headers=head, body=content.encode(), record=record)


def test_the_shipped_connectors_load_and_say_what_they_were_written_against():
    assert len(SHIPPED) >= 5
    ids = [connector.id for _text, connector in SHIPPED]
    assert len(set(ids)) == len(ids)
    for _text, connector in SHIPPED:
        assert connector.api_version, f"{connector.id}: says no API version"
        assert connector.verified is False, f"{connector.id}: nobody ran it against a real system"
        assert connector.test is not None or connector.auth.type in ("session", "zscaler"), connector.id
        assert (DATA / connector.id / "connection.json").exists(), f"{connector.id}: no connection for its fixtures"
        for command in connector.commands:
            assert command.description, f"{connector.id}.{command.name}: no description"
            assert (DATA / connector.id / f"{command.name}.json").exists(), f"{connector.id}.{command.name}: no fixture"
            if command.changes_outside:
                assert command.sample is not None, f"{connector.id}.{command.name}: no sample for dry runs"


@pytest.mark.parametrize(("connector", "name"), CASES, ids=[f"{connector.id}.{name}" for connector, name in CASES])
def test_a_command_sends_what_the_documentation_says_and_reads_the_answer(connector, name):
    fixture = json.loads((DATA / connector.id / f"{name}.json").read_text(encoding="utf-8"))
    connection = _connection(connector.id)
    config = {**connection["config"], **fixture.get("config", {})}
    host = ca.host_of(connector, config).split(":")[0]
    wire = Recorded(fixture["exchanges"], host)
    now = [1_800_000_000.0]
    policy = egress.Policy(mode="listed", hosts=frozenset({host}))
    rt.forget_tokens()

    def runtime() -> rt.Runtime:
        return rt.Runtime(connector, config, connection["secrets"], policy, send=wire, clock=lambda: now[0])

    answer = runtime().run(name, fixture["args"])
    waits = 0
    while not answer.done:
        # A command that waits: the engine would call again at that time, with the state it was given.
        waits += 1
        assert waits < 20 and answer.again_at > now[0]
        now[0] = answer.again_at
        answer = runtime().run(name, fixture["args"], answer.state)
    assert wire.exchanges == [], "the command sent fewer requests than the documentation says"
    assert answer.outputs == fixture["outputs"]
    # No secret of the connection is in what the step would record.
    recorded = json.dumps([answer.outputs, answer.records])
    for value in connection["secrets"].values():
        assert value not in recorded


@pytest.mark.parametrize(("connector", "name"), CASES, ids=[f"{connector.id}.{name}" for connector, name in CASES])
def test_a_dry_run_of_a_command_names_its_first_request(connector, name):
    fixture = json.loads((DATA / connector.id / f"{name}.json").read_text(encoding="utf-8"))
    connection = _connection(connector.id)
    config = {**connection["config"], **fixture.get("config", {})}
    host = ca.host_of(connector, config)

    def nothing(*_args, **_kwargs):
        raise AssertionError("a dry run sent a request")

    policy = egress.Policy(mode="listed", hosts=frozenset({host}))
    # The address is a name the test cannot resolve: the destination is checked by the egress client in the real thing.
    would = rt.Runtime(connector, config, connection["secrets"], policy, send=nothing)
    spec = connector.command(name).request or connector.command(name).steps[0].request
    assert spec.method in ("GET", "POST", "PUT", "PATCH", "DELETE") and would.host == host.split(":")[0]


# --------------------------------------------------------------------------- #
# Fetching and mirroring                                                      #
# --------------------------------------------------------------------------- #
FETCHING = [connector for _text, connector in SHIPPED if connector.fetch is not None]


@pytest.mark.parametrize("connector", FETCHING, ids=[connector.id for connector in FETCHING])
def test_a_shipped_fetch_asks_what_the_documentation_says_and_its_mapper_reads_the_answer(connector, client):
    """``fetch.json`` beside the commands: the state a cycle starts from, the requests it must send,
    the ids and the next state it must give, and what the shipped mapper makes of the first item."""
    from app import fields as registry
    from app import mapping
    from app.automation import expressions as ex
    from app.core.db import SessionLocal

    fixture = json.loads((DATA / connector.id / "fetch.json").read_text(encoding="utf-8"))
    connection = _connection(connector.id)
    config = {**connection["config"], **fixture.get("config", {})}
    host = ca.host_of(connector, config).split(":")[0]
    wire = Recorded(fixture["exchanges"], host)
    rt.forget_tokens()
    runtime = rt.Runtime(
        connector, config, connection["secrets"], egress.Policy(mode="listed", hosts=frozenset({host})), send=wire
    )
    spec = connector.fetch
    state = fixture["state"]
    found = runtime.fetch(
        spec, state, {"iso": "", "epoch": 0, "epoch_ms": 0}, {"iso": "", "epoch": 0, "epoch_ms": 0}, 200
    )
    assert wire.exchanges == [], "the fetch sent fewer requests than the documentation says"
    items = found["items"]

    def of_item(template: str, item) -> str:
        return str(ex.render_text(template, ex.Scope(values={"item": item, "config": config, "state": state})).data)

    assert [of_item(spec.item_id, item) for item in items] == fixture["item_ids"]
    if spec.occurred:
        assert [of_item(spec.occurred, item) for item in items] == fixture["occurred"]
    at = fixture.get("now", {"epoch": 0})["epoch"]
    now = {"iso": "", "epoch": at, "epoch_ms": at * 1000}
    held = {"config": config, "state": state, "response": found["response"], "items": items, "now": now}
    scope = ex.Scope(values=held)
    assert {key: ex.render(value, scope).data for key, value in spec.next_state.items()} == fixture["next_state"]
    # Before the first cycle: the state its request needs, from the moment first_fetch ago.
    start = fixture["first_state_for"]
    moment = {"iso": start.get("iso", ""), "epoch": start["epoch"], "epoch_ms": start["epoch"] * 1000}
    first = ex.render(spec.first_state, ex.Scope(values={"config": config, "first": moment, "now": moment})).data
    assert first == start["state"]

    shipped = vendor.mappers()[connector.id]
    with SessionLocal() as db:
        registry.seed(db)
        db.commit()
        made = mapping.apply_incoming(
            db, mapping.clean_rules(db, connector.id, "incoming", shipped["incoming"]), items[0], connector.id
        )
        assert made.problems == []
        assert made.fields == fixture["mapped"]["fields"]
        assert [path for path, _value in made.context] == fixture["mapped"]["context"]
        if "outgoing" in fixture:
            rules = mapping.clean_rules(db, connector.id, "outgoing", shipped["outgoing"])
            scope = ex.Scope(values={"incident": fixture["outgoing"]["incident"], "context": {}, "mirror": {"id": "x"}})
            sent = {}
            for rule in rules:
                value, _why = mapping._value(rule["from"], scope)
                if value not in (None, ""):
                    sent[rule["to"]] = value
            assert sent == fixture["outgoing"]["sent"]
    if connector.mirror is not None and connector.mirror.comments is not None and "comments" in fixture:
        said = connector.mirror.comments
        result = fixture["comments"]["result"]
        listed = ex.render_text(said.items, ex.Scope(values={"result": result})).data
        read = [
            {
                key: str(ex.render_text(getattr(said, key), ex.Scope(values={"item": item})).data)
                for key in ("id", "text", "author", "at")
            }
            for item in listed
        ]
        assert read == fixture["comments"]["read"]


def test_the_products_that_raise_alerts_and_keep_tickets_are_fetched():
    assert {connector.id for connector in FETCHING} >= {
        "servicenow", "jira-cloud", "jira-datacenter", "sentinelone", "sentinelone-sdl"
    }  # fmt: skip

    fetching = {connector.id for _text, connector in vendor.connectors() if connector.fetch is not None}
    assert set(vendor.mappers()) == fetching and "mail" in fetching


def test_the_mirror_of_a_shipped_connector_names_commands_that_take_what_it_gives():
    mirrored = [connector for _text, connector in SHIPPED if connector.mirror is not None]
    assert {connector.id for connector in mirrored} >= {"servicenow", "jira-cloud", "jira-datacenter"}
    for connector in mirrored:
        for _where, call in connector.mirror_calls():
            assert connector.command(call.command) is not None
        assert connector.fetch is not None, f"{connector.id}: mirrors what it does not fetch"
