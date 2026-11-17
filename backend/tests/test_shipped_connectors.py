"""The connectors Nik ships, each command against an exchange recorded from the vendor's documentation.

No test instance exists for these products: a fixture
(``tests/data/connectors/<id>/<command>.json``) says, for the arguments it
gives, which requests the command must send (method, path, body) and what it
must give back for the answers the documentation shows. Every command of
every shipped connector has one, and none of them is "verified" until the
maintainer runs "Test the connection" against a real system.

    {"args": {...},
     "exchanges": [{"request": {"method", "path", "query"?, "json"?, "form"?, "headers"?, "body_has"?},
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

DATA = Path(__file__).parent / "data" / "connectors"
SHIPPED = ca.shipped()
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
        assert parts.hostname == self.host, f"{where}: sent to {parts.hostname}"
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
