"""The connectors Nik ships, each command against an exchange recorded from the vendor's documentation.

No test instance exists for these products: a fixture
(``tests/data/connectors/<id>/<command>.json``) says, for the arguments it
gives, which requests the command must send (method, path, body) and what it
must give back for the answers the documentation shows. Every command of
every shipped connector has one, and none of them is "verified" until the
maintainer runs "Test the connection" against a real system.

    {"args": {...},
     "exchanges": [{"request": {"method", "path", "query"?, "json"?, "form"?, "headers"?, "body_has"?,
                                "host"? (another host the connector lists), "without_headers"?,
                                "files"? [{"field", "name", "type"?, "text" | "base64"}]},
                    "response": {"status", "json"? | "text"? | "base64"?, "headers"?}}],
     "outputs": {...},
     "store"? {"<name>": {"text" | "base64"}}, "kept"? [{"name", "type"?, "text" | "base64"}]}

A command that carries a file (6.5) says so in three more places. ``store`` is
what Nik holds for the fixture: an argument whose value is ``store:<name>``
is given the artifact of that file. A request that sends files lists them in
``files``, and the body must carry each one byte for byte, in the field and
under the name it says; an answer that is a file is ``base64`` in the
response. ``kept`` is what the command must have handed to the store, in
order. In ``outputs``, ``sha256:<name>`` and ``artifact:<name>`` stand for the
hash and the artifact of a file of ``kept``.

``connection.json`` beside them holds the configuration and the (invented)
credentials the fixtures are run with.
"""

from __future__ import annotations

import base64
import hashlib
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


def _bytes(item: dict) -> bytes:
    """The content a fixture gives a file: as text, or in base64 when it is not text."""
    return base64.b64decode(item["base64"]) if "base64" in item else str(item.get("text", "")).encode()


def _sent(value) -> str:
    """A query value as it goes: yes and no as an address carries them."""
    return {True: "true", False: "false"}.get(value, str(value)) if isinstance(value, bool) else str(value)


class Held:
    """The store of a fixture: the files it says Nik holds, and what a command handed to it."""

    limit_mb = 100
    limit = 100 * 1024 * 1024

    def __init__(self, files: dict):
        self.files = {hashlib.sha256(_bytes(item)).hexdigest(): (name, _bytes(item)) for name, item in files.items()}
        self.kept: list[dict] = []

    def artifact(self, name: str) -> str:
        return next(f"file-{sha}" for sha, (held, _data) in self.files.items() if held == name)

    def describe(self, wanted) -> dict:
        sha = str(wanted).removeprefix("file-")
        name, data = self.files[sha]
        return {"name": name, "size": len(data), "sha256": sha}

    def judge(self, found: list[dict]) -> bool:
        return True

    def read(self, sha: str) -> bytes:
        return self.files[sha][1]

    def keep(self, data: bytes, name: str, kind: str) -> dict:
        sha = hashlib.sha256(data).hexdigest()
        self.kept.append({"name": name, "type": kind, "data": data})
        return {"name": name or sha, "type": kind, "size": len(data), "sha256": sha, "artifact": f"file-{sha}",
                "linked": False}  # fmt: skip


def _named(value, kept: dict[str, bytes]):
    """An expected output with ``sha256:<name>`` and ``artifact:<name>`` replaced by those of a kept file."""
    if isinstance(value, dict):
        return {key: _named(item, kept) for key, item in value.items()}
    if isinstance(value, list):
        return [_named(item, kept) for item in value]
    if isinstance(value, str) and value.partition(":")[0] in ("sha256", "artifact") and value.partition(":")[2] in kept:
        sha = hashlib.sha256(kept[value.partition(":")[2]]).hexdigest()
        return sha if value.startswith("sha256:") else f"file-{sha}"
    return value


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
        assert query == {key: _sent(value) for key, value in wanted.get("query", {}).items()}, f"{where}: query"
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
        raw = body if isinstance(body, bytes) else (body or "").encode()
        text = raw.decode(errors="replace")
        for piece in wanted.get("body_has", []):
            assert piece in text, f"{where}: the body lacks {piece!r}"
        for item in wanted.get("files", []):
            if item.get("field"):
                head = f'name="{item["field"]}"; filename="{item["name"]}"\r\nContent-Type: '
                head += item.get("type", "application/octet-stream")
                part = head.encode() + b"\r\n\r\n" + _bytes(item) + b"\r\n"
                assert part in raw, f"{where}: the body lacks the file {item['name']} as the field {item['field']}"
            else:
                assert raw == _bytes(item), f"{where}: the body is not the file {item['name']}"
        if "base64" in answer:
            content, kind = base64.b64decode(answer["base64"]), "application/octet-stream"
        elif "text" in answer:
            content, kind = answer["text"].encode(), "text/plain"
        else:
            content, kind = json.dumps(answer.get("json", {})).encode(), "application/json"
        head = {"content-type": kind, **answer.get("headers", {})}
        record = {"method": method, "host": parts.hostname, "path": parts.path, "status": answer["status"]}
        return egress.Response(status=answer["status"], headers=head, body=content, record=record)


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
    played(connector, name, fixture, _connection(connector.id))


def played(connector, name: str, fixture: dict, connection: dict) -> None:
    """Run a command against the exchanges of its fixture, and check what it sent, gave and kept."""
    config = {**connection["config"], **fixture.get("config", {})}
    host = ca.host_of(connector, config).split(":")[0]
    wire = Recorded(fixture["exchanges"], host)
    now = [1_800_000_000.0]
    policy = egress.Policy(mode="listed", hosts=frozenset({host}))
    rt.forget_tokens()

    # A command that carries a file has the store of its fixture; the others have none, as before 6.5.
    command = connector.command(name)
    held = Held(fixture.get("store", {})) if command.gives_file or command.sends_file else None
    args = {
        key: held.artifact(value[6:]) if held and isinstance(value, str) and value.startswith("store:") else value
        for key, value in fixture["args"].items()
    }

    def runtime() -> rt.Runtime:
        live = rt.Runtime(connector, config, connection["secrets"], policy, send=wire, clock=lambda: now[0])
        live.store = held
        return live

    answer = runtime().run(name, args)
    waits = 0
    while not answer.done:
        # A command that waits: the engine would call again at that time, with the state it was given.
        waits += 1
        assert waits < 20 and answer.again_at > now[0]
        now[0] = answer.again_at
        answer = runtime().run(name, args, answer.state)
    assert wire.exchanges == [], "the command sent fewer requests than the documentation says"
    wanted = [
        {"name": item["name"], "data": _bytes(item), **({"type": item["type"]} if "type" in item else {})}
        for item in fixture.get("kept", [])
    ]
    if held is not None:
        got = [
            {key: item[key] for key in ("name", "data", *(("type",) if "type" in want else ()))}
            for item, want in zip(held.kept, wanted, strict=True)
        ]
        assert got == wanted, "the command did not hand the store the files the fixture says"
    assert answer.outputs == _named(fixture["outputs"], {item["name"]: item["data"] for item in wanted})
    # No secret of the connection is in what the step would record.
    recorded = json.dumps([answer.outputs, answer.records])
    for value in connection["secrets"].values():
        assert value not in recorded


def test_a_fixture_can_describe_a_file_that_comes_back_and_a_file_that_is_sent():
    """No shipped connector carries a file yet: the format of the fixtures is run here on one that does."""
    from app.automation import connectors as cn

    connector = cn.load(
        """\
name: Depot
id: depot
version: 1
api_version: v1
configuration:
  - { name: url, type: url, required: true }
  - { name: credentials, type: query, param: key }
base_url: "{{ config.url }}"
commands:
  - name: download
    description: Download a file.
    arguments: [{ name: id, type: text, required: true }, { name: raw, type: bool, default: true }]
    request: { method: GET, path: "/files/{{ args.id }}", query: { raw: "{{ args.raw }}" }, answer: file }
    outputs: { artifact: "{{ response.artifact }}", sha256: "{{ response.sha256 }}", name: "{{ response.name }}" }
  - name: submit
    description: Submit a file.
    changes_outside: true
    arguments: [{ name: sample, type: file, required: true }]
    request:
      method: POST
      path: /files
      multipart: { note: from Nik }
      files: { file: { artifact: "{{ args.sample }}", type: application/x-dosexec } }
    outputs: { id: "{{ response.id }}" }
    sample: { id: "" }
"""
    )
    connection = {"config": {"url": "https://depot.example.com/api"}, "secrets": {"value": "depot-key-1234"}}
    blob = base64.b64encode(b"MZ\x90\x00\xff binary").decode()
    played(
        connector,
        "download",
        {
            "args": {"id": "f-1"},
            "exchanges": [
                {
                    "request": {
                        "method": "GET",
                        "path": "/api/files/f-1",
                        "query": {"raw": True, "key": "depot-key-1234"},
                    },
                    "response": {
                        "status": 200,
                        "base64": blob,
                        "headers": {"content-disposition": "attachment; filename=a.exe"},
                    },
                }
            ],
            "kept": [{"name": "a.exe", "type": "application/octet-stream", "base64": blob}],
            "outputs": {"artifact": "artifact:a.exe", "sha256": "sha256:a.exe", "name": "a.exe"},
        },
        connection,
    )
    played(
        connector,
        "submit",
        {
            "args": {"sample": "store:a.exe"},
            "store": {"a.exe": {"base64": blob}},
            "exchanges": [
                {
                    "request": {
                        "method": "POST",
                        "path": "/api/files",
                        "query": {"key": "depot-key-1234"},
                        "body_has": ['name="note"', "from Nik"],
                        "files": [{"field": "file", "name": "a.exe", "type": "application/x-dosexec", "base64": blob}],
                    },
                    "response": {"status": 200, "json": {"id": "s-9"}},
                }
            ],
            "outputs": {"id": "s-9"},
        },
        connection,
    )
    # A fixture that names another file than the one sent, or keeps another than it says, fails.
    wrong = {
        "args": {"sample": "store:a.exe"},
        "store": {"a.exe": {"base64": blob}},
        "exchanges": [
            {
                "request": {"method": "POST", "path": "/api/files", "query": {"key": "depot-key-1234"},
                            "files": [{"field": "file", "name": "a.exe", "type": "application/x-dosexec",
                                       "text": "other"}]},
                "response": {"status": 200, "json": {"id": "s-9"}},
            }
        ],
        "outputs": {"id": "s-9"},
    }  # fmt: skip
    with pytest.raises(AssertionError, match="the body lacks the file a.exe"):
        played(connector, "submit", wrong, connection)


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
