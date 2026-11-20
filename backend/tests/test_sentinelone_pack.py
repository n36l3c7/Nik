"""The SentinelOne packs, beyond the exchange each command is replayed against (test_shipped_connectors.py).

What is checked here is what a recorded exchange cannot say: that a command which acts on endpoints or
threats is stopped when it names none (SentinelOne applies an action with an empty filter to everything
the token reaches), how the lists are read page by page, and what the commands that wait for a file do
when the file does not come, or when the console sends them to another host for it.
"""

from __future__ import annotations

import hashlib
import json
import re
from urllib.parse import parse_qsl, urlsplit

import pytest

from app.automation import connector_runtime as rt
from app.automation import egress
from tests import vendor
from tests.stores import zip_of
from tests.test_shipped_connectors import DATA, Held, _connection

CONNECTORS = {connector.id: connector for _text, connector in vendor.connectors()}
EDR = CONNECTORS["sentinelone"]
SIEM = CONNECTORS["sentinelone-sdl"]
HOST = "acme.sentinelone.net"
AGENT = "1234567890123456789"
THREAT = "5555555555555555555"
PASSWORD = "Nik-Fetch-2026!x"
# What an agent uploads for a fetch: a zip protected with the password the request set.
ARCHIVE = zip_of({"dropper.exe": b"not a real sample: a harmless line of text\n"}, PASSWORD)

# How a template stops a command: the three ways the file writes "this may not be empty".
GUARD = re.compile(r"args\.(\w+)\.(at_least_one|is_needed|every_field_filled)")
# The commands that change the console by adding something to it: they name a scope, not targets, and
# SentinelOne refuses them itself when what they add is missing.
ADDING = {
    "add-hash-to-blocklist",
    "create-endpoint-tag",
    "create-exclusion",
    "create-detection-rule",
    "create-iocs-from-stix",
    "upload-script",
}
CHANGING = [command for command in EDR.commands if command.changes_outside]


class Wire:
    """An egress client that records what is sent and answers what a function says."""

    def __init__(self, answer=None):
        self.sent: list[dict] = []
        self.answer = answer or (lambda request: (200, {"data": []}))

    def __call__(self, policy, method, url, **sent):
        parts = urlsplit(url)
        query = {
            **dict(parse_qsl(parts.query)),
            **{key: str(value) for key, value in (sent.get("query") or {}).items()},
        }
        request = {
            "method": method,
            "host": parts.hostname,
            "path": parts.path,
            "query": query,
            "json": sent.get("json"),
            "headers": sent.get("headers") or {},
        }
        self.sent.append(request)
        status, body = self.answer(request)
        record = {"method": method, "host": parts.hostname, "path": parts.path, "status": status}
        if isinstance(body, bytes):
            return egress.Response(status=status, headers={"content-type": "application/zip"}, body=body, record=record)
        head = {"content-type": "application/json"}
        return egress.Response(status=status, headers=head, body=json.dumps(body).encode(), record=record)


def runtime(connector, wire, clock=None, store=None) -> rt.Runtime:
    connection = _connection(connector.id)
    policy = egress.Policy(mode="listed", hosts=frozenset({HOST}))
    rt.forget_tokens()
    live = rt.Runtime(
        connector,
        connection["config"],
        connection["secrets"],
        policy,
        send=wire,
        clock=clock or (lambda: 1_800_000_000.0),
    )
    live.store = store
    return live


def guarded(command) -> dict[str, str]:
    """argument → how it is guarded, for the arguments a command cannot go without."""
    return {name: how for name, how in GUARD.findall(json.dumps(command.model_dump(mode="json")))}


def fixture_args(name: str) -> dict:
    found = json.loads((DATA / "sentinelone" / f"{name}.json").read_text(encoding="utf-8"))["args"]
    # A file a fixture holds is not needed to see a command refused before anything is sent.
    return {key: value for key, value in found.items() if not (isinstance(value, str) and value.startswith("store:"))}


def test_every_command_that_acts_names_what_it_acts_on():
    assert len(CHANGING) >= 50
    for command in CHANGING:
        if command.name in ADDING:
            continue
        assert guarded(command), f"{command.name}: nothing stops it when its target is empty"
    # The two that take the console's own filter are the only ones whose target is not a list of ids.
    by_filter = [command.name for command in CHANGING if "every_field_filled" in guarded(command).values()]
    assert by_filter == ["run-agent-action", "mitigate-threats"]
    # No command of the file sends a filter that is written empty.
    assert not re.search(r"filter:\s*\{\s*\}", vendor.REPO_PACKS.joinpath(
        "sentinelone", "connectors", "sentinelone", "connector.yml").read_text(encoding="utf-8"))  # fmt: skip


@pytest.mark.parametrize("command", CHANGING, ids=[command.name for command in CHANGING])
def test_an_action_without_its_target_is_refused_before_anything_changes(command):
    """Each argument a changing command cannot go without, left empty in every way a playbook can leave
    it empty: the command fails, and nothing but a read has left."""
    for name, how in guarded(command).items():
        empties = [None, "", [], " , "] if how != "every_field_filled" else [None, {}, "", {"groupIds": []}]
        if how == "is_needed":
            empties = [None, "", []]
        for empty in empties:
            wire = Wire()
            args = {**fixture_args(command.name), name: empty}
            with pytest.raises(rt.CommandError) as refused:
                runtime(EDR, wire, store=Held({})).run(command.name, args)
            assert f"args.{name}.{how}" in refused.value.message, (command.name, name, empty)
            assert [sent["method"] for sent in wire.sent if sent["method"] != "GET"] == [], (command.name, name, empty)


def test_a_filter_with_an_empty_field_is_refused_and_a_full_one_goes_as_it_is():
    for filter_ in ({"siteIds": ["2222222222222222222"], "computerName__contains": ""}, {"groupIds": None}):
        wire = Wire()
        with pytest.raises(rt.CommandError, match="every_field_filled"):
            runtime(EDR, wire).run("run-agent-action", {"action": "disconnect", "filter": filter_})
        assert wire.sent == []
    wire = Wire(lambda request: (200, {"data": {"affected": 7}}))
    wanted = {"groupIds": ["3333333333333333333"], "isActive": True}
    answer = runtime(EDR, wire).run("run-agent-action", {"action": "disconnect", "filter": wanted})
    assert answer.outputs == {"affected": 7}
    assert (wire.sent[0]["path"], wire.sent[0]["json"]) == (
        "/web/api/v2.1/agents/actions/disconnect",
        {"filter": wanted},
    )


def test_an_action_that_is_not_one_of_the_list_does_not_reach_another_endpoint_of_the_api():
    """The action is a part of the address: one a playbook made up (uninstall, decommission) is not sent on."""
    for name, args in (
        ("run-agent-action", {"action": "uninstall", "filter": {"ids": [AGENT]}}),
        ("mitigate-threats", {"action": "../agents/actions/uninstall", "filter": {"ids": [THREAT]}}),
        ("mitigate-threat", {"action": "decommission", "threat_id": THREAT}),
    ):
        wire = Wire(lambda request: (404, {"errors": [{"detail": "Not found"}]}))
        with pytest.raises(rt.CommandError, match="answered 404"):
            runtime(EDR, wire).run(name, args)
        assert [sent["path"].rsplit("/", 1)[-1] for sent in wire.sent] == ["none"], name


def test_several_targets_are_given_as_a_list_or_with_commas():
    for given in ([AGENT, "1234567890123456790"], f"{AGENT}, 1234567890123456790"):
        wire = Wire(lambda request: (200, {"data": {"affected": 2}}))
        assert runtime(EDR, wire).run("isolate-agent", {"agent_id": given}).outputs == {"affected": 2}
        assert wire.sent[0]["json"] == {"filter": {"ids": [AGENT, "1234567890123456790"]}}


def test_a_list_is_read_page_by_page_with_the_size_and_the_number_of_pages_asked_for():
    pages = {
        None: {"data": [{"id": "1"}, {"id": "2"}], "pagination": {"totalItems": 5, "nextCursor": "c-2"}},
        "c-2": {"data": [{"id": "3"}, {"id": "4"}], "pagination": {"totalItems": 5, "nextCursor": "c-3"}},
        "c-3": {"data": [{"id": "5"}], "pagination": {"totalItems": 5, "nextCursor": None}},
    }
    wire = Wire(lambda request: (200, pages[request["query"].get("cursor")]))
    answer = runtime(EDR, wire).run(
        "get-agent", {"site_ids": ["2222222222222222222", "2222222222222222223"], "limit": 2}
    )
    assert [sent["query"] for sent in wire.sent] == [
        {"siteIds": "2222222222222222222,2222222222222222223", "limit": "2"},
        {"siteIds": "2222222222222222222,2222222222222222223", "limit": "2", "cursor": "c-2"},
        {"siteIds": "2222222222222222222,2222222222222222223", "limit": "2", "cursor": "c-3"},
    ]
    found = answer.outputs
    assert (found["ids"], found["count"], found["total"], found["truncated"]) == (
        ["1", "2", "3", "4", "5"],
        5,
        5,
        False,
    )
    assert found["agent_id"] == "1"
    # Fewer pages than there are: what was read is given, and the command says there is more.
    wire = Wire(lambda request: (200, pages[request["query"].get("cursor")]))
    found = runtime(EDR, wire).run("get-agent", {"limit": 2, "pages": 2}).outputs
    assert (found["count"], found["total"], found["truncated"], len(wire.sent)) == (4, 5, True, 2)
    # A page holds 1000 at most, whatever is asked: the limit of the reference.
    wire = Wire(lambda request: (200, pages["c-3"]))
    runtime(EDR, wire).run("get-threats", {"limit": 5000, "pages": 1})
    assert wire.sent[0]["query"] == {"limit": "1000"}


def test_every_list_of_the_console_is_read_by_cursor_within_the_limit_of_the_reference():
    paged = [command for command in EDR.commands if command.pagination is not None]
    assert len(paged) >= 35
    for command in paged:
        page = command.pagination
        assert (page.type, page.param, page.limit_param) == ("cursor", "cursor", "limit"), command.name
        assert page.limit == "{{ args.limit }}" and page.keep == {"total": "{{ response.pagination.totalItems }}"}
        limit = next(argument for argument in command.arguments if argument.name == "limit")
        assert 1 <= limit.default <= 1000, command.name


def _uploads(new_after: int, body: bytes = ARCHIVE):
    """The console of a fetch: the activity that announces the upload is there from the ``new_after``-th look."""
    looks = {"count": 0}

    def answer(request):
        if request["path"].endswith("/activities"):
            looks["count"] += 1
            old = {"id": "8800000000000000001", "agentId": AGENT}
            new = {"id": "8800000000000000007", "agentId": AGENT, "threatId": THREAT}
            return 200, {"data": [new if looks["count"] > new_after else old]}
        if "/uploads/" in request["path"]:
            return 200, body
        return 200, {"data": {"affected": 1}}

    return answer


def test_a_file_that_was_uploaded_before_is_not_taken_for_the_one_asked_for():
    """The newest upload of the threat is looked at before asking: the download waits for another one."""
    now = [1_800_000_000.0]
    wire, held = Wire(_uploads(new_after=3)), Held({})
    args = {"threat_id": THREAT, "password": "Nik-Fetch-2026!x"}

    def again(state=None):
        return runtime(EDR, wire, clock=lambda: now[0], store=held).run("fetch-threat-file", args, state)

    answer = again()
    waits = 0
    while not answer.done:
        waits += 1
        assert answer.again_at == now[0] + 15
        now[0] = answer.again_at
        answer = again(answer.state)
    assert waits == 2
    assert [sent["path"].rsplit("/", 1)[-1] for sent in wire.sent] == [
        "activities", "fetch-file", "activities", "activities", "activities", "8800000000000000007",
    ]  # fmt: skip
    assert wire.sent[1]["json"] == {"data": {"password": "Nik-Fetch-2026!x"}, "filter": {"ids": [THREAT]}}
    assert wire.sent[-1]["path"] == f"/web/api/v2.1/agents/{AGENT}/uploads/8800000000000000007"
    # The archive is kept as it came, and the file inside it beside it.
    assert [(item["name"], item["data"]) for item in held.kept] == [
        ("8800000000000000007", ARCHIVE),
        ("dropper.exe", b"not a real sample: a harmless line of text\n"),
    ]
    assert answer.outputs["activity_id"] == "8800000000000000007" and answer.outputs["size"] == len(ARCHIVE)
    assert (answer.outputs["count"], answer.outputs["skipped"]) == (1, [])
    assert [item["name"] for item in answer.outputs["files"]] == ["dropper.exe"]
    # The password opens the archive and is shown nowhere in what the step gives or records.
    assert PASSWORD not in json.dumps([answer.outputs, answer.records])


@pytest.mark.parametrize(
    ("name", "args"),
    [
        ("fetch-threat-file", {"threat_id": THREAT, "password": "Nik-Fetch-2026!x"}),
        ("fetch-agent-files", {"agent_id": AGENT, "files": ["C:\\a.txt"], "password": "Nik-Fetch-2026!x"}),
        ("fetch-agent-logs", {"agent_id": AGENT, "activity_type": 3015}),
    ],
)
def test_a_fetch_gives_up_when_the_upload_does_not_come_in_a_quarter_of_an_hour(name, args):
    now = [1_800_000_000.0]
    wire, held = Wire(_uploads(new_after=10_000)), Held({})
    answer = runtime(EDR, wire, clock=lambda: now[0], store=held).run(name, args)
    with pytest.raises(rt.CommandError, match="did not finish in time"):
        for _ in range(200):
            assert not answer.done
            now[0] = answer.again_at
            answer = runtime(EDR, wire, clock=lambda: now[0], store=held).run(name, args, answer.state)
    assert now[0] - 1_800_000_000.0 == 900 and held.kept == []
    # It was asked for once, however long the wait.
    assert len([sent for sent in wire.sent if sent["method"] == "POST"]) == 1


LINKED = [
    ("download-threat-from-cloud", {"threat_id": THREAT}, {"downloadUrl": "{}", "fileName": "dropper.exe.zip"}),
    (
        "download-event-file",
        {"download_token": "dvtok-7f3a9c"},
        {"downloadUrl": "{}", "fileName": "powershell.exe.zip"},
    ),
    (
        "download-script-result",
        {"task_id": "7300000000000000002"},
        {"downloadLinks": [{"downloadUrl": "{}", "fileName": "out.zip"}]},
    ),
]


@pytest.mark.parametrize(("name", "args", "shape"), LINKED, ids=[name for name, _args, _shape in LINKED])
def test_a_download_link_on_another_host_is_not_followed_and_the_token_stays_home(name, args, shape):
    elsewhere = "https://s1-files.storage.example.net/a/b.zip?X-Signature=abc"
    wire, held = Wire(lambda request: (200, {"data": json.loads(json.dumps(shape).replace("{}", elsewhere))})), Held({})
    with pytest.raises(rt.CommandError, match="goes to s1-files.storage.example.net, not to its instance"):
        runtime(EDR, wire, store=held).run(name, args)
    # Only the request for the link left, to the console; nothing went to the other host, with or without the token.
    assert [sent["host"] for sent in wire.sent] == [HOST] and held.kept == []


@pytest.mark.parametrize(("name", "args", "shape"), LINKED, ids=[name for name, _args, _shape in LINKED])
def test_a_download_link_on_a_host_the_instance_lists_is_followed_without_the_token(name, args, shape):
    """The instance says where the downloads of this console come from: the link is followed there,
    and the request carries nothing of the connector."""
    storage = "s1-files.storage.example.net"
    elsewhere = f"https://{storage}/a/b.zip?X-Signature=abc"
    body = b"PK not really an archive, kept as it came"

    def answer(request):
        if request["host"] == storage:
            return 200, body
        return 200, {"data": json.loads(json.dumps(shape).replace("{}", elsewhere))}

    connection = _connection(EDR.id)
    for listed in (storage, "*.storage.example.net"):
        wire, held = Wire(answer), Held({})
        rt.forget_tokens()
        live = rt.Runtime(
            EDR,
            {**connection["config"], "download_hosts": listed},
            connection["secrets"],
            egress.Policy(mode="listed", hosts=frozenset({HOST})),
            send=wire,
            clock=lambda: 1_800_000_000.0,
        )
        live.store = held
        live.run(name, args)
        assert [item["data"] for item in held.kept] == [body], listed
        console, fetched = wire.sent[0], wire.sent[-1]
        assert console["host"] == HOST and console["headers"]["Authorization"].startswith("ApiToken ")
        # To the storage: the address the console gave, its signature in it, and no header at all.
        assert (fetched["host"], fetched["path"], fetched["query"]) == (storage, "/a/b.zip", {"X-Signature": "abc"})
        assert fetched["headers"] == {} and "ApiToken" not in json.dumps(fetched)


def test_the_instance_of_the_console_is_asked_where_its_downloads_come_from_and_says_so_when_it_does_not_know():
    entry = next(param for param in EDR.configuration if param.name == "download_hosts")
    assert EDR.download_hosts_from == "download_hosts"
    assert (entry.type, entry.label, entry.required) == ("hosts", "Hosts downloads may come from", False)
    assert "never sent there" in entry.help
    # Nothing listed: the refusal names the host and the field, so the name to write is the one the step gives.
    name, args, shape = LINKED[0]
    elsewhere = "https://s1-files.storage.example.net/a/b.zip?X-Signature=abc"
    wire, held = Wire(lambda request: (200, {"data": json.loads(json.dumps(shape).replace("{}", elsewhere))})), Held({})
    with pytest.raises(rt.CommandError) as refused:
        runtime(EDR, wire, store=held).run(name, args)
    assert refused.value.message == (
        "A request of this connector goes to s1-files.storage.example.net, not to its instance: add it under "
        "Hosts downloads may come from in the instance if it is the vendor's storage"
    )
    # The four that follow a link say both ways: the field of the instance, and the three nodes.
    for command in ("download-threat-from-cloud", "download-event-file", "download-script-result",
                    "download-forensic-collection"):  # fmt: skip
        said = EDR.command(command).description
        assert "Hosts downloads may come from" in said and "nik.download-file" in said, command


def test_the_two_fetches_unpack_the_archive_with_the_password_they_set_and_the_other_files_are_kept_as_they_come():
    """A fetch asks the agent for an archive protected by the password the request itself sets: the same
    password opens it, and it is required. What the console hands over by a link or by the id of an
    activity may be anything: it is kept as it came, and no command guesses that it is an archive."""
    unpacking = [command.name for command in EDR.commands if command.unpacks]
    assert unpacking == ["fetch-agent-files", "fetch-threat-file"]
    for name in unpacking:
        command = EDR.command(name)
        download = command.steps[-1].request
        assert (download.answer, download.unpack.format) == ("file", "zip")
        assert download.unpack.password == "{{ args.password }}"
        password = next(argument for argument in command.arguments if argument.name == "password")
        assert password.required and password.default is None, name
        assert {"files", "count", "skipped"} <= set(command.outputs), name
    kept_as_they_come = [command.name for command in EDR.commands if command.gives_file and not command.unpacks]
    assert {"download-agent-upload", "download-threat-from-cloud", "download-event-file", "download-script-result",
            "download-forensic-collection", "fetch-agent-logs"} <= set(kept_as_they_come)  # fmt: skip
    for name in kept_as_they_come:
        assert all(argument.name != "password" for argument in EDR.command(name).arguments), name
    # The four that follow a link say what a playbook does when the link is on another host.
    for name in (
        "download-threat-from-cloud",
        "download-event-file",
        "download-script-result",
        "download-forensic-collection",
    ):
        said = EDR.command(name).description
        assert "nik.download-file" in said and "nik.unpack-artifact" in said and "no credentials" in said, name


@pytest.mark.parametrize(
    ("password", "why"),
    [
        ("Another-Pass-2026!", "The password does not open the archive"),
        (PASSWORD, "The file is not a zip archive"),
    ],
)
def test_a_fetched_archive_that_cannot_be_opened_fails_the_step_and_is_kept_as_it_came(password, why):
    """The upload came with another password than the one asked with, or is not a zip at all: it is
    evidence all the same, kept alone, and the step says where it is."""
    body = (
        zip_of({"dropper.exe": b"a harmless line\n"}, "Nik-Fetch-2026!x") if "password" in why else b"MZ not an archive"
    )
    wire, held = Wire(_uploads(new_after=1, body=body)), Held({})
    now = [1_800_000_000.0]
    args = {"threat_id": THREAT, "password": password}
    with pytest.raises(rt.CommandError, match=why) as failed:
        answer = runtime(EDR, wire, clock=lambda: now[0], store=held).run("fetch-threat-file", args)
        while not answer.done:
            now[0] = answer.again_at
            answer = runtime(EDR, wire, clock=lambda: now[0], store=held).run("fetch-threat-file", args, answer.state)
    # The archive, and nothing of what may be inside it.
    assert [item["data"] for item in held.kept] == [body]
    artifact = "file-" + hashlib.sha256(body).hexdigest()
    assert failed.value.kept == artifact and failed.value.message.endswith(f"The archive was kept as {artifact}")
    assert password not in failed.value.message


def test_the_fetch_asks_from_the_moment_itself_in_the_order_of_creation():
    spec = EDR.fetch
    assert spec.request.query == {"createdAt__gte": "{{ since.iso }}", "sortBy": "createdAt", "sortOrder": "asc"}
    assert spec.by_time and spec.pagination.limit == 100 and spec.item_id == "{{ item.id }}"
    # The alerts of the SIEM are asked for as before: their API is not in SentinelOne's reference.
    assert SIEM.fetch.lookback_minutes == 5 and "detectedAt" in json.dumps(SIEM.fetch.request.model_dump(mode="json"))


def test_what_a_playbook_of_before_used_still_has_its_name():
    """The commands, arguments and outputs of the connectors of 6.5 are all still there."""
    before = {
        "get-agent": ({"computer_name", "ids"}, {"agents", "ids", "count"}),
        "isolate-agent": ({"agent_id"}, {"affected"}),
        "reconnect-agent": ({"agent_id"}, {"affected"}),
        "add-hash-to-blocklist": ({"hash", "os_type", "description", "site_ids"}, {"ids"}),
        "get-threats": ({"ids", "content_hash", "resolved"}, {"threats", "ids", "count"}),
        "mitigate-threat": ({"threat_id", "action"}, {"affected"}),
        "add-note": ({"threat_id", "text"}, {"affected"}),
        "search-deep-visibility": ({"query", "from_date", "to_date", "limit"}, {"query_id", "events", "count"}),
    }
    for name, (arguments, outputs) in before.items():
        command = EDR.command(name)
        assert arguments <= {argument.name for argument in command.arguments}, name
        assert outputs <= set(command.outputs), name
    for name, arguments, outputs in (
        ("run-query", {"query", "start_time", "end_time"}, {"columns", "rows", "matches"}),
        ("get-alert", {"id"}, {"alert", "status", "severity"}),
        ("update-alert", {"id", "status"}, {"updated", "failed"}),
    ):
        command = SIEM.command(name)
        assert arguments <= {argument.name for argument in command.arguments} and outputs <= set(command.outputs), name
