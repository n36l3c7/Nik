"""Running connector commands against recorded answers: requests, credentials, pages, steps, polls."""

from __future__ import annotations

import base64
import hashlib
import json
import textwrap

import pytest

from app.automation import connector_runtime as rt
from app.automation import connectors as cn
from app.automation import egress

POLICY = egress.Policy(mode="listed", hosts=frozenset({"acme.example.com", "login.example.com"}))


class Wire:
    """Stands in for the egress client: records what is sent, answers what was queued."""

    def __init__(self):
        self.sent: list[dict] = []
        self.answers: list = []

    def answer(self, status=200, body=None, headers=None, text=None):
        content = text if text is not None else json.dumps(body if body is not None else {})
        head = {"content-type": "text/plain" if text is not None else "application/json", **(headers or {})}
        self.answers.append(egress.Response(status=status, headers=head, body=content.encode(), record={}))
        return self

    def fail(self, error: egress.EgressError):
        self.answers.append(error)
        return self

    def __call__(self, policy, method, url, **kwargs):
        self.sent.append({"method": method, "url": url, **{key: value for key, value in kwargs.items() if value}})
        if not self.answers:
            raise AssertionError(f"nothing queued for {method} {url}")
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        answer.record = {"method": method, "host": "acme.example.com", "path": url, "status": answer.status}
        return answer


def connector(commands: str, auth: str = "- { name: credentials, type: basic }", extra: str = "") -> cn.ConnectorFile:
    text = (
        "name: Acme\nid: acme\nversion: 1\nconfiguration:\n"
        "  - { name: url, type: url, required: true }\n"
        + textwrap.indent(textwrap.dedent(auth).strip("\n"), "  ")
        + '\nbase_url: "{{ config.url }}"\n'
        + textwrap.dedent(extra)
        + "commands:\n"
        + textwrap.indent(textwrap.dedent(commands), "  ")
    )
    return cn.load(text)


def runtime(found: cn.ConnectorFile, wire: Wire, secrets=None, clock=None, **config) -> rt.Runtime:
    rt.forget_tokens()
    values = {"url": "https://acme.example.com/api/", **config}
    secrets = {"username": "svc", "password": "s3cret-pass"} if secrets is None else secrets
    return rt.Runtime(found, values, secrets, POLICY, send=wire, clock=clock or (lambda: 1000.0))


CREATE = """\
- name: create-ticket
  changes_outside: true
  arguments:
    - { name: title, type: text, required: true }
    - { name: notify, type: text }
    - { name: urgency, type: choice, choices: ["1", "2"], default: "2" }
  request:
    method: POST
    path: /tickets
    query: { notify: "{{ args.notify | default('') }}" }
    headers: { X-Trace: "nik" }
    json: { title: "{{ args.title }}", urgency: "{{ args.urgency }}" }
  success: { status: [200, 201] }
  error: { message: "{{ response.error.message }}" }
  outputs:
    number: "{{ response.result.number }}"
    link: "{{ config.url }}/t/{{ response.result.id }}"
    missing: "{{ response.result.nope }}"
"""


def test_a_command_is_a_request_built_from_templates_and_outputs_read_from_the_answer():
    found = connector(CREATE)
    wire = Wire().answer(201, {"result": {"number": "T-7", "id": 42}})
    answer = runtime(found, wire).run("create-ticket", {"title": "Phish", "urgency": "1", "notify": None})
    assert answer.done and answer.outputs == {
        "number": "T-7",
        "link": "https://acme.example.com/api/t/42",
        "missing": None,  # the answer did not hold it: empty, not an error
    }
    (sent,) = wire.sent
    assert (sent["method"], sent["url"]) == ("POST", "https://acme.example.com/api/tickets")
    assert sent["json"] == {"title": "Phish", "urgency": "1"}
    assert "query" not in sent  # an empty query value is left out
    assert sent["headers"]["X-Trace"] == "nik"
    assert sent["headers"]["Authorization"] == "Basic " + base64.b64encode(b"svc:s3cret-pass").decode()
    assert answer.records == [
        {"method": "POST", "host": "acme.example.com", "path": "https://acme.example.com/api/tickets", "status": 201}
    ]


def test_an_answer_that_is_not_a_success_fails_with_what_the_other_side_said():
    found = connector(CREATE)
    wire = Wire().answer(400, {"error": {"message": "title too long for s3cret-pass"}})
    with pytest.raises(rt.CommandError) as caught:
        runtime(found, wire).run("create-ticket", {"title": "x", "urgency": "2"})
    # The vendor's message is shown, a refusal is not tried again, and a secret never is.
    assert caught.value.message == "Acme answered 400: title too long for •••"
    assert caught.value.retry is False and caught.value.sent is True
    for status, retry in ((503, True), (429, True), (404, False)):
        with pytest.raises(rt.CommandError) as caught:
            runtime(found, Wire().answer(status, text="down")).run("create-ticket", {"title": "x", "urgency": "2"})
        assert caught.value.retry is retry and caught.value.message == f"Acme answered {status}"
    # What the egress client refuses or loses is passed on as it is.
    lost = egress.EgressError("acme.example.com did not answer in time", sent=True, record={"host": "acme.example.com"})
    with pytest.raises(rt.CommandError) as caught:
        runtime(found, Wire().fail(lost)).run("create-ticket", {"title": "x", "urgency": "2"})
    assert caught.value.sent and caught.value.retry and caught.value.record == {"host": "acme.example.com"}


def test_a_request_never_leaves_the_host_of_the_connection():
    found = connector(
        """\
        - name: fetch
          arguments: [{ name: where, type: text }]
          request: { method: GET, path: "{{ args.where }}" }
        """
    )
    wire = Wire()
    with pytest.raises(rt.CommandError) as caught:
        runtime(found, wire).run("fetch", {"where": "https://evil.example.net/steal"})
    assert caught.value.message == "A request of this connector goes to evil.example.net, not to its instance"
    assert wire.sent == []  # nothing left, and the credentials with it
    # A full address on the connection's own host is fine.
    wire.answer(200, {"ok": True})
    assert runtime(found, wire).run("fetch", {"where": "https://acme.example.com/other"}).outputs == {
        "response": {"ok": True}
    }
    with pytest.raises(rt.CommandError) as caught:
        rt.Runtime(found, {"url": "ftp://acme.example.com"}, {}, POLICY, send=wire)
    assert "not an https:// address" in caught.value.message


def test_each_kind_of_credentials_is_sent_its_own_way():
    command = "- name: ping\n  request: { method: GET, path: /ping }\n"
    bearer = connector(command, "- { name: credentials, type: bearer }")
    wire = Wire().answer()
    runtime(bearer, wire, secrets={"token": "tok-123456"}).run("ping", {})
    assert wire.sent[0]["headers"]["Authorization"] == "Bearer tok-123456"

    header = connector(command, '- { name: credentials, type: header, header: X-Api-Key, prefix: "ApiToken " }')
    wire = Wire().answer()
    runtime(header, wire, secrets={"value": "abcd1234"}).run("ping", {})
    assert wire.sent[0]["headers"]["X-Api-Key"] == "ApiToken abcd1234"

    secret = connector(
        command, "- { name: api_token, type: secret }", extra='headers:\n  X-Token: "{{ secret.api_token }}"\n'
    )
    wire = Wire().answer()
    runtime(secret, wire, secrets={"api_token": "zzzz9999"}).run("ping", {})
    assert wire.sent[0]["headers"] == {"X-Token": "zzzz9999"}


def test_oauth_asks_for_a_token_once_and_keeps_it_until_it_expires():
    found = connector(
        "- name: ping\n  request: { method: GET, path: /ping }\n",
        """\
        - name: credentials
          type: oauth2_client
          token_url: "https://login.example.com/oauth/token"
          scope: read write
        """,
    )
    now = [1000.0]
    wire = Wire().answer(200, {"access_token": "AT-1-secret", "expires_in": 3600}).answer().answer()
    secrets = {"client_id": "nik", "client_secret": "cs-123456"}
    first = rt.Runtime(found, {"url": "https://acme.example.com"}, secrets, POLICY, send=wire, clock=lambda: now[0])
    rt.forget_tokens()
    first.run("ping", {})
    token, ping = wire.sent[0], wire.sent[1]
    assert (token["method"], token["url"]) == ("POST", "https://login.example.com/oauth/token")
    assert token["form"] == {
        "grant_type": "client_credentials",
        "scope": "read write",
        "client_id": "nik",
        "client_secret": "cs-123456",
    }
    assert ping["headers"]["Authorization"] == "Bearer AT-1-secret"
    # Another call, another Runtime, the same connection: the token is still good.
    rt.Runtime(found, {"url": "https://acme.example.com"}, secrets, POLICY, send=wire, clock=lambda: now[0]).run(
        "ping", {}
    )
    assert len(wire.sent) == 3
    # After it expired (a minute early, to be safe) a new one is asked for.
    now[0] += 3600 - 59
    wire.answer(200, {"access_token": "AT-2-secret", "expires_in": 3600}).answer()
    rt.Runtime(found, {"url": "https://acme.example.com"}, secrets, POLICY, send=wire, clock=lambda: now[0]).run(
        "ping", {}
    )
    assert wire.sent[-1]["headers"]["Authorization"] == "Bearer AT-2-secret"
    # No token in the answer: said plainly.
    rt.forget_tokens()
    with pytest.raises(rt.CommandError) as caught:
        rt.Runtime(found, {"url": "https://acme.example.com"}, secrets, POLICY, send=Wire().answer(401, {})).run(
            "ping", {}
        )
    assert caught.value.message == "Acme gave no token (answer 401)"


SESSION = """\
- name: credentials
  type: session
  login:
    request:
      method: POST
      path: /login
      json: { user: "{{ secret.username }}", password: "{{ secret.password }}" }
    token: "{{ response.sid }}"
    header: X-chkp-sid
  logout:
    request: { method: POST, path: /logout, json: {} }
"""


def test_a_session_is_opened_used_and_closed_within_the_call():
    found = connector("- name: ping\n  request: { method: POST, path: /show, json: {} }\n", SESSION)
    wire = Wire().answer(200, {"sid": "SID-abcdef"}).answer(200, {"x": 1}).answer(200, {"message": "OK"})
    answer = runtime(found, wire).run("ping", {})
    assert [sent["url"].rsplit("/", 1)[1] for sent in wire.sent] == ["login", "show", "logout"]
    assert wire.sent[0]["json"] == {"user": "svc", "password": "s3cret-pass"} and "headers" not in wire.sent[0]
    assert wire.sent[1]["headers"]["X-chkp-sid"] == "SID-abcdef" == wire.sent[2]["headers"]["X-chkp-sid"]
    assert answer.outputs == {"response": {"x": 1}}
    # A failed command still logs out; a login without a token is said plainly.
    wire = Wire().answer(200, {"sid": "SID-abcdef"}).answer(500, {}).answer(200, {})
    with pytest.raises(rt.CommandError):
        runtime(found, wire).run("ping", {})
    assert wire.sent[-1]["url"].endswith("/logout")
    with pytest.raises(rt.CommandError) as caught:
        runtime(found, Wire().answer(200, {})).run("ping", {})
    assert caught.value.message == "Acme opened no session: the answer holds no token"


def test_pages_are_read_to_the_end_or_to_the_limit():
    offset = connector(
        """\
        - name: list
          request: { method: GET, path: /items, query: { q: open } }
          pagination: { type: offset, param: offset, limit_param: limit, limit: 2, items: "{{ response.result }}" }
          outputs: { items: "{{ response.items }}", pages: "{{ response.pages }}", cut: "{{ response.truncated }}" }
        """
    )
    wire = Wire().answer(200, {"result": [1, 2]}).answer(200, {"result": [3, 4]}).answer(200, {"result": [5]})
    assert runtime(offset, wire).run("list", {}).outputs == {"items": [1, 2, 3, 4, 5], "pages": 3, "cut": False}
    assert [sent["query"] for sent in wire.sent] == [
        {"q": "open", "limit": 2, "offset": 0},
        {"q": "open", "limit": 2, "offset": 2},
        {"q": "open", "limit": 2, "offset": 4},
    ]

    cursor = connector(
        """\
        - name: list
          request: { method: GET, path: /agents }
          pagination:
            type: cursor
            param: cursor
            items: "{{ response.data }}"
            next: "{{ response.pagination.nextCursor }}"
            max_pages: 2
          outputs: { items: "{{ response.items }}", cut: "{{ response.truncated }}" }
        """
    )
    wire = Wire().answer(200, {"data": ["a"], "pagination": {"nextCursor": "c1"}})
    wire.answer(200, {"data": ["b"], "pagination": {"nextCursor": "c2"}})
    # Two pages at most: the third is not asked for, and the result says it was cut.
    assert runtime(cursor, wire).run("list", {}).outputs == {"items": ["a", "b"], "cut": True}
    assert wire.sent[1]["query"] == {"cursor": "c1"}
    wire = Wire().answer(200, {"data": ["a"], "pagination": {"nextCursor": None}})
    assert runtime(cursor, wire).run("list", {}).outputs == {"items": ["a"], "cut": False}

    link = connector(
        """\
        - name: list
          request: { method: GET, path: /rows, query: { limit: 1 } }
          pagination: { type: link, items: "{{ response.result }}" }
          outputs: { items: "{{ response.items }}" }
        """
    )
    wire = Wire().answer(200, {"result": ["r1"]}, {"link": '<https://acme.example.com/api/rows?offset=1>;rel="next"'})
    wire.answer(200, {"result": ["r2"]}, {"link": '<https://acme.example.com/api/rows?offset=0>;rel="prev"'})
    assert runtime(link, wire).run("list", {}).outputs == {"items": ["r1", "r2"]}
    assert wire.sent[1]["url"] == "https://acme.example.com/api/rows?offset=1"
    # A "next" link that points elsewhere is not followed.
    wire = Wire().answer(200, {"result": ["r1"]}, {"link": '<https://evil.example.net/rows>; rel="next"'})
    with pytest.raises(rt.CommandError) as caught:
        runtime(link, wire).run("list", {})
    assert caught.value.message == "A request of this connector goes to evil.example.net, not to its instance"


PUBLISH = """\
- name: block-host
  changes_outside: true
  arguments:
    - { name: name, type: text, required: true }
    - { name: install, type: bool, default: false }
  steps:
    - name: add
      request: { method: POST, path: /add-host, json: { name: "{{ args.name }}" } }
    - name: publish
      request: { method: POST, path: /publish, json: {} }
    - name: published
      request: { method: POST, path: /show-task, json: { task-id: "{{ steps.publish.response['task-id'] }}" } }
      poll:
        until: { all: [{ left: "{{ response.tasks[0].status }}", op: ne, right: in progress }] }
        fail_when: { all: [{ left: "{{ response.tasks[0].status }}", op: eq, right: failed }] }
        every: 3
        timeout: 60
    - name: install
      when: { all: [{ left: "{{ args.install }}", op: eq, right: true }] }
      request: { method: POST, path: /install-policy, json: { policy-package: standard } }
  outputs:
    uid: "{{ steps.add.response.uid }}"
    task: "{{ steps.publish.response['task-id'] }}"
    installed: "{{ steps.install.status }}"
"""


def test_steps_feed_each_other_and_a_poll_gives_the_step_back_instead_of_waiting():
    found = connector(PUBLISH, SESSION)
    now = [1000.0]
    wire = Wire().answer(200, {"sid": "SID-abcdef"}).answer(200, {"uid": "u-1"}).answer(200, {"task-id": "t-9"})
    wire.answer(200, {"tasks": [{"status": "in progress"}]})
    first = runtime(found, wire, clock=lambda: now[0])
    waiting = first.run("block-host", {"name": "h1", "install": False})
    assert not waiting.done and waiting.again_at == 1003.0 and waiting.outputs is None
    assert wire.sent[3]["json"] == {"task-id": "t-9"}
    # The session stays open across the wait (no logout was sent) and travels in the state.
    assert not wire.sent[-1]["url"].endswith("/logout")
    assert waiting.state["index"] == 2 and waiting.state["session"] == {"X-chkp-sid": "SID-abcdef"}
    assert set(waiting.state["steps"]) == {"add", "publish"}

    # Called again later, by another Runtime: it goes on from the poll, with the same session.
    now[0] = 1003.0
    wire.answer(200, {"tasks": [{"status": "succeeded"}]}).answer(200, {"message": "OK"})
    done = runtime(found, wire, clock=lambda: now[0]).run("block-host", {"name": "h1", "install": False}, waiting.state)
    assert done.done and done.outputs == {"uid": "u-1", "task": "t-9", "installed": 0}  # install was skipped
    assert [sent["url"].rsplit("/", 1)[1] for sent in wire.sent[4:]] == ["show-task", "logout"]
    assert wire.sent[4]["headers"]["X-chkp-sid"] == "SID-abcdef"

    # The other side says it failed; or never finishes.
    wire = Wire().answer(200, {"tasks": [{"status": "failed"}]}).answer(200, {})
    with pytest.raises(rt.CommandError) as caught:
        runtime(found, wire, clock=lambda: now[0]).run("block-host", {"name": "h1"}, waiting.state)
    assert caught.value.message == "Acme says it failed" and wire.sent[-1]["url"].endswith("/logout")
    now[0] = 1000.0 + 61
    wire = Wire().answer(200, {"tasks": [{"status": "in progress"}]}).answer(200, {})
    with pytest.raises(rt.CommandError) as caught:
        runtime(found, wire, clock=lambda: now[0]).run("block-host", {"name": "h1"}, waiting.state)
    assert caught.value.message == "Acme did not finish in time"


def test_zscaler_signs_in_with_its_obfuscated_key_and_a_cookie():
    # The algorithm of Zscaler's own SDKs, on a fixed time.
    key, stamp = rt.zscaler_key("abcdefghijklmnopqrstuvwxyz", 1_700_000_123_456)
    assert stamp == "1700000123456" and key == "bcdefg" + "".join(
        "abcdefghijklmnopqrstuvwxyz"[int(d) + 2] for d in "061728"
    )
    with pytest.raises(rt.CommandError):
        rt.zscaler_key("short", 1_700_000_999_999)

    found = connector(
        "- name: status\n  request: { method: GET, path: /status }\n", "- { name: credentials, type: zscaler }"
    )
    wire = Wire().answer(
        200, {"authType": "ADMIN_LOGIN"}, {"set-cookie": "JSESSIONID=ABC123XYZ; Path=/; Secure; HttpOnly"}
    )
    wire.answer(200, {"status": "ACTIVE"}).answer(204, {})
    secrets = {"username": "admin@acme", "password": "pw-123456", "api_key": "abcdefghijklmnopqrstuvwxyz"}
    answer = runtime(found, wire, secrets=secrets, clock=lambda: 1_700_000_123.456).run("status", {})
    login, call, logout = wire.sent
    assert login["url"].endswith("/authenticatedSession") and login["json"]["apiKey"] == key
    assert login["json"]["timestamp"] == stamp and login["json"]["username"] == "admin@acme"
    assert call["headers"]["Cookie"] == "JSESSIONID=ABC123XYZ"
    assert (logout["method"], logout["headers"]) == ("DELETE", {"Cookie": "JSESSIONID=ABC123XYZ"})
    assert answer.outputs == {"response": {"status": "ACTIVE"}}


def test_the_test_of_a_connection_never_raises_and_a_dry_run_sends_nothing():
    found = connector(CREATE, extra="test:\n  request: { method: GET, path: /me }\n  expect: { status: 200 }\n")
    assert runtime(found, Wire().answer(200, {"name": "svc"})).test() == {
        "ok": True,
        "status": 200,
        "message": "Acme answered 200",
    }
    assert runtime(found, Wire().answer(401, {})).test() == {"ok": False, "status": 401, "message": "Acme answered 401"}
    refused = egress.EgressError("acme.example.com is not among the hosts this playbook may reach", refused=True)
    assert runtime(found, Wire().fail(refused)).test()["message"].startswith("acme.example.com is not among")

    wire = Wire()
    would = rt.Runtime(
        found,
        {"url": "https://93.184.215.14/api"},
        {},
        egress.Policy("listed", frozenset({"93.184.215.14"})),
        send=wire,
    )
    assert would.would_send("create-ticket", {"title": "x"}) == {
        "method": "POST",
        "host": "93.184.215.14",
        "path": "/api/tickets",
        "dry_run": True,
    }
    assert wire.sent == []


def test_a_dry_run_does_not_show_a_key_that_travels_in_the_address():
    found = connector(
        """\
        - name: download-export
          request: { path: "/exports/{{ secret.export_key }}/full.csv" }
        """,
        auth="- { name: export_key, type: secret }",
    )
    would = rt.Runtime(
        found,
        {"url": "https://93.184.215.14/api"},
        {"export_key": "key-in-the-address-1234"},
        egress.Policy("listed", frozenset({"93.184.215.14"})),
        send=Wire(),
    )
    assert would.would_send("download-export", {})["path"] == f"/api/exports/{rt.REDACTED}/full.csv"


def test_a_multipart_body_is_built_for_the_apis_that_want_one():
    found = connector(
        """        - name: put-file
          arguments:
            - { name: content, type: text }
            - { name: message, type: text }
            - { name: commit, type: text }
          request:
            method: PUT
            path: /browse/list.txt
            multipart:
              content: "{{ args.content }}"
              message: "{{ args.message }}"
              branch: main
              sourceCommitId: "{{ args.commit | default(null) }}"
        """
    )
    wire = Wire().answer(200, {"id": "c0ffee"})
    runtime(found, wire).run("put-file", {"content": "1.2.3.4\n5.6.7.8", "message": "block"})
    sent = wire.sent[0]
    boundary = sent["headers"]["Content-Type"].split("boundary=")[1]
    body = sent["body"].decode()
    assert body.count(f"--{boundary}") == 4 and body.endswith(
        f"--{boundary}--\r\n"
    )  # three fields: the empty one is left out
    assert 'name="content"\r\n\r\n1.2.3.4\n5.6.7.8\r\n' in body and 'name="branch"\r\n\r\nmain\r\n' in body


def test_an_answer_read_as_text_is_never_taken_for_json():
    found = connector(
        """        - name: get-file
          request: { method: GET, path: /raw/list.json, answer: text }
          error: { message: "{{ response.text }}" }
          outputs:
            content: "{{ response.text }}"
        - name: get-any
          request: { method: GET, path: /raw/list.json }
          outputs:
            content: "{{ response.text }}"
            first: "{{ response[0] }}"
        """
    )
    names = ["evil.example", "worse.example"]
    listed = json.dumps(names)
    # A file that is JSON, served as JSON, is still the file.
    wire = Wire().answer(200, names).answer(200, names).answer(404, {"error": "no such file"})
    assert runtime(found, wire).run("get-file", {}).outputs == {"content": listed}
    assert runtime(found, wire).run("get-any", {}).outputs == {"content": None, "first": "evil.example"}
    with pytest.raises(rt.CommandError) as refused:
        runtime(found, wire).run("get-file", {})
    assert refused.value.message == 'Acme answered 404: {"error": "no such file"}'
    with pytest.raises(cn.ConnectorError) as wrong:
        connector("        - name: x\n          request: { method: GET, path: /x, answer: xml }\n")
    assert any("answer" in str(problem.where) or "answer" in problem.message for problem in wrong.value.problems)


# --------------------------------------------------------------------------- #
# The two samples of the documentation                                        #
# --------------------------------------------------------------------------- #
SAMPLES = __import__("pathlib").Path(__file__).parent / "data" / "connector_samples"


def test_the_basic_sample_of_the_documentation_is_a_connector_that_works():
    found = cn.load((SAMPLES / "acme-desk.yml").read_text(encoding="utf-8"))
    assert (found.id, found.auth.type, [command.name for command in found.commands]) == (
        "acme-desk",
        "basic",
        ["create-ticket", "get-ticket", "add-comment"],
    )
    policy = egress.Policy(mode="listed", hosts=frozenset({"desk.example.org"}))
    wire = Wire().answer(201, {"number": "T-1042"}).answer(200, {"state": "open", "assignee": {"name": "Anna"}})
    config, secrets = {"url": "https://desk.example.org", "queue": "SOC"}, {"username": "nik", "password": "pw-123456"}
    desk = rt.Runtime(found, config, secrets, policy, send=wire, clock=lambda: 1000.0)
    made = desk.run("create-ticket", {"title": "Phishing", "text": None, "priority": "high"})
    assert made.outputs == {"number": "T-1042", "url": "https://desk.example.org/tickets/T-1042"}
    sent = wire.sent[0]
    assert (sent["method"], sent["url"]) == ("POST", "https://desk.example.org/api/v2/tickets")
    assert sent["json"] == {"queue": "SOC", "title": "Phishing", "priority": "high"}  # the empty text is left out
    assert sent["headers"]["Accept"] == "application/json"
    assert sent["headers"]["Authorization"] == "Basic " + base64.b64encode(b"nik:pw-123456").decode()
    read = rt.Runtime(found, config, secrets, policy, send=wire, clock=lambda: 1000.0).run(
        "get-ticket", {"number": "T-1042"}
    )
    assert read.outputs == {"state": "open", "assignee": "Anna"}


def test_the_oauth_sample_of_the_documentation_pages_and_polls():
    found = cn.load((SAMPLES / "acme-edr.yml").read_text(encoding="utf-8"))
    assert found.auth.type == "oauth2_client" and found.command("list-alerts").pagination.type == "cursor"
    policy = egress.Policy(mode="listed", hosts=frozenset({"api.edr.example.com"}))
    config, secrets = {"url": "https://api.edr.example.com"}, {"client_id": "nik", "client_secret": "cs-123456"}
    now = [1000.0]

    def edr(wire):
        return rt.Runtime(found, config, secrets, policy, send=wire, clock=lambda: now[0])

    rt.forget_tokens()
    wire = Wire().answer(200, {"access_token": "AT-9-secret", "expires_in": 3600})
    wire.answer(200, {"alerts": [{"id": 1}, {"id": 2}], "next_cursor": "c2"}).answer(200, {"alerts": [{"id": 3}]})
    listed = edr(wire).run("list-alerts", {"since": "2026-11-01", "severity": ""})
    assert listed.outputs == {"alerts": [{"id": 1}, {"id": 2}, {"id": 3}], "count": 3, "truncated": False}
    token, first, second = wire.sent
    assert token["url"] == "https://api.edr.example.com/oauth/token"
    assert token["headers"]["Authorization"] == "Basic " + base64.b64encode(b"nik:cs-123456").decode()
    assert token["form"] == {"grant_type": "client_credentials", "scope": "alerts:read hosts:write"}
    assert first["headers"]["Authorization"] == "Bearer AT-9-secret"
    assert first["query"] == {"since": "2026-11-01", "limit": 200}  # the empty severity is not sent
    assert second["query"] == {"since": "2026-11-01", "limit": 200, "cursor": "c2"}

    # Two requests; the second is asked again later, without waiting here.
    wire = Wire().answer(202, {"job_id": "j-7"}).answer(200, {"state": "running"})
    waiting = edr(wire).run("isolate-host", {"host_id": "h-1"})
    assert not waiting.done and waiting.again_at == 1010.0
    now[0] = 1010.0
    wire = Wire().answer(200, {"state": "finished"})
    done = edr(wire).run("isolate-host", {"host_id": "h-1"}, waiting.state)
    assert done.done and done.outputs == {"job": "j-7", "state": "finished"}
    rt.forget_tokens()


def test_a_connector_reaches_the_other_hosts_it_lists_and_keeps_its_credentials_home():
    found = connector(
        """\
        - name: fetch
          arguments: [{ name: where, type: text }]
          request: { method: GET, path: "{{ args.where }}" }
        """,
        extra="more_hosts: [open.acme.example.org]\n",
    )
    wire = Wire().answer(200, {"ok": 1}).answer(200, {"ok": 2})
    assert runtime(found, wire).run("fetch", {"where": "https://open.acme.example.org/1.2.3.4"}).outputs
    assert runtime(found, wire).run("fetch", {"where": "https://acme.example.com/api/me"}).outputs
    # The credentials of the instance go to its own host, and to no other.
    assert "Authorization" not in (wire.sent[0].get("headers") or {})
    assert wire.sent[1]["headers"]["Authorization"].startswith("Basic ")
    # Only by name, over https, on the usual port; and only the hosts that are listed.
    for where in (
        "http://open.acme.example.org/x",
        "https://open.acme.example.org:8443/x",
        "https://evil.example.net/x",
        "https://sub.open.acme.example.org/x",
    ):
        with pytest.raises(rt.CommandError):
            runtime(found, Wire()).run("fetch", {"where": where})
    # What a file may list: names, never an address, a port or a template.
    for wrong in ("10.0.0.1", "host", "Open.Example.org", "a.example.org:8443", "{{ config.url }}", "a.example.org/x"):
        with pytest.raises(cn.ConnectorError):
            connector("- name: x\n  request: { method: GET, path: / }\n", extra=f'more_hosts: ["{wrong}"]\n')
    assert cn.summary(found)["moreHosts"] == ["open.acme.example.org"]


# --------------------------------------------------------------------------- #
# Files: an answer that is one, a request that sends one                      #
# --------------------------------------------------------------------------- #
class Shelf:
    """Stands in for the store of a run (connector_files.Store): what was kept, what it holds, what the guard says."""

    limit_mb = 1
    limit = 1024 * 1024

    def __init__(self, **files: bytes):
        self.files = {hashlib.sha256(data).hexdigest(): (name, data) for name, data in files.items()}
        self.kept: list[tuple[bytes, str, str]] = []
        self.judged: list[list[dict]] = []
        self.read_out: list[str] = []
        self.verdict: bool | Exception = True

    def sha(self, name: str) -> str:
        return next(sha for sha, (held, _data) in self.files.items() if held == name)

    def keep(self, data: bytes, name: str, kind: str) -> dict:
        self.kept.append((data, name, kind))
        sha = hashlib.sha256(data).hexdigest()
        return {"name": name or sha, "type": kind, "size": len(data), "sha256": sha, "artifact": f"file-{sha}",
                "linked": True}  # fmt: skip

    def describe(self, wanted) -> dict:
        sha = str(wanted).removeprefix("file-")
        if sha not in self.files:
            raise rt.CommandError(f"The file {sha[:12]}… is not in the store")
        name, data = self.files[sha]
        return {"name": name, "size": len(data), "sha256": sha}

    def judge(self, found: list[dict]) -> bool:
        self.judged.append(found)
        if isinstance(self.verdict, Exception):
            raise self.verdict
        return self.verdict

    def read(self, sha: str) -> bytes:
        self.read_out.append(sha)
        return self.files[sha][1]


def binary(wire: Wire, data: bytes, status: int = 200, **headers) -> Wire:
    head = {
        "content-type": "application/octet-stream",
        **{key.replace("_", "-"): value for key, value in headers.items()},
    }
    wire.answers.append(egress.Response(status=status, headers=head, body=data, record={}))
    return wire


DOWNLOAD = """\
- name: download
  arguments: [{ name: hash, type: text, required: true }]
  request: { method: GET, path: "/files/{{ args.hash }}/download", answer: file }
  error: { message: "{{ response.error.message }}" }
- name: screenshot
  arguments: [{ name: uuid, type: text, required: true }]
  request:
    method: GET
    path: "/screenshots/{{ args.uuid }}.png"
    answer: file
    save_as: { name: "screenshot-{{ args.uuid }}.png", type: image/png }
  outputs:
    picture: "{{ response.artifact }}"
    bytes: "{{ response.size }}"
    about: "{{ response.name }} of {{ args.uuid }}"
- name: export
  arguments: [{ name: query, type: text, required: true }]
  steps:
    - name: ask
      request: { method: POST, path: /exports, json: { q: "{{ args.query }}" } }
    - name: fetch
      request: { method: GET, path: "/exports/{{ steps.ask.response.id }}", answer: file }
  outputs: { artifact: "{{ steps.fetch.response.artifact }}", id: "{{ steps.ask.response.id }}" }
- name: get-zip
  arguments: [{ name: hash, type: text, required: true }]
  request: { method: POST, path: /v1/, form: { query: get_file, hash: "{{ args.hash }}" }, answer: file }
  success: { when: { all: [{ left: "{{ headers['content-type'] }}", op: ne, right: application/json }] } }
  error: { message: "{{ response.query_status }}" }
"""


def test_an_answer_that_is_a_file_is_kept_and_described_never_read():
    found = connector(DOWNLOAD)
    malware = b"MZ\x90\x00\xff\xfe not text at all \x00\x01"
    wire = binary(Wire(), malware, content_disposition='attachment; filename="invoice.exe"')
    shelf = Shelf()
    live = runtime(found, wire)
    live.store = shelf
    answer = live.run("download", {"hash": "abc"})
    sha = hashlib.sha256(malware).hexdigest()
    # The bytes went to the store as they came, under the name the answer gave; the outputs describe the file.
    assert shelf.kept == [(malware, "invoice.exe", "application/octet-stream")]
    assert answer.outputs == {
        "name": "invoice.exe",
        "type": "application/octet-stream",
        "size": len(malware),
        "sha256": sha,
        "artifact": f"file-{sha}",
        "linked": True,
    }
    assert answer.classes == {"name": ["attachment_name"], "sha256": ["hash"], "artifact": ["nik_id"]}
    # The answer was allowed to be as large as an upload, and no larger.
    assert wire.sent[0]["max_body"] == shelf.limit and wire.sent[0]["url"].endswith("/files/abc/download")
    assert malware.decode("latin-1") not in json.dumps(answer.outputs)

    # The name and the type may be said by the file; the outputs read what describes the file, with its classes.
    wire = binary(Wire(), b"\x89PNG\r\n", content_type="application/octet-stream")
    live = runtime(found, wire)
    live.store = shelf = Shelf()
    answer = live.run("screenshot", {"uuid": "u-1"})
    assert shelf.kept == [(b"\x89PNG\r\n", "screenshot-u-1.png", "image/png")]
    assert answer.outputs["bytes"] == 6 and answer.outputs["picture"].startswith("file-")
    assert answer.outputs["about"] == "screenshot-u-1.png of u-1"
    assert answer.classes == {"picture": ["nik_id"], "about": ["attachment_name"]}

    # Without a name in the answer, the last part of the address is the name; a path in a name is never kept.
    wire = binary(Wire(), b"zip", content_disposition="attachment; filename*=UTF-8''..%2F..%2Fetc%2Fsample%20one.zip")
    live = runtime(found, wire)
    live.store = shelf = Shelf()
    assert live.run("download", {"hash": "abc"}).outputs["name"] == "sample one.zip"
    wire = binary(Wire(), b"zip")
    live = runtime(found, wire)
    live.store = shelf = Shelf()
    assert live.run("download", {"hash": "abc"}).outputs["name"] == "download"

    # A step may be the one that fetches the file: the outputs read it as they read any step.
    wire = binary(Wire().answer(body={"id": "e-7"}), b"PK\x03\x04")
    live = runtime(found, wire)
    live.store = shelf = Shelf()
    answer = live.run("export", {"query": "x"})
    assert answer.outputs == {"artifact": f"file-{hashlib.sha256(b'PK' + bytes([3, 4])).hexdigest()}", "id": "e-7"}
    assert answer.classes == {"artifact": ["nik_id"]} and len(shelf.kept) == 1


def test_a_file_that_cannot_be_kept_says_why_and_nothing_is_stored(monkeypatch):
    monkeypatch.setattr(egress, "resolve", lambda host, port: ["93.184.215.10"])  # a dry run names the host
    found = connector(DOWNLOAD)
    # The other side refuses: its answer is read as any answer is, so that the error can quote it.
    wire = Wire().answer(404, {"error": {"message": "no such file"}})
    live = runtime(found, wire)
    live.store = shelf = Shelf()
    with pytest.raises(rt.CommandError) as caught:
        live.run("download", {"hash": "abc"})
    assert caught.value.message == "Acme answered 404: no such file" and shelf.kept == []
    # Larger than an upload may be: the egress client stops reading, and the sentence names the limit.
    too_large = egress.EgressError("The answer is larger than 1 MB", sent=True)
    too_large.too_large = True
    live = runtime(found, Wire().fail(too_large))
    live.store = shelf = Shelf()
    with pytest.raises(rt.CommandError) as caught:
        live.run("download", {"hash": "abc"})
    assert caught.value.message == "The file is larger than the 1 MB limit of a sample: it was not kept"
    assert shelf.kept == []
    # An API that answers 200 and an error where the file should be: what came with the answer tells them
    # apart ("success.when"), the error is quoted, and the error is not kept as if it were the file.
    live = runtime(found, Wire().answer(200, {"query_status": "file_not_found"}))
    live.store = shelf = Shelf()
    with pytest.raises(rt.CommandError) as caught:
        live.run("get-zip", {"hash": "abc"})
    assert caught.value.message == "Acme answered 200: file_not_found" and shelf.kept == []
    live = runtime(found, binary(Wire(), b"PK", content_type="application/zip"))
    live.store = shelf = Shelf()
    assert live.run("get-zip", {"hash": "abc"}).outputs["type"] == "application/zip" and len(shelf.kept) == 1
    # An empty answer is not a file.
    live = runtime(found, binary(Wire(), b""))
    live.store = shelf = Shelf()
    with pytest.raises(rt.CommandError, match="an empty file"):
        live.run("download", {"hash": "abc"})
    # Where there is no store (a test of the connection, a fetch), nothing is asked for at all.
    wire = Wire()
    with pytest.raises(rt.CommandError, match="runs from a playbook"):
        runtime(found, wire).run("download", {"hash": "abc"})
    assert wire.sent == []
    # A dry run asks for nothing and keeps nothing: it says what the command would do.
    live = runtime(found, wire)
    live.store = shelf = Shelf()
    would = live.would_send("download", {"hash": "abc"})
    assert (would["method"], would["path"], would["keeps"]) == (
        "GET",
        "/api/files/abc/download",
        "a file, as an artifact",
    )
    assert wire.sent == [] and shelf.kept == []


UPLOAD = """\
- name: submit
  changes_outside: true
  arguments:
    - { name: sample, type: file, required: true }
    - { name: password, type: text }
    - { name: as_name, type: text }
  request:
    method: POST
    path: /files
    multipart: { password: "{{ args.password }}", note: from Nik }
    files:
      file: { artifact: "{{ args.sample }}", name: "{{ args.as_name | default('') }}", type: application/x-dosexec }
  outputs: { id: "{{ response.data.id }}" }
  sample: { id: analysis-0 }
- name: put-raw
  changes_outside: true
  arguments: [{ name: sample, type: file, required: true }]
  request:
    method: PUT
    path: "/blobs/{{ args.sample }}"
    body_file: { artifact: "{{ args.sample }}" }
  sample: { response: {} }
"""


def test_a_file_is_sent_as_a_part_of_a_form_or_as_the_body_once_the_guard_let_it():
    found = connector(UPLOAD)
    malware = bytes(range(256)) + b"\r\n--not-a-boundary\r\n"
    shelf = Shelf(**{"invoice.exe": malware})
    sha = shelf.sha("invoice.exe")
    wire = Wire().answer(body={"data": {"id": "a-1"}})
    live = runtime(found, wire)
    live.store = shelf
    answer = live.run("submit", {"sample": f"file-{sha}", "password": "infected"})
    assert answer.outputs == {"id": "a-1"}
    # The guard was asked about the file before anything left, by what it is: its name, its size, its hash.
    assert shelf.judged == [[{"name": "invoice.exe", "size": len(malware), "sha256": sha}]] and shelf.read_out == [sha]
    sent = wire.sent[0]
    boundary = sent["headers"]["Content-Type"].split("boundary=")[1]
    assert sent["headers"]["Content-Type"].startswith("multipart/form-data; boundary=nik")
    body = sent["body"]
    assert isinstance(body, bytes) and body.endswith(f"--{boundary}--\r\n".encode())
    assert b'Content-Disposition: form-data; name="password"\r\n\r\ninfected\r\n' in body
    assert b'Content-Disposition: form-data; name="note"\r\n\r\nfrom Nik\r\n' in body
    head = b'Content-Disposition: form-data; name="file"; filename="invoice.exe"\r\n'
    head += b"Content-Type: application/x-dosexec\r\n\r\n"
    # The bytes of the file are in the body exactly as the store holds them.
    assert head + malware + b"\r\n" in body
    # What the step records names the file, never its content.
    assert answer.records[-1]["files"] == [{"name": "invoice.exe", "size": len(malware), "sha256": sha}]

    # The SHA-256 alone names the file too, and the file may be sent under another name; an argument
    # left empty is not a field of the form.
    wire = Wire().answer(body={"data": {"id": "a-2"}})
    live = runtime(found, wire)
    live.store = shelf
    live.run("submit", {"sample": sha, "as_name": '../we"ird\r\n.bin'})
    assert b'filename="we%22ird .bin"' in wire.sent[0]["body"] and b'name="password"' not in wire.sent[0]["body"]
    assert shelf.judged[-1][0]["name"] == 'we"ird .bin'

    # As the body itself: the bytes, and the type the file says.
    wire = Wire().answer(body={})
    live = runtime(found, wire)
    live.store = shelf
    live.run("put-raw", {"sample": sha})
    assert wire.sent[0]["body"] == malware and wire.sent[0]["method"] == "PUT"
    assert wire.sent[0]["headers"]["Content-Type"] == "application/octet-stream"
    assert wire.sent[0]["url"].endswith(f"/blobs/{sha}")


def test_a_file_that_is_held_or_not_in_the_store_is_never_sent(monkeypatch):
    monkeypatch.setattr(egress, "resolve", lambda host, port: ["93.184.215.10"])  # a dry run names the host
    found = connector(UPLOAD)
    shelf = Shelf(**{"invoice.exe": b"MZ"})
    sha = shelf.sha("invoice.exe")

    def attempt(args, verdict=True):
        wire = Wire().answer(body={"data": {"id": "a-1"}})
        live = runtime(found, wire)
        live.store = shelf
        shelf.verdict = verdict
        return live, wire

    # The guard holds it and the node fails: what the guard raised goes up as it is, and nothing left.
    held = RuntimeError("Held back: attachments")
    live, wire = attempt({}, held)
    with pytest.raises(RuntimeError, match="Held back"):
        live.run("submit", {"sample": sha})
    assert wire.sent == [] and shelf.read_out == []
    # On a node that drops what is held the command is not sent at all: it is nothing without its file.
    live, wire = attempt({}, False)
    with pytest.raises(rt.NotSent, match="held back by the data guard"):
        live.run("submit", {"sample": sha})
    assert wire.sent == [] and shelf.read_out == []
    # The argument itself was held back (or left empty): the same.
    live, wire = attempt({})
    with pytest.raises(rt.NotSent, match="was not given, or was held back"):
        live.run("submit", {"sample": None})
    assert wire.sent == []
    # Not a file of the store: refused before the guard is even asked.
    live, wire = attempt({})
    before = len(shelf.judged)
    with pytest.raises(rt.CommandError, match="is not in the store"):
        live.run("submit", {"sample": "f" * 64})
    assert wire.sent == [] and len(shelf.judged) == before
    # No store: a command that sends a file does not run.
    wire = Wire()
    with pytest.raises(rt.CommandError, match="runs from a playbook"):
        runtime(found, wire).run("submit", {"sample": sha})
    # A dry run sends nothing and shows the file in place of its bytes; the guard is asked as it would be.
    live, wire = attempt({})
    would = live.would_send("submit", {"sample": sha})
    assert would["files"] == [
        {"field": "file", "name": "invoice.exe", "type": "application/x-dosexec", "size": 2, "sha256": sha}
    ]
    assert wire.sent == [] and shelf.read_out == [] and shelf.judged[-1][0]["sha256"] == sha


def test_a_connector_file_says_how_files_travel_and_is_refused_when_it_cannot_be():
    def problems(commands: str, extra: str = "") -> list[str]:
        with pytest.raises(cn.ConnectorError) as caught:
            connector(commands, extra=extra)
        return [problem.message for problem in caught.value.problems]

    upload = """\
    - name: submit
      arguments: [{ name: sample, type: file }]
      request: { method: POST, path: /files, files: { file: { artifact: "{{ args.sample }}" } } }
    """
    # Sending a file changes the outside: the command must say so, so that it asks for approval.
    assert any("changes_outside: true" in message for message in problems(upload))
    assert (
        connector(upload.replace("- name: submit", "- name: submit\n      changes_outside: true"))
        .command("submit")
        .sends_file
    )
    wrong = {
        'files: { file: { artifact: "abc" } }': '"artifact" is a template that gives the file',
        "files: {}": '"files" is empty',
        'files: { f: { artifact: "{{ args.sample }}" } }, json: {}': "beside them, only",
        'body_file: { artifact: "{{ args.sample }}" }, body: "x"': "a request has one of",
        'files: { f: { artifact: "{{ args.sample }}", path: "x" } }': '"path" is not a key that is known here',
    }
    for request, said in wrong.items():
        text = upload.replace('files: { file: { artifact: "{{ args.sample }}" } }', request)
        text = text.replace("- name: submit", "- name: submit\n      changes_outside: true")
        assert any(said in message for message in problems(text)), request
    # A request asked again and again does not carry a file; "save_as" belongs to an answer that is one.
    polled = """\
    - name: fetch
      request: { method: GET, path: /file, answer: file }
      poll: { until: { all: [{ left: "{{ status }}", op: eq, right: 200 }] } }
    """
    assert any("it is not polled nor paged" in message for message in problems(polled))
    assert any(
        '"save_as" belongs to' in message
        for message in problems('- name: aa\n  request: { method: GET, path: /a, save_as: { name: "x" } }\n')
    )
    # What a file is called cannot read the answer itself, which is the file; it may read what came with it.
    named = '- name: aa\n  request: { method: GET, path: /a, answer: file, save_as: { name: "{{ %s }}" } }\n'
    assert any('"response" cannot be read' in message for message in problems(named % "response.name"))
    assert connector(named % "headers['x-file-name'] | default(args.x)" + "  arguments: [{ name: x }]\n")
    # Only a command carries a file: not the test of the connection.
    assert any(
        "Only a command keeps a file or sends one" in message
        for message in problems(
            "- name: aa\n  request: { method: GET, path: /a }\n",
            extra="test:\n  request: { method: GET, path: /me, answer: file }\n",
        )
    )
    # A file argument has no default, and GET and HEAD have no body.
    assert any(
        "has no default" in message
        for message in problems(
            "- name: aa\n  arguments: [{ name: f, type: file, default: x }]\n  request: { path: /a }\n"
        )
    )
    assert any(
        "a HEAD request has no body" in message
        for message in problems("- name: aa\n  request: { method: HEAD, path: /a, json: {} }\n")
    )


# --------------------------------------------------------------------------- #
# The smaller things a connector can say since 6.5                            #
# --------------------------------------------------------------------------- #
def test_a_key_that_is_optional_is_not_sent_empty_and_one_may_go_in_the_address():
    read = "- name: read\n  request: { method: GET, path: /thing, query: { verbose: true, deep: false, n: 3 } }\n"
    header = "- { name: credentials, type: header, header: X-Api-Key }"
    wire = Wire().answer().answer()
    runtime(connector(read, auth=header), wire, secrets={}).run("read", {})
    assert "X-Api-Key" not in wire.sent[0].get("headers", {})
    runtime(connector(read, auth=header), wire, secrets={"value": "k-123456"}).run("read", {})
    assert wire.sent[1]["headers"]["X-Api-Key"] == "k-123456"
    # The header a key goes in is named to the egress client, so that it does not follow a redirect elsewhere.
    assert wire.sent[1]["secret_headers"] == ("X-Api-Key",) and "secret_headers" not in wire.sent[0]
    # Yes and no go in an address as true and false.
    assert wire.sent[0]["query"] == {"verbose": "true", "deep": "false", "n": 3}
    bearer = "- { name: credentials, type: bearer }"
    wire = Wire().answer()
    runtime(connector(read, auth=bearer), wire, secrets={}).run("read", {})
    assert "Authorization" not in wire.sent[0].get("headers", {})

    # A key that goes in the address: said once, added to every request to the instance, never recorded.
    query = "- { name: credentials, type: query, param: key }"
    found = connector(read, auth=query, extra="more_hosts: [other.example.com]\n")
    wire = Wire().answer()
    answer = runtime(found, wire, secrets={"value": "k-123456"}).run("read", {})
    assert wire.sent[0]["query"] == {"verbose": "true", "deep": "false", "n": 3, "key": "k-123456"}
    assert "k-123456" not in json.dumps(answer.records) and "k-123456" not in json.dumps(answer.outputs)
    # Without a key the parameter is not sent; and another host the connector lists never gets it.
    wire = Wire().answer()
    runtime(found, wire, secrets={}).run("read", {})
    assert "key" not in wire.sent[0]["query"]
    elsewhere = connector(
        "- name: read\n  request: { method: GET, path: https://other.example.com/x }\n",
        auth=query,
        extra="more_hosts: [other.example.com]\n",
    )
    wire = Wire().answer()
    runtime(elsewhere, wire, secrets={"value": "k-123456"}).run("read", {})
    assert "query" not in wire.sent[0]
    with pytest.raises(cn.ConnectorError, match='"query" credentials need "param"'):
        connector(read, auth="- { name: credentials, type: query }")
    with pytest.raises(cn.ConnectorError, match='"param" belongs to "query" credentials'):
        connector(read, auth="- { name: credentials, type: header, header: X, param: key }")


def test_pages_may_be_sized_by_an_argument_and_keep_what_the_first_page_says():
    found = connector(
        """\
        - name: search
          arguments:
            - { name: per_page, type: number, default: 2 }
            - { name: pages, type: number, default_from: pages }
          request: { method: GET, path: /search }
          pagination:
            type: page
            param: page
            limit_param: size
            limit: "{{ args.per_page }}"
            max_pages: "{{ args.pages }}"
            items: "{{ response.results }}"
            keep: { total: "{{ response.total }}", took: "{{ response.took }}", absent: "{{ response.nope }}" }
          outputs:
            items: "{{ response.items }}"
            total: "{{ response.kept.total }}"
            pages: "{{ response.pages }}"
            more: "{{ response.truncated }}"
        """,
        auth="- { name: credentials, type: basic }\n- { name: pages, type: number, default: 2 }",
    )
    wire = (
        Wire()
        .answer(body={"results": [1, 2], "total": 9, "took": 3})
        .answer(body={"results": [3, 4], "total": 9, "took": 1})
    )
    answer = runtime(found, wire).run("search", {})
    # The size of a page is the argument's, the number of pages the one the instance says (default_from).
    assert [sent["query"] for sent in wire.sent] == [{"size": 2, "page": 1}, {"size": 2, "page": 2}]
    assert answer.outputs == {"items": [1, 2, 3, 4], "total": 9, "pages": 2, "more": True}
    # Whatever is asked, the bounds of a connector file hold: 1 000 items a page, 100 pages.
    wire = Wire().answer(body={"results": [1], "total": 1})
    runtime(found, wire).run("search", {"per_page": 50_000, "pages": 100_000})
    assert wire.sent[0]["query"]["size"] == 1000
    wire = Wire().answer(body={"results": [], "total": 0})
    with pytest.raises(rt.CommandError, match='The "limit" of the pagination is not a number'):
        runtime(found, wire).run("search", {"per_page": "many"})
    with pytest.raises(cn.ConnectorError, match='"limit" is a number from 1 to 1000'):
        connector(
            "- name: ss\n  request: { path: /s }\n  pagination: { type: page, param: p, items: x, limit: 5000 }\n"
        )
    with pytest.raises(cn.ConnectorError, match="is not a plain value of the configuration"):
        connector("- name: ss\n  arguments: [{ name: a, default_from: nope }]\n  request: { path: /s }\n")


def test_a_poll_waits_as_long_as_the_other_side_asks_and_head_reads_only_headers():
    found = connector(
        """\
        - name: wait
          request: { method: GET, path: /job }
          poll:
            until: { all: [{ left: "{{ response.state }}", op: eq, right: done }] }
            every: 5
            timeout: 3600
          outputs: { state: "{{ response.state }}" }
        - name: exists
          arguments: [{ name: id, type: text, required: true }]
          request: { method: HEAD, path: "/things/{{ args.id }}" }
          success: { status: [200, 404] }
          outputs:
            exists: "{{ status == 200 }}"
            size: "{{ headers['content-length'] | default(0) | int }}"
            asked: "{{ now.iso }}"
            age_days: "{{ now.epoch | date_diff(headers['last-modified-iso'] | default(now.iso), 'days') }}"
        """
    )
    clock = [1000.0]

    def asked(**headers) -> float:
        wire = Wire().answer(body={"state": "running"}, headers=headers)
        return runtime(found, wire, clock=lambda: clock[0]).run("wait", {}).again_at - clock[0]

    assert asked() == 5
    assert asked(**{"retry-after": "30"}) == 30
    assert asked(**{"retry-after": "2"}) == 5  # never sooner than the file says
    assert asked(**{"retry-after": "86400"}) == rt.RETRY_AFTER_MAX
    assert asked(**{"retry-after": "Thu, 01 Jan 1970 00:17:40 GMT"}) == 60  # a date: 1060 on this clock
    assert asked(**{"retry-after": "soon"}) == 5

    wire = Wire().answer(headers={"content-length": "512", "last-modified-iso": "1970-01-01T00:00:00Z"})
    answer = runtime(found, wire, clock=lambda: 86_400.0 * 3 + 5).run("exists", {"id": "x"})
    assert wire.sent[0]["method"] == "HEAD" and "body" not in wire.sent[0]
    # The clock of the engine is what "now" is: the same run gives the same answer.
    assert answer.outputs == {"exists": True, "size": 512, "asked": "1970-01-04T00:00:05Z", "age_days": 3}
    wire = Wire().answer(404)
    assert runtime(found, wire).run("exists", {"id": "x"}).outputs["exists"] is False
