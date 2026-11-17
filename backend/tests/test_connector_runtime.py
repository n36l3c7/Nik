"""Running connector commands against recorded answers: requests, credentials, pages, steps, polls."""

from __future__ import annotations

import base64
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
    assert caught.value.message == "A request of this connector goes to evil.example.net, not to its connection"
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
    assert caught.value.message == "A request of this connector goes to evil.example.net, not to its connection"


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
