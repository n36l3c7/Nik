"""Connector files: reading, validation with the line of each problem."""

from __future__ import annotations

import textwrap

import pytest

from app.automation import connectors as cn

GOOD = textwrap.dedent(
    """\
    name: ServiceNow
    id: servicenow
    version: 1
    description: Incidents and comments in ServiceNow.
    api_version: Table API, release Australia
    configuration:
      - name: url
        label: Instance address
        type: url
        required: true
      - name: credentials
        type: basic
    base_url: "{{ config.url }}"
    headers:
      Accept: application/json
    test:
      request: { method: GET, path: /api/now/table/incident, query: { sysparm_limit: 1 } }
      expect: { status: 200 }
    commands:
      - name: create-incident
        description: Open an incident.
        changes_outside: true
        idempotent: false
        arguments:
          - { name: short_description, type: text, required: true }
          - { name: urgency, type: choice, choices: ["1", "2", "3"], default: "3" }
        request:
          method: POST
          path: /api/now/table/incident
          json:
            short_description: "{{ args.short_description }}"
            urgency: "{{ args.urgency }}"
        success: { status: [200, 201] }
        error: { message: "{{ response.error.message }}" }
        outputs:
          number: "{{ response.result.number }}"
          url: "{{ config.url }}/nav_to.do?uri=incident.do?sys_id={{ response.result.sys_id }}"
        sample: { number: INC0000001, url: "https://example.service-now.com/x" }
      - name: list-incidents
        arguments: [{ name: query, type: text }]
        request:
          method: GET
          path: /api/now/table/incident
          query: { sysparm_query: "{{ args.query | default('') }}" }
        pagination:
          type: offset
          param: sysparm_offset
          limit_param: sysparm_limit
          limit: 100
          items: "{{ response.result }}"
        outputs: { incidents: "{{ response.items }}" }
    """
)


def problems(text: str) -> list[tuple[int, str]]:
    with pytest.raises(cn.ConnectorError) as caught:
        cn.load(text)
    return [(problem.line, problem.message) for problem in caught.value.problems]


def test_a_connector_file_is_read_into_its_parts():
    connector = cn.load(GOOD)
    assert (connector.id, connector.name, connector.version) == ("servicenow", "ServiceNow", 1)
    assert connector.auth.type == "basic" and connector.auth.name == "credentials"
    create = connector.command("create-incident")
    assert create.changes_outside and not create.idempotent
    assert create.request.method == "POST" and create.request.json_body["urgency"] == "{{ args.urgency }}"
    assert create.success.statuses() == {200, 201}
    assert connector.command("list-incidents").pagination.type == "offset"
    assert connector.command("nope") is None
    shown = cn.summary(connector)
    assert [command["name"] for command in shown["commands"]] == ["create-incident", "list-incidents"]
    assert shown["commands"][0]["outputs"] == ["number", "url"] and shown["commands"][0]["changesOutside"] is True
    assert shown["configuration"][0] == {
        "name": "url",
        "label": "Instance address",
        "type": "url",
        "required": True,
        "default": None,
        "choices": [],
        "help": "",
    }
    assert shown["configuration"][1]["label"] == "Credentials"
    assert cn.load(GOOD.encode()).id == "servicenow"


def test_a_file_that_is_not_a_connector_says_why():
    assert problems("- just\n- a list\n") == [(1, "A connector is a mapping: name, id, version, base_url, commands")]
    assert problems("name: [unclosed\n")[0][1].startswith("Not valid YAML: ")
    assert problems("x" * (cn.MAX_BYTES + 1)) == [(0, "The file is larger than 1000 kB")]
    with pytest.raises(cn.ConnectorError) as caught:
        cn.load(b"\xff\xfe")
    assert caught.value.problems[0].message == "The file is not UTF-8 text"
    # YAML is loaded with the safe loader: a tag that would build an object is refused.
    assert problems("name: !!python/object/apply:os.system ['id']\n")[0][1].startswith("Not valid YAML")


def test_every_problem_comes_with_its_line():
    bad = GOOD.replace("id: servicenow", "id: Service Now").replace("method: POST", "method: FETCH")
    bad = bad.replace("changes_outside: true", "changes_outsid: true")
    found = problems(bad)
    lines = {message: line for line, message in found}
    assert lines['"changes_outsid" is not a key that is known here'] == 22
    assert any(line == 28 and "GET" in message for line, message in found)  # the method, on its own line
    assert any("id: a lower-case letter" in message for _line, message in found)

    missing = GOOD.replace('base_url: "{{ config.url }}"\n', "")
    assert (0, '"base_url" is missing') in problems(missing) or (1, '"base_url" is missing') in problems(missing)


def test_templates_are_checked_where_they_are_written():
    # A template that cannot be read, with its line.
    broken = GOOD.replace('"{{ args.urgency }}"', '"{{ args.urgency "')
    found = problems(broken)
    assert found[0][0] == 32 and found[0][1].startswith("The expression is not closed: add }}")
    # What is sent cannot read an answer; what is read from the answer cannot read a secret.
    early = GOOD.replace('short_description: "{{ args.short_description }}"', 'short_description: "{{ response.x }}"')
    assert problems(early)[0] == (
        31,
        '"response" cannot be read in what is sent: only args, config, idempotency, now, secret, steps',
    )
    leak = GOOD.replace('number: "{{ response.result.number }}"', 'number: "{{ secret.token }}"')
    assert any("cannot be read in what is read from the answer" in message for _line, message in problems(leak))
    # Names must exist: an argument, a configuration entry.
    ghost = GOOD.replace("{{ args.urgency }}", "{{ args.priority }}")
    assert problems(ghost) == [
        (20, 'the command "create-incident" reads "args.priority", which is not among its arguments')
    ]
    nowhere = GOOD.replace('base_url: "{{ config.url }}"', 'base_url: "{{ config.address }}"')
    assert (0, '"config.address" is not in the configuration') in problems(nowhere)


def test_shapes_that_do_not_fit_are_refused():
    def with_command(body: str) -> str:
        head = GOOD.split("commands:")[0]
        return head + "commands:\n" + textwrap.indent(textwrap.dedent(body), "  ")

    both = with_command(
        """\
        - name: both
          request: { method: GET, path: /a }
          steps:
            - { name: one, request: { method: GET, path: /b } }
        """
    )
    assert any('a command has "request" or "steps"' in message for _line, message in problems(both))
    two_bodies = with_command(
        """\
        - name: two-bodies
          request: { method: POST, path: /a, json: { a: 1 }, form: { b: 2 } }
        """
    )
    assert any("one of json, form, multipart, body" in message for _line, message in problems(two_bodies))
    later = with_command(
        """\
        - name: publish
          steps:
            - name: change
              request: { method: POST, path: "/x/{{ steps.task.response.id }}" }
            - name: task
              request: { method: POST, path: /show-task }
              poll:
                until: { all: [{ left: "{{ response.status }}", op: ne, right: in progress }] }
                every: 3
                timeout: 120
        """
    )
    assert any(
        'the step "change" reads "steps.task", which is not an earlier step' in message
        for _line, message in problems(later)
    )
    ok = cn.load(later.replace("{{ steps.task.response.id }}", "x"))
    assert ok.command("publish").steps[1].poll.every == 3
    cursor = with_command(
        """\
        - name: agents
          request: { method: GET, path: /agents }
          pagination: { type: cursor, items: "{{ response.data }}" }
        """
    )
    assert any('"cursor" pagination needs "param" and "next"' in message for _line, message in problems(cursor))


def test_credentials_have_their_own_keys():
    def with_auth(body: str) -> str:
        head, rest = GOOD.split("  - name: credentials\n    type: basic\n")
        return head + textwrap.indent(textwrap.dedent(body), "  ") + rest

    session = with_auth(
        """\
        - name: credentials
          type: session
          login:
            request:
              method: POST
              path: /web_api/login
              json: { user: "{{ secret.username }}", password: "{{ secret.password }}" }
            token: "{{ response.sid }}"
            header: X-chkp-sid
          logout:
            request: { method: POST, path: /web_api/logout, json: {} }
        """
    )
    connector = cn.load(session)
    assert connector.auth.login.header == "X-chkp-sid" and connector.auth.logout is not None
    assert any(
        '"session" credentials need "login"' in m
        for _l, m in problems(session.split("    login:")[0] + "commands:" + session.split("commands:")[1])
    )
    header = with_auth("- { name: credentials, type: header }\n")
    assert any('"header" credentials need "header"' in message for _line, message in problems(header))
    oauth = with_auth("- { name: credentials, type: oauth2_client }\n")
    assert any('"oauth2_client" credentials need "token_url"' in message for _line, message in problems(oauth))
    two = with_auth("- { name: credentials, type: basic }\n- { name: token, type: bearer }\n")
    assert any("one set of credentials at most" in message for _line, message in problems(two))
    # A secret is read as secret.<name>, never as config.<name>.
    plain = GOOD.replace(
        "  - name: credentials\n", "  - { name: api_token, type: secret }\n  - name: credentials\n"
    ).replace("Accept: application/json", 'X-Token: "{{ config.api_token }}"')
    assert (0, '"api_token" is a secret: read it as {{ secret.api_token }}') in problems(plain)
    assert cn.load(plain.replace("config.api_token", "secret.api_token")).headers["X-Token"] == "{{ secret.api_token }}"


FETCHING = GOOD + textwrap.dedent(
    """\
      - name: get-incident
        arguments: [{ name: sys_id, type: text, required: true }]
        request: { method: GET, path: "/api/now/table/incident/{{ args.sys_id }}" }
        outputs: { incident: "{{ response.result }}" }
      - name: update-incident
        changes_outside: true
        arguments:
          - { name: sys_id, type: text, required: true }
          - { name: fields, type: object }
        request: { method: PATCH, path: "/api/now/table/incident/{{ args.sys_id }}", json: "{{ args.fields }}" }
        outputs: { incident: "{{ response.result }}" }
      - name: get-comments
        arguments: [{ name: sys_id, type: text, required: true }]
        request: { method: GET, path: /api/now/table/sys_journal_field, query: { element_id: "{{ args.sys_id }}" } }
        outputs: { comments: "{{ response.result }}" }
      - name: add-comment
        changes_outside: true
        arguments:
          - { name: sys_id, type: text, required: true }
          - { name: text, type: text, required: true }
        request:
          method: PATCH
          path: "/api/now/table/incident/{{ args.sys_id }}"
          json: { comments: "{{ args.text }}" }
    fetch:
      interval_seconds: 120
      first_fetch: 3 days
      request:
        method: GET
        path: /api/now/table/incident
        query:
          sysparm_query: "sys_created_on>{{ state.last_time }}"
      pagination:
        type: offset
        param: sysparm_offset
        limit_param: sysparm_limit
        limit: 100
        items: "{{ response.result }}"
        max_pages: 20
      item_id: "{{ item.sys_id }}"
      occurred: "{{ item.sys_created_on }}"
      first_state:
        last_time: "{{ first.iso }}"
      next_state:
        last_time: "{{ items | last | get('sys_created_on') }}"
    schema:
      incoming:
        - { name: short_description, type: text }
        - { name: sys_created_on, type: date, description: When it was opened }
      outgoing:
        - { name: short_description, type: text }
    ext_fields:
      - { name: assignment_group, type: text }
    mirror:
      interval_seconds: 300
      get: { command: get-incident }
      update:
        command: update-incident
        args: { sys_id: "{{ mirror.id }}", fields: "{{ fields }}" }
      comments:
        list: { command: get-comments }
        items: "{{ result.comments }}"
        id: "{{ item.sys_id }}"
        text: "{{ item.value }}"
        author: "{{ item.sys_created_by }}"
        at: "{{ item.sys_created_on }}"
        add:
          command: add-comment
          args: { sys_id: "{{ mirror.id }}", text: "{{ comment.text }}" }
    """
)


def _raised(text: str) -> list[cn.Problem]:
    with pytest.raises(cn.ConnectorError) as caught:
        cn.load(text)
    return caught.value.problems


def test_a_connector_says_how_it_brings_alerts_in_and_keeps_an_object_in_step():
    connector = cn.load(FETCHING)
    fetch = connector.fetch
    assert (fetch.interval_seconds, fetch.first_seconds, fetch.pagination.max_pages) == (120, 3 * 86400, 20)
    assert fetch.item_id == "{{ item.sys_id }}" and list(fetch.next_state) == ["last_time"]
    assert fetch.first_state == {"last_time": "{{ first.iso }}"}
    assert [item.name for item in connector.schema_.incoming] == ["short_description", "sys_created_on"]
    assert connector.ext_fields[0].name == "assignment_group"
    mirror = connector.mirror
    assert (mirror.get.command, mirror.update.command, mirror.interval_seconds) == (
        "get-incident",
        "update-incident",
        300,
    )
    assert mirror.comments.add.args == {"sys_id": "{{ mirror.id }}", "text": "{{ comment.text }}"}
    assert [where for where, _call in connector.mirror_calls()] == [
        "mirror.get",
        "mirror.update",
        "mirror.comments.list",
        "mirror.comments.add",
    ]
    shown = cn.summary(connector)
    # What an instance starts with; this one goes on from what it kept, not from a time.
    assert shown["fetch"] == {"intervalSeconds": 120, "firstFetch": "3 days", "lookbackMinutes": 0, "byTime": False}
    assert shown["mirror"] == {"intervalSeconds": 300, "out": True, "comments": True, "commentsOut": True}
    assert shown["schema"]["incoming"][1] == {
        "name": "sys_created_on",
        "type": "date",
        "description": "When it was opened",
    }
    assert shown["extFields"] == [{"name": "assignment_group", "type": "text", "description": ""}]
    # A connector with none of them says so.
    plain = cn.summary(cn.load(GOOD))
    assert plain["fetch"] is None and plain["mirror"] is None and plain["schema"] == {"incoming": [], "outgoing": []}

    assert cn.first_fetch_seconds("30 minutes") == 1800 and cn.first_fetch_seconds("1 hour") == 3600
    assert cn.first_fetch_seconds("soon") is None and cn.first_fetch_seconds("90 days") is None


def test_a_fetch_by_time_asks_from_the_moment_nik_works_out():
    # A request that reads "since" is a fetch by time: the look-back of an instance applies to it.
    by_time = (
        FETCHING.replace("sys_created_on>{{ state.last_time }}", "sys_created_on>={{ since.iso }}")
        .replace('  first_state:\n    last_time: "{{ first.iso }}"\n', "")
        .replace("  next_state:\n    last_time: \"{{ items | last | get('sys_created_on') }}\"\n", "")
        .replace("  first_fetch: 3 days\n", "  first_fetch: 3 days\n  lookback_minutes: 5\n", 1)
        .replace('  occurred: "{{ item.sys_created_on }}"\n', '  item_time: "{{ item.sys_created_on }}"\n')
    )
    fetch = cn.load(by_time).fetch
    assert (fetch.by_time, fetch.lookback_minutes, fetch.item_time) == (True, 5, "{{ item.sys_created_on }}")
    assert (fetch.first_state, fetch.next_state) == ({}, {})
    said = cn.summary(cn.load(by_time))["fetch"]
    assert said == {"intervalSeconds": 120, "firstFetch": "3 days", "lookbackMinutes": 5, "byTime": True}
    # One that goes on from what it kept is not, and starts with no look-back.
    kept = cn.load(FETCHING).fetch
    assert (kept.by_time, kept.lookback_minutes, kept.item_time) == (False, 0, None)

    def messages(text: str) -> list[str]:
        return [problem.message for problem in _raised(text)]

    assert any(
        "less than or equal to 1440" in message
        for message in messages(by_time.replace("minutes: 5\n", "minutes: 5000\n"))
    )
    # The time of an item is read from the item; a name of the state that starts with _ is kept for Nik.
    assert any(
        '"response" cannot be read' in message
        for message in messages(by_time.replace("{{ item.sys_created_on }}", "{{ response.x }}"))
    )
    assert any(
        "a name of the state does not start with _" in message
        for message in messages(FETCHING.replace("  next_state:\n    last_time:", "  next_state:\n    _since:"))
    )


def test_what_is_wrong_with_a_fetch_or_a_mirror_is_said():
    def messages(text: str) -> list[str]:
        return [problem.message for problem in _raised(text)]

    # The request of a fetch reads the state and the first moment, never an answer or an argument.
    early = FETCHING.replace("{{ state.last_time }}", "{{ response.x }}")
    assert messages(early) == [
        '"response" cannot be read in what is sent: only config, first, now, secret, since, state'
    ]
    assert any(
        '"state" cannot be read' in message
        for message in messages(FETCHING.replace('last_time: "{{ first.iso }}"', 'last_time: "{{ state.x }}"'))
    )
    # One item is told apart by what it holds.
    assert '"item_id" is a template over the item: "{{ item.id }}"' in messages(
        FETCHING.replace('item_id: "{{ item.sys_id }}"', "item_id: sys_id")
    )
    assert any(
        '"response" cannot be read' in message
        for message in messages(FETCHING.replace('item_id: "{{ item.sys_id }}"', 'item_id: "{{ response.id }}"'))
    )
    assert '"first_fetch" is a length of time: 30 minutes, 12 hours, 3 days' in messages(
        FETCHING.replace("first_fetch: 3 days", "first_fetch: a while")
    )
    # Where the items are is said once: by the pagination, or by "items".
    twice = FETCHING.replace(
        '  item_id: "{{ item.sys_id }}"', '  items: "{{ response.result }}"\n  item_id: "{{ item.sys_id }}"'
    )
    assert any("a fetch says where its items are" in message for message in messages(twice))
    too_often = _raised(FETCHING.replace("  interval_seconds: 120", "  interval_seconds: 5"))
    assert any("interval_seconds" in problem.where for problem in too_often)

    # Mirroring runs commands of the file, with arguments they take.
    assert messages(FETCHING.replace("get: { command: get-incident }", "get: { command: read-incident }")) == [
        'mirror.get names "read-incident", which is not a command'
    ]
    wrong_args = FETCHING.replace(
        'args: { sys_id: "{{ mirror.id }}", fields: "{{ fields }}" }', 'args: { id: "{{ mirror.id }}" }'
    )
    assert sorted(messages(wrong_args)) == [
        'mirror.update does not give "sys_id", which "update-incident" needs',
        'mirror.update gives "id", which "update-incident" does not take',
    ]
    quiet = FETCHING.replace("  - name: update-incident\n    changes_outside: true", "  - name: update-incident")
    assert messages(quiet) == ["mirror.update changes the other side: its command says changes_outside: true"]
    assert any(
        '"args" cannot be read in what mirroring gives' in message
        for message in messages(FETCHING.replace('text: "{{ comment.text }}" }', 'text: "{{ args.text }}" }'))
    )
    # Names of ext fields are given once.
    doubled = FETCHING.replace(
        "  - { name: assignment_group, type: text }",
        "  - { name: assignment_group, type: text }\n  - { name: assignment_group, type: text }",
    )
    assert "two ext fields have the same name" in messages(doubled)
