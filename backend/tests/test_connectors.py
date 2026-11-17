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
    assert problems("x" * (cn.MAX_BYTES + 1)) == [(0, "The file is larger than 256 kB")]
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
        '"response" cannot be read in what is sent: only args, config, secret, steps',
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
