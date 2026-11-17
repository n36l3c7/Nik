"""Running a command of a connector.

``Runtime`` takes a connector file (connectors.py), the values of a
connection and the policy of the playbook, and runs one command: it renders
the request from its templates, adds the credentials, sends it through the
egress client, judges the answer and renders the outputs.

What it never does:

- send anywhere but the host of the connection (``base_url``): a ``path`` or a
  "next page" link that names another host is refused, so credentials cannot
  be led away;
- keep a secret: tokens of OAuth and of sessions live in memory (or, for a
  command that waits between two calls, encrypted in the step); what a step
  records has every secret value replaced by ``•••``;
- hold a worker while the other side works: a ``poll`` gives the step back
  with a time, and the engine calls again then (``Result.again_at``).

The names a template reads: ``config``, ``args``, ``steps`` (earlier steps:
``steps.<name>.response``, ``.status``, ``.headers``), ``secret`` (only in
what is sent) and, once there is an answer, ``response``, ``status`` and
``headers``.
"""

from __future__ import annotations

import base64
import json as jsonlib
import secrets as pysecrets
import threading
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

from . import egress
from . import expressions as ex
from .connectors import Command, ConfigParam, ConnectorFile, Poll, RequestSpec, Step, Success

MAX_ITEMS = 5000
REDACTED = "•••"
TOKEN_SKEW = 60

# What each kind of credentials is made of (the fields a connection asks for, all secret).
AUTH_FIELDS: dict[str, tuple[str, ...]] = {
    "basic": ("username", "password"),
    "bearer": ("token",),
    "header": ("value",),
    "oauth2_client": ("client_id", "client_secret"),
    "session": ("username", "password", "api_key"),
    "zscaler": ("username", "password", "api_key"),
}


class CommandError(Exception):
    """A command that failed: a sentence safe to show, and whether trying again may help."""

    def __init__(self, message: str, *, retry: bool = False, sent: bool = False, record: dict | None = None):
        super().__init__(message)
        self.message = message
        self.retry = retry
        self.sent = sent  # the request left: the other side may have acted
        self.record = record or {}


@dataclass
class Answer:
    """What a command gave: outputs, or "call again at"."""

    outputs: dict[str, Any] | None = None
    again_at: float | None = None
    state: dict[str, Any] | None = None
    records: list[dict] = field(default_factory=list)  # one per request sent (method, host, path, status)

    @property
    def done(self) -> bool:
        return self.again_at is None


# OAuth tokens, by connection: {key: (token, expires_at)}. Memory only.
_TOKENS: dict[str, tuple[str, float]] = {}
_TOKENS_LOCK = threading.Lock()


def forget_tokens(key: str | None = None) -> None:
    """Drop cached tokens (a connection changed, or the tests start clean)."""
    with _TOKENS_LOCK:
        if key is None:
            _TOKENS.clear()
        else:
            _TOKENS.pop(key, None)


def zscaler_key(api_key: str, now_ms: int) -> tuple[str, str]:
    """The obfuscated API key the ZIA legacy API asks for at login, and the timestamp it was made with.

    As Zscaler's own SDKs do it: the last six digits of the time in milliseconds pick six
    characters of the key, and those digits halved pick six more, two places further.
    """
    stamp = str(int(now_ms))
    n = stamp[-6:]
    r = str(int(n) >> 1).zfill(6)
    try:
        key = "".join(api_key[int(digit)] for digit in n) + "".join(api_key[int(digit) + 2] for digit in r)
    except IndexError:
        raise CommandError("The Zscaler API key is too short: it has 12 characters at least") from None
    return key, stamp


def _redact(value: Any, hidden: set[str]) -> Any:
    """``value`` with every secret in it replaced."""
    if not hidden:
        return value
    if isinstance(value, str):
        for secret in hidden:
            if secret in value:
                value = value.replace(secret, REDACTED)
        return value
    if isinstance(value, dict):
        return {key: _redact(item, hidden) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact(item, hidden) for item in value]
    return value


def _holds(conditions: Any, scope: ex.Scope) -> bool:
    """``all`` / ``any`` of comparisons (the connector's own, parsed by connectors.py)."""
    if conditions is None:
        return True
    items = conditions.all if conditions.all is not None else conditions.any
    results = []
    for item in items:
        try:
            left = ex.render(item.left, scope).data
        except ex.ExpressionError:
            left = ex.MISSING
        right = ex.render(item.right, scope).data if item.right is not None else None
        results.append(ex.compare(left, item.op, right))
    return all(results) if conditions.all is not None else any(results)


def _multipart(fields: dict[str, Any]) -> tuple[bytes, str]:
    boundary = "nik" + pysecrets.token_hex(12)
    parts = []
    for name, value in fields.items():
        if value is None:
            continue
        text = value if isinstance(value, str) else jsonlib.dumps(value)
        safe = str(name).replace('"', "%22").replace("\r", "").replace("\n", "")
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{safe}"\r\n\r\n{text}\r\n')
    parts.append(f"--{boundary}--\r\n")
    return "".join(parts).encode("utf-8"), f"multipart/form-data; boundary={boundary}"


class Runtime:
    """One connector, one connection, one playbook's policy."""

    def __init__(
        self,
        connector: ConnectorFile,
        config: dict[str, Any],
        secrets: dict[str, Any],
        policy: egress.Policy,
        *,
        token_key: str = "",
        send=None,
        clock=time.time,
    ):
        self.connector = connector
        self.secrets = {key: str(value) for key, value in (secrets or {}).items() if value not in (None, "")}
        self.config = self._config(config or {})
        self.policy = policy
        self.token_key = token_key or connector.id
        self._send = send or egress.request
        self._clock = clock
        self._hidden = {value for value in self.secrets.values() if len(value) >= 4}
        self._session: dict[str, str] | None = None  # the header a session is sent with
        self.records: list[dict] = []
        base = ex.render_text(connector.base_url, ex.Scope(values={"config": self.config})).data
        self.base_url = str(base or "").strip().rstrip("/")
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise CommandError("The address of the connection is not an https:// address")
        self.host = parts.hostname.lower()
        self.allow_http = parts.scheme == "http"
        self.ca_pem = str(self.config.get("ca_pem") or "") or None

    # ----------------------------------------------------------------- values --
    def _config(self, given: dict[str, Any]) -> dict[str, Any]:
        """The plain values of the connection, with the defaults of those left out."""
        out: dict[str, Any] = {}
        for param in self.connector.configuration:
            if param.is_auth or param.type == "secret":
                continue
            value = given.get(param.name)
            if value in (None, ""):
                value = param.default
            if param.type == "url" and isinstance(value, str):
                value = value.strip().rstrip("/")
            out[param.name] = value
        return out

    def _scope(self, args: dict, steps: dict, answer: dict | None = None, *, sent: bool) -> ex.Scope:
        values: dict[str, Any] = {"config": self.config, "args": args, "steps": steps}
        if sent:
            values["secret"] = self.secrets
        if answer is not None:
            values.update(response=answer["response"], status=answer["status"], headers=answer["headers"])
        return ex.Scope(values=values)

    # ---------------------------------------------------------------- sending --
    def _url(self, path: str) -> str:
        """The address of a request: under ``base_url``, and never on another host."""
        target = path if path.startswith(("http://", "https://")) else self.base_url + "/" + path.lstrip("/")
        parts = urlsplit(target)
        if (parts.hostname or "").lower() != self.host:
            raise CommandError(f"A request of this connector goes to {parts.hostname}, not to its connection")
        return target

    def _raw(self, spec: RequestSpec, scope: ex.Scope, auth: bool = True, timeout: float = 60) -> dict[str, Any]:
        """Send one request and give back ``{response, status, headers}``. Raises ``CommandError``."""
        rendered = {
            "path": ex.render_text(spec.path, scope).data,
            "query": ex.render(spec.query, scope).data if spec.query is not None else None,
            "headers": ex.render(spec.headers or {}, scope).data,
            "json": ex.render(spec.json_body, scope).data if spec.json_body is not None else None,
            "form": ex.render(spec.form, scope).data if spec.form is not None else None,
            "multipart": ex.render(spec.multipart, scope).data if spec.multipart is not None else None,
            "body": ex.render_text(spec.body, scope).data if spec.body is not None else None,
        }
        headers = {
            **{key: str(ex.render_text(value, scope).data) for key, value in self.connector.headers.items()},
            **{str(key): str(value) for key, value in (rendered["headers"] or {}).items() if value is not None},
        }
        if auth:
            headers.update(self._credentials())
        body = rendered["body"]
        if rendered["multipart"] is not None:
            body, content_type = _multipart(rendered["multipart"])
            headers["Content-Type"] = content_type
        url = self._url(str(rendered["path"]))
        try:
            answer = self._send(
                self.policy,
                spec.method,
                url,
                headers=headers,
                query={key: value for key, value in (rendered["query"] or {}).items() if value not in (None, "")}
                or None,
                json=rendered["json"],
                form=rendered["form"],
                body=body,
                timeout=timeout,
                allow_http=self.allow_http,
                ca_pem=self.ca_pem,
            )
        except egress.EgressError as error:
            record = _redact(dict(error.record or {}), self._hidden)
            if record:
                self.records.append(record)
            raise CommandError(error.message, retry=not error.refused, sent=error.sent, record=record) from None
        self.records.append(_redact(dict(answer.record), self._hidden))
        parsed = answer.json()
        return {
            "response": parsed if parsed is not None else {"text": answer.text[:200_000]},
            "status": answer.status,
            "headers": dict(answer.headers),
        }

    def _judge(self, answer: dict, success: Success | None, error, scope: ex.Scope) -> None:
        """Raise ``CommandError`` unless the answer is a success."""
        statuses = success.statuses() if success is not None else None
        good = answer["status"] in statuses if statuses else 200 <= answer["status"] < 300
        if good and success is not None and success.when is not None:
            good = _holds(success.when, scope)
        if good:
            return
        message = ""
        if error is not None:
            try:
                message = ex._text(ex.render_text(error.message, scope).data).strip()
            except ex.ExpressionError:
                message = ""
        status = answer["status"]
        said = f"{self.connector.name} answered {status}" + (f": {message[:500]}" if message else "")
        # 429 and 5xx may pass; a refusal (4xx) will be refused again.
        raise CommandError(_redact(said, self._hidden), retry=status == 429 or status >= 500, sent=True)

    # ------------------------------------------------------------ credentials --
    def _credentials(self) -> dict[str, str]:
        auth = self.connector.auth
        if auth is None:
            return {}
        secret = self.secrets
        if auth.type == "basic":
            pair = f"{secret.get('username', '')}:{secret.get('password', '')}".encode()
            return {"Authorization": "Basic " + base64.b64encode(pair).decode("ascii")}
        if auth.type == "bearer":
            return {"Authorization": f"Bearer {secret.get('token', '')}"}
        if auth.type == "header":
            return {str(auth.header): f"{auth.prefix}{secret.get('value', '')}"}
        if auth.type == "oauth2_client":
            return {"Authorization": f"Bearer {self._oauth_token(auth)}"}
        if self._session is None:
            self._session = self._login_zscaler() if auth.type == "zscaler" else self._login(auth)
        return dict(self._session)

    def _oauth_token(self, auth: ConfigParam) -> str:
        now = self._clock()
        with _TOKENS_LOCK:
            cached = _TOKENS.get(self.token_key)
        if cached and cached[1] > now:
            return cached[0]
        token_url = str(ex.render_text(str(auth.token_url), ex.Scope(values={"config": self.config})).data)
        form: dict[str, Any] = {"grant_type": "client_credentials"}
        if auth.scope:
            form["scope"] = auth.scope
        headers: dict[str, str] = {}
        if auth.auth_style == "basic":
            pair = f"{self.secrets.get('client_id', '')}:{self.secrets.get('client_secret', '')}".encode()
            headers["Authorization"] = "Basic " + base64.b64encode(pair).decode("ascii")
        else:
            form.update(
                client_id=self.secrets.get("client_id", ""), client_secret=self.secrets.get("client_secret", "")
            )
        # The token endpoint may be on another host (an identity provider): the policy decides, as for any request.
        try:
            answer = self._send(
                self.policy, "POST", token_url, headers=headers, form=form, timeout=30, ca_pem=self.ca_pem,
                allow_http=self.allow_http,
            )  # fmt: skip
        except egress.EgressError as error:
            raise CommandError(f"The token could not be asked for: {error.message}", retry=not error.refused) from None
        self.records.append(_redact(dict(answer.record), self._hidden))
        data = answer.json() if answer.status < 300 else None
        token = data.get("access_token") if isinstance(data, dict) else None
        if not token:
            raise CommandError(
                f"{self.connector.name} gave no token (answer {answer.status})", retry=answer.status >= 500
            )
        self._hidden.add(str(token))
        lifetime = data.get("expires_in") if isinstance(data.get("expires_in"), (int, float)) else 300
        with _TOKENS_LOCK:
            _TOKENS[self.token_key] = (str(token), now + max(30, float(lifetime) - TOKEN_SKEW))
        return str(token)

    def _login(self, auth: ConfigParam) -> dict[str, str]:
        login = auth.login
        scope = self._scope({}, {}, sent=True)
        answer = self._raw(login.request, scope, auth=False, timeout=30)
        after = self._scope({}, {}, answer, sent=False)
        self._judge(answer, login.success, None, after)
        try:
            token = ex._text(ex.render_text(login.token, after).data)
        except ex.ExpressionError:
            token = ""
        if not token:
            raise CommandError(f"{self.connector.name} opened no session: the answer holds no token")
        self._hidden.add(token)
        return {login.header: f"{login.prefix}{token}"}

    def _login_zscaler(self) -> dict[str, str]:
        key, stamp = zscaler_key(self.secrets.get("api_key", ""), int(self._clock() * 1000))
        body = {
            "apiKey": key,
            "username": self.secrets.get("username", ""),
            "password": self.secrets.get("password", ""),
            "timestamp": stamp,
        }
        try:
            answer = self._send(
                self.policy, "POST", self._url("/authenticatedSession"), json=body, timeout=30, ca_pem=self.ca_pem
            )
        except egress.EgressError as error:
            raise CommandError(f"Zscaler could not be reached: {error.message}", retry=not error.refused) from None
        self.records.append(dict(answer.record))
        cookie = answer.headers.get("set-cookie", "")
        session = next(
            (part.split(";")[0] for part in cookie.split(",") if part.strip().startswith("JSESSIONID=")), ""
        ).strip()
        if answer.status >= 300 or not session:
            raise CommandError(f"Zscaler refused the sign-in (answer {answer.status})", retry=answer.status >= 500)
        self._hidden.add(session.split("=", 1)[1])
        return {"Cookie": session}

    def close(self) -> None:
        """End a session opened for this call. Failures are swallowed: the work is done."""
        auth = self.connector.auth
        session, self._session = self._session, None
        if auth is None or session is None:
            return
        try:
            if auth.type == "zscaler":
                self._send(
                    self.policy, "DELETE", self._url("/authenticatedSession"), headers=session, timeout=15,
                    ca_pem=self.ca_pem,
                )  # fmt: skip
            elif auth.logout is not None:
                self._session = session
                try:
                    self._raw(auth.logout.request, self._scope({}, {}, sent=True), timeout=15)
                finally:
                    self._session = None
        except (CommandError, egress.EgressError, ex.ExpressionError):
            pass

    # --------------------------------------------------------------- commands --
    def _paged(self, command: Command, args: dict) -> dict[str, Any]:
        """Read a list to its end, or to the limits. The answer is ``{items, pages, truncated}``."""
        page = command.pagination
        items: list[Any] = []
        cursor: Any = None
        offset = 0
        number = 1
        next_url: str | None = None
        last: dict[str, Any] = {"response": {}, "status": 0, "headers": {}}
        truncated = False
        for count in range(page.max_pages):
            spec = command.request
            extra: dict[str, Any] = {}
            if page.limit_param:
                extra[page.limit_param] = page.limit
            if page.type == "offset":
                extra[page.param] = offset
            elif page.type == "page":
                extra[page.param] = number
            elif page.type == "cursor" and cursor not in (None, ""):
                extra[page.param] = cursor
            if next_url is not None:
                spec = spec.model_copy(update={"path": next_url, "query": None})
            else:
                spec = spec.model_copy(update={"query": {**(spec.query or {}), **extra}})
            scope = self._scope(args, {}, sent=True)
            last = self._raw(spec, scope, timeout=command.timeout)
            after = self._scope(args, {}, last, sent=False)
            self._judge(last, command.success, command.error, after)
            try:
                found = ex.render_text(page.items, after).data
            except ex.ExpressionError:
                found = []
            found = found if isinstance(found, list) else []
            items += found
            if len(items) >= MAX_ITEMS:
                items, truncated = items[:MAX_ITEMS], True
                break
            if page.type in ("offset", "page"):
                if len(found) < page.limit:
                    break
                offset += len(found)
                number += 1
            elif page.type == "cursor":
                try:
                    cursor = ex.render_text(str(page.next), after).data
                except ex.ExpressionError:
                    cursor = None
                if cursor in (None, "", False) or not found:
                    break
            else:  # link
                next_url = _next_link(last["headers"].get("link", ""), self.base_url)
                if not next_url or not found:
                    break
            if count == page.max_pages - 1:
                truncated = True
        return {"response": {"items": items, "pages": count + 1, "truncated": truncated}, **{
            key: last[key] for key in ("status", "headers")
        }}  # fmt: skip

    def _one(self, part: Command | Step, args: dict, steps: dict, timeout: float) -> dict[str, Any]:
        """One request of a command or of a step, judged."""
        answer = self._raw(part.request, self._scope(args, steps, sent=True), timeout=timeout)
        self._judge(answer, part.success, part.error, self._scope(args, steps, answer, sent=False))
        return answer

    def _polled(self, poll: Poll, answer: dict, args: dict, steps: dict, started: float) -> float | None:
        """None when the poll is over; the time to ask again otherwise. Raises when it failed or ran out."""
        scope = self._scope(args, steps, answer, sent=False)
        if poll.fail_when is not None and _holds(poll.fail_when, scope):
            raise CommandError(f"{self.connector.name} says it failed", sent=True)
        if _holds(poll.until, scope):
            return None
        now = self._clock()
        if now - started >= poll.timeout:
            raise CommandError(f"{self.connector.name} did not finish in time", sent=True)
        return now + poll.every

    def run(self, name: str, args: dict[str, Any], state: dict[str, Any] | None = None) -> Answer:
        """Run a command, or go on with one that asked to be called again. Raises ``CommandError``."""
        command = self.connector.command(name)
        if command is None:
            raise CommandError("This command is not in the connector any more")
        state = dict(state or {})
        if state.get("session"):
            self._session = dict(state["session"])
            self._hidden.update(value.split(" ")[-1].split("=")[-1] for value in self._session.values())
        steps: dict[str, Any] = dict(state.get("steps") or {})
        try:
            if command.steps is None:
                if command.pagination is not None:
                    answer = self._paged(command, args)
                else:
                    answer = self._one(command, args, {}, command.timeout)
                    if command.poll is not None:
                        started = float(state.get("started") or self._clock())
                        again = self._polled(command.poll, answer, args, {}, started)
                        if again is not None:
                            return self._wait(again, {"started": started})
                return Answer(outputs=self._outputs(command, args, {}, answer), records=self.records)
            index = int(state.get("index") or 0)
            answer = None
            while index < len(command.steps):
                step = command.steps[index]
                if step.when is not None and not _holds(step.when, self._scope(args, steps, sent=False)):
                    steps[step.name] = {"skipped": True, "response": {}, "status": 0, "headers": {}}
                    index += 1
                    continue
                answer = self._one(step, args, steps, command.timeout)
                if step.poll is not None:
                    started = (
                        float(state.get("started") or self._clock()) if state.get("index") == index else self._clock()
                    )
                    again = self._polled(step.poll, answer, args, steps, started)
                    if again is not None:
                        return self._wait(again, {"index": index, "steps": steps, "started": started})
                steps[step.name] = answer
                state = {}
                index += 1
            last = answer or {"response": {}, "status": 0, "headers": {}}
            return Answer(outputs=self._outputs(command, args, steps, last), records=self.records)
        except CommandError as error:
            error.record = error.record or (self.records[-1] if self.records else {})
            self.close()
            raise
        except ex.ExpressionError as error:
            self.close()
            raise CommandError(f"A template of the connector could not be filled: {error.message}") from None
        finally:
            if self._session is not None and not self._waiting:
                self.close()

    _waiting = False

    def _wait(self, again_at: float, state: dict[str, Any]) -> Answer:
        """Give the step back, to be called again: a session that is open stays open, and travels with it."""
        self._waiting = True
        if self._session is not None:
            state["session"] = dict(self._session)
        return Answer(again_at=again_at, state=state, records=self.records)

    def _outputs(self, command: Command, args: dict, steps: dict, answer: dict) -> dict[str, Any]:
        scope = self._scope(args, steps, answer, sent=False)
        out: dict[str, Any] = {}
        for key, template in command.outputs.items():
            try:
                out[key] = ex.render(template, scope).data
            except ex.ExpressionError:
                out[key] = None  # the answer did not hold it: the output is empty, not an error
        if not command.outputs:
            out = {"response": answer["response"]}
        return _redact(out, self._hidden)

    def would_send(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """What a command would send first, for a dry run: nothing leaves."""
        command = self.connector.command(name)
        if command is None:
            raise CommandError("This command is not in the connector any more")
        spec = command.request if command.request is not None else command.steps[0].request
        scope = self._scope(args, {}, sent=True)
        path = str(ex.render_text(spec.path, scope).data)
        url = self._url(path)
        _scheme, host, _port, target, _address = egress.destination(self.policy, url, allow_http=self.allow_http)
        return {"method": spec.method, "host": host, "path": target.split("?")[0][:300], "dry_run": True}

    def test(self) -> dict[str, Any]:
        """ "Test the connection": ``{ok, status, message}``. Never raises."""
        spec = self.connector.test
        try:
            if spec is None:
                self._credentials()
                return {"ok": True, "status": 0, "message": "The credentials were accepted"}
            answer = self._raw(spec.request, self._scope({}, {}, sent=True), timeout=30)
            self._judge(answer, spec.expect, None, self._scope({}, {}, answer, sent=False))
            return {
                "ok": True,
                "status": answer["status"],
                "message": f"{self.connector.name} answered {answer['status']}",
            }
        except CommandError as error:
            status = (error.record or {}).get("status") or (self.records[-1].get("status") if self.records else 0)
            return {"ok": False, "status": status or 0, "message": error.message}
        except ex.ExpressionError as error:
            return {
                "ok": False,
                "status": 0,
                "message": f"A template of the connector could not be filled: {error.message}",
            }
        finally:
            self.close()


def _next_link(header: str, base: str) -> str | None:
    """The ``rel="next"`` address of a Link header (RFC 8288)."""
    for part in header.split(","):
        pieces = part.split(";")
        if len(pieces) < 2:
            continue
        target = pieces[0].strip()
        if target.startswith("<") and target.endswith(">") and any(
            piece.strip().replace('"', "").lower() == "rel=next" for piece in pieces[1:]
        ):  # fmt: skip
            return urljoin(base + "/", target[1:-1])
    return None
