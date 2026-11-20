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
- send a key without a value: an optional argument that was not given is left
  out of the body, at any depth, instead of going as ``null``;
- hold a worker while the other side works: a ``poll`` gives the step back
  with a time, and the engine calls again then (``Result.again_at``);
- open a file. One that comes back (``answer: file``) is bytes handed to the
  store of the run (``Runtime.store``), which keeps it as an artifact; one
  that is sent (``files``, ``body_file``) is bytes read from that store,
  after the data guard said it may leave. Nothing here decodes, unpacks or
  runs them, and where there is no store (a test of the connection) a
  command that carries a file is refused.

The names a template reads: ``config``, ``args``, ``steps`` (earlier steps:
``steps.<name>.response``, ``.status``, ``.headers``), ``now`` (the moment of
the engine's clock: ``now.iso``, ``now.epoch``, ``now.epoch_ms``), ``secret``
(only in what is sent) and, once there is an answer, ``response``, ``status``
and ``headers``.
"""

from __future__ import annotations

import base64
import json as jsonlib
import re
import secrets as pysecrets
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any
from urllib.parse import unquote, urljoin, urlsplit

from . import egress
from . import expressions as ex
from .connectors import MAX_PAGES, PAGE_MAX, Command, ConfigParam, ConnectorFile, Poll, RequestSpec, Step, Success

MAX_ITEMS = 5000
REDACTED = "•••"
TOKEN_SKEW = 60
RETRY_AFTER_MAX = 600  # the longest a poll waits because the other side asked it to
# What describes a file, and the classes of data those are: what a command that keeps one gives.
FILE_FIELDS = ("name", "type", "size", "sha256", "artifact", "linked")
FILE_CLASSES = {"name": ["attachment_name"], "sha256": ["hash"], "artifact": ["nik_id"]}
FILE_SAMPLE = {"name": "", "type": "", "size": 0, "sha256": "", "artifact": "", "linked": False}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

# What each kind of credentials is made of (the fields a connection asks for, all secret).
AUTH_FIELDS: dict[str, tuple[str, ...]] = {
    "basic": ("username", "password"),
    "bearer": ("token",),
    "header": ("value",),
    "query": ("value",),
    "oauth2_client": ("client_id", "client_secret"),
    "session": ("username", "password", "api_key"),
    "zscaler": ("username", "password", "api_key"),
}


class CommandError(Exception):
    """A command that failed: a sentence safe to show, and whether trying again may help."""

    def __init__(
        self,
        message: str,
        *,
        retry: bool = False,
        sent: bool = False,
        record: dict | None = None,
        status: int | None = None,
    ):
        super().__init__(message)
        self.status = status  # what the other side answered, when the failure is its answer
        self.message = message
        self.retry = retry
        self.sent = sent  # the request left: the other side may have acted
        self.record = record or {}


class NotSent(CommandError):
    """A command that was not sent because the file it is for was held back, on a node that drops
    what is held: there is nothing to send without it. Not a failure of the step."""


@dataclass
class Answer:
    """What a command gave: outputs, or "call again at"."""

    outputs: dict[str, Any] | None = None
    again_at: float | None = None
    state: dict[str, Any] | None = None
    records: list[dict] = field(default_factory=list)  # one per request sent (method, host, path, status)
    context: list[tuple[str, Any]] = field(default_factory=list)  # (context path, value) the command declares
    classes: dict[str, list] = field(default_factory=dict)  # of the outputs, when the command knows: {path: [class]}

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


def _pruned(value: Any) -> Any:
    """What is sent, without the keys that have no value: an optional argument left empty is left out,
    at any depth, instead of being sent as null. (Items of a list are kept as they are.)"""
    if isinstance(value, dict):
        return {key: _pruned(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_pruned(item) for item in value]
    return value


def _named(fields: dict[str, Any], scope: ex.Scope) -> dict[str, Any]:
    """The fields of a form with the names that are templates filled in."""
    return {
        (ex._text(ex.render_text(key, scope).data) if "{{" in str(key) else key): value for key, value in fields.items()
    }


def _quoted(value: Any) -> str:
    """A name as it is written between quotes in a header of a multipart form."""
    return _CONTROL.sub("", str(value)).replace("\\", "\\\\").replace('"', "%22")


def _multipart(fields: dict[str, Any], files: list[dict[str, Any]] | None = None) -> tuple[bytes, str]:
    """A multipart form: text fields, then files (each ``{field, name, type, data}``, its bytes as they are)."""
    boundary = "nik" + pysecrets.token_hex(12)
    parts: list[bytes] = []
    for name, value in fields.items():
        if value is None:
            continue
        text = value if isinstance(value, str) else jsonlib.dumps(value)
        head = f'--{boundary}\r\nContent-Disposition: form-data; name="{_quoted(name)}"\r\n\r\n'
        parts.append(f"{head}{text}\r\n".encode("utf-8"))
    for item in files or []:
        kind = _CONTROL.sub("", str(item["type"])) or "application/octet-stream"
        head = (
            f'--{boundary}\r\nContent-Disposition: form-data; name="{_quoted(item["field"])}"; '
            f'filename="{_quoted(item["name"])}"\r\nContent-Type: {kind}\r\n\r\n'
        )
        parts.append(head.encode("utf-8") + item["data"] + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode("ascii"))
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def _queried(value: Any) -> Any:
    """A value as an address carries it: yes and no as ``true`` and ``false``, not as Python writes them."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (list, tuple)):
        return [_queried(item) for item in value]
    return value


def _file_name(headers: dict[str, str], url: str) -> str:
    """The name the answer gives a file (``Content-Disposition``), or the last part of its address."""
    said = headers.get("content-disposition", "")
    found = re.search(r"filename\*\s*=\s*(?:UTF-8|utf-8)\'\'([^;]+)", said)
    if found:
        return unquote(found.group(1).strip())
    found = re.search(r'filename\s*=\s*(?:"([^"]*)"|([^;]+))', said)
    if found:
        return (found.group(1) if found.group(1) is not None else found.group(2)).strip()
    return unquote(urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1])


def clean_name(name: Any) -> str:
    """A file name as it is kept and shown: no path, no control character, of a length a person reads."""
    text = " ".join(_CONTROL.sub(" ", str(name or "")).split())
    return text.replace("\\", "/").rsplit("/", 1)[-1][:200]


def _retry_after(headers: dict[str, str], now: float) -> float:
    """How many seconds the answer asks to wait (``Retry-After``: a number, or a date); 0 when it does not."""
    said = str(headers.get("retry-after") or "").strip()
    if not said:
        return 0.0
    if said.isdigit():
        return float(min(int(said), RETRY_AFTER_MAX))
    try:
        moment = parsedate_to_datetime(said)
    except (TypeError, ValueError):
        return 0.0
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return float(max(0.0, min(moment.timestamp() - now, RETRY_AFTER_MAX)))


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
        # Where files are kept and read, and who judges one that leaves: given by who runs the command
        # for a playbook (connector_files.Store). None where no file can be carried.
        self.store: Any = None
        self._output_classes: dict[str, list] = {}
        base = ex.render_text(connector.base_url, ex.Scope(values={"config": self.config})).data
        self.base_url = str(base or "").strip().rstrip("/")
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("https", "http") or not parts.hostname:
            raise CommandError("The address of the instance is not an https:// address")
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

    def _now(self) -> dict[str, Any]:
        """The moment of the clock the runtime was given, as a fetch reads it too."""
        epoch = float(self._clock())
        stamp = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        return {"iso": stamp, "epoch": int(epoch), "epoch_ms": int(epoch * 1000)}

    def _scope(self, args: dict, steps: dict, answer: dict | None = None, *, sent: bool) -> ex.Scope:
        values: dict[str, Any] = {"config": self.config, "args": args, "steps": steps, "now": self._now()}
        classes: dict[str, dict] = {}
        if sent:
            values["secret"] = self.secrets
        if answer is not None:
            values.update(response=answer["response"], status=answer["status"], headers=answer["headers"])
            if answer.get("kept"):
                classes["response"] = FILE_CLASSES
        # A step that kept a file is read by the outputs as steps.<name>.response: its classes go with it.
        kept = {
            f"{name}.response.{key}": held
            for name, step in steps.items()
            if step.get("kept")
            for key, held in FILE_CLASSES.items()
        }
        if kept:
            classes["steps"] = kept
        return ex.Scope(values=values, classes=classes)

    # ---------------------------------------------------------------- sending --
    def _url(self, path: str) -> str:
        """The address of a request: under ``base_url``, and never on another host."""
        target = path if path.startswith(("http://", "https://")) else self.base_url + "/" + path.lstrip("/")
        parts = urlsplit(target)
        host = (parts.hostname or "").lower()
        if host != self.host and not self._other(target):
            raise CommandError(f"A request of this connector goes to {parts.hostname}, not to its instance")
        return target

    def _other(self, url: str) -> bool:
        """Whether an address is on one of the other hosts the connector lists (``more_hosts``): https, on
        the usual port, by name."""
        parts = urlsplit(url)
        host = (parts.hostname or "").lower()
        return (
            host != self.host
            and parts.scheme == "https"
            and parts.port in (None, 443)
            and host in self.connector.more_hosts
        )

    def _files(self, spec: RequestSpec, scope: ex.Scope) -> list[dict[str, Any]]:
        """The files a request sends, described (``field``, ``name``, ``type``, ``size``, ``sha256``): found
        in the store, never read here. Raises when one is not a file Nik holds."""
        parts = [*(spec.files or {}).items()]
        if spec.body_file is not None:
            parts.append(("", spec.body_file))
        if not parts:
            return []
        if self.store is None:
            raise CommandError(
                "A command that sends a file runs from a playbook: there is no store to read it from here"
            )
        found = []
        for name, part in parts:
            wanted = ex.render_text(part.artifact, scope).data
            if wanted in (None, ""):
                # The argument was left empty, or the guard took it out: there is no file to send.
                raise NotSent("The file to send was not given, or was held back: the command was not sent", retry=False)
            described = self.store.describe(wanted)
            given = ex._text(ex.render_text(part.name, scope).data) if part.name else ""
            found.append(
                {
                    "field": ex._text(ex.render_text(name, scope).data) if "{{" in name else name,
                    "name": clean_name(given) or clean_name(described["name"]) or described["sha256"],
                    "type": ex._text(ex.render_text(part.type, scope).data).strip() or "application/octet-stream",
                    "size": described["size"],
                    "sha256": described["sha256"],
                }
            )
        return found

    def _judged(self, files: list[dict[str, Any]]) -> None:
        """Ask the data guard about the files a request is about to send. Held, the guard raises and the
        step fails; on a node that drops what is held the command is not sent at all (``NotSent``): a
        submission without its file is nothing."""
        if files and not self.store.judge([{key: item[key] for key in ("name", "size", "sha256")} for item in files]):
            raise NotSent("The file was held back by the data guard: the command was not sent without it", retry=False)

    def _raw(self, spec: RequestSpec, scope: ex.Scope, auth: bool = True, timeout: float = 60) -> dict[str, Any]:
        """Send one request and give back ``{response, status, headers}`` (with ``file``, the bytes that
        came, when the answer is a file: ``_one`` keeps them). Raises ``CommandError``."""
        files = self._files(spec, scope)
        self._judged(files)
        rendered = {
            "path": ex.render_text(spec.path, scope).data,
            "query": ex.render(spec.query, scope).data if spec.query is not None else None,
            "headers": ex.render(spec.headers or {}, scope).data,
            "json": _pruned(ex.render(spec.json_body, scope).data) if spec.json_body is not None else None,
            # The name of a field may be a template too (Bitbucket names the field after the file).
            "form": _pruned(ex.render(_named(spec.form, scope), scope).data) if spec.form is not None else None,
            "multipart": _pruned(ex.render(_named(spec.multipart, scope), scope).data)
            if spec.multipart is not None
            else None,
            "body": ex.render_text(spec.body, scope).data if spec.body is not None else None,
        }
        headers = {
            **{key: str(ex.render_text(value, scope).data) for key, value in self.connector.headers.items()},
            **{str(key): str(value) for key, value in (rendered["headers"] or {}).items() if value is not None},
        }
        url = self._url(str(rendered["path"]))
        query = {key: _queried(value) for key, value in (rendered["query"] or {}).items() if value not in (None, "")}
        # The credentials of the instance are for its own host: another host the connector lists gets none.
        own: dict[str, str] = {}
        if auth and not self._other(url):
            own = self._credentials()
            headers.update(own)
            query.update(self._query_credentials())
        body = rendered["body"]
        if rendered["multipart"] is not None or spec.files is not None:
            # The bytes are read now, once the guard has let them go, and go as they are.
            parts = [{**item, "data": self.store.read(item["sha256"])} for item in files]
            body, content_type = _multipart(rendered["multipart"] or {}, parts)
            headers["Content-Type"] = content_type
        elif spec.body_file is not None:
            body = self.store.read(files[0]["sha256"])
            headers.setdefault("Content-Type", files[0]["type"])
        more: dict[str, Any] = {}
        if spec.answer == "file":
            if self.store is None:
                raise CommandError(
                    "A command that keeps a file runs from a playbook: there is no store to keep it in here"
                )
            more["max_body"] = self.store.limit
        if own:
            # The header a key goes in is not one of the usual ones: it must not follow a redirect elsewhere.
            more["secret_headers"] = tuple(own)
        try:
            answer = self._send(
                self.policy,
                spec.method,
                url,
                headers=headers,
                query=query or None,
                json=rendered["json"],
                form=rendered["form"],
                body=body,
                timeout=timeout,
                allow_http=self.allow_http,
                ca_pem=self.ca_pem,
                **more,
            )
        except egress.EgressError as error:
            record = _redact(dict(error.record or {}), self._hidden)
            if files:
                record["files"] = [{key: item[key] for key in ("name", "size", "sha256")} for item in files]
            if record:
                self.records.append(record)
            message = error.message
            if getattr(error, "too_large", False) and spec.answer == "file":
                message = f"The file is larger than the {self.store.limit_mb} MB limit of a sample: it was not kept"
            raise CommandError(message, retry=not error.refused, sent=error.sent, record=record) from None
        record = _redact(dict(answer.record), self._hidden)
        if files:
            record["files"] = [{key: item[key] for key in ("name", "size", "sha256")} for item in files]
        self.records.append(record)
        if spec.answer == "file":
            return {
                "response": {},
                "status": answer.status,
                "headers": dict(answer.headers),
                "file": answer,
                "url": url,
            }
        parsed = answer.json() if spec.answer == "auto" else None
        return {
            "response": parsed if parsed is not None else {"text": answer.text[:200_000]},
            "status": answer.status,
            "headers": dict(answer.headers),
        }

    def _kept(self, part: Command | Step, args: dict, steps: dict, answer: dict[str, Any]) -> None:
        """Turn the answer of a request whose answer is a file into what describes the file, kept in the
        store. An answer that is not a success is read as any other is, so that the error can quote it:
        by its status, or by what ``success.when`` says of what came with it (an API that answers 200 and
        an error in JSON where the file should be is told apart by its ``Content-Type``)."""
        came = answer.pop("file")
        url = answer.pop("url")
        statuses = part.success.statuses() if part.success is not None else None
        good = answer["status"] in statuses if statuses else 200 <= answer["status"] < 300
        if good and part.success is not None and part.success.when is not None:
            good = _holds(part.success.when, self._scope(args, steps, answer, sent=False))
        if not good:
            parsed = came.json()
            answer["response"] = parsed if parsed is not None else {"text": came.text[:200_000]}
            return
        data = bytes(came.body)
        if not data:
            raise CommandError(f"{self.connector.name} answered with an empty file: nothing was kept", sent=True)
        scope = self._scope(args, steps, answer, sent=False)
        saved = part.request.save_as
        name = ex._text(ex.render_text(saved.name, scope).data) if saved is not None and saved.name else ""
        kind = ex._text(ex.render_text(saved.type, scope).data) if saved is not None and saved.type else ""
        name = clean_name(name) or clean_name(_file_name(answer["headers"], url))
        kind = kind.strip() or str(answer["headers"].get("content-type") or "").split(";")[0].strip()
        kept = self.store.keep(data, name, kind)
        answer["response"] = {key: kept.get(key) for key in FILE_FIELDS}
        answer["kept"] = True

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
        raise CommandError(_redact(said, self._hidden), retry=status == 429 or status >= 500, sent=True, status=status)

    # ------------------------------------------------------------ credentials --
    def _credentials(self) -> dict[str, str]:
        auth = self.connector.auth
        if auth is None:
            return {}
        secret = self.secrets
        if auth.type == "basic":
            pair = f"{secret.get('username', '')}:{secret.get('password', '')}".encode()
            return {"Authorization": "Basic " + base64.b64encode(pair).decode("ascii")}
        # A key that was not given is not sent: an API that also answers without one is asked without.
        if auth.type == "bearer":
            return {"Authorization": f"Bearer {secret['token']}"} if secret.get("token") else {}
        if auth.type == "header":
            return {str(auth.header): f"{auth.prefix}{secret['value']}"} if secret.get("value") else {}
        if auth.type == "query":
            return {}
        if auth.type == "oauth2_client":
            return {"Authorization": f"Bearer {self._oauth_token(auth)}"}
        if self._session is None:
            self._session = self._login_zscaler() if auth.type == "zscaler" else self._login(auth)
        return dict(self._session)

    def _query_credentials(self) -> dict[str, str]:
        """The key of an instance that goes in the address (``query`` credentials): never recorded, since
        what a step shows of a request stops at the question mark."""
        auth = self.connector.auth
        if auth is None or auth.type != "query" or not self.secrets.get("value"):
            return {}
        return {str(auth.param): self.secrets["value"]}

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
        return self._pages(
            command.request,
            command.pagination,
            command.success,
            command.error,
            command.timeout,
            lambda: self._scope(args, {}, sent=True),
            lambda answer: self._scope(args, {}, answer, sent=False),
            MAX_ITEMS,
        )

    def fetch(self, spec: Any, state: dict[str, Any], first: dict[str, Any], now: dict[str, Any], limit: int) -> dict:
        """Read the items of one cycle of a fetch: ``{"items", "truncated", "response", "status", "headers"}``.

        The request reads ``state`` (and ``first``, ``now``); nobody gives it arguments. With
        ``pagination`` the pages are read to the end or to ``limit`` items; without, ``items`` says
        where they are in the one answer."""
        base = {"config": self.config, "state": state, "first": first, "now": now}

        def sent() -> ex.Scope:
            return ex.Scope(values={**base, "secret": self.secrets})

        def read(answer: dict) -> ex.Scope:
            held = {**base, "response": answer["response"], "status": answer["status"], "headers": answer["headers"]}
            return ex.Scope(values=held)

        if spec.pagination is not None:
            paged = self._pages(spec.request, spec.pagination, spec.success, spec.error, 60, sent, read, limit)
            answer = paged["response"]
            return {"items": answer["items"], "truncated": answer["truncated"], **paged}
        answer = self._raw(spec.request, sent(), timeout=60)
        after = read(answer)
        self._judge(answer, spec.success, spec.error, after)
        try:
            found = ex.render_text(str(spec.items), after).data
        except ex.ExpressionError:
            found = []
        found = found if isinstance(found, list) else []
        return {"items": found[:limit], "truncated": len(found) > limit, **answer}

    def _pages(self, request, page, success, error, timeout, sent_scope, answer_scope, limit: int) -> dict[str, Any]:
        """The loop of a paged request, for a command and for a fetch: who reads what is said by the two scopes."""
        items: list[Any] = []
        cursor: Any = None
        offset = 0
        number = 1
        next_url: str | None = None
        last: dict[str, Any] = {"response": {}, "status": 0, "headers": {}}
        truncated = False
        kept: dict[str, Any] = {}
        # The size of a page and how many are read may come from an argument: within the bounds of the file's own.
        size = self._bounded(page.limit, sent_scope(), PAGE_MAX, "limit")
        pages = self._bounded(page.max_pages, sent_scope(), MAX_PAGES, "max_pages")
        for count in range(pages):
            spec = request
            extra: dict[str, Any] = {}
            if page.limit_param:
                extra[page.limit_param] = size
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
            last = self._raw(spec, sent_scope(), timeout=timeout)
            after = answer_scope(last)
            self._judge(last, success, error, after)
            if count == 0:
                for key, template in page.keep.items():
                    try:
                        kept[key] = ex.render(template, after).data
                    except ex.ExpressionError:
                        kept[key] = None  # the first page did not say it
            try:
                found = ex.render_text(page.items, after).data
            except ex.ExpressionError:
                found = []
            found = found if isinstance(found, list) else []
            items += found
            if len(items) >= limit:
                items, truncated = items[:limit], True
                break
            if page.type in ("offset", "page"):
                if len(found) < size:
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
            if count == pages - 1:
                truncated = True
        response = {"items": items, "pages": count + 1, "truncated": truncated, **({"kept": kept} if page.keep else {})}
        return {"response": response, **{key: last[key] for key in ("status", "headers")}}

    @staticmethod
    def _bounded(value: Any, scope: ex.Scope, most: int, what: str) -> int:
        """A number of the pagination that may be a template: from 1 to ``most``, whatever was asked."""
        if isinstance(value, str):
            value = ex.render_text(value, scope).data
            if isinstance(value, str) and value.strip().isdigit():
                value = int(value.strip())
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise CommandError(f'The "{what}" of the pagination is not a number')
        return max(1, min(int(value), most))

    def _one(self, part: Command | Step, args: dict, steps: dict, timeout: float) -> dict[str, Any]:
        """One request of a command or of a step, judged. A file that came with it is kept first."""
        answer = self._raw(part.request, self._scope(args, steps, sent=True), timeout=timeout)
        if "file" in answer:
            self._kept(part, args, steps, answer)
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
        # The other side may say when to ask again (Retry-After): it is waited for, when it is longer.
        return now + max(float(poll.every), _retry_after(answer["headers"], now))

    def run(self, name: str, args: dict[str, Any], state: dict[str, Any] | None = None) -> Answer:
        """Run a command, or go on with one that asked to be called again. Raises ``CommandError``."""
        command = self.connector.command(name)
        if command is None:
            raise CommandError("This command is not in the connector any more")
        args = self._arguments(command, args)
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
                return Answer(
                    outputs=self._outputs(command, args, {}, answer),
                    records=self.records,
                    context=self._context(command, args, {}, answer),
                    classes=self._output_classes,
                )
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
            return Answer(
                outputs=self._outputs(command, args, steps, last),
                records=self.records,
                context=self._context(command, args, steps, last),
                classes=self._output_classes,
            )
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

    def _arguments(self, command: Command, given: dict[str, Any]) -> dict[str, Any]:
        """Every declared argument can be read: one that was not given has its default (the file's, or
        the value the instance has for it), or is null and so left out of what is sent."""
        defaults = {
            argument.name: self.config.get(argument.default_from) if argument.default_from else argument.default
            for argument in command.arguments
        }
        return {**defaults, **given}

    def _wait(self, again_at: float, state: dict[str, Any]) -> Answer:
        """Give the step back, to be called again: a session that is open stays open, and travels with it."""
        self._waiting = True
        if self._session is not None:
            state["session"] = dict(self._session)
        return Answer(again_at=again_at, state=state, records=self.records)

    def _context(self, command: Command, args: dict, steps: dict, answer: dict) -> list[tuple[str, Any]]:
        """What the command says goes to the context: a value the answer does not hold is left out."""
        scope = self._scope(args, steps, answer, sent=False)
        found = []
        for item in command.context:
            try:
                value = _pruned(ex.render(item.value, scope).data)
            except ex.ExpressionError:
                continue
            if value not in (None, "", [], {}):
                found.append((item.path, _redact(value, self._hidden)))
        return found

    def _outputs(self, command: Command, args: dict, steps: dict, answer: dict) -> dict[str, Any]:
        scope = self._scope(args, steps, answer, sent=False)
        out: dict[str, Any] = {}
        self._output_classes = {}
        for key, template in command.outputs.items():
            try:
                out[key] = ex.render(template, scope).data
            except ex.ExpressionError:
                out[key] = None  # the answer did not hold it: the output is empty, not an error
                continue
            if scope.classes:
                # Only a file that was kept has classes here: its name, its hash, its id in Nik.
                self._output_classes.update(ex.render_classes({key: template}, scope))
        if not command.outputs:
            if answer.get("kept"):
                # A command that keeps a file and says nothing more gives what describes the file.
                out = dict(answer["response"])
                self._output_classes = dict(FILE_CLASSES)
            else:
                out = {"response": answer["response"]}
        return _redact(out, self._hidden)

    def would_send(self, name: str, args: dict[str, Any]) -> dict[str, Any]:
        """What a command would send first, for a dry run: nothing leaves."""
        command = self.connector.command(name)
        if command is None:
            raise CommandError("This command is not in the connector any more")
        args = self._arguments(command, args)
        spec = command.request if command.request is not None else command.steps[0].request
        scope = self._scope(args, {}, sent=True)
        path = str(ex.render_text(spec.path, scope).data)
        url = self._url(path)
        _scheme, host, _port, target, _address = egress.destination(self.policy, url, allow_http=self.allow_http)
        # An API that takes its key in the address (/exports/<key>/full.csv) has a secret in the path: it is
        # replaced here as in what a real request records.
        path = _redact(target.split("?")[0][:300], self._hidden)
        would = {"method": spec.method, "host": host, "path": path, "dry_run": True}
        # The files of the first request, as they would go: what they are, never their bytes. The guard
        # is asked as it would be, so that a dry run says what a real one would hold.
        files = self._files(spec, scope)
        self._judged(files)
        if files:
            would["files"] = [{key: item[key] for key in ("field", "name", "type", "size", "sha256")} for item in files]
        if command.gives_file:
            would["keeps"] = "a file, as an artifact"
        return would

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
