"""Connectors: one YAML file per product, read and checked here.

A connector says how to talk to a product without any code: what a
connection needs (an address, credentials), and commands, each a request
built from templates in the playbooks' own expression language. Each command
becomes an action of the canvas, ``<connector id>.<command>``.

    name: ServiceNow
    id: servicenow
    version: 1
    configuration:
      - { name: url, type: url, required: true }
      - { name: credentials, type: basic }
    base_url: "{{ config.url }}"
    commands:
      - name: get-incident
        arguments: [{ name: number, type: text, required: true }]
        request: { method: GET, path: /api/now/table/incident, query: { sysparm_query: "number={{ args.number }}" } }
        outputs: { sys_id: "{{ response.result[0].sys_id }}" }

This module only reads and validates (``load``): a file is refused with every
problem and the **line** each is on, because these files are written by hand.
Running a command is ``connector_runtime.py``; the format is documented key by
key in ``docs/automation.html``.

Templates may read ``config`` (the connection's values), ``args``,
``steps`` (the answers of earlier steps of the same command), ``now`` (the
moment the command runs: ``now.iso``, ``now.epoch``, ``now.epoch_ms``) and,
where an answer exists, ``response``, ``status`` and ``headers``. Secrets are
read as ``secret.<name>`` and only in what is sent, never in ``outputs``.

**Files.** A command may give a file instead of something to read
(``answer: file``): the bytes go to Nik's store as an artifact, never opened,
and ``response`` is what describes it (``name``, ``type``, ``size``,
``sha256``, ``artifact``). A command may send a file Nik holds: a part of a
multipart form (``files``) or the body itself (``body_file``), each naming
an artifact, usually through an argument of type ``file``. A command that
sends a file changes the outside, and its file must say so.

**Doing a command twice.** A step of a playbook can be cut by a restart after
its request left and before its answer was kept; nobody then knows whether
the other side acted. What Nik does next depends on three keys of the command:

- ``changes_outside: false`` (the default): it only reads. It is done again.
- ``changes_outside: true`` with ``idempotent: true`` (the default): doing it
  twice leaves the other side as doing it once (it sets a state: isolate this
  host, close this ticket). It is done again.
- ``changes_outside: true`` with ``idempotent: false``: twice is two things
  (a ticket, a comment, a mail). It is **not** done again: the run waits for a
  person to say whether it happened.
- ``idempotency_key: true``, for a product that takes a key with a request and
  acts once per key: the command sends ``{{ idempotency.key }}`` where the
  product wants it (a header, a field of the body), Nik gives every try of the
  same step the same key, and the command is done again whatever
  ``idempotent`` says. The key is 32 hexadecimal characters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from . import expressions as ex

MAX_BYTES = 1_000_000  # a connector with every command of a large API is a long file
ID_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")
NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,39}$")
COMMAND_RE = re.compile(r"^[a-z][a-z0-9-]{1,48}$")
METHODS = ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE")
OPERATORS = ("eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "exists", "empty")

# The credentials a connection can be asked for; anything else it is asked for is a plain value.
AUTH_TYPES = ("basic", "bearer", "header", "query", "oauth2_client", "session", "zscaler")
# The commands Nik's own code has for each kind of native connector (automation/mail_runtime.py).
NATIVE: dict[str, frozenset[str]] = {
    "mail": frozenset(
        {
            "send",
            "reply",
            "forward",
            "search",
            "get-message",
            "get-attachments",
            "move",
            "mark-read",
            "mark-unread",
            "delete",
            "list-folders",
        }
    ),
}

MAX_PAGES = 100
PAGE_MAX = 1000
FETCH_MIN_INTERVAL = 30
FETCH_MAX_INTERVAL = 86_400
LOOKBACK_MAX_MINUTES = 1440
_FIRST_FETCH = re.compile(r"^\s*(\d{1,4})\s*(minute|hour|day)s?\s*$")


def first_fetch_seconds(text: str) -> int | None:
    """``3 days`` as seconds; None when it is not a length of time (a month at most)."""
    found = _FIRST_FETCH.match(str(text).lower())
    if found is None:
        return None
    seconds = int(found.group(1)) * {"minute": 60, "hour": 3600, "day": 86400}[found.group(2)]
    return seconds if 0 < seconds <= 31 * 86400 else None


MAX_STEPS = 12
# The name of a host as a connector may list it: labels of letters, digits and -, two at least.
HOST_RE = re.compile(r"^(?=.{4,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")
POLL_MIN, POLL_MAX_TIMEOUT = 2, 3600


class _Strict(BaseModel):
    """Unknown keys are errors: a typo in a hand-written file must not pass silently."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class Comparison(_Strict):
    left: Any
    op: Literal["eq", "ne", "gt", "gte", "lt", "lte", "contains", "in", "exists", "empty"]
    right: Any = None


class Conditions(_Strict):
    """``all`` or ``any`` of comparisons, as in a condition node."""

    all: list[Comparison] | None = None
    any: list[Comparison] | None = None

    @model_validator(mode="after")
    def _one(self):
        if (self.all is None) == (self.any is None) or not (self.all or self.any):
            raise ValueError('needs "all" or "any" with at least one comparison')
        return self


class SaveAs(_Strict):
    """What a file that comes back is called and is, when the answer does not say it well enough.

    Both are templates over the answer (``headers``, ``status``) and what was asked (``args``,
    ``config``). Left out, the name is the one the answer gives (``Content-Disposition``), or the
    last part of the address, and the type is the answer's ``Content-Type``."""

    name: str | None = Field(default=None, min_length=1, max_length=500)
    type: str | None = Field(default=None, min_length=1, max_length=200)


class Unpack(_Strict):
    """A file that comes back is an archive, and the files inside it are what is wanted.

    The archive is kept as it came and each file inside it becomes an artifact of its own, taken out
    of the archive: read in memory, never run, never written anywhere but the store. ``password`` is a
    template over what is sent (``args``, ``config``, ``secret``): an archive of collected files is
    usually protected, and the password is the one the request asked for. It is treated as a secret:
    an argument it reads is not shown in the run."""

    format: Literal["zip"] = "zip"
    password: str | None = Field(default=None, min_length=1, max_length=500)


class FilePart(_Strict):
    """A file Nik holds, as a request sends it: which one, under what name, as what type.

    ``artifact`` is a template that gives the artifact (``file-<sha256>``) or its SHA-256, usually
    ``"{{ args.<an argument of type file> }}"``. Left out, the name is the one the artifact has."""

    artifact: str = Field(min_length=1, max_length=500)
    name: str | None = Field(default=None, min_length=1, max_length=500)
    type: str = Field(default="application/octet-stream", min_length=1, max_length=200)

    @model_validator(mode="after")
    def _names_one(self):
        if "{{" not in self.artifact:
            raise ValueError('"artifact" is a template that gives the file: "{{ args.file }}"')
        return self


class RequestSpec(_Strict):
    """One HTTP request. ``path`` is added to the connector's ``base_url`` (a full address is taken as it is)."""

    method: Literal["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"] = "GET"
    path: str = Field(min_length=1, max_length=2000)
    query: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    json_body: Any = Field(default=None, alias="json")
    form: dict[str, Any] | None = None
    multipart: dict[str, Any] | None = None
    body: str | None = None
    # Files Nik holds, sent as parts of a multipart form (beside the text fields of "multipart"), by field name.
    files: dict[str, FilePart] | None = None
    # A file Nik holds, sent as the body itself.
    body_file: FilePart | None = None
    # How the answer is read: "auto" as JSON when it is JSON, as text otherwise ({{ response.text }});
    # "text" always as text, for a file whose content may happen to be JSON; "file" not at all: the
    # bytes are kept as an artifact and {{ response }} describes it.
    answer: Literal["auto", "text", "file"] = "auto"
    save_as: SaveAs | None = None
    # The file that comes back is an archive: the files inside it are kept as artifacts too.
    unpack: Unpack | None = None

    @model_validator(mode="after")
    def _one_body(self):
        bodies = ("json_body", "form", "multipart", "body", "body_file")
        given = [name for name in bodies if getattr(self, name) is not None]
        if len(given) > 1:
            raise ValueError("a request has one of json, form, multipart, body, body_file")
        if self.files is not None:
            if not self.files:
                raise ValueError('"files" is empty')
            if len(self.files) > 10:
                raise ValueError("a request sends 10 files at most")
            if given and given != ["multipart"]:
                raise ValueError('"files" are parts of a multipart form: beside them, only "multipart"')
            given.append("files")
        if given and self.method in ("GET", "HEAD"):
            raise ValueError(f"a {self.method} request has no body")
        if self.save_as is not None and self.answer != "file":
            raise ValueError('"save_as" belongs to a request whose answer is a file: answer: file')
        if self.unpack is not None and self.answer != "file":
            raise ValueError('"unpack" belongs to a request whose answer is a file: answer: file')
        return self

    @property
    def sends_file(self) -> bool:
        return self.files is not None or self.body_file is not None


class Success(_Strict):
    status: list[int] | int | None = None
    when: Conditions | None = None  # besides the status: what the answer must say

    def statuses(self) -> set[int] | None:
        if self.status is None:
            return None
        return {self.status} if isinstance(self.status, int) else set(self.status)


class ErrorSpec(_Strict):
    message: str = Field(min_length=1, max_length=1000)


class Pagination(_Strict):
    """How a list that comes in pages is read to the end (or to ``max_pages``)."""

    type: Literal["offset", "page", "cursor", "link"]
    items: str = Field(min_length=1, max_length=500)  # "{{ response.result }}"
    param: str | None = None  # offset / page / cursor: the query parameter that moves
    limit_param: str | None = None
    # How many items a page holds and how many pages are read: a number, or a template that gives
    # one ("{{ args.limit }}"), kept within the same bounds when the command runs.
    limit: int | str = 100
    next: str | None = None  # cursor: "{{ response.pagination.nextCursor }}"
    max_pages: int | str = 10
    # What the first page says beside its items (a total, a query id): templates over that answer,
    # read as {{ response.kept.<name> }} beside {{ response.items }}.
    keep: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _shape(self):
        for name, most in (("limit", PAGE_MAX), ("max_pages", MAX_PAGES)):
            value = getattr(self, name)
            if isinstance(value, bool) or (isinstance(value, int) and not 1 <= value <= most):
                raise ValueError(f'"{name}" is a number from 1 to {most}, or a template that gives one')
            if isinstance(value, str) and "{{" not in value:
                raise ValueError(f'"{name}" is a number from 1 to {most}, or a template that gives one')
        if len(self.keep) > 20:
            raise ValueError('"keep" holds 20 values at most')
        if self.type in ("offset", "page") and not self.param:
            raise ValueError(f'"{self.type}" pagination needs "param"')
        if self.type == "cursor" and not (self.param and self.next):
            raise ValueError('"cursor" pagination needs "param" and "next"')
        return self


class Poll(_Strict):
    """Send the request again until the answer says so. Between tries the run waits; no worker is held."""

    until: Conditions
    every: int = Field(default=5, ge=POLL_MIN, le=600)
    timeout: int = Field(default=300, ge=POLL_MIN, le=POLL_MAX_TIMEOUT)
    fail_when: Conditions | None = None


class Step(_Strict):
    """One request of a command that needs several (change, publish, install)."""

    name: str
    request: RequestSpec
    success: Success | None = None
    error: ErrorSpec | None = None
    poll: Poll | None = None
    when: Conditions | None = None  # skipped unless it holds

    @model_validator(mode="after")
    def _name(self):
        if not NAME_RE.match(self.name):
            raise ValueError("a step's name is a lower-case letter, then letters, digits or _")
        return self


class Argument(_Strict):
    name: str
    # "file" is an artifact Nik holds, by its id (file-<sha256>) or its SHA-256: what "files" and "body_file" send.
    type: Literal["text", "number", "bool", "list", "object", "any", "choice", "file"] = "text"
    required: bool = False
    default: Any = None
    # The configuration entry whose value is the default, when the instance says it and not the file.
    default_from: str | None = None
    choices: list[str] | None = None
    description: str = Field(default="", max_length=300)

    @model_validator(mode="after")
    def _shape(self):
        if not NAME_RE.match(self.name):
            raise ValueError("an argument's name is a lower-case letter, then letters, digits or _")
        if self.type == "choice" and not self.choices:
            raise ValueError('a "choice" argument needs "choices"')
        if self.default is not None and self.default_from is not None:
            raise ValueError('an argument has "default" or "default_from", not both')
        if self.type == "file" and (self.default is not None or self.default_from is not None):
            raise ValueError("an argument of type file has no default")
        return self


class ContextOutput(_Strict):
    """Where a result goes in the context of the incident the playbook works on.

    ``path`` is a context path (``Ticket(val.ID == obj.ID)``, ``ext.<this connector>.<name>``,
    ``incident.<field>``); ``value`` a template over the answer, usually an object with the
    keys of the entity."""

    path: str = Field(min_length=1, max_length=200)
    value: Any


class Command(_Strict):
    name: str
    description: str = Field(default="", max_length=500)
    changes_outside: bool = False
    idempotent: bool = True
    # The command sends {{ idempotency.key }} and the product acts once per key: a second try of the
    # same step is safe, whatever "idempotent" says.
    idempotency_key: bool = False
    # The vendor gives this command only to a paid plan: said in the library and on the node, never enforced
    # here (the vendor answers what it answers to the key it is asked with).
    premium: bool = False
    arguments: list[Argument] = Field(default_factory=list, max_length=40)
    request: RequestSpec | None = None
    steps: list[Step] | None = Field(default=None, max_length=MAX_STEPS)
    success: Success | None = None
    error: ErrorSpec | None = None
    pagination: Pagination | None = None
    poll: Poll | None = None
    outputs: dict[str, Any] = Field(default_factory=dict)
    context: list[ContextOutput] = Field(default_factory=list, max_length=20)
    # A command that says what is known of an indicator of this kind: the look-ups of indicators and
    # "!ip", "!domain"… of the War Room ask it. Its first argument is the value; its "verdict" output is
    # counted, and "summary" and "link" are the line and the page shown with it (enrichment/sources.py).
    reputation: Literal["ip", "domain", "url", "file", "email"] | None = None
    # With ``reputation: domain``, for a source that knows registered domains and not the hosts under
    # them (a registry): a look-up gives the command ``example.co.uk`` for ``www.example.co.uk``.
    reputation_of: Literal["registered_domain"] | None = None
    sample: dict[str, Any] | None = None
    timeout: int = Field(default=60, ge=1, le=300)

    def requests(self) -> list[RequestSpec]:
        """Every request the command makes, in order."""
        if self.request is not None:
            return [self.request]
        return [step.request for step in self.steps or []]

    @property
    def gives_file(self) -> bool:
        return any(request.answer == "file" for request in self.requests())

    @property
    def unpacks(self) -> bool:
        return any(request.unpack is not None for request in self.requests())

    @property
    def secret_arguments(self) -> set[str]:
        """The arguments the password of an archive is read from: not shown in a run."""
        found: set[str] = set()
        for request in self.requests():
            if request.unpack is not None and request.unpack.password:
                found.update(re.findall(r"\bargs\.([a-z][a-z0-9_]*)", request.unpack.password))
        return found

    @property
    def sends_file(self) -> bool:
        return any(request.sends_file for request in self.requests())

    @model_validator(mode="after")
    def _shape(self):
        if not COMMAND_RE.match(self.name):
            raise ValueError("a command's name is lower-case letters, digits and -: create-incident")
        # One or the other for a connector that speaks HTTP; neither for one Nik speaks for
        # (``native``), which the connector file checks: it is the one that knows which it is.
        if self.request is not None and self.steps is not None:
            raise ValueError('a command has "request" or "steps"')
        if self.steps is not None:
            if not self.steps:
                raise ValueError('"steps" is empty')
            if self.pagination or self.poll or self.success:
                raise ValueError('with "steps", pagination, poll and success belong to each step')
            names = [step.name for step in self.steps]
            if len(set(names)) != len(names):
                raise ValueError("two steps have the same name")
        if self.pagination and self.poll:
            raise ValueError("a command pages through a list or polls, not both")
        if self.reputation_of is not None and self.reputation != "domain":
            raise ValueError('"reputation_of" is for a command marked "reputation: domain"')
        for where, request, again in (
            ("the command", self.request, self.pagination or self.poll),
            *((f'the step "{step.name}"', step.request, step.poll) for step in self.steps or []),
        ):
            if request is None:
                continue
            if again and (request.answer == "file" or request.sends_file):
                # Asked again and again, it would keep the file each time, or send it each time.
                raise ValueError(f"{where} carries a file: it is not polled nor paged (use a step of its own)")
            if request.sends_file and not self.changes_outside:
                raise ValueError(
                    f"{where} sends a file Nik holds: the command says changes_outside: true, so that it is approved"
                )
        seen = set()
        for argument in self.arguments:
            if argument.name in seen:
                raise ValueError(f'two arguments are called "{argument.name}"')
            seen.add(argument.name)
        if self.idempotency_key and not any(
            "idempotency.key" in str(request.model_dump(exclude_none=True)) for request in self.requests()
        ):
            raise ValueError(
                '"idempotency_key: true" is for a command that sends {{ idempotency.key }} to the product: '
                "no request of this one does"
            )
        return self

    @property
    def safe_to_repeat(self) -> bool:
        """Whether a second try of the same step does no harm on the other side."""
        return not self.changes_outside or self.idempotent or self.idempotency_key


class FetchSpec(_Strict):
    """How a connection brings alerts in: one request, read to the end of its pages, again and again.

    A request that filters by time reads ``since`` (``since.iso``, ``since.epoch``,
    ``since.epoch_ms``): the moment to ask from, which Nik works out. Before the first cycle it is
    the moment ``first_fetch`` ago; afterwards the newest time the cycles saw on an item, less the
    look-back of the instance. The time of an item is ``item_time``, or ``occurred`` when the
    request filters on that. The comparison is to include the moment itself (``>=``): what comes
    back a second time is skipped, because each item is told apart by ``item_id``.

    A request that goes on from a cursor reads ``state`` instead: what the last cycle left in
    ``next_state``, and before the first cycle what ``first_state`` says, which reads ``first``
    (the moment ``first_fetch`` ago). ``interval_seconds``, ``first_fetch`` and
    ``lookback_minutes`` are what an instance starts with: each is changed in the instance."""

    interval_seconds: int = Field(default=120, ge=FETCH_MIN_INTERVAL, le=FETCH_MAX_INTERVAL)
    first_fetch: str = Field(default="3 days", max_length=40)
    lookback_minutes: int = Field(default=0, ge=0, le=LOOKBACK_MAX_MINUTES)
    # None for a native connector, whose runtime knows how to read what is new.
    request: RequestSpec | None = None
    success: Success | None = None
    error: ErrorSpec | None = None
    pagination: Pagination | None = None
    # Where the items are in the answer, when it does not come in pages (pagination says it otherwise).
    items: str | None = Field(default=None, max_length=500)
    item_id: str = Field(min_length=1, max_length=500)  # "{{ item.id }}"
    occurred: str | None = Field(default=None, max_length=500)  # "{{ item.createdAt }}"
    # The time of an item the request filters on, when it is not ``occurred``.
    item_time: str | None = Field(default=None, max_length=500)  # "{{ item.sys_created_on }}"
    first_state: dict[str, Any] = Field(default_factory=dict)  # { last_time: "{{ first.iso }}" }
    next_state: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _shape(self):
        if first_fetch_seconds(self.first_fetch) is None:
            raise ValueError('"first_fetch" is a length of time: 30 minutes, 12 hours, 3 days')
        if self.request is not None and (self.pagination is None) == (self.items is None):
            raise ValueError('a fetch says where its items are: "items", or the "items" of its "pagination"')
        if "{{" not in self.item_id:
            raise ValueError('"item_id" is a template over the item: "{{ item.id }}"')
        if len(self.next_state) > 20 or len(self.first_state) > 20:
            raise ValueError("the state of a fetch holds 20 values at most")
        if any(str(name).startswith("_") for name in (*self.first_state, *self.next_state)):
            raise ValueError("a name of the state does not start with _: those are kept for Nik")
        return self

    @property
    def first_seconds(self) -> int:
        return first_fetch_seconds(self.first_fetch) or 0

    @property
    def by_time(self) -> bool:
        """Whether the request asks from a moment (it reads ``since``): the look-back applies to it."""
        sent = [self.request.model_dump() if self.request is not None else None]
        sent.append(self.pagination.model_dump() if self.pagination is not None else None)
        return _reads(sent, "since")


def _reads(value: Any, name: str) -> bool:
    """Whether a template somewhere under ``value`` reads ``name``."""
    if isinstance(value, dict):
        return any(_reads(item, name) for item in value.values())
    if isinstance(value, (list, tuple)):
        return any(_reads(item, name) for item in value)
    if not isinstance(value, str) or "{{" not in value:
        return False
    try:
        return any(found == name for found, _position in ex.references(value))
    except ex.ExpressionError:
        return False


class SchemaField(_Strict):
    """A field of the other product, by the name the product gives it."""

    name: str = Field(min_length=1, max_length=200)
    type: Literal["text", "number", "bool", "date", "list", "object"] = "text"
    description: str = Field(default="", max_length=300)


class SchemaSpec(_Strict):
    """The names the other product uses: what a fetched item holds, what a create or update takes.
    The mapper editor offers them."""

    incoming: list[SchemaField] = Field(default_factory=list, max_length=300)
    outgoing: list[SchemaField] = Field(default_factory=list, max_length=300)


class ExtField(_Strict):
    """A field this connector adds to the context of an incident, under ``ext.<connector id>``."""

    name: str
    type: Literal["text", "number", "bool", "date", "list", "object"] = "text"
    description: str = Field(default="", max_length=300)

    @model_validator(mode="after")
    def _name(self):
        if not NAME_RE.match(self.name):
            raise ValueError("an ext field's name is a lower-case letter, then letters, digits or _")
        return self


class MirrorCall(_Strict):
    """A command of this connector that mirroring runs, and what it is given.

    ``args`` are templates: ``mirror.id`` (the id of the object on the other side), ``fields``
    (what the outgoing mapper gave, for an update), ``comment`` (the text of a note to send),
    ``since`` (the last comment that came in). With no ``args``, the id goes to the first argument."""

    command: str = Field(min_length=1, max_length=50)
    args: dict[str, Any] = Field(default_factory=dict)


class MirrorComments(_Strict):
    list: MirrorCall
    # Where the comments are in the result of ``list``, and what one is.
    items: str = Field(default="{{ result.comments }}", max_length=500)
    id: str = Field(default="{{ item.id }}", max_length=500)
    text: str = Field(default="{{ item.text }}", max_length=500)
    author: str = Field(default="{{ item.author }}", max_length=500)
    at: str = Field(default="{{ item.created }}", max_length=500)
    add: MirrorCall | None = None


class MirrorKind(_Strict):
    """Another object of the product that an incident can be kept in step with (an alert beside a
    threat): what is read, written and said of it. An incident is mirrored with one of a kind when
    the id of its mirror is written ``<kind>:<id>``; the calls are then given the id alone, as
    ``mirror.id``, and the kind as ``mirror.kind``."""

    get: MirrorCall
    item: str = Field(default="{{ result }}", max_length=500)
    update: MirrorCall | None = None
    comments: MirrorComments | None = None


class MirrorThread(_Strict):
    """A mirror the fetch feeds: an item that goes on with a conversation Nik already holds as an
    incident becomes a line of its War Room and not an incident of its own (a reply to a message).

    ``ids`` is a template over the fetched ``item`` that gives the ids of the earlier items this one
    goes on from (a list, or a text of ids separated by spaces or commas); the id of the item itself
    is ``mirror.id``. An incident mirrored in holds the ids of its conversation: an item that names
    one of them, or is named by one, belongs to it. ``text``, ``author`` and ``at`` are what the
    line says. Nothing is read at an interval and nothing is sent."""

    ids: str = Field(min_length=1, max_length=500)
    text: str = Field(default="{{ item.text }}", max_length=500)
    author: str = Field(default="{{ item.author }}", max_length=500)
    at: str = Field(default="{{ item.created }}", max_length=500)


class MirrorSpec(_Strict):
    """Keeping an incident and one object of the other product in step."""

    # The id, on the other side, of the object a fetched item is: a template over the ``item``.
    # Left out, it is the ``item_id`` of the fetch. With ``kinds`` it may give ``<kind>:<id>``.
    id: str | None = Field(default=None, min_length=1, max_length=500)
    # None for a mirror the fetch feeds (``thread``): there is nothing to read at an interval.
    get: MirrorCall | None = None
    # The object in what ``get`` gave, in the shape a fetched item has: the incoming mapper reads it as ``item``.
    item: str = Field(default="{{ result }}", max_length=500)
    update: MirrorCall | None = None
    comments: MirrorComments | None = None
    interval_seconds: int = Field(default=120, ge=FETCH_MIN_INTERVAL, le=86_400)
    kinds: dict[str, MirrorKind] = Field(default_factory=dict)
    thread: MirrorThread | None = None

    @model_validator(mode="after")
    def _shape(self):
        if self.get is None and self.thread is None:
            raise ValueError('a mirror says how the other side is read: "get", or "thread" when the fetch feeds it')
        if self.get is None and (self.update is not None or self.comments is not None or self.kinds):
            raise ValueError('a mirror with no "get" is fed by the fetch: it has no "update", "comments" nor "kinds"')
        if self.id is not None and "{{" not in self.id:
            raise ValueError('"id" is a template over the fetched item: "{{ item.id }}"')
        if len(self.kinds) > 10:
            raise ValueError("a mirror has 10 kinds at most")
        for name in self.kinds:
            if not NAME_RE.match(str(name)):
                raise ValueError("the name of a kind is a lower-case letter, then letters, digits or _")
        return self

    def of(self, mirror_id: str) -> tuple[str, str, MirrorSpec | MirrorKind]:
        """The kind an id names, the id without it, and what says how that kind is mirrored."""
        kind, colon, rest = str(mirror_id).partition(":")
        if colon and rest and kind in self.kinds:
            return kind, rest, self.kinds[kind]
        return "", str(mirror_id), self


def can_send(part: MirrorSpec | MirrorKind) -> bool:
    """Whether something can be sent to the other side: its fields, or a comment."""
    return part.update is not None or (part.comments is not None and part.comments.add is not None)


class Login(_Strict):
    """``session`` credentials: how a session is opened, where its token is, how it is sent."""

    request: RequestSpec
    token: str = Field(min_length=1, max_length=500)  # "{{ response.sid }}"
    header: str = Field(min_length=1, max_length=100)  # X-chkp-sid, Authorization
    prefix: str = Field(default="", max_length=40)  # "Bearer "
    success: Success | None = None


class Logout(_Strict):
    request: RequestSpec


class ConfigParam(_Strict):
    """One thing a connection is asked for."""

    name: str
    label: str = Field(default="", max_length=100)
    type: Literal[
        "url", "text", "number", "bool", "choice", "hosts", "secret", "basic", "bearer", "header", "query",
        "oauth2_client", "session", "zscaler",
    ] = "text"  # fmt: skip
    required: bool = False
    default: Any = None
    choices: list[str] | None = None
    help: str = Field(default="", max_length=500)
    # header: the name of the header the secret goes in, and what precedes it.
    header: str | None = Field(default=None, max_length=100)
    prefix: str = Field(default="", max_length=40)
    # query: the name of the query parameter the secret goes in (an API that takes its key in the address).
    param: str | None = Field(default=None, max_length=100)
    # oauth2_client
    token_url: str | None = Field(default=None, max_length=2000)
    scope: str = Field(default="", max_length=500)
    auth_style: Literal["form", "basic"] = "form"
    # session
    login: Login | None = None
    logout: Logout | None = None

    @model_validator(mode="after")
    def _shape(self):
        if not NAME_RE.match(self.name):
            raise ValueError("a name is a lower-case letter, then letters, digits or _")
        if self.type == "choice" and not self.choices:
            raise ValueError('a "choice" needs "choices"')
        if self.type == "header" and not self.header:
            raise ValueError('"header" credentials need "header": the name of the header')
        if self.type == "query" and not (self.param and re.fullmatch(r"[A-Za-z0-9_.-]+", self.param)):
            raise ValueError('"query" credentials need "param": the name of the query parameter')
        if self.type != "query" and self.param is not None:
            raise ValueError('"param" belongs to "query" credentials')
        if self.type == "oauth2_client" and not self.token_url:
            raise ValueError('"oauth2_client" credentials need "token_url"')
        if self.type == "session" and self.login is None:
            raise ValueError('"session" credentials need "login"')
        if self.type != "session" and (self.login or self.logout):
            raise ValueError('"login" and "logout" belong to "session" credentials')
        return self

    @property
    def is_auth(self) -> bool:
        return self.type in AUTH_TYPES


class TestSpec(_Strict):
    """What "Test the connection" sends, and what a good answer is."""

    request: RequestSpec
    expect: Success | None = None


class Lookups(_Strict):
    """How the verdicts of this connector's reputation commands count in the overall verdict of an indicator.

    ``weight`` is how much the source is trusted, 1 to 3. ``informational`` is for a source that gives
    facts rather than a judgement (who registered a domain, what a host exposes): it is counted only when
    it flags the value, never for staying silent."""

    weight: int = Field(default=1, ge=1, le=3)
    informational: bool = False


class ConnectorFile(_Strict):
    name: str = Field(min_length=1, max_length=80)
    id: str
    version: int = Field(ge=1, le=1_000_000)
    description: str = Field(default="", max_length=1000)
    api_version: str = Field(default="", max_length=200)  # the vendor's API this was written against
    verified: bool = False  # run against a real system by someone
    configuration: list[ConfigParam] = Field(default_factory=list, max_length=30)
    # What Nik speaks for, when the product is not reached over HTTP: the file then names the
    # commands, their arguments and what they give, and Nik's own code runs them (``NATIVE``).
    native: Literal["mail"] | None = None
    base_url: str = Field(default="", max_length=2000)
    headers: dict[str, str] = Field(default_factory=dict)
    test: TestSpec | None = None
    commands: list[Command] = Field(min_length=1, max_length=400)
    # Bringing alerts in, the names the product uses, what it adds to the context, two-way sync.
    fetch: FetchSpec | None = None
    schema_: SchemaSpec | None = Field(default=None, alias="schema")
    ext_fields: list[ExtField] = Field(default_factory=list, max_length=100)
    mirror: MirrorSpec | None = None
    # Why a connector that fetches cannot mirror: what it brings in has nothing to go back to, or the
    # vendor documents no way to read it again. A sentence, shown where the direction is chosen.
    no_mirror: str | None = Field(default=None, min_length=20, max_length=500)
    # Other hosts the commands may reach beside the one of ``base_url`` (6.1): a service of the same vendor
    # on another name (internetdb.shodan.io), the registries a redirector sends to. Fixed names, written
    # in the file: never a template, never an address. A command reaches one by giving the full https
    # address as its ``path``; the credentials of the instance are sent to the host of ``base_url`` only.
    more_hosts: list[str] = Field(default_factory=list, max_length=40)
    # The hosts a file may be downloaded from, when the file cannot name them: the name of a configuration
    # entry of type ``hosts``, which an administrator fills in the instance (6.6, download_hosts.py). Only a
    # request whose answer is a file goes there, without the credentials of the instance or any header of
    # the connector. Left out, a connector reaches its instance and ``more_hosts`` and nothing else.
    download_hosts_from: str | None = Field(default=None, max_length=60)
    # How its reputation commands count among the sources of the look-ups (6.5); weight 1 when left out.
    lookups: Lookups | None = None

    @field_validator("more_hosts")
    @classmethod
    def _hosts(cls, value: list[str]) -> list[str]:
        cleaned = []
        for host in value:
            if not isinstance(host, str) or not HOST_RE.match(host) or host.replace(".", "").isdigit():
                raise ValueError(f'more_hosts: "{host}" is not the name of a host (lower case, no address, no port)')
            cleaned.append(host)
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("more_hosts: a host is listed twice")
        return cleaned

    @field_validator("id")
    @classmethod
    def _id(cls, value: str) -> str:
        # On the field, so that it is reported together with the problems of other fields.
        if not ID_RE.match(value):
            raise ValueError("id: a lower-case letter, then lower-case letters, digits or - (2 to 41)")
        return value

    @model_validator(mode="after")
    def _shape(self):
        names = [param.name for param in self.configuration]
        if len(set(names)) != len(names):
            raise ValueError("two configuration entries have the same name")
        if sum(1 for param in self.configuration if param.is_auth) > 1:
            raise ValueError("a connector has one set of credentials at most")
        commands = [command.name for command in self.commands]
        if len(set(commands)) != len(commands):
            raise ValueError("two commands have the same name")
        listed = [param.name for param in self.configuration if param.type == "hosts"]
        if self.download_hosts_from is None:
            if listed:
                raise ValueError(
                    f'the configuration entry "{listed[0]}" is a list of hosts: "download_hosts_from" names it'
                )
        else:
            if listed != [self.download_hosts_from]:
                raise ValueError(
                    '"download_hosts_from" names the one configuration entry of type hosts: '
                    f"- {{ name: {self.download_hosts_from}, type: hosts }}"
                )
            if not any(command.gives_file for command in self.commands):
                raise ValueError('"download_hosts_from" is for a connector with a command whose answer is a file')
        if self.lookups is not None and not any(command.reputation for command in self.commands):
            raise ValueError('"lookups" is for a connector with a command marked "reputation"')
        if self.native is None:
            if not self.base_url:
                raise ValueError('"base_url" is missing')
            for command in self.commands:
                if command.request is None and command.steps is None:
                    raise ValueError(f'the command "{command.name}" has neither "request" nor "steps"')
            if self.fetch is not None and self.fetch.request is None:
                raise ValueError('"fetch" has no "request"')
        else:
            if self.base_url or self.headers or self.test is not None:
                raise ValueError('a native connector has no "base_url", "headers" nor "test"')
            if self.mirror is not None and self.mirror.get is not None:
                # Nik speaks for it: what comes in comes with its fetch, and nothing is asked again.
                raise ValueError('the "mirror" of a native connector is fed by its fetch: "thread", and no "get"')
            known = NATIVE[self.native]
            for command in self.commands:
                if command.request is not None or command.steps is not None:
                    raise ValueError(f'the command "{command.name}" of a native connector has no request')
                if command.name not in known:
                    raise ValueError(
                        f'"{command.name}" is not a command Nik has for {self.native}: {", ".join(sorted(known))}'
                    )
            if self.fetch is not None and (self.fetch.request is not None or self.fetch.pagination is not None):
                raise ValueError('the "fetch" of a native connector has no request')
        if self.no_mirror is not None and (self.mirror is not None or self.fetch is None):
            raise ValueError('"no_mirror" says why a connector that fetches does not mirror: with "fetch", no "mirror"')
        if self.mirror is not None and self.mirror.thread is not None and self.fetch is None:
            raise ValueError('a mirror with "thread" is fed by the fetch: the connector has none')
        ext = [item.name for item in self.ext_fields]
        if len(set(ext)) != len(ext):
            raise ValueError("two ext fields have the same name")
        for side in ("incoming", "outgoing"):
            listed = [item.name for item in getattr(self.schema_, side)] if self.schema_ is not None else []
            if len(set(listed)) != len(listed):
                raise ValueError(f"the {side} schema names a field twice")
        return self

    def mirror_calls(self) -> list[tuple[str, MirrorCall]]:
        """The commands mirroring runs, each with where it is named in the file."""
        if self.mirror is None:
            return []
        calls: list[tuple[str, MirrorCall]] = []
        parts = [("mirror", self.mirror), *((f"mirror.kinds.{name}", kind) for name, kind in self.mirror.kinds.items())]
        for where, part in parts:
            if part.get is not None:
                calls.append((f"{where}.get", part.get))
            if part.update is not None:
                calls.append((f"{where}.update", part.update))
            if part.comments is not None:
                calls.append((f"{where}.comments.list", part.comments.list))
                if part.comments.add is not None:
                    calls.append((f"{where}.comments.add", part.comments.add))
        return calls

    @property
    def auth(self) -> ConfigParam | None:
        return next((param for param in self.configuration if param.is_auth), None)

    def command(self, name: str) -> Command | None:
        return next((command for command in self.commands if command.name == name), None)


@dataclass(frozen=True)
class Problem:
    """What is wrong with a connector file, and on which line (1-based; 0 when it is the file itself)."""

    line: int
    message: str
    where: str = ""

    def as_dict(self) -> dict:
        return {"line": self.line, "message": self.message, "where": self.where}


class ConnectorError(ValueError):
    """A file that cannot be a connector: every problem found."""

    def __init__(self, problems: list[Problem]):
        self.problems = problems
        super().__init__(problems[0].message if problems else "Not a connector")


# --------------------------------------------------------------------------- #
# Lines                                                                       #
# --------------------------------------------------------------------------- #
def _lines(node: yaml.Node | None, path: tuple = (), out: dict | None = None) -> dict[tuple, int]:
    """path → line, for every mapping key and list item of the document."""
    out = {} if out is None else out
    if node is None:
        return out
    out[path] = node.start_mark.line + 1
    if isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            name = key.value if isinstance(key, yaml.ScalarNode) else str(key)
            out[(*path, name)] = key.start_mark.line + 1
            _lines(value, (*path, name), out)
            out[(*path, name)] = key.start_mark.line + 1
    elif isinstance(node, yaml.SequenceNode):
        for index, item in enumerate(node.value):
            _lines(item, (*path, index), out)
    return out


def _line_of(lines: dict[tuple, int], loc: tuple) -> int:
    """The line of the deepest part of ``loc`` the document has (aliases are tried under both names)."""
    path = tuple("json" if part == "json_body" else part for part in loc)
    while path:
        if path in lines:
            return lines[path]
        path = path[:-1]
    return lines.get((), 0)


def _where(loc: tuple) -> str:
    out = ""
    for part in loc:
        part = "json" if part == "json_body" else part
        out += f"[{part}]" if isinstance(part, int) else (f".{part}" if out else str(part))
    return out


# --------------------------------------------------------------------------- #
# Templates                                                                   #
# --------------------------------------------------------------------------- #
# The names a template may read, by where it is.
_SENT = frozenset({"config", "args", "steps", "secret", "now", "idempotency"})
_ANSWER = frozenset({"config", "args", "steps", "now", "response", "status", "headers"})
# What a file that came back is named from: the answer is not read, only what came with it.
_SAVED = _ANSWER - {"response"}
# A fetch: what its request reads, what is read from its answer, what is read of one item.
_FETCH_SENT = frozenset({"config", "secret", "state", "first", "now", "since"})
_FETCH_ANSWER = frozenset({"config", "state", "first", "now", "since", "response", "status", "headers", "items"})
_FETCH_ITEM = frozenset({"config", "state", "item"})
# Mirroring: what a call is given, and what is read of a comment.
_MIRROR_ARGS = frozenset({"mirror", "fields", "comment", "since", "incident", "context"})
_MIRROR_COMMENT = frozenset({"result", "item"})


def _check_templates(value: Any, allowed: frozenset, loc: tuple, lines: dict, problems: list[Problem]) -> None:
    """Every template under ``value`` parses and reads only the names it may read there."""
    if isinstance(value, str):
        if "{{" not in value:
            return
        try:
            found = ex.references(value)
        except ex.ExpressionError as error:
            problems.append(Problem(_line_of(lines, loc), f"{error.message} (in {value[:80]!r})", _where(loc)))
            return
        for name, _position in found:
            if name == "credentials" and name not in allowed:
                # A stored credential is named in a field of an instance; a file reads what the instance
                # holds as {{ secret.<name> }} and never knows where the value came from.
                problems.append(Problem(_line_of(lines, loc), ex.CREDENTIALS_ELSEWHERE, _where(loc)))
            elif name not in allowed:
                where = (
                    "what is sent"
                    if "secret" in allowed
                    else "what mirroring gives"
                    if "mirror" in allowed or "result" in allowed
                    else "what is read from the answer"
                )
                names = ", ".join(sorted(allowed))
                problems.append(
                    Problem(_line_of(lines, loc), f'"{name}" cannot be read in {where}: only {names}', _where(loc))
                )
    elif isinstance(value, dict):
        for key, item in value.items():
            if isinstance(key, str) and "{{" in key:
                # The name of a form field may be a template: it is checked like a value.
                _check_templates(key, allowed, (*loc, key), lines, problems)
            _check_templates(item, allowed, (*loc, key), lines, problems)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_templates(item, allowed, (*loc, index), lines, problems)


def _request_templates(
    raw: Any, loc: tuple, lines: dict, problems: list[Problem], sent: frozenset = _SENT, files: bool = True
) -> None:
    """The templates of one request. ``files`` is whether a file may come back or be sent there: only a
    command has a run to keep a file for, and a guard to judge the one it sends."""
    if not isinstance(raw, dict):
        return
    _check_templates({key: value for key, value in raw.items() if key != "save_as"}, sent, loc, lines, problems)
    _check_templates(raw.get("save_as"), _SAVED, (*loc, "save_as"), lines, problems)
    if not files and (raw.get("answer") == "file" or "files" in raw or "body_file" in raw):
        problems.append(
            Problem(_line_of(lines, loc), "Only a command keeps a file or sends one: not this request", _where(loc))
        )


def _check_command(raw: dict, loc: tuple, lines: dict, problems: list[Problem]) -> None:
    """The templates of one command (the document as parsed, so that lines can be named)."""
    answer = _ANSWER
    for key in ("request",):
        _request_templates(raw.get(key), (*loc, key), lines, problems)
    for key in ("outputs", "error", "success", "poll"):
        _check_templates(raw.get(key), answer, (*loc, key), lines, problems)
    for at, item in enumerate(raw.get("context") or []):
        if isinstance(item, dict):
            _check_templates(item.get("value"), answer, (*loc, "context", at, "value"), lines, problems)
    pagination = raw.get("pagination")
    if isinstance(pagination, dict):
        _check_templates(pagination, answer, (*loc, "pagination"), lines, problems)
    for index, step in enumerate(raw.get("steps") or []):
        if not isinstance(step, dict):
            continue
        here = (*loc, "steps", index)
        _request_templates(step.get("request"), (*here, "request"), lines, problems)
        for key in ("error", "success", "poll"):
            _check_templates(step.get(key), answer, (*here, key), lines, problems)
        _check_templates(
            step.get("when"), _ANSWER - {"response", "status", "headers"}, (*here, "when"), lines, problems
        )


# --------------------------------------------------------------------------- #
# Loading                                                                     #
# --------------------------------------------------------------------------- #
def load(text: str | bytes) -> ConnectorFile:
    """Read and check a connector file. Raises ``ConnectorError`` with every problem and its line."""
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError:
            raise ConnectorError([Problem(0, "The file is not UTF-8 text")]) from None
    if len(text.encode("utf-8")) > MAX_BYTES:
        raise ConnectorError([Problem(0, f"The file is larger than {MAX_BYTES // 1000} kB")])
    try:
        node = yaml.compose(text, Loader=yaml.SafeLoader)
        raw = yaml.safe_load(text)
    except yaml.YAMLError as error:
        mark = getattr(error, "problem_mark", None)
        what = getattr(error, "problem", None) or "The file is not valid YAML"
        raise ConnectorError([Problem(mark.line + 1 if mark else 0, f"Not valid YAML: {what}")]) from None
    if not isinstance(raw, dict):
        raise ConnectorError([Problem(1, "A connector is a mapping: name, id, version, base_url, commands")])
    lines = _lines(node)

    problems: list[Problem] = []
    connector: ConnectorFile | None = None
    try:
        connector = ConnectorFile.model_validate(raw)
    except ValidationError as error:
        for item in error.errors():
            loc = tuple(item["loc"])
            message = item["msg"].removeprefix("Value error, ")
            if item["type"] == "extra_forbidden":
                message = f'"{loc[-1]}" is not a key that is known here'
            elif item["type"] == "missing":
                message = f'"{loc[-1]}" is missing'
                loc = loc[:-1]
            problems.append(Problem(_line_of(lines, loc), message, _where(tuple(item["loc"]))))

    # Templates: checked on the document as written, so that each problem has its line.
    _check_templates(raw.get("base_url"), frozenset({"config"}), ("base_url",), lines, problems)
    _check_templates(raw.get("headers"), _SENT - {"steps", "args"}, ("headers",), lines, problems)
    test = raw.get("test")
    if isinstance(test, dict):
        _request_templates(test.get("request"), ("test", "request"), lines, problems, files=False)
    for index, param in enumerate(raw.get("configuration") or []):
        if not isinstance(param, dict):
            continue
        for key in ("login", "logout"):
            part = param.get(key)
            if isinstance(part, dict):
                _request_templates(
                    part.get("request"), ("configuration", index, key, "request"), lines, problems, files=False
                )
                _check_templates(part.get("token"), _ANSWER, ("configuration", index, key, "token"), lines, problems)
        _check_templates(param.get("token_url"), frozenset({"config"}), ("configuration", index), lines, problems)
    for index, command in enumerate(raw.get("commands") or []):
        if isinstance(command, dict):
            _check_command(command, ("commands", index), lines, problems)
    fetch = raw.get("fetch")
    if isinstance(fetch, dict):
        _request_templates(fetch.get("request"), ("fetch", "request"), lines, problems, _FETCH_SENT, files=False)
        for key in ("pagination", "items", "next_state", "success", "error"):
            _check_templates(fetch.get(key), _FETCH_ANSWER, ("fetch", key), lines, problems)
        for key in ("item_id", "occurred", "item_time"):
            _check_templates(fetch.get(key), _FETCH_ITEM, ("fetch", key), lines, problems)
        _check_templates(
            fetch.get("first_state"), frozenset({"config", "first", "now"}), ("fetch", "first_state"), lines, problems
        )
    mirror = raw.get("mirror")
    if isinstance(mirror, dict):
        kinds = mirror.get("kinds") if isinstance(mirror.get("kinds"), dict) else {}
        parts = [(("mirror",), mirror), *((("mirror", "kinds", name), kind) for name, kind in kinds.items())]
        for at, part in parts:
            if not isinstance(part, dict):
                continue
            comments = part.get("comments") if isinstance(part.get("comments"), dict) else {}
            for where, call in (
                ((*at, "get"), part.get("get")),
                ((*at, "update"), part.get("update")),
                ((*at, "comments", "list"), comments.get("list")),
                ((*at, "comments", "add"), comments.get("add")),
            ):
                if isinstance(call, dict):
                    _check_templates(call.get("args"), _MIRROR_ARGS, (*where, "args"), lines, problems)
            for key in ("items", "id", "text", "author", "at"):
                _check_templates(comments.get(key), _MIRROR_COMMENT, (*at, "comments", key), lines, problems)
            _check_templates(part.get("item"), frozenset({"result"}), (*at, "item"), lines, problems)
        # What is read of a fetched item, as the fetch reads its id.
        _check_templates(mirror.get("id"), _FETCH_ITEM, ("mirror", "id"), lines, problems)
        thread = mirror.get("thread")
        if isinstance(thread, dict):
            for key in ("ids", "text", "author", "at"):
                _check_templates(thread.get(key), _FETCH_ITEM, ("mirror", "thread", key), lines, problems)

    if connector is not None and not problems:
        # What a template names must exist: a configuration entry, an argument, an earlier step.
        problems += _check_names(connector, raw, lines)
    if problems or connector is None:
        seen: set[tuple[int, str]] = set()
        unique = []
        for problem in sorted(problems, key=lambda found: (found.line, found.message)):
            if (problem.line, problem.message) not in seen:
                seen.add((problem.line, problem.message))
                unique.append(problem)
        raise ConnectorError(unique or [Problem(0, "Not a connector")])
    return connector


# The credentials that are one value, and what that value is called among the secrets of an instance.
_ONE_VALUE = {"bearer": "token", "header": "value", "query": "value"}


def _paths(value: Any, root: str) -> set[str]:
    """The first names read under ``root`` by the templates of a value: ``config.url`` → ``url``."""
    return ex.first_names(value, root)


NO_MIRROR_SAID = (
    'It fetches and says nothing of mirroring: add "mirror" (how an incident is kept in step with what it was '
    'made from), or "no_mirror" with the reason there is none. Until then its instances are offered None only'
)


def warnings(text: str | bytes) -> list[Problem]:
    """What a file that loads would better say, each with its line: nothing here stops a connector
    from being installed or from working as it did. ``[]`` for a file that does not load: its
    problems are what there is to say of it."""
    try:
        connector = load(text)
    except ConnectorError:
        return []
    found: list[Problem] = []
    if connector.fetch is not None and connector.mirror is None and connector.no_mirror is None:
        if isinstance(text, bytes):
            text = text.decode("utf-8")
        lines = _lines(yaml.compose(text, Loader=yaml.SafeLoader))
        found.append(Problem(_line_of(lines, ("fetch",)), NO_MIRROR_SAID, "fetch"))
    return found


def _check_names(connector: ConnectorFile, raw: dict, lines: dict) -> list[Problem]:
    problems: list[Problem] = []
    plain = {param.name for param in connector.configuration if not param.is_auth and param.type != "secret"}
    secret = {param.name for param in connector.configuration if param.type == "secret"}
    auth = connector.auth
    if auth is not None and auth.type in ("session", "zscaler", "basic"):
        # What a session logs in with: the parts of the credentials.
        secret |= {"username", "password", "api_key"}
    elif auth is not None and auth.type in _ONE_VALUE:
        # Credentials of one value are added to every request to the instance by the runtime, and a file
        # says nothing of them. It may still write the value by hand where the runtime adds nothing: a
        # request to another host the file lists (``more_hosts``), which the same key opens (6.6).
        secret |= {_ONE_VALUE[auth.type]}
    for name in sorted(_paths(raw, "config") - plain):
        if name in secret:
            problems.append(Problem(0, f'"{name}" is a secret: read it as {{{{ secret.{name} }}}}', "config"))
        else:
            problems.append(Problem(0, f'"config.{name}" is not in the configuration', "config"))
    for name in sorted(_paths(raw, "secret") - secret):
        problems.append(Problem(0, f'"secret.{name}" is not a secret of the configuration', "secret"))
    for index, command in enumerate(connector.commands):
        declared = {argument.name for argument in command.arguments}
        body = raw["commands"][index]
        for at, argument in enumerate(command.arguments):
            if argument.default_from is not None and argument.default_from not in plain:
                problems.append(
                    Problem(
                        _line_of(lines, ("commands", index, "arguments", at)),
                        f'the argument "{argument.name}" takes its default from "{argument.default_from}", '
                        "which is not a plain value of the configuration",
                        f"commands[{index}].arguments[{at}]",
                    )
                )
        for name in sorted(_paths(body, "args") - declared):
            problems.append(
                Problem(
                    _line_of(lines, ("commands", index)),
                    f'the command "{command.name}" reads "args.{name}", which is not among its arguments',
                    f"commands[{index}]",
                )
            )
        earlier: set[str] = set()
        for position, step in enumerate(command.steps or []):
            here = body["steps"][position]
            for name in sorted(_paths({"r": here.get("request"), "w": here.get("when")}, "steps") - earlier):
                problems.append(
                    Problem(
                        _line_of(lines, ("commands", index, "steps", position)),
                        f'the step "{step.name}" reads "steps.{name}", which is not an earlier step',
                        f"commands[{index}].steps[{position}]",
                    )
                )
            earlier.add(step.name)
        for name in sorted(_paths(body.get("outputs"), "steps") - {step.name for step in command.steps or []}):
            problems.append(
                Problem(
                    _line_of(lines, ("commands", index, "outputs")),
                    f'the outputs of "{command.name}" read "steps.{name}", which is not a step',
                    f"commands[{index}].outputs",
                )
            )
        for at, item in enumerate(command.context):
            from .. import context as incident_context

            where = ("commands", index, "context", at)
            wrong = incident_context.problem(item.path)
            if wrong is None:
                target = incident_context.parse(item.path)
                if target.kind == "ext" and target.connector != connector.id:
                    wrong = f"A connector writes under ext.{connector.id}, not under ext.{target.connector}"
            if wrong:
                problems.append(Problem(_line_of(lines, where), wrong, f"commands[{index}].context[{at}]"))
            if _paths((body.get("context") or [{}] * (at + 1))[at], "secret"):
                problems.append(Problem(_line_of(lines, where), "A secret cannot go to the context", "context"))
        if _paths(body.get("outputs"), "secret"):
            problems.append(
                Problem(_line_of(lines, ("commands", index, "outputs")), "A secret cannot be an output", "outputs")
            )
    # Mirroring runs commands of this file, and gives them arguments they declare.
    for where, call in connector.mirror_calls():
        loc = tuple(where.split("."))
        command = connector.command(call.command)
        if command is None:
            problems.append(
                Problem(_line_of(lines, loc), f'{where} names "{call.command}", which is not a command', where)
            )
            continue
        declared = {argument.name for argument in command.arguments}
        for name in sorted(set(call.args) - declared):
            problems.append(
                Problem(_line_of(lines, loc), f'{where} gives "{name}", which "{call.command}" does not take', where)
            )
        missing = [
            argument.name
            for argument in command.arguments
            if argument.required and argument.default is None and argument.name not in call.args
        ]
        if call.args and missing:
            problems.append(
                Problem(
                    _line_of(lines, loc), f'{where} does not give "{missing[0]}", which "{call.command}" needs', where
                )
            )
        if not call.args and not command.arguments:
            problems.append(
                Problem(_line_of(lines, loc), f'{where}: "{call.command}" takes no argument to be given the id', where)
            )
    for where, call in connector.mirror_calls():
        command = connector.command(call.command)
        if command is not None and where.endswith(".update") and not command.changes_outside:
            problems.append(
                Problem(
                    _line_of(lines, tuple(where.split("."))),
                    f"{where} changes the other side: its command says changes_outside: true",
                    where,
                )
            )
    return problems


def summary(connector: ConnectorFile) -> dict[str, Any]:
    """What the lists show of a connector."""
    return {
        "id": connector.id,
        "name": connector.name,
        "version": connector.version,
        "description": connector.description,
        "moreHosts": list(connector.more_hosts),
        "downloadHostsFrom": connector.download_hosts_from,
        "apiVersion": connector.api_version,
        "verified": connector.verified,
        "native": connector.native,
        # What it can do besides commands: bring alerts in, keep an object in step.
        "fetch": (
            {
                "intervalSeconds": connector.fetch.interval_seconds,
                "firstFetch": connector.fetch.first_fetch,
                "lookbackMinutes": connector.fetch.lookback_minutes,
                # Whether its request asks from a moment: the look-back of an instance applies to it.
                "byTime": connector.fetch.by_time,
            }
            if connector.fetch is not None
            else None
        ),
        "mirror": (
            {
                "intervalSeconds": connector.mirror.interval_seconds,
                "out": can_send(connector.mirror),
                "comments": connector.mirror.comments is not None or connector.mirror.thread is not None,
                "commentsOut": connector.mirror.comments is not None and connector.mirror.comments.add is not None,
                # What a mirror with this connector does each way: what the choice of an instance says.
                "fieldsIn": connector.mirror.get is not None,
                "fieldsOut": connector.mirror.update is not None,
                # Fed by the fetch (a conversation): nothing is read at an interval.
                "fed": connector.mirror.get is None,
                "kinds": sorted(connector.mirror.kinds),
            }
            if connector.mirror is not None
            else None
        ),
        # Why it fetches and does not mirror, when its file says so.
        "noMirror": connector.no_mirror,
        "schema": (
            {
                "incoming": [item.model_dump() for item in connector.schema_.incoming],
                "outgoing": [item.model_dump() for item in connector.schema_.outgoing],
            }
            if connector.schema_ is not None
            else {"incoming": [], "outgoing": []}
        ),
        "extFields": [item.model_dump() for item in connector.ext_fields],
        "commands": [
            {
                "name": command.name,
                "description": command.description,
                "changesOutside": command.changes_outside,
                "premium": command.premium,
                "arguments": [argument.model_dump(exclude_none=True) for argument in command.arguments],
                "outputs": sorted(command.outputs),
            }
            for command in connector.commands
        ],
        "configuration": [
            {
                "name": param.name,
                "label": param.label or param.name.replace("_", " ").capitalize(),
                "type": param.type,
                "required": param.required,
                "default": param.default,
                "choices": param.choices or [],
                "help": param.help,
            }
            for param in connector.configuration
        ],
    }
