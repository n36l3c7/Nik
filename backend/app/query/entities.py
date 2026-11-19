"""The entities a query can be asked of, and the fields each exposes.

Incidents, artifacts, the audit log, the runs of playbooks, their approvals
and the tasks are tables; the indicator library is assembled in rows
(``ioc_library.library``), so its fields read a row.
"""

from __future__ import annotations

from sqlalchemy import false, func, select

from .. import fields as registry
from ..core.models import (
    Approval,
    Artifact,
    ArtifactLink,
    AuditEntry,
    Connection,
    Incident,
    IncidentType,
    Playbook,
    Run,
    Task,
)
from .fields import Context, Entity, FieldSpec, _bad, _boolean, text_matches
from .incident_fields import TAG_NAMES, TAGS_FIELD, spec_of
from .parser import Value

SEVERITIES = ("low", "medium", "high", "critical")
STATUSES = ("open", "in_progress", "closed")
ARTIFACT_KINDS = ("file", "mail", "pcap", "url", "mailbox")
INDICATOR_TYPES = ("ip", "domain", "url", "email", "md5", "sha1", "sha256")
VERDICTS = ("unknown", "harmless", "suspicious", "malicious")
ORIGINS = ("incident", "manual", "import", "artifact")
TLPS = ("clear", "green", "amber", "red")


# --------------------------------------------------------------------------- #
# Incidents                                                                   #
# --------------------------------------------------------------------------- #
def _timer(name: str):
    """The seconds an SLA timer counted before its last stretch: all of them, once it stopped."""
    return Incident.fields[name]["accumulated_s"].as_float()


_TYPE_NAME = select(IncidentType.name).where(IncidentType.id == Incident.type_id).scalar_subquery()
_SOURCE_NAME = select(Connection.name).where(Connection.id == Incident.source_connection_id).scalar_subquery()

# The fields Nik always had, by the names the language always gave them. Where the registry
# calls one differently (close_reason, sla_breached, time_to_assign), that name is another name
# of it here: a field is asked by the name it has in Settings.
_ALWAYS = (
    FieldSpec("id", "keyword", "The incident's uuid", aliases=("uuid",), column=Incident.id),
    FieldSpec("number", "number", "The number it is called by: number:42", aliases=("no",), column=Incident.number),
    FieldSpec("name", "text", "The name shown in the list", column=Incident.name),
    FieldSpec("ticket", "text", "The ticket of your tracker", aliases=("ticketId",), column=Incident.ticket_id),
    FieldSpec("host", "text", "The host the incident is about", column=Incident.host),
    FieldSpec("username", "text", "The account the incident is about", aliases=("user",), column=Incident.username),
    FieldSpec("os", "keyword", "The operating system", column=Incident.os),
    FieldSpec("severity", "ordered", "low, medium, high or critical", column=Incident.severity, values=SEVERITIES),
    FieldSpec("status", "keyword", "open, in_progress or closed", column=Incident.status, values=STATUSES),
    FieldSpec(
        "owner",
        "keyword",
        'Who has the incident; owner:"" is nobody',
        aliases=("assignee",),
        column=Incident.assignee,
    ),
    FieldSpec("hasMail", "bool", "It holds analysed e-mails", aliases=("mail",), column=Incident.has_mail),
    FieldSpec("created", "date", "When it was created", aliases=("createdAt",), column=Incident.created_at),
    FieldSpec("modified", "date", "When it last changed", aliases=("updated", "updatedAt"), column=Incident.updated_at),
    FieldSpec("type", "keyword", "The name of its type of incident", column=_TYPE_NAME, nullable=True),
    FieldSpec("occurred", "date", "When what it is about happened", column=Incident.occurred_at, nullable=True),
    FieldSpec("closed", "date", "When it was closed", aliases=("closedAt",), column=Incident.closed_at, nullable=True),
    FieldSpec("closeReason", "keyword", "Why it was closed", aliases=("close_reason",), column=Incident.close_reason),
    FieldSpec("close_notes", "text", "What was written when it was closed", column=Incident.close_notes),
    FieldSpec("source", "keyword", "The connection that fetched it", column=_SOURCE_NAME, nullable=True),
    FieldSpec(
        "source_instance",
        "keyword",
        "The id of the connection that fetched it",
        column=Incident.source_connection_id,
        nullable=True,
    ),
    FieldSpec("source_id", "text", "Its id where it was fetched from", column=Incident.source_id, nullable=True),
    FieldSpec(
        "slaBreached",
        "bool",
        "One of its SLA timers ran past its time",
        aliases=("breached", "sla_breached"),
        column=func.coalesce(Incident.fields["sla_breached"].as_boolean(), false()),
    ),
    FieldSpec(
        "timeToAssign",
        "number",
        "Seconds its time-to-assign timer counted",
        aliases=("time_to_assign",),
        column=_timer("time_to_assign"),
    ),
    FieldSpec(
        "timeToContain",
        "number",
        "Seconds its time-to-contain timer counted",
        aliases=("time_to_contain",),
        column=_timer("time_to_contain"),
    ),
    FieldSpec(
        "timeToClose",
        "number",
        "Seconds its time-to-close timer counted",
        aliases=("time_to_close",),
        column=_timer("time_to_close"),
    ),
)


def _kept_in_fields() -> tuple[FieldSpec, ...]:
    """The system fields of the registry that are kept in ``incidents.fields`` and had no name
    in the language: labels, phase, due, tlp, category… Each is what its type makes it."""
    named = {name.lower() for spec in _ALWAYS for name in (spec.name, *spec.aliases)}
    found = []
    for name, system in registry.SYSTEM_FIELDS.items():
        if name in named or system.where != "json":
            continue
        options = {"choices": list(system.options)} if system.options else {}
        found.append(
            spec_of(
                name,
                system.type,
                label=system.label,
                description=system.description,
                options=options,
                # The tags of an incident are asked as those of an artifact or an indicator are.
                aliases=TAG_NAMES if name == TAGS_FIELD else (),
            )
        )
    return tuple(found)


INCIDENTS = Entity(
    name="incidents",
    label="Incidents",
    permission="read",
    model=Incident,
    text_fields=("name", "host", "username", "ticket"),
    fields=(*_ALWAYS, *_kept_in_fields()),
)


# --------------------------------------------------------------------------- #
# Artifacts                                                                   #
# --------------------------------------------------------------------------- #
def _has_link():
    return select(ArtifactLink.artifact_id).where(ArtifactLink.artifact_id == Artifact.id).exists()


def _linked_sql(op: str, value: Value, ctx: Context):
    if op not in ("=", "!"):
        raise _bad("bad_operator", 0, '"linked" is true or false')
    wanted = _boolean(value, 0) == (op == "=")
    return _has_link() if wanted else ~_has_link()


def _incident_sql(op: str, value: Value, ctx: Context):
    """``incident:<id>``: referenced by that incident; ``incident:*`` by any."""
    if op not in ("=", "!"):
        raise _bad("bad_operator", 0, '"incident" takes an incident\'s id')
    if value.is_any or value.is_empty:
        found = _has_link()
        positive = value.is_any == (op == "=")
    else:
        found = (
            select(ArtifactLink.artifact_id)
            .where(ArtifactLink.artifact_id == Artifact.id, ArtifactLink.incident_id == value.text)
            .exists()
        )
        positive = op == "="
    return found if positive else ~found


ARTIFACTS = Entity(
    name="artifacts",
    label="Artifacts",
    permission="read",
    model=Artifact,
    text_fields=("name", "hash", "detail", "tags"),
    fields=(
        FieldSpec("id", "keyword", "The artifact's identifier", column=Artifact.id),
        FieldSpec(
            "kind",
            "keyword",
            "file, mail, pcap, url or mailbox",
            aliases=("type",),
            column=Artifact.kind,
            values=ARTIFACT_KINDS,
        ),
        FieldSpec("name", "text", "Its name", column=Artifact.name),
        FieldSpec(
            "hash",
            "text",
            "Its SHA-256, or the id of a capture or a scan",
            aliases=("sha256", "ref"),
            column=Artifact.ref,
        ),
        FieldSpec("verdict", "keyword", "What the analysis concluded", column=Artifact.verdict),
        FieldSpec("score", "number", "The score of the analysis", column=Artifact.score),
        FieldSpec("detail", "text", "The line under the name", column=Artifact.detail),
        FieldSpec("size", "number", "Its size in bytes", column=Artifact.size),
        FieldSpec("tags", "tags", "Its tags", aliases=("tag",), column=Artifact.tags),
        FieldSpec("created", "date", "When it was added", aliases=("createdAt",), column=Artifact.created_at),
        FieldSpec("createdBy", "keyword", "Who added it", aliases=("by",), column=Artifact.created_by),
        FieldSpec("linked", "bool", "An incident references it", sql=_linked_sql),
        FieldSpec("incident", "keyword", "The id of an incident that references it", sql=_incident_sql),
    ),
)


# --------------------------------------------------------------------------- #
# Audit log                                                                   #
# --------------------------------------------------------------------------- #
AUDIT = Entity(
    name="audit",
    label="Audit log",
    permission="audit.read",
    model=AuditEntry,
    text_fields=("actor", "action", "details", "incident"),
    fields=(
        FieldSpec("at", "date", "When it happened", aliases=("date", "when"), column=AuditEntry.at),
        FieldSpec(
            "actor",
            "text",
            "Who did it: a username, or api:<key label>",
            aliases=("user", "by"),
            column=AuditEntry.actor,
        ),
        FieldSpec(
            "action", "keyword", "What was done, for example user.update or incident.*", column=AuditEntry.action
        ),
        FieldSpec("target", "text", "What it was done to", column=AuditEntry.target, nullable=True),
        FieldSpec("details", "text", "The sentence of the entry", column=AuditEntry.details),
        FieldSpec(
            "incident", "text", "The name of the incident concerned", column=AuditEntry.incident_name, nullable=True
        ),
        FieldSpec(
            "incidentId", "keyword", "The id of the incident concerned", column=AuditEntry.incident_id, nullable=True
        ),
    ),
)


# --------------------------------------------------------------------------- #
# Indicators (rows of the library)                                            #
# --------------------------------------------------------------------------- #
def _list_test(op: str, value: Value, ctx: Context):
    """``list:<name or id>``: kept in that watch list."""
    if op not in ("=", "!"):
        raise _bad("bad_operator", 0, '"list" takes the name of a list')

    def held(row: dict) -> bool:
        lists = row.get("lists") or []
        if value.is_empty:
            return not lists
        if value.is_any:
            return bool(lists)
        return any(
            entry.get("id") == value.text or text_matches(value, entry.get("name", ""), contains=False)
            for entry in lists
        )

    return lambda row: held(row) == (op == "=")


INDICATORS = Entity(
    name="indicators",
    label="Indicators",
    permission="read",
    text_fields=("value", "note", "tags", "listNames"),
    fields=(
        FieldSpec(
            "type",
            "keyword",
            "ip, domain, url, email, md5, sha1 or sha256",
            aliases=("kind",),
            getter=lambda r: r["type"],
            values=INDICATOR_TYPES,
        ),
        FieldSpec("value", "text", "The indicator itself", getter=lambda r: r["value"]),
        FieldSpec(
            "verdict",
            "ordered",
            'What the sources say; verdict:"" is not checked yet',
            getter=lambda r: r.get("verdict"),
            values=VERDICTS,
        ),
        FieldSpec("score", "number", "The reputation score", getter=lambda r: r.get("score")),
        FieldSpec(
            "origin", "keyword", "incident, manual, import or artifact", getter=lambda r: r["origin"], values=ORIGINS
        ),
        FieldSpec("incidents", "number", "In how many incidents it was seen", getter=lambda r: r.get("incidents") or 0),
        FieldSpec("tags", "tags", "Its tags", aliases=("tag",), getter=lambda r: r.get("tags") or []),
        FieldSpec("note", "text", "The note an analyst wrote", getter=lambda r: r.get("note") or ""),
        FieldSpec("tlp", "keyword", "clear, green, amber or red", getter=lambda r: r.get("tlp"), values=TLPS),
        FieldSpec("list", "keyword", "A watch list that keeps it (name or id)", aliases=("lists",), test=_list_test),
        FieldSpec(
            "listNames",
            "tags",
            "The names of its lists",
            getter=lambda r: [e.get("name", "") for e in r.get("lists") or []],
        ),
        FieldSpec("expired", "bool", "Its date has passed", getter=lambda r: r.get("expired")),
        FieldSpec("expires", "date", "The date after which it is no longer current", getter=lambda r: r.get("expires")),
        FieldSpec(
            "firstSeen",
            "date",
            "When Nik first met it",
            aliases=("first_seen", "seen"),
            getter=lambda r: r.get("firstSeen"),
        ),
        FieldSpec(
            "checked",
            "date",
            "When its reputation was last asked",
            aliases=("checkedAt",),
            getter=lambda r: r.get("checkedAt"),
        ),
        FieldSpec("allowlisted", "bool", "It is in the allowlist", getter=lambda r: r.get("allowlisted")),
        FieldSpec(
            "analysed",
            "bool",
            "Nik analysed it itself (a URL it visited)",
            aliases=("analyzed",),
            getter=lambda r: bool(r.get("analysis")),
        ),
        FieldSpec("addedBy", "keyword", "Who added it by hand", getter=lambda r: r.get("addedBy")),
    ),
)

# --------------------------------------------------------------------------- #
# Automation: runs, approvals, tasks                                          #
# --------------------------------------------------------------------------- #
_PLAYBOOK_NAME = select(Playbook.name).where(Playbook.id == Run.playbook_id).scalar_subquery()
_APPROVAL_PLAYBOOK = (
    select(Playbook.name).join(Run, Run.playbook_id == Playbook.id).where(Run.id == Approval.run_id).scalar_subquery()
)

RUNS = Entity(
    name="runs",
    label="Runs",
    permission="automation.run",
    model=Run,
    base=(Run.debug.is_(False),),  # a run of the debugger is nobody's statistics
    text_fields=("playbook", "error", "startedBy"),
    fields=(
        FieldSpec("id", "keyword", "The run's identifier", column=Run.id),
        FieldSpec("playbook", "text", "The name of the playbook", column=_PLAYBOOK_NAME, nullable=True),
        FieldSpec(
            "status",
            "keyword",
            "queued, running, waiting, done, failed or stopped",
            column=Run.status,
            values=("queued", "running", "waiting", "done", "failed", "stopped"),
        ),
        FieldSpec("dryRun", "bool", "It was a dry run", aliases=("dry",), column=Run.dry_run),
        FieldSpec("on", "keyword", "What it ran on: incident, artifact, indicator…", column=Run.object_kind),
        FieldSpec("incident", "keyword", "The id of the incident it ran on", column=Run.incident_id, nullable=True),
        FieldSpec("startedBy", "keyword", "Who or what started it", aliases=("by",), column=Run.started_by),
        FieldSpec("started", "date", "When it started", aliases=("startedAt",), column=Run.started_at),
        FieldSpec("finished", "date", "When it ended", aliases=("finishedAt",), column=Run.finished_at, nullable=True),
        FieldSpec("error", "text", "Why it failed", column=Run.error, nullable=True),
    ),
)

APPROVALS = Entity(
    name="approvals",
    label="Approvals",
    permission="automation.run",
    model=Approval,
    base=(select(Run.id).where(Run.id == Approval.run_id, Run.debug.is_(False)).exists(),),
    text_fields=("question", "playbook"),
    fields=(
        FieldSpec("id", "keyword", "The approval's identifier", column=Approval.id),
        FieldSpec(
            "status",
            "keyword",
            "waiting, approved, rejected or expired",
            column=Approval.status,
            values=("waiting", "approved", "rejected", "expired"),
        ),
        FieldSpec("question", "text", "What is asked", column=Approval.question),
        FieldSpec("playbook", "text", "The name of the playbook that asks", column=_APPROVAL_PLAYBOOK, nullable=True),
        FieldSpec("asked", "date", "When it was asked", aliases=("askedAt",), column=Approval.asked_at),
        FieldSpec(
            "answered",
            "date",
            "When it was answered",
            aliases=("answeredAt",),
            column=Approval.answered_at,
            nullable=True,
        ),
        FieldSpec("answeredBy", "keyword", "Who answered", aliases=("by",), column=Approval.answered_by, nullable=True),
    ),
)

TASKS = Entity(
    name="tasks",
    label="Tasks",
    permission="read",
    model=Task,
    text_fields=("title", "assignee"),
    fields=(
        FieldSpec("id", "keyword", "The task's identifier", column=Task.id),
        FieldSpec("kind", "keyword", "task or ask (a question)", column=Task.kind, values=("task", "ask")),
        FieldSpec(
            "status",
            "keyword",
            "open, overdue, done or skipped",
            column=Task.status,
            values=("open", "overdue", "done", "skipped"),
        ),
        FieldSpec("title", "text", "What is to do", column=Task.title),
        FieldSpec("assignee", "keyword", "The account it is for", aliases=("user",), column=Task.assignee_user),
        FieldSpec("role", "keyword", "The role it is for", column=Task.assignee_role),
        FieldSpec("incident", "keyword", "The id of its incident", column=Task.incident_id, nullable=True),
        FieldSpec("created", "date", "When it was given", aliases=("createdAt",), column=Task.created_at),
        FieldSpec(
            "completed", "date", "When it was done", aliases=("completedAt",), column=Task.completed_at, nullable=True
        ),
        FieldSpec("completedBy", "keyword", "Who did it", column=Task.completed_by),
    ),
)

ENTITIES: dict[str, Entity] = {
    entity.name: entity for entity in (INCIDENTS, ARTIFACTS, INDICATORS, AUDIT, RUNS, APPROVALS, TASKS)
}
